//! The UDF reader: open, label, revision, NSR, listings (S15, slice 1).
//!
//! [`UdfReader::open`] walks the whole chain up front — recognition
//! sequence, anchor probe, main (or reserve) descriptor sequence, file
//! set descriptor, root file entry — so any malformed volume refuses at
//! open time, before any listing. [`UdfReader::read_dir`] then lists any
//! directory entry by resolving its ICB through the partition maps,
//! which is exactly what slice 2 reuses to read file content.
//!
//! *Measured* — the chain above parses byte-identical on the `mkudffs`
//! images from udftools 2.3 (see [`udf`](super) and the slice report):
//! the label reads `LABEL`, the revision `2.01`, the NSR `NSR03`, the
//! empty root lists nothing (only its skipped parent entry), and the
//! populated root lists one subdirectory plus three files with their ICBs.
//!
//! *Inferred* — that accepting both `NSR02` and `NSR03` is right (the
//! writer side pins `NSR03` and refuses `NSR02`; a *reader* that refused
//! `NSR02` images would turn away every `--udfrev=0x0150` volume for no
//! structural reason, so the recognition mirror below accepts both while
//! keeping every other byte check identical to
//! [`recognition`](crate::fs::udf::recognition)).

use std::fmt;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::udf::Nsr;
use crate::text::device_text;
use crate::udf::LongAd;
use crate::udf::PartitionDesc;
use crate::udf::anchor;
use crate::udf::descriptor;
use crate::udf::fid;
use crate::udf::file;
use crate::udf::read_bytes;
use crate::udf::unicode;

/// Absolute byte offset of the volume recognition sequence: three
/// consecutive 2048-byte sectors, identical for both block sizes.
const RECOGNITION_AT: u64 = 32768;
/// Length of the recognition region in bytes.
const RECOGNITION_LEN: u64 = 3 * 2048;

/// One directory entry: the decoded name, the directory flag and the ICB
/// slice 2 needs to read the entry's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Decoded file name (OSTA compressed Unicode). Empty for the root,
    /// which has no name.
    pub name: String,
    /// True for directories (characteristics bit 1).
    pub is_directory: bool,
    /// Long address of the entry's file entry: extent length, block
    /// number (partition-relative) and partition reference.
    pub icb: LongAd,
    /// File version number from the file identifier (1 on real images).
    pub file_version: u16,
}

/// UDF reader over an owned byte store: the anchor, the descriptor
/// sequence, the partition table, the file set and the root ICB, all
/// resolved at [`UdfReader::open`]. No `Debug` derive: the owned
/// `Box<dyn Volume>` store carries none, and a reader needs no debug
/// view.
pub struct UdfReader {
    /// The backing byte store; reads go straight through it with checked
    /// windows (no cache — see [`udf`](super) for why).
    volume: Box<dyn Volume>,
    /// Total store extent in bytes.
    total: u64,
    /// Probed logical block size in bytes.
    block_size: u32,
    /// Recognition sequence NSR (`NSR02` or `NSR03`).
    nsr: Nsr,
    /// Logical volume identifier (d-string, padding trimmed, sanitised).
    label: String,
    /// Domain suffix revision (`2.01` for the pinned writer revision).
    revision: String,
    /// Partition numbers in map-table order.
    maps: Vec<u16>,
    /// Partition descriptors in walk order.
    partitions: Vec<PartitionDesc>,
    /// Partition the root ICB resolves through.
    home: PartitionDesc,
    /// File set descriptor (the root ICB lives here).
    fsd: file::FileSetDescriptor,
}

/// Debug without the byte store: the owned `Box<dyn Volume>` carries no
/// debug view, so the format covers the parsed metadata only.
impl fmt::Debug for UdfReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdfReader")
            .field("total", &self.total)
            .field("block_size", &self.block_size)
            .field("nsr", &self.nsr)
            .field("label", &self.label)
            .field("revision", &self.revision)
            .field("maps", &self.maps)
            .field("partitions", &self.partitions)
            .field("home", &self.home)
            .field("fsd", &self.fsd)
            .finish()
    }
}

impl UdfReader {
    /// Open the volume: verify the recognition sequence, probe the anchor
    /// at sector 256, walk the main descriptor sequence (falling back to
    /// the reserve copy when the main one is incomplete), then resolve the
    /// file set descriptor and validate the root file entry. Any malformed
    /// structure refuses here, naming the block and the numbers.
    pub fn open(volume: Box<dyn Volume>) -> Result<Self> {
        let total = volume.total_bytes();
        let nsr = read_nsr(&*volume, total)?;
        let anchor = anchor::probe(&*volume)?;
        let size = anchor.block_size;
        let walked = descriptor::walk(&*volume, size, anchor.main, total);
        let set = match walked {
            Ok(set) if set.is_complete() => set,
            _ => match anchor.reserve {
                Some(reserve) => {
                    let fallback = descriptor::walk(&*volume, size, reserve, total)?;
                    if !fallback.is_complete() {
                        // Both sequences walked; report the main one's
                        // failure, which the fallback did not repair.
                        walked?;
                    }
                    fallback
                }
                None => walked?,
            },
        };
        let logical = set.logical.as_ref().ok_or_else(|| {
            CoreError::invalid("volume descriptor walk returned no logical volume")
        })?;
        let fsd_rel = logical.fsd.lbn;
        let fsd_part = file::resolve_map(
            &logical.maps,
            &set.partitions,
            logical.fsd.partition_ref,
            "file set descriptor",
        )?;
        let fsd_abs = fsd_part.start.checked_add(fsd_rel).ok_or_else(|| {
            CoreError::invalid(format!(
                "file set descriptor at partition-relative block {fsd_rel} overflows the block number"
            ))
        })?;
        let fsd = file::read_fsd(&*volume, size, fsd_abs, fsd_rel)?;
        let home = file::resolve_map(
            &logical.maps,
            &set.partitions,
            fsd.root_icb.partition_ref,
            "root directory",
        )?;
        let root_abs = home.start.checked_add(fsd.root_icb.lbn).ok_or_else(|| {
            CoreError::invalid(format!(
                "root directory at partition-relative block {} overflows the block number",
                fsd.root_icb.lbn
            ))
        })?;
        check_icb_window(size, total, &fsd.root_icb, root_abs, "root directory")?;
        // Validate the root file entry now so a corrupt root refuses at
        // open time, exactly like the rest of the chain.
        file::read_file_entry(&*volume, size, root_abs, fsd.root_icb.lbn)?;
        let label = device_text(&logical.label);
        Ok(Self {
            volume,
            total,
            block_size: size,
            nsr,
            label,
            revision: logical.revision.clone(),
            maps: logical.maps.clone(),
            partitions: set.partitions,
            home,
            fsd,
        })
    }

    /// Volume label from the logical volume identifier (d-string, padding
    /// trimmed, sanitised to ASCII).
    #[must_use]
    pub fn volume_label(&self) -> &str {
        &self.label
    }

    /// UDF revision from the domain suffix (`2.01` for the pinned writer
    /// revision).
    #[must_use]
    pub fn udf_revision(&self) -> &str {
        &self.revision
    }

    /// Volume recognition sequence NSR (`NSR02` or `NSR03`).
    #[must_use]
    pub fn nsr(&self) -> Nsr {
        self.nsr
    }

    /// Logical block size in bytes (512 or 2048).
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total store extent in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total
    }

    /// Partition number the root resolves through.
    #[must_use]
    pub fn partition_number(&self) -> u16 {
        self.home.number
    }

    /// First absolute block number of that partition.
    #[must_use]
    pub fn partition_start(&self) -> u32 {
        self.home.start
    }

    /// That partition's length in blocks.
    #[must_use]
    pub fn partition_length(&self) -> u32 {
        self.home.length
    }

    /// The file set descriptor (carries the root ICB).
    #[must_use]
    pub fn fsd(&self) -> &file::FileSetDescriptor {
        &self.fsd
    }

    /// The root directory entry (empty name, always a directory),
    /// synthesised from the file set's root ICB.
    #[must_use]
    pub fn root(&self) -> Entry {
        Entry {
            name: String::new(),
            is_directory: true,
            icb: self.fsd.root_icb,
            file_version: 1,
        }
    }

    /// List `entry` (the root or any directory entry): resolve its ICB
    /// through the partition maps, read its file entry, join its data and
    /// parse the file identifiers. Deleted entries (bit 0) and parent
    /// entries (bit 3) are skipped, exactly like ISO skips dot records.
    /// Refuses files, unresolvable ICBs and malformed directory data,
    /// naming the entry.
    pub fn read_dir(&self, entry: &Entry) -> Result<Vec<Entry>> {
        let display = short_name(&entry.name);
        let (home, abs, rel) = self.resolve(&entry.icb, &display)?;
        check_icb_window(self.block_size, self.total, &entry.icb, abs, &display)?;
        let file_entry = file::read_file_entry(&*self.volume, self.block_size, abs, rel)
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        let what = format!("directory `{display}`");
        let (data, segs) = file::collect_data(
            &*self.volume,
            self.block_size,
            &self.maps,
            &self.partitions,
            &home,
            &file_entry,
            &what,
            rel,
        )
        .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        let ids = fid::parse_fids(&data, &segs, self.block_size, &what)
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
        let mut out = Vec::new();
        for id in &ids {
            if id.is_deleted() || id.is_parent() {
                continue;
            }
            let name = unicode::decode_osta(
                &id.name,
                &format!("{what} entry at directory offset {}", id.name_off),
            )
            .map_err(|error| CoreError::invalid(format!("cannot list `{display}`: {error}")))?;
            out.push(Entry {
                name,
                is_directory: id.is_directory,
                icb: id.icb,
                file_version: id.version,
            });
        }
        Ok(out)
    }

    /// Resolve an ICB to its partition, absolute block and
    /// partition-relative block: the partition reference indexes the map
    /// table, the map gives the partition number, and the block adds onto
    /// the partition start. Slice 2 builds file reads on this. Refuses an
    /// unresolvable reference or an overflowing block sum.
    pub fn resolve_icb(&self, icb: &LongAd) -> Result<(u32, u32)> {
        let display = short_name("<icb>");
        let (_, abs, _) = self.resolve(icb, &display)?;
        Ok((abs, icb.extent_length))
    }

    /// Resolve `icb` to (partition, absolute block, relative block).
    fn resolve(&self, icb: &LongAd, display: &str) -> Result<(PartitionDesc, u32, u32)> {
        let home = file::resolve_map(&self.maps, &self.partitions, icb.partition_ref, display)?;
        let abs = home.start.checked_add(icb.lbn).ok_or_else(|| {
            CoreError::invalid(format!(
                "{display} at partition-relative block {} overflows the block number",
                icb.lbn
            ))
        })?;
        Ok((home, abs, icb.lbn))
    }
}

/// The ICB window must hold the addressed block: refuses a zero length, a
/// length past one block (file entries fill exactly their block in slice
/// 1; longer ICBs belong to a later slice) and a window running past the
/// store — each naming the numbers.
fn check_icb_window(size: u32, total: u64, icb: &LongAd, abs: u32, display: &str) -> Result<()> {
    if icb.extent_length == 0 {
        return Err(CoreError::invalid(format!(
            "{display} ICB has zero length: no file entry to read"
        )));
    }
    if icb.extent_length > size {
        return Err(CoreError::invalid(format!(
            "{display} ICB length {} runs past the {size} byte block size: multi-block file \
             entries are not supported",
            icb.extent_length
        )));
    }
    let offset = u64::from(abs).checked_mul(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{display} ICB at block {abs} overflows the byte offset arithmetic"
        ))
    })?;
    let end = offset.checked_add(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{display} ICB of {size} bytes at block {abs} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{display} ICB of {size} bytes at block {abs} (bytes {offset}..{end}) runs past \
             the {total} byte volume end"
        )));
    }
    Ok(())
}

/// Error-message form of an entry name: sanitised to ASCII and capped at
/// 200 characters so a hostile name cannot flood a log line.
fn short_name(name: &str) -> String {
    let clean = if name.is_empty() {
        String::from("/")
    } else {
        device_text(name)
    };
    let mut out: String = clean.chars().take(200).collect();
    if clean.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

/// Verify the volume recognition sequence at absolute bytes 32768..38912:
/// three 2048-byte sectors opening with struct type `0x00`, identifiers
/// `BEA01`/`NSR02`-or-`NSR03`/`TEA01` and struct version `0x01`. Every
/// check mirrors [`recognition`](crate::fs::udf::recognition) except the
/// middle identifier, which accepts both revisions (see the module
/// header). Refusals name the absolute offsets and the bytes found.
fn read_nsr(volume: &dyn Volume, total: u64) -> Result<Nsr> {
    let region = read_bytes(
        volume,
        RECOGNITION_AT,
        RECOGNITION_LEN,
        total,
        "UDF recognition",
    )?;
    check_sector(&region, 0, "BEA01")?;
    let nsr = check_nsr(&region)?;
    check_sector(&region, 2, "TEA01")?;
    Ok(nsr)
}

/// Check one recognition sector's type byte, ASCII identifier and version
/// byte: sector `index` (0 or 2) starts at absolute byte
/// `32768 + index * 2048`.
fn check_sector(region: &[u8], index: usize, expected: &str) -> Result<()> {
    let base = index.saturating_mul(2048);
    let start = (RECOGNITION_AT as usize).saturating_add(base);
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier != expected {
        return Err(identifier_mismatch(start, &identifier, expected));
    }
    check_version_byte(region, base, start)?;
    Ok(())
}

/// Check the middle recognition sector (absolute byte 34816): the type
/// and version bytes read like every sector, while the identifier may be
/// either revision's NSR — `NSR03` or `NSR02` — and anything else refuses
/// naming the expected identifiers.
fn check_nsr(region: &[u8]) -> Result<Nsr> {
    let base = 2048;
    let start = (RECOGNITION_AT as usize).saturating_add(base);
    check_type_byte(region, base, start)?;
    let identifier = sector_identifier(region, base, start)?;
    if identifier == Nsr::Nsr03.as_str() {
        check_version_byte(region, base, start)?;
        return Ok(Nsr::Nsr03);
    }
    if identifier == Nsr::Nsr02.as_str() {
        check_version_byte(region, base, start)?;
        return Ok(Nsr::Nsr02);
    }
    Err(CoreError::invalid(format!(
        "the UDF recognition sector at byte {start} reads `{identifier}` not `NSR03` or \
         `NSR02`: bytes {}..{} must read an NSR identifier",
        start + 1,
        start + 6,
    )))
}

/// Byte 0 of the sector at region offset `base` (absolute `start`) is the
/// struct type `0x00`.
fn check_type_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let found = region.get(base).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct type byte at byte {start}"
        ))
    })?;
    if found != 0x00 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct type 0x{found:02X} \
              not 0x00: byte {start} must read 0x00"
        )));
    }
    Ok(())
}

/// Bytes 1..6 of the sector at region offset `base` as sanitised text.
fn sector_identifier(region: &[u8], base: usize, start: usize) -> Result<String> {
    let bytes = region.get(base + 1..base + 6).ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the identifier bytes {}..{} of the \
             sector at byte {start}",
            start + 1,
            start + 6,
        ))
    })?;
    Ok(device_text(&String::from_utf8_lossy(bytes)))
}

/// Byte 6 of the sector at region offset `base` (absolute `start`) is the
/// struct version `0x01`.
fn check_version_byte(region: &[u8], base: usize, start: usize) -> Result<()> {
    let at = start.saturating_add(6);
    let found = region.get(base + 6).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "the UDF recognition region ends before the struct version byte at byte {at}"
        ))
    })?;
    if found != 0x01 {
        return Err(CoreError::invalid(format!(
            "the UDF recognition sector at byte {start} has struct version 0x{found:02X} \
              not 0x01: byte {at} must read 0x01"
        )));
    }
    Ok(())
}

/// Refusal for a recognition sector whose identifier is not `expected`.
fn identifier_mismatch(start: usize, found: &str, expected: &str) -> CoreError {
    CoreError::invalid(format!(
        "the UDF recognition sector at byte {start} reads `{found}` not `{expected}`: \
          bytes {}..{} must read the {expected} identifier",
        start + 1,
        start + 6,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    const SIZE: u32 = 512;
    /// Absolute block of the anchor (sector 256 in 512-byte units).
    const ANCHOR_AT: u32 = 256;
    /// Main sequence extent: 8 blocks from 96 on.
    const MAIN_AT: u32 = 96;
    /// Partition start both fixtures use.
    const PART_AT: u32 = 257;

    /// Recognition region: BEA01, NSR03, TEA01.
    fn recognition(nsr: &[u8; 5]) -> Vec<u8> {
        let mut region = vec![0u8; 6144];
        for (index, id) in [*b"BEA01", *nsr, *b"TEA01"].iter().enumerate() {
            let base = index * 2048;
            region[base] = 0x00;
            region[base + 1..base + 6].copy_from_slice(id);
            region[base + 6] = 0x01;
        }
        region
    }

    /// Anchor block with a main extent (`MAIN_AT`, 8 blocks) and no
    /// reserve, CRC fixed.
    fn anchor() -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[16..20].copy_from_slice(&(8 * SIZE).to_le_bytes());
        block[20..24].copy_from_slice(&MAIN_AT.to_le_bytes());
        stamp_tag(&mut block, 2, (SIZE - 16) as u16, ANCHOR_AT);
        block
    }

    /// Primary body: zeroes past the tag.
    fn primary(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        stamp_tag(&mut block, 1, (SIZE - 16) as u16, lbn);
        block
    }

    /// Partition body for number 0 at `PART_AT`, contents `+NSR03`.
    fn partition(lbn: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[22..24].copy_from_slice(&0u16.to_le_bytes());
        block[25..31].copy_from_slice(b"+NSR03");
        block[188..192].copy_from_slice(&PART_AT.to_le_bytes());
        block[192..196].copy_from_slice(&900u32.to_le_bytes());
        stamp_tag(&mut block, 5, (SIZE - 16) as u16, lbn);
        block
    }

    /// Logical volume body: label `LABEL`, revision 2.01, one type-1 map
    /// to partition 0, file set at partition-relative block `fsd`.
    fn logical(lbn: u32, fsd: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[84] = 8;
        block[85..90].copy_from_slice(b"LABEL");
        block[84 + 127] = 6;
        block[212..216].copy_from_slice(&SIZE.to_le_bytes());
        block[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        block[240..242].copy_from_slice(&0x0201u16.to_le_bytes());
        block[248..252].copy_from_slice(&SIZE.to_le_bytes());
        block[252..256].copy_from_slice(&fsd.to_le_bytes());
        block[264..268].copy_from_slice(&6u32.to_le_bytes());
        block[268..272].copy_from_slice(&1u32.to_le_bytes());
        block[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        stamp_tag(&mut block, 6, (446 - 16) as u16, lbn);
        block
    }

    fn skipped(lbn: u32, id: u16) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        stamp_tag(&mut block, id, (SIZE - 16) as u16, lbn);
        block
    }

    fn terminator(lbn: u32) -> Vec<u8> {
        skipped(lbn, 8)
    }

    /// File set block at partition-relative `fsd_rel` with the root ICB
    /// (one block, `root_rel`, reference 0).
    fn fsd(fsd_rel: u32, root_rel: u32) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[400..404].copy_from_slice(&SIZE.to_le_bytes());
        block[404..408].copy_from_slice(&root_rel.to_le_bytes());
        stamp_tag(&mut block, 256, (SIZE - 16) as u16, fsd_rel);
        block
    }

    /// Extended file entry with `data` embedded (information length =
    /// data length), claiming partition-relative `rel`.
    fn ext_entry(rel: u32, data: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; SIZE as usize];
        block[16 + 18..16 + 20].copy_from_slice(&3u16.to_le_bytes());
        block[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(data.len() as u32).to_le_bytes());
        block[216..216 + data.len()].copy_from_slice(data);
        stamp_tag(&mut block, 266, (SIZE - 16) as u16, rel);
        block
    }

    /// One FID record: characteristics `char`, ICB (one block, `lbn`),
    /// `name` bytes, location `loc`, CRC fixed, padded to 4.
    fn fid_record(characteristics: u8, lbn: u32, name: &[u8], loc: u32) -> Vec<u8> {
        let body = 38 + name.len();
        let total = body + (4 - body % 4) % 4;
        let mut record = vec![0u8; total];
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18] = characteristics;
        record[19] = name.len() as u8;
        record[20..24].copy_from_slice(&SIZE.to_le_bytes());
        record[24..28].copy_from_slice(&lbn.to_le_bytes());
        record[38..38 + name.len()].copy_from_slice(name);
        stamp_tag(&mut record, 257, (total - 16) as u16, loc);
        record
    }

    /// Full synthetic volume: recognition, anchor, six-descriptor main
    /// sequence (primary, logical with FSD at relative 8, partition,
    /// unallocated, implementation use, terminator), file set at absolute
    /// `PART_AT + 8` and root entry at `PART_AT + 10` embedding `root`.
    /// Layout sketch (512-byte blocks): anchor 256, main 96..104, FSD
    /// 265, root entry 267.
    fn full_volume(root: &[u8]) -> VecVolume {
        let fsd_rel = 8u32;
        let root_rel = 10u32;
        let total_blocks = PART_AT + 16;
        let mut volume = VecVolume::new(u64::from(total_blocks) * u64::from(SIZE), 512)
            .expect("the fixture fits in RAM");
        let recognition = recognition(b"NSR03");
        volume
            .write_all_at(32768, &recognition)
            .expect("the recognition fits");
        let mut put = |abs: u32, bytes: &[u8]| {
            volume
                .write_all_at(u64::from(abs) * u64::from(SIZE), bytes)
                .expect("the block fits");
        };
        put(ANCHOR_AT, &anchor());
        put(96, &primary(96));
        put(97, &logical(97, fsd_rel));
        put(98, &partition(98));
        put(99, &skipped(99, 7));
        put(100, &skipped(100, 4));
        put(101, &terminator(101));
        put(PART_AT + fsd_rel, &fsd(fsd_rel, root_rel));
        put(PART_AT + root_rel, &ext_entry(root_rel, root));
        volume
    }

    /// Root data with a parent plus one file (`f.txt`, ICB at relative
    /// 11) and one subdirectory (`D`, ICB at relative 12), all located in
    /// the root block (relative 10).
    fn root_data() -> Vec<u8> {
        let mut data = fid_record(0x0A, 10, &[], 10);
        data.extend_from_slice(&fid_record(
            0x00,
            11,
            &[8, b'f', b'.', b't', b'x', b't'],
            10,
        ));
        data.extend_from_slice(&fid_record(0x02, 12, &[8, b'D'], 10));
        data
    }

    fn open_root(root: &[u8]) -> UdfReader {
        UdfReader::open(Box::new(full_volume(root))).expect("the synthetic volume opens")
    }

    #[test]
    fn open_reports_label_revision_nsr_and_blocks() {
        let reader = open_root(&root_data());
        assert_eq!(reader.volume_label(), "LABEL");
        assert_eq!(reader.udf_revision(), "2.01");
        assert_eq!(reader.nsr(), Nsr::Nsr03);
        assert_eq!(reader.block_size(), SIZE);
        assert_eq!(reader.partition_number(), 0);
        assert_eq!(reader.partition_start(), PART_AT);
        assert_eq!(reader.partition_length(), 900);
        assert_eq!(reader.fsd().root_icb.lbn, 10);
        assert_eq!(
            reader.total_bytes(),
            u64::from(PART_AT + 16) * u64::from(SIZE)
        );
    }

    #[test]
    fn root_listing_skips_the_parent() {
        let reader = open_root(&root_data());
        let root = reader.root();
        assert_eq!(root.name, "");
        assert!(root.is_directory);
        let entries = reader.read_dir(&root).expect("the root lists");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "f.txt");
        assert!(!entries[0].is_directory);
        assert_eq!(entries[0].icb.lbn, 11);
        assert_eq!(entries[0].file_version, 1);
        assert_eq!(entries[1].name, "D");
        assert!(entries[1].is_directory);
        assert_eq!(entries[1].icb.lbn, 12);
    }

    #[test]
    fn nsr02_opens_too() {
        let mut volume = full_volume(&root_data());
        let region = recognition(b"NSR02");
        volume
            .write_all_at(32768, &region)
            .expect("the NSR02 recognition fits");
        let reader = UdfReader::open(Box::new(volume)).expect("NSR02 opens");
        assert_eq!(reader.nsr(), Nsr::Nsr02);
    }

    #[test]
    fn bad_recognition_identifier_refuses() {
        let mut volume = full_volume(&root_data());
        let region = recognition(b"XXX01");
        volume
            .write_all_at(32768, &region)
            .expect("the bad recognition fits");
        let error = UdfReader::open(Box::new(volume)).expect_err("XXX01 refuses");
        let text = error.to_string();
        assert!(text.contains("34816"), "{text}");
        assert!(text.contains("XXX01"), "{text}");
    }

    #[test]
    fn short_store_refuses_before_any_parse() {
        let volume = VecVolume::new(100, 512).expect("100 bytes fit");
        let error = UdfReader::open(Box::new(volume)).expect_err("100 bytes refuse");
        let text = error.to_string();
        assert!(text.contains("38912"), "{text}");
    }

    #[test]
    fn compression_id_3_in_a_name_refuses() {
        let mut data = fid_record(0x0A, 10, &[], 10);
        data.extend_from_slice(&fid_record(0x00, 11, &[3, b'x'], 10));
        let reader = open_root(&data);
        let error = reader
            .read_dir(&reader.root())
            .expect_err("compression id 3 refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains("offset"), "{text}");
    }

    #[test]
    fn resolve_icb_maps_through_the_partition() {
        let reader = open_root(&root_data());
        let icb = LongAd {
            extent_length: SIZE,
            lbn: 10,
            partition_ref: 0,
        };
        assert_eq!(
            reader.resolve_icb(&icb).expect("the ICB resolves"),
            (PART_AT + 10, SIZE)
        );
        let bad = LongAd {
            extent_length: SIZE,
            lbn: 10,
            partition_ref: 4,
        };
        let error = reader.resolve_icb(&bad).expect_err("reference 4 refuses");
        assert!(error.to_string().contains('4'), "{:?}", error);
    }
}
