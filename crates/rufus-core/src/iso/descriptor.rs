//! Volume-descriptor sequence at sector 16 (S14, slice 1).
//!
//! *Measured* — ECMA-119 section 8: one 2048-byte sector per descriptor,
//! the type byte at 0, `CD001` at bytes 1..6, version 1 at byte 6. Type 1
//! (primary) and type 2 (supplementary) share the shape below: the
//! 32-byte system identifier at 8..40, the 32-byte volume identifier at
//! 40..72, the volume space size as a both-endian word at 80..88, the
//! set size and sequence number as both-endian words at 120..128, the
//! logical block size as a both-endian 16-bit word at 128..132, and the 34-byte
//! root directory record at 156..190. The supplementary descriptor alone
//! carries the 32-byte escape-sequences field at 88..120, whose `%/@`,
//! `%/C`, `%/E` openings mark Joliet levels 1-3. Type 0 (boot record)
//! carries the boot system identifier at 7..39 and the boot identifier at
//! 39..71; type 255 (terminator) ends the sequence.
//!
//! *Inferred* — that real mastering tools emit the same shapes (the
//! slice report says plainly whether the `isoinfo` cross-check ran),
//! and that logical block sizes other than 2048 never occur in inputs
//! worth reading: the reader addresses 2048-byte sectors throughout, so
//! any other block size is refused with the value named.
//!
//! Slice 2 owns Joliet name decoding and the multi-extent join; this
//! slice only parses the supplementary header, detects the Joliet level
//! from the escape sequences, and keeps the descriptor.

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::FIRST_DESCRIPTOR_SECTOR;
use crate::iso::MAX_DESCRIPTORS;
use crate::iso::SECTOR_BYTES_U64;
use crate::iso::cache::SectorCache;
use crate::iso::record::DirRecord;
use crate::iso::record::parse_record;
use crate::text::device_text;

/// Boot record descriptor type.
pub const TYPE_BOOT: u8 = 0;
/// Primary volume descriptor type.
pub const TYPE_PRIMARY: u8 = 1;
/// Supplementary volume descriptor type.
pub const TYPE_SUPPLEMENTARY: u8 = 2;
/// Volume descriptor set terminator type.
pub const TYPE_TERMINATOR: u8 = 255;

/// Standards identifier every descriptor must read at bytes 1..6.
const IDENTIFIER: &[u8; 5] = b"CD001";
/// Descriptor version byte every descriptor must read at byte 6.
const DESCRIPTOR_VERSION: u8 = 1;

/// Offset of the 32-byte volume identifier in primary/supplementary
/// descriptors.
const VOLUME_ID_AT: usize = 40;
/// Length of the volume identifier field.
const VOLUME_ID_LEN: usize = 32;
/// Offset of the root directory record in primary/supplementary
/// descriptors.
const ROOT_AT: usize = 156;
/// Length of the root directory record.
const ROOT_LEN: usize = 34;
/// Offset of the 32-byte escape-sequences field in supplementary
/// descriptors.
const ESCAPE_AT: usize = 88;
/// Length of the escape-sequences field.
const ESCAPE_LEN: usize = 32;

/// Joliet level 1 escape opening (`%/@"` as bytes).
const JOLIET_1: &[u8; 3] = b"%/@";
/// Joliet level 2 escape opening (`%/C"` as bytes).
const JOLIET_2: &[u8; 3] = b"%/C";
/// Joliet level 3 escape opening (`%/E"` as bytes).
const JOLIET_3: &[u8; 3] = b"%/E";

/// Primary volume descriptor: the volume label, the volume size, and the
/// root of the primary tree.
#[derive(Debug, Clone)]
pub struct PrimaryDescriptor {
    /// Volume identifier (32 bytes, trailing spaces trimmed).
    pub label: String,
    /// Volume space size in logical sectors.
    pub volume_space_size: u32,
    /// Root directory record of the primary tree.
    pub root: DirRecord,
}

/// Supplementary volume descriptor: the header slice 1 parses plus the
/// escape sequences slice 2 decodes names with. Joliet name decoding is
/// deliberately not here.
#[derive(Debug, Clone)]
pub struct SupplementaryDescriptor {
    /// Volume identifier (32 bytes, trailing spaces trimmed).
    pub label: String,
    /// Raw 32-byte escape-sequences field, kept for slice 2.
    pub escape_sequences: [u8; ESCAPE_LEN],
    /// Joliet level when the escape sequences open with `%/@`, `%/C` or
    /// `%/E` (levels 1, 2, 3); `None` for non-Joliet supplementary
    /// descriptors, whose names this slice reads as plain bytes.
    pub joliet_level: Option<u8>,
    /// Root directory record of the supplementary tree (kept for slice
    /// 2, which walks it with Joliet decoding).
    pub root: DirRecord,
}

/// Boot record (type 0): accepted and retained, never executed. El
/// Torito handling belongs to a later slice.
#[derive(Debug, Clone)]
pub struct BootRecord {
    /// Boot system identifier (32 bytes, trailing spaces trimmed).
    pub system_id: String,
    /// Boot identifier (32 bytes, trailing spaces trimmed).
    pub boot_id: String,
}

/// The parsed descriptor sequence: exactly one primary, the kept
/// supplementary descriptors, and the boot records.
#[derive(Debug, Clone)]
pub struct DescriptorSet {
    /// The one primary descriptor (a missing or duplicated primary is
    /// refused).
    pub primary: PrimaryDescriptor,
    /// Supplementary descriptors in sequence order, kept for slice 2.
    pub supplementary: Vec<SupplementaryDescriptor>,
    /// Boot records in sequence order.
    pub boot_records: Vec<BootRecord>,
}

/// One byte at `at` of descriptor `sector_no`, refused naming the byte
/// position and the sector when the sector ends first (which cannot
/// happen for whole sectors, but keeps every access checked).
fn byte_at(sector: &[u8], at: usize, sector_no: u32, field: &str) -> Result<u8> {
    sector.get(at).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} ends before its {field} at byte {at}"
        ))
    })
}

/// Both-endian 16-bit word at `le_at` (little half) and `be_at` (big
/// half); the halves must agree, else refused naming the field, the
/// sector and both numbers.
fn both16(sector: &[u8], le_at: usize, be_at: usize, sector_no: u32, field: &str) -> Result<u16> {
    let lo = u16::from_le_bytes([
        byte_at(sector, le_at, sector_no, field)?,
        byte_at(sector, le_at + 1, sector_no, field)?,
    ]);
    let hi = u16::from_be_bytes([
        byte_at(sector, be_at, sector_no, field)?,
        byte_at(sector, be_at + 1, sector_no, field)?,
    ]);
    if lo != hi {
        return Err(CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} {field} endian halves disagree: \
             little-endian {lo} against big-endian {hi}"
        )));
    }
    Ok(lo)
}

/// Both-endian 32-bit word, same contract as [`both16`].
fn both32(sector: &[u8], le_at: usize, be_at: usize, sector_no: u32, field: &str) -> Result<u32> {
    let lo = u32::from_le_bytes([
        byte_at(sector, le_at, sector_no, field)?,
        byte_at(sector, le_at + 1, sector_no, field)?,
        byte_at(sector, le_at + 2, sector_no, field)?,
        byte_at(sector, le_at + 3, sector_no, field)?,
    ]);
    let hi = u32::from_be_bytes([
        byte_at(sector, be_at, sector_no, field)?,
        byte_at(sector, be_at + 1, sector_no, field)?,
        byte_at(sector, be_at + 2, sector_no, field)?,
        byte_at(sector, be_at + 3, sector_no, field)?,
    ]);
    if lo != hi {
        return Err(CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} {field} endian halves disagree: \
             little-endian {lo} against big-endian {hi}"
        )));
    }
    Ok(lo)
}

/// Text field of `len` bytes at `at`: trailing spaces and NULs trimmed,
/// non-UTF-8 decoded lossily (primary fields are ASCII by the standard;
/// anything else survives as the Unicode replacement character rather
/// than failing the open).
fn text_field(sector: &[u8], at: usize, len: usize, sector_no: u32, field: &str) -> Result<String> {
    let end = at.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} {field} overflows the offset arithmetic"
        ))
    })?;
    let bytes = sector.get(at..end).ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} ends inside its {field} at bytes {at}..{end}"
        ))
    })?;
    let mut trimmed = bytes;
    while trimmed.last() == Some(&b' ') || trimmed.last() == Some(&0) {
        match trimmed.get(..trimmed.len() - 1) {
            Some(rest) => trimmed = rest,
            None => break,
        }
    }
    Ok(String::from_utf8_lossy(trimmed).into_owned())
}

/// Display form of a raw identifier for refusals: lossy text through the
/// one device-text sanitiser, so refusals stay ASCII whatever bytes the
/// image holds.
fn display_id(bytes: &[u8]) -> String {
    device_text(&String::from_utf8_lossy(bytes))
}

/// Check the descriptor header shared by every type: `CD001` at bytes
/// 1..6 and version 1 at byte 6. A wrong identifier or version is
/// refused naming the sector and what was found.
fn check_header(sector: &[u8], sector_no: u32) -> Result<()> {
    let identifier = sector.get(1..6).ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} ends before its identifier at bytes 1..6"
        ))
    })?;
    if identifier != IDENTIFIER {
        return Err(CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} reads `{}` not `CD001`: \
             bytes 1..6 must read the CD001 identifier",
            display_id(identifier)
        )));
    }
    let version = byte_at(sector, 6, sector_no, "version")?;
    if version != DESCRIPTOR_VERSION {
        return Err(CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} has version {version} not 1: \
             byte 6 must read 1"
        )));
    }
    Ok(())
}

/// Logical block size both-endian 16-bit word (ECMA-119 8.4.11, format
/// 7.2.2 — two bytes each way, unlike the 32-bit volume space size):
/// verified like every word, then required to be 2048, because the
/// reader addresses 2048-byte sectors throughout and any other size
/// would silently mis-address extents.
fn block_size(sector: &[u8], sector_no: u32) -> Result<()> {
    let size = both16(sector, 128, 130, sector_no, "logical block size")?;
    if size != SECTOR_BYTES_U64 as u16 {
        return Err(CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} has logical block size {size} not 2048: \
             only 2048 byte sectors are supported"
        )));
    }
    Ok(())
}

/// Root directory record at bytes 156..190, parsed with the shared
/// record parser (its errors arrive naming the sector).
fn root_record(sector: &[u8], sector_no: u32) -> Result<DirRecord> {
    let end = ROOT_AT.checked_add(ROOT_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} root record overflows the offset arithmetic"
        ))
    })?;
    let bytes = sector.get(ROOT_AT..end).ok_or_else(|| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} ends inside its root record \
             at bytes {ROOT_AT}..{end}"
        ))
    })?;
    parse_record(bytes).map_err(|error| {
        CoreError::invalid(format!(
            "volume descriptor at sector {sector_no} root record: {error}"
        ))
    })
}

/// Parse a primary descriptor body (header already checked).
fn parse_primary(sector: &[u8], sector_no: u32) -> Result<PrimaryDescriptor> {
    let label = text_field(
        sector,
        VOLUME_ID_AT,
        VOLUME_ID_LEN,
        sector_no,
        "volume identifier",
    )?;
    let volume_space_size = both32(sector, 80, 84, sector_no, "volume space size")?;
    let _set_size = both16(sector, 120, 122, sector_no, "volume set size")?;
    let _sequence = both16(sector, 124, 126, sector_no, "volume sequence number")?;
    block_size(sector, sector_no)?;
    let root = root_record(sector, sector_no)?;
    Ok(PrimaryDescriptor {
        label,
        volume_space_size,
        root,
    })
}

/// Joliet level from the escape-sequences field: `%/@`, `%/C`, `%/E`
/// open levels 1, 2, 3; anything else is not Joliet.
fn joliet_level(escape: &[u8; ESCAPE_LEN]) -> Option<u8> {
    let head = escape.get(..3)?;
    if head == JOLIET_1 {
        Some(1)
    } else if head == JOLIET_2 {
        Some(2)
    } else if head == JOLIET_3 {
        Some(3)
    } else {
        None
    }
}

/// Parse a supplementary descriptor body (header already checked): the
/// header, the escape sequences with the Joliet level, and the root
/// record kept for slice 2. Joliet name decoding is deliberately not
/// here.
fn parse_supplementary(sector: &[u8], sector_no: u32) -> Result<SupplementaryDescriptor> {
    let label = text_field(
        sector,
        VOLUME_ID_AT,
        VOLUME_ID_LEN,
        sector_no,
        "volume identifier",
    )?;
    let _space = both32(sector, 80, 84, sector_no, "volume space size")?;
    let escape_bytes = sector
        .get(ESCAPE_AT..ESCAPE_AT + ESCAPE_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "volume descriptor at sector {sector_no} ends inside its escape sequences \
             at bytes {ESCAPE_AT}..{}",
                ESCAPE_AT + ESCAPE_LEN
            ))
        })?;
    let mut escape_sequences = [0u8; ESCAPE_LEN];
    escape_sequences.copy_from_slice(escape_bytes);
    let level = joliet_level(&escape_sequences);
    let _set_size = both16(sector, 120, 122, sector_no, "volume set size")?;
    let _sequence = both16(sector, 124, 126, sector_no, "volume sequence number")?;
    block_size(sector, sector_no)?;
    let root = root_record(sector, sector_no)?;
    Ok(SupplementaryDescriptor {
        label,
        escape_sequences,
        joliet_level: level,
        root,
    })
}

/// Parse a boot record body (header already checked): the two 32-byte
/// identifiers, retained and never executed.
fn parse_boot(sector: &[u8], sector_no: u32) -> Result<BootRecord> {
    let system_id = text_field(sector, 7, 32, sector_no, "boot system identifier")?;
    let boot_id = text_field(sector, 39, 32, sector_no, "boot identifier")?;
    Ok(BootRecord { system_id, boot_id })
}

/// Read the descriptor sequence starting at sector 16, one sector at a
/// time: primary, supplementary (kept), boot records (kept), until the
/// terminator. Stops at the terminator; refuses a sequence that runs off
/// the volume end (no terminator before the sectors run out), a wrong
/// identifier or version, an unknown descriptor type, a missing primary,
/// a duplicated primary, or more than [`MAX_DESCRIPTORS`] descriptors
/// without a terminator.
pub fn read_descriptor_set(cache: &mut SectorCache) -> Result<DescriptorSet> {
    let mut primary: Option<PrimaryDescriptor> = None;
    let mut supplementary = Vec::new();
    let mut boot_records = Vec::new();
    let mut sector_no = FIRST_DESCRIPTOR_SECTOR;
    let mut seen: usize = 0;
    loop {
        if seen >= MAX_DESCRIPTORS {
            return Err(CoreError::invalid(format!(
                "volume descriptor sequence has no terminator after {seen} descriptors \
                 from sector {FIRST_DESCRIPTOR_SECTOR}: at most {MAX_DESCRIPTORS} are read"
            )));
        }
        let sector: [u8; crate::iso::SECTOR_BYTES] =
            *cache.read_sector(sector_no).map_err(|error| {
                CoreError::invalid(format!(
                    "volume descriptor at sector {sector_no} is unreadable ({error}): \
                     the descriptor sequence runs off the volume end with no terminator"
                ))
            })?;
        seen += 1;
        let kind = byte_at(&sector, 0, sector_no, "type")?;
        check_header(&sector, sector_no)?;
        match kind {
            TYPE_BOOT => {
                boot_records.push(parse_boot(&sector, sector_no)?);
            }
            TYPE_PRIMARY => {
                if primary.is_some() {
                    return Err(CoreError::invalid(format!(
                        "second primary descriptor at sector {sector_no}: \
                         the sequence must hold exactly one primary descriptor"
                    )));
                }
                primary = Some(parse_primary(&sector, sector_no)?);
            }
            TYPE_SUPPLEMENTARY => {
                supplementary.push(parse_supplementary(&sector, sector_no)?);
            }
            TYPE_TERMINATOR => match primary {
                Some(first) => {
                    return Ok(DescriptorSet {
                        primary: first,
                        supplementary,
                        boot_records,
                    });
                }
                None => {
                    return Err(CoreError::invalid(format!(
                        "volume descriptor terminator at sector {sector_no} ends a sequence \
                             with no primary descriptor"
                    )));
                }
            },
            other => {
                return Err(CoreError::invalid(format!(
                    "unknown volume descriptor type {other} at sector {sector_no}: \
                     only boot (0), primary (1), supplementary (2) and terminator (255) \
                     are supported"
                )));
            }
        }
        sector_no = sector_no.checked_add(1).ok_or_else(|| {
            CoreError::invalid(format!(
                "volume descriptor sequence overflows the sector number at sector {sector_no}"
            ))
        })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::iso::SECTOR_BYTES;
    use crate::iso::record::DATE_LEN;
    use crate::iso::record::FLAG_DIRECTORY;

    /// Minimal primary-descriptor sector: type, `CD001`, version 1, label
    /// `TEST LABEL`, space size 32, set size 1, sequence 1, block size
    /// 2048, and a 34-byte root record at 156 (extent 20, length 2048).
    /// Synthetic layout only, claims nothing about real mastering tools.
    fn primary_sector(label: &str) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_PRIMARY;
        sector[1..6].copy_from_slice(IDENTIFIER);
        sector[6] = DESCRIPTOR_VERSION;
        let label_bytes = label.as_bytes();
        let take = label_bytes.len().min(VOLUME_ID_LEN);
        sector[VOLUME_ID_AT..VOLUME_ID_AT + take].copy_from_slice(&label_bytes[..take]);
        for byte in sector
            .iter_mut()
            .skip(VOLUME_ID_AT + take)
            .take(VOLUME_ID_LEN - take)
        {
            *byte = b' ';
        }
        sector[80..84].copy_from_slice(&32u32.to_le_bytes());
        sector[84..88].copy_from_slice(&32u32.to_be_bytes());
        sector[120..122].copy_from_slice(&1u16.to_le_bytes());
        sector[122..124].copy_from_slice(&1u16.to_be_bytes());
        sector[124..126].copy_from_slice(&1u16.to_le_bytes());
        sector[126..128].copy_from_slice(&1u16.to_be_bytes());
        sector[128..130].copy_from_slice(&2048u16.to_le_bytes());
        sector[130..132].copy_from_slice(&2048u16.to_be_bytes());
        write_root(&mut sector, 20, 2048);
        sector
    }

    /// Write the 34-byte root record at bytes 156..190 of `sector`.
    fn write_root(sector: &mut [u8; SECTOR_BYTES], extent: u32, len: u32) {
        let base = ROOT_AT;
        sector[base] = ROOT_LEN as u8;
        sector[base + 1] = 0;
        sector[base + 2..base + 6].copy_from_slice(&extent.to_le_bytes());
        sector[base + 6..base + 10].copy_from_slice(&extent.to_be_bytes());
        sector[base + 10..base + 14].copy_from_slice(&len.to_le_bytes());
        sector[base + 14..base + 18].copy_from_slice(&len.to_be_bytes());
        sector[base + 25] = FLAG_DIRECTORY;
        sector[base + 28..base + 30].copy_from_slice(&1u16.to_le_bytes());
        sector[base + 30..base + 32].copy_from_slice(&1u16.to_be_bytes());
        sector[base + 32] = 1;
        sector[base + 33] = 0;
    }

    /// Supplementary-descriptor sector with the given escape opening.
    fn supplementary_sector(escape: &[u8]) -> [u8; SECTOR_BYTES] {
        let mut sector = primary_sector("SUPP");
        sector[0] = TYPE_SUPPLEMENTARY;
        sector[7] = 0;
        for byte in sector.iter_mut().skip(ESCAPE_AT).take(ESCAPE_LEN) {
            *byte = 0;
        }
        let take = escape.len().min(ESCAPE_LEN);
        sector[ESCAPE_AT..ESCAPE_AT + take].copy_from_slice(&escape[..take]);
        sector
    }

    /// Full-width boot identifier for the fixture: 32 bytes with no
    /// trailing space, so a one-byte read shift cannot hide behind the
    /// trailing-space trim (a short identifier starting with a letter
    /// reads identically from either offset once trimmed).
    const BOOT_ID: &[u8; 32] = b"EL TORITO BOOT ID SHIFT TEST 012";

    /// Boot-record sector with the two identifiers filled, plus a `!`
    /// sentinel at byte 71 (the first byte of boot system use, which a
    /// shifted read would swallow into the identifier).
    fn boot_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_BOOT;
        sector[1..6].copy_from_slice(IDENTIFIER);
        sector[6] = DESCRIPTOR_VERSION;
        sector[7..7 + 11].copy_from_slice(b"EL TORITO  ");
        sector[39..39 + 32].copy_from_slice(BOOT_ID);
        sector[71] = b'!';
        sector
    }

    /// Terminator sector.
    fn terminator_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_TERMINATOR;
        sector[1..6].copy_from_slice(IDENTIFIER);
        sector[6] = DESCRIPTOR_VERSION;
        sector
    }

    /// Image holding `descriptors` from sector 16 on, sized to `sectors`
    /// total, boxed for the cache.
    fn image_with(descriptors: &[&[u8; SECTOR_BYTES]], sectors: u32) -> SectorCache {
        let mut volume =
            VecVolume::new(u64::from(sectors) * SECTOR_BYTES as u64, 512).expect("fits in RAM");
        for (index, descriptor) in descriptors.iter().enumerate() {
            let offset = u64::from(FIRST_DESCRIPTOR_SECTOR) * SECTOR_BYTES as u64
                + index as u64 * SECTOR_BYTES as u64;
            volume
                .write_all_at(offset, *descriptor)
                .expect("the descriptor fits");
        }
        SectorCache::new(Box::new(volume))
    }

    #[test]
    fn primary_supplementary_boot_and_terminator_parse() {
        let primary = primary_sector("TEST LABEL");
        let supplementary = supplementary_sector(b"%/E");
        let boot = boot_sector();
        let terminator = terminator_sector();
        let mut cache = image_with(&[&primary, &supplementary, &boot, &terminator], 32);
        let set = read_descriptor_set(&mut cache).expect("the four-descriptor set parses");
        assert_eq!(set.primary.label, "TEST LABEL");
        assert_eq!(set.primary.volume_space_size, 32);
        assert_eq!(set.primary.root.extent_lba, 20);
        assert_eq!(set.primary.root.data_len, 2048);
        assert_eq!(set.supplementary.len(), 1);
        assert_eq!(set.supplementary[0].joliet_level, Some(3));
        assert_eq!(
            set.supplementary[0].escape_sequences[..3],
            [b'%', b'/', b'E']
        );
        assert_eq!(set.boot_records.len(), 1);
        assert_eq!(set.boot_records[0].system_id, "EL TORITO");
        assert_eq!(set.boot_records[0].boot_id.as_bytes(), BOOT_ID);
    }

    #[test]
    fn boot_identifier_reads_bytes_39_to_71() {
        let sector = boot_sector();
        let record = parse_boot(&sector, 17).expect("the boot record parses");
        assert_eq!(record.system_id, "EL TORITO");
        // Byte-exact full width: a read shifted to 40..72 would drop the
        // leading `E` and swallow the `!` sentinel at byte 71 (boot
        // system use), failing both assertions below.
        assert_eq!(record.boot_id.as_bytes(), BOOT_ID);
        assert!(
            !record.boot_id.contains('!'),
            "byte 71 leaked into the identifier: {}",
            record.boot_id
        );
    }

    #[test]
    fn joliet_levels_detected_from_the_escape_opening() {
        for (escape, level) in [
            (b"%/@".as_slice(), Some(1)),
            (b"%/C".as_slice(), Some(2)),
            (b"%/E".as_slice(), Some(3)),
            (b"".as_slice(), None),
        ] {
            let supplementary = supplementary_sector(escape);
            let parsed = parse_supplementary(&supplementary, 17).expect("the supplementary parses");
            assert_eq!(parsed.joliet_level, level, "escape {escape:?}");
        }
    }

    #[test]
    fn wrong_cd001_refused() {
        let mut primary = primary_sector("X");
        primary[1..6].copy_from_slice(b"XX001");
        let terminator = terminator_sector();
        let mut cache = image_with(&[&primary, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("XX001 refuses");
        let text = error.to_string();
        assert!(text.contains("16"), "{text}");
        assert!(text.contains("CD001"), "{text}");
    }

    #[test]
    fn missing_terminator_refused_at_the_volume_end() {
        let primary = primary_sector("X");
        let mut cache = image_with(&[&primary], 17);
        let error = read_descriptor_set(&mut cache).expect_err("no terminator refuses");
        let text = error.to_string();
        assert!(text.contains("17"), "{text}");
    }

    #[test]
    fn missing_primary_refused_at_the_terminator() {
        let boot = boot_sector();
        let terminator = terminator_sector();
        let mut cache = image_with(&[&boot, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("no primary refuses");
        let text = error.to_string();
        assert!(text.contains("no primary"), "{text}");
    }

    #[test]
    fn duplicate_primary_refused() {
        let first = primary_sector("ONE");
        let second = primary_sector("TWO");
        let terminator = terminator_sector();
        let mut cache = image_with(&[&first, &second, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("two primaries refuse");
        let text = error.to_string();
        assert!(text.contains("17"), "{text}");
        assert!(text.contains("primary"), "{text}");
    }

    #[test]
    fn endian_mismatch_names_both_numbers() {
        let mut primary = primary_sector("X");
        primary[80] = 33;
        let terminator = terminator_sector();
        let mut cache = image_with(&[&primary, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("halves disagree");
        let text = error.to_string();
        assert!(text.contains("33"), "{text}");
        assert!(text.contains("32"), "{text}");
    }

    #[test]
    fn unknown_descriptor_type_refused() {
        let mut primary = primary_sector("X");
        primary[0] = 3;
        let terminator = terminator_sector();
        let mut cache = image_with(&[&primary, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("type 3 refuses");
        let text = error.to_string();
        assert!(text.contains("3"), "{text}");
        assert!(text.contains("16"), "{text}");
    }

    #[test]
    fn non_2048_block_size_refused() {
        let mut primary = primary_sector("X");
        primary[128..130].copy_from_slice(&512u16.to_le_bytes());
        primary[130..132].copy_from_slice(&512u16.to_be_bytes());
        let terminator = terminator_sector();
        let mut cache = image_with(&[&primary, &terminator], 32);
        let error = read_descriptor_set(&mut cache).expect_err("512 byte blocks refuse");
        let text = error.to_string();
        assert!(text.contains("512"), "{text}");
        assert!(text.contains("2048"), "{text}");
    }

    #[test]
    fn label_trims_trailing_spaces() {
        let primary = primary_sector("PADDED");
        let parsed = parse_primary(&primary, 16).expect("the primary parses");
        assert_eq!(parsed.label, "PADDED");
        assert_eq!(parsed.root.recorded.len(), DATE_LEN);
    }
}
