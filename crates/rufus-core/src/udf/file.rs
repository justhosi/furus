//! File set descriptor, file entries and directory data (S15, slice 1).
//!
//! The logical volume's file set address leads to the file set descriptor
//! (tag 256), whose root directory ICB (a long address) leads to the root
//! file entry. Every directory — the root here, any directory for slice
//! 2's reuse — reads the same way: resolve the ICB, parse the file entry,
//! join its allocation extents (or take the embedded bytes), and hand the
//! first `information length` bytes to [`fid`](super::fid).
//!
//! *Measured* — on the `mkudffs --udfrev=0x0201` images (see the slice
//! report): the file set descriptor's tag location is its
//! partition-relative block number; the root ICB has length one block and
//! partition reference 0; its target is an *extended* file entry (tag
//! 266) with ICB flags 3 (embedded: the directory bytes sit directly in
//! the descriptor, `length of allocation descriptors` of them after the
//! extended attributes); the empty root embeds one 40-byte record, the
//! populated root five records in 220 bytes.
//!
//! *Inferred* — the plain file entry offsets (tag 261: extended-attribute
//! area at 176, lengths at 168/172 — no measured image carries one, so
//! the offsets are spec text, ECMA-167 4/14.9), the extended entry offsets
//! past the measured lengths (spec text, ECMA-167 4/14.17), short and
//! long allocation descriptor shapes (spec text: all measured directories
//! are embedded), and the extent-type bits (only recorded extents are
//! accepted; anything else refuses).

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::udf::LongAd;
use crate::udf::MAX_DIR_BYTES;
use crate::udf::MAX_DIR_EXTENTS;
use crate::udf::PartitionDesc;
use crate::udf::le_u16;
use crate::udf::le_u32;
use crate::udf::le_u64;
use crate::udf::parse_long_ad;
use crate::udf::read_block;
use crate::udf::read_bytes;
use crate::udf::tag;

/// File set descriptor tag id.
const TAG_FSD: u16 = 256;
/// File entry tag id.
const TAG_FE: u16 = 261;
/// Extended file entry tag id (what `mkudffs` writes for directories).
const TAG_EXTFE: u16 = 266;

/// Offset of the root directory ICB in a file set descriptor.
const FSD_ROOT_AT: usize = 400;

/// Offset of the ICB flags in a file entry's ICB tag (tag is 16 bytes,
/// flags are the last 2 of the 20-byte ICB tag).
const FE_FLAGS_AT: usize = 16 + 18;
/// Offset of the information length (both entry shapes).
const FE_INFO_AT: usize = 56;
/// Allocation type mask of the ICB flags (bits 0-2).
const FE_AD_MASK: u16 = 7;
/// Short allocation descriptors: extents in the entry's own partition.
const AD_SHORT: u16 = 0;
/// Long allocation descriptors: extents with their own partition refs.
const AD_LONG: u16 = 1;
/// Extended allocation descriptors: refused (never seen, unsupported).
const AD_EXTENDED: u16 = 2;
/// Embedded data: the descriptor bytes after the extended attributes
/// *are* the file data.
const AD_EMBEDDED: u16 = 3;

/// Offset of the extended-attribute and allocation lengths in a plain
/// file entry (spec text — no measured sample).
const FE_LENGTHS_AT: usize = 168;
/// Offset of the extended-attribute area in a plain file entry.
const FE_EA_AT: usize = 176;
/// Offset of the extended-attribute and allocation lengths in an
/// extended file entry (measured: 0 and 40/280).
const EXT_LENGTHS_AT: usize = 208;
/// Offset of the extended-attribute area in an extended file entry.
const EXT_EA_AT: usize = 216;

/// Length of a short allocation descriptor (length, position).
const SHORT_AD_LEN: usize = 8;
/// Length of a long allocation descriptor (length, block, reference).
const LONG_AD_LEN: usize = 16;
/// Offset of the partition reference in a long allocation descriptor.
const LONG_AD_PART_AT: usize = 8;

/// Extent-type bits (top two bits of an allocation extent length).
const EXTENT_TYPE_SHIFT: u32 = 30;
/// Recorded and allocated: the only extent type with readable data.
const EXTENT_RECORDED: u32 = 0;

/// The file set descriptor as slice 1 reads it: the root directory ICB.
/// Everything else the descriptor carries (timestamps, identifiers, the
/// next extent, the system stream) belongs to later slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSetDescriptor {
    /// Long address of the root directory's file entry.
    pub root_icb: LongAd,
}

/// One parsed file entry: the allocation type with either the embedded
/// bytes or the raw allocation descriptors. Extended attributes are
/// skipped (their length only moves the data start); interpreting them
/// belongs to a later slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// True for an extended file entry (tag 266), false for tag 261.
    pub extended: bool,
    /// Information length: the valid data prefix in bytes.
    pub info_len: u64,
    /// Embedded file bytes (allocation type 3 only).
    pub embedded: Vec<u8>,
    /// Raw allocation descriptors (types 0 and 1 only).
    pub ads: Vec<AllocDesc>,
}

/// One raw allocation descriptor: the extent length with its address. The
/// extent-type bits must already be clear (recorded); anything else is
/// refused at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocDesc {
    /// Extent in the file entry's own partition.
    Short {
        /// Extent length in bytes (top two type bits clear).
        len: u32,
        /// Partition-relative block number of the extent.
        pos: u32,
    },
    /// Extent with its own partition reference.
    Long {
        /// Extent length in bytes (top two type bits clear).
        len: u32,
        /// Partition-relative block number of the extent.
        lbn: u32,
        /// Index into the logical volume's partition map table.
        part: u16,
    },
}

/// One collected data segment: the partition-relative block where it
/// starts (for file identifier tag-location checks) with its byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSeg {
    /// Partition-relative block number of the segment's first block.
    pub start: u32,
    /// Segment length in bytes.
    pub len: u64,
}

/// Read the file set descriptor at absolute block `abs_lbn` (whose
/// partition-relative number is `rel_lbn`): tag id 256, location matching
/// `rel_lbn`, a passing CRC, then the root ICB.
pub fn read_fsd(
    volume: &dyn Volume,
    size: u32,
    abs_lbn: u32,
    rel_lbn: u32,
) -> Result<FileSetDescriptor> {
    let total = volume.total_bytes();
    let block = read_block(volume, abs_lbn, size, total, "file set descriptor")?;
    let tag = tag::parse(&block, "file set descriptor")?;
    if tag.id != TAG_FSD {
        return Err(CoreError::invalid(format!(
            "file set descriptor at block {abs_lbn} has tag id {} not {TAG_FSD}",
            tag.id
        )));
    }
    if tag.location != rel_lbn {
        return Err(CoreError::invalid(format!(
            "file set descriptor at block {abs_lbn} claims tag location {} not the \
             partition-relative block {rel_lbn}",
            tag.location
        )));
    }
    tag::verify_crc(&block, &tag, "file set descriptor")?;
    Ok(FileSetDescriptor {
        root_icb: parse_long_ad(&block, FSD_ROOT_AT, "file set descriptor")?,
    })
}

/// Read the file entry at absolute block `abs_lbn` (partition-relative
/// `rel_lbn`): tag id 261 or 266, location matching `rel_lbn`, a passing
/// CRC, then the ICB flags, information length and allocation area.
/// Extended allocation descriptors (type 2) and unknown types refuse
/// naming the value.
pub fn read_file_entry(
    volume: &dyn Volume,
    size: u32,
    abs_lbn: u32,
    rel_lbn: u32,
) -> Result<FileEntry> {
    let total = volume.total_bytes();
    let block = read_block(volume, abs_lbn, size, total, "file entry")?;
    let tag = tag::parse(&block, "file entry")?;
    let extended = match tag.id {
        TAG_FE => false,
        TAG_EXTFE => true,
        other => {
            return Err(CoreError::invalid(format!(
                "file entry at block {abs_lbn} has tag id {other} not {TAG_FE} or \
                 {TAG_EXTFE}: refusing a non file entry"
            )));
        }
    };
    if tag.location != rel_lbn {
        return Err(CoreError::invalid(format!(
            "file entry at block {abs_lbn} claims tag location {} not the \
             partition-relative block {rel_lbn}",
            tag.location
        )));
    }
    tag::verify_crc(&block, &tag, "file entry")?;
    let what = format!("file entry at block {abs_lbn}");
    let flags = le_u16(&block, FE_FLAGS_AT, &what)?;
    let ad_type = flags & FE_AD_MASK;
    let info_len = le_u64(&block, FE_INFO_AT, &what)?;
    let (lengths_at, ea_at) = if extended {
        (EXT_LENGTHS_AT, EXT_EA_AT)
    } else {
        (FE_LENGTHS_AT, FE_EA_AT)
    };
    let ea_len = u64::from(le_u32(&block, lengths_at, &what)?);
    let ad_len = u64::from(le_u32(&block, lengths_at + 4, &what)?);
    let data_at = (ea_at as u64).checked_add(ea_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} extended attributes run past the arithmetic"
        ))
    })?;
    let data_end = data_at.checked_add(ad_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} allocation area of {ad_len} bytes overflows the arithmetic"
        ))
    })?;
    if data_end > u64::from(size) {
        return Err(CoreError::invalid(format!(
            "{what} allocation area of {ad_len} bytes past {ea_len} extended attribute bytes \
             runs past the {size} byte block"
        )));
    }
    match ad_type {
        AD_EMBEDDED => {
            let start = usize::try_from(data_at).map_err(|_| {
                CoreError::invalid(format!("{what} data offset {data_at} is not addressable"))
            })?;
            let end = usize::try_from(data_end).map_err(|_| {
                CoreError::invalid(format!("{what} data end {data_end} is not addressable"))
            })?;
            let embedded = block.get(start..end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} embedded data {start}..{end} runs past the block"
                ))
            })?;
            Ok(FileEntry {
                extended,
                info_len,
                embedded: embedded.to_vec(),
                ads: Vec::new(),
            })
        }
        AD_SHORT | AD_LONG => {
            let unit = if ad_type == AD_SHORT {
                SHORT_AD_LEN
            } else {
                LONG_AD_LEN
            } as u64;
            if !ad_len.is_multiple_of(unit) {
                return Err(CoreError::invalid(format!(
                    "{what} allocation area of {ad_len} bytes is not a multiple of the \
                     {unit} byte allocation descriptor"
                )));
            }
            let count = ad_len / unit;
            if count > MAX_DIR_EXTENTS as u64 {
                return Err(CoreError::invalid(format!(
                    "{what} claims {count} allocation descriptors past the \
                     {MAX_DIR_EXTENTS} extent cap"
                )));
            }
            let area = block
                .get(
                    usize::try_from(data_at).map_err(|_| {
                        CoreError::invalid(format!(
                            "{what} data offset {data_at} is not addressable"
                        ))
                    })?..usize::try_from(data_end).map_err(|_| {
                        CoreError::invalid(format!("{what} data end {data_end} is not addressable"))
                    })?,
                )
                .ok_or_else(|| {
                    CoreError::invalid(format!("{what} allocation area runs past the block"))
                })?;
            let mut ads = Vec::new();
            let mut at: usize = 0;
            while at < area.len() {
                let desc = area.get(at..at + unit as usize).ok_or_else(|| {
                    CoreError::invalid(format!("{what} allocation descriptor at {at} is truncated"))
                })?;
                let raw_len = le_u32(desc, 0, &what)?;
                let extent_type = raw_len >> EXTENT_TYPE_SHIFT;
                if extent_type != EXTENT_RECORDED {
                    return Err(CoreError::invalid(format!(
                        "{what} allocation descriptor at {at} has extent type {extent_type}: \
                         only recorded extents (type 0) carry readable data"
                    )));
                }
                let len = raw_len & 0x3FFF_FFFF;
                if ad_type == AD_SHORT {
                    ads.push(AllocDesc::Short {
                        len,
                        pos: le_u32(desc, 4, &what)?,
                    });
                } else {
                    ads.push(AllocDesc::Long {
                        len,
                        lbn: le_u32(desc, 4, &what)?,
                        part: le_u16(desc, LONG_AD_PART_AT, &what)?,
                    });
                }
                at = at.saturating_add(unit as usize);
            }
            Ok(FileEntry {
                extended,
                info_len,
                embedded: Vec::new(),
                ads,
            })
        }
        AD_EXTENDED => Err(CoreError::invalid(format!(
            "{what} uses extended allocation descriptors (type {AD_EXTENDED}): only short (0), \
             long (1) and embedded (3) descriptors are supported"
        ))),
        other => Err(CoreError::invalid(format!(
            "{what} has unknown allocation descriptor type {other}: only short (0), long (1) \
             and embedded (3) descriptors are supported"
        ))),
    }
}

/// Collect the first `info_len` bytes of a directory's data: embedded
/// bytes pass through, short and long extents read through their
/// partitions (every window bounds-checked before I/O). Returns the bytes
/// with the segment layout for tag-location checks (`fe_rel` is the file
/// entry's own partition-relative block, which anchors embedded data).
/// Refuses an information length past the collected bytes, a total past
/// [`MAX_DIR_BYTES`], and any extent running past the store — each naming
/// the numbers.
///
/// Eight parameters because the call needs the whole addressing context
/// at once; bundling them would only hide the same fields.
#[allow(clippy::too_many_arguments)]
pub fn collect_data(
    volume: &dyn Volume,
    size: u32,
    maps: &[u16],
    partitions: &[PartitionDesc],
    home: &PartitionDesc,
    entry: &FileEntry,
    what: &str,
    fe_rel: u32,
) -> Result<(Vec<u8>, Vec<DataSeg>)> {
    if !entry.ads.is_empty() || entry.info_len > entry.embedded.len() as u64 {
        return collect_extents(volume, size, maps, partitions, home, entry, what);
    }
    let len = usize::try_from(entry.info_len).map_err(|_| {
        CoreError::invalid(format!(
            "{what} information length {} is not addressable",
            entry.info_len
        ))
    })?;
    let data = entry.embedded.get(..len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} information length {} runs past the {} embedded bytes",
            entry.info_len,
            entry.embedded.len()
        ))
    })?;
    Ok((
        data.to_vec(),
        vec![DataSeg {
            start: fe_rel,
            len: entry.info_len,
        }],
    ))
}

/// Extent-backed (and over-long embedded) collection: join every
/// allocation extent in order through its partition, then cut to the
/// information length.
fn collect_extents(
    volume: &dyn Volume,
    size: u32,
    maps: &[u16],
    partitions: &[PartitionDesc],
    home: &PartitionDesc,
    entry: &FileEntry,
    what: &str,
) -> Result<(Vec<u8>, Vec<DataSeg>)> {
    let total = volume.total_bytes();
    if entry.ads.is_empty() {
        return Err(CoreError::invalid(format!(
            "{what} information length {} runs past the {} embedded bytes: the entry \
             carries no allocation descriptors to back it",
            entry.info_len,
            entry.embedded.len()
        )));
    }
    let mut collected: u64 = 0;
    for desc in &entry.ads {
        let len = match desc {
            AllocDesc::Short { len, .. } | AllocDesc::Long { len, .. } => u64::from(*len),
        };
        collected = collected.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} extent lengths overflow the byte arithmetic"
            ))
        })?;
    }
    if entry.info_len > collected {
        return Err(CoreError::invalid(format!(
            "{what} information length {} runs past the {collected} collected extent bytes",
            entry.info_len
        )));
    }
    if collected > MAX_DIR_BYTES {
        return Err(CoreError::invalid(format!(
            "{what} directory data of {collected} bytes runs past the {MAX_DIR_BYTES} byte cap"
        )));
    }
    let count = usize::try_from(collected).map_err(|_| {
        CoreError::invalid(format!("{what} data length {collected} is not addressable"))
    })?;
    let mut out = Vec::new();
    out.try_reserve(count).map_err(|_| {
        CoreError::invalid(format!(
            "{what} directory data of {collected} bytes cannot be buffered"
        ))
    })?;
    let mut segs = Vec::new();
    for desc in &entry.ads {
        let (len, partition, rel) = match desc {
            AllocDesc::Short { len, pos } => (*len, *home, *pos),
            AllocDesc::Long { len, lbn, part } => {
                let resolved = resolve_map(maps, partitions, *part, what)?;
                (*len, resolved, *lbn)
            }
        };
        let abs = partition.start.checked_add(rel).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} extent at partition-relative block {rel} overflows the block number"
            ))
        })?;
        let offset = u64::from(abs).checked_mul(u64::from(size)).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} extent at block {abs} overflows the byte offset arithmetic"
            ))
        })?;
        let bytes = read_bytes(volume, offset, u64::from(len), total, what)?;
        out.extend_from_slice(&bytes);
        segs.push(DataSeg {
            start: rel,
            len: u64::from(len),
        });
    }
    let keep = usize::try_from(entry.info_len).map_err(|_| {
        CoreError::invalid(format!(
            "{what} information length {} is not addressable",
            entry.info_len
        ))
    })?;
    let data = out.get(..keep).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} information length {} runs past the {} collected bytes",
            entry.info_len,
            out.len()
        ))
    })?;
    Ok((data.to_vec(), segs))
}

/// Resolve a partition reference through the map table to its partition
/// descriptor: refuses a reference past the table and a number with no
/// descriptor, naming both.
pub fn resolve_map(
    maps: &[u16],
    partitions: &[PartitionDesc],
    reference: u16,
    what: &str,
) -> Result<PartitionDesc> {
    let number = maps.get(usize::from(reference)).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} partition reference {reference} runs past the {} partition maps",
            maps.len()
        ))
    })?;
    partitions
        .iter()
        .find(|seen| seen.number == number)
        .copied()
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} partition reference {reference} maps to partition {number} with no \
                 partition descriptor"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    const SIZE: u32 = 512;

    /// File set block with the root ICB (length `SIZE`, block `lbn`,
    /// reference 0) at absolute block `abs`.
    fn fsd_block(abs: u32, lbn: u32) -> Vec<u8> {
        let _ = abs;
        let mut block = vec![0u8; SIZE as usize];
        block[400..404].copy_from_slice(&SIZE.to_le_bytes());
        block[404..408].copy_from_slice(&lbn.to_le_bytes());
        stamp_tag(&mut block, TAG_FSD, (SIZE - 16) as u16, lbn);
        block
    }

    /// Extended file entry block with `embedded` bytes as its data and
    /// information length `info`, at absolute block `abs` claiming
    /// partition-relative `rel`.
    fn ext_entry(abs: u32, rel: u32, embedded: &[u8], info: u64) -> Vec<u8> {
        let _ = abs;
        let mut block = vec![0u8; SIZE as usize];
        block[16 + 18..16 + 20].copy_from_slice(&AD_EMBEDDED.to_le_bytes());
        block[56..64].copy_from_slice(&info.to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(embedded.len() as u32).to_le_bytes());
        block[216..216 + embedded.len()].copy_from_slice(embedded);
        stamp_tag(&mut block, TAG_EXTFE, (SIZE - 16) as u16, rel);
        block
    }

    /// Store with `blocks` laid from absolute block `first` on.
    fn store(blocks: &[Vec<u8>], first: u32) -> VecVolume {
        let total = u64::from(first + blocks.len() as u32) * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        for (index, block) in blocks.iter().enumerate() {
            volume
                .write_all_at(u64::from(first + index as u32) * u64::from(SIZE), block)
                .expect("the block fits");
        }
        volume
    }

    #[test]
    fn fsd_parses_the_root_icb() {
        let volume = store(&[fsd_block(40, 8)], 40);
        let fsd = read_fsd(&volume, SIZE, 40, 8).expect("the file set parses");
        assert_eq!(fsd.root_icb.extent_length, SIZE);
        assert_eq!(fsd.root_icb.lbn, 8);
        assert_eq!(fsd.root_icb.partition_ref, 0);
    }

    #[test]
    fn fsd_wrong_tag_refuses() {
        let mut block = fsd_block(40, 8);
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 8);
        let volume = store(&[block], 40);
        let error = read_fsd(&volume, SIZE, 40, 8).expect_err("tag 261 is no file set");
        assert!(error.to_string().contains("261"), "{:?}", error);
    }

    #[test]
    fn fsd_location_mismatch_refuses() {
        let volume = store(&[fsd_block(40, 8)], 40);
        let error = read_fsd(&volume, SIZE, 40, 9).expect_err("relative 9 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('8'), "{text}");
    }

    #[test]
    fn ext_entry_collects_embedded_data() {
        let volume = store(&[ext_entry(41, 9, &[1, 2, 3, 4], 4)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert!(entry.extended);
        assert_eq!(entry.info_len, 4);
        assert!(entry.ads.is_empty());
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let (data, _) = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect("embedded data collects");
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn info_past_embedded_refuses() {
        let volume = store(&[ext_entry(41, 9, &[1, 2], 9)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let error = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect_err("info 9 past 2 embedded refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('2'), "{text}");
    }

    #[test]
    fn extended_ad_type_refuses() {
        let mut block = ext_entry(41, 9, &[], 0);
        block[16 + 18..16 + 20].copy_from_slice(&AD_EXTENDED.to_le_bytes());
        stamp_tag(&mut block, TAG_EXTFE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type 2 refuses");
        let text = error.to_string();
        assert!(text.contains('2'), "{text}");
    }

    #[test]
    fn short_ad_extent_collects_through_home() {
        // Entry at 41 with one short extent (4 bytes at home-relative 2);
        // the data block sits at absolute 34.
        let mut block = vec![0u8; SIZE as usize];
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&4u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&8u32.to_le_bytes());
        block[176..180].copy_from_slice(&4u32.to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let mut data_block = vec![0u8; SIZE as usize];
        data_block[0..4].copy_from_slice(&[9, 8, 7, 6]);
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        // Store lays blocks 34..36: put the data block at absolute 34 by
        // padding entry/data order explicitly instead.
        let total = 64 * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("fits in RAM");
        volume
            .write_all_at(41 * u64::from(SIZE), &block)
            .expect("the entry fits");
        volume
            .write_all_at(34 * u64::from(SIZE), &data_block)
            .expect("the data fits");
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert!(!entry.extended);
        assert_eq!(entry.ads.len(), 1);
        let (data, segs) = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect("the extent collects");
        assert_eq!(data, vec![9, 8, 7, 6]);
        assert_eq!(segs, vec![DataSeg { start: 2, len: 4 }]);
    }

    #[test]
    fn unrecorded_extent_refuses() {
        let mut block = vec![0u8; SIZE as usize];
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&4u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&8u32.to_le_bytes());
        block[176..180].copy_from_slice(&(1u32 << 30 | 4).to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type-1 extent refuses");
        let text = error.to_string();
        assert!(text.contains('1'), "{text}");
    }

    #[test]
    fn partition_ref_past_the_maps_refuses() {
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let error = resolve_map(&[0], &[home], 3, "test").expect_err("ref 3 past 1 map refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains('1'), "{text}");
    }
}
