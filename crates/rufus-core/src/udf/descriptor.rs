//! The volume descriptor sequence walk (S15, slice 1).
//!
//! Walks one anchor extent block by block: every block is tag-validated
//! (identifier, location matching the block read, CRC over the claimed
//! window) and dispatched by tag id. Handled ids: primary (1, presence
//! only), implementation use (4, skipped), partition (5, recorded),
//! logical volume (6, parsed), unallocated space (7, skipped), terminator
//! (8, ends the walk). Any other id is ignored by length — validated,
//! then skipped — so forward-compatible descriptors never break the walk.
//!
//! *Measured* — on the `mkudffs --udfrev=0x0201` images (see the slice
//! report): the sequence is primary, logical volume, partition,
//! unallocated space, implementation use, terminator, then zero padding;
//! the logical volume descriptor carries the block size, the
//! `*OSTA UDF Compliant` domain with suffix revision `0x0201`, one
//! type-1 map (volume sequence 1, partition 0), the file set descriptor
//! address (length one block, partition reference 0) and the d-string
//! label; the partition descriptor carries partition 0 at block 257 with
//! contents `+NSR03`.
//!
//! *Inferred* — the field offsets below (spec text, ECMA-167 3/10.5 and
//! 3/10.6): each offset's value was confirmed on the real images, but the
//! layout itself is not independently cross-checked. Type-2 map
//! identifiers, which no measured image carries, are refused by name.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::text::device_text;
use crate::udf::Extent;
use crate::udf::LongAd;
use crate::udf::MAX_DESCRIPTORS;
use crate::udf::MAX_PARTITION_MAPS;
use crate::udf::le_u16;
use crate::udf::le_u32;
use crate::udf::parse_long_ad;
use crate::udf::read_block;
use crate::udf::tag;
use crate::udf::unicode;

/// Primary volume descriptor tag id (presence only).
const TAG_PRIMARY: u16 = 1;
/// Implementation use volume descriptor tag id (skipped).
const TAG_IUVD: u16 = 4;
/// Partition descriptor tag id.
const TAG_PARTITION: u16 = 5;
/// Logical volume descriptor tag id.
const TAG_LOGICAL: u16 = 6;
/// Unallocated space descriptor tag id (skipped).
const TAG_USD: u16 = 7;
/// Terminating descriptor tag id (ends the walk).
const TAG_TERMINATOR: u16 = 8;

/// Partition map type 1: a physical partition number.
const MAP_PHYSICAL: u8 = 1;
/// Partition map type 2: virtual, sparable or metadata — refused.
const MAP_TYPED: u8 = 2;
/// Length of a type-1 partition map in bytes.
const MAP_PHYSICAL_LEN: u8 = 6;

/// Offset of the partition number in a partition descriptor.
const PD_NUMBER_AT: usize = 22;
/// Offset of the 23-byte contents identifier (past its flags byte) in a
/// partition descriptor's entity id.
const PD_CONTENTS_AT: usize = 25;
/// Length of the contents identifier field.
const PD_CONTENTS_LEN: usize = 23;
/// Offset of the partition start block in a partition descriptor.
const PD_START_AT: usize = 188;
/// Offset of the partition length (in blocks) in a partition descriptor.
const PD_LENGTH_AT: usize = 192;

/// Offset of the 128-byte logical volume identifier d-string in a
/// logical volume descriptor.
const LVD_LABEL_AT: usize = 84;
/// Length of the logical volume identifier field.
const LVD_LABEL_LEN: usize = 128;
/// Offset of the logical block size in a logical volume descriptor.
const LVD_BLOCK_AT: usize = 212;
/// Offset of the 23-byte domain identifier (past its flags byte) in a
/// logical volume descriptor's domain entity id. Read for the window
/// check only: the identifier text itself is not enforced (see
/// [`parse_revision`]).
const LVD_DOMAIN_AT: usize = 217;
/// Length of the domain identifier field.
const LVD_DOMAIN_LEN: usize = 23;
/// Offset of the 8-byte domain suffix (revision first) in a logical
/// volume descriptor.
const LVD_SUFFIX_AT: usize = 240;
/// Offset of the file set descriptor's long address in a logical volume
/// descriptor.
const LVD_FSD_AT: usize = 248;
/// Offset of the map table length in a logical volume descriptor.
const LVD_MAPLEN_AT: usize = 264;
/// Offset of the partition map count in a logical volume descriptor.
const LVD_NMAPS_AT: usize = 268;
/// Offset of the partition map table in a logical volume descriptor.
const LVD_MAPS_AT: usize = 440;

/// Offset of a type-2 map's 23-byte identifier (past its flags byte).
const MAP2_IDENT_AT: usize = 3;
/// Length of a type-2 map's identifier field.
const MAP2_IDENT_LEN: usize = 23;
/// Type-2 identifier for virtual partitions.
const MAP_VIRTUAL: &[u8] = b"*UDF Virtual Partition";
/// Type-2 identifier for sparable partitions.
const MAP_SPARABLE: &[u8] = b"*UDF Sparable Partition";
/// Type-2 identifier for metadata partitions.
const MAP_METADATA: &[u8] = b"*UDF Metadata Partition";

/// One partition descriptor: the number with its block window. The
/// contents identifier must read `+NSR02`/`+NSR03`; anything else refuses
/// naming the sanitised bytes found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionDesc {
    /// Partition number, matched against type-1 map entries.
    pub number: u16,
    /// First absolute block number of the partition.
    pub start: u32,
    /// Partition length in blocks.
    pub length: u32,
}

/// The parsed logical volume descriptor: the addressing basis (block
/// size), the display facts (label, revision), the file set location and
/// the partition numbers in map-table order. Only type-1 (physical) maps
/// survive parsing: a type-2 map refuses naming its kind, and any other
/// map type refuses naming its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalVolume {
    /// Logical block size in bytes (must equal the probed size).
    pub block_size: u32,
    /// Logical volume identifier, d-string decoded and trimmed.
    pub label: String,
    /// Domain suffix revision as `major.minor` (`0x0201` reads `2.01`).
    pub revision: String,
    /// Long address of the file set descriptor.
    pub fsd: LongAd,
    /// Partition numbers in map-table order; the file set and every ICB
    /// address indexes this table by partition reference.
    pub maps: Vec<u16>,
}

/// One walked sequence: primary presence, the partition descriptors in
/// walk order, and the logical volume descriptor when one parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeDescriptors {
    /// True once a primary descriptor (tag 1) has been seen.
    pub has_primary: bool,
    /// Partition descriptors in walk order (numbers unique).
    pub partitions: Vec<PartitionDesc>,
    /// The logical volume descriptor (`None` when the walk held none).
    pub logical: Option<LogicalVolume>,
}

impl VolumeDescriptors {
    /// True when the walk can feed the reader: a primary, a logical
    /// volume and its terminator all seen. The reserve fallback in
    /// [`reader`](super::reader) uses this to decide whether the main
    /// sequence suffices.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.has_primary && self.logical.is_some()
    }
}

/// Walk `extent` (in units of `size` byte blocks) from `volume`: at most
/// [`MAX_DESCRIPTORS`] blocks, stopping at the terminator. Refuses a
/// non-multiple extent length, a tag/location/CRC failure on any block, a
/// missing terminator, a missing primary, a missing logical volume, and
/// any malformed partition or logical volume body — each naming the block
/// and the numbers.
pub fn walk(
    volume: &dyn Volume,
    size: u32,
    extent: Extent,
    total: u64,
) -> Result<VolumeDescriptors> {
    if size == 0 {
        return Err(CoreError::invalid(
            "volume descriptor extent cannot be walked with a zero block size",
        ));
    }
    if !extent.length.is_multiple_of(size) {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent of {} bytes at block {} is not a multiple of the \
             {size} byte block size",
            extent.length, extent.location
        )));
    }
    if extent.length == 0 {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent at block {} has zero length: no descriptors to walk",
            extent.location
        )));
    }
    let blocks = extent.length / size;
    if blocks as usize > MAX_DESCRIPTORS {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent of {blocks} blocks at block {} runs past \
             {MAX_DESCRIPTORS} descriptors with no cap to bound the walk",
            extent.location
        )));
    }
    let mut out = VolumeDescriptors {
        has_primary: false,
        partitions: Vec::new(),
        logical: None,
    };
    let mut terminated = false;
    let mut index: u32 = 0;
    while index < blocks {
        let lbn = extent.location.checked_add(index).ok_or_else(|| {
            CoreError::invalid(format!(
                "volume descriptor extent at block {} plus descriptor {index} overflows \
                 the block number",
                extent.location
            ))
        })?;
        let block = read_block(volume, lbn, size, total, "volume descriptor")?;
        let tag = tag::parse(&block, &format!("volume descriptor at block {lbn}"))?;
        if tag.location != lbn {
            return Err(CoreError::invalid(format!(
                "volume descriptor at block {lbn} claims tag location {}: refusing a \
                 descriptor that does not describe its own block",
                tag.location
            )));
        }
        tag::verify_crc(&block, &tag, &format!("volume descriptor at block {lbn}"))?;
        match tag.id {
            TAG_PRIMARY => {
                if out.has_primary {
                    return Err(CoreError::invalid(format!(
                        "second primary volume descriptor at block {lbn}: the sequence \
                         must hold exactly one primary descriptor"
                    )));
                }
                out.has_primary = true;
            }
            TAG_IUVD | TAG_USD => {}
            TAG_PARTITION => {
                let partition = parse_partition(&block, lbn)?;
                if out
                    .partitions
                    .iter()
                    .any(|seen| seen.number == partition.number)
                {
                    return Err(CoreError::invalid(format!(
                        "second partition descriptor for partition {} at block {lbn}: \
                         partition numbers must be unique",
                        partition.number
                    )));
                }
                out.partitions.push(partition);
            }
            TAG_LOGICAL => {
                if out.logical.is_some() {
                    return Err(CoreError::invalid(format!(
                        "second logical volume descriptor at block {lbn}: the sequence \
                         must hold exactly one logical volume descriptor"
                    )));
                }
                out.logical = Some(parse_logical(&block, lbn, size, tag.crc_len)?);
            }
            TAG_TERMINATOR => {
                terminated = true;
                break;
            }
            _ => {}
        }
        index = index.checked_add(1).ok_or_else(|| {
            CoreError::invalid(format!(
                "volume descriptor walk at block {lbn} overflows the block counter"
            ))
        })?;
    }
    if !terminated {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent of {blocks} blocks at block {} ends with no \
             terminator: refusing an unterminated sequence",
            extent.location
        )));
    }
    if !out.has_primary {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent at block {} holds no primary descriptor: \
             refusing a sequence with no primary",
            extent.location
        )));
    }
    if out.logical.is_none() {
        return Err(CoreError::invalid(format!(
            "volume descriptor extent at block {} holds no logical volume descriptor: \
             refusing a sequence with no logical volume",
            extent.location
        )));
    }
    Ok(out)
}

/// Parse a partition descriptor body (tag already validated): the number,
/// the `+NSR02`/`+NSR03` contents identifier and the block window.
fn parse_partition(block: &[u8], lbn: u32) -> Result<PartitionDesc> {
    let what = format!("partition descriptor at block {lbn}");
    let number = le_u16(block, PD_NUMBER_AT, &what)?;
    let raw = block
        .get(PD_CONTENTS_AT..PD_CONTENTS_AT + PD_CONTENTS_LEN)
        .ok_or_else(|| CoreError::invalid(format!("{what} ends inside its contents identifier")))?;
    let mut contents = raw;
    while contents.last() == Some(&0) {
        match contents.get(..contents.len().saturating_sub(1)) {
            Some(rest) => contents = rest,
            None => break,
        }
    }
    if contents != b"+NSR02" && contents != b"+NSR03" {
        return Err(CoreError::invalid(format!(
            "{what} carries contents identifier `{}` not `+NSR02`/`+NSR03`: refusing a \
             non-UDF partition",
            device_text(&String::from_utf8_lossy(contents))
        )));
    }
    Ok(PartitionDesc {
        number,
        start: le_u32(block, PD_START_AT, &what)?,
        length: le_u32(block, PD_LENGTH_AT, &what)?,
    })
}

/// Parse a logical volume descriptor body (tag already validated): the
/// label, the block size (which must equal the probed `size`), the domain
/// revision, the file set address and the partition map table.
fn parse_logical(block: &[u8], lbn: u32, size: u32, crc_len: u16) -> Result<LogicalVolume> {
    let what = format!("logical volume descriptor at block {lbn}");
    let block_size = le_u32(block, LVD_BLOCK_AT, &what)?;
    if block_size != size {
        return Err(CoreError::invalid(format!(
            "{what} carries logical block size {block_size} not the probed {size}: \
             refusing a volume whose blocks move under the reader"
        )));
    }
    let label_field = block
        .get(LVD_LABEL_AT..LVD_LABEL_AT + LVD_LABEL_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!("{what} ends inside its logical volume identifier"))
        })?;
    let label = unicode::decode_dstring(label_field, &format!("{what} logical volume identifier"))?;
    let revision = parse_revision(block, &what)?;
    let fsd = parse_long_ad(block, LVD_FSD_AT, &what)?;
    if fsd.extent_length != size {
        return Err(CoreError::invalid(format!(
            "{what} file set descriptor extent length {} is not the {size} byte block \
             size: a file set descriptor fills exactly one block",
            fsd.extent_length
        )));
    }
    let map_len = le_u32(block, LVD_MAPLEN_AT, &what)?;
    let map_count = le_u32(block, LVD_NMAPS_AT, &what)?;
    if map_count == 0 {
        return Err(CoreError::invalid(format!(
            "{what} carries no partition maps: no partition reference can resolve"
        )));
    }
    if map_count as usize > MAX_PARTITION_MAPS {
        return Err(CoreError::invalid(format!(
            "{what} claims {map_count} partition maps past the {MAX_PARTITION_MAPS} map cap: \
             refusing a hostile map count"
        )));
    }
    let table_end = (LVD_MAPS_AT as u32).checked_add(map_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} map table length {map_len} overflows the arithmetic"
        ))
    })?;
    if table_end as usize > block.len() {
        return Err(CoreError::invalid(format!(
            "{what} map table of {map_len} bytes at offset {LVD_MAPS_AT} runs past the \
             {} byte block",
            block.len()
        )));
    }
    let crc_end = usize::from(crc_len)
        .checked_add(crate::udf::tag::TAG_LEN)
        .ok_or_else(|| CoreError::invalid(format!("{what} CRC length overflows the arithmetic")))?;
    if table_end as usize > crc_end {
        return Err(CoreError::invalid(format!(
            "{what} map table ends at block offset {table_end} past the CRC-covered \
             {crc_end}: refusing maps the checksum does not cover"
        )));
    }
    let mut maps = Vec::new();
    let mut at = LVD_MAPS_AT;
    for index in 0..map_count {
        let entry = block.get(at..table_end as usize).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} partition map {index} runs past the map table"
            ))
        })?;
        let kind = entry
            .first()
            .copied()
            .ok_or_else(|| CoreError::invalid(format!("{what} partition map {index} is empty")))?;
        let len = usize::from(entry.get(1).copied().ok_or_else(|| {
            CoreError::invalid(format!("{what} partition map {index} has no length byte"))
        })?);
        if len < 2 || len > entry.len() {
            return Err(CoreError::invalid(format!(
                "{what} partition map {index} claims length {len} in {} remaining table \
                 bytes: refusing an overrunning map",
                entry.len()
            )));
        }
        match kind {
            MAP_PHYSICAL => {
                if len != usize::from(MAP_PHYSICAL_LEN) {
                    return Err(CoreError::invalid(format!(
                        "{what} type-1 partition map {index} has length {len} not {}: \
                         refusing a misshapen physical map",
                        MAP_PHYSICAL_LEN
                    )));
                }
                let bytes = entry.get(..len).ok_or_else(|| {
                    CoreError::invalid(format!("{what} partition map {index} overruns its bytes"))
                })?;
                maps.push(le_u16(bytes, 4, &format!("{what} partition map {index}"))?);
            }
            MAP_TYPED => {
                return Err(typed_map_refusal(block, at, len, &what, index));
            }
            other => {
                return Err(CoreError::invalid(format!(
                    "{what} partition map {index} has unknown type {other}: only type 1 \
                     (physical) and type 2 (virtual, sparable, metadata) are recognised"
                )));
            }
        }
        at = at.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} partition map {index} overflows the table offset"
            ))
        })?;
    }
    if at != table_end as usize {
        return Err(CoreError::invalid(format!(
            "{what} partition maps end at table offset {at} not the table end \
             {table_end}: refusing a ragged map table"
        )));
    }
    Ok(LogicalVolume {
        block_size,
        label,
        revision,
        fsd,
        maps,
    })
}

/// Refusal for a type-2 partition map: names the virtual/sparable/
/// metadata kind from its identifier, or the sanitised raw identifier
/// when it matches nothing known.
fn typed_map_refusal(block: &[u8], at: usize, len: usize, what: &str, index: u32) -> CoreError {
    let start = at.saturating_add(MAP2_IDENT_AT);
    let end = start.saturating_add(MAP2_IDENT_LEN);
    let ident = match block.get(start..end) {
        Some(bytes) => bytes,
        None => &[],
    };
    let mut trimmed = ident;
    while trimmed.last() == Some(&0) {
        match trimmed.get(..trimmed.len().saturating_sub(1)) {
            Some(rest) => trimmed = rest,
            None => break,
        }
    }
    let kind = if trimmed == MAP_VIRTUAL {
        "virtual"
    } else if trimmed == MAP_SPARABLE {
        "sparable"
    } else if trimmed == MAP_METADATA {
        "metadata"
    } else {
        ""
    };
    if kind.is_empty() {
        CoreError::invalid(format!(
            "{what} partition map {index} is type 2 with unrecognised identifier `{}` \
             (length {len}): virtual, sparable and metadata maps are not supported",
            device_text(&String::from_utf8_lossy(trimmed))
        ))
    } else {
        CoreError::invalid(format!(
            "{what} partition map {index} is a type-2 {kind} partition map (length {len}): \
             virtual, sparable and metadata maps are not supported"
        ))
    }
}

/// Revision from the domain suffix: the `u16` at the suffix start reads
/// as BCD-ish `major.minor` (`0x0201` is `2.01`, agreeing with `udfinfo`'s
/// `udfrev`). The domain identifier itself is not enforced: foreign
/// formatters may word it differently, and the revision is the fact the
/// reader reports.
fn parse_revision(block: &[u8], what: &str) -> Result<String> {
    let domain = block
        .get(LVD_DOMAIN_AT..LVD_DOMAIN_AT + LVD_DOMAIN_LEN)
        .ok_or_else(|| CoreError::invalid(format!("{what} ends inside its domain identifier")))?;
    let _ = domain;
    let revision = le_u16(block, LVD_SUFFIX_AT, &format!("{what} domain suffix"))?;
    Ok(format!("{:X}.{:02X}", revision >> 8, revision & 0xFF))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    /// One-block store helper: `blocks` in walk order from block 96 on,
    /// each `size` bytes, boxed for the walk.
    fn store(blocks: &[Vec<u8>], size: u32) -> VecVolume {
        let total = u64::from(96 + blocks.len() as u32) * u64::from(size);
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        for (index, block) in blocks.iter().enumerate() {
            let lbn = 96 + index as u32;
            volume
                .write_all_at(u64::from(lbn) * u64::from(size), block)
                .expect("the block fits");
        }
        volume
    }

    /// Blank block with a valid tag; the caller fills the body, then
    /// fixes the CRC with [`stamp_tag`].
    fn blank(size: u32) -> Vec<u8> {
        vec![0u8; size as usize]
    }

    /// Primary body: nothing slice 1 reads, so zeroes past the tag.
    fn primary(size: u32, lbn: u32) -> Vec<u8> {
        let mut block = blank(size);
        stamp_tag(&mut block, TAG_PRIMARY, (size - 16) as u16, lbn);
        block
    }

    /// Partition body for number `number` at `start`/`length`.
    fn partition(size: u32, lbn: u32, number: u16, start: u32, length: u32) -> Vec<u8> {
        let mut block = blank(size);
        block[22..24].copy_from_slice(&number.to_le_bytes());
        block[25..31].copy_from_slice(b"+NSR03");
        block[188..192].copy_from_slice(&start.to_le_bytes());
        block[192..196].copy_from_slice(&length.to_le_bytes());
        stamp_tag(&mut block, TAG_PARTITION, (size - 16) as u16, lbn);
        block
    }

    /// Logical volume body: label `LABEL`, block size `size`, revision
    /// 0x0201, one type-1 map to partition 0, file set at partition-
    /// relative block 1.
    fn logical(size: u32, lbn: u32) -> Vec<u8> {
        logical_with_maps(size, lbn, &[1])
    }

    /// Logical volume body with a chosen map-type sequence: `1` writes a
    /// type-1 map to partition 0, `2` a type-2 virtual map, any other
    /// value a map of that type with length 2.
    fn logical_with_maps(size: u32, lbn: u32, kinds: &[u8]) -> Vec<u8> {
        let mut block = blank(size);
        block[84] = 8;
        block[85..90].copy_from_slice(b"LABEL");
        block[84 + 127] = 6;
        block[212..216].copy_from_slice(&size.to_le_bytes());
        block[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        block[240..242].copy_from_slice(&0x0201u16.to_le_bytes());
        block[248..252].copy_from_slice(&size.to_le_bytes());
        block[252..256].copy_from_slice(&1u32.to_le_bytes());
        let mut maps = Vec::new();
        for kind in kinds {
            match kind {
                1 => {
                    maps.push(1);
                    maps.push(6);
                    maps.extend_from_slice(&1u16.to_le_bytes());
                    maps.extend_from_slice(&0u16.to_le_bytes());
                }
                2 => {
                    maps.push(2);
                    maps.push(64);
                    maps.push(0);
                    maps.extend_from_slice(b"*UDF Virtual Partition");
                    maps.extend_from_slice(&[0u8; 39]);
                }
                other => {
                    maps.push(*other);
                    maps.push(2);
                }
            }
        }
        let map_len = maps.len() as u32;
        block[264..268].copy_from_slice(&map_len.to_le_bytes());
        block[268..272].copy_from_slice(&(kinds.len() as u32).to_le_bytes());
        block[440..440 + maps.len()].copy_from_slice(&maps);
        let crc_len = (440 + maps.len() - 16) as u16;
        stamp_tag(&mut block, TAG_LOGICAL, crc_len, lbn);
        block
    }

    /// Skipped body (implementation use / unallocated space): zeroes past
    /// the tag with the id and location stamped.
    fn skipped(size: u32, lbn: u32, id: u16) -> Vec<u8> {
        let mut block = blank(size);
        stamp_tag(&mut block, id, (size - 16) as u16, lbn);
        block
    }

    fn terminator(size: u32, lbn: u32) -> Vec<u8> {
        skipped(size, lbn, TAG_TERMINATOR)
    }

    /// Full happy-path sequence at 2048-byte blocks: primary, logical,
    /// partition, unallocated, implementation use, terminator.
    fn happy() -> Vec<Vec<u8>> {
        let size = 2048;
        vec![
            primary(size, 96),
            logical(size, 97),
            partition(size, 98, 0, 257, 7672),
            skipped(size, 99, TAG_USD),
            skipped(size, 100, TAG_IUVD),
            terminator(size, 101),
        ]
    }

    fn walk_main(blocks: &[Vec<u8>], size: u32) -> Result<VolumeDescriptors> {
        let volume = store(blocks, size);
        let extent = Extent {
            length: (blocks.len() as u32) * size,
            location: 96,
        };
        walk(&volume, size, extent, volume.total_bytes())
    }

    #[test]
    fn happy_path_parses_everything() {
        let set = walk_main(&happy(), 2048).expect("the six-descriptor set walks");
        assert!(set.has_primary);
        assert!(set.is_complete());
        assert_eq!(
            set.partitions,
            vec![PartitionDesc {
                number: 0,
                start: 257,
                length: 7672
            }]
        );
        let logical = set.logical.expect("the logical volume parsed");
        assert_eq!(logical.block_size, 2048);
        assert_eq!(logical.label, "LABEL");
        assert_eq!(logical.revision, "2.01");
        assert_eq!(logical.fsd.extent_length, 2048);
        assert_eq!(logical.fsd.lbn, 1);
        assert_eq!(logical.fsd.partition_ref, 0);
        assert_eq!(logical.maps, vec![0]);
    }

    #[test]
    fn unknown_ids_are_ignored_by_length() {
        let mut blocks = happy();
        blocks.insert(3, skipped(2048, 99, 9));
        // Re-stamp locations past the insertion: every block's tag must
        // describe its own block.
        let mut fixed = Vec::new();
        for (index, mut block) in blocks.into_iter().enumerate() {
            let lbn = 96 + index as u32;
            let id = u16::from_le_bytes([block[0], block[1]]);
            let crc_len = u16::from_le_bytes([block[10], block[11]]);
            stamp_tag(&mut block, id, crc_len, lbn);
            fixed.push(block);
        }
        let set = walk_main(&fixed, 2048).expect("tag 9 is ignored");
        assert!(set.is_complete());
        assert_eq!(set.partitions.len(), 1);
    }

    #[test]
    fn missing_terminator_refuses() {
        let mut blocks = happy();
        blocks.pop();
        let error = walk_main(&blocks, 2048).expect_err("no terminator refuses");
        let text = error.to_string();
        assert!(text.contains("terminator"), "{text}");
        assert!(text.contains("96"), "{text}");
    }

    #[test]
    fn zero_length_extent_refuses() {
        let blocks = happy();
        let volume = store(&blocks, 2048);
        let extent = Extent {
            length: 0,
            location: 96,
        };
        let error = walk(&volume, 2048, extent, volume.total_bytes())
            .expect_err("a zero-length extent refuses");
        let text = error.to_string();
        assert!(text.contains("zero length"), "{text}");
        assert!(text.contains("96"), "{text}");
    }

    #[test]
    fn missing_primary_refuses() {
        let mut blocks = happy();
        blocks.remove(0);
        // Blocks shift down: re-stamp locations so the only refusal is
        // the missing primary, not a location mismatch.
        let mut fixed = Vec::new();
        for (index, mut block) in blocks.into_iter().enumerate() {
            let lbn = 96 + index as u32;
            let id = u16::from_le_bytes([block[0], block[1]]);
            let crc_len = u16::from_le_bytes([block[10], block[11]]);
            stamp_tag(&mut block, id, crc_len, lbn);
            fixed.push(block);
        }
        let error = walk_main(&fixed, 2048).expect_err("no primary refuses");
        let text = error.to_string();
        assert!(text.contains("primary"), "{text}");
    }

    #[test]
    fn duplicate_primary_refuses() {
        let mut blocks = happy();
        blocks.insert(1, primary(2048, 97));
        let mut fixed = Vec::new();
        for (index, mut block) in blocks.into_iter().enumerate() {
            let lbn = 96 + index as u32;
            let id = u16::from_le_bytes([block[0], block[1]]);
            let crc_len = u16::from_le_bytes([block[10], block[11]]);
            stamp_tag(&mut block, id, crc_len, lbn);
            fixed.push(block);
        }
        let error = walk_main(&fixed, 2048).expect_err("two primaries refuse");
        assert!(error.to_string().contains("primary"), "{:?}", error);
    }

    #[test]
    fn duplicate_partition_number_refuses() {
        let mut blocks = happy();
        blocks.insert(3, partition(2048, 99, 0, 900, 100));
        let mut fixed = Vec::new();
        for (index, mut block) in blocks.into_iter().enumerate() {
            let lbn = 96 + index as u32;
            let id = u16::from_le_bytes([block[0], block[1]]);
            let crc_len = u16::from_le_bytes([block[10], block[11]]);
            stamp_tag(&mut block, id, crc_len, lbn);
            fixed.push(block);
        }
        let error = walk_main(&fixed, 2048).expect_err("two partition 0s refuse");
        let text = error.to_string();
        assert!(text.contains('0'), "{text}");
        assert!(text.contains("partition"), "{text}");
    }

    #[test]
    fn location_mismatch_refuses() {
        let mut blocks = happy();
        let crc_len = u16::from_le_bytes([blocks[2][10], blocks[2][11]]);
        stamp_tag(&mut blocks[2], TAG_PARTITION, crc_len, 99);
        let error = walk_main(&blocks, 2048).expect_err("location 99 at block 98 refuses");
        let text = error.to_string();
        assert!(text.contains("99"), "{text}");
        assert!(text.contains("98"), "{text}");
    }

    #[test]
    fn crc_mismatch_refuses() {
        let mut blocks = happy();
        blocks[2][200] ^= 0xFF;
        let error = walk_main(&blocks, 2048).expect_err("the flipped byte refuses");
        let text = error.to_string();
        assert!(text.contains("mismatch"), "{text}");
        assert!(text.contains("98"), "{text}");
    }

    #[test]
    fn type2_virtual_map_refuses_naming_the_kind() {
        let size = 2048;
        let blocks = vec![
            primary(size, 96),
            logical_with_maps(size, 97, &[2]),
            partition(size, 98, 0, 257, 7672),
            terminator(size, 99),
        ];
        let error = walk_main(&blocks, size).expect_err("a virtual map refuses");
        let text = error.to_string();
        assert!(text.contains("type-2"), "{text}");
        assert!(text.contains("virtual"), "{text}");
    }

    #[test]
    fn unknown_map_type_refuses_naming_the_value() {
        let size = 2048;
        let blocks = vec![
            primary(size, 96),
            logical_with_maps(size, 97, &[9]),
            partition(size, 98, 0, 257, 7672),
            terminator(size, 99),
        ];
        let error = walk_main(&blocks, size).expect_err("map type 9 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
    }

    #[test]
    fn logical_block_size_mismatch_refuses() {
        let size = 2048;
        let mut logical_block = logical(size, 97);
        logical_block[212..216].copy_from_slice(&512u32.to_le_bytes());
        // Re-fix the CRC after editing the body.
        let crc_len = u16::from_le_bytes([logical_block[10], logical_block[11]]);
        stamp_tag(&mut logical_block, TAG_LOGICAL, crc_len, 97);
        let blocks = vec![
            primary(size, 96),
            logical_block,
            partition(size, 98, 0, 257, 7672),
            terminator(size, 99),
        ];
        let error = walk_main(&blocks, size).expect_err("512 against 2048 refuses");
        let text = error.to_string();
        assert!(text.contains("512"), "{text}");
        assert!(text.contains("2048"), "{text}");
    }

    #[test]
    fn non_udf_partition_contents_refuse() {
        let size = 2048;
        let mut partition_block = partition(size, 98, 0, 257, 7672);
        partition_block[25..31].copy_from_slice(b"+CD001");
        let crc_len = u16::from_le_bytes([partition_block[10], partition_block[11]]);
        stamp_tag(&mut partition_block, TAG_PARTITION, crc_len, 98);
        let blocks = vec![
            primary(size, 96),
            logical(size, 97),
            partition_block,
            terminator(size, 99),
        ];
        let error = walk_main(&blocks, size).expect_err("+CD001 refuses");
        let text = error.to_string();
        assert!(text.contains("+CD001"), "{text}");
    }

    #[test]
    fn zero_maps_refuse() {
        let size = 2048;
        let blocks = vec![
            primary(size, 96),
            logical_with_maps(size, 97, &[]),
            partition(size, 98, 0, 257, 7672),
            terminator(size, 99),
        ];
        let error = walk_main(&blocks, size).expect_err("no maps refuse");
        assert!(error.to_string().contains("partition maps"), "{:?}", error);
    }
}
