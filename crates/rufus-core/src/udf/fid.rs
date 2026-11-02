//! File identifier descriptors (S15, slice 1).
//!
//! A directory's data is a run of file identifier descriptors (tag 257):
//! the file version, characteristics, name length, the entry's ICB (a
//! long address), the implementation-use length, then the use bytes and
//! the OSTA name, padded to a 4-byte boundary. Trailing zero bytes are
//! padding, not descriptors: an all-zero tail ends the listing.
//!
//! *Measured* — on the kernel-populated `mkudffs` image (see the slice
//! report): the parent entry reads characteristics `0x0A` (directory +
//! parent) with an empty name pointing at the directory itself, the
//! subdirectory reads `0x02` with a 7-byte `08 SUBDIR` name, files read
//! `0x00` with `08`-prefixed names; every record is 38 fixed bytes plus
//! name, rounded up to 4; every tag location is the partition-relative
//! block holding the record; every CRC covers the whole record past the
//! tag (name and padding included).
//!
//! *Inferred* — multi-block tag locations (the measured rule applied per
//! containing block: no measured directory spans blocks) and the
//! characteristics bit 2 (parsed nowhere: only bits 0, 1 and 3 matter
//! here).

use crate::error::CoreError;
use crate::error::Result;
use crate::udf::LongAd;
use crate::udf::MAX_FIDS;
use crate::udf::file::DataSeg;
use crate::udf::le_u16;
use crate::udf::parse_long_ad;
use crate::udf::tag;

/// File identifier descriptor tag id.
const TAG_FID: u16 = 257;

/// Fixed FID header in bytes (tag, version, characteristics, name
/// length, ICB, implementation-use length).
const FID_FIXED: usize = 38;

/// Offset of the file version number in a file identifier descriptor.
const FID_VERSION_AT: usize = 16;
/// Offset of the file characteristics in a file identifier descriptor.
const FID_CHAR_AT: usize = 18;
/// Offset of the file identifier length in a file identifier descriptor.
const FID_LEN_AT: usize = 19;
/// Offset of the ICB long address in a file identifier descriptor.
const FID_ICB_AT: usize = 20;
/// Offset of the implementation-use length in a file identifier
/// descriptor.
const FID_IU_AT: usize = 36;

/// Characteristics bit 0: set means deleted — the ICB is then undefined
/// and the entry is skipped, never followed.
pub const CHAR_DELETED: u8 = 0x01;
/// Characteristics bit 1: set means directory.
pub const CHAR_DIRECTORY: u8 = 0x02;
/// Characteristics bit 3: set means parent (`..`) — skipped in listings
/// like ISO's dot records.
pub const CHAR_PARENT: u8 = 0x08;

/// One parsed file identifier descriptor: the metadata with the raw name
/// bytes and their data offset (for compression-id refusals). The caller
/// decodes the name and skips deleted/parent entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileId {
    /// File version number (1 on every measured image; carried, not
    /// enforced).
    pub version: u16,
    /// Raw characteristics byte.
    pub characteristics: u8,
    /// True when the directory bit (bit 1) is set.
    pub is_directory: bool,
    /// Long address of the entry's file entry (undefined when deleted).
    pub icb: LongAd,
    /// Raw OSTA name bytes (compression id first).
    pub name: Vec<u8>,
    /// Directory-data offset of the name's first byte.
    pub name_off: usize,
    /// Total record length including 4-byte padding.
    pub record_len: usize,
}

impl FileId {
    /// True when the deleted bit (bit 0) is set.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.characteristics & CHAR_DELETED != 0
    }

    /// True when the parent bit (bit 3) is set.
    #[must_use]
    pub fn is_parent(&self) -> bool {
        self.characteristics & CHAR_PARENT != 0
    }
}

/// Parse every file identifier descriptor in `data` (already cut to the
/// information length): tag id 257, location matching the containing
/// block's partition-relative number from `segs`, a CRC over the whole
/// record, and a CRC length equal to the record minus the tag. A fully
/// zero tail ends the listing; anything else short of a record, a wrong
/// id, a location mismatch, a CRC-length surprise or a CRC mismatch
/// refuses naming the data offset. Past [`MAX_FIDS`] records refuses as a
/// hostile directory.
pub fn parse_fids(data: &[u8], segs: &[DataSeg], size: u32, what: &str) -> Result<Vec<FileId>> {
    let mut out = Vec::new();
    let mut at: usize = 0;
    while at < data.len() {
        let rest = data.get(at..).ok_or_else(|| {
            CoreError::invalid(format!("{what} directory offset {at} runs past its data"))
        })?;
        if rest.iter().all(|byte| *byte == 0) {
            break;
        }
        if out.len() >= MAX_FIDS {
            return Err(CoreError::invalid(format!(
                "{what} directory holds more than {MAX_FIDS} entries: refusing a hostile directory"
            )));
        }
        let parsed = parse_one(rest, at, segs, size, what)?;
        at = at.checked_add(parsed.record_len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} directory offset {at} overflows the arithmetic"
            ))
        })?;
        out.push(parsed);
    }
    Ok(out)
}

/// Parse the single descriptor at the start of `rest` (directory-data
/// offset `at`).
fn parse_one(rest: &[u8], at: usize, segs: &[DataSeg], size: u32, what: &str) -> Result<FileId> {
    let here = format!("{what} entry at directory offset {at}");
    if rest.len() < FID_FIXED {
        return Err(CoreError::invalid(format!(
            "{here} has {} bytes left, fewer than the {FID_FIXED} byte header: \
             the directory is truncated",
            rest.len()
        )));
    }
    let tag = tag::parse(rest, &here)?;
    if tag.id != TAG_FID {
        return Err(CoreError::invalid(format!(
            "{here} has tag id {} not {TAG_FID}: refusing a non file identifier",
            tag.id
        )));
    }
    let want = locate(at, segs, size, what)?;
    if tag.location != want {
        return Err(CoreError::invalid(format!(
            "{here} claims tag location {} not the containing block {want}: refusing a \
             descriptor that does not describe its own block",
            tag.location
        )));
    }
    let version = le_u16(rest, FID_VERSION_AT, &here)?;
    let characteristics = rest.get(FID_CHAR_AT).copied().ok_or_else(|| {
        CoreError::invalid(format!("{here} ends before its characteristics byte"))
    })?;
    let name_len =
        usize::from(rest.get(FID_LEN_AT).copied().ok_or_else(|| {
            CoreError::invalid(format!("{here} ends before its name length byte"))
        })?);
    let iu_len = usize::from(le_u16(rest, FID_IU_AT, &here)?);
    let body_len = FID_FIXED
        .checked_add(iu_len)
        .and_then(|sum| sum.checked_add(name_len))
        .ok_or_else(|| CoreError::invalid(format!("{here} lengths overflow the arithmetic")))?;
    let record_len = body_len
        .checked_add(3)
        .map(|sum| sum - sum % 4)
        .ok_or_else(|| {
            CoreError::invalid(format!("{here} padded length overflows the arithmetic"))
        })?;
    if rest.len() < record_len {
        return Err(CoreError::invalid(format!(
            "{here} needs {record_len} bytes but only {} remain: the directory is truncated",
            rest.len()
        )));
    }
    let expect_crc = record_len.checked_sub(tag::TAG_LEN).ok_or_else(|| {
        CoreError::invalid(format!("{here} padded length underflows the tag length"))
    })?;
    if usize::from(tag.crc_len) != expect_crc {
        return Err(CoreError::invalid(format!(
            "{here} claims CRC length {} but its record needs {expect_crc}: refusing a \
             descriptor whose checksum covers the wrong window",
            tag.crc_len
        )));
    }
    let record = rest.get(..record_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{here} record of {record_len} bytes runs past its data"
        ))
    })?;
    tag::verify_crc(record, &tag, &here)?;
    let name_at = FID_FIXED.checked_add(iu_len).ok_or_else(|| {
        CoreError::invalid(format!("{here} name offset overflows the arithmetic"))
    })?;
    let name_end = name_at
        .checked_add(name_len)
        .ok_or_else(|| CoreError::invalid(format!("{here} name end overflows the arithmetic")))?;
    let name = record.get(name_at..name_end).ok_or_else(|| {
        CoreError::invalid(format!(
            "{here} name bytes {name_at}..{name_end} run past the record"
        ))
    })?;
    Ok(FileId {
        version,
        characteristics,
        is_directory: characteristics & CHAR_DIRECTORY != 0,
        icb: parse_long_ad(record, FID_ICB_AT, &here)?,
        name: name.to_vec(),
        name_off: at.saturating_add(name_at),
        record_len,
    })
}

/// Partition-relative block number holding directory-data offset `at`:
/// walks the collected segments (each a block run in `size` byte units).
/// Refuses an offset past every segment, naming it.
fn locate(at: usize, segs: &[DataSeg], size: u32, what: &str) -> Result<u32> {
    let mut done: u64 = 0;
    for seg in segs {
        let end = done.checked_add(seg.len).ok_or_else(|| {
            CoreError::invalid(format!("{what} segment lengths overflow the arithmetic"))
        })?;
        if (at as u64) < end {
            let into = (at as u64).saturating_sub(done);
            let block = into.checked_div(u64::from(size)).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} cannot locate offset {at} with a zero block size"
                ))
            })?;
            let lbn = u64::from(seg.start).checked_add(block).ok_or_else(|| {
                CoreError::invalid(format!("{what} segment block for offset {at} overflows"))
            })?;
            return u32::try_from(lbn).map_err(|_| {
                CoreError::invalid(format!("{what} segment block for offset {at} is not a u32"))
            });
        }
        done = end;
    }
    Err(CoreError::invalid(format!(
        "{what} directory offset {at} runs past the collected segments"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udf::stamp_tag;

    /// One FID record (unpadded length 38 + name) with characteristics
    /// `char`, ICB (2048, `lbn`, 0) and `name` bytes, CRC fixed, padded to
    /// 4 bytes. Synthetic layout only.
    fn fid_record(characteristics: u8, lbn: u32, name: &[u8], loc: u32) -> Vec<u8> {
        let body_len = FID_FIXED + name.len();
        let record_len = body_len + (4 - body_len % 4) % 4;
        let mut record = vec![0u8; record_len];
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18] = characteristics;
        record[19] = name.len() as u8;
        record[20..24].copy_from_slice(&2048u32.to_le_bytes());
        record[24..28].copy_from_slice(&lbn.to_le_bytes());
        record[38..38 + name.len()].copy_from_slice(name);
        stamp_tag(&mut record, TAG_FID, (record_len - 16) as u16, loc);
        record
    }

    #[test]
    fn parent_subdir_and_file_parse() {
        let mut data = fid_record(0x0A, 3, &[], 3);
        data.extend_from_slice(&fid_record(0x02, 4, &[8, b'S', b'D'], 3));
        data.extend_from_slice(&fid_record(0x00, 5, &[8, b'f'], 3));
        data.extend_from_slice(&[0u8; 64]);
        let segs = vec![DataSeg { start: 3, len: 280 }];
        let parsed = parse_fids(&data, &segs, 2048, "test").expect("three records parse");
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].is_parent());
        assert!(parsed[0].is_directory);
        assert!(!parsed[0].is_deleted());
        assert!(parsed[1].is_directory);
        assert!(!parsed[1].is_deleted());
        assert!(!parsed[1].is_parent());
        assert_eq!(parsed[1].name, vec![8, b'S', b'D']);
        assert!(!parsed[2].is_directory);
        assert_eq!(parsed[2].icb.lbn, 5);
        assert_eq!(parsed[0].version, 1);
    }

    #[test]
    fn zero_tail_ends_the_listing() {
        let mut data = fid_record(0x00, 5, &[8, b'f'], 3);
        data.extend_from_slice(&[0u8; 100]);
        let segs = vec![DataSeg {
            start: 3,
            len: data.len() as u64,
        }];
        let parsed = parse_fids(&data, &segs, 2048, "test").expect("the tail ends it");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn bad_tag_refuses_naming_id_and_offset() {
        let mut data = fid_record(0x00, 5, &[8, b'f'], 3);
        data[0..2].copy_from_slice(&9u16.to_le_bytes());
        let segs = vec![DataSeg {
            start: 3,
            len: data.len() as u64,
        }];
        let error = parse_fids(&data, &segs, 2048, "test").expect_err("tag 9 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains("offset 0"), "{text}");
    }

    #[test]
    fn location_mismatch_refuses() {
        let data = fid_record(0x00, 5, &[8, b'f'], 7);
        let segs = vec![DataSeg {
            start: 3,
            len: data.len() as u64,
        }];
        let error = parse_fids(&data, &segs, 2048, "test").expect_err("location 7 refuses");
        let text = error.to_string();
        assert!(text.contains('7'), "{text}");
        assert!(text.contains('3'), "{text}");
    }

    #[test]
    fn crc_length_surprise_refuses() {
        let mut data = fid_record(0x00, 5, &[8, b'f'], 3);
        // Claim two fewer CRC bytes without fixing the CRC: the length
        // check fires first.
        let crc_len = u16::from_le_bytes([data[10], data[11]]) - 2;
        data[10..12].copy_from_slice(&crc_len.to_le_bytes());
        let segs = vec![DataSeg {
            start: 3,
            len: data.len() as u64,
        }];
        let error = parse_fids(&data, &segs, 2048, "test").expect_err("short CRC refuses");
        assert!(error.to_string().contains("CRC length"), "{:?}", error);
    }

    #[test]
    fn truncated_record_refuses() {
        let mut data = fid_record(0x00, 5, &[8, b'f', b'g'], 3);
        data.truncate(data.len() - 2);
        let segs = vec![DataSeg { start: 3, len: 512 }];
        let error = parse_fids(&data, &segs, 2048, "test").expect_err("cut record refuses");
        assert!(error.to_string().contains("truncated"), "{:?}", error);
    }

    #[test]
    fn short_nonzero_tail_refuses() {
        let data = vec![1u8; 10];
        let segs = vec![DataSeg { start: 3, len: 10 }];
        let error = parse_fids(&data, &segs, 2048, "test").expect_err("10 bytes refuse");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
    }
}
