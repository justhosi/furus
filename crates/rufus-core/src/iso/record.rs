//! Directory records of the primary tree (S14, slice 1).
//!
//! *Measured* — ECMA-119 section 9.1: one length byte, one extended
//! attribute length byte, the extent and data length as both-endian
//! 32-bit words, the 7-byte recording date (kept raw here, decoded by a
//! later slice), the flag byte, unit size and gap, the volume sequence
//! number as a both-endian 16-bit word, the identifier length, the
//! identifier, an alignment pad byte when the identifier length is even,
//! and the system-use tail (Rock Ridge lives there; later slices own it,
//! this one skips it). Records pack a directory's data back to back and
//! never straddle a sector: a zero length byte ends the records of that
//! sector and the next sector continues.
//!
//! *Inferred* — nothing beyond the layout: real mastering tools are
//! expected to emit the same packing, and the slice report says plainly
//! whether the `isoinfo` cross-check ran.
//!
//! Names strip the `;1` version suffix and one trailing `.`, byte-exact
//! otherwise: non-ASCII bytes stay as bytes because Joliet decoding is
//! slice 2's job, and case is never folded. The `.` (`[0x00]`) and `..`
//! (`[0x01]`) records are recognised so listings can skip them while
//! traversal still resolves `..`.

use crate::error::CoreError;
use crate::error::Result;

/// Flag bit 0: the record is hidden from normal listings.
pub const FLAG_HIDDEN: u8 = 0x01;
/// Flag bit 1: the record is a directory.
pub const FLAG_DIRECTORY: u8 = 0x02;
/// Flag bit 2: the record is an associated file.
pub const FLAG_ASSOCIATED: u8 = 0x04;
/// Flag bit 7: this is not the final record of a multi-extent file.
/// Slice 1 refuses such records (slice 2 joins the extents).
pub const FLAG_MULTI_EXTENT: u8 = 0x80;

/// Fixed-part length of a directory record: length byte, extended
/// attribute length, extent (8), data length (8), date (7), flags,
/// unit size, gap, volume sequence number (4) and identifier length.
pub const RECORD_FIXED_LEN: usize = 33;

/// Length of the raw recording-date field, kept byte-exact for a later
/// slice to decode.
pub const DATE_LEN: usize = 7;

/// Identifier of the `.` record: a single zero byte.
const DOT_ID: &[u8; 1] = b"\x00";
/// Identifier of the `..` record: a single `0x01` byte.
const DOTDOT_ID: &[u8; 1] = b"\x01";
/// File-version suffix stripped from identifiers (`NAME.EXT;1`).
const VERSION_SUFFIX: &[u8; 2] = b";1";

/// One parsed directory record: the extent, the length, the raw date,
/// the flag byte and the full identifier (version suffix included —
/// callers strip with [`strip_version`] for display and matching).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirRecord {
    /// Logical sector number of the file or directory data.
    pub extent_lba: u32,
    /// Data length in bytes.
    pub data_len: u32,
    /// Raw 7-byte recording date (years since 1900, month, day, hour,
    /// minute, second, GMT offset in 15-minute steps); decoded later.
    pub recorded: [u8; DATE_LEN],
    /// Raw flag byte ([`FLAG_DIRECTORY`], [`FLAG_MULTI_EXTENT`], ...).
    pub flags: u8,
    /// Full identifier bytes, exactly as stored (including any `;1`).
    pub identifier: Vec<u8>,
}

impl DirRecord {
    /// Flag bit 1: the record is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    /// Flag bit 7: not the final extent; slice 1 refuses these, slice 2
    /// joins them.
    #[must_use]
    pub fn is_multi_extent(&self) -> bool {
        self.flags & FLAG_MULTI_EXTENT != 0
    }

    /// The `.` record (identifier `[0x00]`).
    #[must_use]
    pub fn is_dot(&self) -> bool {
        self.identifier.as_slice() == DOT_ID
    }

    /// The `..` record (identifier `[0x01]`).
    #[must_use]
    pub fn is_parent(&self) -> bool {
        self.identifier.as_slice() == DOTDOT_ID
    }
}

/// One byte at `at` in `record`, refused with the field name when the
/// record ends first.
fn byte_at(record: &[u8], at: usize, field: &str) -> Result<u8> {
    record.get(at).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "directory record of {} bytes ends before its {field} at byte {at}",
            record.len()
        ))
    })
}

/// Both-endian 16-bit word: little-endian half at `le_at`, big-endian
/// half at `be_at`. The halves must agree; a mismatch is refused naming
/// the field and both numbers.
fn both16(record: &[u8], le_at: usize, be_at: usize, field: &str) -> Result<u16> {
    let lo0 = byte_at(record, le_at, field)?;
    let lo1 = byte_at(record, le_at + 1, field)?;
    let hi0 = byte_at(record, be_at, field)?;
    let hi1 = byte_at(record, be_at + 1, field)?;
    let little = u16::from_le_bytes([lo0, lo1]);
    let big = u16::from_be_bytes([hi0, hi1]);
    if little != big {
        return Err(CoreError::invalid(format!(
            "directory record {field} endian halves disagree: little-endian {little} \
             against big-endian {big}"
        )));
    }
    Ok(little)
}

/// Both-endian 32-bit word, same contract as [`both16`].
fn both32(record: &[u8], le_at: usize, be_at: usize, field: &str) -> Result<u32> {
    let b0 = byte_at(record, le_at, field)?;
    let b1 = byte_at(record, le_at + 1, field)?;
    let b2 = byte_at(record, le_at + 2, field)?;
    let b3 = byte_at(record, le_at + 3, field)?;
    let c0 = byte_at(record, be_at, field)?;
    let c1 = byte_at(record, be_at + 1, field)?;
    let c2 = byte_at(record, be_at + 2, field)?;
    let c3 = byte_at(record, be_at + 3, field)?;
    let little = u32::from_le_bytes([b0, b1, b2, b3]);
    let big = u32::from_be_bytes([c0, c1, c2, c3]);
    if little != big {
        return Err(CoreError::invalid(format!(
            "directory record {field} endian halves disagree: little-endian {little} \
             against big-endian {big}"
        )));
    }
    Ok(little)
}

/// Parse exactly one directory record from `record` (which must hold the
/// record's bytes and nothing else — the caller slices `offset..offset +
/// len` first).
///
/// Refuses: records shorter than the 33-byte fixed part, a nonzero
/// extended attribute length (slice 1 has no extended-attribute support),
/// disagreeing endian halves (both numbers named), a nonzero file unit
/// size or interleave gap (interleaved files are not supported), and an
/// identifier that does not fit the record length. The system-use tail is
/// skipped: Rock Ridge parsing belongs to a later slice.
pub fn parse_record(record: &[u8]) -> Result<DirRecord> {
    let len = record.len();
    if len < RECORD_FIXED_LEN {
        return Err(CoreError::invalid(format!(
            "directory record of {len} bytes is shorter than the {RECORD_FIXED_LEN} byte fixed part"
        )));
    }
    let ext_attr_len = byte_at(record, 1, "extended attribute length")?;
    if ext_attr_len != 0 {
        return Err(CoreError::invalid(format!(
            "directory record has extended attribute length {ext_attr_len}: \
             extended attributes are not supported"
        )));
    }
    let extent_lba = both32(record, 2, 6, "extent")?;
    let data_len = both32(record, 10, 14, "data length")?;
    let date = record.get(18..25).ok_or_else(|| {
        CoreError::invalid(format!(
            "directory record of {len} bytes ends before its recording date at bytes 18..25"
        ))
    })?;
    let mut recorded = [0u8; DATE_LEN];
    recorded.copy_from_slice(date);
    let flags = byte_at(record, 25, "flags")?;
    let unit_size = byte_at(record, 26, "file unit size")?;
    let gap_size = byte_at(record, 27, "interleave gap size")?;
    if unit_size != 0 || gap_size != 0 {
        return Err(CoreError::invalid(format!(
            "interleaved files are not supported: directory record has file unit size \
             {unit_size} and interleave gap size {gap_size}"
        )));
    }
    let _volume_seq = both16(record, 28, 30, "volume sequence number")?;
    let ident_len = usize::from(byte_at(record, 32, "identifier length")?);
    // ECMA-119 pads with one byte when the identifier length is even so
    // the system-use tail starts even.
    let pad = if ident_len.is_multiple_of(2) { 1 } else { 0 };
    let ident_end = RECORD_FIXED_LEN
        .checked_add(ident_len)
        .ok_or_else(|| CoreError::invalid("directory record identifier length overflows"))?;
    let minimum = ident_end
        .checked_add(pad)
        .ok_or_else(|| CoreError::invalid("directory record identifier length overflows"))?;
    if len < minimum {
        return Err(CoreError::invalid(format!(
            "directory record of {len} bytes is too short for its {ident_len} byte identifier"
        )));
    }
    let identifier = record
        .get(RECORD_FIXED_LEN..ident_end)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "directory record of {len} bytes ends inside its {ident_len} byte identifier"
            ))
        })?
        .to_vec();
    Ok(DirRecord {
        extent_lba,
        data_len,
        recorded,
        flags,
        identifier,
    })
}

/// Parse the records packed in one sector image: `sector` holds whole
/// sector bytes and only the first `valid_len` of them carry this
/// directory's data (a directory whose length is not a sector multiple
/// uses its last sector partially, per ECMA-119).
///
/// A zero length byte ends the records of this sector (the next sector
/// continues); a record claiming to run past the valid prefix is refused
/// with the sector, the offset, the claimed length and the valid count
/// all named, because records may not straddle a sector.
pub fn parse_records(sector: &[u8], valid_len: usize, sector_no: u32) -> Result<Vec<DirRecord>> {
    let mut out = Vec::new();
    let mut offset: usize = 0;
    while offset < valid_len {
        let len = usize::from(sector.get(offset).copied().ok_or_else(|| {
            CoreError::invalid(format!(
                "directory sector {sector_no} of {} bytes ends before offset {offset}",
                sector.len()
            ))
        })?);
        if len == 0 {
            break;
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "directory record of {len} bytes at offset {offset} of sector {sector_no} \
                 overflows the offset arithmetic"
            ))
        })?;
        if end > valid_len {
            return Err(CoreError::invalid(format!(
                "directory record of {len} bytes at offset {offset} of sector {sector_no} \
                 runs past the {valid_len} valid bytes: records may not straddle a sector"
            )));
        }
        let bytes = sector.get(offset..end).ok_or_else(|| {
            CoreError::invalid(format!(
                "directory sector {sector_no} ends inside the {len} byte record at offset {offset}"
            ))
        })?;
        let record = parse_record(bytes).map_err(|error| {
            CoreError::invalid(format!("sector {sector_no} offset {offset}: {error}"))
        })?;
        out.push(record);
        offset = end;
    }
    Ok(out)
}

/// Display/matching form of an identifier: the `;1` version suffix and
/// one trailing `.` stripped, everything else byte-exact (non-ASCII
/// bytes survive untouched for slice 2's Joliet decoding).
#[must_use]
pub fn strip_version(identifier: &[u8]) -> Vec<u8> {
    let mut end = identifier.len();
    if end >= VERSION_SUFFIX.len()
        && identifier.get(end - VERSION_SUFFIX.len()..end) == Some(VERSION_SUFFIX.as_slice())
    {
        end -= VERSION_SUFFIX.len();
    }
    if end >= 1 && identifier.get(end - 1) == Some(&b'.') {
        end -= 1;
    }
    match identifier.get(..end) {
        Some(stripped) => stripped.to_vec(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iso::SECTOR_BYTES;

    /// Encode one directory record the way the reader tests build
    /// fixtures: both-endian words, 7 zero date bytes, flags, no
    /// interleave, sequence 1, identifier plus the even-length pad.
    /// Test-only encoding of the on-disk layout, not a second parser.
    fn encode_record(extent: u32, data_len: u32, flags: u8, identifier: &[u8]) -> Vec<u8> {
        let pad = if identifier.len().is_multiple_of(2) {
            1
        } else {
            0
        };
        let len = RECORD_FIXED_LEN + identifier.len() + pad;
        let mut out = vec![0u8; len];
        out[0] = len as u8;
        out[1] = 0;
        out[2..6].copy_from_slice(&extent.to_le_bytes());
        out[6..10].copy_from_slice(&extent.to_be_bytes());
        out[10..14].copy_from_slice(&data_len.to_le_bytes());
        out[14..18].copy_from_slice(&data_len.to_be_bytes());
        out[25] = flags;
        out[28..30].copy_from_slice(&1u16.to_le_bytes());
        out[30..32].copy_from_slice(&1u16.to_be_bytes());
        out[32] = identifier.len() as u8;
        out[33..33 + identifier.len()].copy_from_slice(identifier);
        out
    }

    #[test]
    fn parse_record_reads_every_field() {
        let bytes = encode_record(21, 11, FLAG_DIRECTORY, b"DIR");
        let record = parse_record(&bytes).expect("the encoded record parses");
        assert_eq!(record.extent_lba, 21);
        assert_eq!(record.data_len, 11);
        assert_eq!(record.recorded, [0u8; DATE_LEN]);
        assert!(record.is_dir());
        assert!(!record.is_multi_extent());
        assert!(!record.is_dot());
        assert!(!record.is_parent());
        assert_eq!(record.identifier, b"DIR");
    }

    #[test]
    fn dot_and_parent_identifiers_recognised() {
        let dot =
            parse_record(&encode_record(20, 2048, FLAG_DIRECTORY, b"\x00")).expect("dot parses");
        assert!(dot.is_dot());
        assert!(!dot.is_parent());
        let parent = parse_record(&encode_record(20, 2048, FLAG_DIRECTORY, b"\x01"))
            .expect("dot-dot parses");
        assert!(parent.is_parent());
        assert!(!parent.is_dot());
    }

    #[test]
    fn short_record_refused() {
        let error = parse_record(&[34u8; 10]).expect_err("10 bytes hold no record");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("33"), "{text}");
    }

    #[test]
    fn nonzero_extended_attribute_length_refused() {
        let mut bytes = encode_record(21, 11, 0, b"F");
        bytes[1] = 1;
        let error = parse_record(&bytes).expect_err("extended attributes refuse");
        assert!(error.to_string().contains("1"), "{error}");
    }

    #[test]
    fn endian_mismatch_names_both_numbers() {
        let mut bytes = encode_record(21, 11, 0, b"F");
        bytes[2] = 22;
        let error = parse_record(&bytes).expect_err("halves disagree");
        let text = error.to_string();
        assert!(text.contains("22"), "{text}");
        assert!(text.contains("21"), "{text}");
    }

    #[test]
    fn interleave_refused_with_the_supported_message() {
        let mut bytes = encode_record(21, 11, 0, b"F");
        bytes[26] = 1;
        let error = parse_record(&bytes).expect_err("unit size 1 refuses");
        let text = error.to_string();
        assert!(
            text.contains("interleaved files are not supported"),
            "{text}"
        );
        assert!(text.contains("1"), "{text}");

        let mut gap = encode_record(21, 11, 0, b"F");
        gap[27] = 2;
        let error = parse_record(&gap).expect_err("gap size 2 refuses");
        assert!(
            error
                .to_string()
                .contains("interleaved files are not supported"),
            "{error}"
        );
    }

    #[test]
    fn identifier_overrunning_the_record_refused() {
        let mut bytes = encode_record(21, 11, 0, b"AB");
        let len = bytes.len();
        bytes[32] = 200;
        let error = parse_record(&bytes).expect_err("the identifier does not fit");
        let text = error.to_string();
        assert!(text.contains(len.to_string().as_str()), "{text}");
        assert!(text.contains("200"), "{text}");
    }

    #[test]
    fn strip_version_cuts_semicolon_one_and_trailing_dot() {
        assert_eq!(strip_version(b"B.TXT;1"), b"B.TXT");
        assert_eq!(strip_version(b"FILE.;1"), b"FILE");
        assert_eq!(strip_version(b"DIR"), b"DIR");
        assert_eq!(strip_version(b"A."), b"A");
        // Only the exact `;1` suffix strips; the rest stays byte-exact.
        assert_eq!(strip_version(b"A;12"), b"A;12");
        assert_eq!(strip_version(b";1"), b"");
    }

    #[test]
    fn non_ascii_bytes_survive_stripping() {
        let identifier = b"CAF\xC3\xA9.TXT;1";
        assert_eq!(strip_version(identifier), b"CAF\xC3\xA9.TXT");
    }

    #[test]
    fn zero_length_byte_ends_the_sector() {
        let mut sector = [0u8; SECTOR_BYTES];
        let first = encode_record(21, 11, 0, b"A");
        sector[..first.len()].copy_from_slice(&first);
        // The rest stays zero: one record, then padding to the end.
        let records = parse_records(&sector, SECTOR_BYTES, 21).expect("padding ends cleanly");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].identifier, b"A");
    }

    #[test]
    fn record_running_past_its_sector_refused() {
        let mut sector = [0u8; SECTOR_BYTES];
        // One valid record first so parsing reaches the tail: a record
        // claiming 60 bytes with only 40 valid bytes left.
        let first = encode_record(21, 11, 0, b"A");
        sector[..first.len()].copy_from_slice(&first);
        let at = first.len();
        sector[at] = 60;
        let error = parse_records(&sector, at + 40, 77).expect_err("the record overruns");
        let text = error.to_string();
        assert!(text.contains("60"), "{text}");
        assert!(text.contains("77"), "{text}");
    }

    #[test]
    fn record_running_past_a_partial_tail_refused() {
        // Directory data ends 10 bytes into the last sector; a record
        // claiming 34 bytes there overruns the valid prefix.
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = 34;
        let error = parse_records(&sector, 10, 9).expect_err("the tail is short");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("34"), "{text}");
    }
}
