//! VHDX file identifier, headers and region-table validation.
//!
//! The header section is four 64 KiB blocks: the file identifier
//! (`vhdxfile` at 0), two 4 KiB `head` headers (at 64 KiB and 128 KiB,
//! the higher sequence number wins) and the 64 KiB `regi` region table
//! (at 192 KiB, carrying the BAT and metadata regions). All fields are
//! little-endian and every checksum is CRC-32C over the whole block
//! with the checksum field zeroed. Layout facts come from the real
//! `qemu-img 11.1.3` `-f vhdx` image measured for this slice; the field
//! meanings (log version 0, file version 1, the 1 MiB log alignment,
//! the 2047-entry region cap, the BAT and metadata GUIDs) agree with
//! QEMU's `block/vhdx.h`.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::part::gpt::guid_to_string;

use super::le_u16_at;
use super::le_u32_at;
use super::le_u64_at;
use super::read_at;
use super::window;

/// Offset of the first header (64 KiB).
const HEADER1_OFFSET: u64 = 64 * 1024;
/// Offset of the second header (128 KiB).
const HEADER2_OFFSET: u64 = 128 * 1024;
/// Offset of the region table (192 KiB).
const REGION_OFFSET: u64 = 192 * 1024;
/// Length of each header (4 KiB).
const HEADER_LEN: u64 = 4 * 1024;
/// Length of the region table (64 KiB).
const REGION_LEN: u64 = 64 * 1024;
/// End of the header section: a valid VHDX is at least this long.
const HEADER_SECTION_LEN: u64 = 256 * 1024;
/// `vhdxfile`, the file-identifier signature.
const FILE_SIGNATURE: &[u8] = b"vhdxfile";
/// `head`, the header signature.
const HEADER_SIGNATURE: &[u8] = b"head";
/// `regi`, the region-table signature.
const REGION_SIGNATURE: &[u8] = b"regi";
/// Maximum region-table entries (QEMU's `vhdx.h` cap).
const MAX_REGION_ENTRIES: u32 = 2047;
/// Length of one region-table entry in bytes.
const REGION_ENTRY_LEN: u64 = 32;
/// Required-entry flag (bit 0 of an entry's data bits): a parser that
/// does not understand such an entry must refuse the file.
const REGION_REQUIRED: u32 = 0x01;
/// Region-table entries start after the 16-byte table header.
const REGION_ENTRIES_AT: u64 = 16;
/// BAT region GUID, on-disk (mixed-endian) byte order.
const BAT_GUID: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
/// Metadata region GUID, on-disk (mixed-endian) byte order.
const METADATA_GUID: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];
/// Offset of the checksum within a header.
const HEADER_CHECKSUM_AT: usize = 4;
/// Offset of the sequence number within a header.
const HEADER_SEQUENCE_AT: usize = 8;
/// Offset of the log GUID within a header.
const HEADER_LOG_GUID_AT: usize = 48;
/// Offset of the log version within a header.
const HEADER_LOG_VERSION_AT: usize = 64;
/// Offset of the file version within a header.
const HEADER_VERSION_AT: usize = 66;
/// Offset of the log length within a header.
const HEADER_LOG_LENGTH_AT: usize = 68;
/// Offset of the log offset within a header.
const HEADER_LOG_OFFSET_AT: usize = 72;
/// Only file version the format defines.
const FILE_VERSION_1: u16 = 1;
/// Only log version the format defines.
const LOG_VERSION_0: u16 = 0;
/// Log length and offset are multiples of 1 MiB.
const LOG_ALIGNMENT: u64 = 1024 * 1024;
/// Region file offsets are multiples of 1 MiB.
const REGION_ALIGNMENT: u64 = 1024 * 1024;
/// Offset of the checksum within the region table.
const REGION_CHECKSUM_AT: usize = 4;
/// Offset of the entry count within the region table.
const REGION_COUNT_AT: usize = 8;

/// CRC-32C (Castagnoli, polynomial `0x1EDC6F41`, reflected
/// `0x82F63B78`, init and xor-out `0xFFFFFFFF`), table-free and
/// bitwise like the crate's CRC-32/IEEE: the VHDX headers checksum
/// with this polynomial, so the GPT helper (IEEE `0xEDB88320`) is the
/// wrong function and is not reused.
///
/// Reference vector: `crc32c(b"123456789") == 0xE3069283` (the
/// CRC-32C check value, pinned in the tests below).
fn crc32c(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let low_bit = crc & 1;
            crc >>= 1;
            if low_bit != 0 {
                crc ^= 0x82F6_3B78;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// One parsed header: the fields [`validate`] gates on.
struct Header {
    sequence: u64,
    log_guid: [u8; 16],
    log_version: u16,
    version: u16,
    log_length: u32,
    log_offset: u64,
}

/// Validate a file [`detect`](super::detect) committed to
/// [`ImageKind::Vhdx`](super::ImageKind::Vhdx): the file identifier, both headers (`head`
/// signature, sequence number, CRC-32C), the selected header's version
/// fields and log window, a clean (zero) log GUID, and the region
/// table (`regi` signature, entry count, CRC-32C, the BAT and metadata
/// entries).
///
/// Of the two headers the one with the higher sequence number is
/// current; a header with a bad signature or checksum is skipped, and
/// when neither validates the file is refused naming both failures. A
/// non-zero log GUID means a dirty log needing replay (slice 4 does
/// not implement it), so it is refused rather than read stale.
pub(crate) fn validate(volume: &dyn Volume, total: u64) -> Result<()> {
    if total < HEADER_SECTION_LEN {
        return Err(CoreError::invalid(format!(
            "vhdx file of {total} bytes is shorter than the 262144 byte header section \
             (file identifier, two headers and the region table)"
        )));
    }
    let identifier = read_at(volume, total, 0, 8, "vhdx file identifier")?;
    if identifier != FILE_SIGNATURE {
        return Err(CoreError::invalid(
            "vhdx file identifier is not vhdxfile: refusing a file the detector committed to VHDX",
        ));
    }
    let first = read_at(
        volume,
        total,
        HEADER1_OFFSET,
        HEADER_LEN,
        "vhdx first header",
    )?;
    let second = read_at(
        volume,
        total,
        HEADER2_OFFSET,
        HEADER_LEN,
        "vhdx second header",
    )?;
    let current = match (
        parse_header(&first, "vhdx first header"),
        parse_header(&second, "vhdx second header"),
    ) {
        (Ok(a), Ok(b)) => {
            if a.sequence >= b.sequence {
                a
            } else {
                b
            }
        }
        (Ok(a), Err(_)) => a,
        (Err(_), Ok(b)) => b,
        (Err(first_error), Err(second_error)) => {
            return Err(CoreError::invalid(format!(
                "vhdx neither header validates: first: {first_error}; second: {second_error}"
            )));
        }
    };
    if current.version != FILE_VERSION_1 {
        return Err(CoreError::invalid(format!(
            "vhdx file version {} is not 1",
            current.version
        )));
    }
    if current.log_version != LOG_VERSION_0 {
        return Err(CoreError::invalid(format!(
            "vhdx log version {} is not 0",
            current.log_version
        )));
    }
    let log_end = current
        .log_offset
        .checked_add(u64::from(current.log_length))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx log of {} bytes at offset {} overflows the byte offset arithmetic",
                current.log_length, current.log_offset
            ))
        })?;
    if !current.log_offset.is_multiple_of(LOG_ALIGNMENT)
        || !u64::from(current.log_length).is_multiple_of(LOG_ALIGNMENT)
    {
        return Err(CoreError::invalid(format!(
            "vhdx log at offset {} with length {} is not 1 MiB aligned",
            current.log_offset, current.log_length
        )));
    }
    if log_end > total {
        return Err(CoreError::invalid(format!(
            "vhdx log of {} bytes at offset {} (bytes {}..{log_end}) runs past \
             the {total} byte file end",
            current.log_length, current.log_offset, current.log_offset
        )));
    }
    if current.log_guid != [0u8; 16] {
        return Err(CoreError::invalid(
            "vhdx log GUID is not zero: the log is dirty and needs replay, \
             which this reader does not implement",
        ));
    }
    validate_region(volume, total)?;
    Ok(())
}

/// Parse one 4 KiB header image: signature, CRC-32C (computed with the
/// checksum field zeroed) and the gated fields. Each failure names the
/// header (`vhdx first header`, `vhdx second header`) and the reason.
fn parse_header(header: &[u8], what: &str) -> Result<Header> {
    let signature = window(header, 0, 4, &format!("{what} signature"))?;
    if signature != HEADER_SIGNATURE {
        return Err(CoreError::invalid(format!(
            "{what} signature is not head: refusing a corrupt header"
        )));
    }
    let stored = le_u32_at(header, HEADER_CHECKSUM_AT, &format!("{what} checksum"))?;
    let mut zeroed = header.to_vec();
    for byte in zeroed
        .get_mut(HEADER_CHECKSUM_AT..HEADER_CHECKSUM_AT + 4)
        .ok_or_else(|| CoreError::invalid(format!("{what} is shorter than its checksum field")))?
    {
        *byte = 0;
    }
    let computed = crc32c(&zeroed);
    if stored != computed {
        return Err(CoreError::invalid(format!(
            "{what} checksum mismatch: stored {stored:08x} against computed {computed:08x}"
        )));
    }
    Ok(Header {
        sequence: le_u64_at(
            header,
            HEADER_SEQUENCE_AT,
            &format!("{what} sequence number"),
        )?,
        log_guid: window(header, HEADER_LOG_GUID_AT, 16, &format!("{what} log GUID"))?
            .try_into()
            .map_err(|_| CoreError::invalid(format!("{what} log GUID is not 16 bytes")))?,
        log_version: le_u16_at(
            header,
            HEADER_LOG_VERSION_AT,
            &format!("{what} log version"),
        )?,
        version: le_u16_at(header, HEADER_VERSION_AT, &format!("{what} file version"))?,
        log_length: le_u32_at(header, HEADER_LOG_LENGTH_AT, &format!("{what} log length"))?,
        log_offset: le_u64_at(header, HEADER_LOG_OFFSET_AT, &format!("{what} log offset"))?,
    })
}

/// Validate the 64 KiB region table: `regi` signature, CRC-32C,
/// entry count within the 2047 cap with its entries inside the block,
/// and the BAT plus metadata entries (present, 1 MiB aligned, with a
/// non-empty window inside the file). Unknown entries with the
/// required bit set are refused, like QEMU refuses them.
fn validate_region(volume: &dyn Volume, total: u64) -> Result<()> {
    let table = read_at(
        volume,
        total,
        REGION_OFFSET,
        REGION_LEN,
        "vhdx region table",
    )?;
    let signature = window(&table, 0, 4, "vhdx region table signature")?;
    if signature != REGION_SIGNATURE {
        return Err(CoreError::invalid(
            "vhdx region table signature is not regi: refusing a corrupt table",
        ));
    }
    let stored = le_u32_at(&table, REGION_CHECKSUM_AT, "vhdx region table checksum")?;
    let mut zeroed = table.to_vec();
    for byte in zeroed
        .get_mut(REGION_CHECKSUM_AT..REGION_CHECKSUM_AT + 4)
        .ok_or_else(|| CoreError::invalid("vhdx region table is shorter than its checksum field"))?
    {
        *byte = 0;
    }
    let computed = crc32c(&zeroed);
    if stored != computed {
        return Err(CoreError::invalid(format!(
            "vhdx region table checksum mismatch: stored {stored:08x} against computed {computed:08x}"
        )));
    }
    let count = le_u32_at(&table, REGION_COUNT_AT, "vhdx region table entry count")?;
    if count > MAX_REGION_ENTRIES {
        return Err(CoreError::invalid(format!(
            "vhdx region table entry count {count} exceeds the 2047 entry maximum"
        )));
    }
    let entries_end = REGION_ENTRIES_AT
        .checked_add(
            u64::from(count)
                .checked_mul(REGION_ENTRY_LEN)
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhdx region table of {count} entries overflows the byte offset arithmetic"
                    ))
                })?,
        )
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx region table of {count} entries overflows the byte offset arithmetic"
            ))
        })?;
    if entries_end > REGION_LEN {
        return Err(CoreError::invalid(format!(
            "vhdx region table of {count} entries (bytes 16..{entries_end}) runs past \
             the 65536 byte region block"
        )));
    }
    let mut bat_found = false;
    let mut metadata_found = false;
    for index in 0..count {
        let at = REGION_ENTRIES_AT + u64::from(index) * REGION_ENTRY_LEN;
        let at = usize::try_from(at)
            .map_err(|_| CoreError::invalid("vhdx region table entry offset is not addressable"))?;
        let guid = window(&table, at, 16, "vhdx region table entry GUID")?;
        let guid: [u8; 16] = guid
            .try_into()
            .map_err(|_| CoreError::invalid("vhdx region table entry GUID is not 16 bytes"))?;
        let offset = le_u64_at(&table, at + 16, "vhdx region table entry offset")?;
        let length = le_u32_at(&table, at + 24, "vhdx region table entry length")?;
        let data_bits = le_u32_at(&table, at + 28, "vhdx region table entry flags")?;
        if guid == BAT_GUID {
            bat_found = true;
            check_entry_window("vhdx BAT region", offset, length, total)?;
        } else if guid == METADATA_GUID {
            metadata_found = true;
            check_entry_window("vhdx metadata region", offset, length, total)?;
        } else if data_bits & REGION_REQUIRED != 0 {
            return Err(CoreError::invalid(format!(
                "vhdx region table entry {index} requires unknown region {}",
                guid_to_string(&guid)
            )));
        }
    }
    if !bat_found {
        return Err(CoreError::invalid("vhdx region table has no BAT entry"));
    }
    if !metadata_found {
        return Err(CoreError::invalid(
            "vhdx region table has no metadata entry",
        ));
    }
    Ok(())
}

/// Check one region entry's window: non-empty, 1 MiB aligned, inside
/// the file (checked arithmetic, both numbers named).
fn check_entry_window(what: &str, offset: u64, length: u32, total: u64) -> Result<()> {
    if length == 0 {
        return Err(CoreError::invalid(format!("{what} length is zero")));
    }
    if !offset.is_multiple_of(REGION_ALIGNMENT) {
        return Err(CoreError::invalid(format!(
            "{what} offset {offset} is not 1 MiB aligned"
        )));
    }
    let end = offset.checked_add(u64::from(length)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} of {length} bytes at offset {offset} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{what} of {length} bytes at offset {offset} (bytes {offset}..{end}) runs past \
             the {total} byte file end"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// Total bytes of the synthetic disk: past the header section with
    /// room for the 2 MiB BAT and 3 MiB metadata windows.
    const DISK_LEN: usize = 4 * 1024 * 1024;

    /// Stamp the CRC-32C (computed with the checksum field zeroed) at
    /// bytes 4..8 of `block`.
    fn stamp_crc(block: &mut [u8]) {
        block[4..8].copy_from_slice(&[0, 0, 0, 0]);
        let sum = crc32c(block);
        block[4..8].copy_from_slice(&sum.to_le_bytes());
    }

    /// Write one region-table entry at entry `index`.
    fn stamp_entry(table: &mut [u8], index: usize, guid: &[u8; 16], offset: u64, length: u32) {
        let at = 16 + index * 32;
        table[at..at + 16].copy_from_slice(guid);
        table[at + 16..at + 24].copy_from_slice(&offset.to_le_bytes());
        table[at + 24..at + 28].copy_from_slice(&length.to_le_bytes());
        table[at + 28..at + 32].copy_from_slice(&0u32.to_le_bytes());
    }

    /// Write one header at `at` with sequence `sequence`.
    fn stamp_header(disk: &mut [u8], at: usize, sequence: u64) {
        let header = &mut disk[at..at + 4096];
        header[0..4].copy_from_slice(b"head");
        header[8..16].copy_from_slice(&sequence.to_le_bytes());
        header[66..68].copy_from_slice(&1u16.to_le_bytes());
        header[68..72].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        header[72..80].copy_from_slice(&0x0010_0000u64.to_le_bytes());
        stamp_crc(header);
    }

    /// A well-formed 4 MiB disk: clean log, two headers (the second is
    /// current), BAT at 2 MiB and metadata at 3 MiB.
    fn valid_disk() -> Vec<u8> {
        let mut disk = vec![0u8; DISK_LEN];
        disk[0..8].copy_from_slice(b"vhdxfile");
        stamp_header(&mut disk, 65536, 7);
        stamp_header(&mut disk, 131072, 8);
        let table = &mut disk[196608..196608 + 65536];
        table[0..4].copy_from_slice(b"regi");
        table[8..12].copy_from_slice(&2u32.to_le_bytes());
        stamp_entry(table, 0, &BAT_GUID, 2 * 1024 * 1024, 1024 * 1024);
        stamp_entry(table, 1, &METADATA_GUID, 3 * 1024 * 1024, 1024 * 1024);
        stamp_crc(table);
        disk
    }

    /// Validate `disk` through a memory volume of exactly that length.
    fn validate_disk(disk: &[u8]) -> Result<()> {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        validate(&volume, disk.len() as u64)
    }

    #[test]
    fn crc32c_matches_its_standard_vector() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn valid_disk_passes_and_survives_one_dead_header() {
        validate_disk(&valid_disk()).expect("the well-formed disk validates");

        // Corrupt the current (second) header: the first, with its
        // lower sequence number, carries the file alone.
        let mut disk = valid_disk();
        disk[131072 + 40] ^= 0x01;
        validate_disk(&disk).expect("one dead header is survivable");

        // Neither header validates: both failures are named.
        disk[65536 + 40] ^= 0x01;
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("first"), "{text}");
        assert!(text.contains("second"), "{text}");
    }

    #[test]
    fn truncated_file_and_bad_identifier_refuse() {
        let mut small = vec![0u8; 100 * 1024];
        small[0..8].copy_from_slice(b"vhdxfile");
        let error = validate_disk(&small).unwrap_err();
        assert!(error.to_string().contains("262144 byte header section"));

        let mut disk = valid_disk();
        disk[0..8].copy_from_slice(b"vhdxfilf");
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("not vhdxfile"));
    }

    #[test]
    fn version_and_dirty_log_and_log_window_refuse() {
        let mut disk = valid_disk();
        disk[131072 + 66..131072 + 68].copy_from_slice(&2u16.to_le_bytes());
        stamp_crc(&mut disk[131072..131072 + 4096]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("file version 2"));

        let mut disk = valid_disk();
        disk[131072 + 48] = 0x01;
        stamp_crc(&mut disk[131072..131072 + 4096]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("dirty"));

        let mut disk = valid_disk();
        disk[131072 + 68..131072 + 72].copy_from_slice(&0x0080_0000u32.to_le_bytes());
        stamp_crc(&mut disk[131072..131072 + 4096]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("runs past"));
    }

    #[test]
    fn region_table_refusals_name_their_field() {
        // Bad region checksum.
        let mut disk = valid_disk();
        disk[196608 + 100] ^= 0x01;
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("region table checksum mismatch"));

        // Entry count past the cap.
        let mut disk = valid_disk();
        disk[196608 + 8..196608 + 12].copy_from_slice(&2048u32.to_le_bytes());
        stamp_crc(&mut disk[196608..196608 + 65536]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("exceeds the 2047"));

        // No BAT entry: count one, metadata only.
        let mut disk = valid_disk();
        disk[196608 + 8..196608 + 12].copy_from_slice(&1u32.to_le_bytes());
        let metadata = disk[196608 + 48..196608 + 80].to_vec();
        disk[196608 + 16..196608 + 48].copy_from_slice(&metadata);
        stamp_crc(&mut disk[196608..196608 + 65536]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("no BAT entry"));

        // Unknown required entry.
        let mut disk = valid_disk();
        disk[196608 + 16..196608 + 32].copy_from_slice(&[0x42u8; 16]);
        disk[196608 + 16 + 28..196608 + 16 + 32].copy_from_slice(&1u32.to_le_bytes());
        stamp_crc(&mut disk[196608..196608 + 65536]);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("requires unknown region"));
    }
}
