//! VHDX file identifier, headers, region-table and metadata validation,
//! plus the logical reader.
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
//!
//! The reader ([`VhdxReader`]) exposes the logical bytes as a
//! [`Volume`](crate::fs::Volume): the block size and the virtual size
//! come from the metadata region, and each virtual block maps through
//! one BAT entry (state bits 0..=2, file offset in 1 MiB units from
//! bit 20 up) to its payload.
//!
//! *Measured* — `qemu-img 11.1.3` in `archlinux:latest`: a 64 MiB
//! `-f vhdx` conversion of a raw file reads back as the 67108864 byte
//! virtual size from the metadata item, with 8 MiB blocks mapped
//! through fully-present BAT entries to file offsets in 1 MiB units,
//! byte-exact against `qemu-img convert -O raw`. Markers written with
//! `dd` into the raw at 0, 1 MiB, 2 MiB, 32 MiB and the last 512 bytes
//! all read back at their virtual offsets.
//!
//! *Inferred* — the refusal of partially-present blocks (state 7: no
//! producer on this host emits a sector bitmap, and QEMU's own read
//! path fails those too) and of the reserved state 4; the zero-read
//! of the legacy unmapped state 5 (QEMU treats it like unmapped).

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
/// Length of one BAT entry in bytes.
const BAT_ENTRY_LEN: u64 = 8;
/// Mask of the BAT entry state (bits 0..=2, QEMU's
/// `VHDX_BAT_STATE_BIT_MASK`).
const BAT_STATE_MASK: u64 = 0x07;
/// Shift of the BAT entry file offset: bits 20 and up count 1 MiB
/// units (QEMU's `VHDX_BAT_FILE_OFF_MASK` starts at bit 20).
const BAT_OFFSET_SHIFT: u32 = 20;
/// Bytes per BAT file-offset unit (1 MiB).
const BAT_OFFSET_UNIT: u64 = 1024 * 1024;
/// BAT state of a block with no payload (reads as zeros).
const BAT_NOT_PRESENT: u64 = 0;
/// BAT state of a block QEMU leaves undefined (reads as zeros).
const BAT_UNDEFINED: u64 = 1;
/// BAT state of a zero-filled block (reads as zeros).
const BAT_ZERO: u64 = 2;
/// BAT state of an unmapped block (reads as zeros).
const BAT_UNMAPPED: u64 = 3;
/// BAT state of an unmapped block written by the pre-1.0 layout
/// (reads as zeros, like QEMU treats it).
const BAT_UNMAPPED_V095: u64 = 5;
/// BAT state of a block whose payload follows in full.
const BAT_FULLY_PRESENT: u64 = 6;
/// BAT state of a block with a sector bitmap (refused: QEMU's own
/// read path fails those too, so `qemu-img convert` errors there
/// just like this reader).
const BAT_PARTIALLY_PRESENT: u64 = 7;
/// Reserved BAT state 4 (refused: only fully present blocks are
/// readable).
const BAT_RESERVED: u64 = 4;
/// Length of the metadata table header in bytes.
const METADATA_HEADER_LEN: u64 = 32;
/// Length of one metadata table entry in bytes.
const METADATA_ENTRY_LEN: u64 = 32;
/// Maximum metadata entries (QEMU's `VHDX_METADATA_MAX_ENTRIES`).
const MAX_METADATA_ENTRIES: u64 = 2047;
/// Offset of the entry count within the metadata table header (a
/// `u16` after the 8-byte signature and 2 reserved bytes).
const METADATA_COUNT_AT: usize = 10;
/// Offset of an entry's byte offset within a metadata table entry.
const METADATA_OFFSET_AT: usize = 16;
/// Offset of an entry's length within a metadata table entry.
const METADATA_LENGTH_AT: usize = 20;
/// Offset of an entry's data bits within a metadata table entry.
const METADATA_FLAGS_AT: usize = 24;
/// Metadata-entry flag without which the file must be refused when
/// the entry is not understood (QEMU's `VHDX_META_FLAGS_IS_REQUIRED`).
const METADATA_REQUIRED: u32 = 0x04;
/// File-parameters flag marking a differencing disk, which needs
/// its parent (QEMU's `VHDX_PARAMS_HAS_PARENT`).
const FILE_PARAM_HAS_PARENT: u32 = 0x02;
/// Smallest payload block in bytes (QEMU's `VHDX_BLOCK_SIZE_MIN`).
const BLOCK_SIZE_MIN: u64 = 1024 * 1024;
/// Largest payload block in bytes (QEMU's `VHDX_BLOCK_SIZE_MAX`).
const BLOCK_SIZE_MAX: u64 = 256 * 1024 * 1024;
/// Largest virtual disk in bytes (QEMU's `VHDX_MAX_IMAGE_SIZE`).
const MAX_IMAGE_SIZE: u64 = 64 * 1024 * 1024 * 1024 * 1024;
/// File-parameters item GUID, on-disk (mixed-endian) byte order
/// (`caa16737-fa36-4d43-b3b6-33f0aa44e76b`, byte-verified against
/// the real `qemu-img` image).
const FILE_PARAM_GUID: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
/// Virtual-disk-size item GUID (`2fa54224-cd1b-4876-b211-5dbed83bf4b8`,
/// byte-verified against the real image).
const VIRTUAL_SIZE_GUID: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
/// Virtual-disk-ID item GUID (`beca12ab-b2e6-4523-93ef-c309e000c746`,
/// byte-verified against the real image; presence only is required).
const PAGE83_GUID: [u8; 16] = [
    0xab, 0x12, 0xca, 0xbe, 0xe6, 0xb2, 0x23, 0x45, 0x93, 0xef, 0xc3, 0x09, 0xe0, 0x00, 0xc7, 0x46,
];
/// Logical-sector-size item GUID (`8141bf1d-a96f-4709-ba47-f233a8faab5f`,
/// byte-verified against the real image).
const LOGICAL_SECTOR_GUID: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];
/// Physical-sector-size item GUID (`cda348c7-445d-4471-9cc9-e9885251c556`,
/// byte-verified against the real image).
const PHYS_SECTOR_GUID: [u8; 16] = [
    0xc7, 0x48, 0xa3, 0xcd, 0x5d, 0x44, 0x71, 0x44, 0x9c, 0xc9, 0xe9, 0x88, 0x52, 0x51, 0xc5, 0x56,
];
/// Parent-locator item GUID (`a8d35f2d-b30b-454d-abf7-d3d84834ab0c`,
/// from QEMU's `block/vhdx.c`: no producer sample on this host
/// carries one, so only the refusal it triggers is covered).
const PARENT_LOCATOR_GUID: [u8; 16] = [
    0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c,
];

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

/// Read and checksum the 64 KiB region table: the `regi` signature
/// and the CRC-32C (computed with the checksum field zeroed) are
/// checked here, so [`validate_region`] and the reader share one
/// checked copy. Each failure names the table and the reason.
fn read_region_table(volume: &dyn Volume, total: u64) -> Result<Vec<u8>> {
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
    Ok(table)
}

/// Validate the 64 KiB region table: `regi` signature, CRC-32C,
/// entry count within the 2047 cap with its entries inside the block,
/// and the BAT plus metadata entries (present, 1 MiB aligned, with a
/// non-empty window inside the file). Unknown entries with the
/// required bit set are refused, like QEMU refuses them.
fn validate_region(volume: &dyn Volume, total: u64) -> Result<()> {
    let table = read_region_table(volume, total)?;
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

/// Where the BAT and metadata regions live (file offsets from the
/// region table, already window-checked by [`validate_region`]).
struct Regions {
    bat_offset: u64,
    bat_length: u64,
    metadata_offset: u64,
    metadata_length: u64,
}

/// Locate the BAT and metadata regions in the region table: the same
/// walk [`validate_region`] performs, returning the offsets instead of
/// dropping them. Runs after [`validate`], so the signature, the
/// checksum and both windows are already proven; each lookup failure
/// still names its table and reason.
fn find_regions(volume: &dyn Volume, total: u64) -> Result<Regions> {
    let table = read_region_table(volume, total)?;
    let count = le_u32_at(&table, REGION_COUNT_AT, "vhdx region table entry count")?;
    let mut bat: Option<(u64, u64)> = None;
    let mut metadata: Option<(u64, u64)> = None;
    for index in 0..count {
        let at = REGION_ENTRIES_AT
            .checked_add(
                u64::from(index)
                    .checked_mul(REGION_ENTRY_LEN)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhdx region table entry {index} overflows the byte offset arithmetic"
                        ))
                    })?,
            )
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhdx region table entry {index} overflows the byte offset arithmetic"
                ))
            })?;
        let at = usize::try_from(at)
            .map_err(|_| CoreError::invalid("vhdx region table entry offset is not addressable"))?;
        let guid = window(&table, at, 16, "vhdx region table entry GUID")?;
        let guid: [u8; 16] = guid
            .try_into()
            .map_err(|_| CoreError::invalid("vhdx region table entry GUID is not 16 bytes"))?;
        let offset = le_u64_at(&table, at + 16, "vhdx region table entry offset")?;
        let length = le_u32_at(&table, at + 24, "vhdx region table entry length")?;
        if guid == BAT_GUID {
            bat = Some((offset, u64::from(length)));
        } else if guid == METADATA_GUID {
            metadata = Some((offset, u64::from(length)));
        }
    }
    let (bat_offset, bat_length) =
        bat.ok_or_else(|| CoreError::invalid("vhdx region table has no BAT entry"))?;
    let (metadata_offset, metadata_length) =
        metadata.ok_or_else(|| CoreError::invalid("vhdx region table has no metadata entry"))?;
    Ok(Regions {
        bat_offset,
        bat_length,
        metadata_offset,
        metadata_length,
    })
}

/// The geometry the metadata table commits to: the payload block size
/// and the virtual disk size.
struct Geometry {
    block_size: u64,
    virtual_size: u64,
    block_count: u64,
}

/// One metadata-table item: its data window inside the metadata
/// region, already bounds-checked.
struct MetadataItem {
    offset: u64,
    length: u32,
}

/// Look up the item with `guid` in the metadata table at
/// `metadata_offset`: the table signature, the entry count within the
/// 2047 cap, each entry window inside the region, and the refusal of
/// unknown entries carrying the required bit (like QEMU refuses
/// them). A missing item is refused naming the table; each failure
/// names the field and the value.
fn metadata_item(
    file: &dyn Volume,
    file_total: u64,
    metadata_offset: u64,
    metadata_length: u64,
    guid: &[u8; 16],
    what: &str,
) -> Result<MetadataItem> {
    let table = read_at(
        file,
        file_total,
        metadata_offset,
        METADATA_HEADER_LEN,
        "vhdx metadata table header",
    )?;
    let signature = window(&table, 0, 8, "vhdx metadata table signature")?;
    if signature != b"metadata" {
        return Err(CoreError::invalid(
            "vhdx metadata table signature is not metadata: refusing a corrupt table",
        ));
    }
    let count = le_u16_at(&table, METADATA_COUNT_AT, "vhdx metadata table entry count")?;
    if u64::from(count) > MAX_METADATA_ENTRIES {
        return Err(CoreError::invalid(format!(
            "vhdx metadata table entry count {count} exceeds the 2047 entry maximum"
        )));
    }
    let mut found: Option<MetadataItem> = None;
    for index in 0..count {
        let entry_at = METADATA_HEADER_LEN
            .checked_add(
                u64::from(index)
                    .checked_mul(METADATA_ENTRY_LEN)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhdx metadata table entry {index} overflows the byte offset arithmetic"
                        ))
                    })?,
            )
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhdx metadata table entry {index} overflows the byte offset arithmetic"
                ))
            })?;
        let entry_end = entry_at.checked_add(METADATA_ENTRY_LEN).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx metadata table entry {index} overflows the byte offset arithmetic"
            ))
        })?;
        if entry_end > metadata_length {
            return Err(CoreError::invalid(format!(
                "vhdx metadata table entry {index} (bytes {entry_at}..{entry_end}) runs past \
                 the {metadata_length} byte metadata region"
            )));
        }
        let entry_base = metadata_offset.checked_add(entry_at).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx metadata table entry {index} at offset {metadata_offset} \
                 overflows the byte offset arithmetic"
            ))
        })?;
        let entry = read_at(
            file,
            file_total,
            entry_base,
            METADATA_ENTRY_LEN,
            "vhdx metadata table entry",
        )?;
        let entry_guid = window(&entry, 0, 16, "vhdx metadata table entry GUID")?;
        let flags = le_u32_at(&entry, METADATA_FLAGS_AT, "vhdx metadata table entry flags")?;
        if entry_guid == guid.as_slice() {
            let offset = le_u32_at(
                &entry,
                METADATA_OFFSET_AT,
                "vhdx metadata table entry offset",
            )?;
            let length = le_u32_at(
                &entry,
                METADATA_LENGTH_AT,
                "vhdx metadata table entry length",
            )?;
            let item_end = u64::from(offset)
                .checked_add(u64::from(length))
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "{what} of {length} bytes at metadata offset {offset} \
                     overflows the byte offset arithmetic"
                    ))
                })?;
            if item_end > metadata_length {
                return Err(CoreError::invalid(format!(
                    "{what} of {length} bytes at metadata offset {offset} \
                     (bytes {offset}..{item_end}) runs past \
                     the {metadata_length} byte metadata region"
                )));
            }
            found = Some(MetadataItem {
                offset: u64::from(offset),
                length,
            });
        } else if !is_known_metadata(entry_guid) && flags & METADATA_REQUIRED != 0 {
            return Err(CoreError::invalid(format!(
                "vhdx metadata table entry {index} requires unknown metadata item"
            )));
        }
    }
    found.ok_or_else(|| CoreError::invalid(format!("vhdx metadata table has no {what}")))
}

/// Whether `guid_bytes` (16 raw bytes) is one of the metadata items
/// this reader understands: unknown items without the required bit
/// are skipped, like QEMU skips them.
fn is_known_metadata(guid_bytes: &[u8]) -> bool {
    guid_bytes == FILE_PARAM_GUID.as_slice()
        || guid_bytes == VIRTUAL_SIZE_GUID.as_slice()
        || guid_bytes == PAGE83_GUID.as_slice()
        || guid_bytes == LOGICAL_SECTOR_GUID.as_slice()
        || guid_bytes == PHYS_SECTOR_GUID.as_slice()
}

/// Read the geometry out of the metadata region: the block size from
/// the file-parameters item (within the 1 MiB..=256 MiB range, with a
/// differencing disk refused for needing its parent), the virtual
/// size (non-zero, within the 64 TiB maximum), the presence of the
/// page-83 ID, and non-zero sector sizes. Each refusal names the
/// field and the value.
fn read_geometry(
    file: &dyn Volume,
    file_total: u64,
    metadata_offset: u64,
    metadata_length: u64,
) -> Result<Geometry> {
    let item_at = |item: &MetadataItem| {
        metadata_offset.checked_add(item.offset).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx metadata item at offset {} overflows the byte offset arithmetic",
                item.offset
            ))
        })
    };
    let params = metadata_item(
        file,
        file_total,
        metadata_offset,
        metadata_length,
        &FILE_PARAM_GUID,
        "vhdx file parameters",
    )?;
    if params.length < 8 {
        return Err(CoreError::invalid(format!(
            "vhdx file parameters length {} is shorter than the 8 byte block size and flags",
            params.length
        )));
    }
    let params_bytes = read_at(
        file,
        file_total,
        item_at(&params)?,
        8,
        "vhdx file parameters",
    )?;
    let block_size = le_u32_at(&params_bytes, 0, "vhdx block size")?;
    let block_size = u64::from(block_size);
    if !(BLOCK_SIZE_MIN..=BLOCK_SIZE_MAX).contains(&block_size) {
        return Err(CoreError::invalid(format!(
            "vhdx block size {block_size} is outside the 1048576..=268435456 range"
        )));
    }
    let param_flags = le_u32_at(&params_bytes, 4, "vhdx file parameters flags")?;
    if param_flags & FILE_PARAM_HAS_PARENT != 0 {
        return Err(CoreError::invalid(
            "vhdx file parameters mark a differencing disk: parent images are not readable standalone",
        ));
    }
    if metadata_item(
        file,
        file_total,
        metadata_offset,
        metadata_length,
        &PARENT_LOCATOR_GUID,
        "vhdx parent locator",
    )
    .is_ok()
    {
        return Err(CoreError::invalid(
            "vhdx metadata carries a parent locator: differencing disks need their parent image",
        ));
    }
    let size_item = metadata_item(
        file,
        file_total,
        metadata_offset,
        metadata_length,
        &VIRTUAL_SIZE_GUID,
        "vhdx virtual disk size",
    )?;
    if size_item.length < 8 {
        return Err(CoreError::invalid(format!(
            "vhdx virtual disk size length {} is shorter than the 8 byte size",
            size_item.length
        )));
    }
    let size_bytes = read_at(
        file,
        file_total,
        item_at(&size_item)?,
        8,
        "vhdx virtual disk size",
    )?;
    let virtual_size = le_u64_at(&size_bytes, 0, "vhdx virtual disk size")?;
    if virtual_size == 0 {
        return Err(CoreError::invalid("vhdx virtual disk size is zero"));
    }
    if virtual_size > MAX_IMAGE_SIZE {
        return Err(CoreError::invalid(format!(
            "vhdx virtual disk size {virtual_size} exceeds the 70368744177664 byte maximum"
        )));
    }
    metadata_item(
        file,
        file_total,
        metadata_offset,
        metadata_length,
        &PAGE83_GUID,
        "vhdx virtual disk identifier",
    )?;
    for (guid, what) in [
        (&LOGICAL_SECTOR_GUID, "vhdx logical sector size"),
        (&PHYS_SECTOR_GUID, "vhdx physical sector size"),
    ] {
        let item = metadata_item(
            file,
            file_total,
            metadata_offset,
            metadata_length,
            guid,
            what,
        )?;
        if item.length < 4 {
            return Err(CoreError::invalid(format!(
                "{what} length {} is shorter than the 4 byte size",
                item.length
            )));
        }
        let bytes = read_at(file, file_total, item_at(&item)?, 4, what)?;
        let sectors = le_u32_at(&bytes, 0, what)?;
        if sectors == 0 {
            return Err(CoreError::invalid(format!("{what} is zero")));
        }
    }
    let block_count = virtual_size
        .checked_add(block_size - 1)
        .and_then(|rounded| rounded.checked_div(block_size))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx virtual size {virtual_size} with {block_size} byte blocks \
                 overflows the block count arithmetic"
            ))
        })?;
    Ok(Geometry {
        block_size,
        virtual_size,
        block_count,
    })
}

/// The logical VHDX volume: the file's virtual bytes as a read-only
/// [`Volume`].
///
/// Each virtual byte maps through its block (`offset / block_size`)
/// to one BAT entry (a little-endian `u64`: the state in bits 0..=2,
/// the file offset in 1 MiB units from bit 20 up). States 0, 1, 2, 3
/// and 5 (not present, undefined, zero, unmapped, legacy unmapped)
/// read as zeros; state 6 (fully present) reads the `block_size`
/// payload at the stored offset; state 7 (partially present) carries
/// a sector bitmap QEMU's own read path fails too, so it is refused;
/// state 4 is reserved and refused. Every mapping is bounds-checked
/// before I/O with checked arithmetic. Tables are read positionally
/// on demand (8 bytes per BAT entry): nothing is cached.
pub(crate) struct VhdxReader {
    file: Box<dyn Volume>,
    file_total: u64,
    virtual_size: u64,
    block_size: u64,
    block_count: u64,
    bat_offset: u64,
    bat_length: u64,
}

impl std::fmt::Debug for VhdxReader {
    /// The virtual size and the layout: the file itself has no useful
    /// textual shape (it is an open store), so it is not rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdxReader")
            .field("virtual_size", &self.virtual_size)
            .field("block_size", &self.block_size)
            .field("block_count", &self.block_count)
            .finish_non_exhaustive()
    }
}

/// Open the validated VHDX `file` (a `total` byte store [`validate`]
/// accepted) as its logical volume.
pub(crate) fn open(file: Box<dyn Volume>, total: u64) -> Result<VhdxReader> {
    validate(file.as_ref(), total)?;
    let regions = find_regions(file.as_ref(), total)?;
    let geometry = read_geometry(
        file.as_ref(),
        total,
        regions.metadata_offset,
        regions.metadata_length,
    )?;
    let table_len = geometry
        .block_count
        .checked_mul(BAT_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx BAT of {} entries overflows the byte offset arithmetic",
                geometry.block_count
            ))
        })?;
    if table_len > regions.bat_length {
        return Err(CoreError::invalid(format!(
            "vhdx BAT of {} entries ({} bytes) runs past the {} byte BAT region",
            geometry.block_count, table_len, regions.bat_length
        )));
    }
    Ok(VhdxReader {
        file,
        file_total: total,
        virtual_size: geometry.virtual_size,
        block_size: geometry.block_size,
        block_count: geometry.block_count,
        bat_offset: regions.bat_offset,
        bat_length: regions.bat_length,
    })
}

/// Read the raw BAT entry for `block`: an index past `block_count`
/// is refused naming both numbers before any I/O, and the 8-byte
/// window must sit inside the BAT region (never just inside the
/// file: a short region with a long tail is corrupt).
fn bat_entry(reader: &VhdxReader, block: u64) -> Result<u64> {
    if block >= reader.block_count {
        return Err(CoreError::invalid(format!(
            "vhdx block {block} is past the {} BAT entries",
            reader.block_count
        )));
    }
    let at = reader
        .bat_offset
        .checked_add(block.checked_mul(BAT_ENTRY_LEN).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx BAT entry {block} overflows the byte offset arithmetic"
            ))
        })?)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx BAT entry {block} at offset {} overflows the byte offset arithmetic",
                reader.bat_offset
            ))
        })?;
    let end = at.checked_add(BAT_ENTRY_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhdx BAT entry {block} overflows the byte offset arithmetic"
        ))
    })?;
    let region_end = reader
        .bat_offset
        .checked_add(reader.bat_length)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx BAT region at offset {} of {} bytes overflows the byte offset arithmetic",
                reader.bat_offset, reader.bat_length
            ))
        })?;
    if end > region_end {
        return Err(CoreError::invalid(format!(
            "vhdx BAT entry {block} (bytes {at}..{end}) runs past \
             the {} byte BAT region end {region_end}",
            reader.bat_length
        )));
    }
    let bytes = read_at(
        reader.file.as_ref(),
        reader.file_total,
        at,
        8,
        "vhdx BAT entry",
    )?;
    le_u64_at(&bytes, 0, "vhdx BAT entry")
}

impl VhdxReader {
    /// Map one virtual span starting at `cur` (with `end` the read's
    /// end): the file offset (`None` reads as zeros) plus the span
    /// length, capped so the span never crosses a block boundary (a
    /// fresh BAT lookup applies past it) nor `end`. A partially
    /// present block (state 7) or the reserved state 4 is refused
    /// naming the block and the raw entry.
    fn span(&self, cur: u64, end: u64) -> Result<(Option<u64>, u64)> {
        let block = cur.checked_div(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx offset {cur} with {} byte blocks overflows the block number arithmetic",
                self.block_size
            ))
        })?;
        let base = block.checked_mul(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx block {block} with {} byte blocks overflows the byte offset arithmetic",
                self.block_size
            ))
        })?;
        let within = cur.checked_sub(base).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx offset {cur} runs before its block {block} base {base}"
            ))
        })?;
        let block_end = base.checked_add(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx block {block} with {} byte blocks overflows the byte offset arithmetic",
                self.block_size
            ))
        })?;
        let left = block_end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx offset {cur} runs past its block {block} end {block_end}"
            ))
        })?;
        let wanted = end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!("vhdx read position {cur} runs past its end {end}"))
        })?;
        let span = left.min(wanted);
        let entry = bat_entry(self, block)?;
        let state = entry & BAT_STATE_MASK;
        // One refusal for every unreadable state, shared by the two
        // named states below and the wildcard guard after them.
        let unreadable = |entry: u64, state: u64| {
            CoreError::invalid(format!(
                "vhdx block {block} BAT entry {entry:#018x} (state {state}) needs a sector \
                 bitmap or is reserved: only fully present blocks are readable"
            ))
        };
        match state {
            BAT_NOT_PRESENT | BAT_UNDEFINED | BAT_ZERO | BAT_UNMAPPED | BAT_UNMAPPED_V095 => {
                Ok((None, span))
            }
            BAT_FULLY_PRESENT => {
                let file_off = entry
                    .checked_shr(BAT_OFFSET_SHIFT)
                    .and_then(|units| units.checked_mul(BAT_OFFSET_UNIT))
                    .and_then(|block_start| block_start.checked_add(within))
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhdx BAT entry {entry:#018x} of block {block} \
                             overflows the byte offset arithmetic"
                        ))
                    })?;
                let span_end = file_off.checked_add(span).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhdx block {block} read of {span} bytes at offset {file_off} \
                         overflows the byte offset arithmetic"
                    ))
                })?;
                if span_end > self.file_total {
                    return Err(CoreError::invalid(format!(
                        "vhdx block {block} (bytes {file_off}..{span_end}) runs past \
                         the {} byte file end",
                        self.file_total
                    )));
                }
                Ok((Some(file_off), span))
            }
            // The mask keeps three bits and every state 0..=7 is
            // named above; the guard stays so a widened mask refuses
            // rather than silently mapping.
            BAT_RESERVED | BAT_PARTIALLY_PRESENT => Err(unreadable(entry, state)),
            _ => Err(unreadable(entry, state)),
        }
    }
}

impl Volume for VhdxReader {
    /// The virtual disk size from the metadata table (without any
    /// headers, regions or BAT: the 32 MiB file above holds a 64 MiB
    /// disk).
    fn total_bytes(&self) -> u64 {
        self.virtual_size
    }

    /// Fill `buf` from `offset`, mapping each span through the BAT
    /// (fully present blocks read their payload, every other settled
    /// state reads as zeros). The window is bounds-checked against
    /// the virtual size before any I/O, naming the length, the
    /// offset and the virtual size; writes are refused.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len = u64::try_from(buf.len()).map_err(|_| {
            CoreError::invalid("vhdx read length does not fit the byte offset arithmetic")
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhdx read of {len} bytes at offset {offset} overflows the byte offset arithmetic"
            ))
        })?;
        if end > self.virtual_size {
            return Err(CoreError::invalid(format!(
                "vhdx read of {} bytes at offset {offset} runs past the {} byte virtual size",
                buf.len(),
                self.virtual_size
            )));
        }
        let mut done: usize = 0;
        let mut cur = offset;
        let total_len = buf.len();
        while cur < end {
            let (file_off, span) = self.span(cur, end)?;
            let count = usize::try_from(span).map_err(|_| {
                CoreError::invalid(format!(
                    "vhdx read span {span} does not fit this machine's usize"
                ))
            })?;
            let window_end = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("vhdx read position overflows the offset arithmetic")
            })?;
            if window_end > total_len {
                return Err(CoreError::invalid(format!(
                    "vhdx read window {done}..{window_end} runs past the {total_len} byte buffer"
                )));
            }
            let dest = buf.get_mut(done..window_end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhdx read window {done}..{window_end} is not addressable"
                ))
            })?;
            match file_off {
                Some(at) => self.file.read_exact_at(at, dest)?,
                None => dest.fill(0),
            }
            done = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("vhdx read position overflows the offset arithmetic")
            })?;
            cur = cur.checked_add(span).ok_or_else(|| {
                CoreError::invalid("vhdx read position overflows the offset arithmetic")
            })?;
        }
        Ok(())
    }

    /// A VHDX is opened read-only: any write is refused naming the
    /// length and the offset, and the store is left untouched.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        Err(CoreError::invalid(format!(
            "refusing to write {} bytes at offset {offset}: a vhdx image volume is read-only",
            buf.len()
        )))
    }
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

    /// Offsets of the readable-disk layout: BAT at 2 MiB, metadata at
    /// 3 MiB, the one stored payload block at 4 MiB (1 MiB blocks, a
    /// 2 MiB virtual disk, 5 MiB of file).
    const READ_BAT: usize = 2 * 1024 * 1024;
    const READ_META: usize = 3 * 1024 * 1024;
    const READ_PAYLOAD: usize = 4 * 1024 * 1024;
    const READ_DISK: usize = 5 * 1024 * 1024;
    const READ_BLOCK: u64 = 1024 * 1024;

    /// Write one metadata-table entry at entry `index` of the table at
    /// `READ_META`: the item GUID, its region-relative offset and
    /// length, and the entry flags.
    fn stamp_metadata(
        disk: &mut [u8],
        index: usize,
        guid: &[u8; 16],
        offset: u32,
        length: u32,
        flags: u32,
    ) {
        let at = READ_META + 32 + index * 32;
        disk[at..at + 16].copy_from_slice(guid);
        disk[at + 16..at + 20].copy_from_slice(&offset.to_le_bytes());
        disk[at + 20..at + 24].copy_from_slice(&length.to_le_bytes());
        disk[at + 24..at + 28].copy_from_slice(&flags.to_le_bytes());
        disk[at + 28..at + 32].copy_from_slice(&0u32.to_le_bytes());
    }

    /// A readable 5 MiB disk: the valid header section, a BAT whose
    /// block 0 is fully present at 4 MiB and whose block 1 is zero,
    /// and a metadata table describing 1 MiB blocks over a 2 MiB
    /// virtual disk. Neither the BAT nor the metadata region carries
    /// a checksum, so tests may patch their bytes freely.
    fn readable_disk() -> Vec<u8> {
        let mut disk = vec![0u8; READ_DISK];
        disk[0..8].copy_from_slice(b"vhdxfile");
        stamp_header(&mut disk, 65536, 7);
        stamp_header(&mut disk, 131072, 8);
        let table = &mut disk[196608..196608 + 65536];
        table[0..4].copy_from_slice(b"regi");
        table[8..12].copy_from_slice(&2u32.to_le_bytes());
        stamp_entry(table, 0, &BAT_GUID, READ_BAT as u64, 1024 * 1024);
        stamp_entry(table, 1, &METADATA_GUID, READ_META as u64, 1024 * 1024);
        stamp_crc(table);

        disk[READ_BAT..READ_BAT + 8]
            .copy_from_slice(&((4u64 << BAT_OFFSET_SHIFT) | BAT_FULLY_PRESENT).to_le_bytes());
        disk[READ_BAT + 8..READ_BAT + 16].copy_from_slice(&BAT_ZERO.to_le_bytes());

        let meta = READ_META;
        disk[meta..meta + 8].copy_from_slice(b"metadata");
        disk[meta + 10..meta + 12].copy_from_slice(&5u16.to_le_bytes());
        stamp_metadata(&mut disk, 0, &FILE_PARAM_GUID, 512, 8, 0x04);
        stamp_metadata(&mut disk, 1, &VIRTUAL_SIZE_GUID, 520, 8, 0x06);
        stamp_metadata(&mut disk, 2, &PAGE83_GUID, 528, 16, 0x06);
        stamp_metadata(&mut disk, 3, &LOGICAL_SECTOR_GUID, 544, 4, 0x06);
        stamp_metadata(&mut disk, 4, &PHYS_SECTOR_GUID, 548, 4, 0x06);
        disk[meta + 512..meta + 516].copy_from_slice(&(READ_BLOCK as u32).to_le_bytes());
        disk[meta + 520..meta + 528].copy_from_slice(&(2 * READ_BLOCK).to_le_bytes());
        disk[meta + 544..meta + 548].copy_from_slice(&512u32.to_le_bytes());
        disk[meta + 548..meta + 552].copy_from_slice(&512u32.to_le_bytes());

        disk[READ_PAYLOAD..READ_PAYLOAD + 16].copy_from_slice(b"VHDX-BLOCK0-MARK");
        disk[READ_PAYLOAD + READ_BLOCK as usize - 16..READ_PAYLOAD + READ_BLOCK as usize]
            .copy_from_slice(b"VHDX-BLOCK0-TAIL");
        disk
    }

    /// Open `disk` as its logical volume through a memory store.
    fn open_disk(disk: &[u8]) -> VhdxReader {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect("the valid disk opens")
    }

    /// Read `len` bytes at `offset` from `reader`.
    fn read_from(reader: &VhdxReader, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        reader
            .read_exact_at(offset, &mut out)
            .expect("the read fits");
        out
    }

    #[test]
    fn reader_maps_present_blocks_and_zeroes_the_rest() {
        let reader = open_disk(&readable_disk());
        assert_eq!(reader.total_bytes(), 2 * READ_BLOCK);

        assert_eq!(&read_from(&reader, 0, 16), b"VHDX-BLOCK0-MARK");
        assert_eq!(
            &read_from(&reader, READ_BLOCK - 16, 16),
            b"VHDX-BLOCK0-TAIL"
        );
        assert_eq!(
            read_from(&reader, READ_BLOCK, READ_BLOCK as usize),
            vec![0u8; READ_BLOCK as usize]
        );

        // A read may span the present block and the zero block: the
        // marker tail first, then zeros past the boundary.
        let mut mixed = vec![0u8; 32];
        reader
            .read_exact_at(READ_BLOCK - 12, &mut mixed)
            .expect("the spanning read fits");
        assert_eq!(&mixed[..12], b"-BLOCK0-TAIL");
        assert!(mixed[12..].iter().all(|byte| *byte == 0));

        // A read ending exactly on the virtual size fits; one byte
        // past it names the length, the offset and the virtual size.
        read_from(&reader, 2 * READ_BLOCK - 10, 10);
        let mut past = vec![0u8; 11];
        let error = reader
            .read_exact_at(2 * READ_BLOCK - 10, &mut past)
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("11 bytes"), "{text}");
        assert!(text.contains("virtual size"), "{text}");

        let mut reader = reader;
        let error = reader.write_all_at(0, b"x").unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error:?}");
    }

    #[test]
    fn bat_states_read_zeros_or_their_payload_or_refuse() {
        // Each settled non-present state reads its block as zeros;
        // the fully-present state reads the payload; the bitmap and
        // reserved states refuse. Every mutant is restored
        // byte-identically afterwards.
        let pristine = readable_disk();
        for (state, present) in [
            (BAT_NOT_PRESENT, false),
            (BAT_UNDEFINED, false),
            (BAT_ZERO, false),
            (BAT_UNMAPPED, false),
            (BAT_UNMAPPED_V095, false),
            (BAT_FULLY_PRESENT, true),
        ] {
            let mut disk = pristine.clone();
            let entry = if present {
                (4u64 << BAT_OFFSET_SHIFT) | state
            } else {
                state
            };
            disk[READ_BAT..READ_BAT + 8].copy_from_slice(&entry.to_le_bytes());
            let reader = open_disk(&disk);
            let block = read_from(&reader, 0, 16);
            if present {
                assert_eq!(&block, b"VHDX-BLOCK0-MARK");
            } else {
                assert_eq!(block, vec![0u8; 16]);
            }
        }
        for state in [BAT_PARTIALLY_PRESENT, BAT_RESERVED] {
            let mut disk = pristine.clone();
            let entry = (4u64 << BAT_OFFSET_SHIFT) | state;
            disk[READ_BAT..READ_BAT + 8].copy_from_slice(&entry.to_le_bytes());
            let reader = open_disk(&disk);
            let mut out = vec![0u8; 1];
            let error = reader.read_exact_at(0, &mut out).unwrap_err();
            let text = error.to_string();
            assert!(text.contains("block 0"), "{text}");
            assert!(
                text.contains("only fully present blocks are readable"),
                "{text}"
            );
        }
        assert_eq!(pristine, readable_disk(), "the mutants left no trace");
    }

    #[test]
    fn metadata_refusals_name_their_field() {
        // Block size outside the 1 MiB..=256 MiB range.
        let mut disk = readable_disk();
        disk[READ_META + 512..READ_META + 516].copy_from_slice(&512u32.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("block size 512"), "{error:?}");

        // Zero virtual size.
        let mut disk = readable_disk();
        disk[READ_META + 520..READ_META + 528].copy_from_slice(&0u64.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("virtual disk size is zero"));

        // Differencing disk: the parent flag in the file parameters.
        let mut disk = readable_disk();
        disk[READ_META + 516..READ_META + 520]
            .copy_from_slice(&FILE_PARAM_HAS_PARENT.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("differencing"));

        // Parent locator present (a second differencing signal).
        let mut disk = readable_disk();
        let at = READ_META + 32 + 5 * 32;
        disk[at..at + 16].copy_from_slice(&PARENT_LOCATOR_GUID);
        disk[at + 16..at + 20].copy_from_slice(&200u32.to_le_bytes());
        disk[at + 20..at + 24].copy_from_slice(&16u32.to_le_bytes());
        disk[READ_META + 10..READ_META + 12].copy_from_slice(&6u16.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("parent locator"));

        // Unknown required metadata item.
        let mut disk = readable_disk();
        let at = READ_META + 32 + 2 * 32;
        disk[at..at + 16].copy_from_slice(&[0x42u8; 16]);
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("requires unknown metadata item"));

        // No virtual-disk identifier: the page-83 entry turned into an
        // unknown item nobody requires.
        let mut disk = readable_disk();
        let at = READ_META + 32 + 2 * 32;
        disk[at..at + 16].copy_from_slice(&[0x42u8; 16]);
        disk[at + 24..at + 28].copy_from_slice(&0x02u32.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(
            error
                .to_string()
                .contains("has no vhdx virtual disk identifier")
        );

        // A BAT entry pointing past the file end refuses on read.
        let mut disk = readable_disk();
        let entry = (100_000u64 << BAT_OFFSET_SHIFT) | BAT_FULLY_PRESENT;
        disk[READ_BAT..READ_BAT + 8].copy_from_slice(&entry.to_le_bytes());
        let reader = open_disk(&disk);
        let mut out = vec![0u8; 1];
        let error = reader.read_exact_at(0, &mut out).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("block 0"), "{text}");
        assert!(text.contains("byte file end"), "{text}");

        // A block index past the BAT is refused before any I/O.
        let reader = open_disk(&readable_disk());
        let error = bat_entry(&reader, 2).unwrap_err();
        assert!(
            error.to_string().contains("past the 2 BAT entries"),
            "{error:?}"
        );
    }

    /// Open `disk` expecting refusal: the error, not the reader.
    fn open_disk_err(disk: &[u8]) -> CoreError {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect_err("the corrupt disk refuses")
    }
}
