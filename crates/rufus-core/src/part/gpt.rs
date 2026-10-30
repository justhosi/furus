//! The GPT side of the partition module: header and entry decoding
//! ([`parse_gpt`], [`gpt_entry_range`]) plus the S08 writer
//! ([`write_gpt`]) that assembles the protective MBR, the primary
//! header/entry array and their backup copies.
//!
//! Nothing here opens a device — the caller hands in the sectors it
//! read and takes the sector buffers the writer returns. The
//! module-wide rules the tests pin (rot is a warning, hard errors are
//! reserved for meaningless inputs, saturation) live on [`crate::part`].

use crate::error::CoreError;
use crate::error::Result;
use crate::part::TablePartition;
use crate::part::guid_bytes;
use crate::part::mbr::{MbrPartition, write_mbr};
use crate::part::put;
use crate::part::sectors_to_bytes;
use crate::part::starts_with_signature;
use crate::part::u16_le;
use crate::part::u32_le;
use crate::part::u64_le;
use crate::text::device_text;

/// Floor of a GPT header's self-declared `header_size`: anything smaller
/// cannot honestly hold the fields this parser reads. The writer emits
/// exactly this size — the mandatory minimum is the whole header.
const GPT_HEADER_MIN_SIZE: u32 = 92;
/// Entry-count cap. UEFI itself defines at most 128 entries; capping
/// also bounds the work per device instead of trusting the header.
const MAX_GPT_ENTRIES: u32 = 128;
/// GPT on-disk signature at the start of every header sector.
///
/// `pub(crate)` *visibility-only*: the test byte-builders in
/// [`crate::part::test_support`] hand-craft header sectors and must keep
/// spelling the signature exactly like the parser/writer expect.
pub(crate) const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// A GPT entry is at least 128 bytes; larger strides are legal
/// (`size_of_entry` need not be a power of two). The writer emits
/// exactly this stride — the mandatory minimum is the whole entry.
const GPT_ENTRY_MIN_SIZE: u32 = 128;
/// Entry-size ceiling for [`gpt_entry_range`]. A stride larger than a
/// sector carries nothing a reader needs; letting it through would let
/// a corrupt header size every next read as it pleases.
const MAX_GPT_ENTRY_SIZE: u32 = 4096;
/// GPT entry name field: 36 UTF-16 code units at entry offset 56.
const GPT_NAME_UNITS: usize = 36;
/// Offset of the name field inside a GPT entry.
const GPT_ENTRY_NAME_OFFSET: usize = 56;
/// One name code unit is one `u16` = two bytes.
const UTF16_UNIT_BYTES: usize = 2;

/// Offsets of the fixed fields in a GPT header sector. Grouped here so
/// the reader below never hand-writes an offset twice (and the S08
/// writer stamps the very same addresses).
mod header {
    /// `u64`: LBA of this (primary) header.
    pub const MY_LBA: usize = 24;
    /// `u64`: LBA of the backup header (usually the last sector).
    pub const ALTERNATE_LBA: usize = 32;
    /// `u64`: first LBA an ordinary partition may start at (2 + the
    /// entry array's sector count).
    pub const FIRST_USABLE: usize = 40;
    /// `u64`: last LBA an ordinary partition may end at (the backup
    /// entry array's first LBA − 1).
    pub const LAST_USABLE: usize = 48;
    /// 16 bytes disk GUID at offset 56..72.
    pub const DISK_GUID: usize = 56;
    /// `u32` CRC-32 of the whole header, stored at offset 16; stored
    /// zeroed for the verification computation.
    pub const HEADER_CRC: usize = 16;
    /// `u32`: self-declared header size in bytes.
    pub const HEADER_SIZE: usize = 12;
    /// `u32` revision at offset 8..12; the writer pins `0x0001_0000`.
    pub const REVISION: usize = 8;
    /// `u64`: LBA where the entry array starts.
    pub const ENTRY_ARRAY_LBA: usize = 72;
    /// `u32`: number of table entries.
    pub const ENTRY_COUNT: usize = 80;
    /// `u32`: byte stride of the table entries.
    pub const ENTRY_SIZE: usize = 84;
    /// `u32`: CRC-32 of the entry array as declared.
    pub const ENTRIES_CRC: usize = 88;
}

/// Offsets of the fixed fields inside one GPT table entry.
mod entry {
    /// 16 bytes partition-type GUID at the very start.
    pub const TYPE_GUID: usize = 0;
    /// 16 bytes unique per-partition GUID.
    pub const UNIQUE_GUID: usize = 16;
    /// `u64` first LBA (inclusive).
    pub const FIRST_LBA: usize = 32;
    /// `u64` last LBA (inclusive!).
    pub const LAST_LBA: usize = 40;
    /// `u64` attribute bitmap.
    pub const ATTRIBUTES: usize = 48;
}

/// Table-free bitwise CRC-32 (ISO-HDLC / IEEE 802.3: polynomial
/// `0xEDB88320`, standard init/final-xor), implemented here rather than
/// pulled from a crate: it runs on ≤ 4 KiB of header bytes and PLAN §5
/// allows no extra dependency for that convenience.
///
/// Reference vectors: `crc32_ieee(b"") == 0`,
/// `crc32_ieee(b"123456789") == 0xCBF4_3926`.
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    // The loop below would produce 0 for empty input by itself (init and
    // final xor-out cancel); the early return documents the empty-input
    // identity explicitly and skips the work.
    if data.is_empty() {
        return 0;
    }
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Bitwise re-statement of the classic "shift right through
            // the polynomial" table step: one per-bit conditional XOR.
            let low_bit = crc & 1;
            crc >>= 1;
            if low_bit != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Format a 16-byte on-disk (mixed-endian) GUID in canonical
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` lowercase form.
///
/// GPT stores the first three groups little-endian (`data1` as a `u32`,
/// `data2`/`data3` as `u16`s) and the last eight bytes verbatim, so the
/// EFI System Partition's on-disk bytes `28 73 2A C1 1F F8 D2 11 ...`
/// render as `c12a7328-f81f-11d2-...`, exactly how the kernel and Rufus
/// print GUIDs elsewhere.
#[must_use]
pub fn guid_to_string(raw: &[u8; 16]) -> String {
    // Pattern-destructure by value: 16 `u8`s copied out, no indexing, no
    // conversion that could even theoretically fail.
    let &[
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
        b8,
        b9,
        b10,
        b11,
        b12,
        b13,
        b14,
        b15,
    ] = raw;
    let data1 = u32::from_le_bytes([b0, b1, b2, b3]);
    let data2 = u16::from_le_bytes([b4, b5]);
    let data3 = u16::from_le_bytes([b6, b7]);
    format!(
        "{data1:08x}-{data2:04x}-{data3:04x}-{b8:02x}{b9:02x}-{b10:02x}{b11:02x}{b12:02x}{b13:02x}{b14:02x}{b15:02x}"
    )
}

/// Slug for one GPT type GUID (canonical lowercase form from
/// [`guid_to_string`]). The list mirrors the well-known GUIDs Rufus
/// creates or meets for writing; anything else stays `"unknown"` rather
/// than guessing from fuzzy matches.
fn gpt_kind_for_guid(guid: &str) -> &'static str {
    match guid {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "efi_system",
        "21686148-6449-6e6f-744e-656564454649" => "bios_boot",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "microsoft_basic_data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "microsoft_reserved",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "linux_swap",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "linux_filesystem",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "linux_lvm",
        "a19d880f-05fc-4d3b-a006-743f0f84911e" => "linux_raid",
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "linux_home",
        "48465300-0000-11aa-aa11-00306543ecac" => "apple_hfs",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "apple_apfs",
        "516e7cb4-6ecf-11d6-8ff8-00022d09712b" => "freebsd_ufs",
        _ => "unknown",
    }
}

/// GPT entry name: up to [`GPT_NAME_UNITS`] UTF-16 code units from
/// offset [`GPT_ENTRY_NAME_OFFSET`], NUL-terminated. UEFI mandates the
/// terminator and pads the remainder with zero units, so cutting at the
/// first NUL is *correct* reading — pushing the padding through the
/// sanitiser would produce a `name?????????` tail. The surviving units
/// go through [`String::from_utf16_lossy`] and [`device_text`] exactly
/// like every other device string. `None` when nothing readable is left.
fn gpt_entry_name(entry: &[u8]) -> Option<String> {
    let mut units: Vec<u16> = Vec::with_capacity(GPT_NAME_UNITS);
    for unit_index in 0..GPT_NAME_UNITS {
        match u16_le(entry, GPT_ENTRY_NAME_OFFSET + unit_index * UTF16_UNIT_BYTES) {
            Some(0) => break, // NUL terminator: rest is padding
            Some(unit) => units.push(unit),
            None => break, // entry too short: stop at what we have
        }
    }
    let clean = device_text(&String::from_utf16_lossy(&units));
    if clean.is_empty() { None } else { Some(clean) }
}

/// Where the GPT entry array lives, as declared by the header.
///
/// A sizing aid for callers that stream their reads ([`crate::part::detect_layout`]
/// consumes whole buffers, but a device reader first needs to know how
/// many bytes to ask the disk for). The fields are the header's own
/// claims, except `count`/`entry_size` never exceed the parser's caps
/// ([`MAX_GPT_ENTRIES`], [`MAX_GPT_ENTRY_SIZE`]): this type is a read
/// plan, not a verdict, so soft rot stays a [`parse_gpt`] warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptEntryRange {
    /// LBA where the entry array starts (used as-is; `0` is possible for
    /// corrupt headers and simply lets the caller read at its own risk).
    pub entry_lba: u64,
    /// Number of entries, capped at [`MAX_GPT_ENTRIES`].
    pub count: u32,
    /// Byte stride of one entry, capped at [`MAX_GPT_ENTRY_SIZE`].
    pub entry_size: u32,
}

/// Locate the GPT entry array a header sector declares, for callers that
/// must size their next read.
///
/// `None` when the sector is not a GPT header (signature missing, or a
/// buffer too short to hold the location fields) or when the shape is
/// nonsense (`entry_size` zero — a stride of zero means the declared
/// array can never be read usefully). Everything softer stays legal
/// here: sub-minimum strides and oversized counts are clamped/read and
/// [`parse_gpt`] turns them into warnings, exactly the split of jobs
/// documented on [`GptEntryRange`]. Bounds are checked throughout;
/// nothing here can panic on a hostile buffer.
#[must_use]
pub fn gpt_entry_range(header_sector: &[u8]) -> Option<GptEntryRange> {
    if !starts_with_signature(header_sector, GPT_SIGNATURE) {
        return None;
    }
    let entry_lba = u64_le(header_sector, header::ENTRY_ARRAY_LBA)?;
    // Zero is a stride that makes every read degenerate; the parser's
    // own minimum check below (via parse_gpt) rejects it outright, so
    // refusing the read plan here is the honest answer.
    let declared_entry_size = u32_le(header_sector, header::ENTRY_SIZE)?;
    if declared_entry_size == 0 {
        return None;
    }
    Some(GptEntryRange {
        entry_lba,
        count: u32_le(header_sector, header::ENTRY_COUNT)?.min(MAX_GPT_ENTRIES),
        entry_size: declared_entry_size.min(MAX_GPT_ENTRY_SIZE),
    })
}

/// Parse the GPT header sector (LBA1) plus the entry array into
/// partitions and warnings.
///
/// `Err` is reserved for inputs that make parsing meaningless: a
/// missing `EFI PART` signature, a self-declared `header_size` below
/// [`GPT_HEADER_MIN_SIZE`], or an entry size below
/// [`GPT_ENTRY_MIN_SIZE`]. Everything softer — local or entry-array CRC
/// mismatches, a physically short header sector, a truncated entry
/// array, a declared count past [`MAX_GPT_ENTRIES`] — comes back as
/// ASCII warnings in the tuple while the parse proceeds with the bytes
/// it can read (report-only slice: a broken GPT must still yield a
/// verdict, see [`crate::part`]). The caller owns the I/O and hands
/// in the sectors; nothing here opens a device.
pub fn parse_gpt(
    header_sector: &[u8],
    entries: &[u8],
    sector_size: u32,
) -> Result<(Vec<TablePartition>, Vec<String>)> {
    let mut warnings: Vec<String> = Vec::new();

    if !starts_with_signature(header_sector, GPT_SIGNATURE) {
        return Err(CoreError::invalid("gpt header signature is missing"));
    }
    let Some(declared_header_size) = u32_le(header_sector, header::HEADER_SIZE) else {
        return Err(CoreError::invalid(
            "gpt header sector does not even hold a header size",
        ));
    };
    if declared_header_size < GPT_HEADER_MIN_SIZE {
        return Err(CoreError::invalid("gpt header size is nonsense"));
    }

    // Verify the header CRC over its declared span, clamped to the bytes
    // the caller actually provided. Only a fully-present header is
    // verifiable; a physically short one gets its own truncation warning
    // instead of a misleading CRC verdict.
    let declared_len = usize::try_from(declared_header_size).unwrap_or(usize::MAX);
    let span = declared_len.min(header_sector.len());
    if span < declared_len {
        warnings.push("gpt header truncated".to_owned());
    } else if let Some(header) = header_sector.get(..span) {
        let mut expected = header.to_vec();
        if let Some(crc_field) = expected.get_mut(header::HEADER_CRC..header::HEADER_CRC + 4) {
            crc_field.fill(0); // spec: the CRC is computed with this field zeroed
        }
        let stored = u32_le(header_sector, header::HEADER_CRC);
        if stored.is_some_and(|stored| stored != crc32_ieee(&expected)) {
            warnings.push("gpt header crc mismatch".to_owned());
        }
    }

    let Some(count_declared) = u32_le(header_sector, header::ENTRY_COUNT) else {
        return Err(CoreError::invalid(
            "gpt header does not declare an entry count",
        ));
    };
    let Some(entry_size) = u32_le(header_sector, header::ENTRY_SIZE) else {
        return Err(CoreError::invalid(
            "gpt header does not declare an entry size",
        ));
    };
    if entry_size < GPT_ENTRY_MIN_SIZE {
        return Err(CoreError::invalid("gpt entry size is nonsense"));
    }

    let capped_count = count_declared.min(MAX_GPT_ENTRIES);
    if count_declared > MAX_GPT_ENTRIES {
        warnings.push(format!(
            "gpt entry array capped at {MAX_GPT_ENTRIES} entries"
        ));
    }

    let stride = usize::try_from(entry_size).unwrap_or(usize::MAX);
    // Byte span of the declared array; checked because a hostile header
    // may claim counts no real device delivers.
    let Some(declared_span) = (count_declared as usize).checked_mul(stride) else {
        return Err(CoreError::invalid("gpt entry array size overflows"));
    };
    let fitted = if declared_span > entries.len() {
        warnings.push("gpt entry array truncated".to_owned());
        (entries.len() / stride).min(capped_count as usize)
    } else {
        capped_count as usize
    };

    // The stored array CRC covers the declared span. With only part of
    // the array present, what we have is checked against it too — a
    // mismatch is a warning either way, never the hard failure a GPT
    // driver would treat it as.
    let checked_span = declared_span.min(entries.len());
    if u32_le(header_sector, header::ENTRIES_CRC).is_some_and(|stored| {
        entries
            .get(..checked_span)
            .is_some_and(|present| crc32_ieee(present) != stored)
    }) {
        warnings.push("gpt entry array crc mismatch".to_owned());
    }

    let mut partitions = Vec::with_capacity(fitted);
    for slot in 0..fitted {
        let Some(base) = slot.checked_mul(stride) else {
            break; // unreachable: fitted <= 128 entries, but stay total
        };
        let Some(end) = base.checked_add(stride) else {
            break;
        };
        let Some(entry) = entries.get(base..end) else {
            break;
        };
        let Some(type_guid) = guid_bytes(entry, entry::TYPE_GUID) else {
            break;
        };
        if type_guid == [0u8; 16] {
            continue; // unused slot: blanked entry, per UEFI
        }
        let (Some(first_lba), Some(last_lba)) = (
            u64_le(entry, entry::FIRST_LBA),
            u64_le(entry, entry::LAST_LBA),
        ) else {
            continue;
        };
        if last_lba < first_lba {
            warnings.push(format!("gpt entry {} has reversed bounds", slot + 1));
            continue;
        }
        // Saturating on purpose: `first == 0, last == u64::MAX` would
        // otherwise wrap the +1 into 0 and defeat every size check.
        let entry_sectors = (last_lba - first_lba).saturating_add(1);
        let canonical_type = guid_to_string(&type_guid);
        partitions.push(TablePartition {
            index: slot as u32 + 1,
            start_lba: first_lba,
            sectors: entry_sectors,
            size_bytes: sectors_to_bytes(entry_sectors, sector_size),
            kind: gpt_kind_for_guid(&canonical_type).to_owned(),
            name: gpt_entry_name(entry),
            bootable: false,
            attributes: u64_le(entry, entry::ATTRIBUTES),
            guid: Some(canonical_type),
            unique_guid: guid_bytes(entry, entry::UNIQUE_GUID).map(|raw| guid_to_string(&raw)),
        });
    }
    Ok((partitions, warnings))
}

/// Cross-check the backup GPT header: `backup_gpt` stays false unless
/// the last sector carries the GPT signature *and* its self-reported
/// location matches the primary header's backup LBA. A mismatch (or a
/// backup whose location field is unreadable) only warns.
pub(crate) fn verified_backup(
    last_sector: Option<&[u8]>,
    primary_header: Option<&[u8]>,
    warnings: &mut Vec<String>,
) -> bool {
    let Some(backup) = last_sector else {
        return false; // nothing to compare: not an error by itself
    };
    if !starts_with_signature(backup, GPT_SIGNATURE) {
        return false; // no backup header here: nothing to warn about
    }
    let primary_lba = primary_header.and_then(|sector| u64_le(sector, header::ALTERNATE_LBA));
    let backup_lba = u64_le(backup, header::MY_LBA);
    match (primary_lba, backup_lba) {
        (Some(alternate), Some(current)) if alternate == current => true,
        // Different location, or unreadable location fields: the two
        // headers cannot belong together, which is a reportable rot.
        _ => {
            warnings.push("gpt backup header mismatch".to_owned());
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Write side (S08)
// ---------------------------------------------------------------------------

/// One GPT table entry, the input shape of [`write_gpt`].
///
/// Both GUIDs are on-disk (mixed-endian) bytes, exactly the byte order
/// [`guid_to_string`] interprets — a `uuid::Uuid` value converts by
/// emitting `data1`/`data2`/`data3` little-endian and the last eight
/// bytes verbatim. A zero `type_guid` marks an unused slot per UEFI;
/// the parser skips such entries, so callers should always pass a type.
/// Partition spans are inclusive in both directions (`first_lba ..
/// last_lba`); `name` must be ASCII and at most 36 characters, and is
/// written UTF-16LE with a NUL terminator (a full 36-character name
/// fills the field without one, as the on-disk format requires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPartition {
    /// 16-byte partition-type GUID, on-disk mixed-endian bytes.
    pub type_guid: [u8; 16],
    /// 16-byte per-partition unique GUID, on-disk mixed-endian bytes.
    pub unique_guid: [u8; 16],
    /// First LBA of the partition (inclusive).
    pub first_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub last_lba: u64,
    /// Raw GPT 64-bit attribute bitmap, stored verbatim.
    pub attributes: u64,
    /// ASCII partition name, zero-terminated in the entry.
    pub name: &'static str,
}

/// Everything [`write_gpt`] produced, in the order it belongs on the
/// device.
///
/// Placement map (512-byte sectors): the MBR at LBA 0, the primary
/// header at LBA 1, the primary entry array at LBA 2, the backup entry
/// array ending just below the backup header at
/// [`GptImage::backup_lba`]. Between [`GptImage::first_usable`] and
/// [`GptImage::last_usable`] is the range ordinary partitions belong
/// in; the backup entry array and header sit directly above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptImage {
    /// LBA 0 with one `0xEE` entry covering the disk. Always 512 bytes
    /// (the protective MBR is the legacy footprint in LBA0's first
    /// half); the device writer is responsible for placing those 512
    /// bytes at the front of the real LBA0, zero-padded to the physical
    /// sector size on 4096-byte-sector disks.
    pub protective_mbr: [u8; 512],
    /// Primary header for LBA 1: exactly `sector_size` bytes, the 92
    /// header fields at offset 0 and zero padding behind them.
    pub primary_header: Vec<u8>,
    /// The full primary entry array mirrored in
    /// [`GptImage::backup_entries`] (128 entries × 128 bytes = 16384).
    pub primary_entries: Vec<u8>,
    /// The backup copy of the entry array, byte-identical to
    /// [`GptImage::primary_entries`]; its CRC matches for both copies.
    pub backup_entries: Vec<u8>,
    /// Backup header for [`GptImage::backup_lba`]: same shape as the
    /// primary header with current/alternate LBA and entry-array LBA
    /// swapped to their mirrored values, both CRCs freshly computed.
    pub backup_header: Vec<u8>,
    /// LBA of the backup header — the `last_lba` argument of
    /// [`write_gpt`], i.e. the device's final sector.
    pub backup_lba: u64,
    /// First LBA an ordinary partition may start at: 2 + the entry
    /// array's sector count (34 on 512-byte-sector disks, 6 on
    /// 4096-byte-sector disks — the array spans exactly as many sectors
    /// as its fixed 16384 bytes require).
    pub first_usable: u64,
    /// Last LBA an ordinary partition may end at: one below the backup
    /// entry array (`last_lba - 33` on 512-byte-sector disks,
    /// `last_lba - 5` on 4096-byte-sector disks). At the minimum disk
    /// size ([`write_gpt`]'s headroom floor) the range between
    /// [`GptImage::first_usable`] and here degenerates to empty.
    pub last_usable: u64,
}

/// UTF-16LE name field (36 code units) for one entry.
///
/// ASCII names encode as one NUL-terminated little-endian code unit per
/// byte; shorter names keep their zero terminator plus zero padding
/// because the array starts zeroed and only the name's bytes are
/// stamped in. A full 36-character name fills the field without a
/// terminator, which is exactly what the on-disk format allows; anything
/// longer (or any non-ASCII byte) is refused rather than silently
/// truncated — the reader would otherwise report a table that differs
/// from what the caller demanded.
fn gpt_name_field(name: &str) -> Result<[u8; GPT_NAME_UNITS * UTF16_UNIT_BYTES]> {
    if !name.is_ascii() {
        return Err(CoreError::invalid(
            "gpt partition names must be ascii characters",
        ));
    }
    let length = name.len();
    if length > GPT_NAME_UNITS {
        return Err(CoreError::invalid(format!(
            "gpt partition names hold at most {GPT_NAME_UNITS} characters, got {length}"
        )));
    }
    let mut field = [0u8; GPT_NAME_UNITS * UTF16_UNIT_BYTES];
    for (slot, byte) in name.bytes().enumerate() {
        // ASCII is one byte per character; the low byte carries the
        // BMP code point and the high byte stays zero (UTF-16LE).
        let unit = u16::from(byte);
        put(
            &mut field,
            slot * UTF16_UNIT_BYTES,
            &[unit as u8, (unit >> 8) as u8],
        )?;
    }
    Ok(field)
}

/// Stamp one table entry's fixed fields into a 128-byte record.
fn fill_entry(record: &mut [u8], partition: &GptPartition) -> Result<()> {
    put(record, entry::TYPE_GUID, &partition.type_guid)?;
    put(record, entry::UNIQUE_GUID, &partition.unique_guid)?;
    put(record, entry::FIRST_LBA, &partition.first_lba.to_le_bytes())?;
    put(record, entry::LAST_LBA, &partition.last_lba.to_le_bytes())?;
    put(
        record,
        entry::ATTRIBUTES,
        &partition.attributes.to_le_bytes(),
    )?;
    let units = gpt_name_field(partition.name)?;
    put(record, GPT_ENTRY_NAME_OFFSET, &units)?;
    Ok(())
}

/// The three location fields that differ between the two header
/// copies: where this copy lives (`my_lba`), where the other copy lives
/// (`alternate_lba`) and where the entry array it points at starts
/// (`entry_lba`).
struct HeaderSpot {
    my_lba: u64,
    alternate_lba: u64,
    entry_lba: u64,
}

/// The 92-byte header fields of one copy, then stamped into a
/// sector-sized buffer.
///
/// Shared by the primary and the backup header: the two differ only in
/// their [`HeaderSpot`] values. The entries CRC is stamped in first
/// because the header CRC covers it; the header CRC itself is then
/// computed — per spec — with its own field still zero.
fn sealed_header(
    sector_len: usize,
    disk_guid: [u8; 16],
    first_usable: u64,
    last_usable: u64,
    spot: HeaderSpot,
    entries_crc: u32,
) -> Result<Vec<u8>> {
    let mut fields = [0u8; GPT_HEADER_MIN_SIZE as usize]; // header CRC field stays zero until stamped
    put(&mut fields, 0, GPT_SIGNATURE)?;
    put(&mut fields, header::REVISION, &0x0001_0000u32.to_le_bytes())?;
    put(
        &mut fields,
        header::HEADER_SIZE,
        &GPT_HEADER_MIN_SIZE.to_le_bytes(),
    )?;
    // header::HEADER_CRC (16..20) stays zero for the CRC computation;
    // header's reserved bytes (20..24) stay zero, per UEFI.
    put(&mut fields, header::MY_LBA, &spot.my_lba.to_le_bytes())?;
    put(
        &mut fields,
        header::ALTERNATE_LBA,
        &spot.alternate_lba.to_le_bytes(),
    )?;
    put(
        &mut fields,
        header::FIRST_USABLE,
        &first_usable.to_le_bytes(),
    )?;
    put(&mut fields, header::LAST_USABLE, &last_usable.to_le_bytes())?;
    put(&mut fields, header::DISK_GUID, &disk_guid)?;
    put(
        &mut fields,
        header::ENTRY_ARRAY_LBA,
        &spot.entry_lba.to_le_bytes(),
    )?;
    put(
        &mut fields,
        header::ENTRY_COUNT,
        &MAX_GPT_ENTRIES.to_le_bytes(),
    )?;
    put(
        &mut fields,
        header::ENTRY_SIZE,
        &GPT_ENTRY_MIN_SIZE.to_le_bytes(),
    )?;
    put(&mut fields, header::ENTRIES_CRC, &entries_crc.to_le_bytes())?;
    let header_crc = crc32_ieee(&fields); // spec: computed with the CRC field zeroed
    put(&mut fields, header::HEADER_CRC, &header_crc.to_le_bytes())?;

    let mut sector = vec![0u8; sector_len]; // only the first 92 bytes are meaningful
    let Some(window) = sector.get_mut(..usize::try_from(GPT_HEADER_MIN_SIZE).unwrap_or(0)) else {
        return Err(CoreError::invalid(
            "gpt header does not fit the sector size",
        ));
    };
    window.copy_from_slice(&fields);
    Ok(sector)
}

/// Build a complete GPT image: the protective MBR for LBA0, the primary
/// header (LBA 1) with its entry array (LBA 2), and the mirrored backup
/// copies at the end of the disk.
///
/// Geometry and rules the writer enforces (each pinned by a round-trip
/// or placement test):
///
/// * `sector_size` is 512 or 4096; anything else is refused.
/// * The entry array is always the full [`MAX_GPT_ENTRIES`] × 128-byte
///   shape (16384 bytes) — 32 array sectors on 512-byte disks, 4 on
///   4096-byte disks. [`GptImage::first_usable`] is the sector right
///   after the primary array (34 / 6), [`GptImage::last_usable`] the
///   sector right before the backup array (`last_lba - 33` / `last_lba
///   - 5`).
/// * Headroom: the disk needs at least the front 34 sectors (MBR,
///   header, arrays — [`GptImage::first_usable`]) plus the backup
///   array's sectors plus one backup header, i.e. 34 + 32 + 1 = 67
///   sectors total on 512-byte disks; smaller disks are refused before
///   anything overlaps.
/// * The primary header is stamped at LBA 1 (`EFI PART`, revision
///   `0x0001_0000`, header size 92, reserved zero, current LBA 1,
///   alternate `last_lba`, entry array LBA 2, count 128, entry size
///   128, disk GUID); its CRC is computed with the field zeroed, the
///   entries CRC over the whole array.
/// * The backup copy carries the identical header fields with
///   current/alternate LBA and the entry-array LBA swapped to the
///   mirrored values, sits at [`GptImage::backup_lba`] (= `last_lba`)
///   with its array directly below, and recomputes both CRCs — so
///   [`parse_gpt`] verifies the backup like the primary.
/// * Each entry stamps type GUID, unique GUID, inclusive first/last
///   LBA, attributes, and an ASCII NUL-terminated UTF-16LE name.
/// * Refusals, in order: wrong sector size, more than 128 partitions,
///   too little headroom, reversed LBAs (first > last), overlapping
///   LBA spans between any two partitions, non-ASCII or over-long
///   names. Nothing is silently dropped or truncated.
///
/// The caller picks the LBAs; partitions are written into the table in
/// the order given, one per entry slot with no renumbering.
pub fn write_gpt(
    sector_size: u32,
    last_lba: u64,
    disk_guid: [u8; 16],
    partitions: &[GptPartition],
) -> Result<GptImage> {
    if !matches!(sector_size, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "gpt sector size must be 512 or 4096 bytes, got {sector_size}"
        )));
    }
    let count = partitions.len();
    let max_entries = MAX_GPT_ENTRIES as usize;
    if count > max_entries {
        return Err(CoreError::invalid(format!(
            "gpt holds at most {max_entries} entries, got {count}"
        )));
    }

    // Entry-array geometry: the fixed 16384-byte array covers whole
    // sectors on both legal sector sizes.
    let slot_stride = usize::try_from(GPT_ENTRY_MIN_SIZE).unwrap_or(0);
    let array_bytes = max_entries * slot_stride; // 16384
    let array_sectors = u64::try_from(array_bytes)
        .unwrap_or(u64::MAX)
        .div_ceil(u64::from(sector_size));
    let first_usable = 2 + array_sectors;
    // Headroom: front sectors + backup entries + backup header. For a
    // 512-sector disk that is exactly 34 + 32 + 1 = 67 in total.
    let min_total_sectors = first_usable + array_sectors + 1;
    let offered_total_sectors = last_lba.saturating_add(1);
    if offered_total_sectors < min_total_sectors {
        return Err(CoreError::invalid(format!(
            "gpt needs at least {min_total_sectors} sectors of headroom, got {offered_total_sectors}"
        )));
    }
    // The backup copy: entries directly below the final sector, the
    // usable range ending one sector above them.
    let backup_entry_lba = match last_lba.checked_sub(array_sectors) {
        Some(lba) => lba,
        None => return Err(CoreError::invalid("gpt backup entry array does not fit")),
    };
    let last_usable = match backup_entry_lba.checked_sub(1) {
        Some(lba) => lba,
        None => return Err(CoreError::invalid("gpt last usable sector underflows")),
    };

    // Per-entry legality: reversed bounds first (the overlap rule below
    // assumes spans), then pairwise overlap over all slots (an O(n²)
    // pass over at most 128 entries).
    for (slot, partition) in partitions.iter().enumerate() {
        if partition.first_lba > partition.last_lba {
            let (start, end) = (partition.first_lba, partition.last_lba);
            let index = slot + 1;
            return Err(CoreError::invalid(format!(
                "gpt partition {index} lbas are reversed ({start}..{end})"
            )));
        }
    }
    for (slot, partition) in partitions.iter().enumerate() {
        for (later_slot, later) in partitions.iter().enumerate().skip(slot + 1) {
            if partition.first_lba <= later.last_lba && later.first_lba <= partition.last_lba {
                let first_index = slot + 1;
                let second_index = later_slot + 1;
                return Err(CoreError::invalid(format!(
                    "gpt partitions {first_index} and {second_index} lba ranges overlap"
                )));
            }
        }
    }

    // The entry array starts zeroed, so unused slots are the blank
    // (type-GUID-less) entries UEFI prescribes.
    let mut entries = vec![0u8; array_bytes];
    for (slot, partition) in partitions.iter().enumerate() {
        let base = slot * slot_stride;
        let Some(record) = entries.get_mut(base..base + slot_stride) else {
            let index = slot + 1;
            return Err(CoreError::invalid(format!(
                "gpt entry {index} does not fit the entry array"
            )));
        };
        fill_entry(record, partition)?;
    }
    let entries_crc = crc32_ieee(&entries);

    // Both headers share everything but the three mirrored location
    // fields; each recomputes its own CRC over its own bytes.
    let primary_header = sealed_header(
        sector_size as usize,
        disk_guid,
        first_usable,
        last_usable,
        HeaderSpot {
            my_lba: 1,
            alternate_lba: last_lba,
            entry_lba: 2,
        },
        entries_crc,
    )?;
    let backup_header = sealed_header(
        sector_size as usize,
        disk_guid,
        first_usable,
        last_usable,
        HeaderSpot {
            my_lba: last_lba,
            alternate_lba: 1,
            entry_lba: backup_entry_lba,
        },
        entries_crc,
    )?;

    // The protective MBR: one inert 0xEE "whole disk" entry starting at
    // LBA 1, covering as much of the disk as a 32-bit sector count can
    // express; a blank boot area (the GPT world does not run legacy
    // boot code from LBA0) and no disk signature.
    let protective_lbas = u32::try_from(last_lba).unwrap_or(0xFFFF_FFFF);
    let protective = write_mbr(
        &[0u8; crate::part::mbr::MBR_ENTRY_AREA],
        [0u8; 4],
        &[MbrPartition {
            type_id: 0xEE,
            start_lba: 1,
            sectors: protective_lbas,
            bootable: false,
        }],
    )?;

    Ok(GptImage {
        protective_mbr: protective,
        primary_header,
        primary_entries: entries.clone(),
        backup_entries: entries,
        backup_header,
        backup_lba: last_lba,
        first_usable,
        last_usable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::TableKind;
    use crate::part::detect_layout;
    use crate::part::is_protective_mbr;
    use crate::part::test_support::{
        EFI_TYPE_GUID_RAW, LINUX_TYPE_GUID_RAW, UNIQUE_GUID_RAW, uuid_to_gpt_bytes,
    };
    use uuid::Uuid;

    // ------------------------------------------------------------------
    // Byte-independent CRC: the test's own table-driven CRC-32/ISO-HDLC,
    // sharing no code with the bitwise production routine.
    // ------------------------------------------------------------------

    fn independent_crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                if value & 1 != 0 {
                    value = (value >> 1) ^ 0xEDB8_8320;
                } else {
                    value >>= 1;
                }
            }
            *slot = value;
        }
        let mut crc = 0xFFFF_FFFF;
        for &byte in data {
            let low = (crc ^ u32::from(byte)) & 0xFF;
            crc = table[low as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }

    /// Little-endian `u64` at `at` in a header sector (test helper).
    fn u64_at(sector: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(
            sector[at..at + 8]
                .try_into()
                .expect("eight bytes at a header field"),
        )
    }

    /// Little-endian `u32` at `at` in a header sector (test helper).
    fn u32_at(sector: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(
            sector[at..at + 4]
                .try_into()
                .expect("four bytes at a header field"),
        )
    }

    /// A partition in the middle of a 2 MiB disk, EFI type by default.
    fn partition(first_lba: u64, last_lba: u64, name: &'static str) -> GptPartition {
        GptPartition {
            type_guid: EFI_TYPE_GUID_RAW,
            unique_guid: UNIQUE_GUID_RAW,
            first_lba,
            last_lba,
            attributes: 0,
            name,
        }
    }

    // ------------------------------------------------------------------
    // CRC-32 and GUID formatting
    // ------------------------------------------------------------------

    #[test]
    fn crc32_matches_reference_vectors() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32_ieee(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339,
        );
    }

    #[test]
    fn guid_to_string_decodes_the_mixed_endian_groups() {
        assert_eq!(
            guid_to_string(&EFI_TYPE_GUID_RAW),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "the first three groups are LE on disk"
        );
        assert_eq!(
            guid_to_string(&LINUX_TYPE_GUID_RAW),
            "0fc63daf-8483-4772-8e79-3d69d8477de4",
        );
        assert_eq!(
            guid_to_string(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000",
        );
    }

    // ------------------------------------------------------------------
    // GPT
    // ------------------------------------------------------------------

    #[test]
    fn gpt_entry_range_reads_the_declared_location() {
        let header = crate::part::test_support::gpt_header_sector(2);
        assert_eq!(
            gpt_entry_range(&header),
            Some(GptEntryRange {
                entry_lba: 2,
                count: 2,
                entry_size: 128,
            }),
            "the three location fields map verbatim"
        );
        // Exactly 92 bytes is enough: the location fields end there.
        assert_eq!(
            gpt_entry_range(&header[..92]),
            Some(GptEntryRange {
                entry_lba: 2,
                count: 2,
                entry_size: 128,
            }),
        );
    }

    #[test]
    fn gpt_entry_range_interprets_nonsense_as_none() {
        // Not a header at all (no signature): garbage or too short.
        assert_eq!(gpt_entry_range(&[0u8; 512]), None);
        let mut garbage = [0u8; 512];
        garbage[72..80].copy_from_slice(&99u64.to_le_bytes());
        assert_eq!(gpt_entry_range(&garbage), None);
        // Drop below 88 bytes: entry count/size no longer readable.
        assert_eq!(
            gpt_entry_range(&crate::part::test_support::gpt_header_sector(1)[..80]),
            None
        );

        // A zero stride cannot size a read plan.
        let mut header = crate::part::test_support::gpt_header_sector(1);
        header[84..88].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(gpt_entry_range(&header), None, "no stride, no array");
    }

    #[test]
    fn gpt_entry_range_caps_count_and_entry_size() {
        let mut header = crate::part::test_support::gpt_header_sector(200);
        header[84..88].copy_from_slice(&8192u32.to_le_bytes());
        assert_eq!(
            gpt_entry_range(&header),
            Some(GptEntryRange {
                entry_lba: 2,
                count: MAX_GPT_ENTRIES,
                entry_size: MAX_GPT_ENTRY_SIZE,
            }),
            "declared values above the caps clamp to them"
        );
    }

    #[test]
    fn parse_gpt_reads_partitions_guids_names_and_attributes() {
        let entry0: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(EFI_TYPE_GUID_RAW),
            Some(UNIQUE_GUID_RAW),
            2048,
            1_050_623,
            0x1,                                // system partition bit
            Some(&[0x0045, 0x0046, 0x0049, 0]), // "EFI", NUL-terminated
        );
        let entry1: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            1_050_624,
            1_052_671,
            0,
            Some(&[0x0052, 0x004F, 0x004F, 0x0054]), // "ROOT"
        );
        let mut entries = entry0.to_vec();
        entries.extend_from_slice(&entry1);

        let header = crate::part::test_support::sealed_gpt(2, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");

        assert_eq!(partitions.len(), 2);
        assert_eq!(partitions[0].index, 1);
        assert_eq!(partitions[0].kind, "efi_system");
        assert_eq!(partitions[0].name.as_deref(), Some("EFI"));
        assert_eq!(partitions[0].start_lba, 2048);
        assert_eq!(partitions[0].sectors, 1_048_576);
        assert_eq!(partitions[0].size_bytes, 536_870_912);
        assert_eq!(partitions[0].attributes, Some(0x1));
        assert_eq!(
            partitions[0].guid.as_deref(),
            Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
        );
        assert_eq!(
            partitions[0].unique_guid.as_deref(),
            Some("04030201-0605-0807-090a-0b0c0d0e0f10"),
            "the ascending test bytes decode through the LE groups"
        );
        assert!(!partitions[0].bootable, "GPT has no MBR boot flag");
        assert_eq!(partitions[1].kind, "linux_filesystem");
        assert_eq!(partitions[1].name.as_deref(), Some("ROOT"));
        assert_eq!(partitions[1].sectors, 2048);
        assert_eq!(
            partitions[1].unique_guid.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn gpt_names_cut_at_nul_and_pass_the_sanitiser() {
        // BEL and CJK both land as one `?` each; the trailing NUL is a
        // terminator, not content.
        let entry: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            2048,
            2048,
            0,
            Some(&[0x004C, 0x005F, 0x0007, 0x4E2D, 0, 0x0058]), // "L_\x07中\0X"
        );
        let entries = entry.to_vec();
        let header = crate::part::test_support::sealed_gpt(1, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            partitions[0].name.as_deref(),
            Some("L_??"),
            "padding never renders as `?`s"
        );

        // A name-less entry stays None rather than an empty string.
        let blank: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(EFI_TYPE_GUID_RAW),
            None,
            2048,
            2048,
            0,
            Some(&[0]),
        );
        let entries = blank.to_vec();
        let header = crate::part::test_support::sealed_gpt(1, &entries);
        let (partitions, _warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert_eq!(partitions[0].name, None);
    }

    #[test]
    fn parse_gpt_rejects_headers_that_cannot_be_parsed_at_all() {
        // No signature: a headerless sector is not a GPT header.
        let mut header = crate::part::test_support::gpt_header_sector(1);
        header[0] = b'X';
        let err = parse_gpt(&header, &[], 512).expect_err("signature");
        assert!(err.to_string().contains("signature is missing"), "{err}");

        // `header_size` below the mandatory 92.
        let mut header = crate::part::test_support::gpt_header_sector(1);
        header[12..16].copy_from_slice(&91u32.to_le_bytes());
        let err = parse_gpt(&header, &[], 512).expect_err("header size");
        assert!(err.to_string().contains("header size is nonsense"), "{err}");

        // `size_of_entry` below the mandatory 128.
        let mut header = crate::part::test_support::gpt_header_sector(1);
        header[84..88].copy_from_slice(&64u32.to_le_bytes());
        let err = parse_gpt(&header, &[], 512).expect_err("entry size");
        assert!(err.to_string().contains("entry size is nonsense"), "{err}");

        // Header too small to even read the entry-array fields.
        let short_header = &crate::part::test_support::gpt_header_sector(1)[..24];
        let err = parse_gpt(short_header, &[], 512).expect_err("short header");
        assert!(
            err.to_string().contains("does not declare an entry count"),
            "{err}"
        );
    }

    #[test]
    fn parse_gpt_warns_on_header_crc_mismatch_but_parses_on() {
        let entry: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(EFI_TYPE_GUID_RAW),
            None,
            2048,
            1_050_623,
            0,
            None,
        );
        let entries = entry.to_vec();
        let mut header = crate::part::test_support::sealed_gpt(1, &entries);
        header[17] ^= 0x40; // rot one bit inside the stored header CRC
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("crc rot is soft");
        assert_eq!(warnings, vec!["gpt header crc mismatch"]);
        assert_eq!(partitions.len(), 1, "the entries themselves are intact");
    }

    #[test]
    fn parse_gpt_warns_on_entry_array_truncation() {
        let entries_full: [u8; 256] = [
            crate::part::test_support::gpt_entry(
                Some(EFI_TYPE_GUID_RAW),
                None,
                2048,
                2048,
                0,
                None,
            ),
            crate::part::test_support::gpt_entry(
                Some(LINUX_TYPE_GUID_RAW),
                None,
                4096,
                4096,
                0,
                None,
            ),
        ]
        .concat()
        .try_into()
        .expect("256-byte array");
        let mut header = crate::part::test_support::gpt_header_sector(2);
        header[88..92].copy_from_slice(&crc32_ieee(&entries_full).to_le_bytes());
        crate::part::test_support::seal_header(&mut header);

        let (partitions, warnings) =
            parse_gpt(&header, &entries_full[..128], 512).expect("only half the array");
        assert_eq!(
            warnings,
            vec!["gpt entry array truncated", "gpt entry array crc mismatch"],
        );
        assert_eq!(partitions.len(), 1, "only the entry that is fully present");
        assert_eq!(partitions[0].kind, "efi_system");
    }

    #[test]
    fn parse_gpt_caps_the_entry_count_at_128() {
        // 200 entries declared, all present in the buffer: the cap
        // bounds the work and warns, without renting extra memory.
        let mut entries = Vec::new();
        for index in 0..200u32 {
            let first = u64::from(index) * 2048;
            let entry = crate::part::test_support::gpt_entry(
                Some(EFI_TYPE_GUID_RAW),
                None,
                first,
                first + 1,
                0,
                None,
            );
            entries.extend_from_slice(&entry);
        }
        let header = crate::part::test_support::sealed_gpt(200, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("declares fine");
        assert_eq!(warnings, vec!["gpt entry array capped at 128 entries"]);
        assert_eq!(partitions.len(), 128);
        assert_eq!(partitions.last().expect("at least one").index, 128);
    }

    #[test]
    fn parse_gpt_skips_entries_with_reversed_bounds() {
        let entry: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            4096,
            2048,
            0,
            None,
        );
        let entries = entry.to_vec();
        let header = crate::part::test_support::sealed_gpt(1, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert_eq!(warnings, vec!["gpt entry 1 has reversed bounds"]);
        assert!(partitions.is_empty());
    }

    #[test]
    fn gpt_inclusive_span_and_saturation() {
        // first == 0, last == u64::MAX: the +1 must saturate, not wrap
        // to 0, and the byte size must saturate with it.
        let entry: [u8; 128] = crate::part::test_support::gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            0,
            u64::MAX,
            0,
            None,
        );
        let entries = entry.to_vec();
        let header = crate::part::test_support::sealed_gpt(1, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(partitions[0].sectors, u64::MAX);
        assert_eq!(partitions[0].size_bytes, u64::MAX, "saturated, not wrapped");
    }

    #[test]
    fn parse_gpt_handles_larger_entry_sizes() {
        // soe 256: fields stay at their fixed offsets, the stride doubles.
        let mut entry = [0u8; 256];
        entry[0..16].copy_from_slice(&EFI_TYPE_GUID_RAW);
        entry[32..40].copy_from_slice(&2048u64.to_le_bytes());
        entry[40..48].copy_from_slice(&4095u64.to_le_bytes());
        entry[56..58].copy_from_slice(&0x0041u16.to_le_bytes()); // "A"
        let entries = entry.to_vec();
        let mut header = crate::part::test_support::gpt_header_sector(1);
        header[84..88].copy_from_slice(&256u32.to_le_bytes());
        header[88..92].copy_from_slice(&crc32_ieee(&entries).to_le_bytes());
        crate::part::test_support::seal_header(&mut header);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("soe 256");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(partitions[0].kind, "efi_system");
        assert_eq!(partitions[0].sectors, 2048);
        assert_eq!(partitions[0].name.as_deref(), Some("A"));
    }

    // ------------------------------------------------------------------
    // GPT writing (S08)
    // ------------------------------------------------------------------

    /// The full round trip: the writer's primary image reads back
    /// through `parse_gpt` and `detect_layout`, field by field.
    #[test]
    fn write_gpt_round_trips_through_parse_gpt_and_detect_layout() {
        let esp_unique = Uuid::new_v4();
        let linux_unique = Uuid::new_v4();
        let data_unique = Uuid::new_v4();
        let disk_guid = uuid_to_gpt_bytes(Uuid::new_v4());
        let partitions = [
            GptPartition {
                type_guid: EFI_TYPE_GUID_RAW,
                unique_guid: uuid_to_gpt_bytes(esp_unique),
                first_lba: 1024,
                last_lba: 2047,
                attributes: 0x1, // system partition bit
                name: "ESP",
            },
            GptPartition {
                type_guid: LINUX_TYPE_GUID_RAW,
                unique_guid: uuid_to_gpt_bytes(linux_unique),
                first_lba: 2048,
                last_lba: 4063,
                attributes: 0,
                name: "LINUX",
            },
            GptPartition {
                // An unknown type GUID must stay "unknown", not be
                // second-guessed into a slug.
                type_guid: UNIQUE_GUID_RAW,
                unique_guid: uuid_to_gpt_bytes(data_unique),
                first_lba: 512,
                last_lba: 1023,
                attributes: 0,
                name: "DATA",
            },
        ];
        let image = write_gpt(512, 4096, disk_guid, &partitions)
            .expect("three entries fit a 4096-sector disk");
        assert_eq!(image.first_usable, 34, "2 + the 32 array sectors");
        assert_eq!(image.last_usable, 4063, "one below the backup array");
        assert_eq!(image.backup_lba, 4096);

        // The protective MBR marks the disk and covers it.
        assert!(is_protective_mbr(&image.protective_mbr));
        assert_eq!(image.protective_mbr[446 + 4], 0xEE);
        assert_eq!(u32_at(&image.protective_mbr, 454), 1, "protective start");
        assert_eq!(
            u32_at(&image.protective_mbr, 458),
            4096,
            "covering min(last_lba, 0xffff_ffff) sectors"
        );

        let (parsed, warnings) = parse_gpt(&image.primary_header, &image.primary_entries, 512)
            .expect("sealed primary header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].index, 1);
        assert_eq!(parsed[0].kind, "efi_system");
        assert_eq!(parsed[0].name.as_deref(), Some("ESP"));
        assert_eq!(parsed[0].start_lba, 1024);
        assert_eq!(parsed[0].sectors, 1024, "inclusive bounds, 1024..2047");
        assert_eq!(parsed[0].attributes, Some(0x1));
        assert!(!parsed[0].bootable, "GPT has no MBR boot flag");
        assert_eq!(
            parsed[0].guid.as_deref(),
            Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
        );
        assert_eq!(
            parsed[0].unique_guid.as_deref(),
            Some(esp_unique.to_string().as_str()),
            "the uuid crate's GUID round-trips through the on-disk bytes"
        );
        assert_eq!(parsed[1].kind, "linux_filesystem");
        assert_eq!(parsed[1].name.as_deref(), Some("LINUX"));
        assert_eq!(parsed[1].sectors, 2016);
        assert_eq!(
            parsed[1].guid.as_deref(),
            Some("0fc63daf-8483-4772-8e79-3d69d8477de4"),
        );
        assert_eq!(
            parsed[1].unique_guid.as_deref(),
            Some(linux_unique.to_string().as_str()),
        );
        assert_eq!(parsed[2].kind, "unknown");
        assert_eq!(parsed[2].name.as_deref(), Some("DATA"));
        assert_eq!(parsed[2].start_lba, 512);
        assert_eq!(parsed[2].sectors, 512);
        assert_eq!(
            parsed[2].unique_guid.as_deref(),
            Some(data_unique.to_string().as_str()),
        );

        // The disk GUID lives at header offset 56..72, verbatim.
        assert_eq!(
            &image.primary_header[56..72],
            &disk_guid,
            "the caller's disk GUID is written as given"
        );

        let layout = detect_layout(
            &image.protective_mbr,
            Some(&image.primary_header),
            Some(&image.primary_entries),
            Some(&image.backup_header),
            512,
        )
        .expect("protective MBR plus a parseable GPT");
        assert_eq!(layout.kind, TableKind::Gpt);
        assert!(layout.backup_gpt, "the backup header cross-checks");
        assert!(layout.warnings.is_empty(), "{:?}", layout.warnings);
        assert_eq!(layout.partitions, parsed);
    }

    #[test]
    fn write_gpt_crcs_survive_an_independent_check() {
        // Pin the checker itself against the RFC vector before trusting
        // it on the produced bytes.
        assert_eq!(independent_crc32(b"123456789"), 0xCBF4_3926);

        let image =
            write_gpt(512, 4096, [0u8; 16], &[partition(1024, 1535, "P")]).expect("one entry fits");
        for (name, sector, entries) in [
            ("primary", &image.primary_header, &image.primary_entries[..]),
            ("backup", &image.backup_header, &image.backup_entries[..]),
        ] {
            let stored_header_crc = u32_at(sector, header::HEADER_CRC);
            let stored_entries_crc = u32_at(sector, header::ENTRIES_CRC);
            // The header CRC is verified over the 92 declared bytes with
            // the CRC field zeroed — the exact independent routine, not
            // the production function on the full sector.
            let mut zeroed = sector.clone();
            zeroed[header::HEADER_CRC..header::HEADER_CRC + 4].copy_from_slice(&[0; 4]);
            assert_eq!(
                independent_crc32(&zeroed[..92]),
                stored_header_crc,
                "{name} header crc recomputed independently"
            );
            assert_eq!(
                independent_crc32(entries),
                stored_entries_crc,
                "{name} entry-array crc recomputed independently"
            );
        }
    }

    #[test]
    fn write_gpt_places_the_second_copy_at_the_documented_lbas() {
        let image = write_gpt(
            512,
            4096,
            [0u8; 16],
            &[partition(1024, 1535, "P"), partition(1536, 4063, "Q")],
        )
        .expect("two entries fit");

        // Primary header at LBA 1, entries at LBA 2.
        assert_eq!(u64_at(&image.primary_header, header::MY_LBA), 1);
        assert_eq!(u64_at(&image.primary_header, header::ALTERNATE_LBA), 4096);
        assert_eq!(u64_at(&image.primary_header, header::ENTRY_ARRAY_LBA), 2);
        assert_eq!(u64_at(&image.primary_header, header::FIRST_USABLE), 34);
        assert_eq!(u64_at(&image.primary_header, header::LAST_USABLE), 4063);
        assert_eq!(u32_at(&image.primary_header, header::ENTRY_COUNT), 128);
        assert_eq!(u32_at(&image.primary_header, header::ENTRY_SIZE), 128);

        // Backup: current/alternate swapped, entries below the header.
        assert_eq!(image.backup_lba, 4096);
        assert_eq!(u64_at(&image.backup_header, header::MY_LBA), 4096);
        assert_eq!(u64_at(&image.backup_header, header::ALTERNATE_LBA), 1);
        assert_eq!(
            u64_at(&image.backup_header, header::ENTRY_ARRAY_LBA),
            4064,
            "the 32 backup-entry sectors end just below the header"
        );
        assert_eq!(u64_at(&image.backup_header, header::FIRST_USABLE), 34);
        assert_eq!(u64_at(&image.backup_header, header::LAST_USABLE), 4063);
        assert_eq!(
            image.backup_entries, image.primary_entries,
            "the entry arrays are byte-identical copies"
        );

        // The two headers differ only in the fields that say where each
        // copy lives (its own LBA, the other copy's LBA, and where the
        // entry array it points at starts) plus the derived header CRC.
        // Zero those four ranges in both copies; everything else —
        // revision, header size, usable range, disk GUID, entry
        // count/size, entries CRC, reserved field and zero padding —
        // must then be byte-identical.
        let mut primary = image.primary_header.clone();
        let mut backup = image.backup_header.clone();
        for copy in [&mut primary, &mut backup] {
            // The 4-byte CRC field, then the three 8-byte location
            // fields. (The [0; N] fill lengths match the fields, not the
            // other way around.)
            copy[header::HEADER_CRC..header::HEADER_CRC + 4].copy_from_slice(&[0; 4]);
            for field in [
                header::MY_LBA,
                header::ALTERNATE_LBA,
                header::ENTRY_ARRAY_LBA,
            ] {
                copy[field..field + 8].copy_from_slice(&[0; 8]);
            }
        }
        assert_eq!(primary, backup, "only the swapped fields may differ");
    }

    #[test]
    fn write_gpt_scales_to_4096_byte_sectors() {
        let image = write_gpt(4096, 64, [0u8; 16], &[partition(8, 59, "P")])
            .expect("65 sectors clear the 11-sector 4096 floor");
        // Sector-sized buffers with the header at offset 0.
        assert_eq!(image.primary_header.len(), 4096);
        assert_eq!(image.backup_header.len(), 4096);
        assert_eq!(
            &image.primary_header[0..GPT_SIGNATURE.len()],
            &GPT_SIGNATURE[..],
            "EFI PART starts at byte 0"
        );
        assert_eq!(
            &image.backup_header[0..GPT_SIGNATURE.len()],
            &GPT_SIGNATURE[..]
        );

        // Generalised usable range: 2 + 4 array sectors .. last - 4 - 1.
        assert_eq!(image.first_usable, 6);
        assert_eq!(image.last_usable, 59);
        assert_eq!(u64_at(&image.primary_header, header::ENTRY_ARRAY_LBA), 2);
        assert_eq!(u64_at(&image.backup_header, header::ENTRY_ARRAY_LBA), 60);
        assert_eq!(u64_at(&image.backup_header, header::MY_LBA), 64);
        assert_eq!(image.backup_lba, 64);

        // The round trip still ends where it started.
        let (parsed, warnings) =
            parse_gpt(&image.primary_header, &image.primary_entries, 4096).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sectors, 52);

        // The protective MBR covers the disk min(last, 0xffff_ffff) way.
        assert_eq!(u32_at(&image.protective_mbr, 458), 64);
    }

    #[test]
    fn write_gpt_refuses_a_disk_without_enough_headroom() {
        // 512-byte sectors: 34 front sectors + 32 backup-entry sectors
        // + 1 backup header = 67 sectors in total.
        let error = write_gpt(512, 65, [0u8; 16], &[]).expect_err("66 sectors are not enough");
        let text = error.to_string();
        assert!(text.contains("at least 67"), "{text}");
        assert!(text.contains("got 66"), "{text}");
        assert!(
            write_gpt(512, 66, [0u8; 16], &[]).is_ok(),
            "the 67-sector minimum image builds"
        );

        // 4096: 6 front sectors + 4 backup-entry sectors + 1 header = 11.
        let error = write_gpt(4096, 9, [0u8; 16], &[]).expect_err("10 sectors are not enough");
        assert!(error.to_string().contains("at least 11"), "{error}");
        assert!(write_gpt(4096, 10, [0u8; 16], &[]).is_ok());
    }

    #[test]
    fn write_gpt_refuses_sector_sizes_other_than_512_and_4096() {
        for sector_size in [0u32, 1, 512 + 512, 8192] {
            let error = write_gpt(sector_size, 4096, [0u8; 16], &[])
                .expect_err("only 512 and 4096 are legal");
            assert!(error.to_string().contains("512 or 4096"), "{error}");
        }
    }

    #[test]
    fn write_gpt_refuses_reversed_and_overlapping_partitions() {
        let error = write_gpt(
            512,
            4096,
            [0u8; 16],
            &[GptPartition {
                type_guid: EFI_TYPE_GUID_RAW,
                unique_guid: [0u8; 16],
                first_lba: 2048,
                last_lba: 1024,
                attributes: 0,
                name: "R",
            }],
        )
        .expect_err("reversed bounds");
        assert!(error.to_string().contains("reversed"), "{error}");

        let error = write_gpt(
            512,
            4096,
            [0u8; 16],
            &[partition(1024, 2048, "A"), partition(2048, 3000, "B")],
        )
        .expect_err("the two entries share sector 2048");
        assert!(error.to_string().contains("overlap"), "{error}");
        assert!(error.to_string().contains("1 and 2"), "{error}");

        // Touching edges are fine: one entry's last is the next's first − 1.
        assert!(
            write_gpt(
                512,
                4096,
                [0u8; 16],
                &[partition(1024, 2047, "A"), partition(2048, 3000, "B")],
            )
            .is_ok(),
            "touching but disjoint spans are accepted"
        );
    }

    #[test]
    fn write_gpt_refuses_names_that_do_not_fit_the_field() {
        // 36 characters fill the field exactly (no terminator possible);
        // the parser reads all of it back.
        let name36: &'static str = Box::leak("A".repeat(36).into_boxed_str());
        let image = write_gpt(512, 4096, [0u8; 16], &[partition(1024, 1535, name36)])
            .expect("36 characters are exactly the field size");
        let (parsed, warnings) =
            parse_gpt(&image.primary_header, &image.primary_entries, 512).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(parsed[0].name.as_deref(), Some(name36));

        let name37: &'static str = Box::leak("B".repeat(37).into_boxed_str());
        let error = write_gpt(512, 4096, [0u8; 16], &[partition(1024, 1535, name37)])
            .expect_err("37 characters cannot fit");
        assert!(error.to_string().contains("at most 36"), "{error}");

        // Non-ASCII bytes have no honest UTF-16LE round trip through the
        // field rule, so they are refused before any encoding.
        let error = write_gpt(512, 4096, [0u8; 16], &[partition(1024, 1535, "RöSTI")])
            .expect_err("non-ascii name");
        assert!(error.to_string().contains("ascii"), "{error}");
    }

    #[test]
    fn write_gpt_refuses_more_than_128_entries() {
        // Disjoint single-sector entries: the refusal must be about the
        // count, nothing else.
        let many: Vec<GptPartition> = (0..129u64)
            .map(|slot| GptPartition {
                type_guid: EFI_TYPE_GUID_RAW,
                unique_guid: [0u8; 16],
                first_lba: 34 + slot,
                last_lba: 34 + slot,
                attributes: 0,
                name: "P",
            })
            .collect();
        let error =
            write_gpt(512, 4096, [0u8; 16], &many).expect_err("the table holds 128 entries");
        assert!(error.to_string().contains("128"), "{error}");
    }

    #[test]
    fn write_gpt_unique_guids_from_uuid_v4_differ_between_calls() {
        let mut parsed_unique = Vec::new();
        for _ in 0..2 {
            let unique = Uuid::new_v4();
            let image = write_gpt(
                512,
                4096,
                [0u8; 16],
                &[GptPartition {
                    type_guid: EFI_TYPE_GUID_RAW,
                    unique_guid: uuid_to_gpt_bytes(unique),
                    first_lba: 1024,
                    last_lba: 1535,
                    attributes: 0,
                    name: "P",
                }],
            )
            .expect("one entry fits");
            let (parsed, warnings) = parse_gpt(&image.primary_header, &image.primary_entries, 512)
                .expect("sealed header");
            assert!(warnings.is_empty(), "{warnings:?}");
            assert_eq!(
                parsed[0].unique_guid.as_deref(),
                Some(unique.to_string().as_str()),
                "each v4 GUID lands in its entry unchanged"
            );
            parsed_unique.push(parsed[0].unique_guid.clone());
        }
        assert_ne!(
            parsed_unique[0], parsed_unique[1],
            "two new_v4() calls never land as the same table entry"
        );
    }
}
