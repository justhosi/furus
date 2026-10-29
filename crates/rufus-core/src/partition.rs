//! MBR and GPT partition-table parsing, read-side only (S05).
//!
//! S04 trusts the udev record's single `ID_PART_TABLE_TYPE` label; this
//! module re-derives the *authoritative* table from the device bytes so
//! the preview and the safety verdict describe what really rules the
//! disk (PLAN §9-S05: "expose partitions (start, size, type, GUID, name,
//! flags)"). The caller owns the I/O: these functions take raw LBA
//! sectors and never open a device, so every failure mode here is
//! unit-testable without hardware.
//!
//! Rules the tests pin:
//!
//! * A disk without the `0x55AA` LBA0 signature is **not** an error —
//!   a blank or foreign-media card is the normal case and erasing it is
//!   what the tool exists for; the layout simply comes back empty.
//! * CRC or truncation problems are **warnings**, not hard errors: the
//!   report-only verdict must still be answerable when the metadata is
//!   half-rotten. Hard errors are reserved for inputs that make parsing
//!   meaningless (no signature, nonsense header or entry size).
//! * Entry indices are 1-based *positions* in the table, mirroring how
//!   the kernel numbers `sda1..sda4` and GPT entries, so a skipped slot
//!   never renumbers later partitions.
//! * Sizes saturate instead of overflowing: a corrupt entry must never
//!   wrap a byte count into `0` and thereby pass every size check
//!   downstream.

use serde::Serialize;

use crate::error::CoreError;
use crate::error::Result;
use crate::text::device_text;

/// The only two bytes that mark a parsed master boot record; also used
/// by [`crate::fsprobe`] as the FAT boot-sector guard.
pub const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// Where the four MBR partition entries start (the rest of LBA0 is boot
/// code, CHS plumbing, and the signature at 510..512).
const MBR_ENTRY_AREA: usize = 446;
/// One MBR entry is exactly 16 bytes, four entries back-to-back.
const MBR_ENTRY_SIZE: usize = 16;
/// Floor of a GPT header's self-declared `header_size`: anything smaller
/// cannot honestly hold the fields this parser reads.
const GPT_HEADER_MIN_SIZE: u32 = 92;
/// Entry-count cap. UEFI itself defines at most 128 entries; capping
/// also bounds the work per device instead of trusting the header.
const MAX_GPT_ENTRIES: u32 = 128;
/// GPT on-disk signature at the start of every header sector.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// A GPT entry is at least 128 bytes; larger strides are legal
/// (`size_of_entry` need not be a power of two).
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
/// the reader below never hand-writes an offset twice.
mod header {
    /// `u32` CRC-32 of the whole header, stored at offset 16; stored
    /// zeroed for the verification computation.
    pub const HEADER_CRC: usize = 16;
    /// `u32`: self-declared header size in bytes.
    pub const HEADER_SIZE: usize = 12;
    /// `u64`: LBA of this (primary) header.
    pub const MY_LBA: usize = 24;
    /// `u64`: LBA of the backup header (usually the last sector).
    pub const ALTERNATE_LBA: usize = 32;
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

/// Which table format a [`Layout`] was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    /// Classic MBR (DOS) table from LBA0 — includes a protective MBR
    /// whose GPT side failed to parse (the warnings say so).
    Mbr,
    /// GUID partition table; the MBR side was protective and ignored.
    Gpt,
}

/// One partition, normalised across both table formats.
///
/// Field names are publish-facing (they reach the `analyze --json`
/// output), so any rename is a JSON-visible change. `guid`/`unique_guid`
/// are `None` for MBR tables, `name` is `Some` only when a GPT entry
/// states one, and `attributes` keeps the raw GPT 64-bit bitmap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TablePartition {
    /// 1-based position in the table (kernel partition-number style).
    pub index: u32,
    /// First sector of the partition.
    pub start_lba: u64,
    /// Sector count (MBR: the 32-bit value; GPT: `last - first + 1`,
    /// saturated rather than wrapping for corrupt entries).
    pub sectors: u64,
    /// `sectors * sector_size`, saturating — never lies about being `0`
    /// when the true count overflows.
    pub size_bytes: u64,
    /// Stable ASCII slug (`"fat32"`, `"efi_system"`, ...), or the raw
    /// MBR type id as `0x83`-style hex when no slug is known.
    pub kind: String,
    /// GPT entry name, sanitised through [`device_text`]; `None` for MBR
    /// and for empty GPT names (UEFI pads them with NULs, which are
    /// terminator, not content — see `gpt_entry_name`).
    pub name: Option<String>,
    /// MBR bootable flag (`0x80` in the entry). `false` for GPT, where
    /// bootability is an attribute bit, not a flag byte.
    pub bootable: bool,
    /// Raw GPT attribute bitmap; `None` for MBR.
    pub attributes: Option<u64>,
    /// GPT *type* GUID in canonical lowercase `8-4-4-4-12` form.
    pub guid: Option<String>,
    /// GPT per-partition unique GUID in the same form.
    pub unique_guid: Option<String>,
}

/// A parsed device layout: which table format ruled it, its partitions,
/// and everything the parse objected to along the way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// Which table format the partitions were read from.
    pub kind: TableKind,
    /// Normalised partitions, in table order.
    pub partitions: Vec<TablePartition>,
    /// Whether a *valid* second GPT header (the backup copy in the last
    /// sector) was found — the stronger "this disk really is GPT"
    /// signal, since a lone protective MBR can also be history junk.
    pub backup_gpt: bool,
    /// ASCII, end-user-readable notes about rotted metadata ("gpt entry
    /// array truncated", ...). Warnings never abort the parse.
    pub warnings: Vec<String>,
}

/// `sectors * sector_size`, saturating; one helper so no call site does
/// the arithmetic twice and possibly differently.
fn sectors_to_bytes(sectors: u64, sector_size: u32) -> u64 {
    sectors.saturating_mul(u64::from(sector_size))
}

/// Read one little-endian `u16` at `at` (`None` when the buffer is short
/// or the offset overflows; never indexes in a way that can panic).
fn u16_le(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    let unit: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(unit))
}

/// Read one little-endian `u32` at `at`.
fn u32_le(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at.checked_add(4)?)?;
    let unit: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(unit))
}

/// Read one little-endian `u64` at `at`.
fn u64_le(buf: &[u8], at: usize) -> Option<u64> {
    let bytes = buf.get(at..at.checked_add(8)?)?;
    let unit: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(unit))
}

/// Copy 16 raw GUID bytes out of `buf` at `at`.
fn guid_bytes(buf: &[u8], at: usize) -> Option<[u8; 16]> {
    let bytes = buf.get(at..at.checked_add(16)?)?;
    bytes.try_into().ok()
}

/// Does `buf` hold `signature` at offset 0? Shared shape for the GPT
/// header, backup-header and MBR-signature checks.
fn starts_with_signature(buf: &[u8], signature: &[u8]) -> bool {
    buf.get(..signature.len()) == Some(signature)
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

/// Stable slug for one MBR partition type byte.
///
/// The table covers the types a Rufus workflow meets in the field (FAT
/// variants, NTFS/exFAT, Linux, the EFI plumbing); everything else falls
/// back to its raw id in `0x83` form so the report stays truthful
/// instead of inventing a slug.
fn mbr_kind(type_id: u8) -> String {
    let known = match type_id {
        0x01 => "fat12",
        0x04 | 0x06 | 0x0e => "fat16",
        0x0b | 0x0c => "fat32",
        0x07 => "ntfs_exfat",
        0x05 | 0x0f => "extended",
        0x82 => "linux_swap",
        0x83 => "linux",
        0x85 => "linux_extended",
        0x8e => "linux_lvm",
        0xee => "gpt_protective",
        0xef => "efi_system",
        0xa5 => "freebsd",
        0xa8 => "macos",
        0xaf => "hfs",
        0xfd => "linux_raid",
        other => return format!("0x{other:02x}"),
    };
    known.to_owned()
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

/// Decode one MBR entry slot the way [`parse_mbr`] reads it:
/// `(type_id, bootable, start, sectors)` for a live entry, `None` for
/// an unused/zero-geometry slot or a range past the buffer. One decoder
/// for both the partition list and the extended-container warning scan,
/// so the two passes cannot disagree about what was parsed.
fn mbr_slot(lba0: &[u8], slot: usize) -> Option<(u8, bool, u32, u32)> {
    let base = MBR_ENTRY_AREA + slot * MBR_ENTRY_SIZE;
    let entry = lba0.get(base..base + MBR_ENTRY_SIZE)?;
    // The partition type lives at entry offset 4; bytes 0..4 are boot
    // flag and CHS numbers, which no decision here needs.
    let type_id = entry.get(4).copied()?;
    if type_id == 0 {
        return None; // set by the disk's first wipe and never reused
    }
    let start = u32_le(entry, 8)?;
    let entry_sectors = u32_le(entry, 12)?;
    if start == 0 && entry_sectors == 0 {
        return None; // all-zero geometry: historical slot, no media behind it
    }
    Some((type_id, entry.first() == Some(&0x80), start, entry_sectors))
}

/// Parse the MBR entries of LBA0. `None` when the `0x55AA` signature is
/// absent — a blank or foreign disk, not an error (see the module
/// header). One 16-byte entry reads: byte 0 the boot flag (`0x80`
/// marks bootable), byte 4 the partition type, bytes 8 and 12 the
/// start/length `u32`s little-endian. Unused slots (`type == 0`, or
/// start/sectors both zero) are skipped, and the slot position becomes
/// the 1-based index so the numbering keeps matching kernel device
/// nodes.
#[must_use]
pub fn parse_mbr(lba0: &[u8], sector_size: u32) -> Option<Vec<TablePartition>> {
    let signature = lba0.get(510..512);
    if signature != Some(&MBR_SIGNATURE[..]) {
        return None;
    }
    let mut partitions = Vec::with_capacity(4);
    for slot in 0..4 {
        let Some((type_id, bootable, start, entry_sectors)) = mbr_slot(lba0, slot) else {
            // Unused or zero-geometry slot, or past the buffer's edge;
            // every later slot is equally out of bounds, so skipping is
            // the same answer stopping would give.
            continue;
        };
        partitions.push(TablePartition {
            index: slot as u32 + 1,
            start_lba: u64::from(start),
            sectors: u64::from(entry_sectors),
            size_bytes: sectors_to_bytes(u64::from(entry_sectors), sector_size),
            kind: mbr_kind(type_id),
            name: None,
            bootable,
            attributes: None,
            guid: None,
            unique_guid: None,
        });
    }
    Some(partitions)
}

/// Whether any of the four MBR entries claims the protective `0xEE`
/// type — the marker a GPT-formatted disk leaves in LBA0 so legacy
/// tooling sees one inert "whole disk" partition. Only meaningful
/// together with a parsed MBR; callers such as [`detect_layout`] check
/// the signature first, the predicate deliberately does not ask for it.
#[must_use]
pub fn is_protective_mbr(lba0: &[u8]) -> bool {
    (0..4).any(|slot| lba0.get(MBR_ENTRY_AREA + slot * MBR_ENTRY_SIZE + 4) == Some(&0xEE))
}

/// One ASCII warning per extended container entry (`0x05`, `0x0F`,
/// `0x85`), in table order.
///
/// An extended container is not a file-carrying volume: its entry points
/// at an EBR chain of logical partitions, and S05 deliberately does not
/// walk that chain. Listing the container alone would read like a
/// complete inventory of the disk, so the assembled [`Layout`] drops
/// the container entries (see [`detect_layout`]) and every dropped one
/// gets this explicit caveat instead. The message is fixed ASCII (`0x`
/// plus two lowercase hex digits from the raw type byte) — no untrusted
/// text is interpolated.
fn extended_container_warnings(lba0: &[u8]) -> Vec<String> {
    (0..4)
        .filter_map(|slot| mbr_slot(lba0, slot))
        .filter(|(type_id, ..)| matches!(type_id, 0x05 | 0x0f | 0x85))
        .map(|(type_id, ..)| {
            format!("extended partition (type 0x{type_id:02x}): logical partitions are not listed")
        })
        .collect()
}

/// Where the GPT entry array lives, as declared by the header.
///
/// A sizing aid for callers that stream their reads ([`detect_layout`]
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
/// verdict, see the module header). The caller owns the I/O and hands
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
fn verified_backup(
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

/// Read-side assembly from raw sectors (the caller owns the I/O).
///
/// Rules, tried in order:
///
/// 1. no `0x55AA` in LBA0 → `None`: blank or foreign media, not an
///    error — erasing such a disk is the tool's normal job;
/// 2. plain (non-protective) MBR → [`TableKind::Mbr`] with MBR entries;
///    an extended container entry (`0x05`/`0x0F`/`0x85`) is *not* a
///    listed partition — it points into an EBR chain this slice never
///    walks — so it drops out of the list and earns one explicit
///    "logical partitions are not listed" warning per container;
/// 3. protective MBR + a parseable GPT header → [`TableKind::Gpt`] with
///    the GPT partitions; the protective MBR entry itself is history,
///    not a live partition, and is dropped (extended-container warnings
///    do not apply here: the MBR view is fully replaced);
/// 4. protective MBR with a broken or missing GPT → warning, and the
///    protective MBR's own entries stand in as [`TableKind::Mbr`],
///    under the same extended-container rule as rule 2, after the GPT
///    failure notes.
///
/// `backup_gpt` reflects the last-sector cross-check from
/// [`verified_backup`]; mismatches warn, they never fail the layout.
#[must_use]
pub fn detect_layout(
    lba0: &[u8],
    gpt_header: Option<&[u8]>,
    gpt_entries: Option<&[u8]>,
    last_sector: Option<&[u8]>,
    sector_size: u32,
) -> Option<Layout> {
    let mbr_partitions = parse_mbr(lba0, sector_size)?;
    // Extended containers leave the listed set (rule 2 above): what
    // remains is primaries and the `0xEE` protective marker, plus one
    // caveat per dropped container, in table order.
    let extended_warnings = extended_container_warnings(lba0);
    let mbr_partitions: Vec<TablePartition> = mbr_partitions
        .into_iter()
        .filter(|partition| !matches!(partition.kind.as_str(), "extended" | "linux_extended"))
        .collect();
    if !is_protective_mbr(lba0) {
        return Some(Layout {
            kind: TableKind::Mbr,
            partitions: mbr_partitions,
            backup_gpt: false,
            warnings: extended_warnings,
        });
    }
    // Protective MBR: expectedly GPT territory, with an MBR fallback.
    let mut warnings: Vec<String> = Vec::new();
    match (gpt_header, gpt_entries) {
        (Some(header), Some(entry_bytes)) => match parse_gpt(header, entry_bytes, sector_size) {
            Ok((gpt_partitions, mut gpt_warnings)) => {
                warnings.append(&mut gpt_warnings);
                // The protective MBR entry itself is dropped above: the
                // GPT partitions replace the whole MBR view, and a
                // synthetic "whole disk" entry is not a partition.
                let backup_gpt = verified_backup(last_sector, Some(header), &mut warnings);
                return Some(Layout {
                    kind: TableKind::Gpt,
                    partitions: gpt_partitions,
                    backup_gpt,
                    warnings,
                });
            }
            Err(cause) => warnings.push(format!("gpt unreadable: {cause}")),
        },
        _ => warnings.push("gpt header missing".to_owned()),
    }
    // Broken or absent GPT: the protective MBR's own entries stand in
    // (protective `0xEE` included — it is what the LBA0 bytes say),
    // with the failure recorded first, then the container caveats.
    warnings.extend(extended_warnings);
    Some(Layout {
        kind: TableKind::Mbr,
        partitions: mbr_partitions,
        backup_gpt: false,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Byte builders: every fixture is assembled programmatically so no
    // binary blob is committed and each field shift is self-evident.
    // ------------------------------------------------------------------

    /// EFI System Partition GUID, on-disk mixed-endian form: `data1`
    /// `C12A7328` reads little-endian as `28 73 2A C1`, `data2`
    /// `F81F` as `1F F8`, `data3` `11D2` as `D2 11`, rest verbatim.
    const EFI_TYPE_GUID_RAW: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    /// Linux filesystem GUID, on-disk mixed-endian form.
    const LINUX_TYPE_GUID_RAW: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    /// A distinctive unique-guid so the field mapping is visible in tests.
    const UNIQUE_GUID_RAW: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    /// Fresh LBA0 with the `0x55AA` signature and empty entries.
    fn mbr_lba0() -> [u8; 512] {
        let mut lba0 = [0u8; 512];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        lba0
    }

    /// Stamp one MBR entry (`type`, boot flag, start, sectors) into a slot.
    fn write_mbr_entry(
        lba0: &mut [u8; 512],
        slot: usize,
        boot: u8,
        type_id: u8,
        start: u32,
        sectors: u32,
    ) {
        let base = 446 + slot * 16;
        lba0[base] = boot;
        lba0[base + 4] = type_id;
        lba0[base + 8..base + 12].copy_from_slice(&start.to_le_bytes());
        lba0[base + 12..base + 16].copy_from_slice(&sectors.to_le_bytes());
    }

    /// Minimal GPT header: signature, one partition far away backup LBA
    /// (99), `size_of_entry` 128, and `count` entries.
    fn gpt_header_sector(count: u32) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[0..8].copy_from_slice(GPT_SIGNATURE);
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // rev 1.0
        header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
        header[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
        header[32..40].copy_from_slice(&99u64.to_le_bytes()); // backup lba
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries lba
        header[80..84].copy_from_slice(&count.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        header
    }

    /// Set the header CRC (computed over the first 92 bytes with the CRC
    /// field zeroed, exactly like the parser verifies it).
    fn seal_header(header: &mut [u8; 512]) {
        let mut working = *header;
        working[16..20].copy_from_slice(&[0; 4]);
        let crc = crc32_ieee(&working[..92]);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    /// Header sealed together with the entry-array CRC.
    fn sealed_gpt(count: u32, entries: &[u8]) -> [u8; 512] {
        let mut header = gpt_header_sector(count);
        header[88..92].copy_from_slice(&crc32_ieee(entries).to_le_bytes());
        seal_header(&mut header);
        header
    }

    /// One GPT table entry, 128 bytes all filled (`first == last` keeps
    /// a 1-sector partition).
    fn gpt_entry(
        type_guid: Option<[u8; 16]>,
        unique_guid: Option<[u8; 16]>,
        first: u64,
        last: u64,
        attributes: u64,
        name: Option<&[u16]>,
    ) -> [u8; 128] {
        let mut entry = [0u8; 128];
        if let Some(type_guid) = type_guid {
            entry[0..16].copy_from_slice(&type_guid);
        }
        if let Some(unique_guid) = unique_guid {
            entry[16..32].copy_from_slice(&unique_guid);
        }
        entry[32..40].copy_from_slice(&first.to_le_bytes());
        entry[40..48].copy_from_slice(&last.to_le_bytes());
        entry[48..56].copy_from_slice(&attributes.to_le_bytes());
        if let Some(name) = name {
            for (slot, &unit) in name.iter().enumerate() {
                let at = 56 + slot * 2;
                entry[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        entry
    }

    /// A last sector carrying only the backup-header signature and its
    /// own location (a real backup header has the selfsame layout).
    fn backup_sector(lba: u64) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[0..8].copy_from_slice(GPT_SIGNATURE);
        sector[24..32].copy_from_slice(&lba.to_le_bytes());
        sector
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
    // MBR
    // ------------------------------------------------------------------

    #[test]
    fn mbr_without_signature_is_none_not_an_error() {
        assert_eq!(
            parse_mbr(&[0u8; 512], 512),
            None,
            "all-zero LBA0: blank disk"
        );
        // Even a truncated buffer just reads as "no signature".
        assert_eq!(parse_mbr(&[0x55, 0xAA], 512), None);
    }

    #[test]
    fn parse_mbr_maps_relevant_entry_fields() {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x80, 0x0b, 2048, 1_000_000); // fat32, bootable
        write_mbr_entry(&mut lba0, 1, 0x00, 0x83, 1_002_048, 2_048); // linux
        write_mbr_entry(&mut lba0, 3, 0x00, 0xee, 0, 1); // protective marker

        let partitions = parse_mbr(&lba0, 512).expect("signature present");
        assert_eq!(partitions.len(), 3, "unused slot 2 disappears");
        assert_eq!(partitions[0].index, 1);
        assert!(partitions[0].bootable, "0x80 boot flag");
        assert_eq!(partitions[0].kind, "fat32");
        assert_eq!(partitions[0].start_lba, 2048);
        assert_eq!(partitions[0].sectors, 1_000_000);
        assert_eq!(partitions[0].size_bytes, 512_000_000);
        assert_eq!(partitions[0].name, None);
        assert_eq!(partitions[0].attributes, None);
        assert_eq!(partitions[0].guid, None);
        assert_eq!(partitions[1].kind, "linux");
        assert!(!partitions[1].bootable);
        assert_eq!(
            partitions[2].index, 4,
            "slot position is the index, never renumbered"
        );
        assert_eq!(partitions[2].kind, "gpt_protective");
    }

    #[test]
    fn parse_mbr_skips_unused_and_zero_geometry_slots() {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x00, 0x00, 2048, 8); // type 0: always unused
        write_mbr_entry(&mut lba0, 1, 0x00, 0x83, 0, 0); // zero start + sectors
        write_mbr_entry(&mut lba0, 2, 0x00, 0xef, 4096, 8); // the one kept slot
        let partitions = parse_mbr(&lba0, 512).expect("signature present");
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].index, 3, "index stays the slot number");
        assert_eq!(partitions[0].kind, "efi_system");
    }

    #[test]
    fn mbr_type_slugs_are_pinned() {
        let known = [
            (0x01, "fat12"),
            (0x04, "fat16"),
            (0x06, "fat16"),
            (0x0e, "fat16"),
            (0x0b, "fat32"),
            (0x0c, "fat32"),
            (0x07, "ntfs_exfat"),
            (0x05, "extended"),
            (0x0f, "extended"),
            (0x82, "linux_swap"),
            (0x83, "linux"),
            (0x85, "linux_extended"),
            (0x8e, "linux_lvm"),
            (0xee, "gpt_protective"),
            (0xef, "efi_system"),
            (0xa5, "freebsd"),
            (0xa8, "macos"),
            (0xaf, "hfs"),
            (0xfd, "linux_raid"),
        ];
        for (type_id, slug) in known {
            let mut lba0 = mbr_lba0();
            write_mbr_entry(&mut lba0, 0, 0, type_id, 1, 1);
            let partitions = parse_mbr(&lba0, 512).expect("signature present");
            assert_eq!(partitions[0].kind, slug, "type id 0x{type_id:02x}");
        }
        // Unknown ids stay raw hex instead of getting an invented slug.
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0, 0x42, 1, 1);
        let partitions = parse_mbr(&lba0, 512).expect("signature present");
        assert_eq!(partitions[0].kind, "0x42");
    }

    #[test]
    fn mbr_multiplies_the_largest_legal_geometry_exactly() {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0, 0x07, u32::MAX / 2, u32::MAX);
        let partitions = parse_mbr(&lba0, u32::MAX).expect("signature present");
        let want = u64::from(u32::MAX) * u64::from(u32::MAX); // fits in u64
        assert_eq!(partitions[0].size_bytes, want, "no false saturation");
    }

    #[test]
    fn protective_marker_is_found_and_signature_independent() {
        let mut lba0 = mbr_lba0();
        assert!(!is_protective_mbr(&lba0));
        write_mbr_entry(&mut lba0, 2, 0, 0xEE, 1, 1);
        assert!(is_protective_mbr(&lba0));
        // The predicate judges entries, not the signature (callers check
        // the signature separately through parse_mbr): an entry anywhere
        // in the four slots counts, signature or not.
        assert!(!is_protective_mbr(&[0u8; 526]));
        let mut no_signature = [0u8; 526];
        no_signature[446 + 32 + 4] = 0xEE; // slot 2, type-byte position
        assert!(is_protective_mbr(&no_signature));
    }

    // ------------------------------------------------------------------
    // GPT
    // ------------------------------------------------------------------

    #[test]
    fn gpt_entry_range_reads_the_declared_location() {
        let header = gpt_header_sector(2);
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
        assert_eq!(gpt_entry_range(&gpt_header_sector(1)[..80]), None);

        // A zero stride cannot size a read plan.
        let mut header = gpt_header_sector(1);
        header[84..88].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(gpt_entry_range(&header), None, "no stride, no array");
    }

    #[test]
    fn gpt_entry_range_caps_count_and_entry_size() {
        let mut header = gpt_header_sector(200);
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
        let entry0: [u8; 128] = gpt_entry(
            Some(EFI_TYPE_GUID_RAW),
            Some(UNIQUE_GUID_RAW),
            2048,
            1_050_623,
            0x1,                                // system partition bit
            Some(&[0x0045, 0x0046, 0x0049, 0]), // "EFI", NUL-terminated
        );
        let entry1: [u8; 128] = gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            1_050_624,
            1_052_671,
            0,
            Some(&[0x0052, 0x004F, 0x004F, 0x0054]), // "ROOT"
        );
        let mut entries = entry0.to_vec();
        entries.extend_from_slice(&entry1);

        let header = sealed_gpt(2, &entries);
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
        let entry: [u8; 128] = gpt_entry(
            Some(LINUX_TYPE_GUID_RAW),
            None,
            2048,
            2048,
            0,
            Some(&[0x004C, 0x005F, 0x0007, 0x4E2D, 0, 0x0058]), // "L_\x07中\0X"
        );
        let entries = entry.to_vec();
        let header = sealed_gpt(1, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            partitions[0].name.as_deref(),
            Some("L_??"),
            "padding never renders as `?`s"
        );

        // A name-less entry stays None rather than an empty string.
        let blank: [u8; 128] = gpt_entry(Some(EFI_TYPE_GUID_RAW), None, 2048, 2048, 0, Some(&[0]));
        let entries = blank.to_vec();
        let header = sealed_gpt(1, &entries);
        let (partitions, _warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert_eq!(partitions[0].name, None);
    }

    #[test]
    fn parse_gpt_rejects_headers_that_cannot_be_parsed_at_all() {
        // No signature: a headerless sector is not a GPT header.
        let mut header = gpt_header_sector(1);
        header[0] = b'X';
        let err = parse_gpt(&header, &[], 512).expect_err("signature");
        assert!(err.to_string().contains("signature is missing"), "{err}");

        // `header_size` below the mandatory 92.
        let mut header = gpt_header_sector(1);
        header[12..16].copy_from_slice(&91u32.to_le_bytes());
        let err = parse_gpt(&header, &[], 512).expect_err("header size");
        assert!(err.to_string().contains("header size is nonsense"), "{err}");

        // `size_of_entry` below the mandatory 128.
        let mut header = gpt_header_sector(1);
        header[84..88].copy_from_slice(&64u32.to_le_bytes());
        let err = parse_gpt(&header, &[], 512).expect_err("entry size");
        assert!(err.to_string().contains("entry size is nonsense"), "{err}");

        // Header too small to even read the entry-array fields.
        let short_header = &gpt_header_sector(1)[..24];
        let err = parse_gpt(short_header, &[], 512).expect_err("short header");
        assert!(
            err.to_string().contains("does not declare an entry count"),
            "{err}"
        );
    }

    #[test]
    fn parse_gpt_warns_on_header_crc_mismatch_but_parses_on() {
        let entry: [u8; 128] = gpt_entry(Some(EFI_TYPE_GUID_RAW), None, 2048, 1_050_623, 0, None);
        let entries = entry.to_vec();
        let mut header = sealed_gpt(1, &entries);
        header[17] ^= 0x40; // rot one bit inside the stored header CRC
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("crc rot is soft");
        assert_eq!(warnings, vec!["gpt header crc mismatch"]);
        assert_eq!(partitions.len(), 1, "the entries themselves are intact");
    }

    #[test]
    fn parse_gpt_warns_on_entry_array_truncation() {
        let entries_full: [u8; 256] = [
            gpt_entry(Some(EFI_TYPE_GUID_RAW), None, 2048, 2048, 0, None),
            gpt_entry(Some(LINUX_TYPE_GUID_RAW), None, 4096, 4096, 0, None),
        ]
        .concat()
        .try_into()
        .expect("256-byte array");
        let mut header = gpt_header_sector(2);
        header[88..92].copy_from_slice(&crc32_ieee(&entries_full).to_le_bytes());
        seal_header(&mut header);

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
            let entry = gpt_entry(Some(EFI_TYPE_GUID_RAW), None, first, first + 1, 0, None);
            entries.extend_from_slice(&entry);
        }
        let header = sealed_gpt(200, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("declares fine");
        assert_eq!(warnings, vec!["gpt entry array capped at 128 entries"]);
        assert_eq!(partitions.len(), 128);
        assert_eq!(partitions.last().expect("at least one").index, 128);
    }

    #[test]
    fn parse_gpt_skips_entries_with_reversed_bounds() {
        let entry: [u8; 128] = gpt_entry(Some(LINUX_TYPE_GUID_RAW), None, 4096, 2048, 0, None);
        let entries = entry.to_vec();
        let header = sealed_gpt(1, &entries);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("sealed header");
        assert_eq!(warnings, vec!["gpt entry 1 has reversed bounds"]);
        assert!(partitions.is_empty());
    }

    #[test]
    fn gpt_inclusive_span_and_saturation() {
        // first == 0, last == u64::MAX: the +1 must saturate, not wrap
        // to 0, and the byte size must saturate with it.
        let entry: [u8; 128] = gpt_entry(Some(LINUX_TYPE_GUID_RAW), None, 0, u64::MAX, 0, None);
        let entries = entry.to_vec();
        let header = sealed_gpt(1, &entries);
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
        let mut header = gpt_header_sector(1);
        header[84..88].copy_from_slice(&256u32.to_le_bytes());
        header[88..92].copy_from_slice(&crc32_ieee(&entries).to_le_bytes());
        seal_header(&mut header);
        let (partitions, warnings) = parse_gpt(&header, &entries, 512).expect("soe 256");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(partitions[0].kind, "efi_system");
        assert_eq!(partitions[0].sectors, 2048);
        assert_eq!(partitions[0].name.as_deref(), Some("A"));
    }

    // ------------------------------------------------------------------
    // detect_layout: the four documented rules
    // ------------------------------------------------------------------

    fn protective_lba0() -> [u8; 512] {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x00, 0xEE, 1, 1);
        lba0
    }

    fn one_gpt_entry() -> [u8; 128] {
        gpt_entry(Some(EFI_TYPE_GUID_RAW), None, 2048, 2048, 0, None)
    }

    #[test]
    fn detect_layout_plain_mbr_and_blank_disk() {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x80, 0x0b, 2048, 1_000);
        let layout = detect_layout(&lba0, None, None, None, 512).expect("signature rules the MBR");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert!(!layout.backup_gpt);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "fat32");
        assert!(
            layout
                .warnings
                .iter()
                .all(|warning| !warning.contains("extended partition")),
            "a plain MBR carries no container caveat: {:?}",
            layout.warnings
        );

        // No 0x55AA anywhere: the layout is None, not an error.
        assert_eq!(detect_layout(&[0u8; 512], None, None, None, 512), None);
    }

    #[test]
    fn extended_container_warns_and_yields_only_primaries() {
        // One extended container plus one real primary: the container
        // drops out of the listed set (it points into an unwalked EBR
        // chain), the primary stays, and the omission is stated.
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x00, 0x0f, 2048, 1_000);
        write_mbr_entry(&mut lba0, 1, 0x80, 0x83, 1_002_048, 500);
        let layout = detect_layout(&lba0, None, None, None, 512).expect("plain MBR");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert_eq!(
            layout.partitions.len(),
            1,
            "the extended container is not part of the inventory"
        );
        assert_eq!(layout.partitions[0].index, 2);
        assert_eq!(layout.partitions[0].kind, "linux");
        assert!(layout.partitions[0].bootable);
        assert_eq!(
            layout.warnings,
            vec!["extended partition (type 0x0f): logical partitions are not listed"],
        );
    }

    #[test]
    fn extended_containers_warn_once_each_in_table_order() {
        // Two containers of two different spellings (0x05 generic, 0x85
        // Linux-extended) around one primary: one warning per container
        // entry, emitted in slot order, never merged.
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x00, 0x05, 2048, 1_000);
        write_mbr_entry(&mut lba0, 1, 0x00, 0x83, 3_048, 500);
        write_mbr_entry(&mut lba0, 2, 0x00, 0x85, 5_048, 1_000);
        let layout = detect_layout(&lba0, None, None, None, 512).expect("plain MBR");
        assert_eq!(
            layout.warnings,
            vec![
                "extended partition (type 0x05): logical partitions are not listed",
                "extended partition (type 0x85): logical partitions are not listed",
            ],
        );
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "linux");
    }

    #[test]
    fn extended_container_warns_in_the_protective_fallback_too() {
        // Protective MBR with missing GPT bytes (warned), and an
        // extended container in the surviving MBR view: the fallback
        // keeps the `0xEE` marker entry but still needs the container
        // caveat, deterministically after the GPT failure note.
        let mut lba0 = protective_lba0();
        write_mbr_entry(&mut lba0, 1, 0x00, 0x0f, 2048, 1_000);
        let layout = detect_layout(&lba0, None, None, None, 512).expect("fallback parses");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert_eq!(layout.partitions.len(), 1, "only the 0xEE marker is listed");
        assert_eq!(layout.partitions[0].kind, "gpt_protective");
        assert_eq!(
            layout.warnings,
            vec![
                "gpt header missing",
                "extended partition (type 0x0f): logical partitions are not listed",
            ],
        );
    }

    #[test]
    fn detect_layout_gpt_path_ignores_the_protective_entry() {
        let entries = one_gpt_entry().to_vec();
        let header = sealed_gpt(1, &entries);
        let last = backup_sector(99); // matches the header's alternate LBA
        let layout = detect_layout(
            &protective_lba0(),
            Some(&header),
            Some(&entries),
            Some(&last),
            512,
        )
        .expect("protective MBR plus GPT");
        assert_eq!(layout.kind, TableKind::Gpt);
        assert!(layout.backup_gpt, "backup header cross-checks");
        assert!(layout.warnings.is_empty());
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "efi_system");
    }

    #[test]
    fn detect_layout_backup_mismatch_warns_but_holds_on() {
        let entries = one_gpt_entry().to_vec();
        let header = sealed_gpt(1, &entries);
        let last = backup_sector(100); // header says the backup lives at 99
        let layout = detect_layout(
            &protective_lba0(),
            Some(&header),
            Some(&entries),
            Some(&last),
            512,
        )
        .expect("protective MBR plus GPT");
        assert_eq!(layout.kind, TableKind::Gpt);
        assert!(!layout.backup_gpt);
        assert_eq!(layout.warnings, vec!["gpt backup header mismatch"]);
    }

    #[test]
    fn detect_layout_broken_gpt_falls_back_to_protective_mbr() {
        let mut header = sealed_gpt(1, &one_gpt_entry());
        header[0] = b'X'; // signature rots: parse_gpt hard-errors
        let layout = detect_layout(
            &protective_lba0(),
            Some(&header),
            Some(&[0u8; 128]),
            None,
            512,
        )
        .expect("still a parseable protective MBR");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert!(!layout.backup_gpt);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "gpt_protective");
        assert!(
            layout.warnings
                == vec!["gpt unreadable: invalid input: gpt header signature is missing"],
            "{:?}",
            layout.warnings
        );
    }

    #[test]
    fn detect_layout_protective_without_gpt_bytes_warns_and_falls_back() {
        let layout = detect_layout(&protective_lba0(), None, None, None, 512)
            .expect("protective MBR parses on its own");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert_eq!(layout.warnings, vec!["gpt header missing"]);
        assert_eq!(layout.partitions.len(), 1);
    }
}
