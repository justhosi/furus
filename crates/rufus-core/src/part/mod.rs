//! MBR and GPT partition tables — shared types and read/write assembly.
//!
//! The table formats live in [`gpt`] and [`mbr`]; this module holds the
//! shared types, the byte-reading helpers, and [`detect_layout`], the
//! read-side assembly the preview and the safety verdict consume. The
//! S08 writers live next to their parsers (`mbr::write_mbr` builds
//! sector 0, `gpt::write_gpt` builds the protective MBR plus both GPT
//! copies), and [`plan`] turns the PLAN §9-S08 layouts into
//! [`plan::TablePlan`]s rendered to absolute sector writes.
//!
//! **The writers are `pub(in crate::part)` on purpose.** `plan::render`
//! is the only supported way to turn a layout into bytes: it is where a
//! caller's spans are bounded against the table's own usable range,
//! which the writers deliberately do not re-check. The S17 pipeline must
//! consume [`plan::Rendered`] (a list of absolute [`plan::SectorWrite`]s)
//! rather than reach for `write_gpt`/`write_mbr`. They were public API
//! until this slice — `rufus_core::part::gpt::write_gpt` was reachable
//! from every dependent crate, though nothing outside `rufus-core`
//! called it — and narrowing them to `crate::part` is what stops a later
//! in-crate `pipeline` module from taking the shortcut: it would not
//! compile.
//!
//! S04 trusts the udev record's single `ID_PART_TABLE_TYPE` label; the
//! read side re-derives the *authoritative* table from the device bytes
//! so the preview and the safety verdict describe what really rules the
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
use crate::part::gpt::{parse_gpt, verified_backup};
use crate::part::mbr::{extended_container_warnings, parse_mbr};

pub mod gpt;
pub mod mbr;
pub mod plan;

/// The only two bytes that mark a parsed master boot record; also used
/// by [`crate::fsprobe`] as the FAT boot-sector guard.
pub const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

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
    /// GPT entry name, sanitised through
    /// [`device_text`](crate::text::device_text); `None` for MBR
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
pub(crate) fn sectors_to_bytes(sectors: u64, sector_size: u32) -> u64 {
    sectors.saturating_mul(u64::from(sector_size))
}

/// Write `bytes` at `at`, byte-exactly.
///
/// The write-side counterpart of the readers below: the write side of
/// this tree (S08) addresses offsets only in buffers it built itself a
/// line earlier (a 512-byte MBR, a ≥ 512-byte GPT header, a fixed
/// 128-byte entry), so the error arm is a guard against future edits,
/// not a reachable failure. Routed through `get_mut` the write stays
/// total — no indexing, no panic — exactly like every reader here.
pub(crate) fn put(sink: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    let total = sink.len();
    let end = at
        .checked_add(bytes.len())
        .filter(|&end| end <= total)
        .ok_or_else(|| {
            let len = bytes.len();
            CoreError::invalid(format!(
                "field at offset {at} ({len} bytes) does not fit a buffer of {total} bytes"
            ))
        })?;
    let Some(window) = sink.get_mut(at..end) else {
        // Unreachable after the `end <= total` filter above; the early
        // return keeps the write total like every reader in the tree.
        return Err(CoreError::invalid("write window vanished mid-slice"));
    };
    window.copy_from_slice(bytes);
    Ok(())
}

/// Read one little-endian `u16` at `at` (`None` when the buffer is short
/// or the offset overflows; never indexes in a way that can panic).
pub(crate) fn u16_le(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    let unit: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(unit))
}

/// Read one little-endian `u32` at `at`.
pub(crate) fn u32_le(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at.checked_add(4)?)?;
    let unit: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(unit))
}

/// Read one little-endian `u64` at `at`.
pub(crate) fn u64_le(buf: &[u8], at: usize) -> Option<u64> {
    let bytes = buf.get(at..at.checked_add(8)?)?;
    let unit: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(unit))
}

/// Copy 16 raw GUID bytes out of `buf` at `at`.
pub(crate) fn guid_bytes(buf: &[u8], at: usize) -> Option<[u8; 16]> {
    let bytes = buf.get(at..at.checked_add(16)?)?;
    bytes.try_into().ok()
}

/// Does `buf` hold `signature` at offset 0? Shared shape for the GPT
/// header, backup-header and MBR-signature checks.
pub(crate) fn starts_with_signature(buf: &[u8], signature: &[u8]) -> bool {
    buf.get(..signature.len()) == Some(signature)
}

/// Whether any of the four MBR entries claims the protective `0xEE`
/// type — the marker a GPT-formatted disk leaves in LBA0 so legacy
/// tooling sees one inert "whole disk" partition. Only meaningful
/// together with a parsed MBR; callers such as [`detect_layout`] check
/// the signature first, the predicate deliberately does not ask for it.
#[must_use]
pub fn is_protective_mbr(lba0: &[u8]) -> bool {
    let area = mbr::MBR_ENTRY_AREA;
    let size = mbr::MBR_ENTRY_SIZE;
    (0..4).any(|slot| lba0.get(area + slot * size + 4) == Some(&0xEE))
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
pub(crate) mod test_support {
    use uuid::Uuid;

    use crate::part::MBR_SIGNATURE;
    use crate::part::gpt::crc32_ieee;
    use crate::part::mbr::MBR_ENTRY_AREA;

    /// EFI System Partition GUID, on-disk mixed-endian form: `data1`
    /// `C12A7328` reads little-endian as `28 73 2A C1`, `data2`
    /// `F81F` as `1F F8`, `data3` `11D2` as `D2 11`, rest verbatim.
    pub(crate) const EFI_TYPE_GUID_RAW: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];
    /// Linux filesystem GUID, on-disk mixed-endian form.
    pub(crate) const LINUX_TYPE_GUID_RAW: [u8; 16] = [
        0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D,
        0xE4,
    ];
    /// A distinctive unique-guid so the field mapping is visible in tests.
    pub(crate) const UNIQUE_GUID_RAW: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    /// On-disk (mixed-endian) GUID bytes for one `uuid::Uuid`.
    ///
    /// `Uuid::as_bytes()` laid out big-endian is what the canonical
    /// `xxxxxxxx-…` string prints ("data1 data2 data3 data4"); GPT
    /// instead stores the first three groups little-endian and the last
    /// eight bytes verbatim — the same byte-order rule
    /// [`guid_to_string`](crate::part::gpt::guid_to_string) undoes, so
    /// the round trip lands exactly on the UUID's own string.
    pub(crate) fn uuid_to_gpt_bytes(id: Uuid) -> [u8; 16] {
        let canonical = *id.as_bytes();
        let data1 = u32::from_be_bytes(canonical[0..4].try_into().expect("four data1 bytes"));
        let data2 = u16::from_be_bytes(canonical[4..6].try_into().expect("two data2 bytes"));
        let data3 = u16::from_be_bytes(canonical[6..8].try_into().expect("two data3 bytes"));
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&data1.to_le_bytes());
        raw[4..6].copy_from_slice(&data2.to_le_bytes());
        raw[6..8].copy_from_slice(&data3.to_le_bytes());
        raw[8..16].copy_from_slice(&canonical[8..16]);
        raw
    }

    /// Fresh LBA0 with the `0x55AA` signature and empty entries.
    pub(crate) fn mbr_lba0() -> [u8; 512] {
        let mut lba0 = [0u8; 512];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        lba0
    }

    /// Stamp one MBR entry (`type`, boot flag, start, sectors) into a slot.
    pub(crate) fn write_mbr_entry(
        lba0: &mut [u8; 512],
        slot: usize,
        boot: u8,
        type_id: u8,
        start: u32,
        sectors: u32,
    ) {
        let base = MBR_ENTRY_AREA + slot * 16;
        lba0[base] = boot;
        lba0[base + 4] = type_id;
        lba0[base + 8..base + 12].copy_from_slice(&start.to_le_bytes());
        lba0[base + 12..base + 16].copy_from_slice(&sectors.to_le_bytes());
    }

    /// A protective LBA0: one `0xEE` marker entry in slot 0.
    pub(crate) fn protective_lba0() -> [u8; 512] {
        let mut lba0 = mbr_lba0();
        write_mbr_entry(&mut lba0, 0, 0x00, 0xEE, 1, 1);
        lba0
    }

    /// Minimal GPT header: signature, one partition far away backup LBA
    /// (99), `size_of_entry` 128, and `count` entries.
    pub(crate) fn gpt_header_sector(count: u32) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[0..8].copy_from_slice(crate::part::gpt::GPT_SIGNATURE);
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
    pub(crate) fn seal_header(header: &mut [u8; 512]) {
        let mut working = *header;
        working[16..20].copy_from_slice(&[0; 4]);
        let crc = crc32_ieee(&working[..92]);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    /// Header sealed together with the entry-array CRC.
    pub(crate) fn sealed_gpt(count: u32, entries: &[u8]) -> [u8; 512] {
        let mut header = gpt_header_sector(count);
        header[88..92].copy_from_slice(&crc32_ieee(entries).to_le_bytes());
        seal_header(&mut header);
        header
    }

    /// One GPT table entry, 128 bytes all filled (`first == last` keeps
    /// a 1-sector partition).
    pub(crate) fn gpt_entry(
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
    pub(crate) fn backup_sector(lba: u64) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[0..8].copy_from_slice(crate::part::gpt::GPT_SIGNATURE);
        sector[24..32].copy_from_slice(&lba.to_le_bytes());
        sector
    }

    /// The one-entry fixture `detect_layout`'s GPT tests share.
    pub(crate) fn one_gpt_entry() -> [u8; 128] {
        gpt_entry(Some(EFI_TYPE_GUID_RAW), None, 2048, 2048, 0, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::test_support::{
        backup_sector, mbr_lba0, one_gpt_entry, protective_lba0, sealed_gpt, write_mbr_entry,
    };

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
    // detect_layout: the four documented rules
    // ------------------------------------------------------------------

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
