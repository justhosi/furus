//! The MBR side of the partition module: the entry decoder
//! ([`parse_mbr`]) moved from the former monolithic `partition.rs`, plus
//! the S08 writer (`write_mbr`) that assembles sector 0.
//!
//! Nothing here opens a device: the caller hands in LBA0 bytes it read
//! and takes the sector 0 the writer builds. The module-wide rules the
//! tests pin — a missing `0x55AA` is not an error, 1-based slot
//! semantics, saturation instead of wrapping — live on [`crate::part`].

use crate::error::CoreError;
use crate::error::Result;
use crate::part::MBR_SIGNATURE;
use crate::part::TablePartition;
use crate::part::put;
use crate::part::sectors_to_bytes;
use crate::part::u32_le;

/// Where the four MBR partition entries start (the rest of LBA0 is boot
/// code, CHS plumbing, and the signature at 510..512).
///
/// `pub(crate)` *visibility-only*: [`crate::part::is_protective_mbr`]
/// scans the same slots and both must keep sharing one constant, while
/// the offsets themselves stay an implementation detail of this module.
pub(crate) const MBR_ENTRY_AREA: usize = 446;
/// One MBR entry is exactly 16 bytes, four entries back-to-back.
pub(crate) const MBR_ENTRY_SIZE: usize = 16;
/// Offset of the 4 disk-signature bytes within sector 0. They sit in
/// the boot area's tail, so `write_mbr` stamps them *over* whatever
/// `boot_area` holds at that spot — the parameter wins.
const DISK_SIGNATURE_OFFSET: usize = 440;

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
/// absent — a blank or foreign disk, not an error (see [`crate::part`]).
/// One 16-byte entry reads: byte 0 the boot flag (`0x80`
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

/// One ASCII warning per extended container entry (`0x05`, `0x0F`,
/// `0x85`), in table order.
///
/// An extended container is not a file-carrying volume: its entry points
/// at an EBR chain of logical partitions, and S05 deliberately does not
/// walk that chain. Listing the container alone would read like a
/// complete inventory of the disk, so the assembled
/// [`Layout`](crate::part::Layout) drops the container entries (see
/// [`crate::part::detect_layout`]) and every dropped one gets this
/// explicit caveat instead. The message is fixed ASCII (`0x` plus two
/// lowercase hex digits from the raw type byte) — no untrusted text is
/// interpolated.
pub(crate) fn extended_container_warnings(lba0: &[u8]) -> Vec<String> {
    (0..4)
        .filter_map(|slot| mbr_slot(lba0, slot))
        .filter(|(type_id, ..)| matches!(type_id, 0x05 | 0x0f | 0x85))
        .map(|(type_id, ..)| {
            format!("extended partition (type 0x{type_id:02x}): logical partitions are not listed")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Write side (S08)
// ---------------------------------------------------------------------------

/// One MBR primary entry, the input shape of `write_mbr`.
///
/// `type_id` is the raw partition-type byte (`0x0b` FAT32, `0x83`
/// Linux, `0xee` protective marker — the reader's slug table lives in
/// [`mbr_kind`]); `start_lba` and `sectors` are taken verbatim as the
/// little-endian 32-bit entry fields; `bootable` drives the `0x80` boot
/// flag. Up to four entries stamp slots 0..4 of sector 0 in the order
/// given; further entries are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    /// Raw MBR partition type byte.
    pub type_id: u8,
    /// First sector of the partition, stored little-endian as-is.
    pub start_lba: u32,
    /// Sector count, stored little-endian as-is.
    pub sectors: u32,
    /// Boot flag: `0x80` in the entry when true.
    pub bootable: bool,
}

/// CHS geometry the writer assumes for its LBA-compatible tuples:
/// 255 heads and 63 sectors per track — the canonical "large disk"
/// geometry every modern tool uses, so the CHS fields stay consistent
/// with the LBA fields for LBAs that fit the 10-bit cylinder field.
const CHS_HEADS: u32 = 255;
const CHS_SECTORS_PER_TRACK: u32 = 63;
/// LBAs at or above this ceiling cannot be expressed with 10 cylinders
/// bits (1024 × 255 × 63); their CHS fields saturate instead.
const CHS_MAX_LBA: u32 = 1024 * CHS_HEADS * CHS_SECTORS_PER_TRACK;

/// LBA-compatible CHS triple (head, sector, cylinder) for `lba`, in the
/// on-disk 3-byte MBR encoding: byte 0 the head, byte 1 the 1-based
/// sector (low 6 bits) plus the two high cylinder bits as bits 6..8,
/// byte 2 the low 8 cylinder bits. LBAs past [`CHS_MAX_LBA`], and thus
/// partition ends past it, use the standard saturate tuple
/// `FE FF FF` (= cylinder 1023, head 254, sector 63) — the fields stay
/// display-only here anyway, because the real geometry lives in the
/// little-endian LBA fields next to them.
fn chs_tuple(lba: u32) -> [u8; 3] {
    if lba >= CHS_MAX_LBA {
        // Cylinder 1023 / head 254 / sector 63: "beyond CHS reach".
        return [0xFE, 0xFF, 0xFF];
    }
    let cylinder = lba / (CHS_HEADS * CHS_SECTORS_PER_TRACK);
    let head = (lba / CHS_SECTORS_PER_TRACK) % CHS_HEADS;
    let sector = (lba % CHS_SECTORS_PER_TRACK) + 1; // 1-based, 1..=63
    let cylinder_low = (cylinder & 0xFF) as u8;
    let cylinder_high = ((cylinder >> 8) & 0x03) as u8;
    [
        head as u8,
        (sector as u8) | (cylinder_high << 6),
        cylinder_low,
    ]
}

/// Build sector 0 of a formatted disk from the four 16-byte primary
/// entries.
///
/// Rules the writer enforces (mirrored by the round-trip tests):
///
/// * `boot_area` is copied byte-for-byte across offsets 0..446 (an
///   existing bootloader or all zeros); the four bytes at
///   [`DISK_SIGNATURE_OFFSET`] are then stamped from `disk_signature` —
///   the explicit signature wins over the boot area's tail;
/// * the CHS fields of every entry come from [`chs_tuple`] under the
///   255/63 geometry — computed for LBAs inside the cylinder range and
///   saturated `FE FF FF` outside, so the tuple never contradicts the
///   LBA fields;
/// * the boot flag is `0x80` on bootable entries and `0x00` elsewhere;
///   type byte and start/sector count follow little-endian, exactly the
///   shape [`parse_mbr`] reads back;
/// * unused slots stay zeroed (a fresh `[0u8; 512]` base, no leakage
///   from other diagrams);
/// * the trailing `0x55AA` signature is always set;
/// * more than four partitions is an error — sector 0 has four primary
///   slots and silently dropping entries would produce a table that
///   disagrees with the caller's plan.
///
/// **Not public, and not a validation boundary.** Entries are taken as
/// given: this writer has no opinion on whether the disk is big enough
/// or whether the spans fit the table's usable range. `plan::render` is
/// the only supported producer of table bytes and does that bounding
/// once; the S17 pipeline consumes `plan::Rendered`, and
/// `pub(in crate::part)` keeps the shortcut out of reach elsewhere.
pub(in crate::part) fn write_mbr(
    boot_area: &[u8; 446],
    disk_signature: [u8; 4],
    partitions: &[MbrPartition],
) -> Result<[u8; 512]> {
    let count = partitions.len();
    if count > 4 {
        return Err(CoreError::invalid(format!(
            "mbr holds at most 4 primary partitions, got {count}"
        )));
    }

    let mut sector = [0u8; 512];
    let Some(sink) = sector.get_mut(..MBR_ENTRY_AREA) else {
        return Err(CoreError::invalid(
            "mbr sector 0 does not hold the 446-byte boot area",
        ));
    };
    sink.copy_from_slice(boot_area);
    put(&mut sector, DISK_SIGNATURE_OFFSET, &disk_signature)?;

    // The 64-byte entry window, individually writable per field like
    // every reader above is individually readable.
    let Some(entry_area) = sector.get_mut(MBR_ENTRY_AREA..MBR_ENTRY_AREA + 4 * MBR_ENTRY_SIZE)
    else {
        return Err(CoreError::invalid(
            "mbr sector 0 does not hold the four entry slots",
        ));
    };
    for (slot, partition) in partitions.iter().enumerate() {
        let base = slot * MBR_ENTRY_SIZE;
        // The last sector the entry describes; a zero-sector entry
        // degenerates to its start LBA. Saturating arithmetic keeps the
        // tuple total even when `start + sectors` would wrap.
        let end_lba = match partition.sectors.checked_sub(1) {
            Some(offset) => partition.start_lba.saturating_add(offset),
            None => partition.start_lba,
        };
        let boot_flag: [u8; 1] = [if partition.bootable { 0x80 } else { 0x00 }];
        put(entry_area, base, &boot_flag)?;
        put(entry_area, base + 1, &chs_tuple(partition.start_lba))?;
        put(entry_area, base + 4, &[partition.type_id])?;
        put(entry_area, base + 5, &chs_tuple(end_lba))?;
        put(entry_area, base + 8, &partition.start_lba.to_le_bytes())?;
        put(entry_area, base + 12, &partition.sectors.to_le_bytes())?;
    }

    put(&mut sector, 510, &MBR_SIGNATURE)?;
    Ok(sector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::test_support::{mbr_lba0, write_mbr_entry};

    // ------------------------------------------------------------------
    // MBR parsing (moved with the code from the former partition.rs)
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

    // ------------------------------------------------------------------
    // MBR writing (S08)
    // ------------------------------------------------------------------

    /// Blank boot area, no disk signature — the shape most new MBRs
    /// start from.
    fn blank_boot_area() -> [u8; 446] {
        [0u8; 446]
    }

    #[test]
    fn write_mbr_round_trips_through_parse_mbr() {
        let partitions = [
            MbrPartition {
                type_id: 0x0b,
                start_lba: 2048,
                sectors: 1_000_000,
                bootable: true,
            },
            MbrPartition {
                type_id: 0x83,
                start_lba: 1_002_048,
                sectors: 2_048,
                bootable: false,
            },
            MbrPartition {
                type_id: 0xef,
                start_lba: 1_004_096,
                sectors: 8192,
                bootable: false,
            },
        ];
        let sector = write_mbr(&blank_boot_area(), [0xDE, 0xAD, 0xBE, 0xEF], &partitions)
            .expect("three primaries fit");
        assert_eq!(&sector[510..512], &MBR_SIGNATURE[..], "trailing 0x55AA");
        assert_eq!(
            &sector[440..444],
            &[0xDE, 0xAD, 0xBE, 0xEF],
            "the disk signature lands inside the boot area's tail"
        );
        // The unused fourth slot stays zero.
        assert!(
            sector[446 + 3 * 16..510].iter().all(|&byte| byte == 0),
            "unused slot and its geometry are zero, not stale data"
        );

        let parsed = parse_mbr(&sector, 512).expect("signature present");
        assert_eq!(parsed.len(), 3, "the empty slot disappears again");
        assert_eq!(parsed[0].kind, "fat32");
        assert!(parsed[0].bootable, "bootable entries carry the 0x80 flag");
        assert_eq!(parsed[0].start_lba, 2048);
        assert_eq!(parsed[0].sectors, 1_000_000);
        assert_eq!(parsed[0].size_bytes, 512_000_000);
        assert_eq!(parsed[0].name, None);
        assert_eq!(parsed[0].attributes, None);
        assert_eq!(parsed[1].kind, "linux");
        assert!(!parsed[1].bootable);
        assert_eq!(parsed[1].start_lba, 1_002_048);
        assert_eq!(parsed[1].sectors, 2_048);
        assert_eq!(parsed[2].kind, "efi_system");
        assert_eq!(parsed[2].start_lba, 1_004_096);
        assert_eq!(parsed[2].sectors, 8192);
    }

    #[test]
    fn write_mbr_chs_is_computed_low_and_saturates_at_the_ceiling() {
        // 63 sectors/track, 255 heads: LBA 2048 = cylinder 0, head 32,
        // sector 33. The partition ends at LBA 4095 = head 65, sector 1.
        let low = write_mbr(
            &blank_boot_area(),
            [0u8; 4],
            &[MbrPartition {
                type_id: 0x83,
                start_lba: 2048,
                sectors: 2048,
                bootable: false,
            }],
        )
        .expect("one partition");
        let entry = &low[446..462];
        assert_eq!(
            &entry[1..4],
            &[0x20, 0x21, 0x00],
            "head 32, sector 33 with cylinder 0 in the high bits"
        );
        assert_eq!(
            &entry[5..8],
            &[65, 0x01, 0x00],
            "the end LBA 4095 maps the same way"
        );

        // At or above 1024 cylinders × 255 heads × 63 sectors the CHS
        // fields cannot keep up, so both tuples take the standard
        // saturate shape (1023 / 254 / 63 encoded as FE FF FF).
        let ceiling = 1024 * 255 * 63;
        let high = write_mbr(
            &blank_boot_area(),
            [0u8; 4],
            &[MbrPartition {
                type_id: 0x83,
                start_lba: ceiling,
                sectors: 2,
                bootable: false,
            }],
        )
        .expect("one partition");
        let entry = &high[446..462];
        assert_eq!(&entry[1..4], &[0xFE, 0xFF, 0xFF], "start tuple saturates");
        assert_eq!(&entry[5..8], &[0xFE, 0xFF, 0xFF], "end tuple saturates too");

        // The LBA fields stay exact regardless of the CHS saturation.
        assert_eq!(
            u32_le(entry, 8),
            Some(ceiling),
            "the entry's LBA start field carries the real value"
        );
    }

    #[test]
    fn write_mbr_preserves_the_boot_area_and_stamps_the_disk_signature() {
        // A realistic stub: boot jump bytes plus the disk signature in
        // the boot area's tail, exactly where the writer expects it.
        let mut boot_area = [0xAAu8; 446];
        boot_area[0] = 0xEB; // short jump
        boot_area[1] = 0x3C;
        boot_area[2] = 0x90; // NOP
        boot_area[440..444].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let sector = write_mbr(&boot_area, [0xDE, 0xAD, 0xBE, 0xEF], &[])
            .expect("an empty table is a valid fresh MBR");
        assert_eq!(
            &sector[..446],
            &boot_area[..],
            "the boot area survives byte-for-byte, signature included"
        );

        // Where the two disagree, the explicit signature wins.
        let sector = write_mbr(&blank_boot_area(), [0xC0, 0xFF, 0xEE, 0x42], &[])
            .expect("an empty table is a valid fresh MBR");
        assert_eq!(
            &sector[440..444],
            &[0xC0, 0xFF, 0xEE, 0x42],
            "the disk signature is stamped over the blank boot area's tail"
        );
        assert!(
            sector[..440].iter().all(|&byte| byte == 0),
            "a blank boot area really is blank"
        );
    }

    #[test]
    fn write_mbr_refuses_more_than_four_partitions() {
        let five: Vec<MbrPartition> = (0..5u32)
            .map(|slot| MbrPartition {
                type_id: 0x83,
                start_lba: 2048 + slot * 2048,
                sectors: 2048,
                bootable: false,
            })
            .collect();
        let error = write_mbr(&blank_boot_area(), [0u8; 4], &five)
            .expect_err("sector 0 has only four primary slots");
        let text = error.to_string();
        assert!(text.contains("at most 4"), "{text}");
        assert!(text.contains("got 5"), "{text}");

        // Four primaries go through and read back as four entries.
        let sector =
            write_mbr(&blank_boot_area(), [0u8; 4], &five[..4]).expect("four primaries fit");
        let parsed = parse_mbr(&sector, 512).expect("signature present");
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[3].index, 4);
        assert_eq!(parsed[3].start_lba, 2048 + 3 * 2048);
    }
}
