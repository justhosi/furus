//! The FAT32 on-disk structure images (S09 part A): the boot sector
//! (with its BPB), the FSInfo structure and the backup copies.
//!
//! All three builders return plain `[u8; N]` images — no I/O — so the
//! tests can pin every offset, and [`crate::fs::fat32::format`] writes
//! them at sector-aligned [`Volume`](crate::fs::Volume) offsets. The
//! boot sector stays 512 bytes for *any* sector size: the FAT32 EBPB
//! layout supersedes the FAT12/16-era assumption that the boot sector
//! spans a whole sector, and 4Kn volumes keep the 512-byte structure
//! at byte 0 of their larger physical sector and leave the rest
//! untouched (every parser that matters — DOS, Windows, UEFI,
//! fsck.fat — reads the BPB out of the first 512 bytes).
//!
//! The label field is this module's single implementation and the
//! format's root-directory entry reuses it ([`label_field`]): one
//! encoding, one validation, no second one to drift against. The rule
//! mirrors the Rufus behaviour the whole write side keeps: uppercase
//! ASCII in the 11-byte OEM label field, Windows-forbidden characters
//! refused rather than silently bent, no cropping — length trimming is
//! the file API's `set_label` business (S09 part B), not the byte
//! builder's.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::geometry::BACKUP_BOOT_SECTOR;
use crate::fs::fat32::geometry::FSINFO_SECTOR;
use crate::fs::fat32::geometry::Geometry;
use crate::fs::fat32::geometry::MAX_CLUSTERS;
use crate::fs::fat32::geometry::MIN_CLUSTERS;
use crate::fs::fat32::geometry::ROOT_CLUSTER;
use crate::fs::fat32::put_bytes;
use crate::fs::fat32::put_u16;
use crate::fs::fat32::put_u32;

/// The 512-byte size of the boot sector (and of FSInfo), independent
/// of the volume's sector size.
pub const BOOT_SECTOR_BYTES: usize = 512;

/// Start of the boot code area, right after the `"FAT32   "` type
/// string: offsets `90..510` are the 420 bytes a boot loader would
/// occupy. The formatter zero-fills them (them not shipping a boot
/// loader) and the S19 boot stage fills the bytes it needs inside
/// this very window — published with the builder so both stages
/// address the same bytes.
pub const BOOT_CODE_AREA: std::ops::Range<usize> = 90..510;
/// The boot code area's length ([`BOOT_CODE_AREA`]).
pub const BOOT_CODE_AREA_BYTES: usize = 420;

/// CHS plumbing every BPB carries and no modern reader uses: 63
/// sectors per track and 255 heads — the canonical "large disk"
/// assumptions the FAT spec shows in its example (Rufus writes the
/// same), so old CHS-based tools display something plausible.
const SECTORS_PER_TRACK: u16 = 63;
const HEADS: u16 = 255;

/// The fixed 0x29 boot signature: an extended-BPB boot sector that
/// carries the volume id, label and type — not the 0x28 short form.
const EXTENDED_BOOT_SIGNATURE: u8 = 0x29;

/// The media descriptor for non-removable media: `0xF8`. This
/// formatter only ever writes FAT32 onto drive-like targets, and a
/// `0xF8` is the class every FAT32 in the wild carries.
const MEDIA_DESCRIPTOR: u8 = 0xF8;

/// FAT drivers read this name to pick their parsing rules: exactly
/// `"FAT32   "`, spaces padded to 8.
const FAT_TYPE: [u8; 8] = *b"FAT32   ";

/// OEM name [`FormatOptions::default`] carries, matching what Rufus
/// stamps: `MSWIN4.1` is the Windows-95B+ FAT32 dialect every
/// in-tree consumer (Windows, dosfstools, UEFI) parses.
pub const DEFAULT_OEM: [u8; 8] = *b"MSWIN4.1";

/// The label bytes the BPB carries when the volume has no label —
/// exactly 11 bytes, spaces padded. `set_label`'s removal path writes
/// the same field.
pub const NO_NAME_LABEL: [u8; 11] = *b"NO NAME    ";

/// Characters Windows refuses in a volume label. It names the set for
/// FAT labels exactly like for file names: `" * / : < > ? \ |`;
/// everything ASCII-printable beyond that (spaces *inside* the field
/// included) is legal on a FAT volume.
const FORBIDDEN_LABEL_CHARS: [u8; 9] = *b"\"*/:<>?\\|";

/// One boot-sector build request: the resolved [`Geometry`] (its BPB
/// numbers fill the sector), the volume id, the optional label and the
/// OEM name bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootSectorInput<'a> {
    /// The geometry to encode.
    pub geometry: &'a Geometry,
    /// 32-bit volume id — the "serial number" Explorer shows. `0` is
    /// refused: it is the blank marker of unformatted media, and two
    /// freshly formatted sticks must stay distinguishable.
    pub volume_id: u32,
    /// Optional volume label; the field carries [`NO_NAME_LABEL`]
    /// when absent.
    pub label: Option<&'a str>,
    /// OEM name bytes, written verbatim — pass `*b"MSWIN4.1"` or, as
    /// mkfs.fat does, `*b"mkfs.fat"`.
    pub oem: [u8; 8],
}

/// Encode the 11-byte BPB label field.
///
/// The rule set (single source for the BPB *and* the root-directory
/// entry): uppercase ASCII only; the Windows-forbidden
/// [`FORBIDDEN_LABEL_CHARS`], control bytes and non-ASCII bytes are
/// refused with the offending byte named; the field holds at most 11
/// bytes — longer labels are refused, not cropped (cropping is
/// `set_label`'s decision, part B of the slice); a `None` or an empty
/// label fills the field with [`NO_NAME_LABEL`]; anything shorter is
/// padded with spaces.
pub(crate) fn label_field(label: Option<&str>) -> Result<[u8; 11]> {
    let Some(label) = label else {
        return Ok(NO_NAME_LABEL);
    };
    let bytes = label.as_bytes();
    if bytes.is_empty() {
        return Ok(NO_NAME_LABEL);
    }
    if bytes.len() > 11 {
        return Err(CoreError::invalid(format!(
            "volume label is {} bytes long, the fat32 label field holds at most 11",
            bytes.len()
        )));
    }
    for &byte in bytes {
        if byte < 0x20 || byte == 0x7F {
            return Err(CoreError::invalid(format!(
                "volume label carries a control byte (0x{byte:02X}), labels are plain ascii text"
            )));
        }
        if byte >= 0x80 {
            return Err(CoreError::invalid(
                "volume label carries a non-ascii byte, labels are plain ascii text",
            ));
        }
        if FORBIDDEN_LABEL_CHARS.contains(&byte) {
            let character = char::from_u32(u32::from(byte)).unwrap_or('?');
            return Err(CoreError::invalid(format!(
                "volume label carries '{character}' which windows forbids in a volume label"
            )));
        }
    }
    let mut field = [b' '; 11];
    for (slot, &byte) in bytes.iter().enumerate() {
        field[slot] = byte.to_ascii_uppercase();
    }
    Ok(field)
}

/// Build the 512-byte boot sector image.
///
/// Every offset below is the FAT32 EBPB layout; the test module pins
/// the full byte map. Notes on the deliberately-non-obvious fields:
///
/// * bytes 0..3 are the `jmp` scaffolding (`EB 3C 90` — a hop over
///   the BPB into the boot code area; the 3C distance and the `90`
///   no-op are the classic pair the BIOS-side tools expect);
/// * `root entries` (17), `total sectors 16` (19) and `FAT size 16`
///   (22) are FAT12/16-era fields: zero on FAT32, the authoritative
///   32-bit versions live at 32 and 36;
/// * `hidden sectors` (28) is 0: this formatter addresses whole
///   targets; a partition offset is the table writers' (S08) business;
/// * `ext flags` (40) is 0 — both FATs are equally rootable and no
///   mirroring is forced; `fs version` (42) is 0 (FAT32 revision 1.0);
/// * the drive number (64) is `0x80`, byte 65 is the NT-flag
///   placeholder kept zero, and the signature is 0x29 extended-BPB;
/// * the 420 boot-code bytes ([`BOOT_CODE_AREA`]) stay zero and the
///   `0x55AA` signature closes the sector at 510.
pub fn boot_sector(input: &BootSectorInput<'_>) -> Result<[u8; 512]> {
    if input.volume_id == 0 {
        return Err(CoreError::invalid(
            "volume id 0 is refused: the caller must generate a real one",
        ));
    }
    let geometry = input.geometry;
    let sectors_per_cluster = u8::try_from(geometry.sectors_per_cluster).map_err(|_| {
        let count = geometry.sectors_per_cluster;
        CoreError::invalid(format!(
            "sectors per cluster {count} does not fit the 8-bit bpb field"
        ))
    })?;
    let reserved = u16::try_from(geometry.reserved_sectors).map_err(|_| {
        let count = geometry.reserved_sectors;
        CoreError::invalid(format!(
            "reserved sector count {count} does not fit the 16-bit bpb field"
        ))
    })?;
    let label = label_field(input.label)?;
    let mut sector = [0u8; BOOT_SECTOR_BYTES];

    put_bytes(&mut sector, 0, &[0xEB, 0x3C, 0x90])?;
    put_bytes(&mut sector, 3, &input.oem)?;
    put_u16(&mut sector, 11, geometry.bytes_per_sector)?;
    put_bytes(&mut sector, 13, &[sectors_per_cluster])?;
    put_u16(&mut sector, 14, reserved)?;
    put_bytes(&mut sector, 16, &[geometry.num_fats])?;
    put_u16(&mut sector, 17, geometry.root_entries)?;
    put_u16(&mut sector, 19, 0)?; // total sectors 16: dead on FAT32
    put_bytes(&mut sector, 21, &[MEDIA_DESCRIPTOR])?;
    put_u16(&mut sector, 22, 0)?; // FAT size 16: dead on FAT32
    put_u16(&mut sector, 24, SECTORS_PER_TRACK)?;
    put_u16(&mut sector, 26, HEADS)?;
    put_u32(&mut sector, 28, 0)?; // hidden sectors
    put_u32(&mut sector, 32, geometry.total_sectors)?;
    put_u32(&mut sector, 36, geometry.fat_sectors)?;
    put_u16(&mut sector, 40, 0)?; // ext flags: no forced FAT mirroring
    put_u16(&mut sector, 42, 0)?; // fs version
    put_u32(&mut sector, 44, geometry.root_cluster)?;
    put_u16(&mut sector, 48, FSINFO_SECTOR as u16)?;
    put_u16(&mut sector, 50, BACKUP_BOOT_SECTOR as u16)?;
    put_bytes(&mut sector, 64, &[0x80])?; // BIOS drive number (first disk)
    put_bytes(&mut sector, 66, &[EXTENDED_BOOT_SIGNATURE])?;
    put_u32(&mut sector, 67, input.volume_id)?;
    put_bytes(&mut sector, 71, &label)?;
    put_bytes(&mut sector, 82, &FAT_TYPE)?;
    // BOOT_CODE_AREA keeps its zeros (the buffer starts fresh): no
    // boot loader shipped, S19 fills it.
    put_bytes(&mut sector, 510, &[0x55, 0xAA])?;
    Ok(sector)
}

/// The backup boot sector image at reserved sector 6 — a byte
/// identical copy of the primary (FAT32 spec: the backup exists to be
/// copied, not to be tweaked).
#[must_use]
pub fn backup_boot_sector(boot: &[u8; 512]) -> [u8; 512] {
    *boot
}

/// Graft a Syslinux VBR's boot code onto a volume's own boot sector.
///
/// The returned 512 bytes take `vbr[0x00..0x0B]` — the jump
/// instruction plus the OEM name — keep `current[0x0B..0x5A]` (the
/// whole FAT32 BPB/EBPB geometry), take `vbr[0x5A..0x1FE]` (the boot
/// code, [`BOOT_CODE_AREA`]), and keep `current[0x1FE..0x200]` (the
/// `0x55AA` signature, which both sides carry).
///
/// The geometry survives but the entry point does not: a VBR's own
/// BPB describes the build machine's volume, never this one, so
/// copying it would repoint the FATs, the cluster size and the FSInfo
/// pointer at a stranger's layout — while the formatter's own jump
/// (`EB 3C 90`, landing at `0x3E`) would enter the retained header
/// and never reach the Syslinux code at `0x5A`. The payload's jump
/// (`EB 58 90`, landing at `0x5A`) must win, and its OEM name with it:
/// upstream identifies an installed volume by `"SYSLINUX"` at offset
/// 3. Only the primary boot sector is grafted — the FAT32 backup boot
/// sector in the reserved area is deliberately not rewritten, so it
/// keeps the formatter's image until a later slice owns the backup
/// policy.
///
/// Refuses a `vbr` shorter than [`BOOT_SECTOR_BYTES`], naming both
/// lengths, and likewise a `current` image shorter than a sector: a
/// longer `vbr` (a padded or multi-sector image) is fine, its bytes
/// past 512 are ignored.
pub fn graft_boot_code(current: &[u8], vbr: &[u8]) -> Result<[u8; BOOT_SECTOR_BYTES]> {
    let vbr_len = vbr.len();
    if vbr_len < BOOT_SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "syslinux vbr image is {vbr_len} bytes, a boot sector graft needs {BOOT_SECTOR_BYTES} bytes: refusing"
        )));
    }
    let current_len = current.len();
    if current_len < BOOT_SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "volume boot sector image is {current_len} bytes, a boot sector graft needs {BOOT_SECTOR_BYTES} bytes: refusing"
        )));
    }
    // Offsets as numbers: 11 is the BPB start (bytes-per-sector) and
    // 90/510 are the [`BOOT_CODE_AREA`] ends — the code window shares
    // the named range, the entry and geometry windows have no constant
    // of their own.
    let entry = vbr
        .get(..11)
        .ok_or_else(|| CoreError::invalid("syslinux vbr entry window vanished mid-copy"))?;
    let bpb = current.get(11..BOOT_CODE_AREA.start).ok_or_else(|| {
        CoreError::invalid("volume boot sector geometry window vanished mid-copy")
    })?;
    let code = vbr
        .get(BOOT_CODE_AREA.clone())
        .ok_or_else(|| CoreError::invalid("syslinux vbr code window vanished mid-copy"))?;
    let signature = current
        .get(BOOT_CODE_AREA.end..BOOT_SECTOR_BYTES)
        .ok_or_else(|| {
            CoreError::invalid("volume boot sector signature window vanished mid-copy")
        })?;
    let mut out = [0u8; BOOT_SECTOR_BYTES];
    put_bytes(&mut out, 0, entry)?;
    put_bytes(&mut out, 11, bpb)?;
    put_bytes(&mut out, BOOT_CODE_AREA.start, code)?;
    put_bytes(&mut out, BOOT_CODE_AREA.end, signature)?;
    Ok(out)
}

/// Build the FSInfo structure image: the `0x41615252` (`RRaA`) lead
/// signature at offset 0, the `0x61417272` (`rrAa`) structure
/// signature at 484, free-cluster bookkeeping at 488/492 and the
/// `0xAA550000` closing signature at 508 — the layout
/// `fsck.fat`/Windows expect, verified against
/// `mkfs.fat 4.2`'s own output byte for byte.
///
/// Unknown counts (`u32::MAX`) are a real FAT32 feature — a driver
/// copies a valid count when it sees a plausible one and falls back to
/// scanning the FAT otherwise. The file API (S09 part B) publishes
/// counted values through [`fsinfo_with_counts`] as it allocates and
/// flushes; [`fsinfo`] keeps the formatter's post-format shape that
/// genuinely does not know the free count any better than "unknown".
///
/// Infallible by construction: every offset is a compile-time
/// constant inside the 512-byte buffer, so the [`put_bytes`] results
/// (which exist for totality) cannot miss and are dropped with `ok`.
#[must_use]
pub fn fsinfo_with_counts(free_clusters: u32, next_free: u32) -> [u8; 512] {
    let mut sector = [0u8; BOOT_SECTOR_BYTES];
    put_bytes(&mut sector, 0, &0x4161_5252_u32.to_le_bytes()).ok(); // "RRaA"
    put_bytes(&mut sector, 484, &0x6141_7272_u32.to_le_bytes()).ok(); // "rrAa"
    put_u32(&mut sector, 488, free_clusters).ok(); // free cluster count
    put_u32(&mut sector, 492, next_free).ok(); // first free cluster hint
    put_bytes(&mut sector, 508, &0xAA55_0000_u32.to_le_bytes()).ok();
    sector
}

/// Build the FSInfo structure image with the counts unknown
/// (`u32::MAX`): the formatter's own shape. When the file API later
/// allocates and flushes, the counted variant
/// [`fsinfo_with_counts`] publishes the real numbers.
#[must_use]
pub fn fsinfo() -> [u8; 512] {
    fsinfo_with_counts(u32::MAX, u32::MAX)
}

/// One little-endian `u16` of a boot-sector image, defaulting to 0 on a
/// truncated image (the 55AA check refuses truncation far above).
fn le_u16(boot: &[u8], at: usize) -> u16 {
    let low = u16::from(boot.get(at).copied().unwrap_or(0));
    let high = u16::from(boot.get(at + 1).copied().unwrap_or(0));
    (high << 8) | low
}

/// One little-endian `u32` of a boot-sector image (as [`le_u16`]).
fn le_u32(boot: &[u8], at: usize) -> u32 {
    u32::from(le_u16(boot, at)) | u32::from(le_u16(boot, at + 2)) << 16
}

/// Parse a formatted boot sector back into the [`Geometry`] it encodes.
///
/// This is the read half of [`boot_sector`]: `Fat32::open` reads the
/// volume's first 512 bytes and lets this parser rebuild the layout the
/// BPB claims, refusing anything the writer side would never publish.
/// The rules mirror the writer's law set:
///
/// * the image carries the `0x55AA` boot signature and is at least
///   [`BOOT_SECTOR_BYTES`] long;
/// * `bytes per sector` is 512 or 4096, `sectors per cluster` is a
///   power of two within 1..=128, and the resulting cluster stays at
///   the 64 KiB cap the tier table writes (the file API's cluster
///   windows are bounded by it);
/// * `reserved sectors` ≥ 1 and `number of FATs` in 1..=4;
/// * the FAT12/16-era fields root entries (17), total sectors 16 (19)
///   and FAT size 16 (22) are zero — a non-zero one marks a FAT12/16
///   volume dressed as FAT32, refused;
/// * total sectors 32 (32), FAT size 32 (36) are non-zero and resolve
///   to at least [`MIN_CLUSTERS`] and at most
///   [`MAX_CLUSTERS`](crate::fs::fat32::geometry::MAX_CLUSTERS) data
///   clusters;
/// * the extended boot signature (66) is 0x29 — this crate's writer
///   and Rufus both stamp it;
/// * the root cluster (44) numbers a real data cluster (2..=cluster
///   count + 1).
///
/// `volume_total_bytes` is stored verbatim as the geometry's
/// [`Geometry::total_bytes`] reading (the caller's
/// `Volume::total_bytes`), exactly like [`geometry`] carries it.
pub fn parse_boot_sector(boot: &[u8], volume_total_bytes: u64) -> Result<Geometry> {
    if boot.len() < BOOT_SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "boot sector image is {} bytes, a fat32 one is {}",
            boot.len(),
            BOOT_SECTOR_BYTES
        )));
    }
    if boot.get(510) != Some(&0x55) || boot.get(511) != Some(&0xAA) {
        return Err(CoreError::invalid(
            "the boot sector lacks the 0x55AA signature, refusing to open the volume",
        ));
    }
    let bytes_per_sector = le_u16(boot, 11);
    if !matches!(bytes_per_sector, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "boot sector claims {bytes_per_sector} byte sectors, fat32 carries 512 and 4096 only"
        )));
    }
    let sectors_per_cluster = u32::from(boot.get(13).copied().unwrap_or(0));
    if sectors_per_cluster == 0
        || sectors_per_cluster > 128
        || !sectors_per_cluster.is_power_of_two()
    {
        return Err(CoreError::invalid(format!(
            "boot sector claims {sectors_per_cluster} sectors per cluster, fat32 takes a power of two within 1..=128"
        )));
    }
    if u64::from(bytes_per_sector) * u64::from(sectors_per_cluster) > 64 * 1024 {
        return Err(CoreError::invalid(
            "boot sector claims clusters above the 64 KiB fat32 tier maximum",
        ));
    }
    let reserved_sectors = u32::from(le_u16(boot, 14));
    if reserved_sectors == 0 {
        return Err(CoreError::invalid(
            "boot sector claims zero reserved sectors, unusable as a fat32 volume",
        ));
    }
    let num_fats = u32::from(boot.get(16).copied().unwrap_or(0));
    if !(1..=4).contains(&num_fats) {
        return Err(CoreError::invalid(format!(
            "boot sector claims {num_fats} fat copies, fat32 takes 1..=4"
        )));
    }
    if le_u16(boot, 17) != 0 {
        return Err(CoreError::invalid(
            "boot sector carries a 16-bit root entry count, this is not a fat32 volume",
        ));
    }
    if le_u16(boot, 19) != 0 {
        return Err(CoreError::invalid(
            "boot sector carries a 16-bit total sector count, this is not a fat32 volume",
        ));
    }
    if le_u16(boot, 22) != 0 {
        return Err(CoreError::invalid(
            "boot sector carries a 16-bit fat size, this is not a fat32 volume",
        ));
    }
    if boot.get(66) != Some(&EXTENDED_BOOT_SIGNATURE) {
        return Err(CoreError::invalid(format!(
            "boot sector signature byte is 0x{:02X}, expected 0x29 (extended bpb)",
            boot.get(66).copied().unwrap_or(0)
        )));
    }
    let total_sectors = le_u32(boot, 32);
    if total_sectors == 0 {
        return Err(CoreError::invalid(
            "boot sector claims zero total sectors, unusable as a fat32 volume",
        ));
    }
    let fat_sectors = le_u32(boot, 36);
    if fat_sectors == 0 {
        return Err(CoreError::invalid(
            "boot sector claims a zero fat size, unusable as a fat32 volume",
        ));
    }
    let first_data = reserved_sectors
        .checked_add(fat_sectors.checked_mul(num_fats).ok_or_else(|| {
            CoreError::invalid("the boot sector's fat sizes overflow their sector arithmetic")
        })?)
        .ok_or_else(|| {
            CoreError::invalid("the boot sector's fat sizes overflow their sector arithmetic")
        })?;
    if first_data > total_sectors {
        return Err(CoreError::invalid(format!(
            "boot sector's fat copies start at sector {first_data}, past its own {total_sectors} total sectors"
        )));
    }
    let cluster_count = (total_sectors - first_data) / sectors_per_cluster;
    if cluster_count < MIN_CLUSTERS {
        return Err(CoreError::invalid(format!(
            "fat32 needs at least {MIN_CLUSTERS} data clusters, the boot sector maps for {cluster_count}"
        )));
    }
    if cluster_count > MAX_CLUSTERS {
        return Err(CoreError::invalid(format!(
            "fat32 allows at most {MAX_CLUSTERS} data clusters, the boot sector maps for {cluster_count}"
        )));
    }
    let root_cluster = le_u32(boot, 44);
    if root_cluster < ROOT_CLUSTER || root_cluster > cluster_count.saturating_add(1) {
        return Err(CoreError::invalid(format!(
            "boot sector claims root cluster {root_cluster}, outside the data clusters 2..={}",
            cluster_count.saturating_add(1)
        )));
    }
    Ok(Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats: num_fats
            .try_into()
            .map_err(|_| CoreError::invalid("the fat copy count does not fit the u8 bpb field"))?,
        root_entries: 0,
        total_sectors,
        fat_sectors,
        root_cluster,
        cluster_count,
        total_bytes: volume_total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::fat32::geometry::geometry;
    use std::sync::OnceLock;

    /// The one sample geometry the byte pins run against: 64 MiB at
    /// 512-byte sectors (spc 1, FAT 1009, 129,022 clusters).
    fn sample_geometry() -> &'static Geometry {
        static GEOMETRY: OnceLock<Geometry> = OnceLock::new();
        GEOMETRY.get_or_init(|| geometry(64 * 1024 * 1024, 512).expect("64 MiB geometry"))
    }

    /// A boot input both test modules start from: the sample geometry,
    /// serial `0x1A2B_3C4D`, label `Rufus`, Rufus's own OEM name.
    fn sample_input() -> BootSectorInput<'static> {
        BootSectorInput {
            geometry: sample_geometry(),
            volume_id: 0x1A2B_3C4D,
            label: Some("Rufus"),
            oem: DEFAULT_OEM,
        }
    }

    /// `(name, offset, expected bytes)` for every documented field of
    /// the boot sector; the test below additionally proves every byte
    /// outside these windows is zero.
    const BOOT_MAP: [(&str, usize, &[u8]); 28] = [
        ("jump", 0, &[0xEB, 0x3C, 0x90]),
        ("oem", 3, b"MSWIN4.1"),
        ("bytes per sector", 11, &[0x00, 0x02]), // 512 LE
        ("sectors per cluster", 13, &[0x01]),
        ("reserved", 14, &[32, 0x00]),
        ("fat count", 16, &[2]),
        ("root entries 16", 17, &[0, 0]),
        ("total 16", 19, &[0, 0]),
        ("media", 21, &[0xF8]),
        ("fat size 16", 22, &[0, 0]),
        ("sectors per track", 24, &[63, 0x00]),
        ("heads", 26, &[255, 0x00]),
        ("hidden", 28, &[0, 0, 0, 0]),
        ("total 32", 32, &[0x00, 0x00, 0x02, 0x00]), // 131,072 LE
        ("fat size 32", 36, &[0xF1, 0x03, 0x00, 0x00]), // 1,009 LE
        ("ext flags", 40, &[0, 0]),
        ("fs version", 42, &[0, 0]),
        ("root cluster", 44, &[2, 0, 0, 0]),
        ("fsinfo sector", 48, &[1, 0]),
        ("backup boot sector", 50, &[6, 0]),
        ("drive number", 64, &[0x80]),
        ("nt reserved", 65, &[0x00]),
        ("boot signature", 66, &[0x29]),
        ("volume id", 67, &[0x4D, 0x3C, 0x2B, 0x1A]),
        ("label", 71, b"RUFUS      "),
        ("fat type", 82, b"FAT32   "),
        ("boot code area", 90, &[0u8; BOOT_CODE_AREA_BYTES]), // 90..510 zeroed
        ("signature", 510, &[0x55, 0xAA]),
    ];

    #[test]
    fn boot_sector_pins_every_documented_offset() {
        let boot = boot_sector(&sample_input()).expect("the boot sector builds");
        assert_eq!(boot.len(), BOOT_SECTOR_BYTES);

        let mut covered = [false; BOOT_SECTOR_BYTES];
        for (name, offset, expected) in BOOT_MAP {
            let end = offset + expected.len();
            assert!(end <= BOOT_SECTOR_BYTES, "{name} window beyond 512");
            assert_eq!(&boot[offset..end], expected, "{name} at offset {offset}");
            for slot in covered[offset..end].iter_mut() {
                *slot = true;
            }
        }
        // ... and everything outside the named windows is zero: the
        // FAT12/16-carried fields, the hidden sectors, the ext flags,
        // the FSInfo pointer scaffolding of unused positions and the
        // whole boot code area.
        for (offset, &byte) in boot.iter().enumerate() {
            if !covered[offset] {
                assert_eq!(byte, 0, "undocumented non-zero byte at {offset}");
            }
        }
    }

    #[test]
    fn label_adds_up_to_the_windows_rules() {
        // uppercase, spaces inside are legal, pad to 11
        assert_eq!(label_field(Some("rufus")).expect("rufus"), *b"RUFUS      ");
        assert_eq!(label_field(Some("AB CD")).expect("ab cd"), *b"AB CD      ");
        assert_eq!(
            label_field(Some("ABCDEFGHIJK")).expect("11 chars"),
            *b"ABCDEFGHIJK"
        );
        // absent and empty both mean NO NAME
        assert_eq!(label_field(None).expect("absent"), NO_NAME_LABEL);
        assert_eq!(label_field(Some("")).expect("empty"), NO_NAME_LABEL);

        // the boot sector carries the same bytes
        let mut input = sample_input();
        input.label = Some("boot-label");
        input.volume_id = 7;
        let boot = boot_sector(&input).expect("builds");
        assert_eq!(&boot[71..82], b"BOOT-LABEL ");
    }

    #[test]
    fn label_rejections_name_the_problem() {
        // the whole Windows-forbidden set
        for &forbidden in FORBIDDEN_LABEL_CHARS.iter() {
            let character = char::from_u32(u32::from(forbidden)).unwrap_or('?');
            let name = format!("x{character}y");
            let error = label_field(Some(&name)).expect_err("forbidden character");
            let text = error.to_string();
            assert!(text.contains(character), "{text}");
        }
        // control bytes (0x01, 0x7F) and non-ascii (0xFC) rejected
        let error = label_field(Some("a\u{1}b")).expect_err("control byte");
        assert!(error.to_string().contains("control"), "{error}");
        assert!(label_field(Some("a\u{7f}b")).is_err());
        assert!(label_field(Some("a\u{fc}b")).is_err());
        // too long: 11 fits, 12 does not, and the message says so
        assert!(label_field(Some("ABCDEFGHIJK")).is_ok(), "exactly 11 fits");
        let error = label_field(Some("ABCDEFGHIJKL")).expect_err("12 chars");
        assert!(error.to_string().contains("at most 11"), "{error}");
    }

    #[test]
    fn volume_id_zero_is_refused_and_shapes_the_label_field() {
        let mut input = sample_input();
        input.volume_id = 0;
        let error = boot_sector(&input).expect_err("volume id 0 refused");
        assert!(error.to_string().contains("volume id 0"), "{error}");

        // absent and empty labels land as NO NAME on the image
        let mut input = sample_input();
        input.label = None;
        let boot = boot_sector(&input).expect("builds");
        assert_eq!(&boot[71..82], b"NO NAME    ");

        let mut input = sample_input();
        input.label = Some("");
        let boot = boot_sector(&input).expect("builds");
        assert_eq!(&boot[71..82], b"NO NAME    ");
    }

    #[test]
    fn volume_id_round_trips_through_the_bpb() {
        let boot = boot_sector(&sample_input()).expect("builds");
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&boot[67..71]);
        assert_eq!(u32::from_le_bytes(bytes), 0x1A2B_3C4D);
    }

    #[test]
    fn boot_sector_depends_on_the_geometry_only_in_its_bpb() {
        // the same 32 GiB volume class once at 512 and once at 4096
        // byte sectors: the boot sector is byte-identical outside its
        // BPB, especially the boot code area and the 0x55AA; the BPB
        // itself carries each geometry's own numbers.
        let g512 = geometry(32 * 1024 * 1024 * 1024, 512).expect("32 GiB 512");
        let g4096 = geometry(32 * 1024 * 1024 * 1024, 4096).expect("32 GiB 4Kn");
        let sector_for = |geometry: &Geometry| {
            boot_sector(&BootSectorInput {
                geometry,
                volume_id: 0x1234,
                label: None,
                oem: DEFAULT_OEM,
            })
            .expect("builds")
        };
        let sector_512 = sector_for(&g512);
        let sector_4096 = sector_for(&g4096);

        // same ambition everywhere outside bytes 11..40
        for (offset, (a, b)) in sector_512.iter().zip(sector_4096.iter()).enumerate() {
            if !(11..40).contains(&offset) {
                assert_eq!(a, b, "some byte outside the bpb differs at {offset}");
            }
        }
        // ... and inside it, each sector carries its geometry
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&sector_4096[11..13]);
        assert_eq!(u16::from_le_bytes(bytes), 4096);
        assert_eq!(sector_4096[13] as u32, g4096.sectors_per_cluster);
        let mut wide = [0u8; 4];
        wide.copy_from_slice(&sector_4096[32..36]);
        assert_eq!(u32::from_le_bytes(wide), g4096.total_sectors);
        wide.copy_from_slice(&sector_4096[36..40]);
        assert_eq!(u32::from_le_bytes(wide), g4096.fat_sectors);
        assert_eq!(
            g4096.cluster_bytes(),
            65_536,
            "4Kn large tier stays 64 KiB clusters"
        );
    }

    #[test]
    fn fsinfo_carries_signatures_and_unknown_counts() {
        let sector = fsinfo();
        assert_eq!(&sector[0..4], b"RRaA");
        assert_eq!(&sector[484..488], b"rrAa");
        let free = u32::from_le_bytes(sector[488..492].try_into().expect("4 bytes"));
        let next = u32::from_le_bytes(sector[492..496].try_into().expect("4 bytes"));
        let tail = u32::from_le_bytes(sector[508..512].try_into().expect("4 bytes"));
        assert_eq!(free, u32::MAX, "free cluster count unknown");
        assert_eq!(next, u32::MAX, "next free hint unknown");
        assert_eq!(tail, 0xAA55_0000, "the closing signature");
        // the reserved spans stay zero
        assert!(
            sector[4..484].iter().all(|&b| b == 0),
            "first reserved span zero"
        );
        assert!(
            sector[496..508].iter().all(|&b| b == 0),
            "mid tail span zero"
        );
    }

    #[test]
    fn fsinfo_counts_variant_publishes_the_given_numbers() {
        let sector = fsinfo_with_counts(123_456, 789);
        assert_eq!(&sector[0..4], b"RRaA");
        assert_eq!(&sector[484..488], b"rrAa");
        let free = u32::from_le_bytes(sector[488..492].try_into().expect("4 bytes"));
        let next = u32::from_le_bytes(sector[492..496].try_into().expect("4 bytes"));
        let tail = u32::from_le_bytes(sector[508..512].try_into().expect("4 bytes"));
        assert_eq!(free, 123_456);
        assert_eq!(next, 789);
        assert_eq!(tail, 0xAA55_0000, "the closing signature");
        // every other reserved byte stays zero (identical shape to the
        // formatter's unknown-count image)
        let unknown = fsinfo();
        let differ = sector
            .iter()
            .zip(unknown.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(differ, 8, "only the two count fields differ");
    }

    #[test]
    fn parse_round_trips_the_written_boot_sector() {
        for (bytes, sector_size) in [
            (64 * 1024 * 1024_u64, 512_u32),
            (2 * 1024 * 1024 * 1024_u64, 4096),
        ] {
            let want = geometry(bytes, sector_size).expect("the geometry formats");
            let boot = boot_sector(&BootSectorInput {
                geometry: &want,
                volume_id: 0x1A2B_3C4D,
                label: Some("RUFUS"),
                oem: DEFAULT_OEM,
            })
            .expect("the boot sector builds");
            let parsed = parse_boot_sector(&boot, bytes).expect("the parser reads it back");
            assert_eq!(
                parsed, want,
                "the round trip of {bytes} bytes at {sector_size}"
            );
        }
    }

    #[test]
    fn parse_refuses_everything_the_writer_would_never_publish() {
        let want = geometry(64 * 1024 * 1024, 512).expect("the sample geometry");
        let boot = boot_sector(&BootSectorInput {
            geometry: &want,
            volume_id: 0x1A2B_3C4D,
            label: Some("RUFUS"),
            oem: DEFAULT_OEM,
        })
        .expect("builds");
        let mutated = |at: usize, with: &[u8]| {
            let mut copy = boot;
            copy[at..at + with.len()].copy_from_slice(with);
            copy
        };
        // the signature and the 0x29 stamp
        let error = parse_boot_sector(&boot[..500], 64 * 1024 * 1024).expect_err("truncated");
        assert!(error.to_string().contains("500"), "{error}");
        let error =
            parse_boot_sector(&mutated(510, &[0x44, 0x44]), 64 * 1024 * 1024).expect_err("55aa");
        assert!(error.to_string().contains("0x55AA"), "{error}");
        let error = parse_boot_sector(&mutated(66, &[0x28]), 64 * 1024 * 1024).expect_err("0x28");
        assert!(error.to_string().contains("0x29"), "{error}");
        // the sector laws
        let error =
            parse_boot_sector(&mutated(11, &[0, 4]), 64 * 1024 * 1024).expect_err("1024 bps");
        assert!(error.to_string().contains("1024"), "{error}");
        for (spc_bytes, fragment) in [
            (&[0u8], "claims 0"),
            (&[3u8], "3 sectors"),
            (&[129u8], "129"),
        ] {
            let error =
                parse_boot_sector(&mutated(13, spc_bytes), 64 * 1024 * 1024).expect_err("bad spc");
            assert!(error.to_string().contains(fragment), "{error}");
        }
        // cluster bytes above the 64 KiB cap: 4096-byte sectors × 128
        let over = mutated(11, &[0, 16]); // 4096 byte sectors
        let over = {
            let mut copy = over;
            copy[13] = 128;
            copy
        };
        let error = parse_boot_sector(&over, 64 * 1024 * 1024).expect_err("512 KiB clusters");
        assert!(error.to_string().contains("64 KiB"), "{error}");
        // the fat12/16 hand-ups
        let error =
            parse_boot_sector(&mutated(17, &[1, 0]), 64 * 1024 * 1024).expect_err("root 16");
        assert!(error.to_string().contains("root entry"), "{error}");
        let error =
            parse_boot_sector(&mutated(19, &[1, 0]), 64 * 1024 * 1024).expect_err("total 16");
        assert!(error.to_string().contains("total sector"), "{error}");
        let error = parse_boot_sector(&mutated(22, &[1, 0]), 64 * 1024 * 1024).expect_err("fat16");
        assert!(error.to_string().contains("fat size"), "{error}");
        // reserved 0, fat count 0
        let error =
            parse_boot_sector(&mutated(14, &[0, 0]), 64 * 1024 * 1024).expect_err("reserved");
        assert!(error.to_string().contains("zero reserved"), "{error}");
        let error = parse_boot_sector(&mutated(16, &[0]), 64 * 1024 * 1024).expect_err("no fats");
        assert!(error.to_string().contains("0 fat copies"), "{error}");
        // zero totals
        let error = parse_boot_sector(&mutated(32, &[0; 4]), 64 * 1024 * 1024).expect_err("total");
        assert!(error.to_string().contains("zero total"), "{error}");
        let error = parse_boot_sector(&mutated(36, &[0; 4]), 64 * 1024 * 1024).expect_err("fat");
        assert!(error.to_string().contains("zero fat size"), "{error}");
        // the data area past the own totals (fat large enough to start
        // past the -totals law, small enough to stay inside u32
        // arithmetic: the u32-overflowing claim of 0xFFFFFFFF refusals
        // through the overflow law first)
        let error = parse_boot_sector(&mutated(36, &[0xA0, 0x86, 1, 0]), 64 * 1024 * 1024)
            .expect_err("past the top");
        assert!(error.to_string().contains("past its own"), "{error}");
        // root cluster outside the data cluster window
        let error =
            parse_boot_sector(&mutated(44, &[1, 0, 0, 0]), 64 * 1024 * 1024).expect_err("root 1");
        assert!(error.to_string().contains("root cluster 1"), "{error}");
        // a claim below the fat32 cluster floor
        let mut shrunken = boot;
        shrunken[19..23].copy_from_slice(&0_u32.to_le_bytes()); // keep 16-bit total at 0
        shrunken[32..36].copy_from_slice(&1_000_u32.to_le_bytes()); // total sectors
        shrunken[36..40].copy_from_slice(&4_u32.to_le_bytes()); // fat sectors
        let error = parse_boot_sector(&shrunken, 64 * 1024 * 1024).expect_err("tiny volume");
        assert!(error.to_string().contains("65525"), "{error}");
    }

    #[test]
    fn backup_boot_sector_is_a_copy() {
        let boot = boot_sector(&sample_input()).expect("builds");
        let backup = backup_boot_sector(&boot);
        assert_eq!(boot, backup, "fsck compares both copies byte for byte");
    }

    #[test]
    fn graft_takes_the_entry_and_code_but_keeps_the_geometry() {
        let current = boot_sector(&sample_input()).expect("the volume sector builds");
        // A VBR with a real-shaped entry (a jump landing at 0x5A plus
        // an OEM name), a foreign BPB and a recognizable code window:
        // every window differs from `current` where the graft must take
        // the VBR, and matches where it must keep the volume.
        let mut vbr = [0xCCu8; BOOT_SECTOR_BYTES];
        vbr[0..11].copy_from_slice(b"\xEB\x58\x90SYSLINUX");
        for (index, slot) in vbr[BOOT_CODE_AREA].iter_mut().enumerate() {
            *slot = (index % 251) as u8;
        }
        let grafted = graft_boot_code(&current, &vbr).expect("the graft builds");
        assert_eq!(grafted.len(), BOOT_SECTOR_BYTES);
        assert_eq!(
            &grafted[0..11],
            &vbr[0..11],
            "the jump and OEM name come from the VBR"
        );
        assert_eq!(
            &grafted[0..3],
            &vbr[0..3],
            "the entry point is the payload's, never the formatter's"
        );
        assert_eq!(
            2 + u16::from(grafted[1]),
            0x5A,
            "the jump lands on the code at 0x5A"
        );
        assert_eq!(
            &grafted[11..BOOT_CODE_AREA.start],
            &current[11..BOOT_CODE_AREA.start],
            "the BPB/EBPB geometry survives"
        );
        assert_eq!(
            &grafted[BOOT_CODE_AREA], &vbr[BOOT_CODE_AREA],
            "the boot code comes from the VBR"
        );
        assert_eq!(
            &grafted[BOOT_CODE_AREA.end..],
            &current[BOOT_CODE_AREA.end..],
            "the 0x55AA signature survives"
        );
        assert_eq!(
            grafted[BOOT_CODE_AREA.end..],
            [0x55, 0xAA],
            "the tail is the signature itself"
        );
    }

    #[test]
    fn graft_lands_real_payload_jumps_on_the_code() {
        // The pinned 6.04 and 4.07 VBRs straight from the asset tree:
        // both open `eb 58 90` (`"SYSLINUX"` at offset 3) and the graft
        // must carry those exact entry bytes onto the volume.
        let dir = std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ));
        for file in ["RCDATA_400.bin", "RCDATA_402.bin"] {
            let vbr = std::fs::read(dir.join(file)).expect("the pinned vbr reads");
            assert_eq!(vbr.len(), BOOT_SECTOR_BYTES, "{file} is one sector");
            assert_eq!(
                &vbr[0..4],
                &[0xEB, 0x58, 0x90, b'S'],
                "{file} opens with the syslinux jump and OEM"
            );
            let current = boot_sector(&sample_input()).expect("the volume sector builds");
            let grafted = graft_boot_code(&current, &vbr).expect("the graft builds");
            assert_eq!(
                &grafted[0..3],
                &vbr[0..3],
                "{file}: the payload jump wins over the formatter's eb 3c 90"
            );
            assert_eq!(
                2 + u16::from(grafted[1]),
                0x5A,
                "{file}: the jump lands on the code"
            );
            assert_eq!(
                &grafted[3..11],
                b"SYSLINUX",
                "{file}: the OEM name marks an installed volume"
            );
            assert_eq!(
                &grafted[11..BOOT_CODE_AREA.start],
                &current[11..BOOT_CODE_AREA.start],
                "{file}: the geometry survives"
            );
            assert_eq!(
                &grafted[BOOT_CODE_AREA], &vbr[BOOT_CODE_AREA],
                "{file}: the code comes from the VBR"
            );
            assert_eq!(
                &grafted[BOOT_CODE_AREA.end..],
                [0x55, 0xAA],
                "{file}: the signature closes the sector"
            );
        }
    }

    #[test]
    fn graft_refuses_a_short_vbr_naming_both_lengths() {
        let current = boot_sector(&sample_input()).expect("the volume sector builds");
        let short = [0xCCu8; BOOT_SECTOR_BYTES - 1];
        let error = graft_boot_code(&current, &short).expect_err("511 bytes refuse");
        let text = error.to_string();
        assert!(
            text.contains(&short.len().to_string()),
            "the refusal names the vbr length: {text}"
        );
        assert!(
            text.contains(&BOOT_SECTOR_BYTES.to_string()),
            "the refusal names the needed length: {text}"
        );
    }

    #[test]
    fn graft_ignores_vbr_bytes_past_the_sector() {
        // A 4096-byte VBR image (a padded or multi-sector read) grafts
        // exactly like its first 512 bytes: the tail is never touched.
        let current = boot_sector(&sample_input()).expect("the volume sector builds");
        let mut vbr = [0xCCu8; 4096];
        vbr[0..11].copy_from_slice(b"\xEB\x58\x90SYSLINUX");
        for (index, slot) in vbr[BOOT_CODE_AREA].iter_mut().enumerate() {
            *slot = (index % 251) as u8;
        }
        let grafted = graft_boot_code(&current, &vbr).expect("a long vbr grafts");
        assert_eq!(&grafted[BOOT_CODE_AREA], &vbr[BOOT_CODE_AREA]);
        assert_eq!(&grafted[0..11], &vbr[0..11]);
        assert_eq!(
            &grafted[11..BOOT_CODE_AREA.start],
            &current[11..BOOT_CODE_AREA.start]
        );
        assert_eq!(
            &grafted[BOOT_CODE_AREA.end..],
            &current[BOOT_CODE_AREA.end..]
        );
    }
}
