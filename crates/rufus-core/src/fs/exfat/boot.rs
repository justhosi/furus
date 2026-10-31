//! The exFAT boot region: the boot sector, the extended boot sectors, the
//! OEM and reserved sectors, the boot checksum and the backup copy (S10).
//!
//! The region is 24 sectors: sectors 0..=11 are the main copy and
//! 12..=23 a byte-for-byte backup. Sector 11 of each copy holds the
//! checksum of everything before it, computed with the rotate-right-add
//! accumulator the specification defines, *skipping* the two mutating
//! fields of the boot sector (the volume flags and the percent-in-use
//! byte) - otherwise every mount that updated them would appear to be
//! corruption.
//!
//! Field offsets are the specification's, and every write goes through
//! the checked helpers in [`super`], so a short buffer is an error rather
//! than a panic.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::exfat::geometry::Geometry;
use crate::fs::exfat::put_bytes;
use crate::fs::exfat::put_u16;
use crate::fs::exfat::put_u32;
use crate::fs::exfat::put_u64;

/// Bytes of a boot sector, independent of the medium's sector size.
pub const BOOT_SECTOR_BYTES: usize = 512;

/// Number of sectors in one boot region copy (main or backup).
pub const BOOT_REGION_SECTORS: usize = 12;

/// The eight-byte signature every boot sector starts with.
pub const BOOT_SIGNATURE: [u8; 8] = *b"EXFAT   ";

/// Trailing signature of the boot sector and of every extended boot
/// sector.
pub const SECTOR_TAIL: [u8; 4] = [0x00, 0x00, 0x55, 0xAA];

/// File-system revision 1.00, stored little-endian.
pub const REVISION_1_00: u16 = 0x0100;

/// `PercentInUse` value meaning "unknown".
pub const PERCENT_IN_USE_UNKNOWN: u8 = 0xFF;

// Boot-sector field offsets (the specification's table).
mod field {
    pub const JUMP: usize = 0;
    pub const SIGNATURE: usize = 3;
    pub const PARTITION_OFFSET: usize = 64;
    pub const VOLUME_LENGTH: usize = 72;
    pub const FAT_OFFSET: usize = 80;
    pub const FAT_LENGTH: usize = 84;
    pub const CLUSTER_HEAP_OFFSET: usize = 88;
    pub const CLUSTER_COUNT: usize = 92;
    pub const ROOT_CLUSTER: usize = 96;
    pub const VOLUME_SERIAL: usize = 100;
    pub const REVISION: usize = 104;
    pub const VOLUME_FLAGS: usize = 106;
    pub const BYTES_PER_SECTOR_SHIFT: usize = 108;
    pub const SECTORS_PER_CLUSTER_SHIFT: usize = 109;
    pub const NUMBER_OF_FATS: usize = 110;
    pub const DRIVE_SELECT: usize = 111;
    pub const PERCENT_IN_USE: usize = 112;
    pub const BOOT_CODE_START: usize = 120;
    pub const SIGNATURE_TRAILER: usize = 510;
}

/// Length of the boot-code field, from offset 120 to the signature trailer.
pub const BOOT_CODE_LEN: usize = field::SIGNATURE_TRAILER - field::BOOT_CODE_START;

/// The halt instruction the specification requires when no loader is written.
pub const BOOT_CODE_HALT: u8 = 0xF4;

/// The fields [`parse_boot_sector`] recovers, enough for the live volume
/// API to trust its own geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedBoot {
    /// Volume length in sectors.
    pub volume_length_sectors: u64,
    /// First sector of the FAT.
    pub fat_offset: u32,
    /// FAT length in sectors.
    pub fat_length: u32,
    /// First sector of the cluster heap.
    pub cluster_heap_offset: u32,
    /// Number of clusters.
    pub cluster_count: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Volume serial number.
    pub volume_serial: u32,
    /// File-system revision as stored (minor in the high byte).
    pub revision: u16,
    /// Volume flags word.
    pub volume_flags: u16,
    /// Bytes per sector implied by the shift.
    pub sector_size: u32,
    /// Sectors per cluster implied by the shift.
    pub sectors_per_cluster: u32,
    /// Number of FATs the volume declares.
    pub number_of_fats: u8,
    /// Drive-select byte.
    pub drive_select: u8,
    /// Percent-in-use byte, `0xFF` when unknown.
    pub percent_in_use: u8,
}

/// Build the 512-byte boot sector for `geometry`.
///
/// The boot sector is always [`BOOT_SECTOR_BYTES`] bytes: on a 4Kn medium
/// the rest of sector 0 is padding, which [`boot_region`] adds.
pub fn boot_sector(
    geometry: &Geometry,
    volume_serial: u32,
    percent_in_use: u8,
) -> Result<[u8; 512]> {
    if volume_serial == 0 {
        return Err(CoreError::invalid(
            "an exFAT volume serial must not be zero",
        ));
    }
    let sectors_per_cluster_shift = shift_of(geometry.sectors_per_cluster).ok_or_else(|| {
        CoreError::invalid(format!(
            "sectors per cluster {} is not a power of two",
            geometry.sectors_per_cluster
        ))
    })?;
    let sector_shift = shift_of(geometry.sector_size).ok_or_else(|| {
        CoreError::invalid(format!(
            "{} byte sectors are not a power of two",
            geometry.sector_size
        ))
    })?;

    let mut sector = [0u8; BOOT_SECTOR_BYTES];
    put_bytes(&mut sector, field::JUMP, &[0xEB, 0x76, 0x90])?;
    put_bytes(&mut sector, field::SIGNATURE, &BOOT_SIGNATURE)?;
    put_u64(&mut sector, field::PARTITION_OFFSET, 0)?;
    put_u64(
        &mut sector,
        field::VOLUME_LENGTH,
        geometry.volume_length_sectors,
    )?;
    put_u32(&mut sector, field::FAT_OFFSET, geometry.fat_offset)?;
    put_u32(&mut sector, field::FAT_LENGTH, geometry.fat_length)?;
    put_u32(
        &mut sector,
        field::CLUSTER_HEAP_OFFSET,
        geometry.cluster_heap_offset,
    )?;
    put_u32(&mut sector, field::CLUSTER_COUNT, geometry.cluster_count)?;
    put_u32(&mut sector, field::ROOT_CLUSTER, geometry.root_cluster)?;
    put_u32(&mut sector, field::VOLUME_SERIAL, volume_serial)?;
    put_u16(&mut sector, field::REVISION, REVISION_1_00)?;
    put_u16(&mut sector, field::VOLUME_FLAGS, 0)?;
    put_bytes(&mut sector, field::BYTES_PER_SECTOR_SHIFT, &[sector_shift])?;
    put_bytes(
        &mut sector,
        field::SECTORS_PER_CLUSTER_SHIFT,
        &[sectors_per_cluster_shift],
    )?;
    put_bytes(&mut sector, field::NUMBER_OF_FATS, &[1])?;
    put_bytes(&mut sector, field::DRIVE_SELECT, &[0x80])?;
    put_bytes(&mut sector, field::PERCENT_IN_USE, &[percent_in_use])?;
    // This formatter writes no boot loader, and the specification is
    // explicit about what that means: every byte of the boot-code field
    // "shall" be initialized to 0xF4, the halt instruction (section
    // 3.1.19). `mkfs.exfat` 1.4.3 instead stores a 132-byte non-bootable
    // stub at bytes 120..=251 ("This exFAT/GPT volume is not bootable...").
    // Both are accepted by `fsck.exfat`; the 0xF4 fill is the conformant
    // choice for an image with no loader.
    put_bytes(
        &mut sector,
        field::BOOT_CODE_START,
        &[BOOT_CODE_HALT; BOOT_CODE_LEN],
    )?;
    // The boot sector ends with the two-byte signature alone; the four
    // byte `00 00 55 AA` tail belongs to the extended boot sectors.
    put_bytes(&mut sector, field::SIGNATURE_TRAILER, &SECTOR_TAIL[2..])?;
    Ok(sector)
}

/// One extended boot sector: zeroes with the shared tail signature.
pub fn extended_boot_sector(sector_size: u32) -> Result<Vec<u8>> {
    sector_with_tail(sector_size)
}

/// The OEM-parameters sector: all zero, tail included. Its last 32 bytes
/// are reserved by the specification, whose definition of a reserved byte
/// is zero (section 1.2), and `mkfs.exfat` writes zeros there too.
pub fn oem_parameters(sector_size: u32) -> Result<Vec<u8>> {
    zero_sector(sector_size)
}

/// The reserved sector: all zero, tail included (section 1.2).
pub fn reserved_sector(sector_size: u32) -> Result<Vec<u8>> {
    zero_sector(sector_size)
}

/// A sector that is entirely zero.
fn zero_sector(sector_size: u32) -> Result<Vec<u8>> {
    let size = usize::try_from(sector_size)
        .map_err(|_| CoreError::invalid(format!("{sector_size} byte sectors do not fit memory")))?;
    if size == 0 {
        return Err(CoreError::invalid("a sector cannot be empty".to_string()));
    }
    Ok(vec![0u8; size])
}

/// The checksum sector: the 32-bit checksum repeated across the sector.
pub fn checksum_sector(sector_size: u32, checksum: u32) -> Result<Vec<u8>> {
    let size = usize::try_from(sector_size)
        .map_err(|_| CoreError::invalid(format!("{sector_size} byte sectors do not fit memory")))?;
    if size < 4 || size % 4 != 0 {
        return Err(CoreError::invalid(format!(
            "a {sector_size} byte sector cannot hold whole checksums"
        )));
    }
    let mut sector = vec![0u8; size];
    let word = checksum.to_le_bytes();
    let mut at = 0usize;
    while at < size {
        put_bytes(&mut sector, at, &word)?;
        at += 4;
    }
    Ok(sector)
}

/// The rotate-right-add checksum over sectors 0..=10 of one boot region.
///
/// The volume-flags word (offset 106) and the percent-in-use byte (offset
/// 112) live in sector 0 and are excluded because the specification says
/// so: they change while the volume is in use, and a checksum covering
/// them would go stale on the first mount.
pub fn boot_checksum(region: &[u8], sector_size: u32) -> Result<u32> {
    let needed = usize::try_from(u64::from(sector_size) * 11)
        .map_err(|_| CoreError::invalid("the boot region does not fit memory"))?;
    if region.len() < needed {
        return Err(CoreError::invalid(format!(
            "a boot checksum needs {needed} bytes, the region has {}",
            region.len()
        )));
    }
    let mut checksum = 0u32;
    for (index, byte) in region.iter().take(needed).enumerate() {
        if matches!(index, 106 | 107 | 112) {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(u32::from(*byte));
    }
    Ok(checksum)
}

/// The complete main boot region (sectors 0..=11) for `geometry`.
pub fn boot_region(geometry: &Geometry, volume_serial: u32, percent_in_use: u8) -> Result<Vec<u8>> {
    let sector_size = usize::try_from(geometry.sector_size)
        .map_err(|_| CoreError::invalid("the sector size does not fit memory"))?;
    let total = sector_size
        .checked_mul(BOOT_REGION_SECTORS)
        .ok_or_else(|| CoreError::invalid("the boot region overflows memory"))?;
    let mut region = vec![0u8; total];

    let boot = boot_sector(geometry, volume_serial, percent_in_use)?;
    let boot_slot = region
        .get_mut(..BOOT_SECTOR_BYTES)
        .ok_or_else(|| CoreError::invalid("the boot region has no sector 0"))?;
    boot_slot.copy_from_slice(&boot);

    for sector in 1..=8usize {
        let image = extended_boot_sector(geometry.sector_size)?;
        put_sector(&mut region, sector_size, sector, &image)?;
    }
    put_sector(
        &mut region,
        sector_size,
        9,
        &oem_parameters(geometry.sector_size)?,
    )?;
    put_sector(
        &mut region,
        sector_size,
        10,
        &reserved_sector(geometry.sector_size)?,
    )?;

    let checksum = boot_checksum(&region, geometry.sector_size)?;
    let checksum_image = checksum_sector(geometry.sector_size, checksum)?;
    put_sector(&mut region, sector_size, 11, &checksum_image)?;
    Ok(region)
}

/// Parse the fields of a boot sector, refusing anything that is not one.
pub fn parse_boot_sector(sector: &[u8]) -> Result<ParsedBoot> {
    let short = || {
        CoreError::invalid(format!(
            "a boot sector is at least {BOOT_SECTOR_BYTES} bytes"
        ))
    };
    if sector.len() < BOOT_SECTOR_BYTES {
        return Err(short());
    }
    let signature = sector
        .get(field::SIGNATURE..field::SIGNATURE + 8)
        .ok_or_else(short)?;
    if signature != BOOT_SIGNATURE {
        return Err(CoreError::invalid(
            "the boot sector does not start with EXFAT",
        ));
    }
    let tail = sector
        .get(field::SIGNATURE_TRAILER..field::SIGNATURE_TRAILER + 2)
        .ok_or_else(short)?;
    if tail != &SECTOR_TAIL[2..] {
        return Err(CoreError::invalid(
            "the boot sector does not end with the exFAT signature",
        ));
    }

    let read_u64 = |at: usize| -> Result<u64> {
        super::get_u64(sector, at).ok_or_else(|| CoreError::invalid("a boot sector field is short"))
    };
    let read_u32 = |at: usize| -> Result<u32> {
        super::get_u32(sector, at).ok_or_else(|| CoreError::invalid("a boot sector field is short"))
    };
    let read_u16 = |at: usize| -> Result<u16> {
        super::get_u16(sector, at).ok_or_else(|| CoreError::invalid("a boot sector field is short"))
    };

    let sector_shift = byte_at(sector, field::BYTES_PER_SECTOR_SHIFT)?;
    if !(9..=12).contains(&sector_shift) {
        return Err(CoreError::invalid(format!(
            "the boot sector's sector shift {sector_shift} is not 9..=12"
        )));
    }
    let cluster_shift = byte_at(sector, field::SECTORS_PER_CLUSTER_SHIFT)?;
    if cluster_shift > 25 {
        return Err(CoreError::invalid(format!(
            "the boot sector's cluster shift {cluster_shift} is out of range"
        )));
    }
    let number_of_fats = byte_at(sector, field::NUMBER_OF_FATS)?;
    if number_of_fats != 1 {
        return Err(CoreError::invalid(format!(
            "this formatter writes one FAT, the volume declares {number_of_fats}"
        )));
    }

    Ok(ParsedBoot {
        volume_length_sectors: read_u64(field::VOLUME_LENGTH)?,
        fat_offset: read_u32(field::FAT_OFFSET)?,
        fat_length: read_u32(field::FAT_LENGTH)?,
        cluster_heap_offset: read_u32(field::CLUSTER_HEAP_OFFSET)?,
        cluster_count: read_u32(field::CLUSTER_COUNT)?,
        root_cluster: read_u32(field::ROOT_CLUSTER)?,
        volume_serial: read_u32(field::VOLUME_SERIAL)?,
        revision: read_u16(field::REVISION)?,
        volume_flags: read_u16(field::VOLUME_FLAGS)?,
        sector_size: 1u32 << sector_shift,
        sectors_per_cluster: 1u32 << cluster_shift,
        number_of_fats,
        drive_select: byte_at(sector, field::DRIVE_SELECT)?,
        percent_in_use: byte_at(sector, field::PERCENT_IN_USE)?,
    })
}

/// A zeroed sector whose last four bytes carry [`SECTOR_TAIL`].
fn sector_with_tail(sector_size: u32) -> Result<Vec<u8>> {
    let size = usize::try_from(sector_size)
        .map_err(|_| CoreError::invalid(format!("{sector_size} byte sectors do not fit memory")))?;
    if size < 4 {
        return Err(CoreError::invalid(format!(
            "a {sector_size} byte sector cannot hold a signature"
        )));
    }
    let mut sector = vec![0u8; size];
    put_bytes(&mut sector, size - 4, &SECTOR_TAIL)?;
    Ok(sector)
}

/// Copy `image` into sector `index` of `region`.
fn put_sector(region: &mut [u8], sector_size: usize, index: usize, image: &[u8]) -> Result<()> {
    if image.len() != sector_size {
        return Err(CoreError::invalid(format!(
            "sector {index} is {} bytes, expected {sector_size}",
            image.len()
        )));
    }
    let at = index
        .checked_mul(sector_size)
        .ok_or_else(|| CoreError::invalid("the boot region offset overflows"))?;
    put_bytes(region, at, image)
}

/// `Some(log2(value))` when `value` is a power of two.
fn shift_of(value: u32) -> Option<u8> {
    if value == 0 || !value.is_power_of_two() {
        return None;
    }
    u8::try_from(value.trailing_zeros()).ok()
}

/// Checked single byte read.
fn byte_at(source: &[u8], at: usize) -> Result<u8> {
    source
        .get(at)
        .copied()
        .ok_or_else(|| CoreError::invalid(format!("the image has no byte at {at}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn small_geometry() -> Geometry {
        Geometry::resolve(64 * MIB, 512, None).expect("64 MiB resolves")
    }

    #[test]
    fn the_boot_sector_carries_every_field_at_its_specification_offset() {
        let geometry = small_geometry();
        let sector = boot_sector(&geometry, 0x1234_5678, 0).expect("builds");
        assert_eq!(&sector[0..3], &[0xEB, 0x76, 0x90]);
        assert_eq!(&sector[3..11], b"EXFAT   ");
        assert_eq!(&sector[11..64], &[0u8; 53], "the reserved gap stays zero");
        assert_eq!(super::super::get_u64(&sector, 64), Some(0));
        assert_eq!(
            super::super::get_u64(&sector, 72),
            Some(geometry.volume_length_sectors)
        );
        assert_eq!(
            super::super::get_u32(&sector, 80),
            Some(geometry.fat_offset)
        );
        assert_eq!(
            super::super::get_u32(&sector, 84),
            Some(geometry.fat_length)
        );
        assert_eq!(
            super::super::get_u32(&sector, 88),
            Some(geometry.cluster_heap_offset)
        );
        assert_eq!(
            super::super::get_u32(&sector, 92),
            Some(geometry.cluster_count)
        );
        assert_eq!(
            super::super::get_u32(&sector, 96),
            Some(geometry.root_cluster)
        );
        assert_eq!(super::super::get_u32(&sector, 100), Some(0x1234_5678));
        assert_eq!(super::super::get_u16(&sector, 104), Some(REVISION_1_00));
        assert_eq!(super::super::get_u16(&sector, 106), Some(0));
        assert_eq!(sector[108], 9, "512 byte sectors");
        assert_eq!(sector[109], 3, "8 sectors per cluster");
        assert_eq!(sector[110], 1, "one FAT");
        assert_eq!(sector[111], 0x80, "hard-disk drive select");
        assert_eq!(sector[112], 0);
        // No loader is written, so section 3.1.19 requires the halt
        // instruction across the whole boot-code field.
        assert_eq!(
            &sector[field::BOOT_CODE_START..field::SIGNATURE_TRAILER],
            &[BOOT_CODE_HALT; BOOT_CODE_LEN],
            "boot code area is the halt instruction"
        );
        assert_eq!(&sector[510..512], &[0x55, 0xAA]);
    }

    #[test]
    fn a_zero_serial_is_refused() {
        let error = boot_sector(&small_geometry(), 0, 0).expect_err("refused");
        assert!(error.to_string().contains("serial"), "{error}");
    }

    #[test]
    fn extended_boot_sectors_carry_the_tail_signature() {
        for sector_size in [512u32, 4096] {
            let sector = extended_boot_sector(sector_size).expect("builds");
            assert_eq!(sector.len() as u32, sector_size);
            let tail = sector.len() - 4;
            assert_eq!(&sector[tail..], &[0x00, 0x00, 0x55, 0xAA]);
            assert_eq!(&sector[..tail], vec![0u8; tail].as_slice());
        }
    }

    #[test]
    fn the_checksum_sector_repeats_the_checksum_across_the_sector() {
        let sector = checksum_sector(512, 0xDEAD_BEEF).expect("builds");
        assert_eq!(sector.len(), 512);
        for chunk in sector.as_chunks::<4>().0 {
            assert_eq!(chunk, &[0xEF, 0xBE, 0xAD, 0xDE]);
        }
    }

    #[test]
    fn the_checksum_skips_the_volume_flags_and_percent_in_use_only() {
        // Pinned against an independent calculation over a synthetic
        // region: byte i = (i * 37 + 11) & 0xFF, 11 sectors of 512.
        let region: Vec<u8> = (0..11 * 512)
            .map(|i| ((i * 37 + 11) & 0xFF) as u8)
            .collect();
        assert_eq!(boot_checksum(&region, 512).expect("computes"), 0xAA6E_5F46);
    }

    #[test]
    fn the_checksum_ignores_the_two_mutating_fields() {
        let geometry = small_geometry();
        let region = boot_region(&geometry, 7, 0).expect("builds");
        let mut mounted = region.clone();
        mounted[106] = 0x01;
        mounted[107] = 0x02;
        mounted[112] = 42;
        assert_eq!(
            boot_checksum(&region, 512).expect("computes"),
            boot_checksum(&mounted, 512).expect("computes"),
        );
        // A byte anywhere else does change it.
        let mut damaged = region.clone();
        damaged[120] = 0xFF;
        assert_ne!(
            boot_checksum(&region, 512).expect("computes"),
            boot_checksum(&damaged, 512).expect("computes"),
        );
    }

    #[test]
    fn a_short_region_is_refused_by_the_checksum() {
        let error = boot_checksum(&[0u8; 512], 512).expect_err("refused");
        assert!(error.to_string().contains("needs 5632 bytes"), "{error}");
    }

    #[test]
    fn the_region_is_twelve_sectors_with_the_checksum_in_the_last_one() {
        for sector_size in [512u32, 4096] {
            let geometry = Geometry::resolve(64 * MIB, sector_size, None).expect("resolves");
            let region = boot_region(&geometry, 0x0102_0304, 0).expect("builds");
            let size = sector_size as usize;
            assert_eq!(region.len(), size * BOOT_REGION_SECTORS);
            let checksum_at = 11 * size;
            let stored = super::super::get_u32(&region, checksum_at).expect("a checksum word");
            assert_eq!(
                stored,
                boot_checksum(&region, sector_size).expect("computes")
            );
            for at in (checksum_at + 4..region.len()).step_by(4) {
                assert_eq!(
                    super::super::get_u32(&region, at),
                    Some(stored),
                    "every word repeats the checksum"
                );
            }
            // Only the extended boot sector carries the shared tail. The
            // OEM-parameters and reserved sectors are reserved bytes, and
            // the specification defines those as zero - measured against
            // `mkfs.exfat`, which writes zeros in both.
            let sector = |index: usize| &region[index * size..(index + 1) * size];
            assert_eq!(&sector(8)[size - 4..], &SECTOR_TAIL);
            assert_eq!(&sector(9)[size - 4..], &[0u8; 4], "OEM parameters end zero");
            assert_eq!(
                &sector(10)[size - 4..],
                &[0u8; 4],
                "reserved sector is zero"
            );
        }
    }

    #[test]
    fn parsing_round_trips_the_generated_boot_sector() {
        let geometry = small_geometry();
        let region = boot_region(&geometry, 0x0A0B_0C0D, 0).expect("builds");
        let parsed = parse_boot_sector(&region).expect("parses");
        assert_eq!(parsed.volume_length_sectors, geometry.volume_length_sectors);
        assert_eq!(parsed.fat_offset, geometry.fat_offset);
        assert_eq!(parsed.fat_length, geometry.fat_length);
        assert_eq!(parsed.cluster_heap_offset, geometry.cluster_heap_offset);
        assert_eq!(parsed.cluster_count, geometry.cluster_count);
        assert_eq!(parsed.root_cluster, geometry.root_cluster);
        assert_eq!(parsed.volume_serial, 0x0A0B_0C0D);
        assert_eq!(parsed.revision, REVISION_1_00);
        assert_eq!(parsed.sector_size, 512);
        assert_eq!(parsed.sectors_per_cluster, geometry.sectors_per_cluster);
        assert_eq!(parsed.number_of_fats, 1);
        assert_eq!(parsed.drive_select, 0x80);
        assert_eq!(parsed.percent_in_use, 0);
    }

    #[test]
    fn parsing_refuses_a_short_or_foreign_image() {
        assert!(parse_boot_sector(&[0u8; 511]).is_err());
        let mut foreign = vec![0u8; 512];
        foreign[3..11].copy_from_slice(b"NTFS    ");
        assert!(parse_boot_sector(&foreign).is_err());
        let mut no_tail = vec![0u8; 512];
        no_tail[3..11].copy_from_slice(b"EXFAT   ");
        assert!(parse_boot_sector(&no_tail).is_err());
    }

    #[test]
    fn a_volume_declaring_two_fats_is_refused() {
        let geometry = small_geometry();
        let mut sector = boot_sector(&geometry, 5, 0).expect("builds");
        sector[110] = 2;
        let error = parse_boot_sector(&sector).expect_err("refused");
        assert!(error.to_string().contains("one FAT"), "{error}");
    }
}
