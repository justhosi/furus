//! The exFAT write step: boot region, FAT, allocation bitmap, up-case
//! table, root directory and label (S10).
//!
//! The order is the one the specification explains and the one the
//! standard tools use: the boot region first (so a half-written volume is
//! visibly not a volume), then the FAT that describes the system clusters,
//! then the three things those clusters hold, and finally a flush. The
//! result is a mountable, empty exFAT volume - no files, no directories
//! beyond the root, and every system cluster accounted for in the bitmap.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::exfat::boot;
use crate::fs::exfat::boot::BOOT_REGION_SECTORS;
use crate::fs::exfat::geometry::Geometry;
use crate::fs::exfat::put_bytes;
use crate::fs::exfat::put_u32;
use crate::fs::exfat::put_u64;
use crate::fs::exfat::upcase;
use crate::units::human_bytes;

/// Entry type of the allocation-bitmap directory entry.
pub const ENTRY_BITMAP: u8 = 0x81;

/// Entry type of the up-case table directory entry.
pub const ENTRY_UP_CASE: u8 = 0x82;

/// Entry type of the volume-label directory entry.
pub const ENTRY_VOLUME_LABEL: u8 = 0x83;

/// Bytes of one directory entry.
pub const ENTRY_BYTES: usize = 32;

/// Longest label exFAT stores, in UTF-16 units.
pub const MAX_LABEL_UNITS: usize = 11;

/// FAT value marking the end of a cluster chain.
pub const FAT_END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// FAT value of entry 0, which carries the media descriptor.
pub const FAT_MEDIA: u32 = 0xFFFF_FFF8;

/// How the formatter fills a volume.
#[derive(Debug, Clone, Default)]
pub struct FormatOptions {
    /// Volume label, at most eleven UTF-16 units.
    pub label: Option<String>,
    /// Volume serial number. The specification accepts every value,
    /// including zero, but the formatter refuses zero: it means the
    /// caller did not generate one, and shipping a volume whose
    /// serial reads as unset would hide that mistake.
    pub volume_id: u32,
    /// Cluster size override; `None` uses the measured default ladder.
    pub cluster_bytes: Option<u32>,
}

impl FormatOptions {
    /// Options with a serial and no label, using the default ladder.
    pub fn new(volume_id: u32) -> Self {
        Self {
            label: None,
            volume_id,
            cluster_bytes: None,
        }
    }
}

/// Format `volume` as exFAT.
///
/// Refuses before the first write when the serial is zero, the label does
/// not fit or carries a character the format forbids, or the geometry
/// cannot be resolved; re-reads the volume's extent before writing so a
/// store that changed size since the caller measured it is an error
/// rather than a truncated layout.
pub fn format(volume: &mut dyn Volume, options: &FormatOptions) -> Result<Geometry> {
    if options.volume_id == 0 {
        return Err(CoreError::invalid(
            "an exFAT volume serial must not be zero",
        ));
    }
    let measured = volume.total_bytes();
    let sector_size = volume.sector_size();
    let geometry = Geometry::resolve(measured, sector_size, options.cluster_bytes)?;
    let label = label_units(options.label.as_deref())?;

    if volume.total_bytes() != measured {
        return Err(CoreError::invalid(format!(
            "the volume changed size while it was being formatted: {} then {}",
            human_bytes(measured),
            human_bytes(volume.total_bytes())
        )));
    }

    write_boot_regions(volume, &geometry, options.volume_id)?;
    write_fat(volume, &geometry)?;
    write_bitmap(volume, &geometry)?;
    write_upcase(volume, &geometry)?;
    write_root_directory(volume, &geometry, label.as_deref())?;
    volume.flush()?;
    Ok(geometry)
}

/// The main and backup boot regions, 24 sectors in total.
fn write_boot_regions(volume: &mut dyn Volume, geometry: &Geometry, serial: u32) -> Result<()> {
    // 0xFF ("unknown"), not 0 ("empty"): a freshly formatted volume has no
    // idea how full it is, the specification allows either, and the field is
    // excluded from the boot checksum. `mkfs.exfat` writes 0.
    let region = boot::boot_region(geometry, serial, boot::PERCENT_IN_USE_UNKNOWN)?;
    volume.write_all_at(0, &region)?;
    let backup_at = (BOOT_REGION_SECTORS as u64) * u64::from(geometry.sector_size);
    volume.write_all_at(backup_at, &region)?;
    Ok(())
}

/// The FAT: two reserved entries, the system chains and zero everywhere
/// else.
fn write_fat(volume: &mut dyn Volume, geometry: &Geometry) -> Result<()> {
    let sector_size = usize::try_from(geometry.sector_size)
        .map_err(|_| CoreError::invalid("the sector size does not fit memory"))?;
    let fat_bytes =
        usize::try_from(u64::from(geometry.fat_length) * u64::from(geometry.sector_size))
            .map_err(|_| CoreError::invalid("the FAT does not fit memory"))?;
    let mut fat = vec![0u8; fat_bytes];
    put_u32(&mut fat, 0, FAT_MEDIA)?;
    put_u32(&mut fat, 4, FAT_END_OF_CHAIN)?;

    link_chain(&mut fat, geometry.bitmap_cluster, geometry.bitmap_clusters)?;
    let up_case_clusters = geometry.up_case_clusters();
    link_chain(&mut fat, geometry.up_case_cluster(), up_case_clusters)?;
    let root_at = entry_offset(geometry.root_cluster)?;
    put_u32(&mut fat, root_at, FAT_END_OF_CHAIN)?;

    let fat_at = u64::from(geometry.fat_offset) * u64::from(geometry.sector_size);
    let chunk = sector_size.saturating_mul(64);
    for (index, piece) in fat.chunks(chunk).enumerate() {
        let at = fat_at
            .checked_add((index as u64) * (chunk as u64))
            .ok_or_else(|| CoreError::invalid("the FAT offset overflows"))?;
        volume.write_all_at(at, piece)?;
    }
    Ok(())
}

/// Point each entry of a `count`-cluster chain at the next one, ending in
/// the end-of-chain marker.
fn link_chain(fat: &mut [u8], first: u32, count: u32) -> Result<()> {
    if count == 0 {
        return Err(CoreError::invalid(format!(
            "cluster {first} was reserved with no clusters"
        )));
    }
    for step in 0..count {
        let cluster = first
            .checked_add(step)
            .ok_or_else(|| CoreError::invalid("a cluster chain overflows"))?;
        let value = if step + 1 == count {
            FAT_END_OF_CHAIN
        } else {
            cluster + 1
        };
        put_u32(fat, entry_offset(cluster)?, value)?;
    }
    Ok(())
}

/// The allocation bitmap: one bit per cluster, set for the clusters the
/// formatter itself occupies.
fn write_bitmap(volume: &mut dyn Volume, geometry: &Geometry) -> Result<()> {
    let bytes = usize::try_from(geometry.bitmap_bytes)
        .map_err(|_| CoreError::invalid("the allocation bitmap does not fit memory"))?;
    let mut bitmap = vec![0u8; bytes];
    let used = SystemClusters::of(geometry)?.used();
    for cluster in geometry.bitmap_cluster..geometry.bitmap_cluster + used {
        let index = usize::try_from(cluster - geometry.bitmap_cluster)
            .map_err(|_| CoreError::invalid("a bitmap index does not fit memory"))?;
        let Some(byte) = bitmap.get_mut(index / 8) else {
            return Err(CoreError::invalid(format!(
                "the bitmap does not cover cluster {cluster}"
            )));
        };
        *byte |= 1 << (index % 8);
    }
    let at = geometry.cluster_offset(geometry.bitmap_cluster)?;
    volume.write_all_at(at, &bitmap)?;
    Ok(())
}

/// The up-case table in its compressed form.
fn write_upcase(volume: &mut dyn Volume, geometry: &Geometry) -> Result<()> {
    let at = geometry.cluster_offset(geometry.up_case_cluster())?;
    volume.write_all_at(at, upcase::table())?;
    Ok(())
}

/// The root directory: label (when there is one), bitmap entry, up-case
/// entry and the zero terminator.
fn write_root_directory(
    volume: &mut dyn Volume,
    geometry: &Geometry,
    label: Option<&[u16]>,
) -> Result<()> {
    let cluster_bytes = usize::try_from(geometry.cluster_bytes)
        .map_err(|_| CoreError::invalid("the cluster size does not fit memory"))?;
    let mut root = vec![0u8; cluster_bytes];
    let mut at = 0usize;

    if let Some(units) = label {
        let entry = label_entry(units)?;
        put_bytes(&mut root, at, &entry)?;
        at += ENTRY_BYTES;
    }

    let bitmap = system_entry(
        ENTRY_BITMAP,
        geometry.bitmap_cluster,
        geometry.bitmap_bytes,
        None,
    )?;
    put_bytes(&mut root, at, &bitmap)?;
    at += ENTRY_BYTES;

    let up_case = system_entry(
        ENTRY_UP_CASE,
        geometry.up_case_cluster(),
        upcase::TABLE_BYTES,
        Some(upcase::UP_CASE_TABLE_CHECKSUM),
    )?;
    put_bytes(&mut root, at, &up_case)?;
    at += ENTRY_BYTES;

    // The directory ends at the first zero type byte, which the buffer
    // already provides; make it explicit so a later edit cannot drop it.
    put_bytes(&mut root, at, &[0u8])?;

    let root_at = geometry.cluster_offset(geometry.root_cluster)?;
    volume.write_all_at(root_at, &root)?;
    Ok(())
}

/// A 0x81 / 0x82 style entry: type, first cluster, length and an optional
/// checksum in the up-case slot.
fn system_entry(
    kind: u8,
    first_cluster: u32,
    length: u64,
    checksum: Option<u32>,
) -> Result<[u8; ENTRY_BYTES]> {
    let mut entry = [0u8; ENTRY_BYTES];
    put_bytes(&mut entry, 0, &[kind])?;
    if let Some(value) = checksum {
        put_u32(&mut entry, 4, value)?;
    }
    put_u32(&mut entry, 20, first_cluster)?;
    put_u64(&mut entry, 24, length)?;
    Ok(entry)
}

/// The 0x83 volume-label entry: character count then UTF-16LE units.
fn label_entry(units: &[u16]) -> Result<[u8; ENTRY_BYTES]> {
    if units.len() > MAX_LABEL_UNITS {
        return Err(CoreError::invalid(format!(
            "an exFAT label holds {MAX_LABEL_UNITS} characters, not {}",
            units.len()
        )));
    }
    let mut entry = [0u8; ENTRY_BYTES];
    put_bytes(&mut entry, 0, &[ENTRY_VOLUME_LABEL])?;
    let count = u8::try_from(units.len())
        .map_err(|_| CoreError::invalid("the label length does not fit a byte"))?;
    put_bytes(&mut entry, 1, &[count])?;
    for (index, unit) in units.iter().enumerate() {
        let at = 2 + index * 2;
        put_bytes(&mut entry, at, &unit.to_le_bytes())?;
    }
    Ok(entry)
}

/// Validate the label and return its UTF-16 units.
fn label_units(label: Option<&str>) -> Result<Option<Vec<u16>>> {
    let Some(label) = label else {
        return Ok(None);
    };
    if label.is_empty() {
        return Ok(None);
    }
    let units: Vec<u16> = label.encode_utf16().collect();
    if units.len() > MAX_LABEL_UNITS {
        return Err(CoreError::invalid(format!(
            "an exFAT label holds {MAX_LABEL_UNITS} characters, this one needs {}",
            units.len()
        )));
    }
    for unit in &units {
        let forbidden = *unit < 0x20
            || matches!(
                *unit,
                0x22 | 0x2A | 0x2F | 0x3A | 0x3C | 0x3E | 0x3F | 0x5C | 0x7C
            );
        if forbidden {
            return Err(CoreError::invalid(format!(
                "an exFAT label cannot contain the character U+{unit:04X}"
            )));
        }
    }
    Ok(Some(units))
}

/// Byte offset of `cluster`'s FAT entry.
fn entry_offset(cluster: u32) -> Result<usize> {
    let at = u64::from(cluster) * 4;
    usize::try_from(at).map_err(|_| CoreError::invalid(format!("FAT entry {cluster} overflows")))
}

/// The clusters the formatter occupies: bitmap, up-case table and root.
struct SystemClusters {
    bitmap: u32,
    up_case: u32,
    root: u32,
}

impl SystemClusters {
    fn of(geometry: &Geometry) -> Result<Self> {
        let up_case = geometry.up_case_clusters();
        let total = geometry
            .bitmap_clusters
            .checked_add(up_case)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| CoreError::invalid("the system clusters overflow"))?;
        if total > geometry.cluster_count {
            return Err(CoreError::invalid(
                "the volume is too small for its own system clusters".to_string(),
            ));
        }
        Ok(Self {
            bitmap: geometry.bitmap_clusters,
            up_case,
            root: 1,
        })
    }

    fn used(&self) -> u32 {
        self.bitmap + self.up_case + self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::exfat::get_u16;
    use crate::fs::exfat::get_u32;
    use crate::fs::exfat::get_u64;

    const MIB: u64 = 1024 * 1024;

    fn formatted(size: u64, sector_size: u32, options: &FormatOptions) -> (VecVolume, Geometry) {
        let mut volume = VecVolume::new(size, sector_size).expect("the store allocates");
        let geometry = format(&mut volume, options).expect("the volume formats");
        (volume, geometry)
    }

    #[test]
    fn the_boot_region_is_written_twice_with_the_checksum_in_place() {
        let (volume, geometry) = formatted(64 * MIB, 512, &FormatOptions::new(0x1122_3344));
        let bytes = volume.bytes();
        let size = 512usize;
        let main_end = size * BOOT_REGION_SECTORS;
        assert_eq!(
            &bytes[..main_end],
            &bytes[main_end..2 * main_end],
            "the backup region is a byte copy"
        );
        let stored = get_u32(bytes, 11 * size).expect("a checksum word");
        assert_eq!(
            stored,
            boot::boot_checksum(&bytes[..main_end], 512).expect("computes"),
        );
        // The region sits in front of the FAT.
        assert_eq!(bytes[0], 0xEB);
        assert_eq!(&bytes[3..11], b"EXFAT   ");
        assert_eq!(get_u64(bytes, 72), Some(geometry.volume_length_sectors));
        // PercentInUse is 0xFF ("unknown") on a fresh volume: the
        // specification allows it, mkfs writes 0, and the field is excluded
        // from the checksum. Pin the byte so the choice cannot drift.
        assert_eq!(bytes[112], 0xFF);
        assert_eq!(boot::PERCENT_IN_USE_UNKNOWN, 0xFF);
    }

    #[test]
    fn the_fat_describes_every_system_chain_and_nothing_else() {
        let (volume, geometry) = formatted(64 * MIB, 512, &FormatOptions::new(1));
        let fat_at = usize::try_from(geometry.fat_offset).expect("fits") * 512;
        let bytes = volume.bytes();
        // Literals, not `FAT_MEDIA`/`FAT_END_OF_CHAIN`: an expectation written
        // as the constant that produced it cannot catch a wrong constant.
        // Both values are the spec's, and `mkfs.exfat` 1.4.3 writes them too.
        assert_eq!(get_u32(bytes, fat_at), Some(0xFFFF_FFF8));
        assert_eq!(get_u32(bytes, fat_at + 4), Some(0xFFFF_FFFF));
        assert_eq!(
            get_u32(bytes, fat_at + 4 * geometry.bitmap_cluster as usize),
            Some(FAT_END_OF_CHAIN),
        );
        let up_case = geometry.up_case_cluster();
        assert_eq!(
            get_u32(bytes, fat_at + 4 * up_case as usize),
            Some(if geometry.up_case_clusters() > 1 {
                up_case + 1
            } else {
                FAT_END_OF_CHAIN
            }),
            "the up-case chain links its clusters",
        );
        assert_eq!(
            get_u32(bytes, fat_at + 4 * geometry.root_cluster as usize),
            Some(FAT_END_OF_CHAIN),
        );
    }

    #[test]
    fn the_bitmap_marks_the_system_clusters_only() {
        let (volume, geometry) = formatted(64 * MIB, 512, &FormatOptions::new(2));
        let at = usize::try_from(
            geometry
                .cluster_offset(geometry.bitmap_cluster)
                .expect("offset"),
        )
        .expect("fits");
        let bytes = volume.bytes();
        // Measured from `mkfs.exfat` 1.4.3 on a 64 MiB image: clusters 2, 3,
        // 4 and 5 are taken (bitmap, two up-case clusters, root), so the first
        // bitmap byte is 0x0F and everything after it is zero. Pinning the
        // bytes rather than recomputing them from `SystemClusters` is what
        // makes a dropped or extra bit fail.
        assert_eq!(bytes[at], 0x0F, "clusters 2..=5 are the system clusters");
        assert_eq!(bytes[at + 1], 0x00, "the next cluster is free");
        assert_eq!(
            geometry.up_case_cluster(),
            3,
            "measured: the bitmap takes one cluster at 64 MiB"
        );
    }

    #[test]
    fn the_upcase_table_is_written_whole() {
        let (volume, geometry) = formatted(64 * MIB, 512, &FormatOptions::new(3));
        let at = usize::try_from(
            geometry
                .cluster_offset(geometry.up_case_cluster())
                .expect("offset"),
        )
        .expect("fits");
        let bytes = volume.bytes();
        assert_eq!(&bytes[at..at + 4], &[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            &bytes[at..at + upcase::TABLE_BYTES as usize],
            upcase::table(),
            "the table is stored byte for byte",
        );
    }

    #[test]
    fn the_root_directory_lists_the_label_bitmap_and_upcase_entries() {
        let options = FormatOptions {
            label: Some("RUFUS".to_string()),
            volume_id: 4,
            cluster_bytes: None,
        };
        let (volume, geometry) = formatted(64 * MIB, 512, &options);
        let at = usize::try_from(
            geometry
                .cluster_offset(geometry.root_cluster)
                .expect("offset"),
        )
        .expect("fits");
        let bytes = volume.bytes();
        assert_eq!(bytes[at], ENTRY_VOLUME_LABEL);
        assert_eq!(bytes[at + 1], 5, "five characters");
        assert_eq!(get_u16(bytes, at + 2), Some(u16::from(b'R')));
        assert_eq!(get_u16(bytes, at + 10), Some(u16::from(b'S')));
        assert_eq!(bytes[at + 32], ENTRY_BITMAP);
        assert_eq!(get_u32(bytes, at + 32 + 20), Some(geometry.bitmap_cluster));
        assert_eq!(get_u64(bytes, at + 32 + 24), Some(geometry.bitmap_bytes));
        assert_eq!(bytes[at + 64], ENTRY_UP_CASE);
        assert_eq!(
            get_u32(bytes, at + 64 + 4),
            Some(upcase::UP_CASE_TABLE_CHECKSUM)
        );
        assert_eq!(
            get_u32(bytes, at + 64 + 20),
            Some(geometry.up_case_cluster())
        );
        assert_eq!(get_u64(bytes, at + 64 + 24), Some(upcase::TABLE_BYTES));
        assert_eq!(bytes[at + 96], 0, "the directory is terminated");
    }

    #[test]
    fn formatting_twice_produces_the_same_bytes() {
        let (first, _) = formatted(64 * MIB, 512, &FormatOptions::new(9));
        let (second, _) = formatted(64 * MIB, 512, &FormatOptions::new(9));
        assert_eq!(first.bytes(), second.bytes(), "formatting is deterministic");
    }

    #[test]
    fn a_zero_serial_is_refused_before_anything_is_written() {
        let mut volume = VecVolume::new(64 * MIB, 512).expect("allocates");
        let error = format(&mut volume, &FormatOptions::new(0)).expect_err("refused");
        assert!(error.to_string().contains("serial"), "{error}");
        assert!(
            volume.bytes().iter().all(|byte| *byte == 0),
            "nothing was written"
        );
    }

    #[test]
    fn labels_that_cannot_be_stored_are_refused() {
        let long = "A".repeat(12);
        let options = FormatOptions {
            label: Some(long),
            volume_id: 1,
            cluster_bytes: None,
        };
        let mut volume = VecVolume::new(64 * MIB, 512).expect("allocates");
        let error = format(&mut volume, &options).expect_err("refused");
        assert!(error.to_string().contains("11 characters"), "{error}");

        let forbidden = FormatOptions {
            label: Some("BAD:NAME".to_string()),
            volume_id: 1,
            cluster_bytes: None,
        };
        let error = format(&mut volume, &forbidden).expect_err("refused");
        assert!(error.to_string().contains("U+003A"), "{error}");

        let eleven = FormatOptions {
            label: Some("ABCDEFGHIJK".to_string()),
            volume_id: 1,
            cluster_bytes: None,
        };
        format(&mut volume, &eleven).expect("eleven characters fit");
    }

    #[test]
    fn a_store_that_changes_size_between_the_two_measurements_is_refused() {
        use std::cell::Cell;

        struct Drifty {
            inner: VecVolume,
            reads: Cell<u32>,
        }
        impl Volume for Drifty {
            fn total_bytes(&self) -> u64 {
                let seen = self.reads.get();
                self.reads.set(seen + 1);
                // The first reading (the one the geometry is resolved
                // from) is the real size; every later one claims a byte
                // more, which is the drift the guard exists for.
                if seen == 0 {
                    self.inner.total_bytes()
                } else {
                    self.inner.total_bytes() + 1
                }
            }
            fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
                self.inner.read_exact_at(offset, buf)
            }
            fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
                self.inner.write_all_at(offset, buf)
            }
            fn sector_size(&self) -> u32 {
                512
            }
        }

        let mut store = Drifty {
            inner: VecVolume::new(64 * MIB, 512).expect("allocates"),
            reads: Cell::new(0),
        };
        let error = format(&mut store, &FormatOptions::new(1)).expect_err("drift is refused");
        assert!(error.to_string().contains("changed size"), "{error}");
        assert!(
            store.inner.bytes().iter().all(|byte| *byte == 0),
            "nothing was written before the drift was noticed"
        );
    }
}
