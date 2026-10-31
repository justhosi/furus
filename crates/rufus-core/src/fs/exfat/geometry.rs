//! exFAT geometry: cluster size, FAT size, cluster count and the refusal
//! boundaries (S10).
//!
//! exFAT has no fixed relationship between volume size and cluster size —
//! the formatter picks one, and the boot sector records it. This module
//! makes that choice in one place and proves the layout fits before a
//! single byte is written:
//!
//! * the *default* ladder reproduces `mkfs.exfat` from about 7 MiB upwards;
//!   below that `mkfs` steps straight down to its 512-byte minimum, which
//!   the cluster floor (`MIN_CLUSTER_BYTES`) refuses;
//! * an explicit cluster size is honoured when it is a power of two in
//!   4 KiB..=32 MiB and a whole number of sectors;
//! * the FAT is sized from the cluster count and the heap starts on a
//!   1 MiB boundary, so the layout is reproducible byte for byte.
//!
//! The numbers below were measured against `mkfs.exfat` from exfatprogs
//! 1.4.3 on this machine rather than inferred. For a 64 MiB image it
//! produces FAT offset 2048 sectors, FAT length 126 sectors, heap offset
//! 4096 sectors and 15,872 clusters of 4096 bytes, and for a 2 GiB image
//! 512, 4096 and 65,472 clusters of 32 KiB - both exactly what
//! [`Geometry::resolve`] returns. Across 33 measured sizes from 8 MiB to
//! 2 TiB the two layouts agree on cluster size, FAT offset, FAT length,
//! heap offset and cluster count. The invariants that matter (the FAT
//! covers every cluster, the heap is 1 MiB aligned and starts after the
//! FAT) are tested at every size class.

use crate::error::CoreError;
use crate::error::Result;
use crate::units::human_bytes;

/// Sector sizes the exFAT layout supports (the same pair FAT32 accepts).
pub const ACCEPTED_SECTOR_SIZES: [u32; 2] = [512, 4096];

/// Bytes per MiB, used for the heap alignment.
const MIB: u64 = 1024 * 1024;

/// Smallest volume this formatter accepts.
///
/// The specification's own floor is `2^20 / bytes-per-sector` sectors
/// (1 MiB). This layout is stricter on purpose: the cluster heap starts on
/// a 1 MiB boundary, and a 2.5 MiB volume would leave only 512 KiB of heap
/// after the boot region, the aligned FAT and the heap alignment padding.
/// `mkfs.exfat` does format 2.5 MiB (with 512-byte clusters, below our
/// 4 KiB floor); 3 MiB is a policy choice that keeps at least 1 MiB of
/// heap, not a physical limit of the format.
pub const MIN_VOLUME_BYTES: u64 = 3 * MIB;

/// Largest volume this formatter accepts. exFAT itself allows more, but
/// a 2 TiB ceiling matches the FAT32 side and keeps every offset inside
/// the range the boot sector's `u32` fields can describe.
pub const MAX_VOLUME_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;

/// Smallest cluster the formatter will place.
pub const MIN_CLUSTER_BYTES: u32 = 4096;

/// Largest cluster the formatter will place.
pub const MAX_CLUSTER_BYTES: u32 = 32 * 1024 * 1024;

/// Largest cluster count the specification allows. Every volume this
/// formatter accepts stays far below it, so the ceiling is a guard rather
/// than a boundary any real layout reaches.
pub const MAX_CLUSTER_COUNT: u32 = 0xFFFF_FFF5;

/// First cluster of the cluster heap (clusters 0 and 1 are reserved).
pub const FIRST_HEAP_CLUSTER: u32 = 2;

/// Cluster holding the allocation bitmap.
pub const BITMAP_CLUSTER: u32 = 2;

/// The resolved on-disk geometry of one exFAT volume.
///
/// Every field is exactly what the boot sector and the FAT need; nothing
/// here is derived a second time by the writer, so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Bytes per sector (512 or 4096).
    pub sector_size: u32,
    /// Sectors per cluster; always a power of two.
    pub sectors_per_cluster: u32,
    /// Bytes per cluster.
    pub cluster_bytes: u32,
    /// Volume length in sectors, as stored in the boot sector.
    pub volume_length_sectors: u64,
    /// First sector of the FAT.
    pub fat_offset: u32,
    /// FAT length in sectors.
    pub fat_length: u32,
    /// First sector of the cluster heap.
    pub cluster_heap_offset: u32,
    /// Number of clusters in the heap.
    pub cluster_count: u32,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// First cluster of the allocation bitmap.
    pub bitmap_cluster: u32,
    /// Number of clusters the bitmap spans.
    pub bitmap_clusters: u32,
    /// Size of the bitmap in bytes (`ceil(cluster_count / 8)`).
    pub bitmap_bytes: u64,
}

impl Geometry {
    /// Resolve the layout for a volume of `total_bytes` with the given
    /// sector size, optionally overriding the cluster size.
    ///
    /// This is the only constructor: a `Geometry` cannot describe a
    /// layout the writer would then have to second-guess.
    pub fn resolve(
        total_bytes: u64,
        sector_size: u32,
        cluster_bytes_override: Option<u32>,
    ) -> Result<Self> {
        if !ACCEPTED_SECTOR_SIZES.contains(&sector_size) {
            return Err(CoreError::invalid(format!(
                "exfat supports 512 and 4096 byte sectors, not {sector_size}"
            )));
        }
        if total_bytes < MIN_VOLUME_BYTES {
            return Err(CoreError::invalid(format!(
                "exfat needs at least {} of volume, this one is {}",
                human_bytes(MIN_VOLUME_BYTES),
                human_bytes(total_bytes)
            )));
        }
        if total_bytes > MAX_VOLUME_BYTES {
            return Err(CoreError::invalid(format!(
                "exfat volumes stop at {}, this one is {}",
                human_bytes(MAX_VOLUME_BYTES),
                human_bytes(total_bytes)
            )));
        }

        let cluster_bytes = match cluster_bytes_override {
            Some(requested) => {
                check_cluster_bytes(requested, sector_size)?;
                requested
            }
            None => default_cluster_bytes(total_bytes),
        };

        let sectors_per_cluster = cluster_bytes / sector_size;
        let volume_length_sectors = total_bytes / u64::from(sector_size);
        // The layout is expressed in sectors, so a trailing partial
        // sector is simply not part of the volume (the same rule the
        // boot sector's VolumeLength follows).
        let align_sectors = u32::try_from(MIB / u64::from(sector_size)).map_err(|_| {
            CoreError::invalid(format!(
                "a 1 MiB alignment does not fit {sector_size} byte sectors"
            ))
        })?;

        // The FAT starts after the 24-sector boot region, on the heap's
        // alignment: this is what makes the layout reproducible.
        let fat_offset = align_up(24, align_sectors)?;
        let fat_start_bytes = u64::from(fat_offset) * u64::from(sector_size);
        if volume_length_sectors * u64::from(sector_size) <= fat_start_bytes {
            return Err(CoreError::invalid(format!(
                "{} is too small for an exFAT boot region",
                human_bytes(total_bytes)
            )));
        }

        // First estimate from the classic sizing formula, then grow the
        // FAT until it really covers the clusters the heap ends up with
        // (the heap alignment can move the boundary, so one pass is not
        // a proof).
        let per_cluster_cost = u64::from(cluster_bytes) + 4;
        let max_clusters = (total_bytes - fat_start_bytes - 8 - 1) / per_cluster_cost + 1;
        let max_clusters = u32::try_from(max_clusters.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let mut fat_length = fat_sectors_for(max_clusters, sector_size)?;

        loop {
            let heap_offset = align_up(fat_offset + fat_length, align_sectors)?;
            let heap_bytes = u64::from(heap_offset) * u64::from(sector_size);
            if heap_bytes >= total_bytes {
                return Err(CoreError::invalid(format!(
                    "{} is too small for an exFAT cluster heap of {} clusters",
                    human_bytes(total_bytes),
                    human_bytes(u64::from(cluster_bytes))
                )));
            }
            let cluster_count = (total_bytes - heap_bytes) / u64::from(cluster_bytes);
            let cluster_count = u32::try_from(cluster_count).map_err(|_| {
                CoreError::invalid(format!(
                    "exfat cluster count {cluster_count} does not fit 32 bits"
                ))
            })?;
            if cluster_count == 0 {
                return Err(CoreError::invalid(format!(
                    "{} is too small for one {} cluster",
                    human_bytes(total_bytes),
                    human_bytes(u64::from(cluster_bytes))
                )));
            }
            if cluster_count > MAX_CLUSTER_COUNT {
                return Err(CoreError::invalid(format!(
                    "exfat supports at most {MAX_CLUSTER_COUNT} clusters, {} of {} bytes would need {cluster_count}",
                    human_bytes(total_bytes),
                    human_bytes(u64::from(cluster_bytes))
                )));
            }

            let needed = fat_sectors_for(cluster_count, sector_size)?;
            if needed <= fat_length {
                let bitmap_bytes = u64::from(cluster_count).div_ceil(8);
                let bitmap_clusters = clusters_for(bitmap_bytes, cluster_bytes);
                let upcase_cluster = BITMAP_CLUSTER + bitmap_clusters;
                let upcase_clusters =
                    clusters_for(crate::fs::exfat::upcase::TABLE_BYTES, cluster_bytes);
                let root_cluster = upcase_cluster + upcase_clusters;
                if root_cluster >= cluster_count {
                    return Err(CoreError::invalid(format!(
                        "{} is too small to hold the exFAT system clusters",
                        human_bytes(total_bytes)
                    )));
                }
                return Ok(Self {
                    sector_size,
                    sectors_per_cluster,
                    cluster_bytes,
                    volume_length_sectors,
                    fat_offset,
                    fat_length,
                    cluster_heap_offset: heap_offset,
                    cluster_count,
                    root_cluster,
                    bitmap_cluster: BITMAP_CLUSTER,
                    bitmap_clusters,
                    bitmap_bytes,
                });
            }
            fat_length = needed;
        }
    }

    /// First cluster of the up-case table, which follows the bitmap.
    pub fn up_case_cluster(&self) -> u32 {
        self.bitmap_cluster + self.bitmap_clusters
    }

    /// Clusters the up-case table occupies.
    pub fn up_case_clusters(&self) -> u32 {
        clusters_for(crate::fs::exfat::upcase::TABLE_BYTES, self.cluster_bytes)
    }

    /// Bytes per cluster, as a `u64` for offset arithmetic.
    pub fn cluster_bytes(&self) -> u64 {
        u64::from(self.cluster_bytes)
    }

    /// Byte offset of `cluster`'s first byte inside the volume.
    ///
    /// Clusters 0 and 1 are reserved and have no bytes of their own, so
    /// they are refused rather than clipped.
    pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if cluster < FIRST_HEAP_CLUSTER {
            return Err(CoreError::invalid(format!(
                "cluster {cluster} is reserved in exFAT"
            )));
        }
        let index = u64::from(cluster - FIRST_HEAP_CLUSTER);
        let base = u64::from(self.cluster_heap_offset) * u64::from(self.sector_size);
        base.checked_add(index * self.cluster_bytes())
            .ok_or_else(|| CoreError::invalid(format!("cluster {cluster} offset overflows")))
    }

    /// Cluster that owns byte `offset`, if `offset` is inside the heap.
    pub fn cluster_of(&self, offset: u64) -> Option<u32> {
        let base = u64::from(self.cluster_heap_offset) * u64::from(self.sector_size);
        if offset < base {
            return None;
        }
        let index = (offset - base) / self.cluster_bytes();
        let cluster = u32::try_from(index).ok()?.checked_add(FIRST_HEAP_CLUSTER)?;
        (cluster < self.cluster_count + FIRST_HEAP_CLUSTER).then_some(cluster)
    }
}

/// The Windows / `mkfs.exfat` cluster-size ladder, measured on this
/// machine with exfatprogs 1.4.3: a 64 MiB and a 256 MiB volume get
/// 4 KiB clusters, 257 MiB through 32 GiB get 32 KiB, and anything
/// larger gets 128 KiB (the 2 TiB image included).
pub fn default_cluster_bytes(total_bytes: u64) -> u32 {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if total_bytes <= 256 * MIB {
        4096
    } else if total_bytes <= 32 * GIB {
        32 * 1024
    } else {
        128 * 1024
    }
}

/// Refuse a cluster size the formatter cannot place.
fn check_cluster_bytes(cluster_bytes: u32, sector_size: u32) -> Result<()> {
    if !(MIN_CLUSTER_BYTES..=MAX_CLUSTER_BYTES).contains(&cluster_bytes) {
        return Err(CoreError::invalid(format!(
            "an exFAT cluster is 4 KiB to 32 MiB, not {}",
            human_bytes(u64::from(cluster_bytes))
        )));
    }
    if !cluster_bytes.is_power_of_two() {
        return Err(CoreError::invalid(format!(
            "an exFAT cluster size must be a power of two, not {}",
            human_bytes(u64::from(cluster_bytes))
        )));
    }
    if !cluster_bytes.is_multiple_of(sector_size) {
        return Err(CoreError::invalid(format!(
            "a {} cluster is not a whole number of {sector_size} byte sectors",
            human_bytes(u64::from(cluster_bytes))
        )));
    }
    Ok(())
}

/// Round `value` up to the next multiple of `alignment`.
fn align_up(value: u32, alignment: u32) -> Result<u32> {
    if alignment == 0 {
        return Err(CoreError::invalid("alignment must not be zero"));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| CoreError::invalid(format!("{value} sectors overflow the 32-bit layout")))
}

/// Sectors a FAT covering `cluster_count` clusters needs, including the
/// two reserved entries. The `+2` is entries 0 and 1; the `div_ceil`
/// rounds a partial sector up, because the heap must start after a whole
/// FAT.
pub fn fat_sectors_for(cluster_count: u32, sector_size: u32) -> Result<u32> {
    let entries = u64::from(cluster_count) + 2;
    let bytes = entries
        .checked_mul(4)
        .ok_or_else(|| CoreError::invalid("exFAT FAT size overflows"))?;
    let sectors = bytes.div_ceil(u64::from(sector_size));
    u32::try_from(sectors)
        .map_err(|_| CoreError::invalid(format!("an exFAT FAT of {bytes} bytes is too large")))
}

/// Clusters needed to hold `bytes`.
pub(crate) fn clusters_for(bytes: u64, cluster_bytes: u32) -> u32 {
    let clusters = bytes.div_ceil(u64::from(cluster_bytes));
    u32::try_from(clusters).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Row = (u64, u32, u32, u32, u32);

    /// `(total_bytes, sectors_per_cluster, fat_length, heap_offset, cluster_count)`
    /// pinned against `dump.exfat` output from `mkfs.exfat` 1.4.3.
    const MEASURED: [Row; 2] = [
        (64 * MIB, 8, 126, 4096, 15_872),
        (2 * 1024 * MIB, 64, 512, 4096, 65_472),
    ];

    #[test]
    fn measured_rows_match_mkfs_exfat() {
        for (total, spc, fat, heap, clusters) in MEASURED {
            let geometry = Geometry::resolve(total, 512, None).expect("the row resolves");
            assert_eq!(
                geometry.sectors_per_cluster, spc,
                "sectors per cluster at {total}"
            );
            assert_eq!(geometry.fat_length, fat, "FAT length at {total}");
            assert_eq!(geometry.cluster_heap_offset, heap, "heap offset at {total}");
            assert_eq!(geometry.cluster_count, clusters, "cluster count at {total}");
        }
    }

    #[test]
    fn the_default_ladder_matches_the_measured_tiers() {
        assert_eq!(default_cluster_bytes(MIB), 4096);
        assert_eq!(default_cluster_bytes(64 * MIB), 4096);
        assert_eq!(default_cluster_bytes(256 * MIB), 4096);
        assert_eq!(default_cluster_bytes(257 * MIB), 32 * 1024);
        assert_eq!(default_cluster_bytes(32 * 1024 * MIB), 32 * 1024);
        assert_eq!(default_cluster_bytes(32 * 1024 * MIB + MIB), 128 * 1024);
        assert_eq!(default_cluster_bytes(MAX_VOLUME_BYTES), 128 * 1024);
    }

    #[test]
    fn an_explicit_cluster_size_is_honoured() {
        let geometry = Geometry::resolve(64 * MIB, 512, Some(32 * 1024)).expect("32 KiB clusters");
        assert_eq!(geometry.cluster_bytes, 32 * 1024);
        assert_eq!(geometry.sectors_per_cluster, 64);
        // 64 MiB over 32 KiB clusters is 2048 clusters, so the FAT is 16 sectors.
        assert_eq!(geometry.fat_length, 16);
    }

    #[test]
    fn cluster_sizes_outside_the_table_are_refused() {
        for bad in [1024, 2048, 64 * 1024 * 1024] {
            let error = Geometry::resolve(64 * MIB, 512, Some(bad)).expect_err("refused");
            assert!(
                error.to_string().contains("4 KiB to 32 MiB"),
                "an out-of-range cluster size names its own bounds: {error}"
            );
        }
        let error = Geometry::resolve(64 * MIB, 512, Some(3 * 1024 * 1024)).expect_err("refused");
        assert!(
            error.to_string().contains("power of two"),
            "a size inside the range but not a power of two says so: {error}"
        );
    }

    #[test]
    fn a_cluster_equal_to_the_sector_size_places_one_sector_per_cluster() {
        let geometry =
            Geometry::resolve(256 * MIB, 4096, Some(4096)).expect("an equal cluster fits");
        assert_eq!(geometry.sectors_per_cluster, 1);
    }

    #[test]
    fn sector_sizes_outside_the_pair_are_refused() {
        for bad in [1024, 2048, 8192] {
            let error = Geometry::resolve(64 * MIB, bad, None).expect_err("refused");
            assert!(error.to_string().contains("sector"), "{error}");
        }
    }

    #[test]
    fn the_volume_floor_is_the_documented_three_mib() {
        // The floor is a policy, so pin its value and both sides of it: a
        // relative comparison against the constant cannot notice the
        // constant moving.
        assert_eq!(MIN_VOLUME_BYTES, 3 * MIB);
        Geometry::resolve(3 * MIB, 512, None).expect("3 MiB resolves");
        let refused = Geometry::resolve(3 * MIB - 512, 512, None).expect_err("below the floor");
        assert!(refused.to_string().contains("3.00 MiB"), "{refused}");
    }

    #[test]
    fn volumes_outside_the_supported_range_are_refused() {
        let small = Geometry::resolve(MIN_VOLUME_BYTES - 512, 512, None).expect_err("too small");
        assert!(small.to_string().contains("at least"), "{small}");
        let large = Geometry::resolve(MAX_VOLUME_BYTES + 512, 512, None).expect_err("too large");
        assert!(large.to_string().contains("stop at"), "{large}");
    }

    #[test]
    fn the_two_tebibyte_ceiling_still_resolves() {
        let geometry = Geometry::resolve(MAX_VOLUME_BYTES, 512, None).expect("2 TiB resolves");
        assert_eq!(geometry.cluster_bytes, 128 * 1024);
        assert!(geometry.cluster_count > 16_000_000);
        assert!(u64::from(geometry.cluster_count) <= u64::from(MAX_CLUSTER_COUNT));
    }

    #[test]
    fn system_clusters_sit_inside_the_heap() {
        for (total, _, _, _, clusters) in MEASURED {
            let geometry = Geometry::resolve(total, 512, None).expect("resolves");
            assert_eq!(geometry.bitmap_cluster, 2);
            assert!(geometry.bitmap_clusters >= 1);
            assert!(geometry.root_cluster > geometry.bitmap_cluster + geometry.bitmap_clusters);
            assert!(geometry.root_cluster < clusters);
            assert_eq!(
                geometry.bitmap_bytes,
                u64::from(clusters).div_ceil(8),
                "bitmap covers every cluster"
            );
        }
    }

    #[test]
    fn cluster_offsets_start_after_the_heap() {
        let geometry = Geometry::resolve(64 * MIB, 512, None).expect("resolves");
        let heap = u64::from(geometry.cluster_heap_offset) * 512;
        assert_eq!(geometry.cluster_offset(2).expect("heap start"), heap);
        assert_eq!(
            geometry.cluster_offset(3).expect("second cluster"),
            heap + u64::from(geometry.cluster_bytes)
        );
        assert!(geometry.cluster_offset(0).is_err());
        assert!(geometry.cluster_offset(1).is_err());
        assert_eq!(geometry.cluster_of(heap), Some(2));
        assert_eq!(geometry.cluster_of(heap - 1), None);
        assert_eq!(
            geometry
                .cluster_of(heap + u64::from(geometry.cluster_count) * geometry.cluster_bytes()),
            None
        );
    }

    #[test]
    fn the_fat_always_covers_every_cluster_and_its_two_reserved_entries() {
        for total in [
            MIN_VOLUME_BYTES,
            64 * MIB,
            260 * MIB,
            2 * 1024 * MIB,
            MAX_VOLUME_BYTES,
        ] {
            let geometry = Geometry::resolve(total, 512, None).expect("resolves");
            let covered = u64::from(geometry.fat_length) * 512 / 4;
            assert!(
                covered >= u64::from(geometry.cluster_count) + 2,
                "FAT covers {covered} entries at {total}, needs {}",
                u64::from(geometry.cluster_count) + 2
            );
        }
    }

    #[test]
    fn four_kn_sectors_place_a_single_sector_cluster() {
        let geometry = Geometry::resolve(256 * MIB, 4096, None).expect("4Kn resolves");
        assert_eq!(geometry.sector_size, 4096);
        assert_eq!(geometry.cluster_bytes, 4096);
        assert_eq!(geometry.sectors_per_cluster, 1);
        assert_eq!(geometry.volume_length_sectors, 256 * MIB / 4096);
    }

    #[test]
    fn a_cluster_size_the_volume_cannot_hold_is_refused() {
        // 3 MiB leaves a 1 MiB heap after the aligned FAT, which cannot
        // hold a single 32 MiB cluster.
        let error = Geometry::resolve(MIN_VOLUME_BYTES, 512, Some(32 * 1024 * 1024))
            .expect_err("no room for one cluster");
        assert!(error.to_string().contains("too small"), "{error}");
        // The smallest accepted volume does resolve at the default size.
        let geometry = Geometry::resolve(MIN_VOLUME_BYTES, 512, None).expect("the floor resolves");
        assert!(geometry.cluster_count >= 1);
        assert!(geometry.root_cluster < geometry.cluster_count);
    }
}
