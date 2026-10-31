//! The FAT32 geometry resolver (S09 part A): everything a `Volume`
//! byte count and sector size imply about clusters, FAT size and the
//! refusal boundaries.
//!
//! [`geometry(total_bytes, sector_size)`] mirrors the Rufus small/large
//! FAT32 behaviour (PLAN §9-S09 "512 B–64 KiB, large FAT32 above
//! 32 GiB, 2 TiB limit check, cluster count validation"): the cluster
//! tier ladder follows the Rufus `format.c` class table, the FAT size
//! keeps the slack sector real formatters pad with, and the resulting
//! geometry is checked against the FAT32 cluster-count law — fewer than
//! 65,525 data clusters is FAT16 territory and is refused rather than
//! silently formatted as a fake FAT32.
//!
//! The one number this module *solves* rather than looks up is the
//! cluster/fat-size fixed point: `cluster_count` depends on
//! `fat_sectors`, which depends on `cluster_count`. [`solve_table`]
//! iterates it. Two array facts make the loop honest (see the docs
//! there): the iteration is monotone non-increasing after the first
//! round and provably settles within a handful of rounds for any size
//! whose map owns a fixed point — sizes whose map has none (a small
//! measured set, all clustered around ±2-cluster boundaries) end on the
//! smaller leg of their 2-cycle, which is the self-consistent leg.
//!
//! [`geometry(total_bytes, sector_size)`]: geometry

use crate::error::CoreError;
use crate::error::Result;
use crate::units::human_bytes;

/// Reserved sectors between the boot sectors and the first FAT: the
/// FAT32 spec-mandated 32 that holds the boot sector (0), its backup
/// (6), the FSInfo (1) and its backup (7) — Rufus writes the same 32.
pub const RESERVED_SECTORS: u32 = 32;
/// Number of FAT copies: 2, the FAT32 spec value and exactly what
/// Rufus lays out (both written, neither mirrored automatically —
/// ext flags stay 0).
pub const NUM_FATS: u8 = 2;
/// First valid cluster number. FAT entry 0 and 1 are the media/id
/// scaffolding; clusters start counting at 2, which is also where the
/// root directory lives.
pub const ROOT_CLUSTER: u32 = 2;
/// The FSInfo structure lives in reserved sector 1 (the EBPB carries
/// the pointer) — the FAT32 spec position Rufus writes.
pub const FSINFO_SECTOR: u32 = 1;
/// Backup copy of the boot sector, at reserved sector 6 — the FAT32
/// spec position, written byte-identically to sector 0.
pub const BACKUP_BOOT_SECTOR: u32 = 6;
/// Fewest data clusters a legal FAT32 volume owns (the count the
/// Windows FAT family logic -- and every formatter following it, Rufus
/// included -- uses to decide "this is no longer FAT16").
pub const MIN_CLUSTERS: u32 = 65_525;
/// Most data clusters the FAT32 extended format can name
/// (`0x0FFFFFF5`): entry values `0x0FFFFFF6`..`0x0FFFFFFF` are bad/EoC
/// scaffolding. Under the 2 TiB and 64 KiB cluster caps this is never
/// reachable (33.55 M clusters at most) — the check is enforced anyway
/// so the invariant survives future tier edits.
pub const MAX_CLUSTERS: u32 = 0x0FFF_FFF5;
/// The 2 TiB FAT32 ceiling Rufus carries for large-FAT32 volumes.
pub const MAX_VOLUME_BYTES: u64 = 2 * 1024_u64.pow(4);

/// Sector sizes the formatter accepts. `512` covers every normal
/// drive; `4096` covers 4Kn media (the S05 device reporter surfaces
/// `LOGICAL SECTOR SIZE 4096`).
const ACCEPTED_SECTOR_SIZES: [u32; 2] = [512, 4096];

/// Byte-based cluster tiers, sorted rising: every volume whose byte
/// size is below the row's threshold takes that row's cluster size and
/// the last row is the large-FAT32 floor.
///
/// This is the Rufus large-FAT32 table, byte for byte:
///
/// * under 260 MiB the "small FAT32" window uses 512-byte clusters to
///   keep the cluster count (not the volume) FAT32-legal — on 4Kn
///   media ([`geometry`]) a tier smaller than one sector clamps up to
///   the sector size, so a cluster always spans at least one sector;
/// * under 8 GiB, 4 KiB; under 16 GiB, 8 KiB; under 32 GiB, 16 KiB —
///   the classic Windows FAT32 sizes;
/// * 32 GiB and above, 64 KiB clusters — the "large FAT32" layout
///   Windows itself refuses but USB makers keep using.
///
/// Thresholds compare against the *volume* size, not the data span, so
/// a row flip lands within one sector of the named boundary.
const CLUSTER_TIERS: [(u64, u64); 4] = [
    (260 * 1024 * 1024, 512),
    (8 * 1024_u64.pow(3), 4 * 1024),
    (16 * 1024_u64.pow(3), 8 * 1024),
    (32 * 1024_u64.pow(3), 16 * 1024),
];
/// Cluster size for volumes at or beyond the last tier threshold: the
/// large-FAT32 64 KiB cluster.
const LARGE_CLUSTER_BYTES: u64 = 64 * 1024;

/// Most fixed-point rounds the solver may burn (see [`solve_table`]).
/// The delta argument in its docs bounds the settling depth by
/// `log(2^32)/log(64) ≈ 5.4` plus the first collapse, so 8 rounds is
/// headroom, not a magic constant tuned to a test.
const FIXED_POINT_ROUNDS: u8 = 8;

/// The resolved FAT32 layout of one volume: the numbers the BPB
/// carries and the byte windows every later write must live inside.
///
/// Build it through [`geometry`]; the fields would let a caller forge an
/// inconsistent layout by hand otherwise. [`cluster_offset`] is the
/// gate every cluster-relative write funnels through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Sector size the volume was formatted for (512 or 4096).
    pub bytes_per_sector: u16,
    /// Clusters of exactly this many sectors split the data area
    /// (1 at the small end, 128 for large-FAT32 volumes).
    pub sectors_per_cluster: u32,
    /// Reserved sectors before the FATs (the 32 above; the EBPB and
    /// FSInfo live inside).
    pub reserved_sectors: u32,
    /// FAT copies laid out back-to-back (2).
    pub num_fats: u8,
    /// FAT16-era root directory entry cap, always 0 here: FAT32 keeps
    /// only the cluster chain (the BPB field is carried over zeroed).
    pub root_entries: u16,
    /// Total sectors the volume maps, truncating a trailing partial
    /// sector (see [`geometry`]).
    pub total_sectors: u32,
    /// FAT size in sectors including the trailing slack sector of
    /// [`solve_table`].
    pub fat_sectors: u32,
    /// Cluster number the root directory starts at (2).
    pub root_cluster: u32,
    /// Data clusters the volume provides, 2 through
    /// `cluster_count + 1` numbered.
    pub cluster_count: u32,
    /// Volume bytes the geometry was resolved for — the caller's
    /// `Volume::total_bytes` reading, kept verbatim so the formatter's
    /// size cross-check has both ends. A trailing partial sector is
    /// *not* part of the mapped data (it is simply unpublishable
    /// sector-leftover byteage; see [`geometry`]).
    pub total_bytes: u64,
}

impl Geometry {
    /// Bytes each cluster spans (`sectors_per_cluster *
    /// bytes_per_sector`). No overflow: the tier table caps both
    /// factors (at most 128 sectors of at most 4096 bytes).
    #[must_use]
    pub fn cluster_bytes(&self) -> u64 {
        u64::from(self.sectors_per_cluster) * u64::from(self.bytes_per_sector)
    }

    /// Byte offset of the first FAT (the reserved area's end).
    /// No overflow: 32 reserved sectors of at most 4096 bytes.
    #[must_use]
    pub fn fat_offset(&self) -> u64 {
        u64::from(self.reserved_sectors) * u64::from(self.bytes_per_sector)
    }

    /// Byte length of one FAT copy, including its slack sector.
    /// No overflow: at most ~134 MB of FAT fits a 2 TiB volume at
    /// 4096-byte sectors.
    #[must_use]
    pub fn fat_length_bytes(&self) -> u64 {
        u64::from(self.fat_sectors) * u64::from(self.bytes_per_sector)
    }

    /// First sector of the data area (after reserved + 2 FATs). Both
    /// factors stay far below `u32::MAX` under the documented caps
    /// (reserved 32; FAT 262,113 sectors at the 2 TiB wall), so the
    /// saturating adds never actually saturate — they exist for
    /// totality, mirroring every reader in [`crate::part`].
    #[must_use]
    pub fn first_data_sector(&self) -> u32 {
        self.reserved_sectors
            .saturating_add(self.fat_sectors.saturating_mul(u32::from(self.num_fats)))
    }

    /// Absolute byte offset of `cluster`, `None` when the number is
    /// not a data cluster in this geometry.
    ///
    /// Cluster numbering starts at 2 (0 and 1 are FAT scaffolding; a
    /// *cluster 1* would point into reserved area — invalid), and the
    /// last valid number is `cluster_count + 1`. Overflow checks fall
    /// out as `None` the same as the range checks do.
    #[must_use]
    pub fn cluster_offset(&self, cluster: u32) -> Option<u64> {
        if cluster < ROOT_CLUSTER {
            return None;
        }
        let index = u64::from(cluster.checked_sub(ROOT_CLUSTER)?);
        if index >= u64::from(self.cluster_count) {
            return None;
        }
        let relative = index.checked_mul(u64::from(self.sectors_per_cluster))?;
        u64::from(self.first_data_sector())
            .checked_add(relative)
            .and_then(|sectors| sectors.checked_mul(u64::from(self.bytes_per_sector)))
    }
}

/// Resolve the FAT32 geometry for a volume of `total_bytes` laid out
/// on `sector_size`-byte sectors.
///
/// Refusals (all [`CoreError::invalid`], ASCII, numbers in the form
/// that reads best):
///
/// * `sector_size` is neither 512 nor 4096 — the message names the
///   handed value;
/// * the volume exceeds the 2 TiB FAT32 limit;
/// * the truncating sector count would not fit the BPB 32-bit total
///   field (`u32::MAX` sectors maximum);
/// * fewer than [`MIN_CLUSTERS`] data clusters (the caller asked for a
///   FAT *16*-small volume under a FAT *32* formatter; smallest legal
///   size at 512-byte sectors, measured by exhaustive search over the
///   512-aligned sizes: 34,090,496 bytes ≈ 34.09 MB);
/// * more than [`MAX_CLUSTERS`] data clusters — enforced, though the
///   2 TiB × 64 KiB caps keep it unreachable today (see the const).
///
/// `total_bytes` is accepted as handed and mapped to `total_sectors`
/// truncating: a trailing partial sector is simply not part of the
/// volume (nobody can address a fraction of what the store reports).
/// The field [`Geometry::total_bytes`] keeps the caller's reading so
/// the formatter can name both numbers in its cross-check.
pub fn geometry(total_bytes: u64, sector_size: u32) -> Result<Geometry> {
    if !ACCEPTED_SECTOR_SIZES.contains(&sector_size) {
        return Err(CoreError::invalid(format!(
            "sector size {sector_size} is not supported: fat32 writes 512 and 4096 byte sectors only"
        )));
    }
    if total_bytes > MAX_VOLUME_BYTES {
        return Err(CoreError::invalid(format!(
            "volume size {} exceeds the fat32 limit of {}",
            human_bytes(total_bytes),
            human_bytes(MAX_VOLUME_BYTES)
        )));
    }
    let bytes_per_sector: u16 = sector_size as u16;
    let sector: u64 = u64::from(bytes_per_sector);
    // Truncating map, by design (see the function doc): the leftover
    // bytes cannot form a sector.
    let total_sectors = total_bytes / sector;
    if total_sectors > u64::from(u32::MAX) {
        return Err(CoreError::invalid(format!(
            "{} volume bytes map to {total_sectors} sectors which exceeds the u32 {} boot sector field",
            human_bytes(total_bytes),
            4_294_967_295u64
        )));
    }
    let tier_bytes = cluster_bytes_for(total_bytes);
    // A cluster occupies at least one sector: on 4096-byte-sector media
    // the sub-260-MiB 512-byte tier is smaller than one sector, so the
    // tier clamps up (`max(1)`) and the cluster spans exactly one 4Kn
    // sector — `cluster_bytes = max(tier, sector)`. Without the clamp a
    // 512/4096 division lands at 0 and the solver below would divide
    // by it (panicked on every sub-260-MiB 4Kn volume).
    let sectors = (tier_bytes / sector).max(1);
    let sectors_per_cluster: u32 = sectors.try_into().map_err(|_| {
        CoreError::invalid(format!(
            "sectors per cluster {sectors} does not fit the 32-bit fat32 addressing"
        ))
    })?;
    let (fat_sectors, cluster_count) =
        solve_table(total_sectors, u64::from(sectors_per_cluster), sector)?;
    if cluster_count < MIN_CLUSTERS {
        return Err(CoreError::invalid(format!(
            "fat32 needs at least {MIN_CLUSTERS} data clusters, a {} volume provides {cluster_count}",
            human_bytes(total_bytes)
        )));
    }
    if cluster_count > MAX_CLUSTERS {
        return Err(CoreError::invalid(format!(
            "fat32 allows at most {MAX_CLUSTERS} data clusters, this volume provides {cluster_count}"
        )));
    }
    let total_sectors: u32 = total_sectors as u32;
    Ok(Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors: RESERVED_SECTORS,
        num_fats: NUM_FATS,
        root_entries: 0,
        total_sectors,
        fat_sectors,
        root_cluster: ROOT_CLUSTER,
        cluster_count,
        total_bytes,
    })
}

/// Cluster size in bytes a volume of `total_bytes` gets, per the Rufus
/// tier ladder ([`CLUSTER_TIERS`] documents each row).
fn cluster_bytes_for(total_bytes: u64) -> u64 {
    for (below, bytes) in CLUSTER_TIERS {
        if total_bytes < below {
            return bytes;
        }
    }
    LARGE_CLUSTER_BYTES
}

/// FAT size in sectors for `clusters` data clusters:
/// `ceil((clusters + 2) * 4 / bytes_per_sector) + 1`.
///
/// The trailing `+1` is the slack sector real formatters keep; measured
/// against `mkfs.fat 4.2` on this machine (64 MiB, 512-byte sectors)
/// it produces exactly the same numbers this crate does — FAT 1009
/// sectors and 129,022 data clusters — so the formula mirrors that
/// layout rather than diverging from it, and the FAT never butts
/// against the first data sector.
fn fat_sectors_for(clusters: u64, bytes_per_sector: u64) -> Result<u64> {
    let table_bytes = clusters
        .checked_add(2)
        .and_then(|entries| entries.checked_mul(4))
        .ok_or_else(|| CoreError::invalid("fat32 entry table does not fit u64 bytes"))?;
    let sectors = table_bytes.div_ceil(bytes_per_sector);
    sectors
        .checked_add(1)
        .ok_or_else(|| CoreError::invalid("fat32 entry table does not fit u64 sectors"))
}

/// Solve the `cluster_count ↔ fat_sectors` mutual dependency.
///
/// `cluster_count = floor((total − 32 − 2·fat) / spc)` and
/// `fat = ceil((count + 2)·4 / bps) + 1` feed on each other, so the
/// plan is fixed-point iteration: start with `fat = 0` (the maximal
/// cluster estimate `count₀ = floor((total − 32)/spc)`), then
/// alternate.
///
/// Properties that make the bounded loop honest (both `fat(·)` and
/// the data span shrink as `count` grows):
///
/// * the step `count ↦ floor((total − 32 − 2·fat(count)) / spc)` is
///   *non-increasing* in `count` while count grows at round *n*, so
///   the sequence never rises;
/// * consecutive deltas shrink by a factor near
///   `8 / (bps · spc)` — each lost cluster costs 4 FAT bytes, so 2
///   lost data sectors per sector grown... precisely: `Δclusters ≈
///   8·Δclusters_prev / (bps·spc)`, and `bps·spc ≥ 4096` on every
///   reachable combination (512·1 at the smallest), giving a
///   geometric shrink of at worst `/64` per round. From the first
///   estimate bounded by 2³² that is `log₂(2³²)/log₂(64) ≈ 5.34`
///   shrinking rounds; 8 rounds is proven headroom, and the measured
///   worst case everywhere (exhaustive below 512 MiB, sampled above)
///   is 3.
/// * a map without a fixed point cannot drain: the sequence traps
///   into a 2-cycle (`fat(count)` flips one sector across the floor
///   boundary). Measured exhaustively below 512 MiB and by sampling
///   above: cycle legs differ by at most 2 clusters, and the smaller
///   leg is always self-consistent — with `fat(smaller)` the data
///   span still holds *both* legs (that is exactly why the cycle
///   keeps bouncing). Taking the smaller leg is therefore the
///   conservative, deterministic resolution; the invariant
///   `reserved + 2·fat + clusters·spc ≤ total` still holds.
///
/// At most [`FIXED_POINT_ROUNDS`] rounds, stopping as soon as a round
/// changes nothing. `(u32 cluster count, u32 fat sectors)` narrowed
/// after the caller's own gates; an arithmetic surprise surfaces as
/// [`CoreError::invalid`] rather than a panic.
fn solve_table(
    total_sectors: u64,
    sectors_per_cluster: u64,
    bytes_per_sector: u64,
) -> Result<(u32, u32)> {
    let reserved = u64::from(RESERVED_SECTORS);
    let mut clusters = total_sectors.saturating_sub(reserved) / sectors_per_cluster;
    let mut previous = clusters;
    let mut fat = 0_u64;
    let mut rounds = 0_u8;
    let mut stable = false;
    while rounds < FIXED_POINT_ROUNDS {
        fat = fat_sectors_for(clusters, bytes_per_sector)?;
        let data_sectors = total_sectors
            .checked_sub(reserved)
            .and_then(|rest| rest.checked_sub(fat.checked_mul(2)?));
        let next = data_sectors.unwrap_or(0) / sectors_per_cluster;
        if next == clusters {
            stable = true;
            break;
        }
        previous = clusters;
        clusters = next;
        rounds += 1;
    }
    if !stable {
        // Ran out of rounds on a 2-cycle (see the doc): fall onto the
        // smaller, provably self-consistent leg and take that FAT.
        clusters = clusters.min(previous);
        fat = fat_sectors_for(clusters, bytes_per_sector)?;
    }
    let cluster_count = u32::try_from(clusters).map_err(|_| {
        CoreError::invalid(format!(
            "cluster count {clusters} does not fit the 32-bit fat32 addressing"
        ))
    })?;
    let fat_sectors = u32::try_from(fat).map_err(|_| {
        CoreError::invalid(format!(
            "fat size {fat} sectors does not fit the 32-bit fat32 addressing"
        ))
    })?;
    Ok((fat_sectors, cluster_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One pinned table row: (`name`, volume bytes, sector size,
    /// (`spc`, `fat_sectors`, `cluster_count`)).
    type GeometryRow = (&'static str, u64, u32, (u32, u32, u32));

    /// The pinned (size, sector) → (spc, fat_sectors, cluster_count)
    /// table. Everything here was computed mechanically from
    /// `geometry`'s own rules before being pinned; each row also
    /// carries the note of what it pins (a tier row, a boundary walk
    /// or the giants).
    const TABLE: [GeometryRow; 17] = [
        // (name, bytes, sector_size, (expected spc, fat, clusters))
        ("34 MiB", 34 * 1024 * 1024, 512, (1, 537, 68_526)),
        ("64 MiB", 64 * 1024 * 1024, 512, (1, 1009, 129_022)),
        ("260 MiB", 260 * 1024 * 1024, 512, (8, 520, 66_426)),
        ("2 GiB", 2 * 1024 * 1024 * 1024, 512, (8, 4089, 523_261)),
        ("8 GiB", 8 * 1024 * 1024 * 1024, 512, (16, 8185, 1_047_550)),
        (
            "16 GiB",
            16 * 1024 * 1024 * 1024,
            512,
            (32, 8190, 1_048_063),
        ),
        ("32 GiB", 32 * 1024 * 1024 * 1024, 512, (128, 4097, 524_223)),
        (
            "64 GiB",
            64 * 1024 * 1024 * 1024,
            512,
            (128, 8193, 1_048_447),
        ),
        (
            "2 TiB minus 1 MiB",
            2 * 1024_u64.pow(4) - 1024 * 1024,
            512,
            (128, 262_113, 33_550_320),
        ),
        // one 4096-byte-sector row per regime: the tier ladder rides on
        // volume bytes, so the sectors/cluster halve fourfold less: a
        // 2 TiB class 4Kn volume stays inside the u32 sector field.
        ("2 GiB 4Kn", 2 * 1024 * 1024 * 1024, 4096, (1, 512, 523_232)),
        (
            "32 GiB 4Kn",
            32 * 1024 * 1024 * 1024,
            4096,
            (16, 513, 524_221),
        ),
        // 4Kn at the small-FAT32 tier boundary: below 260 MiB the tier
        // says 512 bytes, which is smaller than one 4Kn sector, so the
        // tier clamps up to a one-sector cluster (spc 1) — 260 MiB
        // minus one sector sits under the boundary, 260 MiB exactly on
        // it (the row's tier is 4096 there — `260 < 260` is false).
        (
            "260 MiB minus one 4Kn sector",
            260 * 1024 * 1024 - 4096,
            4096,
            (1, 66, 66_395),
        ),
        ("260 MiB 4Kn", 260 * 1024 * 1024, 4096, (1, 66, 66_396)),
        // tier boundaries walked on both sides: the lower boundary is
        // exclusive (`<`), the upper row is the volume exactly at it.
        (
            "260 MiB minus 512 B",
            260 * 1024 * 1024 - 512,
            512,
            (1, 4097, 524_253),
        ),
        (
            "8 GiB minus 512 B",
            8 * 1024 * 1024 * 1024 - 512,
            512,
            (8, 16_354, 2_093_059),
        ),
        (
            "16 GiB minus 512 B",
            16 * 1024 * 1024 * 1024 - 512,
            512,
            (16, 16_370, 2_095_103),
        ),
        (
            "32 GiB minus 512 B",
            32 * 1024 * 1024 * 1024 - 512,
            512,
            (32, 16_378, 2_096_127),
        ),
    ];

    fn assert_table_row(name: &str, bytes: u64, sector: u32, want: (u32, u32, u32)) {
        let g = geometry(bytes, sector).unwrap_or_else(|error| panic!("refused {name}: {error}"));
        let got = (g.sectors_per_cluster, g.fat_sectors, g.cluster_count);
        assert_eq!(got, want, "geometry of {name}");
        assert_eq!(g.bytes_per_sector, sector as u16, "{name} sector size");
        assert_eq!(g.num_fats, NUM_FATS, "{name} fat copies");
        assert_eq!(g.reserved_sectors, RESERVED_SECTORS, "{name} reserved");
        assert_eq!(g.root_cluster, ROOT_CLUSTER, "{name} root cluster");
        assert_eq!(g.root_entries, 0, "{name} carries the FAT16 hole as 0");
        assert_eq!(
            g.total_sectors,
            (bytes / u64::from(sector)) as u32,
            "{name} sector map"
        );
        assert_eq!(g.total_bytes, bytes, "{name} keeps the caller's reading");

        // the cluster-vs-sector law of every row: a cluster occupies at
        // least one sector (the 4Kn clamp of `geometry` below the
        // 260 MiB boundary included)
        assert!(
            g.sectors_per_cluster >= 1,
            "{name}: sectors per cluster is at least one"
        );
        assert!(
            g.cluster_bytes() >= u64::from(g.bytes_per_sector),
            "{name}: a cluster ({} bytes) spans at least one sector ({})",
            g.cluster_bytes(),
            g.bytes_per_sector
        );

        // the layout invariant the formatter trusts: reserved plus
        // both FATs plus the clusters stays inside the volume's
        // sector count
        let used = u64::from(g.reserved_sectors)
            + u64::from(g.num_fats) * u64::from(g.fat_sectors)
            + u64::from(g.cluster_count) * u64::from(g.sectors_per_cluster);
        assert!(
            used <= u64::from(g.total_sectors),
            "{name}: reserved + both FATs + clusters ({used}) must stay inside \
             the volume's {} sectors",
            g.total_sectors
        );
        // ... and the data area starts exactly at the FATs' end
        assert_eq!(
            g.first_data_sector(),
            g.reserved_sectors + 2 * g.fat_sectors,
            "{name} data start"
        );
        // the root cluster is the FAT32 first data cluster and
        // resolves to its own byte window
        assert_eq!(
            g.cluster_offset(g.root_cluster),
            Some(u64::from(g.first_data_sector()) * u64::from(g.bytes_per_sector)),
            "{name} root cluster bytes"
        );
    }

    #[test]
    fn geometry_table_pinned_sizes() {
        for (name, bytes, sector, want) in TABLE {
            assert_table_row(name, bytes, sector, want);
        }
    }

    #[test]
    fn sub_floor_4kn_volumes_refuse_instead_of_panicking() {
        // Below 260 MiB the small-FAT32 tier (512 bytes) is smaller
        // than one 4096-byte sector; the clamp (`max(1)`) keeps the
        // solver alive and the cluster law, not a division by zero,
        // answers. Both sizes panicked before the clamp (measured on
        // the pre-fix code); each one's true cluster count is pinned.
        for (mib_label, bytes, clusters_offered) in [
            ("34.00 MiB", 34 * 1024 * 1024_u64, 8_652_u32),
            ("64.00 MiB", 64 * 1024 * 1024, 16_318),
        ] {
            let error =
                geometry(bytes, 4096).expect_err("below the 65525-cluster FAT32 floor at 4Kn");
            let text = error.to_string();
            assert!(text.contains("at least 65525"), "{text}");
            assert!(text.contains(&clusters_offered.to_string()), "{text}");
            assert!(
                text.contains(mib_label),
                "the refusal names the volume size {mib_label}: {text}"
            );
        }
    }

    #[test]
    fn mkfs_fat_reference_row_matches_the_measured_layout() {
        // Measured on this machine with mkfs.fat 4.2 (dosfstools), per
        // the slice brief: `mkfs.fat -F 32 -n RUFUS` on a 64 MiB image
        // yields bytes/sector 512, spc 1, reserved 32, 2 FATs, root
        // entries 0, total32 131072, FAT size 1009, root cluster 2,
        // FSInfo 1, backup 6, label set, and `fsck.fat -n` reports
        // `1/129022 clusters` — identical to this solver on every
        // field, including the FAT size and the cluster count. The
        // pinned 64 MiB row above therefore agrees with the reference
        // formatter field for field; the tier ladder is not treated as
        // an "ours differs" island anywhere.
        let g = geometry(64 * 1024 * 1024, 512).expect("64 MiB");
        assert_eq!(g.sectors_per_cluster, 1);
        assert_eq!(g.fat_sectors, 1009, "the slack lands on 1009 there too");
        assert_eq!(g.cluster_count, 129_022);
    }

    #[test]
    fn refusals_including_boundary() {
        // The measured smallest legal size at 512-byte sectors:
        // 34,090,496 bytes map to 66,583 sectors; the fixed point
        // resolves to FAT 513 sectors and (66,583 - 32 - 2·513) =
        // 65,525 data clusters — exactly `MIN_CLUSTERS`. One sector
        // below (34,089,984 bytes) resolves to 65,524 and is refused.
        // The slice brief names 33 MiB as a refusal, but under the
        // pinned rules 33 MiB resolves to 66,510 clusters *above* the
        // minimum (mkfs.fat 4.2 confirms it formats fine); the honest
        // boundary is pinned here instead of bending the rules to the
        // size.
        let boundary = 34_090_496_u64;
        assert_eq!(
            geometry(boundary, 512)
                .expect("the boundary itself formats")
                .cluster_count,
            MIN_CLUSTERS
        );
        let error = geometry(boundary - 512, 512).unwrap_err();
        assert!(error.to_string().contains("at least 65525"), "{error}");

        // 32 MiB (the flagrantly small case, 64,494 clusters)
        let error = geometry(32 * 1024 * 1024, 512).unwrap_err();
        assert!(error.to_string().contains("at least 65525"), "{error}");

        // zero bytes provide zero clusters and are refused by the same
        // cluster law (not a separate "empty" error class)
        let error = geometry(0, 512).unwrap_err();
        assert!(error.to_string().contains("at least 65525"), "{error}");

        // sector size gate
        let error = geometry(64 * 1024 * 1024, 1024).unwrap_err();
        assert!(error.to_string().contains("1024"), "{error}");

        // the 2 TiB ceiling itself is one sector too many at 512-byte
        // sectors (2^32 > u32::MAX) and refused through the sector law
        let error = geometry(2 * 1024_u64.pow(4), 512).unwrap_err();
        assert!(error.to_string().contains("exceeds the u32"), "{error}");

        // 3 TiB hits the 2 TiB law first
        let error = geometry(3 * 1024_u64.pow(4), 512).unwrap_err();
        assert!(
            error.to_string().contains("exceeds the fat32 limit"),
            "{error}"
        );

        // u64::MAX does both, 2 TiB verdict first (the law order is
        // pinned: human-readable size before sector arithmetic)
        let error = geometry(u64::MAX, 512).unwrap_err();
        assert!(
            error.to_string().contains("exceeds the fat32 limit"),
            "{error}"
        );
    }

    #[test]
    fn cluster_offset_bounds() {
        let g = geometry(64 * 1024 * 1024, 512).expect("64 MiB");
        // clusters 0 and 1 are reserved-accounting, never addressable
        assert_eq!(g.cluster_offset(0), None);
        assert_eq!(g.cluster_offset(1), None);
        // 2 is the first, cluster_count + 1 the last valid number
        assert_eq!(
            g.cluster_offset(2),
            Some(g.first_data_sector() as u64 * u64::from(g.bytes_per_sector))
        );
        let last = g.cluster_offset(g.cluster_count + 1);
        assert_ne!(last, None, "the last cluster resolves");
        // and the one past both ends is None
        assert_eq!(g.cluster_offset(g.cluster_count + 2), None);
        assert_eq!(g.cluster_offset(u32::MAX), None);
        // monotone in cluster number
        let mut previous = 0;
        for cluster in 2..=g.cluster_count + 1 {
            let offset = g.cluster_offset(cluster).expect("reachable cluster");
            assert!(offset > previous);
            previous = offset;
        }
    }

    #[test]
    fn two_cycle_sizes_take_the_smaller_leg_deterministically() {
        // Measured example of the 2-cycle family (see `solve_table`):
        // 34,095,616 bytes bounces between 65,535 and 65,533 clusters;
        // the smaller leg is taken and stays self-consistent.
        let g = geometry(34_095_616, 512).expect("2-cycle-size formats");
        assert_eq!(g.cluster_count, 65_533);
        assert_eq!(g.fat_sectors, 513);
        let used = u64::from(g.reserved_sectors)
            + 2 * u64::from(g.fat_sectors)
            + u64::from(g.cluster_count) * u64::from(g.sectors_per_cluster);
        assert!(
            used <= g.total_sectors as u64,
            "the invariant holds on the cycle-resolved leg ({used} of {})",
            g.total_sectors
        );
        // deterministic every time
        let again = geometry(34_095_616, 512).expect("same size again");
        assert_eq!(g, again);
    }

    #[test]
    fn trailing_partial_sector_is_truncated_not_refused() {
        let clean = geometry(64 * 1024 * 1024, 512).expect("clean 64 MiB");
        let ragged = geometry(64 * 1024 * 1024 + 300, 512).expect("ragged accepted");
        assert_eq!(ragged.total_sectors, clean.total_sectors);
        assert_eq!(ragged.fat_sectors, clean.fat_sectors);
        assert_eq!(ragged.cluster_count, clean.cluster_count);
        assert_eq!(ragged.total_bytes, clean.total_bytes + 300);
    }
}
