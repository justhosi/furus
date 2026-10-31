//! The live exFAT volume (S10 part B1) — the file/directory API core
//! over the formatter substrate from part A: [`Exfat::format`] and
//! [`Exfat::open`] build (or adopt) a volume, and every operation this
//! slice owns is a method on it: `mkdir`, `create_file`, `list_dir`,
//! `free_bytes`, `flush` plus the geometry handle. `write_at`,
//! `read_file`, `set_times` and `set_label` join in part B2.
//!
//! Design notes, the ones the implementations lean on:
//!
//! * **One allocation discipline.** Clusters come from the bitmap's
//!   first-fit scan ([`Bitmap::first_fit`]) as *contiguous* runs, and
//!   every allocation is described by a NoFatChain stream entry — the
//!   shape the measured reference tree showed the kernel writing
//!   (stream flags 0x03; 0x01 with cluster 0 for a zero-length file).
//!   The FAT is never touched for user data; it only links the root's
//!   chain, exactly as the boot sector describes the root (spec
//!   3.1.10: the root is always a cluster chain).
//! * **The rollback.** Every mutating call snapshots the bitmap bytes,
//!   the cached free count and the dirty flag first ([`Snapshot`]), and
//!   records beside them every FAT entry it rewrites as a
//!   `(cluster, previous value)` pair. Any error after the first
//!   allocation puts all of it back ([`Exfat::restore`]): FAT links
//!   undone newest first with the exact values they replaced, then the
//!   in-memory ledger — the same exactness fat32's `AllocationSnapshot`
//!   gives, now true for the root growth too, the one place this slice
//!   touches the FAT. What the rollback does *not* do is undo bytes
//!   already written: a set stamped into a live parent directory
//!   before an I/O failure stays on disk, but the two-phase write
//!   below leaves it in inactive form, which every reader skips rather
//!   than parses — so the directory stays walkable and the allocation
//!   ledger (bitmap, free count, root chain, the part fsck judges)
//!   stays exact. A refused create that never allocated writes nothing
//!   at all: every refusal (name, duplicate, missing component, volume
//!   with no room) happens before the first allocation.
//! * **Two-phase entry-set writes.** A fresh set goes down whole with
//!   its lead still inactive — the lead's InUse bit clear (0x85 to
//!   0x05, every other byte exactly final, the checksum field the
//!   final set's) — and then the lead alone is rewritten in its final
//!   form, one 32-byte write that makes the whole set visible at once.
//!   A call interrupted in either phase leaves a 0x05 lead over any
//!   mix of secondaries, which this crate's walker, the kernel driver
//!   and `fsck.exfat -n` 1.4.3 all skip (measured: exit 0, `clean.`
//!   with a 0x05 lead and active, partial or missing secondaries; a
//!   wrong checksum in that lead is never even read). The reverse
//!   order — secondaries before the lead — is measured unacceptable:
//!   a torn run there leaves stray slots behind the 0x00 marker and
//!   fsck refuses the shape (`other entry follows unused entry`, exit
//!   4). The same scheme rewrites a live set's lead and stream slot
//!   (a directory growth's stream entry): deactivate, rewrite, publish.
//! * **Directory entries** live in the directory's clusters, and new
//!   sets are written *at the 0x00 terminator slot* (append before the
//!   terminator; deleted 0xE5/0x05 leads are never reused — simpler,
//!   and every reader accepts it). The root's reserved system entries
//!   (0x81 bitmap, 0x82 up-case, 0x83 label) sit in front of the first
//!   file set; they are skipped by the listing walk (only 0x85 opens a
//!   set) and can never be overwritten, because nothing ever writes
//!   before the terminator slot. The one 0x00 marker ends the
//!   directory, and the slots behind it stay zero, so the set written
//!   into the marker's slot always leaves a fresh marker after itself.
//! * **Directory growth** adds one cluster of entry space when the set
//!   would run past the allocation:
//!   * a *subdirectory* extends in place when the run's next cluster
//!     is still free (zeroing it — an all-zero cluster is an empty
//!     directory), or relocates to a fresh `N + 1`-cluster contiguous
//!     run otherwise: the content is copied, and its own stream entry
//!     — which lives in the parent's set — is rewritten together with
//!     the parent set checksum;
//!   * *the root* must not relocate: the boot sector's
//!     FirstClusterOfRootDirectory would have to move, invalidating
//!     the boot checksum. It grows by one cluster appended to its FAT
//!     chain instead — the one directory whose description *is* a
//!     chain, and the only place this slice touches the FAT.
//! * **Paths** are absolute, `/`-separated component paths naming
//!   directories and leaves; a leading slash is tolerated, a trailing
//!   or doubled slash (an empty component) refuses, `.` and `..`
//!   refuse (they are linkage, not user paths). Lookups are
//!   case-insensitive through the canonical up-case table
//!   ([`dirent::upcase_name`]); entries are created as given
//!   (case-preserved, like the measured tree).
//! * **`PercentInUse`.** `flush` recomputes the percentage of
//!   *allocated* clusters, floored (spec 3.1.18: the field is the
//!   percentage of clusters in use, rounded down, or FF for unknown)
//!   into byte 112 of *both* boot sectors, and — that byte being
//!   excluded from the boot region checksum (part A verified the skip
//!   list against `mkfs`) — the patch needs no checksum updates. Only a
//!   *changed* byte is written. Measured behaviour, for the record:
//!   `fsck.exfat -n` (exfatprogs 1.4.3) accepted images carrying 0,
//!   105, 200 and 255 in that byte, and the mount-created reference
//!   image never updated it either — the spec's own definition is the
//!   pin, not the kernel's laziness.
//! * **No panics anywhere.** All cluster and byte math goes through
//!   checked helpers reporting [`CoreError::invalid`]; the bitmap, the
//!   FAT-walk bounds and the slot windows refuse instead of writing
//!   past their own ends.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::exfat::bitmap::Bitmap;
use crate::fs::exfat::boot;
use crate::fs::exfat::dirent;
use crate::fs::exfat::format;
use crate::fs::exfat::geometry::FIRST_HEAP_CLUSTER;
use crate::fs::exfat::geometry::Geometry;
use crate::fs::exfat::get_u32;
use crate::fs::exfat::get_u64;
use crate::fs::exfat::put_u16;
use crate::fs::exfat::put_u32;
use crate::fs::exfat::put_u64;

/// The user-visible entry summary [`Exfat::list_dir`] reports, in the
/// order the volume stores the entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirInfo {
    /// The entry's name (case-preserved; the listing shows it as the
    /// caller created it).
    pub name: String,
    /// Directory flag.
    pub is_dir: bool,
    /// The allocation's byte size (the file's size, or a directory's
    /// whole allocation).
    pub size: u64,
}

/// FAT value marking the end of a cluster chain.
const FAT_END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// FAT value for a free cluster (never a legal chain link here).
const FAT_FREE: u32 = 0;

/// The byte inside the 512-byte boot sector where PercentInUse lives
/// (spec 3.1.18, Table 4); the backup copy is a byte copy 12 sectors
/// later, so both carry the same offset inside their 512-byte image.
const PERCENT_IN_USE_AT: usize = 112;

/// The allocation bitmap's own stream entry, in the root's first
/// cluster: its FirstCluster (offset 20) and DataLength (offset 24)
/// name the bitmap wherever the format's layout put it.
fn bitmap_entry_image(image: &[u8]) -> Result<Option<(u32, u64, u8)>> {
    let mut at = 0_usize;
    while at + format::ENTRY_BYTES <= image.len() {
        let window = image
            .get(at..at + format::ENTRY_BYTES)
            .ok_or_else(|| CoreError::invalid("a root slot lost its window".to_string()))?;
        match window.first().copied() {
            Some(0x00) => break, // the marker ends the critical entries
            Some(0x81) => {
                let first_cluster = get_u32(window, 20)
                    .ok_or_else(|| CoreError::invalid("the 0x81 entry lost its cluster field"))?;
                let data_length = get_u64(window, 24)
                    .ok_or_else(|| CoreError::invalid("the 0x81 entry lost its length field"))?;
                let flags = window
                    .get(1)
                    .copied()
                    .ok_or_else(|| CoreError::invalid("the 0x81 entry lost its flags byte"))?;
                return Ok(Some((first_cluster, data_length, flags)));
            }
            _ => at += format::ENTRY_BYTES,
        }
    }
    Ok(None)
}

/// One directory's resolved content: which clusters its bytes live in
/// (chain order) and the bytes themselves. Both directory shapes the
/// format knows reduce to this — a contiguous NoFatChain run (every
/// directory this crate makes) or a FAT chain (the root, always).
#[derive(Debug, Clone)]
struct DirContent {
    /// Clusters in on-disk order (chain order for the root, ascending
    /// for a contiguous run).
    chain: Vec<u32>,
    /// The bytes, in that cluster order (a whole number of clusters).
    bytes: Vec<u8>,
}

impl DirContent {
    /// Byte offset of the `slot`-th 32-byte slot on the volume.
    fn slot_address(&self, geometry: &Geometry, slot: usize) -> Result<u64> {
        let per_cluster = usize::try_from(geometry.cluster_bytes() / 32)
            .map_err(|_| CoreError::invalid("a cluster's slots do not fit this machine"))?;
        if per_cluster == 0 {
            return Err(CoreError::invalid(format!(
                "a cluster of {} bytes is smaller than one directory slot",
                geometry.cluster_bytes()
            )));
        }
        let middle = slot % per_cluster;
        let within = u64::try_from(middle)
            .ok()
            .and_then(|offset| offset.checked_mul(32))
            .ok_or_else(|| CoreError::invalid("a slot offset overflows a u64"))?;
        let cluster = self.chain.get(slot / per_cluster).ok_or_else(|| {
            CoreError::invalid(format!(
                "slot {slot} runs past the {} slots this directory's allocation holds",
                self.chain.len().saturating_mul(per_cluster)
            ))
        })?;
        let address = geometry
            .cluster_offset(*cluster)?
            .checked_add(within)
            .ok_or_else(|| CoreError::invalid("a slot address overflows a u64"))?;
        Ok(address)
    }
}

/// One component of a resolved path: the directory's content plus the
/// facts its growth needs — its own allocation, and where its own
/// entry set lives in its parent (so a relocation can rewrite that
/// stream entry).
#[derive(Debug, Clone)]
struct Level {
    /// The directory's bytes, cluster-ordered.
    content: DirContent,
    /// First cluster of its allocation.
    first_cluster: u32,
    /// Clusters the allocation spans (`0` for the root: its length is
    /// its chain, which the content already carries).
    clusters: u32,
    /// Whether the allocation is one contiguous run (`NoFatChain`).
    /// A fragmented directory can be read but not grown in place.
    contiguous: bool,
    /// Slot indices of its own entry set inside its parent (`None` for
    /// the root, which has no parent-side entry) — file first, then
    /// stream, then names.
    own_set_slots: Option<Vec<usize>>,
}

/// The allocation state one mutating call snapshotted before its first
/// allocation: the bitmap bytes, the cached free count and the dirty
/// flag. Restored on any later error — see the module docs.
struct Snapshot {
    bitmap: Vec<u8>,
    free_clusters: u32,
    dirty: bool,
    /// The FAT words this call overwrote, oldest first, with the value
    /// each held before. The root's chain is the only FAT writer, and a
    /// replayed link is what keeps a rolled-back volume consistent: a
    /// free cluster that a live directory still points at is corruption
    /// (fsck reports it as `cluster is already allocated`).
    fat_writes: Vec<(u32, u32)>,
}

/// The live exFAT volume: one [`Volume`], the geometry it was opened
/// (or formatted) for, the in-memory allocation bitmap, the cached
/// free count and the bitmap's dirty flag. Nothing here is shared
/// state — one `Exfat` owns its volume for its whole life, exactly
/// like the formatter's pass does.
pub struct Exfat<V: Volume> {
    volume: V,
    geometry: Geometry,
    bitmap: Bitmap,
    free_clusters: u32,
    bitmap_dirty: bool,
}

impl<V: Volume> Exfat<V> {
    /// Format a whole exFAT volume onto `volume` and hand its live API
    /// back.
    ///
    /// The volume content is built by part A's
    /// [`format::format`](format::format) writer (boot regions, FAT,
    /// allocation bitmap, up-case table, root directory, label) — this
    /// type takes over the bitmap bookkeeping: the bitmap bytes are
    /// loaded back from the just-formatted image and the free count is
    /// counted from the bits, so the two views agree by construction
    /// (and the count matches what `mkfs.exfat` reports for the same
    /// layout — measured 15,868 free of 15,872 clusters on 64 MiB).
    pub fn format(mut volume: V, options: &format::FormatOptions) -> Result<Self> {
        let geometry = format::format(&mut volume, options)?;
        let base_offset = geometry.cluster_offset(geometry.bitmap_cluster)?;
        let bitmap = Bitmap::load(
            &volume,
            geometry.bitmap_cluster,
            geometry.bitmap_clusters,
            geometry.cluster_bytes,
            geometry.cluster_count,
            base_offset,
        )?;
        Ok(Self {
            volume,
            geometry,
            free_clusters: bitmap.free_clusters(),
            bitmap,
            bitmap_dirty: false,
        })
    }

    /// Adopt an already-formatted volume: the boot sector is parsed
    /// back (part A's parser keeps its checks — the `EXFAT`
    /// signature, the tail signature, the sector shifts, one FAT), the
    /// main boot region's own checksum is verified against the word
    /// its checksum sector stores ([`boot::boot_checksum`]'s
    /// accumulator over the eleven sectors each copy covers, the
    /// mutating volume-flags word and PercentInUse byte excluded — so
    /// a mount's own boot-sector patches never trip it, while the
    /// damage `fsck.exfat` rejects a volume for refuses here), the
    /// store must be at least as large as its boot sector claims, and
    /// the allocation bitmap is located through the root directory's
    /// 0x81 entry — the entry the spec says names it — rather than
    /// assumed at cluster 2, because other layouts may put it
    /// elsewhere (a measured 512-byte-cluster `mkfs` volume starts its
    /// up-case table at cluster 4, showing the entry's own words are
    /// the only portable truth).
    pub fn open(volume: V) -> Result<Self> {
        let mut boot_bytes = [0_u8; boot::BOOT_SECTOR_BYTES];
        volume.read_exact_at(0, &mut boot_bytes)?;
        let parsed = boot::parse_boot_sector(&boot_bytes)?;
        // The checksum binds sectors 0..=10 of the main copy; the same
        // accumulator `boot_region` wrote it with, so a formatted
        // volume always passes and one flipped byte anywhere in the
        // covered range (or in the checksum sector itself) refuses.
        let sector_bytes = usize::try_from(parsed.sector_size)
            .map_err(|_| CoreError::invalid("the sector size does not fit memory"))?;
        let region_len = 12usize
            .checked_mul(sector_bytes)
            .ok_or_else(|| CoreError::invalid("the boot region does not fit memory"))?;
        let region = read_whole(
            &volume,
            0,
            u32::try_from(region_len)
                .map_err(|_| CoreError::invalid("the boot region does not fit a u32"))?,
            "main boot region",
        )?;
        let computed = boot::boot_checksum(&region, parsed.sector_size)?;
        let stored_at = sector_bytes
            .checked_mul(boot::BOOT_REGION_SECTORS - 1)
            .ok_or_else(|| CoreError::invalid("the checksum sector overflows"))?;
        let stored = get_u32(&region, stored_at)
            .ok_or_else(|| CoreError::invalid("the boot region lost its checksum word"))?;
        if stored != computed {
            let covered = boot::BOOT_REGION_SECTORS - 1;
            return Err(CoreError::invalid(format!(
                "the boot region checksum reads {stored:#010x} but the first {covered} sectors \
                 hash to {computed:#010x}"
            )));
        }
        let mapped = parsed
            .volume_length_sectors
            .checked_mul(u64::from(parsed.sector_size))
            .ok_or_else(|| CoreError::invalid("the boot sector's volume length overflows a u64"))?;
        if mapped > volume.total_bytes() {
            return Err(CoreError::invalid(format!(
                "the boot sector maps {mapped} bytes but the volume reports {}",
                volume.total_bytes()
            )));
        }
        let cluster_bytes = parsed
            .sector_size
            .checked_mul(parsed.sectors_per_cluster)
            .ok_or_else(|| CoreError::invalid("the boot sector's cluster size overflows"))?;
        if cluster_bytes == 0 {
            return Err(CoreError::invalid(
                "the boot sector declares empty clusters",
            ));
        }
        let geometry = Geometry {
            sector_size: parsed.sector_size,
            sectors_per_cluster: parsed.sectors_per_cluster,
            cluster_bytes,
            volume_length_sectors: parsed.volume_length_sectors,
            fat_offset: parsed.fat_offset,
            fat_length: parsed.fat_length,
            cluster_heap_offset: parsed.cluster_heap_offset,
            cluster_count: parsed.cluster_count,
            root_cluster: parsed.root_cluster,
            // Filled in from the root's 0x81 entry below.
            bitmap_cluster: FIRST_HEAP_CLUSTER,
            bitmap_clusters: 0,
            bitmap_bytes: 0,
        };
        // The root's first cluster holds the critical primary entries
        // (label, bitmap, up-case) in every layout the format allows.
        let image = read_whole(
            &volume,
            geometry.cluster_offset(parsed.root_cluster)?,
            cluster_bytes,
            "root cluster",
        )?;
        let (bitmap_cluster, bitmap_bytes, bitmap_flags) =
            bitmap_entry_image(&image)?.ok_or_else(|| {
                CoreError::invalid(
                    "the root's 0x81 allocation bitmap entry is missing before its first marker"
                        .to_string(),
                )
            })?;
        if !(FIRST_HEAP_CLUSTER..=parsed.cluster_count.saturating_add(1)).contains(&bitmap_cluster)
        {
            return Err(CoreError::invalid(format!(
                "the 0x81 entry names bitmap cluster {bitmap_cluster}, not within the heap"
            )));
        }
        if bitmap_bytes == 0 {
            return Err(CoreError::invalid(
                "the root's 0x81 allocation bitmap entry claims zero bytes".to_string(),
            ));
        }
        // A chained bitmap would be read (and written back) linearly,
        // which corrupts it: refuse rather than guess, matching the
        // contiguous-only allocation this module documents. Measured
        // against `mkfs.exfat` 1.4.3, whose 0x81 entry carries flags
        // 0x00 (neither bit set) -- so only the *claim* that the bitmap
        // may be chained (AllocationPossible without NoFatChain) is
        // refused, not the absence of flags.
        if bitmap_flags & 0x03 == 0x01 {
            return Err(CoreError::invalid(
                "the 0x81 allocation bitmap entry is not marked NoFatChain".to_string(),
            ));
        }
        let cluster_span = bitmap_bytes.div_ceil(u64::from(cluster_bytes)).max(1);
        let bitmap_clusters = u32::try_from(cluster_span).map_err(|_| {
            CoreError::invalid(format!(
                "a bitmap allocation of {cluster_span} clusters overflows a u32"
            ))
        })?;
        let base_offset = geometry.cluster_offset(bitmap_cluster)?;
        let bitmap = Bitmap::load(
            &volume,
            bitmap_cluster,
            bitmap_clusters,
            cluster_bytes,
            parsed.cluster_count,
            base_offset,
        )?;
        let geometry = Geometry {
            bitmap_cluster,
            bitmap_clusters,
            bitmap_bytes,
            ..geometry
        };
        Ok(Self {
            volume,
            geometry,
            free_clusters: bitmap.free_clusters(),
            bitmap,
            bitmap_dirty: false,
        })
    }

    /// The geometry this volume was parsed (or formatted) for.
    #[must_use]
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Free bytes available for new files: the cached free-cluster
    /// count times the cluster size. The count is exact — every
    /// allocation decrements it in the same step that marks the
    /// bitmap, and `open` counted it from the bit image itself.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        u64::from(self.free_clusters).saturating_mul(self.geometry.cluster_bytes())
    }

    /// Make everything durable: the bitmap (only when it changed), the
    /// PercentInUse byte of both boot sectors (only when the count
    /// moved it) and then the store itself.
    ///
    /// PercentInUse is the percentage of *allocated* clusters, floored
    /// (spec 3.1.18), and it is excluded from the boot checksum, so
    /// patching byte 112 of the two boot-sector images neither
    /// invalidates nor needs to update that checksum (part A verified
    /// the skip list against `mkfs`'s).
    pub fn flush(&mut self) -> Result<()> {
        if self.bitmap_dirty {
            self.bitmap.write_back(&mut self.volume)?;
            self.bitmap_dirty = false;
        }
        let used = self
            .geometry
            .cluster_count
            .checked_sub(self.free_clusters)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "free clusters {} exceed the heap's {} clusters",
                    self.free_clusters, self.geometry.cluster_count
                ))
            })?;
        // Percentage of *allocated* clusters, floored (spec 3.1.18). The
        // multiply runs in `u64`: a legal layout with an explicit 4 KiB
        // cluster size can carry tens of millions of clusters, where
        // `used * 100` would saturate a `u32` and understate the value.
        let percent = u64::from(used)
            .saturating_mul(100)
            .checked_div(u64::from(self.geometry.cluster_count.max(1)))
            .unwrap_or(0)
            .min(100);
        self.patch_percent_in_use(u8::try_from(percent).map_err(|_| {
            CoreError::invalid("a percent-in-use value overflows a byte".to_string())
        })?)?;
        self.volume.flush()?;
        Ok(())
    }

    /// Patch byte 112 of the main and backup boot sectors with
    /// `percent`, skipping the write entirely when the byte already
    /// carries it (mounts leave the value stale; churning writes on
    /// every flush would otherwise touch the boot region for nothing).
    fn patch_percent_in_use(&mut self, percent: u8) -> Result<()> {
        let backup_at = u64::from(boot::BOOT_REGION_SECTORS as u32)
            .checked_mul(u64::from(self.geometry.sector_size))
            .ok_or_else(|| CoreError::invalid("the backup boot offset overflows"))?;
        let mut boot_image = [0_u8; boot::BOOT_SECTOR_BYTES];
        self.volume.read_exact_at(0, &mut boot_image)?;
        let mut backup_image = [0_u8; boot::BOOT_SECTOR_BYTES];
        self.volume.read_exact_at(backup_at, &mut backup_image)?;
        // Both copies must agree: a mount may leave one stale, and the
        // skip must not excuse the other. The two boot sectors differ in
        // their checksum sector only, so one patched image serves both.
        let patch = |image: &mut [u8; boot::BOOT_SECTOR_BYTES]| -> Result<()> {
            let Some(slot) = image.get_mut(PERCENT_IN_USE_AT) else {
                return Err(CoreError::invalid(
                    "the boot sector lost its PercentInUse byte".to_string(),
                ));
            };
            *slot = percent;
            Ok(())
        };
        // Each copy is patched on its own: cloning the main sector over
        // the backup would also copy the main's VolumeFlags word, which
        // the specification defines for the main copy only.
        if backup_image.get(PERCENT_IN_USE_AT).copied() != Some(percent) {
            patch(&mut backup_image)?;
            self.volume.write_all_at(backup_at, &backup_image)?;
        }
        if boot_image.get(PERCENT_IN_USE_AT).copied() != Some(percent) {
            patch(&mut boot_image)?;
            self.volume.write_all_at(0, &boot_image)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Creation: mkdir / create_file
    // ------------------------------------------------------------------

    /// Create a directory at `path`: a fresh zeroed cluster carries the
    /// (empty) directory's content and the parent's set — file entry,
    /// stream entry and name — describes it with the Directory bit.
    /// exFAT has no `.`,`..` linkage entries to generate.
    ///
    /// An existing name (file or directory, case-insensitively)
    /// refuses, as do invalid names and missing or non-directory path
    /// components — all before any allocation. A refused call rolls
    /// back: the fresh directory cluster, any cluster the parent grew
    /// into, the bitmap bytes and the free count all return to the
    /// state [`Snapshot`] captured (see the module docs for what
    /// happens to bytes written into freed clusters).
    pub fn mkdir(&mut self, path: &str, times: dirent::Stamps) -> Result<()> {
        self.create_entry(path, true, 0, times).map(|_| ())
    }

    /// Create a file entry of `size_hint` bytes at `path`: the storage
    /// is claimed *contiguously* (`ceil(size_hint / cluster_size)`
    /// clusters; none at all for a zero-size file — the measured
    /// empty-file shape of cluster 0) in the same call, the entry's
    /// ValidDataLength starts at 0 (spec 8.1's write ordering: the data
    /// length first, contents after, valid data last — part B2 owns
    /// `write_at`), and the first cluster comes back (`0` for an empty
    /// file). The caller fills the bytes through `write_at` (part B2).
    ///
    /// An existing name refuses, case-insensitively. A size whose
    /// cluster run has no contiguous fit refuses with the free-cluster
    /// count named. A refused call rolls back exactly like
    /// [`Exfat::mkdir`], so the volume stays fsck-clean.
    pub fn create_file(
        &mut self,
        path: &str,
        size_hint: u64,
        times: dirent::Stamps,
    ) -> Result<u32> {
        self.create_entry(path, false, size_hint, times)
    }

    /// The create path both `mkdir` and `create_file` share; the shape
    /// differences (attributes, cluster claim, valid-data length) live
    /// in the two public callers.
    fn create_entry(
        &mut self,
        path: &str,
        is_dir: bool,
        size_hint: u64,
        times: dirent::Stamps,
    ) -> Result<u32> {
        // Refusals before anything else: the name and the parent path.
        let Some(components) = Self::split_path(path)? else {
            return Err(CoreError::invalid(format!(
                "path {path:?} names the root directory, create needs a leaf name"
            )));
        };
        let Some(leaf) = components.last().cloned() else {
            return Err(CoreError::invalid(
                "a path without a final component".to_string(),
            ));
        };
        dirent::validate_name(&leaf)?;
        let parent_components: Vec<String> = components
            .iter()
            .take(components.len().saturating_sub(1))
            .cloned()
            .collect();
        let mut levels = self.walk(&parent_components)?;
        // The duplicate check is read-only and happens before the
        // snapshot: a refused create changes nothing at all.
        let parent = levels
            .last()
            .ok_or_else(|| CoreError::invalid("every create goes through a parent".to_string()))?;
        let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
        let upcased = dirent::upcase_name(&leaf);
        let exists = listing
            .entries
            .iter()
            .any(|entry| dirent::upcase_name(&entry.name) == upcased);
        if exists {
            return Err(CoreError::invalid(format!(
                "the name {leaf:?} already exists in {:?}",
                parent_text(&parent_components)
            )));
        }
        let units = leaf.encode_utf16().collect::<Vec<u16>>();

        // From here on, any failure rolls the ledger back.
        let mut snapshot = self.snapshot();
        let result = self.commit(
            &mut levels,
            units,
            is_dir,
            size_hint,
            times,
            &mut snapshot.fat_writes,
        );
        if result.is_err() {
            // The commit error is the one worth reporting; a failed
            // undo would only mask it, and the next open recounts the
            // bitmap anyway.
            self.restore(snapshot).ok();
        }
        result
    }

    /// The mutating half of the create paths, transaction-shaped: the
    /// caller snapshotted the ledger and restores it if this errs.
    ///
    /// Order: allocation first (so a volume with no room refuses before
    /// any slot is touched), then the entry set's slots (parent growth
    /// included). Everything that can err after the first allocation is
    /// covered by the caller's rollback.
    fn commit(
        &mut self,
        levels: &mut [Level],
        units: Vec<u16>,
        is_dir: bool,
        size_hint: u64,
        times: dirent::Stamps,
        fat_writes: &mut Vec<(u32, u32)>,
    ) -> Result<u32> {
        let cluster_bytes = self.geometry.cluster_bytes();
        // The allocation: a directory takes exactly one cluster for its
        // (empty) content; a file takes ceil(size / cluster_size) —
        // zero for an empty file, which carries no cluster at all (the
        // measured shape: cluster 0, stream flags 0x01).
        let (first_cluster, data_length, valid_data_length) = if is_dir {
            let run = self.allocate(1, "a new directory needs")?;
            // A fresh directory cluster: all-zero bytes, which makes
            // its first slot the end-of-directory marker of an empty
            // directory (nothing else needs writing into it).
            zero_cluster(&mut self.volume, &self.geometry, run)?;
            (run, cluster_bytes, cluster_bytes)
        } else {
            let count = u32::try_from(size_hint.div_ceil(cluster_bytes)).map_err(|_| {
                CoreError::invalid(format!(
                    "{size_hint} bytes need more clusters than this volume numbers"
                ))
            })?;
            if count == 0 {
                (0, 0, 0)
            } else {
                let run = self.allocate(count, "a new file needs")?;
                (run, size_hint, 0)
            }
        };
        let plan = dirent::Plan {
            name_units: units,
            attributes: dirent::DirEntry::attributes_for(is_dir),
            is_dir,
            first_cluster,
            valid_data_length,
            data_length,
            stamps: times,
        };
        let set = dirent::entry_set(&plan)?;
        self.append_set(levels, &set, fat_writes)?;
        Ok(first_cluster)
    }

    /// Claim `count` contiguous clusters from the bitmap: first fit,
    /// mark, count update. Every refusal names the numbers and happens
    /// *before* any bit is marked.
    fn allocate(&mut self, count: u32, what: &str) -> Result<u32> {
        let Some(run) = self.bitmap.first_fit(count)? else {
            return Err(CoreError::invalid(format!(
                "{what} {count} contiguous clusters but the volume holds {} free clusters",
                self.free_clusters
            )));
        };
        self.bitmap.mark(count, run)?;
        self.free_clusters = self.free_clusters.checked_sub(count).ok_or_else(|| {
            CoreError::invalid(format!(
                "marking {count} clusters would leave the {} free count negative",
                self.free_clusters
            ))
        })?;
        self.bitmap_dirty = true;
        Ok(run)
    }

    /// Hand `count` clusters back to the pool (the old allocation of a
    /// relocated directory): clear, count update.
    fn release(&mut self, count: u32, first_cluster: u32) -> Result<()> {
        self.bitmap.clear(count, first_cluster)?;
        self.free_clusters = self.free_clusters.saturating_add(count);
        Ok(())
    }

    /// Write an entry set into the directory of `level_index` (always
    /// the last level the caller resolved), growing that directory by
    /// one cluster as often as the set does not fit in front of the
    /// end of its allocation.
    fn append_set(
        &mut self,
        levels: &mut [Level],
        set: &[[u8; format::ENTRY_BYTES]],
        fat_writes: &mut Vec<(u32, u32)>,
    ) -> Result<()> {
        let level_index = levels
            .len()
            .checked_sub(1)
            .ok_or_else(|| CoreError::invalid("a set needs a parent directory".to_string()))?;
        loop {
            let fits = {
                let parent = levels.get(level_index).ok_or_else(|| {
                    CoreError::invalid("the parent directory vanished".to_string())
                })?;
                let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
                let terminator = listing.terminator_slot;
                terminator.saturating_add(set.len()) <= listing.total_slots
            };
            if fits {
                // One write per slot: sets can straddle clusters, and
                // the slot after the set is already the fresh 0x00
                // marker the slots behind the old marker always were.
                // Two-phase, so a write that dies mid-set leaves a
                // *deleted* set rather than a poisoned directory: the
                // lead entry goes down first with its InUse bit clear (a
                // shape every walker skips, checksum field included),
                // the secondaries follow, and only then does the lead
                // become visible. Measured: an inactive lead with live
                // secondaries is fsck-clean in every torn state, while a
                // lead written first is not (its checksum cannot match a
                // half-written set).
                let lead = set
                    .first()
                    .copied()
                    .ok_or_else(|| CoreError::invalid("an entry set needs a lead".to_string()))?;
                let first_at = self.append_set_slot_address(levels, level_index, 0)?;
                let mut dormant = lead;
                dirent::deactivate(&mut dormant);
                self.volume.write_all_at(first_at, &dormant)?;
                for (step, image) in set.iter().enumerate().skip(1) {
                    let at = self.append_set_slot_address(levels, level_index, step)?;
                    self.volume.write_all_at(at, image)?;
                }
                self.volume.write_all_at(first_at, &lead)?;
                return Ok(());
            }
            self.grow_directory(levels, level_index, fat_writes)?;
        }
    }

    /// The volume address of set slot `step`, recomputed per write from
    /// a fresh parse (the growth loop may have moved the directory).
    fn append_set_slot_address(
        &self,
        levels: &[Level],
        level_index: usize,
        step: usize,
    ) -> Result<u64> {
        let parent = levels
            .get(level_index)
            .ok_or_else(|| CoreError::invalid("the parent directory vanished".to_string()))?;
        let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
        let step = listing.terminator_slot.saturating_add(step);
        parent.content.slot_address(&self.geometry, step)
    }

    // ------------------------------------------------------------------
    // Directory views
    // ------------------------------------------------------------------

    /// List the directory at `path`: every real entry as [`DirInfo`],
    /// in on-disk order. The root's reserved system entries (0x81,
    /// 0x82, 0x83 — and every other non-set slot) never list, because
    /// the walk only opens 0x85 sets.
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirInfo>> {
        let components = Self::split_path(path)?.unwrap_or_default();
        let levels = self.walk(&components)?;
        let content = levels
            .last()
            .ok_or_else(|| CoreError::invalid("a listing needs at least the root".to_string()))?;
        let listing = dirent::parse_dir_listing(&content.content.bytes)?;
        Ok(listing
            .entries
            .iter()
            .map(|entry| DirInfo {
                name: entry.name.clone(),
                is_dir: entry.is_dir,
                size: entry.size,
            })
            .collect())
    }

    // ------------------------------------------------------------------
    // Internal: path resolution
    // ------------------------------------------------------------------

    /// The components of a user path: `None` for the root (`"/"`),
    /// else component names — an optional single leading slash
    /// tolerated (`"/a"` names the same leaf as `"a"`), a trailing or
    /// doubled slash (an empty component) refused, every component
    /// validated by [`dirent::validate_name`].
    fn split_path(path: &str) -> Result<Option<Vec<String>>> {
        if path.is_empty() {
            return Err(CoreError::invalid("a path is empty".to_string()));
        }
        if path == "/" {
            return Ok(None); // the root itself
        }
        let parts: Vec<&str> = path.split('/').collect();
        // A single leading slash is tolerated; anything more is an
        // empty component, refused below exactly like a trailing one.
        let start = usize::from(parts.first() == Some(&""));
        let mut components = Vec::with_capacity(parts.len());
        for part in parts.iter().skip(start).copied() {
            if part.is_empty() {
                return Err(CoreError::invalid(format!(
                    "path {path:?} carries an empty path component (a trailing or doubled slash)"
                )));
            }
            dirent::validate_name(part)?;
            components.push(part.to_string());
        }
        if components.is_empty() {
            return Err(CoreError::invalid(format!(
                "path {path:?} names nothing but slashes"
            )));
        }
        Ok(Some(components))
    }

    /// Walk the component chain from the root, every component being a
    /// directory (errors name the first offending component). The last
    /// level is therefore the parent a create appends into, or the
    /// directory a view reads.
    fn walk(&self, components: &[String]) -> Result<Vec<Level>> {
        let mut levels = vec![self.root_level()?];
        for component in components {
            let parent = levels
                .last()
                .ok_or_else(|| CoreError::invalid("the walk lost its parent".to_string()))?;
            let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
            let upcased = dirent::upcase_name(component);
            let mut hit = None;
            for (index, (entry, start)) in listing
                .entries
                .iter()
                .cloned()
                .zip(listing.set_starts.iter().copied())
                .enumerate()
            {
                if dirent::upcase_name(&entry.name) != upcased {
                    continue;
                }
                let set_end = listing
                    .set_starts
                    .get(index + 1)
                    .copied()
                    .unwrap_or(listing.terminator_slot);
                // The set's second slot is its stream entry; byte 1
                // carries its flags, whose NoFatChain bit decides how
                // the data reads. (The flags sit outside [`dirent`]'s
                // read-back type on purpose: the volume layer owns the
                // allocation facts.)
                let stream_flags = parent
                    .content
                    .bytes
                    .get(
                        start
                            .checked_add(1)
                            .and_then(|slot| slot.checked_mul(format::ENTRY_BYTES))
                            .and_then(|at| at.checked_add(1))
                            .ok_or_else(|| {
                                CoreError::invalid("a stream slot address overflows".to_string())
                            })?,
                    )
                    .copied()
                    .unwrap_or(0);
                hit = Some((entry, start, set_end, stream_flags));
                break;
            }
            let Some((entry, start, set_end, stream_flags)) = hit else {
                return Err(CoreError::invalid(format!(
                    "path component {component:?} does not exist on the volume"
                )));
            };
            if !entry.is_dir {
                return Err(CoreError::invalid(format!(
                    "path component {component:?} names a file, not a directory"
                )));
            }
            let set_slots: Vec<usize> = (start..set_end).collect();
            let content = self.read_dir_content(
                entry.first_cluster,
                stream_flags & 0x02 != 0,
                Some(entry.size),
            )?;
            let clusters = u32::try_from(entry.size.div_ceil(self.geometry.cluster_bytes()))
                .unwrap_or(u32::MAX);
            levels.push(Level {
                content,
                first_cluster: entry.first_cluster,
                clusters,
                contiguous: stream_flags & 0x02 != 0,
                own_set_slots: Some(set_slots),
            });
        }
        Ok(levels)
    }

    /// The root directory's content: its cluster chain (the one
    /// directory the boot sector describes through the FAT), read from
    /// cluster offsets — the root's length is the chain.
    fn root_level(&self) -> Result<Level> {
        let content = self.read_dir_content(self.geometry.root_cluster, false, None)?;
        Ok(Level {
            content,
            first_cluster: self.geometry.root_cluster,
            clusters: 0,
            contiguous: false,
            own_set_slots: None,
        })
    }

    /// Read a directory's bytes: one contiguous read when the stream is
    /// NoFatChain (the measured 0x03 shape), a per-cluster FAT walk
    /// otherwise (the root, always, and foreign fragmented
    /// directories). Both refuse corruption with numbers named.
    fn read_dir_content(
        &self,
        first_cluster: u32,
        contiguous: bool,
        data_length: Option<u64>,
    ) -> Result<DirContent> {
        let cluster_bytes = self.geometry.cluster_bytes();
        let last = self.geometry.cluster_count.saturating_add(1);
        if !(FIRST_HEAP_CLUSTER..=last).contains(&first_cluster) {
            return Err(CoreError::invalid(format!(
                "directory cluster {first_cluster} is not a heap cluster of this volume"
            )));
        }
        if contiguous {
            let Some(data_length) = data_length else {
                return Err(CoreError::invalid(
                    "a contiguous directory must know its length".to_string(),
                ));
            };
            let clusters = u32::try_from(data_length.div_ceil(cluster_bytes)).map_err(|_| {
                CoreError::invalid("a directory longer than u32 clusters is corrupt".to_string())
            })?;
            let mut chain = Vec::with_capacity(clusters.min(1_024) as usize);
            for step in 0..clusters {
                let cluster = first_cluster
                    .checked_add(step)
                    .ok_or_else(|| CoreError::invalid("a directory chain overflows a u32"))?;
                if cluster > last {
                    return Err(CoreError::invalid(format!(
                        "the contiguous directory run runs past cluster {last}"
                    )));
                }
                chain.push(cluster);
            }
            let bytes = self.read_clusters(&chain)?;
            return Ok(DirContent { chain, bytes });
        }
        // A FAT-walked directory: read clusters until the chain ends
        // (or the data length is covered), bounded by the heap so a
        // hostile loop cannot spin forever.
        let mut chain = Vec::new();
        let mut cluster = first_cluster;
        loop {
            let reached = u64::from(chain.len() as u32)
                .checked_mul(cluster_bytes)
                .ok_or_else(|| CoreError::invalid("a directory length overflows a u64"))?;
            if let Some(data_length) = data_length
                && reached >= data_length
            {
                break; // the chain may continue; the length is the truth
            }
            if chain.len() as u64 > u64::from(self.geometry.cluster_count) {
                return Err(CoreError::invalid(format!(
                    "the directory chain at cluster {first_cluster} runs past every cluster \
                     the volume has"
                )));
            }
            chain.push(cluster);
            let next = self.fat_entry(cluster)?;
            if next == FAT_END_OF_CHAIN {
                // The chain ending exactly at the claimed length is the
                // well-formed case: a fragmented directory's own length
                // is what says how many clusters it holds.
                let covered = u64::try_from(chain.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(cluster_bytes);
                if data_length.is_none() || data_length.is_some_and(|len| covered >= len) {
                    break;
                }
                return Err(CoreError::invalid(format!(
                    "the chain of cluster {first_cluster} ends before its claimed {} bytes",
                    data_length.unwrap_or(0)
                )));
            }
            if next == FAT_FREE || !(FIRST_HEAP_CLUSTER..=last).contains(&next) {
                return Err(CoreError::invalid(format!(
                    "the directory chain carries corrupt fat value {next:#010x} at cluster \
                     {cluster}"
                )));
            }
            cluster = next;
        }
        let bytes = self.read_clusters(&chain)?;
        Ok(DirContent { chain, bytes })
    }

    /// Read whole clusters into one byte vector, in chain order.
    fn read_clusters(&self, chain: &[u32]) -> Result<Vec<u8>> {
        let cluster_bytes = self.geometry.cluster_bytes();
        let cluster_bytes_usize = usize::try_from(cluster_bytes)
            .map_err(|_| CoreError::invalid("a cluster longer than this machine's usize"))?;
        let all = chain
            .len()
            .checked_mul(cluster_bytes_usize)
            .ok_or_else(|| CoreError::invalid("a directory read overflows memory"))?;
        let mut bytes = vec![0_u8; all];
        for (index, cluster) in chain.iter().enumerate() {
            let start = index
                .checked_mul(cluster_bytes_usize)
                .ok_or_else(|| CoreError::invalid("a cluster window overflows".to_string()))?;
            let window = bytes
                .get_mut(start..start.saturating_add(cluster_bytes_usize))
                .ok_or_else(|| CoreError::invalid("a cluster window vanished".to_string()))?;
            self.volume
                .read_exact_at(self.geometry.cluster_offset(*cluster)?, window)?;
        }
        Ok(bytes)
    }

    /// One FAT entry, checked into the heap's cluster numbering.
    fn fat_entry(&self, cluster: u32) -> Result<u32> {
        let last = self.geometry.cluster_count.saturating_add(1);
        if !(FIRST_HEAP_CLUSTER..=last).contains(&cluster) {
            return Err(CoreError::invalid(format!(
                "fat entry for cluster {cluster} is outside the heap"
            )));
        }
        let at = u64::from(self.geometry.fat_offset)
            .checked_mul(u64::from(self.geometry.sector_size))
            .and_then(|base| {
                u64::from(cluster)
                    .checked_mul(4)
                    .and_then(|step| base.checked_add(step))
            })
            .ok_or_else(|| CoreError::invalid("a fat offset overflows a u64"))?;
        let mut bytes = [0_u8; 4];
        self.volume.read_exact_at(at, &mut bytes)?;
        Ok(get_u32(&bytes, 0).unwrap_or(0))
    }

    /// Write one FAT entry (the root's chain is the only writer).
    fn set_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
        let last = self.geometry.cluster_count.saturating_add(1);
        if !(FIRST_HEAP_CLUSTER..=last).contains(&cluster) {
            return Err(CoreError::invalid(format!(
                "fat entry for cluster {cluster} is outside the heap"
            )));
        }
        let at = u64::from(self.geometry.fat_offset)
            .checked_mul(u64::from(self.geometry.sector_size))
            .and_then(|base| {
                u64::from(cluster)
                    .checked_mul(4)
                    .and_then(|step| base.checked_add(step))
            })
            .ok_or_else(|| CoreError::invalid("a fat offset overflows a u64"))?;
        let mut image = [0_u8; 4];
        put_u32(&mut image, 0, value)?;
        self.volume.write_all_at(at, &image)?;
        Ok(())
    }

    /// [`Self::set_fat_entry`] with the previous value recorded in the
    /// caller's rollback ledger.
    fn set_fat_entry_ledgered(
        &mut self,
        cluster: u32,
        value: u32,
        ledger: &mut Vec<(u32, u32)>,
    ) -> Result<()> {
        let previous = self.fat_entry(cluster)?;
        self.set_fat_entry(cluster, value)?;
        ledger.push((cluster, previous));
        Ok(())
    }

    /// The allocation state a create path snapshotted.
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            bitmap: self.bitmap.bytes().to_vec(),
            free_clusters: self.free_clusters,
            dirty: self.bitmap_dirty,
            fat_writes: Vec::new(),
        }
    }

    /// Put the ledger back to a [`Snapshot`] state: the FAT words this
    /// call wrote (newest first), then the bitmap, the cached free count
    /// and the dirty flag.
    fn restore(&mut self, snapshot: Snapshot) -> Result<()> {
        for (cluster, previous) in snapshot.fat_writes.iter().rev() {
            self.set_fat_entry(*cluster, *previous)?;
        }
        self.bitmap.replace_bits(snapshot.bitmap);
        self.free_clusters = snapshot.free_clusters;
        self.bitmap_dirty = snapshot.dirty;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: directory growth
    // ------------------------------------------------------------------

    /// Grow the directory at `level_index` by one cluster of entry
    /// space: the root through a FAT chain link, a subdirectory by
    /// extending its contiguous allocation in place when the run's
    /// next cluster is free, relocating to a fresh contiguous run
    /// otherwise.
    fn grow_directory(
        &mut self,
        levels: &mut [Level],
        level_index: usize,
        fat_writes: &mut Vec<(u32, u32)>,
    ) -> Result<()> {
        if level_index == 0 {
            let root = levels
                .get_mut(0)
                .ok_or_else(|| CoreError::invalid("the root directory vanished".to_string()))?;
            return self.grow_root(root, fat_writes);
        }
        self.grow_subdir(levels, level_index)
    }

    /// Extend the root's chain by one cluster: allocate, zero, link it
    /// behind the current tail in the FAT, and extend the in-memory
    /// content with the cluster's zeros. The boot sector's
    /// FirstClusterOfRootDirectory stays where it is.
    fn grow_root(&mut self, root: &mut Level, fat_writes: &mut Vec<(u32, u32)>) -> Result<()> {
        let new = self.allocate(1, "a root directory extension needs")?;
        zero_cluster(&mut self.volume, &self.geometry, new)?;
        let tail = root
            .content
            .chain
            .last()
            .copied()
            .ok_or_else(|| CoreError::invalid("the root chain lost its tail".to_string()))?;
        // Write the new cluster's own end-of-chain first: if the link
        // below fails, the root still ends at `tail` and the fresh
        // cluster is simply unreferenced, which the caller's rollback
        // then frees. The reverse order would leave a live cluster
        // pointing at a chain the rollback has handed back.
        // Both words are recorded, so the rollback can put the old
        // end-of-chain back on `tail` — a freed cluster that a live
        // directory still points at is exactly what fsck reports as
        // "cluster is already allocated for the other file".
        self.set_fat_entry_ledgered(new, FAT_END_OF_CHAIN, fat_writes)?;
        self.set_fat_entry_ledgered(tail, new, fat_writes)?;
        let zeros = vec![0_u8; usize::try_from(self.geometry.cluster_bytes()).unwrap_or(0)];
        root.content.chain.push(new);
        root.content.bytes.extend_from_slice(&zeros);
        Ok(())
    }

    /// Extend a subdirectory's allocation by one cluster of entry
    /// space: in place when the run's next cluster is free (zero the
    /// cluster, grow the data length), a fresh contiguous run
    /// otherwise (content copied over, the fresh tail zeroed).
    fn grow_subdir(&mut self, levels: &mut [Level], level_index: usize) -> Result<()> {
        let (first_cluster, old_chain_len, old_clusters) = {
            let level = levels
                .get(level_index)
                .ok_or_else(|| CoreError::invalid("the growing directory vanished".to_string()))?;
            let chain_len = level.content.chain.len();
            let old = u32::try_from(chain_len).map_err(|_| {
                CoreError::invalid("a directory longer than u32 clusters is corrupt".to_string())
            })?;
            (level.first_cluster, chain_len, old)
        };
        if !levels
            .get(level_index)
            .is_some_and(|level| level.contiguous)
        {
            return Err(CoreError::invalid(format!(
                "the directory at cluster {first_cluster} is fragmented (its stream entry \
                 does not set NoFatChain), so it cannot grow in place or by relocation"
            )));
        }
        let cluster_bytes = self.geometry.cluster_bytes();
        let next = first_cluster.checked_add(old_clusters);
        let extendable = next.is_some_and(|cluster| {
            cluster <= self.geometry.cluster_count.saturating_add(1)
                && self.bitmap.is_free(cluster).unwrap_or(false)
        });
        if extendable {
            // Adopt the neighbouring cluster: mark it, zero it, extend.
            let new = next.ok_or_else(|| {
                CoreError::invalid("the in-place extension lost its cluster".to_string())
            })?;
            self.allocate_in_place(new)?;
            zero_cluster(&mut self.volume, &self.geometry, new)?;
            let zeros = vec![0_u8; usize::try_from(cluster_bytes).unwrap_or(0)];
            let new_chain_len = old_chain_len.checked_add(1).ok_or_else(|| {
                CoreError::invalid("a directory's cluster count overflows".to_string())
            })?;
            let level = levels
                .get_mut(level_index)
                .ok_or_else(|| CoreError::invalid("the growing directory vanished".to_string()))?;
            level.content.chain.push(new);
            level.content.bytes.extend_from_slice(&zeros);
            level.clusters = u32::try_from(new_chain_len).unwrap_or(u32::MAX);
            // The stream entry keeps its first cluster; only the data
            // length (and the set checksum) move.
            self.rewrite_stream_entry(levels, level_index, first_cluster, new_chain_len)?;
            return Ok(());
        }
        // Relocate: `old + 1` contiguous clusters somewhere else, the
        // content copied, the fresh tail zeroed.
        let new_clusters = old_clusters.checked_add(1).ok_or_else(|| {
            CoreError::invalid("a directory's cluster count overflows".to_string())
        })?;
        let run = self.allocate(new_clusters, "a directory relocation needs")?;
        let bytes = {
            let level = levels
                .get(level_index)
                .ok_or_else(|| CoreError::invalid("the growing directory vanished".to_string()))?;
            let old_len = level.content.bytes.len();
            let new_len = old_len
                .checked_add(usize::try_from(cluster_bytes).unwrap_or(0))
                .ok_or_else(|| {
                    CoreError::invalid("a relocated directory overflows memory".to_string())
                })?;
            let mut bytes = vec![0_u8; new_len];
            let head = bytes
                .get_mut(..old_len)
                .ok_or_else(|| CoreError::invalid("a relocation window vanished".to_string()))?;
            head.copy_from_slice(&level.content.bytes);
            bytes
        };
        let at = self.geometry.cluster_offset(run)?;
        self.volume.write_all_at(at, &bytes)?;
        let new_chain_len = old_chain_len.checked_add(1).ok_or_else(|| {
            CoreError::invalid("a directory's cluster count overflows".to_string())
        })?;
        {
            let level = levels
                .get_mut(level_index)
                .ok_or_else(|| CoreError::invalid("the growing directory vanished".to_string()))?;
            let chain: Vec<u32> = (0..new_chain_len)
                .map(|step| run.checked_add(step as u32))
                .collect::<Option<Vec<u32>>>()
                .ok_or_else(|| CoreError::invalid("a relocation chain overflows".to_string()))?;
            level.content = DirContent { chain, bytes };
            level.first_cluster = run;
            level.clusters = u32::try_from(new_chain_len).unwrap_or(u32::MAX);
        }
        self.rewrite_stream_entry(levels, level_index, run, new_chain_len)?;
        // The old allocation returns to the pool.
        self.release(old_clusters, first_cluster)?;
        Ok(())
    }

    /// The in-place flavour of [`Exfat::allocate`]: one *specific*
    /// cluster (the allocation run's next neighbour) instead of a
    /// first-fit scan.
    fn allocate_in_place(&mut self, cluster: u32) -> Result<()> {
        self.bitmap.mark(1, cluster)?;
        self.free_clusters = self.free_clusters.checked_sub(1).ok_or_else(|| {
            CoreError::invalid("marking the neighbour would go negative".to_string())
        })?;
        self.bitmap_dirty = true;
        Ok(())
    }

    /// Rewrite a subdirectory's own stream entry inside its parent's
    /// set — first cluster, data length and (a directory's) valid-data
    /// length equal to it — recompute the parent's set checksum from
    /// the patched set, and write both changed images back. This is
    /// what makes a directory relocation (or an in-place extension)
    /// visible to every reader at the parent.
    fn rewrite_stream_entry(
        &mut self,
        levels: &mut [Level],
        level_index: usize,
        first_cluster: u32,
        clusters: usize,
    ) -> Result<()> {
        let cluster_bytes = self.geometry.cluster_bytes();
        let data_length = u64::from(u32::try_from(clusters).map_err(|_| {
            CoreError::invalid("a directory longer than u32 clusters is corrupt".to_string())
        })?)
        .checked_mul(cluster_bytes)
        .ok_or_else(|| CoreError::invalid("a directory's data length overflows a u64"))?;
        let set_slots = levels
            .get(level_index)
            .and_then(|level| level.own_set_slots.clone())
            .ok_or_else(|| {
                CoreError::invalid("a relocated directory has no parent set".to_string())
            })?;
        let cluster_bytes_usize = usize::try_from(cluster_bytes)
            .map_err(|_| CoreError::invalid("a cluster longer than this machine's usize"))?;
        let mut images = Vec::with_capacity(set_slots.len());
        for slot in &set_slots {
            images.push(
                levels
                    .get(level_index - 1)
                    .ok_or_else(|| CoreError::invalid("the parent directory vanished".to_string()))
                    .and_then(|parent| slot_image(&parent.content, cluster_bytes_usize, *slot))?,
            );
        }
        // Patch the stream entry: for a directory the whole allocation
        // is valid data (the spec's rule), so valid == data; the flag
        // bytes stay (NoFatChain held both before and after).
        let Some(stream_image) = images.get_mut(1) else {
            return Err(CoreError::invalid(
                "a parent set lost its stream slot".to_string(),
            ));
        };
        put_u64(stream_image, 8, data_length)?; // ValidDataLength
        put_u32(stream_image, 20, first_cluster)?; // FirstCluster
        put_u64(stream_image, 24, data_length)?; // DataLength
        // The set checksum binds the whole set: recompute it over the
        // patched images and store it in the file entry.
        let checksum = dirent::set_checksum(&images);
        let Some(file_image) = images.first_mut() else {
            return Err(CoreError::invalid(
                "a parent set lost its file slot".to_string(),
            ));
        };
        put_u16(file_image, 2, checksum)?;
        // Write the two changed images back into the parent's slots.
        let file_slot = set_slots
            .first()
            .copied()
            .ok_or_else(|| CoreError::invalid("a parent set lost its file slot".to_string()))?;
        let stream_slot = set_slots
            .get(1)
            .copied()
            .ok_or_else(|| CoreError::invalid("a parent set lost its stream slot".to_string()))?;
        let (file_at, stream_at) = {
            let parent = levels
                .get(level_index - 1)
                .ok_or_else(|| CoreError::invalid("the parent directory vanished".to_string()))?;
            (
                parent.content.slot_address(&self.geometry, file_slot)?,
                parent.content.slot_address(&self.geometry, stream_slot)?,
            )
        };
        let file_image = *images.first().unwrap_or(&[0_u8; format::ENTRY_BYTES]);
        let stream_image = *images.get(1).unwrap_or(&[0_u8; format::ENTRY_BYTES]);
        // Same two-phase discipline as a fresh set: the lead goes down
        // deactivated, the changed stream slot follows, and the lead
        // becomes visible last — a torn rewrite is then a deleted set
        // instead of a checksum failure at every later walk.
        let mut dormant = file_image;
        dirent::deactivate(&mut dormant);
        self.volume.write_all_at(file_at, &dormant)?;
        self.volume.write_all_at(stream_at, &stream_image)?;
        self.volume.write_all_at(file_at, &file_image)?;
        Ok(())
    }
}

/// Read `len` bytes at one offset, wrapping read errors with the
/// location that failed.
fn read_whole(volume: &dyn Volume, at: u64, len: u32, what: &str) -> Result<Vec<u8>> {
    let size = usize::try_from(len)
        .map_err(|_| CoreError::invalid(format!("{what} does not fit memory")))?;
    let mut bytes = vec![0_u8; size];
    volume.read_exact_at(at, &mut bytes).map_err(|error| {
        CoreError::invalid(format!("reading the {what} at offset {at} failed: {error}"))
    })?;
    Ok(bytes)
}

/// Zero one whole cluster (the shape of a fresh directory cluster).
fn zero_cluster(volume: &mut dyn Volume, geometry: &Geometry, cluster: u32) -> Result<()> {
    let at = geometry.cluster_offset(cluster)?;
    let zeros = vec![0_u8; usize::try_from(geometry.cluster_bytes()).unwrap_or(0)];
    volume.write_all_at(at, &zeros)
}

/// A slot's 32 bytes copied out of a directory's in-memory bytes (the
/// memory mapping is cluster-major: cluster *i*'s bytes start at
/// `i * cluster_bytes`).
fn slot_image(
    content: &DirContent,
    cluster_bytes: usize,
    slot: usize,
) -> Result<[u8; format::ENTRY_BYTES]> {
    let per_cluster = cluster_bytes / format::ENTRY_BYTES;
    if per_cluster == 0 {
        return Err(CoreError::invalid(
            "a cluster smaller than one directory slot cannot hold entries".to_string(),
        ));
    }
    let cluster_index = slot / per_cluster;
    let within = slot % per_cluster;
    let at = cluster_index
        .checked_mul(cluster_bytes)
        .and_then(|base| base.checked_add(within.checked_mul(format::ENTRY_BYTES)?))
        .ok_or_else(|| CoreError::invalid("a slot window overflows".to_string()))?;
    let window = content
        .bytes
        .get(at..at.saturating_add(format::ENTRY_BYTES))
        .ok_or_else(|| CoreError::invalid(format!("slot {slot} lost its window")))?;
    let Ok(image) = <[u8; format::ENTRY_BYTES]>::try_from(window) else {
        return Err(CoreError::invalid(format!("slot {slot} is not 32 bytes")));
    };
    Ok(image)
}

/// A parent path as display text (`/a/b`; the root is `/`).
fn parent_text(components: &[String]) -> String {
    if components.is_empty() {
        return "/".to_string();
    }
    format!("/{}", components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use std::cell::Cell;
    use std::rc::Rc;

    const MIB: u64 = 1024 * 1024;
    const SERIAL: u32 = 0x5EED_1234;

    fn formatted() -> Exfat<VecVolume> {
        let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        let options = format::FormatOptions::new(SERIAL);
        Exfat::format(volume, &options).expect("the formatter accepts this store")
    }

    /// A formatted volume whose store can be told to fail on the Nth
    /// write: the seam the torn-write and rollback tests drive.
    fn flaky_formatted() -> Exfat<Flaky> {
        let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        let options = format::FormatOptions::new(SERIAL);
        Exfat::format(Flaky::new(volume), &options).expect("the formatter accepts this store")
    }

    fn names(listing: &[DirInfo]) -> Vec<&str> {
        listing.iter().map(|entry| entry.name.as_str()).collect()
    }

    #[test]
    fn a_created_tree_lists_back_in_creation_order() {
        let mut volume = formatted();

        volume
            .mkdir("/docs", dirent::Stamps::epoch())
            .expect("the directory is created");
        volume
            .create_file("/docs/readme.txt", 0, dirent::Stamps::epoch())
            .expect("the empty file is created");
        volume
            .create_file("/docs/Mixed Case.txt", 0, dirent::Stamps::epoch())
            .expect("the mixed-case file is created");

        let root = volume.list_dir("/").expect("the root lists");
        assert_eq!(names(&root), ["docs"]);
        assert!(root[0].is_dir, "the root entry is a directory");
        assert_eq!(
            root[0].size,
            volume.geometry().cluster_bytes(),
            "a directory reports its whole allocation"
        );

        let docs = volume.list_dir("/docs").expect("the directory lists");
        assert_eq!(names(&docs), ["readme.txt", "Mixed Case.txt"]);
        assert!(!docs[0].is_dir, "a file is not a directory");
        assert_eq!(docs[1].size, 0, "an empty file allocates nothing");
    }

    #[test]
    fn a_fresh_volume_lists_nothing_and_hides_the_system_entries() {
        let volume = formatted();
        assert!(
            volume.list_dir("/").expect("the root lists").is_empty(),
            "the bitmap, up-case and label entries never list"
        );
    }

    #[test]
    fn a_duplicate_name_is_refused_case_insensitively() {
        let mut volume = formatted();
        volume
            .create_file("/notes.txt", 0, dirent::Stamps::epoch())
            .expect("the first file is created");

        let error = volume
            .create_file("/NOTES.TXT", 0, dirent::Stamps::epoch())
            .expect_err("the second name collides");
        let message = error.to_string();
        assert!(
            message.contains("exists"),
            "the refusal names the collision: {message}"
        );
        assert_eq!(
            names(&volume.list_dir("/").expect("the root lists")),
            ["notes.txt"],
            "the refused create added nothing"
        );
    }

    #[test]
    fn a_create_with_no_room_rolls_the_ledger_back() {
        let mut volume = formatted();
        let free_before = volume.free_bytes();
        let clusters_before = volume.bitmap.free_clusters();

        let error = volume
            .create_file("/huge.bin", 64 * MIB, dirent::Stamps::epoch())
            .expect_err("the volume cannot hold this file");
        assert!(
            error.to_string().contains("cluster"),
            "the refusal reports the allocation: {error}"
        );
        assert_eq!(volume.free_bytes(), free_before, "the ledger is restored");
        assert_eq!(volume.bitmap.free_clusters(), clusters_before);
        assert!(
            volume.list_dir("/").expect("the root lists").is_empty(),
            "the refused create left no entry"
        );
    }

    #[test]
    fn directories_grow_past_one_cluster_in_the_root_and_in_a_subdirectory() {
        let mut volume = formatted();
        let slots_per_cluster = usize::try_from(volume.geometry().cluster_bytes() / 32)
            .expect("a cluster holds a whole number of slots");
        // Every short-named file is a three-slot set, so this many
        // entries cannot fit one cluster.
        let count = slots_per_cluster / 3 + 4;

        volume
            .mkdir("/inner", dirent::Stamps::epoch())
            .expect("the directory is created");
        for index in 0..count {
            volume
                .create_file(&format!("/f{index:04}.bin"), 0, dirent::Stamps::epoch())
                .expect("the root accepts the entry");
            volume
                .create_file(
                    &format!("/inner/g{index:04}.bin"),
                    0,
                    dirent::Stamps::epoch(),
                )
                .expect("the subdirectory accepts the entry");
        }

        assert_eq!(
            volume.list_dir("/").expect("the root lists").len(),
            count + 1
        );
        assert_eq!(
            volume
                .list_dir("/inner")
                .expect("the directory lists")
                .len(),
            count
        );
        for index in 0..count {
            let name = format!("f{index:04}.bin");
            assert!(
                volume
                    .list_dir("/")
                    .expect("the root lists")
                    .iter()
                    .any(|entry| entry.name == name),
                "the entry {name} survives the growth"
            );
        }
    }

    #[test]
    fn flush_publishes_the_allocated_percentage_of_the_used_clusters() {
        let mut volume = formatted();
        // Three mebibytes of an eight mebibyte volume: a floored
        // percentage that is far from zero, so "always write 0" fails.
        volume
            .create_file("/payload.bin", 3 * MIB, dirent::Stamps::epoch())
            .expect("the file is created");

        let cluster_count = u64::from(volume.geometry().cluster_count);
        let used = cluster_count - u64::from(volume.bitmap.free_clusters());
        let expected = u8::try_from(used * 100 / cluster_count).expect("a percentage fits a byte");
        assert!(
            expected >= 30,
            "the fixture must keep the percentage away from zero"
        );

        volume.flush().expect("the volume flushes");
        let boot = volume
            .volume
            .bytes()
            .get(..512)
            .expect("the boot sector exists");
        assert_eq!(
            boot[PERCENT_IN_USE_AT], expected,
            "byte 112 carries the floored percentage of allocated clusters"
        );
        // The backup boot region carries the same byte.
        let backup = volume
            .volume
            .bytes()
            .get(12 * 512..13 * 512)
            .expect("the backup boot sector exists");
        assert_eq!(backup[PERCENT_IN_USE_AT], expected);
    }

    /// A store that can be told to fail the next write, so a create
    /// path that fails *after* its first allocation is reachable.
    struct Flaky {
        inner: VecVolume,
        fail_after: Rc<Cell<Option<u64>>>,
        writes: Rc<Cell<u64>>,
    }

    impl Flaky {
        fn new(store: VecVolume) -> Self {
            Self {
                inner: store,
                fail_after: Rc::new(Cell::new(None)),
                writes: Rc::new(Cell::new(0)),
            }
        }
    }

    impl Volume for Flaky {
        fn total_bytes(&self) -> u64 {
            self.inner.total_bytes()
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_exact_at(offset, buf)
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            if let Some(limit) = self.fail_after.get() {
                if self.writes.get() >= limit {
                    // One shot: the rollback that follows a real I/O
                    // error must be able to write, so the injected
                    // failure happens exactly once.
                    self.fail_after.set(None);
                    return Err(CoreError::io(
                        "<flaky store>",
                        std::io::Error::other("injected write failure"),
                    ));
                }
                self.writes.set(self.writes.get() + 1);
            }
            self.inner.write_all_at(offset, buf)
        }

        fn flush(&mut self) -> Result<()> {
            self.inner.flush()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }
    }

    #[test]
    fn a_subdirectory_grows_in_place_next_to_a_free_cluster() {
        // Nothing is allocated beside `/solo`, so its growth takes the
        // neighbour rather than relocating: the stream entry on disk
        // must then carry the doubled data length.
        let mut volume = formatted();
        volume
            .mkdir("/solo", dirent::Stamps::epoch())
            .expect("the directory is created");
        let cluster_bytes = volume.geometry().cluster_bytes();
        for index in 0..60_u32 {
            let name = format!("/solo/f{index:03}.bin");
            volume
                .create_file(&name, 0, dirent::Stamps::epoch())
                .expect("the file is created");
        }

        let listing = volume.list_dir("/solo").expect("the directory lists");
        assert_eq!(listing.len(), 60, "every entry survives the growth");
        let root = volume.list_dir("/").expect("the root lists");
        let solo = root.first().expect("solo is listed");
        assert_eq!(
            solo.size,
            2 * cluster_bytes,
            "the on-disk stream length moved with the in-place extension"
        );
    }

    #[test]
    fn a_write_failure_midway_rolls_the_ledger_back() {
        let store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        let mut volume = Exfat::format(Flaky::new(store), &format::FormatOptions::new(SERIAL))
            .expect("the formatter accepts this store");
        let before_free = volume.free_bytes();
        let bitmap_first = volume.bitmap.first_cluster();
        let bitmap_at = volume
            .geometry
            .cluster_offset(bitmap_first)
            .expect("the bitmap cluster has an offset");
        let span = volume.bitmap.bytes().len();
        let mut before = vec![0_u8; span];
        volume
            .volume
            .read_exact_at(bitmap_at, &mut before)
            .expect("the bitmap reads");

        volume.volume.fail_after.set(Some(0));
        let error = volume
            .create_file("/lost.bin", 8192, dirent::Stamps::epoch())
            .expect_err("the injected write failure refuses the create");
        assert!(error.to_string().contains("injected"), "{error}");
        volume.volume.fail_after.set(None);

        assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
        assert!(
            volume.list_dir("/").expect("the root lists").is_empty(),
            "no entry survives the refused create"
        );
        volume.flush().expect("the bitmap writes back");
        let mut after = vec![0_u8; span];
        volume
            .volume
            .read_exact_at(bitmap_at, &mut after)
            .expect("the bitmap reads");
        assert_eq!(after, before, "the flushed bitmap is byte-identical");

        volume
            .create_file("/kept.bin", 8192, dirent::Stamps::epoch())
            .expect("the retry succeeds");
        let cluster_bytes = volume.geometry().cluster_bytes();
        assert_eq!(
            volume.free_bytes(),
            before_free - 2 * cluster_bytes,
            "two clusters are claimed by the retry"
        );
    }

    #[test]
    fn a_torn_set_is_skipped_not_a_poisoned_directory() {
        let mut volume = flaky_formatted();
        let before_free = volume.free_bytes();
        // A 4 KiB file writes its cluster (if the allocator zeroes
        // it), then the dormant lead, the stream, the name and finally
        // the lead again. Failing on the last write leaves the whole set
        // on disk with its lead still deactivated -- exactly the state a
        // power cut during a create produces.
        volume.volume.writes.set(0);
        volume.volume.fail_after.set(Some(3));
        let error = volume
            .create_file("/torn.bin", 4096, dirent::Stamps::epoch())
            .expect_err("the injected write failure refuses the create");
        assert!(error.to_string().contains("injected"), "{error:?}");
        volume.volume.fail_after.set(None);

        assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
        assert!(
            volume
                .list_dir("/")
                .expect("the root still parses")
                .is_empty(),
            "a deactivated set is skipped, not a checksum failure"
        );

        // The bytes really are the deleted shape, not never-written.
        let cluster_bytes = usize::try_from(volume.geometry.cluster_bytes()).expect("fits");
        let root_first = volume
            .geometry
            .cluster_offset(volume.geometry.root_cluster)
            .expect("the root has an offset");
        let mut root = vec![0_u8; cluster_bytes];
        volume
            .volume
            .read_exact_at(root_first, &mut root)
            .expect("the root reads");
        let listing = dirent::parse_dir_listing(&root).expect("the torn root parses");
        let lead = listing.terminator_slot;
        assert_eq!(
            root.get(lead * 32).copied(),
            Some(dirent::ENTRY_IN_USE & 0x7F),
            "the lead slot is a deleted entry"
        );

        volume
            .create_file("/kept.bin", 4096, dirent::Stamps::epoch())
            .expect("the retry succeeds");
        assert_eq!(volume.list_dir("/").expect("the root lists").len(), 1);
    }

    #[test]
    fn a_rolled_back_root_growth_puts_the_root_chain_back() {
        let mut volume = flaky_formatted();
        let slots = usize::try_from(volume.geometry.cluster_bytes() / 32).expect("fits");
        // The root already holds its two system entries plus the
        // end-of-directory marker, and every create takes three slots
        // (file, stream and one name entry -- an 8.3 name still carries
        // a 0xC1), so this fills the cluster exactly and leaves no slot
        // for the next set: the create below has to grow the chain.
        let fitting = (slots.saturating_sub(3)) / 3 + 1;
        for index in 0..fitting {
            volume
                .create_file(&format!("/f{index:03}.bin"), 0, dirent::Stamps::epoch())
                .expect("the root fills");
        }
        let root_cluster = volume.geometry.root_cluster;
        assert_eq!(
            volume
                .fat_entry(root_cluster)
                .expect("the root chain reads"),
            FAT_END_OF_CHAIN,
            "a full root still ends at its last cluster"
        );
        let before_free = volume.free_bytes();
        let before_listing = volume.list_dir("/").expect("the root lists").len();

        // The growth writes: the new cluster (0), its end-of-chain (1),
        // the link on the tail (2), then the set's dormant lead (3),
        // where the failure lands -- after both FAT words.
        volume.volume.writes.set(0);
        volume.volume.fail_after.set(Some(3));
        let error = volume
            .create_file("/grow.bin", 0, dirent::Stamps::epoch())
            .expect_err("the injected write failure refuses the create");
        assert!(error.to_string().contains("injected"), "{error}");
        volume.volume.fail_after.set(None);

        assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
        assert_eq!(
            volume.list_dir("/").expect("the root lists").len(),
            before_listing,
            "no entry survives the refused create"
        );
        assert_eq!(
            volume
                .fat_entry(root_cluster)
                .expect("the root chain reads"),
            FAT_END_OF_CHAIN,
            "the rollback puts the old end-of-chain back: a live root must not point at a freed cluster"
        );

        // The next create grows the root again, cleanly.
        volume
            .create_file("/grow.bin", 0, dirent::Stamps::epoch())
            .expect("the retry grows the root");
        assert_eq!(
            volume.list_dir("/").expect("the root lists").len(),
            before_listing + 1
        );
    }

    #[test]
    fn a_formatted_volume_opens_and_lists_back() {
        let mut volume = formatted();
        volume
            .mkdir("/docs", dirent::Stamps::epoch())
            .expect("the directory is created");
        volume
            .create_file("/docs/a.txt", 4096, dirent::Stamps::epoch())
            .expect("the file is created");
        volume.flush().expect("the volume flushes");
        let bytes = volume.volume.bytes().to_vec();
        let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        store
            .write_all_at(0, &bytes)
            .expect("the image copies back");
        let reopened = Exfat::open(store).expect("the formatter's image opens");
        assert_eq!(reopened.free_bytes(), volume.free_bytes());
        assert_eq!(
            reopened
                .list_dir("/docs")
                .expect("the directory lists")
                .len(),
            1
        );
    }

    #[test]
    fn open_refuses_a_damaged_boot_region_checksum() {
        let mut volume = formatted();
        volume.flush().expect("the volume flushes");
        let sector = usize::try_from(volume.geometry.sector_size).expect("fits");
        let mut bytes = volume.volume.bytes().to_vec();
        // Flip one byte inside the boot sector proper: the stored
        // checksum in sector 11 no longer describes it.
        bytes[sector + 123] ^= 0x01;
        let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        store
            .write_all_at(0, &bytes)
            .expect("the image copies back");
        let Err(error) = Exfat::open(store) else {
            panic!("a damaged boot region must not open");
        };
        let text = error.to_string();
        assert!(text.contains("checksum"), "{text}");
    }

    #[test]
    fn open_refuses_a_damaged_checksum_sector() {
        let mut volume = formatted();
        volume.flush().expect("the volume flushes");
        let sector = usize::try_from(volume.geometry.sector_size).expect("fits");
        let mut bytes = volume.volume.bytes().to_vec();
        // Sector 11 is the checksum sector, and its *first* word is
        // the one `open` compares against the accumulated checksum (the
        // sector repeats it for the region's other copies; flipping a
        // repetition is invisible to a reader that only reads word 0,
        // which is why the corruption goes in the first word).
        bytes[11 * sector] ^= 0x40;
        let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        store
            .write_all_at(0, &bytes)
            .expect("the image copies back");
        let Err(error) = Exfat::open(store) else {
            panic!("a damaged boot region must not open");
        };
        assert!(error.to_string().contains("checksum"), "{error}");
    }

    #[test]
    fn a_fragmented_directory_reads_its_chain_and_refuses_growth() {
        // A directory grown in place stays contiguous. Turn the same
        // bytes into a FAT-chained directory by linking the run and
        // clearing NoFatChain, the shape another implementation may
        // write; reading it must still work, and growing it must refuse
        // rather than write a stream entry its FAT chain does not back.
        let mut volume = formatted();
        volume
            .mkdir("/d", dirent::Stamps::epoch())
            .expect("the directory is created");
        let slots = usize::try_from(volume.geometry().cluster_bytes() / 32).expect("slots");
        let per_set = 3; // file, stream, one name entry
        let count = slots / per_set + 4;
        for index in 0..count {
            volume
                .create_file(&format!("/d/f{index:03}.bin"), 0, dirent::Stamps::epoch())
                .expect("the files fit after a growth");
        }
        let root = volume.root_level().expect("the root reads");
        let levels = volume.walk(&["d".to_owned()]).expect("the directory walks");
        let level = levels.last().expect("the directory level");
        assert!(level.contiguous, "the fixture starts contiguous");
        let chain = level.content.chain.clone();
        assert_eq!(chain.len(), 2, "the fixture grew to two clusters");
        volume
            .set_fat_entry(chain[0], chain[1])
            .expect("the link lands");
        volume
            .set_fat_entry(chain[1], FAT_END_OF_CHAIN)
            .expect("the end lands");
        let set_slots = level.own_set_slots.clone().expect("the set is known");
        let mut images: Vec<[u8; 32]> = set_slots
            .iter()
            .map(|slot| {
                let mut image = [0_u8; 32];
                let at = root
                    .content
                    .slot_address(volume.geometry(), *slot)
                    .expect("the slot has an address");
                volume
                    .volume
                    .read_exact_at(at, &mut image)
                    .expect("the slot reads");
                image
            })
            .collect();
        let stream = images.get_mut(1).expect("the set has a stream slot");
        let flags = stream.get(1).copied().expect("the flags are in range");
        *stream.get_mut(1).expect("the flags are in range") = flags & !0x02;
        let checksum = dirent::set_checksum(&images);
        images
            .first_mut()
            .expect("the set has a lead")
            .get_mut(2..4)
            .expect("the checksum field is in range")
            .copy_from_slice(&checksum.to_le_bytes());
        for (slot, image) in set_slots.iter().zip(images.iter()) {
            let at = root
                .content
                .slot_address(volume.geometry(), *slot)
                .expect("the slot has an address");
            volume
                .volume
                .write_all_at(at, image)
                .expect("the slot writes");
        }
        volume.flush().expect("the image flushes");

        let mut reopened = Exfat::open(volume.volume.clone()).expect("the image reopens");
        let listed = reopened.list_dir("/d").expect("a chained directory lists");
        assert_eq!(listed.len(), count, "every entry survives the chain read");

        // Fill the two clusters, then one more set has to grow the
        // directory - which a fragmented allocation cannot do.
        let target_sets = (2 * slots) / per_set;
        let mut created = count;
        while created < target_sets {
            reopened
                .create_file(&format!("/d/f{created:03}.bin"), 0, dirent::Stamps::epoch())
                .expect("the directory still has slots");
            created += 1;
        }
        let error = reopened
            .create_file("/d/overflow.bin", 0, dirent::Stamps::epoch())
            .expect_err("a fragmented directory cannot grow");
        assert!(
            error.to_string().contains("fragmented"),
            "the refusal names the fragmentation: {error}"
        );
    }

    #[test]
    fn a_path_naming_the_root_is_not_a_leaf() {
        let mut volume = formatted();
        let error = volume
            .mkdir("/", dirent::Stamps::epoch())
            .expect_err("the root cannot be created");
        assert!(error.to_string().contains("root"), "{error}");
    }
}
