//! The live exFAT volume (S10 part B1) — the file/directory API core
//! over the formatter substrate from part A: [`Exfat::format`] and
//! [`Exfat::open`] build (or adopt) a volume, and every operation this
//! slice owns is a method on it: `mkdir`, `create_file`, `list_dir`,
//! `free_bytes`, `flush` plus the geometry handle. `write_at` and
//! `read_file` joined in part B2's content half; `set_times` joined in
//! B2b's stamp half, `set_label` alongside it.
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
//!   set) and are never overwritten, because nothing ever writes
//!   before the terminator slot — `set_label`'s replacement of a live
//!   0x83 slot is the one deliberate exception, with a fresh label
//!   appending at the marker slot like every set. The one 0x00 marker
//!   ends the directory, and the slots behind it stay zero, so the set
//!   written into the marker's slot always leaves a fresh marker after
//!   itself.
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
//! * **File data** is written through `write_at` into the file's own
//!   contiguous run, and growing it follows the same shape directory
//!   growth does: adopt the run's free neighbours in place when the
//!   bitmap shows them inside the heap, or relocate the whole run — a
//!   fresh contiguous allocation, the `ValidDataLength` bytes copied
//!   over, the old clusters freed, the stream entry rewritten with the
//!   set checksum recomputed. Both live under the same
//!   snapshot/rollback ledger and never touch the FAT (file clusters
//!   are bitmap-only; `fat_writes` stays empty there). Bytes a growing
//!   `ValidDataLength` makes readable that sit between the old valid
//!   length and the write's offset are zeroed first — the zero region
//!   the format promises there — while the allocation tail beyond
//!   `ValidDataLength` is never read back. `DataLength` ends at the
//!   write's own end, so a listing reports the bytes written. The entry's stamps
//!   never move in these paths; `set_times` owns them.
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
use crate::fs::exfat::put_bytes;
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
    /// The file's size in bytes, straight from its stream entry's
    /// `DataLength` (byte-exact, even when the allocation rounds up);
    /// for a directory, its whole allocation.
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

/// How much of a zero gap or a relocation copy moves per write.
///
/// Both spans are bounded by the heap's own byte size (up to 2 TiB) or
/// by a file's valid length, so they are streamed through a fixed
/// buffer instead of being materialised.
const COPY_CHUNK_BYTES: usize = 1024 * 1024;

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

/// A path resolved to a *file*: what the content read and write paths
/// need — the parent chain's live directory content, the file's own
/// slot window inside its parent, and the stream entry's allocation
/// facts. [`Exfat::resolve_file`] builds one; [`Exfat::write_at`] and
/// [`Exfat::read_file`] consume it.
#[derive(Debug, Clone)]
struct FileTarget {
    /// The resolved walk: the last level is the directory holding the
    /// file's set (the root for a top-level file).
    levels: Vec<Level>,
    /// Slot indices of the file's own set inside its parent — file
    /// entry, stream entry, then names.
    set_slots: Vec<usize>,
    /// First cluster of the file's allocation (`0` for the empty-file
    /// shape, which claims no cluster at all).
    first_cluster: u32,
    /// The stream entry's `DataLength`: the file's size in bytes,
    /// byte-exact even when the allocation rounds up to whole clusters
    /// (the on-disk size a listing reports).
    data_length: u64,
    /// The stream entry's `ValidDataLength`: how far user data has
    /// actually been written; everything past it is the zero region
    /// the format defines there.
    valid_data_length: u64,
}

/// The allocation shape one [`Exfat::grow_file`] call decided before
/// its first bitmap change: how many clusters the file holds, how many
/// the grown write needs, the `DataLength` that shape records, and —
/// for the in-place flavour — the first free neighbour to adopt from.
#[derive(Debug, Clone, Copy)]
struct GrowthPlan {
    /// Clusters the file's allocation currently spans.
    alloc_clusters: u32,
    /// Clusters the grown allocation spans.
    new_clusters: u32,
    /// The grown `DataLength`: the write's end.
    data_length: u64,
    /// Clusters the growth adds (`new_clusters - alloc_clusters`).
    needed: u32,
    /// First cluster of the free neighbours to adopt in place, or
    /// `None` for the relocation flavour.
    adopt_first: Option<u32>,
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
    // Files: content writes and reads
    // ------------------------------------------------------------------

    /// Write `data` into the file at `path` starting at byte `offset`,
    /// and update the entry so the write's shape is what every later
    /// reader sees.
    ///
    /// The file's clusters are one contiguous run and its stream entry
    /// sets NoFatChain; `DataLength` is the write's end (the
    /// allocation spans whole clusters past it) and `ValidDataLength` is the range a reader may
    /// return. A write whose end fits `DataLength` goes straight
    /// through; one that runs past grows the allocation first — the
    /// run's own free neighbours inside the heap when the bitmap shows
    /// them (in place, so the first cluster keeps its number), or a
    /// relocate-to-fresh-run: a contiguous allocation of the grown
    /// size, the `ValidDataLength` bytes copied over, the old clusters
    /// freed, the stream entry rewritten. Both shapes sit under the
    /// [`Snapshot`] ledger and never touch the FAT (file clusters are
    /// bitmap-only, so `fat_writes` stays empty): a refused allocation
    /// leaves `free_bytes` and the listing unchanged, and the
    /// allocation happens only after the volume-end refusal, which
    /// names the write's end and the heap's byte capacity
    /// (`cluster_count` clusters).
    ///
    /// Every refusal names its subject: a missing leaf, a leaf that is
    /// a directory, a fragmented allocation, and a stream entry whose
    /// valid length claims past its data length (all through
    /// [`Exfat::resolve_file`]). A zero-length write is a no-op once
    /// the path resolved: nothing is allocated, nothing is written
    /// and no checksum churns — `ValidDataLength` never grows past
    /// the bytes the entry can prove were written.
    ///
    /// Bytes between the old `ValidDataLength` and a growing write's
    /// offset are zeroed before the stream entry publishes the new
    /// valid length — the zero region the format promises there — and
    /// the grown `DataLength` ends at the write. The
    /// entry's stamps never move in this call: the separate
    /// `set_times` owns them.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let target = self.resolve_file(path, "write_at")?;
        if data.is_empty() {
            return Ok(());
        }
        let bytes = u64::try_from(data.len())
            .map_err(|_| CoreError::invalid("a write longer than a u64".to_string()))?;
        let end = offset.checked_add(bytes).ok_or_else(|| {
            CoreError::invalid(format!(
                "a write of {bytes} bytes at offset {offset} overflows a u64"
            ))
        })?;
        if end <= target.data_length {
            return self.write_through(target, offset, data, end);
        }
        self.grow_file(target, offset, data, end)
    }

    /// Read back the file at `path`: exactly `ValidDataLength` bytes,
    /// read through the file's own contiguous run — never the
    /// allocation's tail beyond the valid length, which is the zero
    /// region the format defines there.
    ///
    /// A missing path refuses with the path named, a directory refuses
    /// with the path named, a fragmented allocation (a stream entry
    /// without NoFatChain) refuses, and a stream entry whose valid
    /// length claims more than its data length refuses with both
    /// numbers (all [`Exfat::resolve_file`]'s refusals). The data
    /// length is additionally bounded by the volume's own data
    /// capacity before anything is read — see the comment in the body.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let target = self.resolve_file(path, "read_file")?;
        if target.valid_data_length == 0 {
            return Ok(Vec::new());
        }
        // The allocation is bounded by the volume's own data capacity
        // (`cluster_count` clusters of `cluster_bytes` bytes) before
        // the read buffer is built — the same discipline
        // [`Exfat::read_dir_content`] applies to a directory's data
        // length: a host-damaged claim of tebibytes refuses here, not
        // on the caller's back as a volume-sized allocation.
        let capacity = u64::from(self.geometry.cluster_count)
            .checked_mul(self.geometry.cluster_bytes())
            .ok_or_else(|| {
                CoreError::invalid("the heap's byte capacity overflows a u64".to_string())
            })?;
        if target.data_length > capacity {
            return Err(CoreError::invalid(format!(
                "the file at {path} claims {data_length} data bytes, beyond this heap's \
                 {capacity} data bytes",
                data_length = target.data_length
            )));
        }
        let last = self.geometry.cluster_count.saturating_add(1);
        if !(FIRST_HEAP_CLUSTER..=last).contains(&target.first_cluster) {
            return Err(CoreError::invalid(format!(
                "the file at {path} claims first cluster {}, not a cluster of this heap",
                target.first_cluster
            )));
        }
        let cluster_bytes = self.geometry.cluster_bytes();
        let clusters =
            u32::try_from(target.valid_data_length.div_ceil(cluster_bytes)).map_err(|_| {
                CoreError::invalid(format!(
                    "the file's valid length of {} bytes spans more clusters than u32",
                    target.valid_data_length
                ))
            })?;
        let end_cluster = target
            .first_cluster
            .checked_add(clusters.saturating_sub(1))
            .ok_or_else(|| CoreError::invalid("a data run overflows a u32".to_string()))?;
        if end_cluster > last {
            return Err(CoreError::invalid(format!(
                "the file at {path} reads to cluster {end_cluster}, past this heap's last \
                 cluster {last}"
            )));
        }
        let size = usize::try_from(target.valid_data_length).map_err(|_| {
            CoreError::invalid("the file's valid length does not fit memory".to_string())
        })?;
        let mut bytes = vec![0_u8; size];
        self.volume.read_exact_at(
            self.geometry.cluster_offset(target.first_cluster)?,
            &mut bytes,
        )?;
        Ok(bytes)
    }

    /// Resolve `path` to one *file* entry set: the walk resolves the
    /// parent chain (component-shaped refusals, the offending component
    /// named), the leaf is looked up in its parent's live listing, and
    /// a hit is reduced to the facts the content calls need — the
    /// parent chain itself, the leaf's own slot window, and the stream
    /// entry's allocation numbers.
    ///
    /// Every refusal names the path or the component that produced it:
    /// a leaf that is not on the volume, a leaf that is a directory
    /// (`op` names which operation wanted a file), a stream entry that
    /// does not mark the allocation NoFatChain (a fragmented file is a
    /// FAT chain, which nothing here reads or extends), and a stream
    /// entry whose valid length claims past its data length (host
    /// damage, both numbers named).
    fn resolve_file(&self, path: &str, op: &str) -> Result<FileTarget> {
        let Some(components) = Self::split_path(path)? else {
            return Err(CoreError::invalid(format!(
                "path {path:?} names a directory, and {op} works on a file's content"
            )));
        };
        let leaf = components
            .last()
            .cloned()
            .ok_or_else(|| CoreError::invalid("a path without a final component".to_string()))?;
        let parents: Vec<String> = components
            .iter()
            .take(components.len().saturating_sub(1))
            .cloned()
            .collect();
        let levels = self.walk(&parents)?;
        let parent = levels.last().ok_or_else(|| {
            CoreError::invalid("a path's last directory vanished from the walk".to_string())
        })?;
        let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
        let upcased = dirent::upcase_name(&leaf);
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
            if entry.is_dir {
                return Err(CoreError::invalid(format!(
                    "path {path:?} names a directory, and {op} works on a file's content"
                )));
            }
            // The set's second slot is its stream entry; byte 1
            // carries the flags whose NoFatChain bit decides the
            // allocation shape. (The flags sit outside dirent's
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
            if entry.first_cluster != 0 && stream_flags & dirent::STREAM_NO_FAT_CHAIN == 0 {
                return Err(CoreError::invalid(format!(
                    "the file at {path} has a fragmented allocation (its stream entry does not \
                     set NoFatChain), which no content read or write here can address"
                )));
            }
            if entry.valid_data_length > entry.size {
                return Err(CoreError::invalid(format!(
                    "the file at {path} claims {valid} valid data bytes beyond its {size} data \
                     length",
                    valid = entry.valid_data_length,
                    size = entry.size
                )));
            }
            let set_end =
                listing
                    .set_starts
                    .get(index.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("an entry index overflows".to_string())
                    })?)
                    .copied()
                    .unwrap_or(listing.terminator_slot);
            return Ok(FileTarget {
                levels,
                set_slots: (start..set_end).collect(),
                first_cluster: entry.first_cluster,
                data_length: entry.size,
                valid_data_length: entry.valid_data_length,
            });
        }
        Err(CoreError::invalid(format!(
            "path {path:?} does not exist on the volume"
        )))
    }

    /// The in-allocation half of [`Exfat::write_at`]: the write's end
    /// fits `DataLength`, so no cluster moves or is claimed. The gap
    /// the write jumps over (if `ValidDataLength` grows past it) is
    /// zeroed first, then the data goes down, then the stream slot is
    /// rewritten only when its contents really change — the valid
    /// length, or `DataLength` moving out to the write's own end. Both
    /// rewrites keep the two-phase order and the recomputed set
    /// checksum ([`Exfat::rewrite_stream_slot`]).
    fn write_through(
        &mut self,
        mut target: FileTarget,
        offset: u64,
        data: &[u8],
        end: u64,
    ) -> Result<()> {
        // `DataLength` is the write's own end, not the allocation's
        // byte size: the kernel keeps it byte-exact for `NoFatChain`
        // files (measured: a 5000-byte file reads `data=5000`) and a
        // listing reports it as the file size, so padding it to whole
        // clusters would make every written file longer than its
        // payload.
        let record = end.max(target.data_length);
        let base = self.geometry.cluster_offset(target.first_cluster)?;
        self.write_gap_and_data(base, target.valid_data_length, offset, data)?;
        if end <= target.valid_data_length && record == target.data_length {
            return Ok(());
        }
        let parent = target
            .levels
            .last_mut()
            .ok_or_else(|| CoreError::invalid("the file's directory vanished".to_string()))?;
        let valid = end.max(target.valid_data_length);
        self.rewrite_stream_slot(
            parent,
            &target.set_slots,
            target.first_cluster,
            record,
            valid,
            false,
        )
    }

    /// The growth half of [`Exfat::write_at`]: the write's `end` runs
    /// past `DataLength`, so the allocation moves. The volume-end
    /// refusal comes first, before any state moves. If the grown size
    /// still fits the existing clusters, no cluster is claimed and
    /// [`Exfat::write_through`] finishes the call, publishing
    /// `DataLength` as the write's end; otherwise the free
    /// neighbours are surveyed and the growth is committed in place or
    /// by relocation, under the [`Snapshot`] ledger.
    fn grow_file(&mut self, target: FileTarget, offset: u64, data: &[u8], end: u64) -> Result<()> {
        let cluster_bytes = self.geometry.cluster_bytes();
        let capacity = u64::from(self.geometry.cluster_count)
            .checked_mul(cluster_bytes)
            .ok_or_else(|| {
                CoreError::invalid("the heap's byte capacity overflows a u64".to_string())
            })?;
        if end > capacity {
            return Err(CoreError::invalid(format!(
                "the write ends at {end} bytes, past this volume's {cluster_count} clusters of \
                 {cluster_bytes} bytes ({capacity} bytes of data)",
                cluster_count = self.geometry.cluster_count
            )));
        }
        let alloc_clusters =
            u32::try_from(target.data_length.div_ceil(cluster_bytes)).map_err(|_| {
                CoreError::invalid("the file's allocation is longer than u32 clusters".to_string())
            })?;
        let new_clusters = u32::try_from(end.div_ceil(cluster_bytes)).map_err(|_| {
            CoreError::invalid("the grown allocation is longer than u32 clusters".to_string())
        })?;
        // `end <= capacity` above bounds both divisions: the grown
        // cluster count cannot exceed the heap's own count, so the
        // checked conversions are the belt for that reasoning.
        if new_clusters == alloc_clusters {
            // The write fits the clusters already claimed, so nothing
            // moves but `DataLength` (out to the write's end) and
            // `ValidDataLength`; no cluster is claimed, so no snapshot
            // is taken either.
            return self.write_through(target, offset, data, end);
        }
        let needed = new_clusters.checked_sub(alloc_clusters).ok_or_else(|| {
            CoreError::invalid(format!(
                "the grown allocation of {new_clusters} clusters cannot shrink below the \
                 current {alloc_clusters}"
            ))
        })?;
        // The adoption survey, read-only: the growth stays in place
        // when the run's own following clusters are free and still
        // inside the heap — the same rule the directory growth
        // applies. An empty allocation (first cluster 0) has no
        // neighbours to adopt from.
        let last = self.geometry.cluster_count.saturating_add(1);
        let mut adopt_first: Option<u32> = None;
        if target.first_cluster != 0
            && let Some(start) = target.first_cluster.checked_add(alloc_clusters)
        {
            let free = (0..needed).all(|step| {
                start.checked_add(step).is_some_and(|cluster| {
                    cluster <= last && self.bitmap.is_free(cluster).unwrap_or(false)
                })
            });
            if free {
                adopt_first = Some(start);
            }
        }
        // From here on, any failure rolls the ledger back: the adopted
        // neighbours, or the fresh relocation run plus the released
        // old clusters, all return to the snapshot state. File
        // clusters are bitmap-only, so the ledger's `fat_writes` stays
        // empty and the restore replays no FAT words.
        let snapshot = self.snapshot();
        let plan = GrowthPlan {
            alloc_clusters,
            new_clusters,
            data_length: end.max(target.data_length),
            adopt_first,
            needed,
        };
        let result = self.grow_committed(target, plan, offset, data, end);
        if result.is_err() {
            // The commit error is the one worth reporting; a failed
            // undo would only mask it, and the next open recounts the
            // bitmap anyway.
            self.restore(snapshot).ok();
        }
        result
    }

    /// The committed half of [`Exfat::grow_file`], transaction-shaped:
    /// the caller took the [`Snapshot`] and restores it if this errs.
    /// The shape follows the directory growth's orders — adopt the
    /// surveyed free neighbours and keep the first cluster, or
    /// allocate a fresh contiguous run while the old one still exists,
    /// copy it, rewrite the stream entry, and release the old clusters
    /// last.
    fn grow_committed(
        &mut self,
        mut target: FileTarget,
        plan: GrowthPlan,
        offset: u64,
        data: &[u8],
        end: u64,
    ) -> Result<()> {
        let valid = end.max(target.valid_data_length);
        let relocated = plan.adopt_first.is_none();
        let (first, base) = match plan.adopt_first {
            Some(first_free) => {
                // The surveyed neighbours come in as specific free
                // clusters, so the allocation is a mark
                // ([`Exfat::allocate_in_place`]) rather than a scan.
                self.allocate_in_place(plan.needed, first_free)?;
                (
                    target.first_cluster,
                    self.geometry.cluster_offset(target.first_cluster)?,
                )
            }
            None => {
                // A refusal here names the count and the free-cluster
                // count; the snapshot is already on the ledger, and
                // with no allocation yet made the restore keeps
                // `free_bytes` and the listing exactly as they were.
                let run = self.allocate(plan.new_clusters, "a file growth relocation needs")?;
                let base = self.geometry.cluster_offset(run)?;
                // The old run still exists while the copy reads it,
                // so the fresh run cannot collide with the bytes it
                // replaces.
                if target.valid_data_length > 0 {
                    // Copied in fixed-size pieces: the source range is
                    // a file's valid length, which can be gigabytes on
                    // a large volume, so a single buffer would tie the
                    // allocation to the file size.
                    let source = self.geometry.cluster_offset(target.first_cluster)?;
                    let mut moved = 0_u64;
                    let mut piece = vec![0_u8; COPY_CHUNK_BYTES];
                    while moved < target.valid_data_length {
                        let left = target.valid_data_length - moved;
                        let take =
                            usize::try_from(left.min(COPY_CHUNK_BYTES as u64)).map_err(|_| {
                                CoreError::invalid(
                                    "the file's valid length does not fit memory".to_string(),
                                )
                            })?;
                        let buffer = piece.get_mut(..take).ok_or_else(|| {
                            CoreError::invalid("the copy piece fits its buffer".to_string())
                        })?;
                        let at = source.checked_add(moved).ok_or_else(|| {
                            CoreError::invalid("the copy's address overflows a u64".to_string())
                        })?;
                        self.volume.read_exact_at(at, buffer)?;
                        let to = base.checked_add(moved).ok_or_else(|| {
                            CoreError::invalid("the copy's address overflows a u64".to_string())
                        })?;
                        self.volume.write_all_at(to, buffer)?;
                        moved += take as u64;
                    }
                }
                (run, base)
            }
        };
        self.write_gap_and_data(base, target.valid_data_length, offset, data)?;
        let parent = target
            .levels
            .last_mut()
            .ok_or_else(|| CoreError::invalid("the file's directory vanished".to_string()))?;
        self.rewrite_stream_slot(
            parent,
            &target.set_slots,
            first,
            plan.data_length,
            valid,
            true,
        )?;
        if relocated && plan.alloc_clusters > 0 {
            // The stream entry now names the fresh run: the old
            // allocation's clusters are unreferenced, and return to
            // the pool the same way a directory relocation frees its
            // run. A file that had no allocation at all (the empty
            // file every `create_file` starts as, first cluster 0)
            // releases nothing -- `Bitmap::clear` refuses an empty
            // run, and there is no old run to give back.
            self.release(plan.alloc_clusters, target.first_cluster)?;
        }
        Ok(())
    }

    /// Put a write's bytes down at `base + offset`, zeroing the gap
    /// from `valid` first when the write starts past it: the range the
    /// growing valid length makes readable is the zero region, so the
    /// bytes between the old reader limit and the write's own offset
    /// are zeros, not whatever the run held before.
    fn write_gap_and_data(
        &mut self,
        base: u64,
        valid: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        if offset > valid {
            // Streamed in fixed-size pieces: a sparse write far past
            // the old end may ask for a zero region many gigabytes
            // wide, which no single buffer should have to hold.
            let mut filled = valid;
            let zeros = vec![0_u8; COPY_CHUNK_BYTES];
            while filled < offset {
                let take = usize::try_from((offset - filled).min(COPY_CHUNK_BYTES as u64))
                    .map_err(|_| {
                        CoreError::invalid(
                            "the write's zero region does not fit memory".to_string(),
                        )
                    })?;
                let buffer = zeros.get(..take).ok_or_else(|| {
                    CoreError::invalid("the zero piece fits its buffer".to_string())
                })?;
                let at = base.checked_add(filled).ok_or_else(|| {
                    CoreError::invalid("the zero region's address overflows a u64".to_string())
                })?;
                self.volume.write_all_at(at, buffer)?;
                filled += take as u64;
            }
        }
        let at = base
            .checked_add(offset)
            .ok_or_else(|| CoreError::invalid("the write's address overflows a u64".to_string()))?;
        self.volume.write_all_at(at, data)
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
    // Stamps: set_times
    // ------------------------------------------------------------------

    /// Stamp the entry at `path` (a file or a directory, found
    /// case-insensitively) with `times`. The set's lead File entry is
    /// the only slot that carries stamp fields, so it is the only one
    /// rewritten — the stream and name slots are left byte-for-byte
    /// untouched. All three stamp triples replace what the set
    /// carried, minus one thing: the format defines no 10 ms field
    /// for the access stamp, so only its date-time and UTC offset
    /// reach the disk.
    ///
    /// Nothing is allocated, so no [`Snapshot`] ledger is involved —
    /// the same no-ledger shape [`Exfat::rewrite_stream_slot`] has —
    /// yet the lead still goes down in the two-phase order, dormant
    /// first and live second: a torn stamp rewrite leaves a skipped
    /// set rather than a checksum failure at every later walk (see
    /// the module docs).
    ///
    /// Every refusal names its subject and happens before any byte
    /// moves: the root is not nameable here, a missing leaf refuses
    /// with the path named, and a mid-path component that is missing
    /// or a file surfaces [`Exfat::walk`]'s own refusal.
    pub fn set_times(&mut self, path: &str, times: dirent::Stamps) -> Result<()> {
        let Some(components) = Self::split_path(path)? else {
            return Err(CoreError::invalid(format!(
                "path {path:?} names the root directory, set_times needs an entry inside the volume"
            )));
        };
        let leaf = components
            .last()
            .cloned()
            .ok_or_else(|| CoreError::invalid("a path without a final component".to_string()))?;
        let parents: Vec<String> = components
            .iter()
            .take(components.len().saturating_sub(1))
            .cloned()
            .collect();
        let mut levels = self.walk(&parents)?;
        let parent = levels.last().ok_or_else(|| {
            CoreError::invalid("a path's last directory vanished from the walk".to_string())
        })?;
        let listing = dirent::parse_dir_listing(&parent.content.bytes)?;
        let upcased = dirent::upcase_name(&leaf);
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
            // The set's slots end where the next set begins (or at the
            // terminator), the same window every other leaf
            // resolution here reduces a hit to.
            let set_end =
                listing
                    .set_starts
                    .get(index.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("an entry index overflows".to_string())
                    })?)
                    .copied()
                    .unwrap_or(listing.terminator_slot);
            let set_slots: Vec<usize> = (start..set_end).collect();
            let parent = levels.last_mut().ok_or_else(|| {
                CoreError::invalid("a path's last directory vanished from the walk".to_string())
            })?;
            return self.rewrite_lead_stamps(parent, &set_slots, times);
        }
        Err(CoreError::invalid(format!(
            "path {path:?} does not exist on the volume"
        )))
    }

    /// Rewrite the stamp fields of one entry set living in `parent`:
    /// only the set's lead File slot changes — the patch, the
    /// recomputed set checksum and the two-phase write. The stream
    /// side's sibling is [`Exfat::rewrite_stream_slot`]: one slot
    /// kind, one helper, one convention.
    fn rewrite_lead_stamps(
        &mut self,
        parent: &mut Level,
        set_slots: &[usize],
        times: dirent::Stamps,
    ) -> Result<()> {
        let cluster_bytes = usize::try_from(self.geometry.cluster_bytes())
            .map_err(|_| CoreError::invalid("a cluster longer than this machine's usize"))?;
        let mut images = Vec::with_capacity(set_slots.len());
        for slot in set_slots {
            images.push(slot_image(&parent.content, cluster_bytes, *slot)?);
        }
        // The lead must be the File entry for a stamp rewrite to be
        // meaningful — [`dirent::parse_dir_listing`] only opens 0x85
        // sets, so this pins the same invariant on the very image the
        // patch below tampers with.
        let lead_type = images
            .first()
            .and_then(|image| image.first().copied())
            .unwrap_or(0);
        if lead_type != dirent::ENTRY_FILE {
            return Err(CoreError::invalid(format!(
                "an entry set starts with type byte {lead_type:#04x}, not the 0x85 file entry"
            )));
        }
        // The volume layer owns the field facts (they would sit in
        // dirent's private tables): the three DOS date-time words at
        // 8, 12 and 16, the 10 ms bytes at 20 (create) and 21 (modify)
        // — the format defines no 10 ms field for access — and the
        // three UTC-offset bytes at 22, 23 and 24.
        let Some(lead) = images.first_mut() else {
            return Err(CoreError::invalid(
                "a parent set lost its file slot".to_string(),
            ));
        };
        put_u32(lead, 8, times.create.date_time)?; // create date-time
        put_u32(lead, 12, times.modify.date_time)?; // modify date-time
        put_u32(lead, 16, times.access.date_time)?; // access date-time
        put_bytes(lead, 20, &[times.create.tenths])?; // create 10 ms
        put_bytes(lead, 21, &[times.modify.tenths])?; // modify 10 ms
        put_bytes(lead, 22, &[times.create.utc_offset])?; // create utc
        put_bytes(lead, 23, &[times.modify.utc_offset])?; // modify utc
        put_bytes(lead, 24, &[times.access.utc_offset])?; // access utc
        // The set checksum binds the whole set: recompute it over the
        // patched images and store it in the lead (bytes 2..=3, the
        // bytes [`dirent::set_checksum`] itself skips).
        let checksum = dirent::set_checksum(&images);
        let Some(lead) = images.first_mut() else {
            return Err(CoreError::invalid(
                "a parent set lost its file slot".to_string(),
            ));
        };
        put_u16(lead, 2, checksum)?;
        // Only the lead is written back — the secondaries are unchanged,
        // so rewriting them would only widen the torn window. Same
        // two-phase discipline as every other lead rewrite: the lead
        // goes down deactivated, then live, a torn rewrite leaving a
        // skipped set instead of a checksum failure.
        let lead_slot = set_slots
            .first()
            .copied()
            .ok_or_else(|| CoreError::invalid("a parent set lost its file slot".to_string()))?;
        let lead_at = parent.content.slot_address(&self.geometry, lead_slot)?;
        let lead_image = *images.first().unwrap_or(&[0_u8; format::ENTRY_BYTES]);
        let mut dormant = lead_image;
        dirent::deactivate(&mut dormant);
        self.volume.write_all_at(lead_at, &dormant)?;
        self.volume.write_all_at(lead_at, &lead_image)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Labels: set_label
    // ------------------------------------------------------------------

    /// Rewrite the volume label: `Some(name)` stores `name`, `None`
    /// retires a label that is on the volume — and an empty label
    /// string clears exactly like `None`, matching `format()`'s
    /// reading of an empty label.
    ///
    /// The label lives only in the root directory's 0x83 slot: the
    /// boot sector carries no label field, so this call moves no boot
    /// byte, no FAT word, no bitmap bit and no PercentInUse value.
    /// Nothing is allocated, so no [`Snapshot`] ledger is involved.
    ///
    /// Every refusal happens before the first write, so a refused call
    /// leaves the image untouched: the label's length and characters
    /// are validated through [`format::label_units`] first, then the
    /// destination slot is resolved — for an append, bounded by
    /// [`fresh_label_slot`] with the slot numbers named — before
    /// anything moves. A live label is rewritten in its own slot, the
    /// one root system slot this module may write before the
    /// terminator slot; a fresh label takes over the end-of-directory
    /// marker's slot, whose checked-zero successor becomes the marker
    /// exactly like every other append there. Deleted label slots
    /// (lead 0x03) are never reused, the same rule deleted sets follow.
    ///
    /// The one-slot write keeps the two-phase order the set rewrites
    /// use: the deleted image goes down first and the live image makes
    /// the label visible, so a torn window leaves either a deleted
    /// label or the fresh one — both states every walker handles —
    /// instead of a half-written entry.
    pub fn set_label(&mut self, label: Option<&str>) -> Result<()> {
        let Some(units) = format::label_units(label)? else {
            return self.clear_label();
        };
        // The live image is built before any write: the label's shape
        // above, the destination slot below — past both, only an I/O
        // failure can still refuse, and a torn window there leaves a
        // label-shaped slot of one whole form or the other.
        let image = format::label_entry(&units)?;
        let (root, listing) = self.root_listing()?;
        // The destination slot: the live label's own slot when there is
        // one, else the marker slot a fresh label takes over.
        let slot = match live_label_slot(&root.content, &listing) {
            Some(slot) => slot,
            None => fresh_label_slot(&root.content, &listing)?,
        };
        let at = root.content.slot_address(&self.geometry, slot)?;
        self.volume.write_all_at(at, &deleted_label_image()?)?;
        self.volume.write_all_at(at, &image)?;
        Ok(())
    }

    /// The clear half of [`Exfat::set_label`]: a live label's slot is
    /// rewritten to the deleted image in a single write — the deleted
    /// form is the *final* state, so there is no second phase to tear,
    /// and a window torn inside that one write leaves either the old
    /// live label or the deleted shape, both parseable — while a root
    /// without a live label writes nothing at all.
    fn clear_label(&mut self) -> Result<()> {
        let (root, listing) = self.root_listing()?;
        let Some(slot) = live_label_slot(&root.content, &listing) else {
            return Ok(()); // no label on the volume: a clear is already true
        };
        let at = root.content.slot_address(&self.geometry, slot)?;
        let deleted = deleted_label_image()?;
        self.volume.write_all_at(at, &deleted)
    }

    /// The root directory's content and its parsed listing, resolved
    /// once: the facts both label paths need — a live label's slot
    /// inside the content, plus the marker slot and the capacity the
    /// listing reports.
    fn root_listing(&self) -> Result<(Level, dirent::DirListing)> {
        let root = self.root_level()?;
        let listing = dirent::parse_dir_listing(&root.content.bytes)?;
        Ok((root, listing))
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
            self.allocate_in_place(1, new)?;
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

    /// The in-place flavour of [`Exfat::allocate`]: `count` *specific*
    /// clusters (an allocation run's surveyed free neighbours) instead
    /// of a first-fit scan. The caller validated the whole run free
    /// and inside the heap; the bitmap's own `mark` refuses otherwise,
    /// so the cached free count never drifts from the bit image.
    fn allocate_in_place(&mut self, count: u32, cluster: u32) -> Result<()> {
        self.bitmap.mark(count, cluster)?;
        self.free_clusters = self.free_clusters.checked_sub(count).ok_or_else(|| {
            CoreError::invalid(format!(
                "marking {count} neighbouring clusters would go negative"
            ))
        })?;
        self.bitmap_dirty = true;
        Ok(())
    }

    /// Rewrite a subdirectory's own stream entry inside its parent's
    /// set — first cluster, data length and (a directory's) valid-data
    /// length equal to it — through [`Exfat::rewrite_stream_slot`].
    /// This is what makes a directory relocation (or an in-place
    /// extension) visible to every reader at the parent.
    fn rewrite_stream_entry(
        &mut self,
        levels: &mut [Level],
        level_index: usize,
        first_cluster: u32,
        clusters: usize,
    ) -> Result<()> {
        let cluster_bytes = self.geometry.cluster_bytes();
        let count = u32::try_from(clusters).map_err(|_| {
            CoreError::invalid("a directory longer than u32 clusters is corrupt".to_string())
        })?;
        let data_length = u64::from(count).checked_mul(cluster_bytes).ok_or_else(|| {
            CoreError::invalid("a directory's data length overflows a u64".to_string())
        })?;
        let set_slots = levels
            .get(level_index)
            .and_then(|level| level.own_set_slots.clone())
            .ok_or_else(|| {
                CoreError::invalid("a relocated directory has no parent set".to_string())
            })?;
        let parent = levels
            .get_mut(level_index.checked_sub(1).ok_or_else(|| {
                CoreError::invalid("a relocated directory has no parent".to_string())
            })?)
            .ok_or_else(|| CoreError::invalid("the parent directory vanished".to_string()))?;
        self.rewrite_stream_slot(
            parent,
            &set_slots,
            first_cluster,
            data_length,
            data_length,
            true,
        )
    }

    /// Rewrite the stream slot of one entry set that lives in
    /// `parent`: FirstCluster, DataLength and ValidDataLength take the
    /// given numbers (a directory hands equal length values, a file's
    /// valid length trails its allocation), the parent set checksum is
    /// recomputed over the patched images, and the two changed images
    /// go back down in the two-phase order. The stream slot is where
    /// [`Exfat::rewrite_stream_entry`] and the file content paths in
    /// [`Exfat::write_at`] meet: one helper, one convention.
    fn rewrite_stream_slot(
        &mut self,
        parent: &mut Level,
        set_slots: &[usize],
        first_cluster: u32,
        data_length: u64,
        valid_data_length: u64,
        contiguous: bool,
    ) -> Result<()> {
        let cluster_bytes = usize::try_from(self.geometry.cluster_bytes())
            .map_err(|_| CoreError::invalid("a cluster longer than this machine's usize"))?;
        let mut images = Vec::with_capacity(set_slots.len());
        for slot in set_slots {
            images.push(slot_image(&parent.content, cluster_bytes, *slot)?);
        }
        // Patch the stream entry: for a directory the whole allocation
        // is valid data (the spec's rule), so its callers hand equal
        // lengths; a file's valid length trails its allocation.
        let Some(stream_image) = images.get_mut(1) else {
            return Err(CoreError::invalid(
                "a parent set lost its stream slot".to_string(),
            ));
        };
        put_u64(stream_image, 8, valid_data_length)?; // ValidDataLength
        put_u32(stream_image, 20, first_cluster)?; // FirstCluster
        put_u64(stream_image, 24, data_length)?; // DataLength
        if contiguous {
            // The allocation this rewrite publishes is one
            // uninterrupted run, so the stream must say so: a file
            // grown from nothing starts with flags `0x01` (the
            // measured empty-file shape) and would otherwise be read
            // back as a fragmented chain the format never wrote.
            let flags = stream_image.get(1).copied().unwrap_or(0) | dirent::STREAM_NO_FAT_CHAIN;
            put_bytes(stream_image, 1, &[flags])?;
        }
        // The set checksum binds the whole set: recompute it over the
        // patched images and store it in the file entry (bytes 2..=3
        // of the lead, the bytes [`dirent::set_checksum`] itself
        // skips).
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
        let (file_at, stream_at) = (
            parent.content.slot_address(&self.geometry, file_slot)?,
            parent.content.slot_address(&self.geometry, stream_slot)?,
        );
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

/// The root slot whose lead byte carries a *live* 0x83 label, or
/// `None` when the root holds none. The scan reads raw lead bytes slot
/// by slot up to the first end-of-directory marker —
/// [`dirent::parse_dir_listing`] skips the system entries it walks
/// over, so a label can only be found outside that listing's
/// `entries`. A deleted label (lead 0x03, the shape a clear leaves)
/// never matches: deleted slots are never reused, exactly like every
/// other deleted set in this crate.
fn live_label_slot(content: &DirContent, listing: &dirent::DirListing) -> Option<usize> {
    (0..listing.terminator_slot).find(|slot| {
        content.bytes.get(slot * format::ENTRY_BYTES).copied() == Some(format::ENTRY_VOLUME_LABEL)
    })
}

/// The slot a fresh label is written into: the current end-of-directory
/// marker's slot, with the check that a slot exists behind it AND is
/// zeroed — the marker itself moves one slot back, and a slot holding
/// anything else would swallow the marker. The slots behind the marker
/// are the zeros this crate's format and growth always leave there, so
/// either refusal fires only on a foreign image, and both name the
/// numbers before anything is written.
fn fresh_label_slot(content: &DirContent, listing: &dirent::DirListing) -> Result<usize> {
    let terminator = listing.terminator_slot;
    let behind = terminator
        .checked_add(1)
        .ok_or_else(|| CoreError::invalid("a label slot index overflows".to_string()))?;
    if behind >= listing.total_slots {
        return Err(CoreError::invalid(format!(
            "the root directory ends at slot {terminator} of {} slots, leaving no slot \
             behind the marker for a fresh label",
            listing.total_slots
        )));
    }
    let window = content
        .bytes
        .get(behind * format::ENTRY_BYTES..(behind + 1) * format::ENTRY_BYTES)
        .ok_or_else(|| CoreError::invalid(format!("the root's slot {behind} lost its window")))?;
    if window.iter().any(|byte| *byte != 0) {
        return Err(CoreError::invalid(format!(
            "the root directory ends at slot {terminator} of {} slots, but the slot behind \
             the marker is not zeroed, so a fresh label would erase the end-of-directory \
             marker",
            listing.total_slots
        )));
    }
    Ok(terminator)
}

/// The deleted label image: lead 0x83 with its InUse bit clear over
/// entirely zeroed bytes — the shape a cleared label ends at, the
/// dormant state a replaced label passes through and the lead state an
/// appended one starts from. Every walker (this crate's
/// [`dirent::parse_dir_listing`], the kernel driver, fsck) skips such a
/// slot one at a time instead of parsing it.
fn deleted_label_image() -> Result<[u8; format::ENTRY_BYTES]> {
    let mut image = [0_u8; format::ENTRY_BYTES];
    put_bytes(
        &mut image,
        0,
        &[format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE],
    )?;
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

    /// The stream entry of the file at `path`, read out of its
    /// parent's live directory content: `(first cluster, data length,
    /// valid data length)` — the three on-disk facts `write_at` owns
    /// and the tests pin.
    #[track_caller]
    fn stream_entry(volume: &Exfat<VecVolume>, path: &str) -> (u32, u64, u64) {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let leaf = parts.last().copied().expect("the path has a leaf");
        let parents: Vec<String> = parts
            .iter()
            .take(parts.len().saturating_sub(1))
            .map(|part| (*part).to_owned())
            .collect();
        let levels = volume.walk(&parents).expect("the parent directory walks");
        let parent = levels.last().expect("the parent is in the walk");
        let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
        let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
            .expect("a cluster fits this machine's usize");
        for (entry, start) in listing.entries.iter().zip(listing.set_starts.iter()) {
            if dirent::upcase_name(&entry.name) != dirent::upcase_name(leaf) {
                continue;
            }
            let image = slot_image(&parent.content, cluster_bytes, start + 1)
                .expect("the stream slot reads");
            return (
                get_u32(&image, 20).unwrap_or(0),
                get_u64(&image, 24).unwrap_or(0),
                get_u64(&image, 8).unwrap_or(0),
            );
        }
        panic!("the file {path} is not in its parent's listing");
    }

    /// Overwrite the `ValidDataLength` of the file at `path` directly
    /// on the image (set checksum recomputed) — the corruption-shaped
    /// entry the refusal tests drive against, which the volume API
    /// would never write itself.
    #[track_caller]
    fn patch_valid_length(volume: &mut Exfat<VecVolume>, path: &str, valid: u64) {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let leaf = parts.last().copied().expect("the path has a leaf");
        let parents: Vec<String> = parts
            .iter()
            .take(parts.len().saturating_sub(1))
            .map(|part| (*part).to_owned())
            .collect();
        let levels = volume.walk(&parents).expect("the parent directory walks");
        let parent = levels.last().expect("the parent is in the walk");
        let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
        let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
            .expect("a cluster fits this machine's usize");
        let mut start = None;
        for (entry, found) in listing.entries.iter().zip(listing.set_starts.iter()) {
            if dirent::upcase_name(&entry.name) == dirent::upcase_name(leaf) {
                start = Some(*found);
            }
        }
        let start = start.expect("the file is in the listing");
        let set_end = listing
            .set_starts
            .iter()
            .copied()
            .find(|found| *found > start)
            .unwrap_or(listing.terminator_slot);
        let mut images: Vec<[u8; 32]> = (start..set_end)
            .map(|slot| slot_image(&parent.content, cluster_bytes, slot).expect("the slot reads"))
            .collect();
        put_u64(
            images.get_mut(1).expect("the set has a stream slot"),
            8,
            valid,
        )
        .expect("the valid field fits");
        let checksum = dirent::set_checksum(&images);
        let mut lead = images.first().copied().expect("the set has a lead");
        put_u16(&mut lead, 2, checksum).expect("the checksum field fits");
        let stream_image = images.get(1).copied().expect("the set has a stream slot");
        let file_at = parent
            .content
            .slot_address(volume.geometry(), start)
            .expect("the file slot has an address");
        let stream_at = parent
            .content
            .slot_address(volume.geometry(), start + 1)
            .expect("the stream slot has an address");
        volume
            .volume
            .write_all_at(file_at, &lead)
            .expect("the patched file slot writes");
        volume
            .volume
            .write_all_at(stream_at, &stream_image)
            .expect("the patched stream slot writes");
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
    fn a_relocation_copy_and_a_sparse_gap_survive_the_chunk_loop() {
        // Both spans here are larger than `COPY_CHUNK_BYTES`, so the copy
        // and the zero fill each iterate more than once. The single-chunk
        // sizes the other tests use cannot tell the loop body from a
        // whole-span `vec!`.
        // A larger heap than the default fixture: the sparse gap, the
        // payload and the relocation copy all have to fit at once.
        let store = VecVolume::new(32 * MIB, 512).expect("a thirty-two mebibyte store");
        let options = format::FormatOptions::new(SERIAL);
        let mut volume = Exfat::format(store, &options).expect("the formatter accepts this store");
        let cluster = volume.geometry().cluster_bytes() as usize;

        // A write that jumps three megabytes over untouched heap: the gap
        // is zero filled through the loop. This runs first, while the heap
        // still has one contiguous run that long.
        volume
            .create_file("/sparse.bin", 0, dirent::Stamps::epoch())
            .expect("the sparse file is created");
        volume
            .write_at("/sparse.bin", 0, b"head")
            .expect("the near write lands");
        let far = 3 * 1024 * 1024u64;
        volume
            .write_at("/sparse.bin", far, b"tail")
            .expect("the far write lands");
        let bytes = volume.read_file("/sparse.bin").expect("read back");
        assert_eq!(bytes.len() as u64, far + 4, "the size is the write's end");
        assert_eq!(&bytes[..4], b"head");
        assert_eq!(
            &bytes[4..far as usize],
            vec![0u8; far as usize - 4],
            "the jumped gap is zero"
        );
        assert_eq!(&bytes[far as usize..], b"tail");

        // A 2 MiB file followed by a gate: growing it cannot adopt the
        // next cluster, so the relocation copies the whole payload.
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        volume
            .create_file("/big.bin", payload.len() as u64, dirent::Stamps::epoch())
            .expect("the file is created");
        let half = payload.len() / 2;
        volume
            .write_at("/big.bin", 0, &payload[..half])
            .expect("the first half goes down");
        volume
            .write_at("/big.bin", half as u64, &payload[half..])
            .expect("the second half goes down");
        volume
            .create_file("/gate.bin", cluster as u64, dirent::Stamps::epoch())
            .expect("the gate is created");
        volume
            .write_at("/gate.bin", 0, &[0x00; 512])
            .expect("the gate is filled");
        let tail = [0xA5u8; 64];
        volume
            .write_at("/big.bin", payload.len() as u64, &tail)
            .expect("the relocating write lands");
        let mut expected = payload.clone();
        expected.extend_from_slice(&tail);
        assert_eq!(
            volume.read_file("/big.bin").expect("read back"),
            expected,
            "the relocated copy keeps every byte"
        );
    }

    #[test]
    fn an_empty_file_reads_as_no_bytes() {
        let mut volume = formatted();
        volume
            .create_file("/empty.bin", 0, dirent::Stamps::epoch())
            .expect("the empty file is created");
        assert_eq!(
            stream_entry(&volume, "/empty.bin").0,
            0,
            "an empty file owns no cluster"
        );
        let bytes = volume
            .read_file("/empty.bin")
            .expect("the empty file reads");
        assert!(
            bytes.is_empty(),
            "an empty file has no bytes, got {bytes:?}"
        );
    }

    #[test]
    fn a_write_failure_during_growth_rolls_the_ledger_back() {
        let store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        let mut volume = Exfat::format(Flaky::new(store), &format::FormatOptions::new(SERIAL))
            .expect("the formatter accepts this store");
        volume
            .create_file("/grow.bin", 0, dirent::Stamps::epoch())
            .expect("the empty file is created");
        let before_free = volume.free_bytes();
        let cluster_bytes = volume.geometry().cluster_bytes();

        volume.volume.fail_after.set(Some(0));
        let payload = vec![0x5A_u8; usize::try_from(2 * cluster_bytes).expect("two clusters")];
        let error = volume
            .write_at("/grow.bin", 0, &payload)
            .expect_err("the injected write failure refuses the growth");
        assert!(error.to_string().contains("injected"), "{error}");
        volume.volume.fail_after.set(None);

        assert_eq!(volume.free_bytes(), before_free, "the ledger is restored");
        let listed = volume.list_dir("/").expect("the root lists");
        assert_eq!(listed.len(), 1, "the file entry survives");
        assert_eq!(listed[0].size, 0, "the refused growth publishes no length");
        assert!(
            volume
                .read_file("/grow.bin")
                .expect("the empty file reads")
                .is_empty(),
            "the refused growth leaves no data behind"
        );

        volume
            .write_at("/grow.bin", 0, &payload)
            .expect("the retry succeeds");
        assert_eq!(
            volume.read_file("/grow.bin").expect("the retry reads"),
            payload
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

    #[test]
    fn a_written_file_round_trips_through_a_zero_gap() {
        let mut volume = formatted();
        let cluster_bytes = volume.geometry().cluster_bytes();
        volume
            .mkdir("/docs", dirent::Stamps::epoch())
            .expect("the directory is created");
        volume
            .create_file("/docs/pattern.bin", cluster_bytes, dirent::Stamps::epoch())
            .expect("the file claims exactly one cluster");
        // Garble the allocated run and its two neighbours before any
        // byte of content exists: a fresh store reads zeros everywhere,
        // so only bytes write_at itself puts down can explain a zero
        // readback below.
        let (first, data_length, valid) = stream_entry(&volume, "/docs/pattern.bin");
        assert_eq!(
            data_length, cluster_bytes,
            "the size hint is the DataLength"
        );
        assert_eq!(valid, 0, "a fresh file carries no valid data");
        let garble = vec![0xAA_u8; usize::try_from(3 * cluster_bytes).expect("fits")];
        let at = volume
            .geometry()
            .cluster_offset(first)
            .expect("the run's offset reads");
        volume
            .volume
            .write_all_at(at, &garble)
            .expect("the garble lands");

        // Write at 0, then one further past the allocation with a gap
        // between the two writes: the gap must read back zeros.
        let head: Vec<u8> = (0..cluster_bytes / 2)
            .map(|step| (step % 251) as u8)
            .collect();
        volume
            .write_at("/docs/pattern.bin", 0, &head)
            .expect("the head lands inside the allocation");
        let tail_offset = 3 * cluster_bytes + 123;
        let tail: Vec<u8> = (0..50u64).map(|step| ((step % 97) + 7) as u8).collect();
        volume
            .write_at("/docs/pattern.bin", tail_offset, &tail)
            .expect("the tail grows the allocation");

        let read = volume
            .read_file("/docs/pattern.bin")
            .expect("the file reads back");
        assert_eq!(
            read.len() as u64,
            tail_offset + tail.len() as u64,
            "exactly the valid bytes come back"
        );
        assert_eq!(&read[..head.len()], &head[..], "the head survives");
        let tail_at = usize::try_from(tail_offset).expect("fits");
        assert!(
            read[head.len()..tail_at].iter().all(|&byte| byte == 0),
            "the gap the write jumped over reads back as zeros"
        );
        assert_eq!(&read[tail_at..], &tail[..], "the tail lands at its offset");

        // The listing reports the new size, and the stream entry kept
        // its first cluster: the growth adopted free neighbours.
        let (first_after, data_after, valid_after) = stream_entry(&volume, "/docs/pattern.bin");
        assert_eq!(
            first_after, first,
            "the growth adopted the neighbours in place"
        );
        assert_eq!(
            data_after,
            tail_offset + tail.len() as u64,
            "DataLength ends at the write, not at the allocation"
        );
        assert_eq!(valid_after, tail_offset + tail.len() as u64);
        let docs = volume.list_dir("/docs").expect("the directory lists");
        assert_eq!(
            docs.first().expect("the file lists").size,
            tail_offset + tail.len() as u64,
            "the listing reports the bytes written"
        );
    }

    #[test]
    fn a_write_past_the_allocation_grows_in_place_with_free_neighbours() {
        let mut volume = formatted();
        let cluster_bytes = volume.geometry().cluster_bytes();
        // Filler allocations come first, so the target sits mid-heap
        // with the clusters behind it free deliberately, not by
        // low-address luck.
        for index in 0..10 {
            volume
                .create_file(
                    &format!("/filler{index:02}.bin"),
                    3 * cluster_bytes,
                    dirent::Stamps::epoch(),
                )
                .expect("a filler claims three clusters");
        }
        volume
            .create_file("/target.bin", cluster_bytes, dirent::Stamps::epoch())
            .expect("the target claims exactly one cluster");
        let (first, data_length, valid) = stream_entry(&volume, "/target.bin");
        assert_eq!(data_length, cluster_bytes);
        assert_eq!(valid, 0);
        assert_ne!(first, 0, "the fixture needs a real run to grow");
        assert!(
            volume
                .bitmap
                .is_free(first.checked_add(1).expect("fits"))
                .expect("the neighbour is inside the heap"),
            "the fixture must leave the next cluster free for adoption"
        );

        let free_before = volume.free_bytes();
        // Two clusters of content one allocation-past the end: the
        // growth adopts both neighbours in place.
        let added = vec![0x5E_u8; usize::try_from(2 * cluster_bytes).expect("fits")];
        volume
            .write_at("/target.bin", cluster_bytes, &added)
            .expect("the writer adopted the free neighbours");

        let (first_after, data_after, valid_after) = stream_entry(&volume, "/target.bin");
        assert_eq!(
            first_after, first,
            "in-place growth keeps the first cluster"
        );
        assert_eq!(data_after, 3 * cluster_bytes);
        assert_eq!(valid_after, 3 * cluster_bytes);
        assert_eq!(
            free_before - volume.free_bytes(),
            2 * cluster_bytes,
            "the free count dropped by exactly the adopted clusters"
        );
        let read = volume
            .read_file("/target.bin")
            .expect("the file reads back");
        assert_eq!(read.len() as u64, 3 * cluster_bytes);
        assert!(
            read[..cluster_bytes as usize].iter().all(|&byte| byte == 0),
            "the adopted-gap bytes read back as zeros"
        );
        assert_eq!(&read[cluster_bytes as usize..], &added[..]);
        assert_eq!(
            volume.list_dir("/").expect("the root lists").len(),
            11,
            "the fillers and the target all survive the growth"
        );
    }

    #[test]
    fn a_write_past_taken_neighbours_relocates_the_run_and_frees_the_old() {
        let mut volume = formatted();
        let cluster_bytes = volume.geometry().cluster_bytes();
        volume
            .create_file("/owner.bin", cluster_bytes, dirent::Stamps::epoch())
            .expect("the owner claims one cluster");
        // The gate sits exactly behind the owner: the owners free
        // neighbours are taken, so the growth must relocate.
        volume
            .create_file("/gate.bin", 2 * cluster_bytes, dirent::Stamps::epoch())
            .expect("the gate claims two clusters");
        let (first, _, _) = stream_entry(&volume, "/owner.bin");
        let (gate, _, _) = stream_entry(&volume, "/gate.bin");
        assert_eq!(
            gate,
            first.checked_add(1).expect("fits"),
            "the fixture pins the gate right behind the owner"
        );
        // The owner gets real content first, so the relocation has
        // existing ValidDataLength bytes to move.
        let head: Vec<u8> = (0..100u64)
            .map(|step| ((step * 7 + 3) % 251) as u8)
            .collect();
        volume
            .write_at("/owner.bin", 0, &head)
            .expect("the head lands inside the allocation");

        let free_before = volume.free_bytes();
        // Two clusters one allocation-past the end: with the
        // neighbours taken, the whole run relocates.
        let body = vec![0x3C_u8; usize::try_from(2 * cluster_bytes).expect("fits")];
        volume
            .write_at("/owner.bin", cluster_bytes, &body)
            .expect("the writer relocated the run");

        let (first_after, data_after, valid_after) = stream_entry(&volume, "/owner.bin");
        assert_ne!(
            first_after, first,
            "the stream entry moved to the fresh run"
        );
        assert_eq!(data_after, 3 * cluster_bytes);
        assert_eq!(valid_after, 3 * cluster_bytes);
        let read = volume
            .read_file("/owner.bin")
            .expect("the relocated data reads back");
        assert_eq!(read.len() as u64, 3 * cluster_bytes);
        assert_eq!(
            &read[..head.len()],
            &head[..],
            "the copied valid bytes survive the move"
        );
        assert!(
            read[head.len()..cluster_bytes as usize]
                .iter()
                .all(|&byte| byte == 0),
            "the zero region inside the fresh run reads back as zeros"
        );
        assert_eq!(
            &read[cluster_bytes as usize..],
            &body[..],
            "the written tail lands at its offset in the fresh run"
        );
        // The old cluster is free again, and the free count moved by
        // exactly the growth: three clusters claimed, one released.
        assert!(
            volume
                .bitmap
                .is_free(first)
                .expect("the old cluster is inside the heap"),
            "the released old run returns to the pool"
        );
        assert_eq!(
            free_before - volume.free_bytes(),
            (3 - 1) * cluster_bytes,
            "the free count reflects three claimed and one released clusters"
        );
        // And the gate kept both its clusters untouched.
        let (gate_after, gate_data, gate_valid) = stream_entry(&volume, "/gate.bin");
        assert_eq!(gate_after, gate, "a relocation does not move other files");
        assert_eq!(gate_data, 2 * cluster_bytes);
        assert_eq!(gate_valid, 0);
    }

    #[test]
    fn write_and_read_refusals_name_their_paths_and_numbers() {
        let mut volume = formatted();
        volume
            .mkdir("/adir", dirent::Stamps::epoch())
            .expect("the directory is created");

        // A directory refuses for both directions, with the path named.
        let error = volume
            .write_at("/adir", 0, b"x")
            .expect_err("a directory cannot be written");
        let text = error.to_string();
        assert!(
            text.contains("/adir") && text.contains("directory"),
            "{text}"
        );
        let error = volume
            .read_file("/adir")
            .expect_err("a directory cannot be read");
        let text = error.to_string();
        assert!(
            text.contains("/adir") && text.contains("directory"),
            "{text}"
        );

        // A missing path refuses, path named, for both directions.
        let error = volume
            .write_at("/ghost.txt", 0, b"x")
            .expect_err("there is nothing to write into");
        assert!(error.to_string().contains("ghost.txt"), "{error}");
        let error = volume
            .read_file("/ghost.txt")
            .expect_err("there is nothing to read");
        assert!(error.to_string().contains("ghost.txt"), "{error}");

        // A write past the volume end refuses, naming the write's end
        // and the heap's byte capacity, and leaves nothing behind.
        // The file must exist first: a missing path refuses before
        // the growth math even runs.
        let cluster_bytes = volume.geometry().cluster_bytes();
        let capacity = u64::from(volume.geometry().cluster_count) * cluster_bytes;
        volume
            .create_file("/end.bin", 0, dirent::Stamps::epoch())
            .expect("the empty end-marker file is created");
        let free_before = volume.free_bytes();
        let error = volume
            .write_at("/end.bin", capacity, b"!")
            .expect_err("the write would end past the volume");
        let text = error.to_string();
        assert!(
            text.contains(&(capacity + 1).to_string()) && text.contains(&capacity.to_string()),
            "the refusal names the write's end and the capacity: {text}"
        );
        assert_eq!(
            volume.free_bytes(),
            free_before,
            "the refused write moved no allocation"
        );
        assert_eq!(
            names(&volume.list_dir("/").expect("the root lists")),
            ["adir", "end.bin"],
            "the refused write left exactly what was there"
        );

        // A stream entry whose valid length claims past its data
        // length (hand-made damage) refuses, both numbers named.
        volume
            .create_file("/liar.bin", cluster_bytes, dirent::Stamps::epoch())
            .expect("the file is created");
        patch_valid_length(&mut volume, "/liar.bin", cluster_bytes + 1);
        let error = volume
            .read_file("/liar.bin")
            .expect_err("valid cannot claim past data");
        let text = error.to_string();
        assert!(
            text.contains(&(cluster_bytes + 1).to_string())
                && text.contains(&cluster_bytes.to_string()),
            "the refusal names both lengths: {text}"
        );
    }

    #[test]
    fn a_zero_length_write_is_a_no_op_down_to_the_stored_bytes() {
        let mut volume = formatted();
        volume
            .create_file(
                "/still.bin",
                volume.geometry().cluster_bytes(),
                dirent::Stamps::epoch(),
            )
            .expect("the sized file is created");
        volume
            .create_file("/empty.bin", 0, dirent::Stamps::epoch())
            .expect("the empty file is created");
        let listing = volume.list_dir("/").expect("the root lists");
        let before = volume.volume.bytes().to_vec();

        // A zero-length write at any offset (even far past the
        // allocation) neither allocates, writes, nor rewrites an entry
        // — and a zero-length write to a missing path still resolves
        // first, so it refuses rather than silently succeeding.
        volume
            .write_at("/still.bin", 1 << 30, b"")
            .expect("the no-op write succeeds");
        volume
            .write_at("/empty.bin", 0, b"")
            .expect("the no-op write into the empty file succeeds");
        let error = volume
            .write_at("/ghost.txt", 0, b"")
            .expect_err("resolution comes before the no-op");
        assert!(error.to_string().contains("ghost.txt"), "{error}");

        assert_eq!(volume.volume.bytes(), &before[..], "not one byte moved");
        assert_eq!(
            volume.list_dir("/").expect("the root lists"),
            listing,
            "the listing is untouched"
        );
    }

    /// A stamp set distinct from the epoch fixture: three different
    /// moments, each with its own tenth-of-second and UTC-offset byte
    /// — so a test can tell one swapped field from a dropped one, and
    /// tell either from "nothing changed".
    fn later_stamps() -> dirent::Stamps {
        dirent::Stamps {
            create: dirent::Stamp {
                tenths: 7,
                utc_offset: 0x80,
                ..dirent::Stamp::from_ymdhms(2026, 11, 1, 9, 0, 0).expect("valid ymdhms")
            },
            modify: dirent::Stamp {
                tenths: 148,
                utc_offset: 0x40,
                ..dirent::Stamp::from_ymdhms(2026, 11, 1, 10, 30, 2).expect("valid ymdhms")
            },
            access: dirent::Stamp {
                // A tenth byte deliberately left unrepresentable on
                // disk: the format defines no access 10 ms field, so
                // storing 199 there must change nothing a reader sees.
                tenths: 199,
                utc_offset: 0x15,
                ..dirent::Stamp::from_ymdhms(2026, 11, 1, 23, 59, 58).expect("valid ymdhms")
            },
        }
    }

    /// The stamps from `times` as the on-disk reader
    /// ([`dirent::parse_dir_listing`] over the set's slots) reports
    /// them back: everything round-trips except the access stamp's
    /// tenth byte, which the format gives no field to — readers
    /// always see zero there.
    fn as_stored(times: dirent::Stamps) -> dirent::Stamps {
        dirent::Stamps {
            create: times.create,
            modify: times.modify,
            access: dirent::Stamp {
                tenths: 0,
                ..times.access
            },
        }
    }

    /// The entry set of the leaf at `path`, read back from its
    /// parent's live directory content: the parsed entry (stamps
    /// included) plus the raw 32 bytes of its lead slot, which the
    /// stamp tests pin field-by-field.
    #[track_caller]
    fn set_entry(volume: &Exfat<VecVolume>, path: &str) -> (dirent::DirEntry, [u8; 32]) {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let leaf = parts.last().copied().expect("the path has a leaf");
        let parents: Vec<String> = parts
            .iter()
            .take(parts.len().saturating_sub(1))
            .map(|part| (*part).to_owned())
            .collect();
        let levels = volume.walk(&parents).expect("the parent directory walks");
        let parent = levels.last().expect("the parent is in the walk");
        let listing = dirent::parse_dir_listing(&parent.content.bytes).expect("the listing parses");
        let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
            .expect("a cluster fits this machine's usize");
        for (entry, start) in listing.entries.iter().zip(listing.set_starts.iter()) {
            if dirent::upcase_name(&entry.name) != dirent::upcase_name(leaf) {
                continue;
            }
            let lead =
                slot_image(&parent.content, cluster_bytes, *start).expect("the lead slot reads");
            return (entry.clone(), lead);
        }
        panic!("the entry {path} is not in its parent's listing");
    }

    #[test]
    fn set_times_stamps_a_file_set() {
        let mut volume = formatted();
        volume
            .create_file("/file.bin", 0, dirent::Stamps::epoch())
            .expect("the file is created");
        let times = later_stamps();

        volume
            .set_times("/file.bin", times)
            .expect("the stamp rewrite lands");

        let (entry, lead) = set_entry(&volume, "/file.bin");
        assert_eq!(
            entry.stamps.create, times.create,
            "the create stamp round-trips"
        );
        assert_eq!(
            entry.stamps.modify, times.modify,
            "the modify stamp round-trips"
        );
        assert_eq!(
            entry.stamps.access,
            as_stored(times).access,
            "the access stamp keeps its date-time and offset; its tenth byte has no field on disk"
        );
        // Pin the raw tenth bytes too: exactly create at 20 and modify
        // at 21 — the offsets the reader derives the stamps from.
        assert_eq!(
            lead[20], times.create.tenths,
            "the create tenth lives at byte 20"
        );
        assert_eq!(
            lead[21], times.modify.tenths,
            "the modify tenth lives at byte 21"
        );
        assert_eq!(
            [lead[22], lead[23], lead[24]],
            [
                times.create.utc_offset,
                times.modify.utc_offset,
                times.access.utc_offset
            ],
            "all three utc offsets live at bytes 22, 23 and 24"
        );
    }

    #[test]
    fn set_times_stamps_a_directory_set() {
        let mut volume = formatted();
        volume
            .mkdir("/docs", dirent::Stamps::epoch())
            .expect("the directory is created");
        let times = later_stamps();

        volume
            .set_times("/docs", times)
            .expect("the stamp rewrite lands");

        let (entry, lead) = set_entry(&volume, "/docs");
        assert!(entry.is_dir, "the stamped set is still a directory");
        assert_eq!(
            entry.stamps.create, times.create,
            "the create stamp round-trips"
        );
        assert_eq!(
            entry.stamps.modify, times.modify,
            "the modify stamp round-trips"
        );
        assert_eq!(
            entry.stamps.access,
            as_stored(times).access,
            "the access stamp keeps its date-time and offset"
        );
        assert_eq!(lead[20], times.create.tenths, "the create tenth survives");
        assert_eq!(lead[21], times.modify.tenths, "the modify tenth survives");
        assert_eq!(
            lead[24], times.access.utc_offset,
            "the access offset survives"
        );
    }

    #[test]
    fn set_times_survives_a_reopen_round_trip() {
        let mut volume = formatted();
        volume
            .mkdir("/docs", dirent::Stamps::epoch())
            .expect("the directory is created");
        volume
            .create_file("/docs/notes.txt", 0, dirent::Stamps::epoch())
            .expect("the file is created");
        let times = later_stamps();
        volume
            .set_times("/docs", times)
            .expect("the directory's stamps land");
        volume
            .set_times("/docs/notes.txt", times)
            .expect("the file's stamps land");

        // The listings still report name, size and shape exactly as
        // before: stamps are not part of what a listing shows.
        let root = volume.list_dir("/").expect("the root lists");
        assert_eq!(names(&root), ["docs"]);
        assert!(root[0].is_dir, "the root's entry is still a directory");
        assert_eq!(
            root[0].size,
            volume.geometry().cluster_bytes(),
            "the directory reports its whole allocation"
        );
        assert_eq!(
            names(&volume.list_dir("/docs").expect("the directory lists")),
            ["notes.txt"]
        );

        volume.flush().expect("the volume flushes");
        let bytes = volume.volume.bytes().to_vec();
        let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        store
            .write_all_at(0, &bytes)
            .expect("the image copies back");
        let reopened = Exfat::open(store).expect("the stamped image opens");
        for path in ["/docs", "/docs/notes.txt"] {
            let (entry, _) = set_entry(&reopened, path);
            assert_eq!(
                entry.stamps.create, times.create,
                "the create stamp survives at {path}"
            );
            assert_eq!(
                entry.stamps.modify, times.modify,
                "the modify stamp survives at {path}"
            );
            assert_eq!(
                entry.stamps.access,
                as_stored(times).access,
                "the access stamp survives at {path}"
            );
        }
    }

    #[test]
    fn set_times_moves_only_the_stamp_fields() {
        let mut volume = formatted();
        volume
            .create_file(
                "/target.bin",
                volume.geometry().cluster_bytes(),
                dirent::Stamps::epoch(),
            )
            .expect("the file claims exactly one cluster");
        let stream_before = stream_entry(&volume, "/target.bin");
        let free_before = volume.free_clusters;

        let times = later_stamps();
        volume
            .set_times("/target.bin", times)
            .expect("the stamp rewrite lands");

        assert_eq!(
            stream_entry(&volume, "/target.bin"),
            stream_before,
            "the stream entry's cluster and lengths are untouched"
        );
        assert_eq!(
            volume.free_clusters, free_before,
            "no cluster moved for a stamp rewrite"
        );
        assert_eq!(
            names(&volume.list_dir("/").expect("the root lists")),
            ["target.bin"],
            "the entry still lists with its name"
        );
    }

    #[test]
    fn set_times_refuses_the_root_and_a_missing_leaf() {
        let mut volume = formatted();
        volume
            .create_file("/kept.bin", 0, dirent::Stamps::epoch())
            .expect("the file is created");
        let times = later_stamps();

        let error = volume
            .set_times("/", times)
            .expect_err("the root cannot be stamped");
        let text = error.to_string();
        assert!(text.contains("root"), "the refusal names the root: {text}");
        assert!(text.contains("set_times"), "{text}");
        assert!(text.is_ascii(), "refusals stay ascii: {text}");

        let error = volume
            .set_times("/nope", times)
            .expect_err("a missing leaf cannot be stamped");
        let text = error.to_string();
        assert!(text.contains("/nope"), "the refusal names the path: {text}");
        assert!(text.is_ascii(), "refusals stay ascii: {text}");

        assert_eq!(
            names(&volume.list_dir("/").expect("the root lists")),
            ["kept.bin"],
            "the refused calls left exactly what was there"
        );
    }

    #[test]
    fn a_write_at_never_moves_the_set_times() {
        let mut volume = formatted();
        volume
            .create_file("/doc.bin", 0, dirent::Stamps::epoch())
            .expect("the file is created");
        let times = later_stamps();
        volume
            .set_times("/doc.bin", times)
            .expect("the stamp rewrite lands");

        volume
            .write_at("/doc.bin", 0, b"payload")
            .expect("the write lands");
        assert_eq!(
            volume.read_file("/doc.bin").expect("the file reads"),
            b"payload",
            "the write reached the file"
        );

        let (entry, _) = set_entry(&volume, "/doc.bin");
        assert_eq!(
            entry.stamps.create, times.create,
            "the create stamp survived the write"
        );
        assert_eq!(
            entry.stamps.modify, times.modify,
            "the modify stamp survived the write"
        );
        assert_eq!(
            entry.stamps.access,
            as_stored(times).access,
            "the access stamp survived the write"
        );
        let (first, data, valid) = stream_entry(&volume, "/doc.bin");
        assert_ne!(first, 0, "the write allocated a run");
        assert_eq!(
            data,
            b"payload".len() as u64,
            "DataLength ends at the write"
        );
        assert_eq!(valid, b"payload".len() as u64, "ValidDataLength covers it");
    }

    // ------------------------------------------------------------------
    // Labels: set_label
    // ------------------------------------------------------------------

    /// A formatted volume whose root carries a live "RUFUS" label: the
    /// variant `set_label` replaces, clears and refuses around (the
    /// struct-literal options mirror the format.rs label test, pinning
    /// this fixture's own serial).
    fn labelled() -> Exfat<VecVolume> {
        let volume = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        let options = format::FormatOptions {
            label: Some("RUFUS".to_string()),
            volume_id: SERIAL,
            cluster_bytes: None,
        };
        Exfat::format(volume, &options).expect("the formatter accepts this store")
    }

    /// The raw 32 bytes of the root's `slot`-th slot.
    #[track_caller]
    fn root_slot(volume: &Exfat<VecVolume>, slot: usize) -> [u8; 32] {
        let root = volume.root_level().expect("the root reads");
        let cluster_bytes = usize::try_from(volume.geometry().cluster_bytes())
            .expect("a cluster fits this machine's usize");
        slot_image(&root.content, cluster_bytes, slot).expect("the slot reads")
    }

    /// The root's live label entry, found the raw way the volume code
    /// scans for it (a lead byte of 0x83 before the terminator): the
    /// slot it sits in and its 32 bytes. The slot index pins *where* a
    /// label landed — slot 0 on a labelled format, behind the up-case
    /// entry after an append, at the marker after a clear.
    #[track_caller]
    fn live_label(volume: &Exfat<VecVolume>) -> (usize, [u8; 32]) {
        let root = volume.root_level().expect("the root reads");
        let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the listing parses");
        for slot in 0..listing.terminator_slot {
            let image = root_slot(volume, slot);
            if image[0] == format::ENTRY_VOLUME_LABEL {
                return (slot, image);
            }
        }
        panic!("the root has no live label entry");
    }

    /// The label text a 0x83 slot's bytes carry: count byte, then
    /// UTF-16LE units.
    fn label_text(image: &[u8]) -> String {
        let units: Vec<u16> = (0..usize::from(image[1]))
            .map(|step| u16::from_le_bytes([image[2 + step * 2], image[3 + step * 2]]))
            .collect();
        String::from_utf16(&units).expect("the label decodes")
    }

    /// A byte-copy reopen: the fixture's image, flushed, copied into a
    /// fresh store and parsed back with `Exfat::open` — the round trip
    /// the older reopen tests carry out inline.
    #[track_caller]
    fn reopened(volume: &mut Exfat<VecVolume>) -> Exfat<VecVolume> {
        volume.flush().expect("the volume flushes");
        let bytes = volume.volume.bytes().to_vec();
        let mut store = VecVolume::new(8 * MIB, 512).expect("an eight mebibyte store");
        store
            .write_all_at(0, &bytes)
            .expect("the image copies back");
        Exfat::open(store).expect("the image opens")
    }

    #[test]
    fn set_label_replaces_a_formatted_label_in_place() {
        let mut volume = labelled();
        volume
            .set_label(Some("HELLO"))
            .expect("the replacement lands");

        let (slot, image) = live_label(&volume);
        assert_eq!(slot, 0, "the live label is rewritten in its own slot");
        assert_eq!(
            image[0],
            format::ENTRY_VOLUME_LABEL,
            "the lead is a live label"
        );
        assert_eq!(
            usize::from(image[1]),
            "HELLO".encode_utf16().count(),
            "the count byte carries the unit count"
        );
        assert_eq!(label_text(&image), "HELLO", "the units decode back");
        assert!(
            image.iter().skip(12).all(|byte| *byte == 0),
            "past the units the slot is zero"
        );

        // The rewritten slot survives a reopen round trip, and the
        // listing walk still ends in an empty listing (labels never list).
        let volume = reopened(&mut volume);
        assert!(volume.list_dir("/").expect("the root lists").is_empty());
        assert_eq!(
            live_label(&volume),
            (slot, image),
            "the replaced label round-trips"
        );
    }

    #[test]
    fn set_label_none_deletes_the_live_label_entry() {
        let mut volume = labelled();
        volume.set_label(None).expect("the clear lands");

        // The old label slot is the deleted shape: lead 0x03, then zeros.
        let image = root_slot(&volume, 0);
        assert_eq!(
            image[0],
            format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE,
            "the slot's lead carries the deleted label type"
        );
        assert!(
            image[1..].iter().all(|byte| *byte == 0),
            "count and units are zeroed"
        );

        // The walk still parses, ending at the same marker; the system
        // entries behind the deleted slot stay in place (and never list).
        let root = volume.root_level().expect("the root reads");
        let listing = dirent::parse_dir_listing(&root.content.bytes).expect("the walk parses");
        assert_eq!(
            listing.terminator_slot, 3,
            "the marker kept its slot behind the system entries"
        );
        assert_eq!(
            root_slot(&volume, 1)[0],
            format::ENTRY_BITMAP,
            "the bitmap entry stayed"
        );
        assert_eq!(
            root_slot(&volume, 2)[0],
            format::ENTRY_UP_CASE,
            "the up-case entry stayed"
        );
        assert_eq!(
            listing.total_slots,
            usize::try_from(volume.geometry().cluster_bytes()).expect("fits") / format::ENTRY_BYTES,
            "the capacity read is the cluster's slot count"
        );
        assert!(
            volume.list_dir("/").expect("the root lists").is_empty(),
            "the system entries (and the deleted label) never list"
        );

        // And the image still opens: the bitmap is found through the walk.
        let volume = reopened(&mut volume);
        assert!(volume.list_dir("/").expect("the root lists").is_empty());
    }

    #[test]
    fn set_label_appends_behind_the_system_entries_when_there_was_none() {
        let mut volume = formatted();
        volume
            .set_label(Some("APPENDED"))
            .expect("the append lands");

        let (slot, image) = live_label(&volume);
        assert_eq!(
            slot, 2,
            "the label took the marker's slot behind the bitmap (0) and up-case (1) entries"
        );
        assert_eq!(image[0], format::ENTRY_VOLUME_LABEL);
        assert_eq!(label_text(&image), "APPENDED");

        // The marker moved one slot back: the slot behind the label is
        // the fresh end-of-directory zeros.
        let marker = root_slot(&volume, slot + 1);
        assert!(
            marker.iter().all(|byte| *byte == 0),
            "the marker moved behind the label"
        );

        // A single-slot entry behind the system entries stays walkable
        // across a reopen, and the bitmap is still found through it.
        let volume = reopened(&mut volume);
        assert!(volume.list_dir("/").expect("the root lists").is_empty());
        assert_eq!(
            live_label(&volume),
            (slot, image),
            "the appended label round-trips"
        );
    }

    #[test]
    fn set_label_carries_the_maximum_of_eleven_characters() {
        let mut volume = formatted();
        let name = "ELEVENCHARS"; // eleven ASCII characters
        volume
            .set_label(Some(name))
            .expect("the maximum length lands");

        let (slot, image) = live_label(&volume);
        assert!(slot >= 2, "the label sits behind the system entries");
        assert_eq!(image[0], format::ENTRY_VOLUME_LABEL);
        assert_eq!(
            usize::from(image[1]),
            name.encode_utf16().count(),
            "every unit counted"
        );
        assert_eq!(label_text(&image), name, "all eleven round-trip exactly");
    }

    #[test]
    fn set_label_refusals_move_not_a_byte() {
        let mut volume = labelled();
        let before = volume.volume.bytes().to_vec();

        // Twelve characters: over the limit, refusing with the exact
        // text the formatter's own label validation carries.
        let error = volume
            .set_label(Some("TWELVE_CHARS"))
            .expect_err("twelve characters refuse");
        let text = error.to_string();
        assert!(
            text.contains("an exFAT label holds 11 characters, this one needs 12"),
            "the refusal quotes the limit: {text}"
        );
        assert!(text.is_ascii(), "refusals stay ascii: {text}");

        // A forbidden character refuses with the character named.
        let error = volume
            .set_label(Some("BAD:NAME"))
            .expect_err("the colon refuses");
        let text = error.to_string();
        assert!(
            text.contains("an exFAT label cannot contain the character U+003A"),
            "the refusal names the character: {text}"
        );
        assert!(text.is_ascii(), "refusals stay ascii: {text}");

        assert_eq!(volume.volume.bytes(), &before[..], "neither refusal wrote");
        assert_eq!(
            label_text(&live_label(&volume).1),
            "RUFUS",
            "the live label is untouched"
        );
    }

    #[test]
    fn clearing_a_label_that_was_never_there_writes_nothing() {
        let mut volume = formatted();
        let before = volume.volume.bytes().to_vec();

        // `None` with no live label anywhere: Ok, and not one byte moves.
        volume.set_label(None).expect("the clear is a no-op");
        assert_eq!(volume.volume.bytes(), &before[..], "not one byte moved");
        // An empty string clears, matching format(): also a no-op here.
        volume
            .set_label(Some(""))
            .expect("an empty label clears like None");
        assert_eq!(
            volume.volume.bytes(),
            &before[..],
            "the empty label moved nothing either"
        );
    }

    #[test]
    fn a_cleared_label_is_set_again_behind_the_marker() {
        let mut volume = labelled();
        volume.set_label(None).expect("the clear lands");
        assert_eq!(
            root_slot(&volume, 0)[0],
            format::ENTRY_VOLUME_LABEL & !dirent::ENTRY_IN_USE,
            "the old slot is left deleted"
        );

        volume
            .set_label(Some("THIRD"))
            .expect("the second set lands");
        let (slot, image) = live_label(&volume);
        assert_eq!(
            slot, 3,
            "the fresh label appended at the marker, not into the deleted slot 0"
        );
        assert_eq!(label_text(&image), "THIRD");
        let marker = root_slot(&volume, slot + 1);
        assert!(
            marker.iter().all(|byte| *byte == 0),
            "the marker moved one slot back"
        );

        // Open still succeeds — the deleted slot never blocks the walk.
        let volume = reopened(&mut volume);
        assert_eq!(
            live_label(&volume),
            (slot, image),
            "the relabelled volume reopens"
        );
        assert!(volume.list_dir("/").expect("the root lists").is_empty());
    }
}
