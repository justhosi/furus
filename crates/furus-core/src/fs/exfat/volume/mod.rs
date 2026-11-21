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
use crate::fs::exfat::format as fmt;
use crate::fs::exfat::geometry::FIRST_HEAP_CLUSTER;
use crate::fs::exfat::geometry::Geometry;
use crate::fs::exfat::get_u32;
use crate::fs::exfat::get_u64;
use crate::fs::exfat::put_bytes;
use crate::fs::exfat::put_u16;
use crate::fs::exfat::put_u32;
use crate::fs::exfat::put_u64;
use io::read_whole;

mod fat;
mod format;
mod io;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

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
    while at + fmt::ENTRY_BYTES <= image.len() {
        let window = image
            .get(at..at + fmt::ENTRY_BYTES)
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
            _ => at += fmt::ENTRY_BYTES,
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
}
