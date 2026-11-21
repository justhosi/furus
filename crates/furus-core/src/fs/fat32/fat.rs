//! The FAT32 cluster table (S09 part B): FAT entry reads and writes
//! through the [`crate::fs::Volume`] byte store, the end-of-chain /
//! free / link classification of raw entry values, the pending-write
//! journal the live volume flushes into *both* FAT copies, and the
//! first-fit free-run scanner the contiguous allocator is built on.
//!
//! The value semantics follow the FAT32 spec exactly:
//!
//! * `0x00000000` is a free cluster;
//! * `0x0FFFFFF8`..`0x0FFFFFFF` are end-of-chain (EoC) family values;
//! * data clusters link by their own cluster number;
//! * everything else (0, the bad-cluster band `0x0FFFFFF6..7`, or a
//!   number beyond the data area) is scaffold or corruption and the
//!   chain walker refuses it rather than dereferencing it.
//!
//! Writes: the live volume records every entry change in a
//! [`FatDelta`] journal and [`flush_delta`] materializes it into *both*
//! FAT copies at flush time through bounded 64 KiB chunks — the same
//! bounded-chunk discipline [`bpb`](crate::fs::fat32::bpb) and
//! [`format`](crate::fs::fat32::format) use, never a whole-image
//! allocation. Every FAT read consults the journal first, so in-memory
//! state is always the current truth; until the flush the on-disk FATs
//! stay untouched (which is exactly why flush exists).
//!
//! Scans: [`scan_free_run`] reads the first FAT copy in 64 KiB windows
//! (a per-cluster 4-byte syscall-shaped read across a 33-million-cluster
//! volume would dominate every allocation), first-fit from the FSInfo
//! next-free hint, wrapping to the volume start exactly once, and
//! refuses runs that wrap past the last cluster: contiguous means
//! consecutive cluster *numbers*, which a wrap cannot produce.

use std::collections::BTreeMap;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::geometry::Geometry;
use crate::fs::fat32::geometry::ROOT_CLUSTER;

/// First end-of-chain-family value: `0x0FFFFFF8` (media descriptor byte
/// carrying the `0xF8` register value inside the EoC band).
pub(crate) const EOC_MIN: u32 = 0x0FFF_FFF8;
/// Last end-of-chain-family value: `0x0FFFFFFF`, the one our writer and
/// formatter pin.
pub(crate) const EOC: u32 = 0x0FFF_FFFF;
/// The free-cluster value.
pub(crate) const FREE: u32 = 0;

/// The bounded window the FAT readers stream through: 16 Ki entries = 64
/// KiB, one worst-case cluster.
const WINDOW_ENTRIES: usize = 16 * 1024;
const WINDOW_BYTES: usize = WINDOW_ENTRIES * 4;

/// One FAT entry as a chain walker reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FatEntry {
    /// `0`: a free cluster — never legal inside a chain.
    Free,
    /// The chain continues from this cluster number.
    Link(u32),
    /// End-of-chain band: the chain ends here.
    End,
    /// Everything unclassifiable: cluster 1, the bad-cluster band
    /// `0x0FFFFFF6..7`, or a link beyond the data area.
    Corrupt(u32),
}

/// Classify a raw FAT entry value against `cluster_count` (which is the
/// count of *data* clusters; numbers `2..=cluster_count + 1` are links).
/// The 28-bit field is masked first — the spec reading every FAT driver
/// uses (the top nibble is reserved and ignored), so `0xFFFFFFFF` and
/// `0x0FFFFFFF` both land in the end-of-chain band.
#[must_use]
pub(crate) fn classify(raw: u32, cluster_count: u32) -> FatEntry {
    let value = raw & 0x0FFF_FFFF;
    match value {
        FREE => FatEntry::Free,
        EOC_MIN..=EOC => FatEntry::End,
        // `cluster_count + 1` cannot overflow: the geometry caps the
        // count far below u32::MAX, and saturating keeps it total.
        value if value >= ROOT_CLUSTER && value <= cluster_count.saturating_add(1) => {
            FatEntry::Link(value)
        }
        _ => FatEntry::Corrupt(raw),
    }
}

/// Absolute byte offset of `cluster`'s FAT entry in FAT copy `copy`:
/// the copy's own base plus four bytes per cluster number. Errors (all
/// [`CoreError::invalid`]) instead of overflowing: an absurd copy number
/// or cluster number names itself in the refusal.
pub(crate) fn fat_copy_offset(geometry: &Geometry, copy: u32, cluster: u32) -> Result<u64> {
    let copy_base = geometry
        .fat_offset()
        .checked_add(
            u64::from(copy)
                .checked_mul(geometry.fat_length_bytes())
                .ok_or_else(|| CoreError::invalid("the fat copy offset overflows a u64"))?,
        )
        .ok_or_else(|| CoreError::invalid("a fat copy sits beyond the volume"))?;
    let entry = copy_base
        .checked_add(u64::from(cluster).checked_mul(4).ok_or_else(|| {
            CoreError::invalid(format!("fat entry {cluster}'s byte offset overflows a u64"))
        })?)
        .ok_or_else(|| {
            CoreError::invalid(format!("fat entry {cluster}'s byte offset overflows a u64"))
        })?;
    Ok(entry)
}

/// Read one FAT entry from the first FAT copy, favouring the journal
/// (`overlay`) when it holds the cluster — in-memory state is the
/// current truth, the disk only catches up at flush.
pub(crate) fn read_entry(
    volume: &dyn Volume,
    geometry: &Geometry,
    overlay: Option<&FatDelta>,
    cluster: u32,
) -> Result<u32> {
    if cluster < ROOT_CLUSTER || cluster > geometry.cluster_count.saturating_add(1) {
        return Err(CoreError::invalid(format!(
            "fat entry {cluster} is not a data cluster number (2..={})",
            geometry.cluster_count.saturating_add(1)
        )));
    }
    if let Some(value) = overlay.and_then(|journal| journal.get_value(cluster)) {
        return Ok(value);
    }
    let offset = fat_copy_offset(geometry, 0, cluster)?;
    let mut bytes = [0u8; 4];
    volume.read_exact_at(offset, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

/// The FAT journal: every entry written since the last flush, holds the
/// cluster → value pairs until flush materializes them into both FAT
/// copies. Empty between flushes is the everyday shape; the memory is
/// bounded by *changed* clusters, never by the volume's FAT size.
/// `Clone` backs the allocation rollback of the create paths: a
/// refused `create_file`/`mkdir`/`link_file` restores the whole
/// pre-call journal instead of hand-reverting entry values.
#[derive(Debug, Clone, Default)]
pub(crate) struct FatDelta {
    pending: BTreeMap<u32, u32>,
}

impl FatDelta {
    /// Record one entry write (the caller supplies the classified
    /// value; the journal stores the raw number).
    pub fn set(&mut self, cluster: u32, value: u32) {
        self.pending.insert(cluster, value);
    }

    /// The journal's current value for `cluster`, when any.
    #[must_use]
    pub fn get_value(&self, cluster: u32) -> Option<u32> {
        self.pending.get(&cluster).copied()
    }

    /// Whether any entry still waits for the disk (`false` after a
    /// successful flush or a no-op session — the flush-fast path).
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Merged half-open `[lo, hi)` runs of the pending cluster numbers:
    /// the flush unit — a contiguous allocation becomes exactly one
    /// run, which emits one chunk-driven write pair per copy.
    #[must_use]
    pub fn runs(&self) -> Vec<(u32, u32)> {
        let mut runs: Vec<(u32, u32)> = Vec::new();
        for (&cluster, _) in self.pending.range(..) {
            match runs.last_mut() {
                // Adjacent to the open run: extend its end.
                Some(last) if last.1 == cluster => last.1 = cluster.saturating_add(1),
                Some(_) | None => runs.push((cluster, cluster.saturating_add(1))),
            }
        }
        runs
    }

    /// Reset the journal after a flush (or a caller's full rollback).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// Materialize the journal into *both* FAT copies: every pending value
/// reaches every copy, through bounded 64 KiB chunks — the same
/// bounded-chunk discipline [`bpb`](crate::fs::fat32::bpb) writes its
/// FAT images with, and never a whole-FAT allocation. Journal runs are
/// merged first, so one contiguous allocation is one run.
///
/// On success the journal is cleared (the disk now carries the state);
/// on failure it stays dirty so a retry can resume.
pub(crate) fn flush_delta(
    volume: &mut dyn Volume,
    geometry: &Geometry,
    delta: &mut FatDelta,
) -> Result<()> {
    for run in delta.runs() {
        let total = usize::try_from(run.1.saturating_sub(run.0)).map_err(|_| {
            CoreError::invalid("a fat journal run does not fit this machine's usize")
        })?;
        let mut piece_start = 0_usize;
        while piece_start < total {
            let entries = (total - piece_start).min(WINDOW_ENTRIES);
            let mut bytes = [0u8; WINDOW_BYTES];
            for (slot, index) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(0..entries) {
                let offset_in_run = piece_start
                    .checked_add(index)
                    .and_then(|delta| u32::try_from(delta).ok())
                    .ok_or_else(|| {
                        CoreError::invalid("a fat journal cluster overflows u32 numbering")
                    })?;
                let cluster = run.0.saturating_add(offset_in_run);
                let value = delta.get_value(cluster).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "the fat journal lost pending cluster {cluster} mid-flush"
                    ))
                })?;
                slot.copy_from_slice(&value.to_le_bytes());
            }
            let first = run
                .0
                .saturating_add(u32::try_from(piece_start).map_err(|_| {
                    CoreError::invalid("a fat journal run piece overflows the cluster numbering")
                })?);
            let byte_len = entries
                .checked_mul(4)
                .ok_or_else(|| CoreError::invalid("a fat flush chunk overflows its bytes"))?;
            for copy in 0..u32::from(geometry.num_fats) {
                let offset = fat_copy_offset(geometry, copy, first)?;
                volume.write_all_at(
                    offset,
                    bytes
                        .get(..byte_len)
                        .ok_or_else(|| CoreError::invalid("a fat flush chunk window vanished"))?,
                )?;
            }
            piece_start += entries;
        }
    }
    delta.clear();
    Ok(())
}

/// The widened result of a free-run scan: everything the caller needs —
/// the found run (or `None` when the volume cannot serve it), the true
/// free-cluster count, the largest run seen, and the first free cluster
/// (the FSInfo next-free hint a recount republishes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FreeScan {
    /// The first-fit run — `(first cluster, run length)` — or `None`
    /// when the whole (wrapped) scan found no run of `need` clusters.
    pub run: Option<(u32, u32)>,
    /// Free clusters seen so far: the *true* volume total only when the
    /// scan ran to completion (the full/refusal path); a partial
    /// reading when the scan stopped at the first fit.
    pub free_seen: u32,
    /// Largest contiguous free run observed (a partial reading on an
    /// early exit).
    pub largest_run: u32,
    /// The first free cluster seen — `None` on a volume with none.
    pub first_free: Option<u32>,
}

/// A windowed reader over the first FAT copy: loads 16 Ki entries per
/// disk read and serves entry values from the window, consulting the
/// journal (when present) ahead of the window so live state wins.
struct FatWindow<'a> {
    volume: &'a dyn Volume,
    geometry: &'a Geometry,
    journal: Option<&'a FatDelta>,
    bytes: [u8; WINDOW_BYTES],
    /// Cluster number the window starts at (0 = unloaded).
    start: u32,
    /// Entries currently valid in the window.
    count: u32,
}

impl<'a> FatWindow<'a> {
    fn new(volume: &'a dyn Volume, geometry: &'a Geometry, journal: Option<&'a FatDelta>) -> Self {
        Self {
            volume,
            geometry,
            journal,
            bytes: [0u8; WINDOW_BYTES],
            start: 0,
            count: 0,
        }
    }

    /// Load the window that serves `cluster` (and as much of what
    /// follows as one 64 KiB read allows).
    fn load(&mut self, cluster: u32) -> Result<()> {
        let last = self.geometry.cluster_count;
        if cluster > last.saturating_add(1) {
            return Err(CoreError::invalid(format!(
                "fat scan ran past the data clusters at {cluster}"
            )));
        }
        let available = last
            .saturating_add(1)
            .checked_sub(cluster)
            .and_then(|size| u32::checked_add(size, 1)) // inclusive span
            .unwrap_or(0);
        let entries =
            usize::try_from(available.min(u32::try_from(WINDOW_ENTRIES).unwrap_or(u32::MAX)))
                .map_err(|_| CoreError::invalid("a fat window length exceeds usize"))?;
        let byte_len = entries
            .checked_mul(4)
            .ok_or_else(|| CoreError::invalid("a fat window overflows its bytes"))?;
        let offset = fat_copy_offset(self.geometry, 0, cluster)?;
        self.volume.read_exact_at(
            offset,
            self.bytes
                .get_mut(..byte_len)
                .ok_or_else(|| CoreError::invalid("a fat window buffer vanished mid-read"))?,
        )?;
        self.start = cluster;
        self.count = entries as u32;
        Ok(())
    }

    /// The entry value for `cluster`: the journal first, then the
    /// loaded window (`Err` when the volume misbehaves mid-read).
    fn entry(&mut self, cluster: u32) -> Result<u32> {
        if let Some(value) = self.journal.and_then(|journal| journal.get_value(cluster)) {
            return Ok(value);
        }
        if !(self.start..self.start.saturating_add(self.count)).contains(&cluster) {
            self.load(cluster)?;
        }
        let at = cluster
            .checked_sub(self.start)
            .and_then(|delta| {
                usize::try_from(delta)
                    .ok()
                    .and_then(|machine| machine.checked_mul(4))
            })
            .ok_or_else(|| {
                CoreError::invalid(format!("fat window lost track of cluster {cluster}"))
            })?;
        let mut value = [0u8; 4];
        let window = self.bytes.get(at..at + 4).ok_or_else(|| {
            CoreError::invalid(format!("fat window lost track of cluster {cluster}"))
        })?;
        value.copy_from_slice(window);
        Ok(u32::from_le_bytes(value))
    }
}

/// First-fit scan for a run of `need` consecutive free data clusters,
/// starting at the FSInfo next-free `hint` and wrapping to the volume
/// start exactly once. The reader streams the first FAT copy through
/// 64 KiB windows; the `journal` overlays pending allocations so no
/// scan can pick a cluster the journal already claims.
///
/// A run never wraps past the last cluster: contiguity means
/// consecutive cluster numbers, and the wrap span is walked *after* the
/// span from `hint` on, so a run ending at the data-top ends there too.
pub(crate) fn scan_free_run(
    volume: &dyn Volume,
    geometry: &Geometry,
    journal: &FatDelta,
    hint: u32,
    need: u32,
) -> Result<FreeScan> {
    let last = geometry.cluster_count.saturating_add(1);
    let start = if hint >= ROOT_CLUSTER && hint <= last {
        hint
    } else {
        ROOT_CLUSTER
    };
    // Two spans walk every data cluster exactly once: from the hint to
    // the top, then the wrapped remainder (empty when the hint already
    // was the volume's beginning).
    let spans: [(u32, u32); 2] = [(start, last), (ROOT_CLUSTER, start.saturating_sub(1))];
    let mut reader = FatWindow::new(volume, geometry, Some(journal));
    let mut scan = FreeScan {
        run: None,
        free_seen: 0,
        largest_run: 0,
        first_free: None,
    };
    for (from, to) in spans {
        if to < from {
            continue; // empty span (the hint at the volume start)
        }
        // A run may not cross a span boundary (the wrap cut), so the
        // counter resets between spans.
        let mut run_len = 0_u32;
        let mut run_first = 0_u32;
        for cluster in from..=to {
            let value = reader.entry(cluster)?;
            if value != FREE {
                run_len = 0;
                continue;
            }
            scan.free_seen = scan.free_seen.saturating_add(1);
            if scan.first_free.is_none() {
                scan.first_free = Some(cluster);
            }
            if run_len == 0 {
                run_first = cluster;
            }
            run_len = run_len.saturating_add(1);
            scan.largest_run = scan.largest_run.max(run_len);
            if run_len == need {
                scan.run = Some((run_first, need));
                return Ok(scan); // first fit: stop the scan
            }
        }
    }
    Ok(scan)
}

/// Recount the free clusters across the whole FAT (the cost the FSInfo
/// docs name: one full pass over the first FAT copy, 4 bytes per
/// cluster) and take the first free cluster as the next-free hint.
/// Used by `open()` when the FSInfo says "unknown", and by tests.
pub(crate) fn recount(
    volume: &dyn Volume,
    geometry: &Geometry,
    journal: &FatDelta,
) -> Result<(u32, u32)> {
    let scan = scan_free_run(volume, geometry, journal, ROOT_CLUSTER, u32::MAX)?;
    Ok((scan.free_seen, scan.first_free.unwrap_or(u32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::fat32::geometry::NUM_FATS;
    use crate::fs::fat32::geometry::geometry;

    /// The 64 MiB sample geometry (spc 1, FAT 1009, 129,022 clusters),
    /// shared by the raw-table tests.
    fn sample_geometry() -> &'static Geometry {
        use std::sync::OnceLock;
        static GEOMETRY: OnceLock<Geometry> = OnceLock::new();
        GEOMETRY.get_or_init(|| geometry(64 * 1024 * 1024, 512).expect("64 MiB geometry"))
    }

    fn sample_volume() -> VecVolume {
        VecVolume::new(64 * 1024 * 1024, 512).expect("64 MiB of RAM")
    }

    /// Write one FAT entry raw (both copies), bypassing the journal —
    /// the low-level simulator of "some earlier session allocated this".
    fn raw_set(volume: &mut VecVolume, geometry: &Geometry, cluster: u32, value: u32) {
        for copy in 0..u32::from(NUM_FATS) {
            let offset = fat_copy_offset(geometry, copy, cluster).expect("in-range entry");
            volume
                .write_all_at(offset, &value.to_le_bytes())
                .expect("fat entry write");
        }
    }

    fn raw_get(volume: &VecVolume, geometry: &Geometry, copy: u32, cluster: u32) -> u32 {
        let offset = fat_copy_offset(geometry, copy, cluster).expect("in-range entry");
        let mut bytes = [0u8; 4];
        volume
            .read_exact_at(offset, &mut bytes)
            .expect("fat entry read");
        u32::from_le_bytes(bytes)
    }

    #[test]
    fn classify_bands_match_the_fat32_law() {
        let clusters = 1_000_u32;
        assert_eq!(classify(0, clusters), FatEntry::Free);
        for value in [EOC_MIN, 0x0FFF_FFF9, 0x0FFF_FFFE, EOC, u32::MAX] {
            assert_eq!(classify(value, clusters), FatEntry::End, "value {value:#x}");
        }
        assert_eq!(classify(2, clusters), FatEntry::Link(2));
        assert_eq!(
            classify(clusters + 1, clusters),
            FatEntry::Link(clusters + 1)
        );
        for value in [1_u32, 0x0FFF_FFF7, clusters + 2, 0x0FFF_FFF6] {
            let classified = classify(value, clusters);
            assert_eq!(classified, FatEntry::Corrupt(value), "value {value:#x}");
        }
    }

    #[test]
    fn delta_records_runs_and_flushes_into_both_copies() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let mut delta = FatDelta::default();
        // one contiguous chain: clusters 10..14 link on with an EoC end
        delta.set(10, 11);
        delta.set(11, 12);
        delta.set(12, 13);
        delta.set(13, EOC);
        assert!(delta.is_dirty());
        // merged runs: exactly one
        assert_eq!(delta.runs(), vec![(10, 14)]);

        flush_delta(&mut volume, geometry, &mut delta).expect("the flush lands");
        assert!(!delta.is_dirty(), "the journal clears on success");
        for cluster in [10_u32, 11, 12, 13] {
            let want = if cluster == 13 { EOC } else { cluster + 1 };
            for copy in 0..u32::from(NUM_FATS) {
                assert_eq!(
                    raw_get(&volume, geometry, copy, cluster),
                    want,
                    "cluster {cluster} in copy {copy}"
                );
            }
        }
        // untouched clusters stay free
        assert_eq!(raw_get(&volume, geometry, 0, 14), 0);
        // and a second flush is a no-op
        let mut second = FatDelta::default();
        flush_delta(&mut volume, geometry, &mut second).expect("no-op flush");
    }

    #[test]
    fn read_entry_prefers_the_journal_then_the_disk() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let mut delta = FatDelta::default();
        delta.set(7, EOC);
        // journal wins before flush...
        assert_eq!(
            read_entry(&volume, geometry, Some(&delta), 7).expect("overlaid read"),
            EOC
        );
        // ...the disk still shows free
        assert_eq!(
            read_entry(&volume, geometry, None, 7).expect("disk read"),
            0
        );
        // ...and flush publishes to the disk
        flush_delta(&mut volume, geometry, &mut delta).expect("flush");
        assert_eq!(
            read_entry(&volume, geometry, None, 7).expect("published read"),
            EOC
        );
        // out-of-range cluster numbers are refused, not read
        let error = read_entry(&volume, geometry, None, 1).expect_err("cluster 1");
        assert!(error.to_string().contains("1"), "{error}");
        let error = read_entry(&volume, geometry, None, geometry.cluster_count + 2)
            .expect_err("past the top");
        assert!(
            error
                .to_string()
                .contains(&(geometry.cluster_count + 2).to_string()),
            "{error}"
        );
    }

    #[test]
    fn scan_free_run_finds_the_first_fit_from_the_hint() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let journal = FatDelta::default();
        // simulate a formatted volume: cluster 2 is the (allocated) root
        raw_set(&mut volume, geometry, 2, EOC);
        // ...and scatter a few allocations: {3, 5, 9, 10, 11}
        for cluster in [3_u32, 5, 9, 10, 11] {
            raw_set(&mut volume, geometry, cluster, EOC);
        }
        // hint 4, need 1: 4 is the first free from the hint
        let scan = scan_free_run(&volume, geometry, &journal, 4, 1).expect("scan");
        assert_eq!(scan.run, Some((4, 1)));
        assert_eq!(scan.first_free, Some(4));
        // hint 2, need 2: runs break on every allocation — first fit
        // is the hole at 6..8
        let scan = scan_free_run(&volume, geometry, &journal, 2, 2).expect("scan");
        assert_eq!(scan.run, Some((6, 2)));
        // hint past the top (stale/unknown): the scan wraps to 2 and the
        // first fit still lands on the low hole
        let scan = scan_free_run(&volume, geometry, &journal, u32::MAX, 1).expect("scan");
        assert_eq!(scan.run, Some((4, 1)), "wrap starts from cluster 2");
        // the journal overlays: claiming the first hole (4) moves the
        // fit past it, claiming the next (6) again
        let mut claimed = FatDelta::default();
        claimed.set(4, 5);
        let scan = scan_free_run(&volume, geometry, &claimed, 2, 1).expect("overlay scan");
        assert_eq!(scan.run, Some((6, 1)), "the journal hides its claims");
        claimed.set(6, 7);
        let scan = scan_free_run(&volume, geometry, &claimed, 2, 1).expect("overlay scan");
        assert_eq!(scan.run, Some((7, 1)), "both holes closed by the journal");
        // and a full-scan return names the truth: 2, 3, 5, 9, 10 and 11
        // are allocated, so 129,016 of 129,022 clusters stay free
        let scan =
            scan_free_run(&volume, geometry, &journal, u32::MAX, u32::MAX).expect("full scan");
        assert_eq!(scan.run, None, "no run of u32::MAX clusters");
        assert_eq!(scan.free_seen, geometry.cluster_count - 6);
        // largest free run: everything from 12 up to the top (count+1)
        assert_eq!(scan.largest_run, geometry.cluster_count - 10);
    }

    #[test]
    fn scan_free_run_never_crosses_the_volume_top() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let journal = FatDelta::default();
        // a formatted-shaped volume: the root allocated, plus the last
        // two data clusters ((cluster_count + 1) is the top number)
        let last = geometry.cluster_count + 1;
        raw_set(&mut volume, geometry, 2, EOC);
        raw_set(&mut volume, geometry, last - 1, last);
        raw_set(&mut volume, geometry, last, EOC);
        // hint at the free zone's end: the span [hint..last] holds one
        // free cluster before the allocations break the run
        let scan = scan_free_run(&volume, geometry, &journal, last - 2, 1).expect("scan");
        assert_eq!(scan.run, Some((last - 2, 1)), "first fit from the hint");
        // a 2-run cannot complete in that span and lands in the wrapped
        // remainder instead (first free there is cluster 3)
        let scan = scan_free_run(&volume, geometry, &journal, last - 2, 2).expect("scan");
        assert_eq!(scan.run, Some((3, 2)), "the wrap span's first fit");
        // a stale hint walks the honest wrap-once pass to the same run
        let scan = scan_free_run(&volume, geometry, &journal, u32::MAX, 2).expect("wrap scan");
        assert_eq!(scan.run, Some((3, 2)), "the wrap span's first fit");
        // a full exploration (a recount shape) reports the totals
        let scan =
            scan_free_run(&volume, geometry, &journal, u32::MAX, u32::MAX).expect("full scan");
        assert_eq!(scan.run, None);
        assert_eq!(scan.free_seen, geometry.cluster_count - 3);
        assert_eq!(scan.largest_run, geometry.cluster_count - 3);
        assert_eq!(scan.first_free, Some(3));
    }

    #[test]
    fn recount_takes_the_full_fat_pass() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let journal = FatDelta::default();
        // pristine table: every cluster free, first free is cluster 2
        let (free, next) = recount(&volume, geometry, &journal).expect("recount");
        assert_eq!(free, geometry.cluster_count);
        assert_eq!(next, 2);

        // now claim a handful through raw writes (as an earlier session
        // would have): the recount tracks the disk exactly
        for cluster in [2_u32, 3, 4, 10, 11] {
            raw_set(&mut volume, geometry, cluster, EOC);
        }
        let (free, next) = recount(&volume, geometry, &journal).expect("recount");
        assert_eq!(free, geometry.cluster_count - 5);
        assert_eq!(next, 5, "the first free cluster after 2, 3, 4");
    }

    #[test]
    fn delta_flush_chunks_a_long_chain_without_allocating_it_all() {
        let geometry = sample_geometry();
        let mut volume = sample_volume();
        let mut delta = FatDelta::default();
        // a chain longer than one 64 KiB chunk: 20,000 clusters of run
        let start = 5_u32;
        for offset in 0..20_000_u32 {
            let cluster = start + offset;
            let value = if offset + 1 == 20_000 {
                EOC
            } else {
                cluster + 1
            };
            delta.set(cluster, value);
        }
        assert_eq!(delta.runs(), vec![(start, start + 20_000)]);
        flush_delta(&mut volume, geometry, &mut delta).expect("the long chain flushes");
        // spot-check the chunk-boundary entries (per cluster index
        // 16_383 | 16_384: the two sides of the 64 KiB piece)
        for index in [0_u32, 16_383, 16_384, 19_999] {
            let want = if index + 1 == 20_000 {
                EOC
            } else {
                start + index + 1
            };
            for copy in 0..u32::from(NUM_FATS) {
                assert_eq!(raw_get(&volume, geometry, copy, start + index), want);
            }
        }
        assert!(!delta.is_dirty());
    }
}
