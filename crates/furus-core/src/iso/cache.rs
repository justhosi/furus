//! Whole-sector reads through a 64 KiB LRU cache (S14, slice 1).
//!
//! The cache owns the store as `Box<dyn Volume>` and serves every read in
//! units of one 2048-byte ISO sector ([`SECTOR_BYTES`](super::SECTOR_BYTES)):
//! 32 slots ([`SLOT_COUNT`]) hold the most recently used sectors, evicted
//! least-recently-used via a wrapping use counter. A hit never touches the
//! store; a miss reads exactly one sector. Repetitive directory walks and
//! descriptor scans therefore cost one store read per sector no matter how
//! often the caller revisits it — the amortised pattern the PLAN's mmap
//! mandate wants, without mapping anything.
//!
//! Every access is bounds-checked against `total_bytes` *before* any I/O
//! (`offset + len <= total`, checked arithmetic), and the refusal names
//! the sector, the offset and the volume extent, exactly like
//! [`fs`](crate::fs) demands. A sector that is not fully present is
//! refused rather than zero-padded: a short store must never dress a
//! bogus volume up as readable.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::iso::SECTOR_BYTES;
use crate::iso::SECTOR_BYTES_U64;

/// Cached sectors: 32 slots of 2048 bytes are exactly 64 KiB.
const SLOT_COUNT: usize = 32;

/// One cached sector: its logical sector number, the bytes, and the last
/// use stamp for LRU eviction.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// Logical 2048-byte sector number this slot holds.
    sector: u32,
    /// The sector bytes, read whole from the store on a miss.
    bytes: [u8; SECTOR_BYTES],
    /// Wrapping use counter at last hit-or-fill; the smallest stamp is
    /// evicted next.
    last_used: u64,
}

/// Whole-sector LRU cache over an owned byte store.
///
/// The store is owned (`Box<dyn Volume>`) so the cache — and through it
/// the reader — carries no lifetime; a borrow would thread the store's
/// lifetime into every call site for no benefit, and the image is small
/// enough to own outright in every test and tool call this slice makes.
pub struct SectorCache {
    /// The backing byte store; only touched on a cache miss, one whole
    /// sector at a time.
    volume: Box<dyn Volume>,
    /// Fixed slot ring; `None` until first filled.
    slots: [Option<Slot>; SLOT_COUNT],
    /// Wrapping use counter handed out on every access (wrapping, so the
    /// counter itself can never overflow-panic no matter how long the
    /// reader runs).
    clock: u64,
}

impl std::fmt::Debug for SectorCache {
    /// Occupancy and extent only: the cached bytes never appear in debug
    /// output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filled = self.slots.iter().filter(|slot| slot.is_some()).count();
        f.debug_struct("SectorCache")
            .field("total_bytes", &self.volume.total_bytes())
            .field("filled_slots", &filled)
            .finish()
    }
}

impl SectorCache {
    /// Wrap `volume`: no I/O happens here, the slots start empty.
    #[must_use]
    pub fn new(volume: Box<dyn Volume>) -> Self {
        Self {
            volume,
            slots: [None; SLOT_COUNT],
            clock: 0,
        }
    }

    /// Total extent in bytes the backing store exposes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.volume.total_bytes()
    }

    /// The whole 2048-byte `sector`, from the cache on a hit or from the
    /// store on a miss (evicting the least-recently-used slot).
    ///
    /// The byte window is bounds-checked against `total_bytes` before any
    /// I/O, and a sector that would run past the volume end is refused
    /// with the sector, the offset and the extent all named — never
    /// zero-padded.
    pub fn read_sector(&mut self, sector: u32) -> Result<&[u8; SECTOR_BYTES]> {
        self.clock = self.clock.wrapping_add(1);
        let now = self.clock;
        let mut hit: Option<usize> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(entry) if entry.sector == sector => {
                    hit = Some(index);
                    break;
                }
                _ => {}
            }
        }
        if let Some(index) = hit {
            match self.slots.get_mut(index) {
                Some(Some(entry)) => {
                    entry.last_used = now;
                    return Ok(&entry.bytes);
                }
                _ => {
                    return Err(CoreError::invalid(
                        "iso sector cache lost its entry between lookup and use",
                    ));
                }
            }
        }
        let offset = u64::from(sector)
            .checked_mul(SECTOR_BYTES_U64)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "iso sector {sector} overflows the byte offset arithmetic"
                ))
            })?;
        let total = self.volume.total_bytes();
        let end = offset.checked_add(SECTOR_BYTES_U64).ok_or_else(|| {
            CoreError::invalid(format!(
                "iso sector {sector} at offset {offset} overflows the byte offset arithmetic"
            ))
        })?;
        if end > total {
            return Err(CoreError::invalid(format!(
                "read of 2048 bytes at offset {offset} runs past the {total} byte \
                 volume end (iso sector {sector} is not fully present)"
            )));
        }
        let mut bytes = [0u8; SECTOR_BYTES];
        self.volume.read_exact_at(offset, &mut bytes)?;
        let victim = self.lru_victim();
        match self.slots.get_mut(victim) {
            Some(slot) => {
                *slot = Some(Slot {
                    sector,
                    bytes,
                    last_used: now,
                });
            }
            None => {
                return Err(CoreError::invalid(
                    "iso sector cache lost its eviction slot between lookup and use",
                ));
            }
        }
        match self.slots.get(victim) {
            Some(Some(entry)) => Ok(&entry.bytes),
            _ => Err(CoreError::invalid(
                "iso sector cache lost its entry between fill and use",
            )),
        }
    }

    /// Index of the slot to evict: the first empty slot, else the slot
    /// with the smallest use stamp. Always below [`SLOT_COUNT`].
    fn lru_victim(&self) -> usize {
        let mut victim: usize = 0;
        let mut victim_stamp: Option<u64> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                None => {
                    return index;
                }
                Some(entry) => match victim_stamp {
                    None => {
                        victim = index;
                        victim_stamp = Some(entry.last_used);
                    }
                    Some(best) => {
                        if entry.last_used < best {
                            victim = index;
                            victim_stamp = Some(entry.last_used);
                        }
                    }
                },
            }
        }
        victim
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Counting in-memory [`Volume`] for the cache tests: records how
    /// many store reads happened so hits versus misses are observable.
    /// (`VecVolume` would serve the bytes, but it cannot count reads; the
    /// counter is shared through `Rc` so tests can observe it past the
    /// `Box` the cache owns.)
    #[derive(Debug)]
    struct CountingVolume {
        bytes: Vec<u8>,
        reads: Rc<Cell<usize>>,
    }

    impl CountingVolume {
        fn new(len: usize, reads: &Rc<Cell<usize>>) -> Self {
            Self {
                bytes: vec![0u8; len],
                reads: Rc::clone(reads),
            }
        }
    }

    impl Volume for CountingVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.bytes.len() {
                return Err(CoreError::invalid(format!(
                    "read of {} bytes at offset {offset} runs past the {} byte volume end",
                    buf.len(),
                    self.bytes.len()
                )));
            }
            buf.copy_from_slice(&self.bytes[start..end]);
            Ok(())
        }

        fn write_all_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<()> {
            Err(CoreError::invalid("counting volume is read-only"))
        }
    }

    /// A cache over `sectors` zeroed sectors plus its shared read counter.
    fn cache_over(sector_count: usize) -> (Rc<Cell<usize>>, SectorCache) {
        let reads = Rc::new(Cell::new(0));
        let volume = CountingVolume::new(sector_count * SECTOR_BYTES, &reads);
        (Rc::clone(&reads), SectorCache::new(Box::new(volume)))
    }

    #[test]
    fn total_bytes_tracks_the_store() {
        let (_reads, cache) = cache_over(4);
        assert_eq!(cache.total_bytes(), 4 * SECTOR_BYTES as u64);
    }

    #[test]
    fn miss_reads_once_then_hits_are_free() {
        let reads = Rc::new(Cell::new(0));
        let mut volume = CountingVolume::new(2 * SECTOR_BYTES, &reads);
        for (index, byte) in volume.bytes.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let expected_first: [u8; SECTOR_BYTES] = volume.bytes[..SECTOR_BYTES]
            .try_into()
            .expect("the fixture is two sectors");
        let mut cache = SectorCache::new(Box::new(volume));
        let first = *cache.read_sector(0).expect("sector 0 is present");
        assert_eq!(first, expected_first);
        assert_eq!(reads.get(), 1, "the miss costs one store read");
        let again = *cache.read_sector(0).expect("sector 0 is cached");
        assert_eq!(again, expected_first);
        assert_eq!(reads.get(), 1, "the hit costs no store read");
    }

    #[test]
    fn eviction_drops_the_least_recently_used_slot() {
        let (reads, mut cache) = cache_over(40);
        for sector in 0..32u32 {
            cache
                .read_sector(sector)
                .expect("the fixture has 40 sectors");
        }
        assert_eq!(reads.get(), 32);
        // Touch sector 0 so sector 1 becomes the oldest instead.
        cache.read_sector(0).expect("sector 0 is cached");
        assert_eq!(reads.get(), 32, "re-reading sector 0 is still a hit");
        // Two fresh sectors evict the two oldest untouched slots.
        cache.read_sector(32).expect("sector 32 is present");
        cache.read_sector(33).expect("sector 33 is present");
        assert_eq!(reads.get(), 34);
        // Sector 1 fell out (a miss again); sector 0 survived (a hit).
        cache.read_sector(1).expect("sector 1 is present");
        assert_eq!(reads.get(), 35, "sector 1 was evicted and re-read");
        cache.read_sector(0).expect("sector 0 survived");
        assert_eq!(reads.get(), 35, "sector 0 was never evicted");
    }

    #[test]
    fn sector_past_the_end_names_sector_offset_and_extent() {
        // Two sectors: reading sector 2 starts exactly at the end.
        let (_reads, mut cache) = cache_over(2);
        let error = cache.read_sector(2).expect_err("sector 2 is not present");
        let text = error.to_string();
        assert!(text.contains("4096"), "{text}");
        assert!(text.contains("sector 2"), "{text}");
    }

    #[test]
    fn partial_last_sector_is_refused_not_padded() {
        // The store ends 100 bytes into sector 1: the sector is not fully
        // present, so it refuses instead of zero-padding the tail.
        let reads = Rc::new(Cell::new(0));
        let volume = CountingVolume::new(SECTOR_BYTES + 100, &reads);
        let mut cache = SectorCache::new(Box::new(volume));
        let error = cache.read_sector(1).expect_err("the tail is short");
        let text = error.to_string();
        assert!(text.contains("2048"), "{text}");
        assert!(text.contains("2148"), "{text}");
        assert_eq!(reads.get(), 0, "the refusal happens before any I/O");
    }
}
