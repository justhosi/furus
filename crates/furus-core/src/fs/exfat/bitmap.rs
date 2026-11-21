//! The exFAT allocation bitmap, in memory and back to the volume (S10
//! part B1).
//!
//! exFAT splits the cluster bookkeeping in two: the FAT describes
//! *chains*, but *allocations* — which clusters may be handed out —
//! live in the bitmap, a single byte-stream whose 0x81 directory entry
//! names its first cluster (spec 7.1). One bit per heap cluster, LSB
//! first within each byte: bit *i* describes cluster `i + 2`, the same
//! numbering the measured `mkfs.exfat` images carry (a freshly
//! formatted 64 MiB volume reads `0x0F` in byte 0 — clusters 2..=5,
//! the system clusters — and zeroes everywhere else; three small
//! measured volumes with cluster counts not divisible by 8 all carry
//! zero bits beyond the cluster count in the partial last byte).
//!
//! This module keeps one [`Bitmap`] in memory, hands out contiguous
//! runs ([`Bitmap::first_fit`], a first-fit scan that never wraps) and
//! marks/clears clusters. The live volume pairs it with a cached free
//! count and a dirty flag; [`Bitmap::write_back`] puts the bytes back
//! onto the volume at the offset the load recorded.
//!
//! Nothing here indexes a slice directly and every out-of-range
//! cluster refuses with the number named — a hostile or corrupt
//! bitmap produces errors, never a write past its own end.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

/// First heap cluster (clusters 0 and 1 are reserved).
pub const FIRST_HEAP_CLUSTER: u32 = 2;

/// The in-memory allocation bitmap of one volume.
///
/// `bytes` holds exactly `ceil(cluster_count / 8)` meaningful bytes —
/// the length the 0x81 entry's DataLength makes true — while
/// `clusters` records how many clusters the volume set aside for the
/// stream (a whole number of clusters, usually one more byte's worth
/// of slack inside the last cluster).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitmap {
    /// One bit per heap cluster, LSB-first: bit *i* = cluster `i + 2`,
    /// set when the cluster is in use.
    bytes: Vec<u8>,
    /// Number of clusters in the heap; cluster `cluster_count + 1` is
    /// the last one the bitmap describes.
    cluster_count: u32,
    /// First cluster of the bitmap stream (from the volume's 0x81
    /// entry; cluster 2 in this formatter's layouts).
    first_cluster: u32,
    /// Clusters the bitmap stream spans.
    clusters: u32,
    /// Byte offset on the volume where the stream begins — fixed at
    /// load so [`Bitmap::write_back`] needs nothing else.
    base_offset: u64,
}

impl Bitmap {
    /// Load the bitmap of a volume whose stream starts at
    /// `first_cluster` and spans `clusters` clusters, the stream's
    /// first byte living at `base_offset`.
    ///
    /// Refusals name the numbers: a byte length larger than the stream
    /// actually holds (`ceil(cluster_count / 8)` against
    /// `clusters * cluster_bytes`) and a read that comes up short.
    /// The stream itself is read contiguously — this crate's own
    /// volumes allocate the bitmap run contiguously, which the pinned
    /// `Geometry` fields and the fsck-clean acceptance both rely on.
    pub fn load(
        volume: &dyn Volume,
        first_cluster: u32,
        clusters: u32,
        cluster_bytes: u32,
        cluster_count: u32,
        base_offset: u64,
    ) -> Result<Self> {
        let bitmap_bytes = u64::from(cluster_count).div_ceil(8);
        let stream_bytes = u64::from(clusters).saturating_mul(u64::from(cluster_bytes.max(1)));
        if bitmap_bytes > stream_bytes {
            return Err(CoreError::invalid(format!(
                "an allocation bitmap of {bitmap_bytes} bytes cannot fit in {clusters} clusters \
                 of {cluster_bytes} bytes"
            )));
        }
        let len = usize::try_from(bitmap_bytes)
            .map_err(|_| CoreError::invalid("the allocation bitmap does not fit memory"))?;
        let mut bytes = vec![0_u8; len];
        volume.read_exact_at(base_offset, &mut bytes)?;
        Ok(Self {
            bytes,
            cluster_count,
            first_cluster,
            clusters,
            base_offset,
        })
    }

    /// The bitmap's first cluster, for the copy-perserving operations
    /// that need to know where the stream lives.
    #[must_use]
    pub fn first_cluster(&self) -> u32 {
        self.first_cluster
    }

    /// Clusters the bitmap stream spans.
    #[must_use]
    pub fn clusters(&self) -> u32 {
        self.clusters
    }

    /// Replace the in-memory bits wholesale — the rollback path only:
    /// the caller restores a previously loaded-and-validated byte image
    /// (the snapshot of a create call), not arbitrary new state.
    pub(crate) fn replace_bits(&mut self, bytes: Vec<u8>) {
        // Only a snapshot of this bitmap can arrive here, so a short
        // image means a caller bug; ignoring it keeps every bit honest
        // (a truncated image would otherwise read missing bytes as
        // free) without a panic in a recovery path.
        if bytes.len() == self.bytes.len() {
            self.bytes = bytes;
        }
    }

    /// The raw bytes (tests and integrity checks only).
    #[allow(dead_code)]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte offset the stream starts at on the volume.
    #[must_use]
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// Free clusters in total, counted from the bits themselves.
    ///
    /// A set bit marks a used cluster, so the free count is the heap's
    /// cluster count minus the set bits — and bits beyond the cluster
    /// count (the partial last byte's padding) never count either way:
    /// the measured `mkfs` volumes carry zeros there, but counting
    /// only meaningful bits keeps the number exact even if a foreign
    /// volume's padding were dirty.
    #[must_use]
    pub fn free_clusters(&self) -> u32 {
        let whole_bytes = usize::try_from(u64::from(self.cluster_count) / 8)
            .ok()
            .unwrap_or(self.bytes.len());
        let mut in_use = self
            .bytes
            .iter()
            .take(whole_bytes)
            .map(|byte| byte.count_ones())
            .sum::<u32>();
        let tail_bits = usize::try_from(u64::from(self.cluster_count) % 8).ok();
        if let (Some(remainder), Some(bits)) = (self.bytes.get(whole_bytes), tail_bits)
            && bits > 0
        {
            let mask =
                (1_u8.checked_shl(bits.try_into().unwrap_or(31)).unwrap_or(0)).wrapping_sub(1);
            in_use = in_use.saturating_add(u32::from(remainder & mask).count_ones());
        }
        self.cluster_count.saturating_sub(in_use)
    }

    /// Whether `cluster` (2..= `cluster_count + 1`) is free. Anything
    /// else refuses with the offending cluster named — clusters 0 and
    /// 1 are reserved and exist nowhere in the bitmap.
    pub fn is_free(&self, cluster: u32) -> Result<bool> {
        let (index, bit) = self.bit_of(cluster)?;
        Ok(is_free_bit(
            self.bytes.get(index).copied().unwrap_or(0),
            bit,
        ))
    }

    /// The first contiguous run of `count` free clusters, scanning
    /// upward from the heap start and never wrapping: `None` when no
    /// such run exists in front of the end of the heap. The returned
    /// cluster number is the run's first cluster.
    ///
    /// `count == 0` is refused (there is no such thing as a zero-run
    /// allocation) and so is a run longer than the whole heap — both
    /// name their numbers instead of quietly meaning "not found".
    pub fn first_fit(&self, count: u32) -> Result<Option<u32>> {
        if count == 0 {
            return Err(CoreError::invalid(
                "an allocation claims at least one cluster, run length 0 refused".to_string(),
            ));
        }
        if count > self.cluster_count {
            return Err(CoreError::invalid(format!(
                "a run of {count} clusters is longer than the heap holds {cluster_count}",
                cluster_count = self.cluster_count
            )));
        }
        let last = self.last_cluster();
        let mut run = 0_u32;
        let mut start: Option<u32> = None;
        for cluster in FIRST_HEAP_CLUSTER..=last {
            let (index, bit) = self.bit_of(cluster)?;
            if !is_free_bit(self.bytes.get(index).copied().unwrap_or(0), bit) {
                run = 0;
                start = None;
                continue;
            }
            if run == 0 {
                start = Some(cluster);
            }
            run = run.saturating_add(1);
            if run == count {
                return Ok(start);
            }
        }
        Ok(None)
    }

    /// Mark `count` clusters starting at `cluster` in use.
    ///
    /// Every cluster of the run must currently be free — marking an
    /// in-use cluster is an arithmetic bug somewhere upstream, and this
    /// refuses with the first such cluster named rather than silently
    /// double-allocating it. A run reaching past the last heap cluster
    /// refuses the same way.
    pub fn mark(&mut self, count: u32, cluster: u32) -> Result<()> {
        if count == 0 {
            return Err(CoreError::invalid(
                "marking zero clusters describes nothing".to_string(),
            ));
        }
        for step in 0..count {
            let at = cluster
                .checked_add(step)
                .ok_or_else(|| CoreError::invalid(format!("mark run from {cluster} overflows")))?;
            let (index, bit) = self.bit_of(at)?;
            if !is_free_bit(self.bytes.get(index).copied().unwrap_or(0), bit) {
                return Err(CoreError::invalid(format!(
                    "cluster {at} of the run is already in use"
                )));
            }
        }
        for step in 0..count {
            let at = cluster
                .checked_add(step)
                .ok_or_else(|| CoreError::invalid(format!("mark run from {cluster} overflows")))?;
            let (index, bit) = self.bit_of(at)?;
            self.set_bit(index, bit, true)?;
        }
        Ok(())
    }

    /// Return `count` clusters starting at `cluster` to the free pool.
    ///
    /// Every cluster of the run must currently be in use — clearing a
    /// free cluster would hide a real corruption, so the first such
    /// cluster is named in the refusal. A run reaching past the last
    /// heap cluster refuses the same way.
    pub fn clear(&mut self, count: u32, cluster: u32) -> Result<()> {
        if count == 0 {
            return Err(CoreError::invalid(
                "clearing zero clusters describes nothing".to_string(),
            ));
        }
        for step in 0..count {
            let at = cluster
                .checked_add(step)
                .ok_or_else(|| CoreError::invalid(format!("clear run from {cluster} overflows")))?;
            let (index, bit) = self.bit_of(at)?;
            if is_free_bit(self.bytes.get(index).copied().unwrap_or(0), bit) {
                return Err(CoreError::invalid(format!(
                    "cluster {at} of the run is already free"
                )));
            }
        }
        for step in 0..count {
            let at = cluster
                .checked_add(step)
                .ok_or_else(|| CoreError::invalid(format!("clear run from {cluster} overflows")))?;
            let (index, bit) = self.bit_of(at)?;
            self.set_bit(index, bit, false)?;
        }
        Ok(())
    }

    /// Write the bitmap bytes back onto the volume at the offset the
    /// load recorded — byte-exact, `ceil(cluster_count / 8)` bytes of
    /// it. The padding bits stay zero: they were zero on every measured
    /// reference volume and remain unmanaged here.
    pub fn write_back(&self, volume: &mut dyn Volume) -> Result<()> {
        volume.write_all_at(self.base_offset, &self.bytes)
    }

    /// The last cluster the bitmap describes.
    fn last_cluster(&self) -> u32 {
        self.cluster_count
            .saturating_add(FIRST_HEAP_CLUSTER.saturating_sub(1))
    }

    /// Byte index and bit index of `cluster`, both checked.
    fn bit_of(&self, cluster: u32) -> Result<(usize, u8)> {
        if !(FIRST_HEAP_CLUSTER..=self.last_cluster()).contains(&cluster) {
            return Err(CoreError::invalid(format!(
                "cluster {cluster} is not a heap cluster of this volume (2..={} are)",
                self.last_cluster()
            )));
        }
        let bit = u64::from(cluster - FIRST_HEAP_CLUSTER);
        let index = usize::try_from(bit / 8)
            .map_err(|_| CoreError::invalid(format!("cluster {cluster} does not fit memory")))?;
        let within = u8::try_from(bit % 8).unwrap_or(0);
        Ok((index, within))
    }

    /// Set or clear one bit, checked against the byte vector.
    fn set_bit(&mut self, index: usize, bit: u8, value: bool) -> Result<()> {
        let Some(byte) = self.bytes.get_mut(index) else {
            return Err(CoreError::invalid(format!(
                "the bitmap has no byte {index} for that cluster"
            )));
        };
        if value {
            *byte |= u8::from(bit < 8) << bit;
        } else {
            *byte &= !(1_u8 << bit);
        }
        Ok(())
    }
}

/// The free-ness of one bit: bit *bit* of `byte`, LSB first.
fn is_free_bit(byte: u8, bit: u8) -> bool {
    byte & (1_u8 << bit) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::exfat::format::FormatOptions;
    use crate::fs::exfat::format::format as exfat_format;
    use crate::fs::exfat::geometry::Geometry;

    const MIB: u64 = 1024 * 1024;

    /// A bitmap built directly from bytes for bit-level tests — the
    /// constructor the volume path never uses.
    fn bitmap_from(cluster_count: u32, bytes: Vec<u8>) -> Bitmap {
        Bitmap {
            bytes,
            cluster_count,
            first_cluster: FIRST_HEAP_CLUSTER,
            clusters: 1,
            base_offset: 0,
        }
    }

    #[test]
    fn bit_zero_of_the_first_byte_is_cluster_two() {
        // Bit order within a byte, the layout the measured mkfs
        // volumes pin: bit i = cluster i+2, LSB first.
        // 12 heap clusters (2..=13) so the 4-run at 10..=13 fits.
        let mut bitmap = bitmap_from(12, vec![0; 2]);
        bitmap.mark(1, FIRST_HEAP_CLUSTER).expect("cluster 2 marks");
        assert_eq!(bitmap.bytes.first().copied(), Some(0x01));
        bitmap.mark(1, 9).expect("cluster 9 marks");
        // Cluster 9 is bit 7 of byte 0.
        assert_eq!(bitmap.bytes.first().copied(), Some(0x81));
        bitmap.mark(4, 10).expect("clusters 10..=13 mark");
        assert_eq!(
            bitmap.bytes.get(1).copied(),
            Some(0x0F),
            "bit 0 of byte 1 is cluster 10"
        );
    }

    #[test]
    fn the_fresh_volume_bitmap_matches_the_measured_shape() {
        // A 64 MiB volume formatted by this crate (part A's writer):
        // clusters 2..=5 are the system clusters, so byte 0 reads 0x0F
        // — the same value the mkfs-measured image carries, and the
        // same byte part A's own test pins.
        let mut volume = VecVolume::new(64 * MIB, 512).expect("ram");
        let geometry = exfat_format(&mut volume, &FormatOptions::new(7)).expect("formats");
        let bitmap = Bitmap::load(
            &volume,
            geometry.bitmap_cluster,
            geometry.bitmap_clusters,
            geometry.cluster_bytes as u32,
            geometry.cluster_count,
            geometry
                .cluster_offset(geometry.bitmap_cluster)
                .expect("offset"),
        )
        .expect("loads");
        assert_eq!(
            bitmap.bytes().first().copied(),
            Some(0x0F),
            "clusters 2..=5 are the system clusters"
        );
        assert_eq!(bitmap.free_clusters(), geometry.cluster_count - 4);
    }

    #[test]
    fn a_run_search_crosses_byte_boundaries_forward_only() {
        // Clusters 2..=5 in use (byte 0 bits 0..=3 = 0x0F) and clusters
        // 14,15 in use (byte 1 bits 4..=5 = 0x30). Free: a long run
        // 6..=13 across the byte boundary, then a short run 16..=17.
        let bytes = vec![0x0F, 0x30];
        let bitmap = bitmap_from(16, bytes);
        assert_eq!(
            bitmap.first_fit(5).expect("search"),
            Some(6),
            "clusters 6..=10 fit, crossing the byte boundary"
        );
        assert_eq!(
            bitmap.first_fit(8).expect("search"),
            Some(6),
            "the long run is exactly clusters 6..=13"
        );
        // A run of 9 needs the wrap the format forbids: the long run
        // holds 8 and the tail holds 2 — refused with None, never
        // by splicing the two together.
        assert_eq!(bitmap.first_fit(9).expect("search"), None);
    }

    #[test]
    fn the_partial_last_byte_limits_the_search() {
        // 11 clusters: bits 0..=10 are meaningful (clusters 2..=12),
        // bits 11..=15 of byte 1 are padding this code never uses.
        // Clusters 2,3 (byte 0 bits 0,1) and the whole meaningful
        // tail — 10,11,12 (byte 1 bits 0..=2) — are in use.
        let bitmap = bitmap_from(11, vec![0x03, 0x07]);
        assert_eq!(bitmap.free_clusters(), 6, "5 in use of 11, padding ignored");
        // The first free cluster is bit 2 of byte 0 = cluster 4.
        assert_eq!(bitmap.first_fit(1).expect("search"), Some(4));
        // Byte 0's free tail holds clusters 4..=9: exactly 6.
        assert_eq!(bitmap.first_fit(6).expect("search"), Some(4));
        // A run of 7 does not exist: the free tail is 6 long and the
        // meaningful tail bits are all taken — the padding bits
        // (clusters 13..=17's space) never satisfy a search.
        assert_eq!(bitmap.first_fit(7).expect("search"), None);
        // The last heap cluster (12) can still be marked and freed;
        // cluster 13 is beyond the heap and refused however free the
        // byte looks.
        let mut bitmap = bitmap_from(11, vec![0x03, 0x07]);
        bitmap.clear(1, 12).expect("the last cluster clears");
        bitmap.mark(1, 12).expect("the last cluster marks");
        let error = bitmap.mark(1, 13).expect_err("beyond the heap");
        assert!(error.to_string().contains("13"), "{error}");
        bitmap.clear(1, 12).expect("the last cluster clears");
        let error = bitmap.clear(1, 13).expect_err("beyond the heap");
        assert!(error.to_string().contains("13"), "{error}");
    }

    #[test]
    fn a_run_that_would_cross_the_heap_end_is_refused() {
        // The heap here holds clusters 2..=11; runs reaching past it
        // refuse with the out-of-range cluster named.
        let mut bitmap = bitmap_from(10, vec![0, 0]);
        bitmap.mark(2, 10).expect("clusters 10,11 mark");
        // Free the tail cluster so that a run starting at 11 looks
        // possible until its second step runs past the heap.
        bitmap.clear(1, 11).expect("cluster 11 clears");
        let error = bitmap.mark(2, 11).expect_err("a run to 12 refuses");
        assert!(error.to_string().contains("12"), "{error}");
        bitmap.mark(1, 11).expect("cluster 11 marks");
        let error = bitmap.clear(2, 11).expect_err("a clear to 12 refuses");
        assert!(error.to_string().contains("12"), "{error}");
        // The refusal validates the whole run before touching a bit, so
        // the lead cluster is still in use afterwards.
        assert!(
            !bitmap.is_free(11).expect("cluster 11 is in range"),
            "a refused run must not have cleared its first cluster"
        );
        // Clusters 0 and 1 are reserved and never touch the bitmap.
        let error = bitmap.mark(1, 1).expect_err("cluster 1 refuses");
        assert!(error.to_string().contains("cluster 1"), "{error}");
        assert!(bitmap.is_free(1).is_err());
        assert!(bitmap.is_free(0).is_err());
    }

    #[test]
    fn marking_already_used_or_clearing_already_free_clusters_refuses() {
        let mut bitmap = bitmap_from(10, vec![0x01, 0]);
        let error = bitmap
            .mark(1, FIRST_HEAP_CLUSTER)
            .expect_err("cluster 2 in use");
        assert!(error.to_string().contains("already in use"), "{error}");
        assert!(bitmap.mark(2, 5).is_ok(), "clusters 5,6 are still free");
        let error = bitmap.clear(1, 4).expect_err("clearing free cluster 4");
        assert!(error.to_string().contains("already free"), "{error}");
        bitmap
            .clear(1, FIRST_HEAP_CLUSTER)
            .expect("clearing in-use cluster 2");
        // Clusters 5 and 6 stay marked: 10 - 2 = 8 free.
        assert_eq!(
            bitmap.free_clusters(),
            8,
            "only the two cleared clusters are free again"
        );
    }

    #[test]
    fn free_clusters_counts_only_meaningful_bits() {
        // The padding bits (beyond cluster_count) must not inflate the
        // count even if they are set.
        let bitmap = bitmap_from(10, vec![0, 0xFF]);
        // Clusters 2..=9 are byte 0 (free); byte 1 bits 0..=1 are
        // clusters 10,11 (marked), bits 2..=7 are padding → ignored.
        assert_eq!(bitmap.free_clusters(), 8);
        let bitmap = bitmap_from(8, vec![0xFF]);
        assert_eq!(bitmap.free_clusters(), 0);
    }

    #[test]
    fn zero_and_oversized_runs_refuse_with_their_numbers() {
        let mut bitmap = bitmap_from(10, vec![0, 0]);
        let error = bitmap.first_fit(0).expect_err("zero run");
        assert!(
            error.to_string().contains("at least one cluster"),
            "{error}"
        );
        let error = bitmap.mark(0, 2).expect_err("zero mark");
        assert!(error.to_string().contains("zero"), "{error}");
        let error = bitmap.clear(0, 2).expect_err("zero clear");
        assert!(error.to_string().contains("zero"), "{error}");
        let error = bitmap.first_fit(11).expect_err("longer than the heap");
        assert!(
            error.to_string().contains("longer than the heap"),
            "{error}"
        );
    }

    #[test]
    fn a_marked_run_round_trips_through_the_volume() {
        // The write path: format a real 64 MiB volume, load, mark two
        // fresh clusters, write back — the raw volume bytes must then
        // carry the two extra bits exactly where the bit order says.
        let mut volume = VecVolume::new(64 * MIB, 512).expect("ram");
        let geometry = exfat_format(&mut volume, &FormatOptions::new(8)).expect("formats");
        let mut bitmap = Bitmap::load(
            &volume,
            geometry.bitmap_cluster,
            geometry.bitmap_clusters,
            geometry.cluster_bytes as u32,
            geometry.cluster_count,
            geometry
                .cluster_offset(geometry.bitmap_cluster)
                .expect("offset"),
        )
        .expect("loads");
        bitmap.mark(2, 6).expect("clusters 6,7 mark");
        assert_eq!(bitmap.free_clusters(), geometry.cluster_count - 6);
        bitmap.write_back(&mut volume).expect("writes");
        // Read the raw volume bytes back and check the bit shape.
        let at = geometry
            .cluster_offset(geometry.bitmap_cluster)
            .expect("offset");
        let mut raw = vec![0_u8; bitmap.bytes().len()];
        volume.read_exact_at(at, &mut raw).expect("reads");
        assert_eq!(
            raw.first().copied(),
            Some(0x3F),
            "0x0F for the system clusters + bits 4,5 = clusters 6,7"
        );
        // A clear restores the measured shape exactly.
        bitmap.clear(2, 6).expect("clusters 6,7 clear");
        bitmap.write_back(&mut volume).expect("writes");
        volume.read_exact_at(at, &mut raw).expect("reads");
        assert_eq!(
            raw.first().copied(),
            Some(0x0F),
            "the measured fresh shape is back"
        );
    }

    #[test]
    fn a_loaded_bitmap_refuses_a_stream_too_small_or_a_short_read() {
        // 5 clusters of bytes at 4 bytes per cluster-sized stream: the
        // 64 MiB geometry's real numbers matter nothing here; what is
        // being refused is ceil(count/8) > stream bytes.
        let geometry = Geometry::resolve(64 * MIB, 512, None).expect("resolves");
        let volume = VecVolume::new(64 * MIB, 512).expect("ram");
        let error = Bitmap::load(
            &volume,
            geometry.bitmap_cluster,
            /* clusters = */ 0,
            /* cluster_bytes = */ 1,
            geometry.cluster_count,
            0,
        )
        .expect_err("no stream bytes");
        assert!(error.to_string().contains("cannot fit"), "{error}");
    }
}
