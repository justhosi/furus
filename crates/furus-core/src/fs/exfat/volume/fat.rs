use super::*;

impl<V: Volume> Exfat<V> {
    /// Free bytes available for new files: the cached free-cluster
    /// count times the cluster size. The count is exact — every
    /// allocation decrements it in the same step that marks the
    /// bitmap, and `open` counted it from the bit image itself.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        u64::from(self.free_clusters).saturating_mul(self.geometry.cluster_bytes())
    }

    /// Patch byte 112 of the main and backup boot sectors with
    /// `percent`, skipping the write entirely when the byte already
    /// carries it (mounts leave the value stale; churning writes on
    /// every flush would otherwise touch the boot region for nothing).
    pub(super) fn patch_percent_in_use(&mut self, percent: u8) -> Result<()> {
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

    /// Claim `count` contiguous clusters from the bitmap: first fit,
    /// mark, count update. Every refusal names the numbers and happens
    /// *before* any bit is marked.
    pub(super) fn allocate(&mut self, count: u32, what: &str) -> Result<u32> {
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
    pub(super) fn release(&mut self, count: u32, first_cluster: u32) -> Result<()> {
        self.bitmap.clear(count, first_cluster)?;
        self.free_clusters = self.free_clusters.saturating_add(count);
        Ok(())
    }

    /// Read whole clusters into one byte vector, in chain order.
    pub(super) fn read_clusters(&self, chain: &[u32]) -> Result<Vec<u8>> {
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
    pub(super) fn fat_entry(&self, cluster: u32) -> Result<u32> {
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
    pub(super) fn set_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
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
    pub(super) fn set_fat_entry_ledgered(
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
    pub(super) fn snapshot(&self) -> Snapshot {
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
    pub(super) fn restore(&mut self, snapshot: Snapshot) -> Result<()> {
        for (cluster, previous) in snapshot.fat_writes.iter().rev() {
            self.set_fat_entry(*cluster, *previous)?;
        }
        self.bitmap.replace_bits(snapshot.bitmap);
        self.free_clusters = snapshot.free_clusters;
        self.bitmap_dirty = snapshot.dirty;
        Ok(())
    }

    /// The in-place flavour of [`Exfat::allocate`]: `count` *specific*
    /// clusters (an allocation run's surveyed free neighbours) instead
    /// of a first-fit scan. The caller validated the whole run free
    /// and inside the heap; the bitmap's own `mark` refuses otherwise,
    /// so the cached free count never drifts from the bit image.
    pub(super) fn allocate_in_place(&mut self, count: u32, cluster: u32) -> Result<()> {
        self.bitmap.mark(count, cluster)?;
        self.free_clusters = self.free_clusters.checked_sub(count).ok_or_else(|| {
            CoreError::invalid(format!(
                "marking {count} neighbouring clusters would go negative"
            ))
        })?;
        self.bitmap_dirty = true;
        Ok(())
    }
}
