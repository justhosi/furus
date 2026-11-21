use super::*;
use crate::fs::exfat::format;

impl<V: Volume> Exfat<V> {
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
    /// A following flush() recomputes the PercentInUse byte when it
    /// still says unknown (0xff) — the value set_label itself never
    /// touches.
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
    pub(super) fn walk(&self, components: &[String]) -> Result<Vec<Level>> {
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
    pub(super) fn root_level(&self) -> Result<Level> {
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
pub(super) fn read_whole(volume: &dyn Volume, at: u64, len: u32, what: &str) -> Result<Vec<u8>> {
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
pub(super) fn slot_image(
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
