//! The live FAT32 volume type (S09 part B) — the file API over the
//! formatter substrate from part A: [`Fat32::format`] and
//! [`Fat32::open`] build (or adopt) a volume, and every operation the
//! PLAN's S09 deliverables name is a method on it: `mkdir`,
//! `create_file`, `write_at`, `read_file`, `list_dir`,
//! `allocate_contiguous`, `link_file`, `set_times`, `set_label`,
//! `free_bytes`, `flush` and the `set_now` clock hatch tests inject.
//!
//! Design notes, the ones the implementations below lean on:
//!
//! * **One allocation discipline.** Every cluster allocation goes
//!   through [`Fat32::allocate_contiguous`], a first-fit scanner that
//!   starts at the FSInfo next-free hint, wraps to the volume start
//!   once, and returns *contiguous* runs. Contiguity is a hard
//!   requirement of Syslinux's stage file (S19 lays `ldlinux` down
//!   through this API), so `create_file` never trades it for
//!   cluster-at-a-time allocation.
//! * **The FAT journal.** FAT entry writes settle in the
//!   [`fat::FatDelta`] journal and reach *both* FAT copies when
//!   [`Fat32::flush`] runs — chunked exactly like
//!   [`format`](crate::fs::fat32::format) writes its images. Every FAT
//!   read overlays the journal, so in-memory state is the current truth
//!   and no two allocations inside one flush window can ever claim the
//!   same clusters. Directory and file content are written straight
//!   through the store; a caller that cares about crash consistency
//!   flushes at the end of its write pass. The fsck acceptance of this
//!   slice runs on a flushed image, and the pipeline that will call this
//!   API (S17) is where the flush belongs in production.
//! * **Names.** [`bpb`](crate::fs::fat32::bpb) keeps the volume-label
//!   rules; [`dirent`] keeps the file-name rules ([`dirent::validate_name`])
//!   and the 8.3 rendering with the `~n` collision tails. Lookups are
//!   case-insensitive; entries are created as given — the LFN run
//!   stores the caller's case, the short field is always uppercase.
//! * **Paths.** Component paths name directories and leaves with
//!   `/` separators; an optional single leading slash is tolerated (the
//!   spelling this slice's acceptance tests use), a trailing
//!   slash or any empty component refuses, and `.`/`..` are generated
//!   entry linkage, never user paths.
//! * **Timestamps.** `create_file` and `mkdir` stamp the volume's
//!   "now" — an injectable clock ([`Fat32::set_now`]) defaulting to the
//!   DOS epoch so tests stay deterministic; a later slice's pipeline
//!   passes the real time through the same seam. `write_at` deliberately never
//!   touches timestamps.
//! * **No panics anywhere.** All cluster and byte math goes through
//!   checked or saturating helpers reporting [`CoreError::invalid`]; a
//!   hostile path string or a corrupt FAT table only produces errors,
//!   never a dereference of cluster 1 or an out-of-window write.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::bpb;
use crate::fs::fat32::dirent;
use crate::fs::fat32::dirent::ENTRY_LEN;
use crate::fs::fat32::dirent::FatTime;
use crate::fs::fat32::dirent::SHORT_NAME_LEN;
use crate::fs::fat32::fat;
use crate::fs::fat32::fat::FatDelta;
use crate::fs::fat32::format::FormatOptions;
use crate::fs::fat32::geometry::BACKUP_BOOT_SECTOR;
use crate::fs::fat32::geometry::Geometry;
use crate::fs::fat32::geometry::ROOT_CLUSTER;

/// The largest cluster this formatter writes: 64 KiB (the large-FAT32
/// tier). The directory windows below are stack buffers of this size;
/// `parse_boot_sector` refuses bigger claims, so the buffer always
/// holds a whole cluster of any volume this crate accepts.
const DIR_CLUSTER_BYTES: usize = 64 * 1024;

/// The offsets of the two FSInfo count fields inside the 512-byte
/// structure: free-cluster count (488) and next-free hint (492).
const FSINFO_FREE_AT: usize = 488;
const FSINFO_NEXT_AT: usize = 492;

/// Most LFN pieces a reassembly run may hold before it is treated as
/// corrupt (the same cap [`dirent`] enforces inside the reassembler):
/// the scan's pending buffer stays bounded by it for a hostile image.
const LFN_PIECE_CAP: usize = 20;

/// Most numeric tails a 8.3 collision search burns before it refuses:
/// `~999999` is the 6-digit end of the base's own budget.
const SFN_TAIL_LIMIT: u32 = 999_999;

/// The user-visible entry summary [`Fat32::list_dir`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// Display name: the reassembled long name when the entry carries
    /// an LFN run, the short name otherwise.
    pub name: String,
    /// The 8.3 short name as user text (uppercase, dot-joined).
    pub short_name: String,
    /// Directory flag.
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size_bytes: u64,
    /// First cluster of the content chain (0 for an empty file).
    pub first_cluster: u32,
    /// The entry's write timestamp pair.
    pub times: FatTime,
}

/// One 32-byte slot position: the cluster number and the slot index
/// inside its cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotPos {
    cluster: u32,
    index: u32,
}

/// One reserved slot run inside a directory: a start position and how
/// many consecutive slots the reservation spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotRun {
    start: SlotPos,
    count: u32,
}

/// One existing entry collected while planning a new one: the short
/// field (the collision key, compared byte-for-byte — short fields are
/// stored uppercase, so equality is inherently case-insensitive) and
/// the display name (the duplicate key).
#[derive(Debug, Clone)]
struct Existing {
    short: [u8; SHORT_NAME_LEN],
    display: String,
}

/// The planned shape of one new entry: the 8.3 render chosen against
/// the directory's colliders, its 11-byte field, and the name's UTF-16
/// pieces (when the name loses information in the short form, the
/// pieces carry the LFN run).
struct PlannedEntry {
    field: [u8; SHORT_NAME_LEN],
    units: Vec<u16>,
    piece_count: usize,
}

/// One real entry discovered by a directory walk.
#[derive(Debug, Clone)]
struct WalkEntry {
    slot: SlotPos,
    short: [u8; SHORT_NAME_LEN],
    display: String,
    is_label: bool,
    is_dir: bool,
    first_cluster: u32,
    size_bytes: u64,
    write_times: FatTime,
}

/// One lookup hit for the mutators: the 32-byte slot, the flags, the
/// chain head and the size.
#[derive(Debug, Clone)]
struct DirHit {
    slot: SlotPos,
    is_dir: bool,
    first_cluster: u32,
    size_bytes: u64,
}

/// The allocation state of one create-path call before it runs: the
/// FAT journal (every entry it would otherwise leak), the cached
/// free-cluster count and next-free hint, and their dirty flag. See
/// [`Fat32::allocation_snapshot`] for the contract.
struct AllocationSnapshot {
    journal: FatDelta,
    free_clusters: u32,
    next_free: u32,
    fsinfo_dirty: bool,
}

/// The live volume: a [`Volume`], the geometry parsed (or derived) for
/// it, the FSInfo bookkeeping, the FAT journal and the "now" clock.
/// Nothing here is shared state — one [`Fat32`] owns its [`Volume`] for
/// its whole life, exactly like the formatter's pass does.
pub struct Fat32 {
    volume: Box<dyn Volume>,
    geometry: Geometry,
    /// FSInfo sector the BPB points at (`None`: the structure is not
    /// in use, the counts stay recount-driven only).
    fsinfo_sector: Option<u32>,
    /// Cached free-cluster count — always a *counted* reality, never
    /// the "unknown" marker.
    free_clusters: u32,
    /// Cached FSInfo next-free hint (`u32::MAX` = unknown; the
    /// allocator starts its scan at cluster 2 then).
    next_free: u32,
    /// FAT entries written since the last flush, journaled until the
    /// flush materializes them into both copies.
    journal: FatDelta,
    /// The FSInfo counts changed since the last flush.
    fsinfo_dirty: bool,
    /// The stamp new entries carry (see the module docs on the clock).
    now: FatTime,
}

impl Fat32 {
    /// Format a whole FAT32 volume onto `volume` and hand its live API
    /// back.
    ///
    /// The volume content is built by [`format`](crate::fs::fat32::format)'s
    /// own writer (superblocks, both FATs, the root cluster and the
    /// label entry) — this type then takes over the FSInfo accounting:
    /// the fresh counts are known by construction (everything except
    /// the root cluster is free), so they are derived here and the
    /// first [`flush`](Fat32::flush) publishes them over the formatter's
    /// "unknown" FSInfo. The same refusals as the free function apply
    /// (a `0` volume id, a drifted store, an oversized volume).
    pub fn format(mut volume: Box<dyn Volume>, options: &FormatOptions<'_>) -> Result<Self> {
        let geometry = crate::fs::fat32::format::format(volume.as_mut(), options)?;
        Self::load(volume, geometry, true)
    }

    /// Adopt an already-formatted volume: the boot sector is parsed
    /// back with [`bpb::parse_boot_sector`] and the FSInfo counts are
    /// read.
    ///
    /// Unknown (`0xFFFF_FFFF`) counts — the formatter's own fresh-image
    /// shape, and every driver's honest ignorance — trigger a full FAT
    /// recount: one pass over the first FAT copy, 4 bytes per data
    /// cluster. That is the documented cost of never trusting an
    /// unstated count: a 64 MiB volume costs 129,022 reads inside 13
    /// bounded window reads, a 2 TiB one 33.5 million. Counts beyond
    /// the cluster count count as unknown for the same reason.
    ///
    /// The store must be at least as large as its BPB claims: a volume
    /// smaller than its mapped sectors is refused naming both numbers.
    pub fn open(volume: Box<dyn Volume>) -> Result<Self> {
        let geometry = {
            let mut boot = [0u8; bpb::BOOT_SECTOR_BYTES];
            volume.read_exact_at(0, &mut boot)?;
            let total = volume.total_bytes();
            bpb::parse_boot_sector(&boot, total)?
        };
        let mapped = u64::from(geometry.total_sectors) * u64::from(geometry.bytes_per_sector);
        if mapped > volume.total_bytes() {
            return Err(CoreError::invalid(format!(
                "the boot sector maps {mapped} bytes but the volume reports {}",
                volume.total_bytes()
            )));
        }
        Self::load(volume, geometry, false)
    }

    /// Load the live state over a parsed geometry. `fresh` marks a
    /// volume formatted by this very call: the counts are derived
    /// analytically instead of recounted.
    fn load(volume: Box<dyn Volume>, geometry: Geometry, fresh: bool) -> Result<Self> {
        let volume = volume;
        let sector = u64::from(geometry.bytes_per_sector);
        let mut boot = [0u8; bpb::BOOT_SECTOR_BYTES];
        volume.read_exact_at(0, &mut boot)?;
        let fsinfo_ptr = u32::from(le_u16(&boot, 48));
        let fsinfo_sector = if fsinfo_ptr >= 1 && fsinfo_ptr < geometry.reserved_sectors {
            Some(fsinfo_ptr)
        } else {
            None
        };
        let mut this = Self {
            volume,
            geometry,
            fsinfo_sector,
            free_clusters: 0,
            next_free: u32::MAX,
            journal: FatDelta::default(),
            fsinfo_dirty: false,
            now: FatTime::default(),
        };
        // The disk's reading of the counts (the "unknown" pair on a
        // fresh image): kept to decide the dirty flag with the truth in
        // the loop below.
        let mut disk_free = u32::MAX;
        let mut disk_next = u32::MAX;
        if let Some(fsinfo_at) = fsinfo_sector {
            let mut image = [0u8; bpb::BOOT_SECTOR_BYTES];
            this.volume
                .read_exact_at(u64::from(fsinfo_at) * sector, &mut image)?;
            let signature_ok = image.get(..4) == Some(b"RRaA".as_slice())
                && image.get(484..488) == Some([0x72, 0x72, 0x41, 0x61].as_slice());
            if signature_ok {
                disk_free = le_u32(&image, FSINFO_FREE_AT);
                disk_next = le_u32(&image, FSINFO_NEXT_AT);
            }
        }
        if fresh {
            // A just-formatted volume: exactly the root cluster is
            // allocated, so the counts are derived, not scanned.
            this.free_clusters = this.geometry.cluster_count.checked_sub(1).ok_or_else(|| {
                CoreError::invalid("a volume without any data cluster is unusable")
            })?;
            this.next_free = ROOT_CLUSTER.saturating_add(1);
        } else {
            let plausible = disk_free != u32::MAX
                && disk_free <= this.geometry.cluster_count
                && this.is_free_hint_plausible(disk_free, disk_next);
            if plausible {
                this.free_clusters = disk_free;
                this.next_free = disk_next;
            } else {
                // Unknown or implausible counts: recount by scanning
                // the first FAT copy (the cost `open` documents).
                let (free, next) = fat::recount(&*this.volume, &this.geometry, &this.journal)?;
                this.free_clusters = free;
                this.next_free = next;
            }
        }
        // Publish counts over whatever the FSInfo said: dirty when (and
        // only when) the resolution differs from the disk.
        this.fsinfo_dirty = disk_free != this.free_clusters || disk_next != this.next_free;
        Ok(this)
    }

    /// Whether `next_free` may serve the allocator as the scan hint.
    /// The unknown marker is always legal; a stale-but-in-range hint is
    /// tolerated (a hint names no truth, it only speeds a scan).
    fn is_free_hint_plausible(&self, free: u32, next: u32) -> bool {
        if next == u32::MAX {
            return true; // the honest "unknown" hint
        }
        if free == 0 {
            return true; // a full volume carries no meaningful hint
        }
        let last = self.geometry.cluster_count.saturating_add(1);
        (ROOT_CLUSTER..=last).contains(&next)
    }

    /// The geometry this volume was parsed (or formatted) for.
    #[must_use]
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Free bytes available for new files: the cached free-cluster
    /// count times the cluster size. The count is exact: every
    /// allocation decrements it in the same step that writes the FAT
    /// journal, and `open` recounts whenever it met unknown counts.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        u64::from(self.free_clusters).saturating_mul(self.geometry.cluster_bytes())
    }

    /// Set the stamp `create_file`/`mkdir` carry into their new
    /// entries. Tests inject a fixed value; a caller writing real files
    /// passes the wall clock through the same seam
    /// ([`FatTime::from_ymdhms`] is the constructor). Existing entries
    /// change through [`Fat32::set_times`] only.
    pub fn set_now(&mut self, times: FatTime) {
        self.now = times;
    }

    /// Make everything durable: materialize the FAT journal into both
    /// FAT copies (chunked like the formatter writes its images) and
    /// publish the FSInfo counts — each *only* when it changed since
    /// the last flush — then ask the store to flush itself.
    pub fn flush(&mut self) -> Result<()> {
        if self.journal.is_dirty() {
            // Field-split borrows: the journal is one field, the store
            // another; both reach `flush_delta` together.
            let journal = &mut self.journal;
            let geometry = &self.geometry;
            let volume: &mut dyn Volume = self.volume.as_mut();
            fat::flush_delta(volume, geometry, journal)?;
        }
        if self.fsinfo_dirty {
            self.write_fsinfo()?;
        }
        self.volume.flush()?;
        Ok(())
    }

    /// Write the FSInfo structure — primary and the spec-mirrored
    /// backup `pointer + 6` sectors later — with the current counts.
    fn write_fsinfo(&mut self) -> Result<()> {
        let Some(sector) = self.fsinfo_sector else {
            return Ok(()); // no FSInfo pointer in the BPB: nothing to publish
        };
        let image = bpb::fsinfo_with_counts(self.free_clusters, self.next_free);
        let bps = u64::from(self.geometry.bytes_per_sector);
        let backup = sector.saturating_add(6);
        if backup < self.geometry.reserved_sectors {
            self.volume.write_all_at(u64::from(backup) * bps, &image)?;
        }
        self.volume.write_all_at(u64::from(sector) * bps, &image)?;
        self.fsinfo_dirty = false;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Labels
    // ------------------------------------------------------------------

    /// Set (change, or remove) the volume label: the BPB's label window
    /// and the root-directory entry are kept byte-identical —
    /// [`None`] removes the entry and writes the `NO NAME    ` field.
    ///
    /// Labels longer than 11 bytes crop to the field's width; control
    /// bytes, non-ASCII bytes and Windows-forbidden characters refuse
    /// exactly like [`bpb`]'s own label rules (the single source). An
    /// empty or all-whitespace label means removal.
    pub fn set_label(&mut self, label: Option<&str>) -> Result<()> {
        let field = match label {
            None => None,
            Some(text) => {
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(Self::label_field_for(trimmed)?)
                }
            }
        };
        self.patch_boot_label(field)?;
        self.sync_root_label_entry(field)?;
        Ok(())
    }

    /// The 11-byte label field: [`bpb`]'s rules on the whole text, with
    /// one concession — when the *only* complaint is the length, the
    /// crop to 11 bytes is re-validated with the same rules (cropping
    /// is this part of the slice's call, per the brief).
    fn label_field_for(label: &str) -> Result<[u8; 11]> {
        match bpb::label_field(Some(label)) {
            Ok(field) => Ok(field),
            Err(error) => {
                let too_long = label.len() > 11;
                let first_11_ascii = label
                    .as_bytes()
                    .get(..11)
                    .map(|bytes| bytes.iter().all(u8::is_ascii))
                    .unwrap_or(false);
                if too_long && first_11_ascii {
                    let Some(window) = label.as_bytes().get(..11) else {
                        return Err(error);
                    };
                    let cropped = String::from_utf8(window.to_vec()).unwrap_or_default();
                    if cropped.len() == 11 {
                        return bpb::label_field(Some(&cropped));
                    }
                }
                Err(error)
            }
        }
    }

    /// Patch the 11 label bytes of the boot sector — and, when the BPB
    /// points the backup somewhere real, of that mirror — keeping the
    /// two copies byte-identical outside the patched window.
    fn patch_boot_label(&mut self, field: Option<[u8; 11]>) -> Result<()> {
        let bytes = field.unwrap_or(bpb::NO_NAME_LABEL);
        let bps = u64::from(self.geometry.bytes_per_sector);
        let mut boot = [0u8; bpb::BOOT_SECTOR_BYTES];
        self.volume.read_exact_at(0, &mut boot)?;
        let backup_ptr = u32::from(le_u16(&boot, 50));
        if let Some(window) = boot.get_mut(71..82) {
            window.copy_from_slice(&bytes);
        }
        self.volume.write_all_at(0, &boot)?;
        if backup_ptr >= 1 && backup_ptr < self.geometry.reserved_sectors {
            let mut mirror = [0u8; bpb::BOOT_SECTOR_BYTES];
            self.volume
                .read_exact_at(u64::from(backup_ptr) * bps, &mut mirror)?;
            if let Some(window) = mirror.get_mut(71..82) {
                window.copy_from_slice(&bytes);
            }
            self.volume
                .write_all_at(u64::from(backup_ptr) * bps, &mirror)?;
        }
        Ok(())
    }

    /// Insert (overwrite, or remove) the root volume-label entry, and
    /// clear any duplicate label entries found along the way. The
    /// entry's timestamps stay *zero* — byte-identical to the
    /// formatter's label entry, which carries no stamp at all
    /// ([`FatTime::default`] is the DOS epoch, not zero, so it is
    /// deliberately not used here).
    fn sync_root_label_entry(&mut self, field: Option<[u8; 11]>) -> Result<()> {
        let root = self.geometry.root_cluster;
        let mut label_slots = Vec::new();
        self.walk_dir_entries(root, &mut |entry| {
            if entry.is_label {
                label_slots.push(entry.slot);
            }
            Ok(false)
        })?;
        if let Some(field) = field {
            let image = dirent::entry_image(
                &field,
                dirent::ATTR_VOLUME_ID,
                0,
                0,
                FatTime { date: 0, time: 0 },
            );
            match label_slots.first() {
                Some(&slot) => self.write_slot(slot, &image)?,
                None => {
                    let run = self.find_free_slot_run(root, 1)?.ok_or_else(|| {
                        CoreError::invalid(
                            "the root directory holds no free slot for the label entry",
                        )
                    })?;
                    self.write_slot(run.start, &image)?;
                }
            }
        }
        // Duplicates and removal: any label entry beyond the first (or
        // all, when no label remains) is struck out.
        let keep = usize::from(field.is_some());
        for &slot in label_slots.iter().skip(keep) {
            self.write_slot(slot, &deleted_slot_image())?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Boot code
    // ------------------------------------------------------------------

    /// Graft a Syslinux VBR's boot code onto this volume's boot sector,
    /// primary and backup.
    ///
    /// Reads sector 0 and writes the 512 grafted bytes back at offset 0
    /// ([`bpb::graft_boot_code`]): the VBR's `0..11` jump/OEM entry, the
    /// volume's own `11..90` BPB/EBPB geometry, the VBR's `90..510` boot
    /// code and the volume's `510..512` `0x55AA` signature. The identical
    /// 512 bytes are then written at the BPB's backup pointer (offset 50,
    /// falling back to `BACKUP_BOOT_SECTOR` — reserved sector 6 — when
    /// the field is zero or outside the reserved area (the same field
    /// and rule `patch_boot_label` reads), matching
    /// upstream `WritePBR`'s two-pass loop
    /// (`src/format.c`), which writes the same record at offset 0 and at
    /// `6 * SectorSize`: without the mirror `fsck.fat` reports
    /// differences between the boot sector and its backup, and an
    /// interactive "copy backup to original" would destroy the installed
    /// record. The record itself stays a 512-byte structure whatever the
    /// sector size; only the backup's byte offset scales with the
    /// volume's real sector size. Refuses a VBR shorter than a sector,
    /// naming both lengths. When the backup sector would fall outside
    /// the volume the call refuses before the first write — naming the
    /// sector and the volume size — so nothing is half-applied. The
    /// caller is responsible for the payload being a real Syslinux VBR:
    /// this moves bytes, it never checks them. Does not flush: the
    /// caller flushes after its last write.
    pub fn write_boot_code(&mut self, vbr: &[u8]) -> Result<()> {
        let mut current = [0u8; bpb::BOOT_SECTOR_BYTES];
        self.volume.read_exact_at(0, &mut current)?;
        let grafted = bpb::graft_boot_code(&current, vbr)?;
        // The mirror target is the BPB's own backup pointer (offset 50),
        // the same field `patch_boot_label` reads; a zero or
        // out-of-reserved-area value falls back to `BACKUP_BOOT_SECTOR`
        // (every volume this crate formats carries 6 there, so the two
        // agree on our own images). The backup's byte offset scales with
        // the volume's real sector size; the record itself stays the
        // 512-byte structure above. Validated before the first write so
        // a refusal leaves sector 0 with the formatter's record, never
        // a half-mirrored stick.
        let backup_ptr = u32::from(le_u16(&current, 50));
        let backup_sector = if backup_ptr >= 1 && backup_ptr < self.geometry.reserved_sectors {
            backup_ptr
        } else {
            BACKUP_BOOT_SECTOR
        };
        let backup_offset = u64::from(backup_sector)
            .checked_mul(u64::from(self.geometry.bytes_per_sector))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "fat32 backup boot sector {backup_sector} sits past u64 addressing: refusing"
                ))
            })?;
        let backup_end = backup_offset
            .checked_add(bpb::BOOT_SECTOR_BYTES as u64)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "fat32 backup boot sector {backup_sector} ends past u64 addressing: refusing"
                ))
            })?;
        let total = self.volume.total_bytes();
        if backup_end > total {
            return Err(CoreError::invalid(format!(
                "fat32 backup boot sector {backup_sector} at byte offset {backup_offset} does not fit the {total} byte volume: refusing"
            )));
        }
        self.volume.write_all_at(0, &grafted)?;
        self.volume.write_all_at(backup_offset, &grafted)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Creation: mkdir / create_file / link_file
    // ------------------------------------------------------------------

    /// Create a directory: a fresh zeroed cluster carrying `.` (its own
    /// cluster) and `..` (the parent's, or 0 when the parent is the
    /// root — the FAT32 linkage rule, which a directory directly under
    /// the root therefore carries as 0 too), plus the parent's entry
    /// with the LFN run when the name needs one.
    ///
    /// An existing name (file or directory, case-insensitively) refuses.
    ///
    /// A refused call rolls back: every cluster reserved on the way
    /// (directory growth, the directory's own cluster) returns to the
    /// free ledger (see [`Fat32::allocation_snapshot`]), so the volume
    /// stays fsck-clean and the counts exact.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let (dir_first, leaf) = self.split_leaf(path)?;
        let planned = self.plan_entry(dir_first, leaf)?;
        let snapshot = self.allocation_snapshot();
        let result = self.mkdir_entry(dir_first, &planned);
        if result.is_err() {
            self.restore_allocation(snapshot);
        }
        result
    }

    /// The mutating half of [`Fat32::mkdir`], transaction-shaped: the
    /// caller snapshotted the ledger and restores it if this errs.
    fn mkdir_entry(&mut self, dir_first: u32, planned: &PlannedEntry) -> Result<()> {
        let run = self.reserve_slot_run(dir_first, planned.entry_slots())?;
        // The directory's own cluster: allocated, zeroed, then the
        // linkage dots.
        let (own, _) = self.allocate_contiguous(self.geometry.cluster_bytes())?;
        self.zero_cluster(own)?;
        let parent_cluster = if dir_first == ROOT_CLUSTER {
            0
        } else {
            dir_first
        };
        let dot = dirent::dot_entry_image(&dirent::DOT_FIELD, own, self.now);
        let dotdot = dirent::dot_entry_image(&dirent::DOTDOT_FIELD, parent_cluster, self.now);
        self.write_slot(
            SlotPos {
                cluster: own,
                index: 0,
            },
            &dot,
        )?;
        self.write_slot(
            SlotPos {
                cluster: own,
                index: 1,
            },
            &dotdot,
        )?;
        self.stamp_entry(planned, run, own, 0, true)?;
        Ok(())
    }

    /// Create a file entry of `size_bytes` bytes: the size is claimed
    /// *contiguously* (the Syslinux requirement) in the same call and
    /// the entry's first cluster comes back — `0` for an empty file.
    /// The caller fills the bytes through [`Fat32::write_at`].
    ///
    /// An existing name refuses, case-insensitively. A size beyond the
    /// FAT 32-bit size field refuses, as does one needing more clusters
    /// than the volume has (the shortfall named). A refused call rolls
    /// back: the slot run reserved on the way (including any directory
    /// growth) returns to the free ledger (see
    /// [`Fat32::allocation_snapshot`]), so the volume stays fsck-clean
    /// and the counts exact.
    pub fn create_file(&mut self, path: &str, size_bytes: u64) -> Result<u32> {
        if size_bytes > u64::from(u32::MAX) {
            return Err(CoreError::invalid(format!(
                "file size {size_bytes} exceeds the 32-bit fat32 size field"
            )));
        }
        let (dir_first, leaf) = self.split_leaf(path)?;
        let planned = self.plan_entry(dir_first, leaf)?;
        let snapshot = self.allocation_snapshot();
        let result = self.create_file_entry(dir_first, &planned, size_bytes);
        if result.is_err() {
            self.restore_allocation(snapshot);
        }
        result
    }

    /// The mutating half of [`Fat32::create_file`],
    /// transaction-shaped: the caller snapshotted the ledger and
    /// restores it if this errs.
    fn create_file_entry(
        &mut self,
        dir_first: u32,
        planned: &PlannedEntry,
        size_bytes: u64,
    ) -> Result<u32> {
        let run = self.reserve_slot_run(dir_first, planned.entry_slots())?;
        // The data chain: contiguous, through the one allocator.
        let first = if size_bytes == 0 {
            0
        } else {
            self.allocate_contiguous(size_bytes)?.0
        };
        self.stamp_entry(planned, run, first, size_bytes, false)?;
        Ok(first)
    }

    /// Link a *pre-allocated* run to a new file entry: `allocate_contiguous`
    /// hands out `(first, clusters)`; this call verifies the chain the
    /// allocation promised — `[first, first + clusters)` linked
    /// cluster-by-cluster with the end-of-chain family value at the
    /// last entry — and writes the directory entry, where `clusters`
    /// is exactly what `size_bytes` round up implies.
    ///
    /// Refusals (all naming the numbers): a first cluster below the
    /// data area, one beyond it, a chain whose links do not match the
    /// contiguous promise, a size whose claim does not fit the chain,
    /// and a zero-size link with a non-zero first cluster (and the
    /// reverse: a non-zero size at cluster 0). No FAT entry changes
    /// here — the allocation already accounted for everything. A
    /// refused call rolls back the ledger exactly like
    /// [`Fat32::create_file`] (the slot run it reserved returns to the
    /// free ledger), so the volume stays fsck-clean.
    pub fn link_file(&mut self, path: &str, first_cluster: u32, size_bytes: u64) -> Result<()> {
        if size_bytes > u64::from(u32::MAX) {
            return Err(CoreError::invalid(format!(
                "file size {size_bytes} exceeds the 32-bit fat32 size field"
            )));
        }
        let (dir_first, leaf) = self.split_leaf(path)?;
        let planned = self.plan_entry(dir_first, leaf)?;
        let snapshot = self.allocation_snapshot();
        let result = self.link_file_entry(dir_first, &planned, first_cluster, size_bytes);
        if result.is_err() {
            self.restore_allocation(snapshot);
        }
        result
    }

    /// The mutating half of [`Fat32::link_file`], transaction-shaped:
    /// the caller snapshotted the ledger and restores it if this errs.
    fn link_file_entry(
        &mut self,
        dir_first: u32,
        planned: &PlannedEntry,
        first_cluster: u32,
        size_bytes: u64,
    ) -> Result<()> {
        let run = self.reserve_slot_run(dir_first, planned.entry_slots())?;
        self.verify_preallocated_chain(first_cluster, size_bytes)?;
        self.stamp_entry(planned, run, first_cluster, size_bytes, false)?;
        Ok(())
    }

    /// The chain check behind [`Fat32::link_file`]: `size_bytes` round
    /// up applied to the cluster size must reach exactly an
    /// end-of-chain entry through links `first, first+1, ...`.
    fn verify_preallocated_chain(&self, first_cluster: u32, size_bytes: u64) -> Result<()> {
        let cluster_bytes = self.geometry.cluster_bytes();
        if size_bytes == 0 {
            if first_cluster != 0 {
                return Err(CoreError::invalid(format!(
                    "zero-size link claims first cluster {first_cluster}: an empty file carries none"
                )));
            }
            return Ok(());
        }
        if first_cluster < ROOT_CLUSTER {
            return Err(CoreError::invalid(format!(
                "first cluster {first_cluster} is below the fat32 data clusters (2)"
            )));
        }
        let clusters = size_bytes.div_ceil(cluster_bytes);
        let mut cluster = first_cluster;
        for link in 0..clusters {
            let last = link.saturating_add(1) == clusters;
            let wants = if last {
                "an end-of-chain marker"
            } else {
                "a link to the next cluster"
            };
            let raw = fat::read_entry(&*self.volume, &self.geometry, Some(&self.journal), cluster)?;
            let expected = fat::classify(raw, self.geometry.cluster_count);
            let fits = if last {
                matches!(expected, fat::FatEntry::End)
            } else {
                matches!(expected, fat::FatEntry::Link(next) if next == cluster.saturating_add(1))
            };
            if !fits {
                return Err(CoreError::invalid(format!(
                    "pre-allocated chain mismatch at cluster {cluster}: the fat carries {raw:#010x}, \
                     link {link} of {clusters} needs {wants}"
                )));
            }
            if !last {
                cluster = cluster.saturating_add(1);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Free space
    // ------------------------------------------------------------------

    /// Claim `size_bytes` as a contiguous free cluster run and return
    /// `(first cluster, clusters)`. The scan is first-fit from the
    /// FSInfo next-free hint, wrapping to the volume start once; the
    /// chain marks in the FAT journal and the cached counts move in the
    /// same step, so [`free_bytes`](Fat32::free_bytes) stays exact.
    ///
    /// Refusals (all [`CoreError::invalid`], naming the numbers): a zero
    /// byte claim, a claim whose cluster count alone exceeds the volume,
    /// and a volume that cannot serve the run — the largest free run and
    /// the true free-cluster count (from the completed wrap) appear in
    /// the message.
    pub fn allocate_contiguous(&mut self, size_bytes: u64) -> Result<(u32, u32)> {
        if size_bytes == 0 {
            return Err(CoreError::invalid(
                "an allocation claims space for at least one cluster, size 0 refused",
            ));
        }
        let cluster_bytes = self.geometry.cluster_bytes();
        let count = u32::try_from(size_bytes.div_ceil(cluster_bytes)).map_err(|_| {
            CoreError::invalid(format!(
                "a claim of {size_bytes} bytes needs more clusters than fat32 numbering provides"
            ))
        })?;
        if count > self.geometry.cluster_count {
            return Err(CoreError::invalid(format!(
                "a claim of {size_bytes} bytes needs {count} clusters, the volume provides {}",
                self.geometry.cluster_count
            )));
        }
        let scan = fat::scan_free_run(
            &*self.volume,
            &self.geometry,
            &self.journal,
            self.next_free,
            count,
        )?;
        let Some((first, _)) = scan.run else {
            // The scan wrapped completely: free_seen is the true count,
            // the cache is corrected from it before the refusal.
            self.free_clusters = scan.free_seen;
            self.next_free = scan.first_free.unwrap_or(u32::MAX);
            self.fsinfo_dirty = true;
            return Err(CoreError::invalid(format!(
                "allocation needs {count} contiguous clusters but the largest free run holds {}, \
                 {scan_free} free clusters in total",
                scan.largest_run,
                scan_free = scan.free_seen
            )));
        };
        // The chain: each cluster links to the next, the tail carries
        // the end-of-chain value.
        for offset in 0..count {
            let cluster = first.saturating_add(offset);
            let value = if offset.checked_add(1) == Some(count) {
                fat::EOC
            } else {
                cluster.saturating_add(1)
            };
            self.journal.set(cluster, value);
        }
        self.free_clusters = self.free_clusters.saturating_sub(count);
        let last = self.geometry.cluster_count.saturating_add(1);
        let after = first.saturating_add(count);
        self.next_free = if after <= last { after } else { u32::MAX };
        self.fsinfo_dirty = true;
        Ok((first, count))
    }

    // ------------------------------------------------------------------
    // File content
    // ------------------------------------------------------------------

    /// Write `data` at `offset` inside the file at `path`, walking the
    /// FAT chain per write (no cached cluster map). The write must fit
    /// under `size_bytes` (fixed at create/link time); pieces land
    /// cluster-aligned through the store's exact writes.
    ///
    /// A zero-length write is `Ok(())` without any I/O. Sizes of 0 with
    /// data refuse, directories refuse, and a missing path refuses.
    /// Timestamps are untouched — [`Fat32::set_times`] owns them.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let Some(hit) = self.resolve_entry(path)? else {
            return Err(CoreError::invalid(format!(
                "{path:?} does not exist on the volume, so it cannot be written"
            )));
        };
        if hit.is_dir {
            return Err(CoreError::invalid(format!(
                "{path:?} names a directory, writes need a file"
            )));
        }
        let data_len =
            u64::try_from(data.len()).map_err(|_| CoreError::invalid("a write longer than u64"))?;
        if hit.size_bytes == 0 && !data.is_empty() {
            return Err(CoreError::invalid(format!(
                "file {path:?} has size 0: a write with data needs a real size"
            )));
        }
        if offset
            .checked_add(data_len)
            .ok_or_else(|| CoreError::invalid("a file write offset overflows a u64"))?
            > hit.size_bytes
        {
            return Err(CoreError::invalid(format!(
                "write of {data_len} bytes at offset {offset} runs past the {} byte end of {path:?}",
                hit.size_bytes
            )));
        }
        if data.is_empty() {
            return Ok(()); // the zero-length no-op
        }
        let cluster_bytes = self.geometry.cluster_bytes();
        let write_end = offset + data_len; // checked above
        let mut cluster = hit.first_cluster;
        let mut index = 0_u64;
        let mut steps = 0_u64;
        // The chain walk: every cluster's file window is intersected
        // with the write span; pieces land exactly, cluster-aligned.
        while index
            .checked_mul(cluster_bytes)
            .ok_or_else(|| CoreError::invalid("a file write's cluster window overflows a u64"))?
            < write_end
        {
            steps = steps.saturating_add(1);
            if steps > u64::from(self.geometry.cluster_count) {
                return Err(CoreError::invalid(format!(
                    "the chain of {path:?} runs past every cluster the volume has: corrupt"
                )));
            }
            let span_start = index * cluster_bytes;
            let span_end = span_start.saturating_add(cluster_bytes);
            let piece_lo = span_start.max(offset);
            let piece_hi = span_end.min(write_end);
            if piece_lo < piece_hi {
                let within = piece_lo
                    .checked_sub(span_start)
                    .ok_or_else(|| CoreError::invalid("a write piece lost its window"))?;
                let data_from = piece_lo
                    .checked_sub(offset)
                    .and_then(|delta| usize::try_from(delta).ok())
                    .ok_or_else(|| CoreError::invalid("a write piece lost its own offset"))?;
                let data_to = piece_hi
                    .checked_sub(offset)
                    .and_then(|delta| usize::try_from(delta).ok())
                    .ok_or_else(|| CoreError::invalid("a write piece lost its own end"))?;
                let piece = data
                    .get(data_from..data_to)
                    .ok_or_else(|| CoreError::invalid("a write piece window vanished"))?;
                let piece_offset = self
                    .geometry
                    .cluster_offset(cluster)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "cluster {cluster} does not resolve on this volume"
                        ))
                    })?
                    .checked_add(within)
                    .ok_or_else(|| CoreError::invalid("a write piece overflows its cluster"))?;
                self.volume.write_all_at(piece_offset, piece)?;
            }
            if write_end <= span_end {
                break;
            }
            cluster = self.chain_next(cluster)?.ok_or_else(|| {
                CoreError::invalid(format!(
                    "the chain of {path:?} ended before its {} byte claim (at cluster {index})",
                    hit.size_bytes
                ))
            })?;
            index = index.saturating_add(1);
        }
        Ok(())
    }

    /// Read the whole file at `path` back: the chain is walked first
    /// (bounded, corrupt loops refuse), then each cluster is read
    /// through the store's exact window, appended in chain order.
    ///
    /// Corruption refuses before any byte read: a size whose cluster
    /// count exceeds the volume's own cluster count, a chain that ends
    /// short of the claimed length, and a chain that cycles — a loop
    /// would otherwise read the same clusters twice and return
    /// repetitions dressed as a longer file. The walk's allocation is
    /// capped at the volume's cluster count for the same reason (a
    /// hostile size field can claim millions of clusters).
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let Some(hit) = self.resolve_entry(path)? else {
            return Err(CoreError::invalid(format!(
                "{path:?} does not exist on the volume, so it cannot be read"
            )));
        };
        if hit.is_dir {
            return Err(CoreError::invalid(format!(
                "{path:?} names a directory, reads need a file"
            )));
        }
        if hit.size_bytes == 0 {
            return Ok(Vec::new());
        }
        let cluster_bytes = self.geometry.cluster_bytes();
        let needed = hit.size_bytes.div_ceil(cluster_bytes);
        // The chain walk first: every corruption shape refuses before
        // any byte is read, and the bookkeeping allocation stays
        // capped at the volume's real cluster count.
        if needed > u64::from(self.geometry.cluster_count) {
            return Err(CoreError::invalid(format!(
                "file {path:?} claims {needed} clusters but the volume provides {}",
                self.geometry.cluster_count
            )));
        }
        let chain_cap =
            usize::try_from(needed).map_err(|_| CoreError::invalid("a file longer than usize"))?;
        let mut clusters = Vec::with_capacity(chain_cap);
        // The visited set grows with the real chain; a cycle repeats a
        // cluster before the claim's cluster count is reached, and the
        // read would otherwise return repetitions dressed as a longer
        // file.
        let mut visited = std::collections::HashSet::new();
        let mut cluster = hit.first_cluster;
        while clusters.len() < chain_cap {
            if !visited.insert(cluster) {
                return Err(CoreError::invalid(format!(
                    "the chain of {path:?} loops back onto cluster {cluster} after {} of the \
                     {needed} clusters it claims: corrupt",
                    clusters.len()
                )));
            }
            clusters.push(cluster);
            if clusters.len() == chain_cap {
                break;
            }
            cluster = self.chain_next(cluster)?.ok_or_else(|| {
                CoreError::invalid(format!(
                    "file {path:?} claims {} bytes but its chain covers {} clusters only",
                    hit.size_bytes,
                    clusters.len()
                ))
            })?;
        }
        // Reading: one 64 KiB window at a time, appended in order.
        let mut out = Vec::new();
        let mut buf = [0u8; DIR_CLUSTER_BYTES];
        for (position, &chain_cluster) in clusters.iter().enumerate() {
            let span_start = u64::try_from(position)
                .map_err(|_| CoreError::invalid("a chain position"))?
                * cluster_bytes;
            let span_end = span_start.saturating_add(cluster_bytes).min(hit.size_bytes);
            if span_start >= span_end {
                break;
            }
            let read_len =
                usize::try_from(span_end - span_start).map_err(|_| CoreError::invalid("read"))?;
            let base = self.geometry.cluster_offset(chain_cluster).ok_or_else(|| {
                CoreError::invalid(format!(
                    "cluster {chain_cluster} does not resolve on this volume"
                ))
            })?;
            self.volume.read_exact_at(
                base,
                buf.get_mut(..read_len)
                    .ok_or_else(|| CoreError::invalid("a read window vanished"))?,
            )?;
            out.extend_from_slice(
                buf.get(..read_len)
                    .ok_or_else(|| CoreError::invalid("a read window vanished"))?,
            );
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Directory views
    // ------------------------------------------------------------------

    /// List the directory at `path`: every real entry as [`DirEntryInfo`]
    /// in chain order. The volume-label entry, `.`/`..` linkage, deleted
    /// slots and stray LFN pieces never list — the names the listing
    /// shows are the LFN names (reassembled, with the corrupt-run and
    /// checksum fallback to the short name), exactly the ones a Windows
    /// Explorer would show.
    pub fn list_dir(&mut self, path: &str) -> Result<Vec<DirEntryInfo>> {
        let dir_first = self.resolve_dir(path)?;
        let mut out = Vec::new();
        self.walk_dir_entries(dir_first, &mut |entry| {
            if entry.is_label || dirent::is_dot_entry(&entry.short) {
                return Ok(false);
            }
            out.push(DirEntryInfo {
                name: entry.display.clone(),
                short_name: dirent::short_name_text(&entry.short),
                is_dir: entry.is_dir,
                size_bytes: entry.size_bytes,
                first_cluster: entry.first_cluster,
                times: entry.write_times,
            });
            Ok(false)
        })?;
        Ok(out)
    }

    /// Replace the timestamps of the entry at `path` — create, write
    /// and access take the given pair. Files and directories both take
    /// stamps; the LFN run pieces are untouched (they carry none).
    pub fn set_times(&mut self, path: &str, times: FatTime) -> Result<()> {
        let Some(hit) = self.resolve_entry(path)? else {
            return Err(CoreError::invalid(format!(
                "{path:?} does not exist on the volume, so its times cannot be set"
            )));
        };
        let slot = self.read_slot(hit.slot)?;
        let short = dirent::short_field_of(&slot);
        let attr = dirent::attr_of(&slot);
        let cluster = dirent::first_cluster_of(&slot);
        let size = u32::try_from(dirent::size_of(&slot))
            .map_err(|_| CoreError::invalid("an entry size does not fit the u32 field"))?;
        let image = dirent::entry_image(&short, attr, cluster, size, times);
        self.write_slot(hit.slot, &image)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: allocation helpers
    // ------------------------------------------------------------------

    /// Freeze the allocation state a create path (`create_file`,
    /// `mkdir`, `link_file`) is about to mutate — the FAT journal, the
    /// cached counts and their dirty flag — so a failure in any later
    /// step can put the ledger back exactly as it was.
    ///
    /// What [`Fat32::restore_allocation`] therefore guarantees: a
    /// refused create leaves *no* FAT or count residue — the freed
    /// clusters are free for the next scan and the FSInfo books stay
    /// consistent, which is what fsck judges ("Reclaimed N unused
    /// cluster(s)" and "Free cluster summary wrong" cannot happen off
    /// a refused call). On a fresh image the ledger restore also makes
    /// the volume byte-identical, because every cluster the path
    /// zeroed was zero already. Where bytes were *written* into
    /// clusters this rollback frees (a directory's dot entries, a
    /// half-stamped run after an I/O failure mid-write) they remain:
    /// the store has no read-back undo, a free cluster's content is
    /// unspecified garbage to the format, and the chains themselves
    /// stay clean — a retry re-stamps the same free slots over them.
    fn allocation_snapshot(&self) -> AllocationSnapshot {
        AllocationSnapshot {
            journal: self.journal.clone(),
            free_clusters: self.free_clusters,
            next_free: self.next_free,
            fsinfo_dirty: self.fsinfo_dirty,
        }
    }

    /// Put the ledger back to a [`Fat32::allocation_snapshot`] state.
    fn restore_allocation(&mut self, snapshot: AllocationSnapshot) {
        self.journal = snapshot.journal;
        self.free_clusters = snapshot.free_clusters;
        self.next_free = snapshot.next_free;
        self.fsinfo_dirty = snapshot.fsinfo_dirty;
    }

    /// Step one FAT chain link: `None` at the end-of-chain family,
    /// refusals on free and corrupt entries (a chain walker never
    /// dereferences cluster 1 or a bad-cluster band value).
    fn chain_next(&self, cluster: u32) -> Result<Option<u32>> {
        let raw = fat::read_entry(&*self.volume, &self.geometry, Some(&self.journal), cluster)?;
        match fat::classify(raw, self.geometry.cluster_count) {
            fat::FatEntry::End => Ok(None),
            fat::FatEntry::Link(next) => Ok(Some(next)),
            fat::FatEntry::Free => Err(CoreError::invalid(format!(
                "the chain hits a free fat entry at cluster {cluster}"
            ))),
            fat::FatEntry::Corrupt(raw) => Err(CoreError::invalid(format!(
                "the chain carries corrupt fat value {raw:#010x} at cluster {cluster}"
            ))),
        }
    }

    /// Zero a whole cluster (a fresh directory cluster's shape).
    fn zero_cluster(&mut self, cluster: u32) -> Result<()> {
        let base = self.geometry.cluster_offset(cluster).ok_or_else(|| {
            CoreError::invalid(format!("cluster {cluster} does not resolve on this volume"))
        })?;
        let cluster_bytes = usize::try_from(self.geometry.cluster_bytes())
            .map_err(|_| CoreError::invalid("a cluster longer than the machine's usize"))?;
        let buf = [0u8; DIR_CLUSTER_BYTES];
        self.volume.write_all_at(
            base,
            buf.get(..cluster_bytes)
                .ok_or_else(|| CoreError::invalid("a cluster window vanished"))?,
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: name planning
    // ------------------------------------------------------------------

    /// Plan an entry for `name` inside `dir_first`: the name validates
    /// through [`dirent::validate_name`], an existing name refuses
    /// (case-insensitively — the display name and the short name both
    /// count), and the short field is generated with the `~n` collision
    /// tails until it is unique.
    fn plan_entry(&self, dir_first: u32, name: &str) -> Result<PlannedEntry> {
        dirent::validate_name(name)?;
        let existing = self.collect_existing(dir_first)?;
        if let Some(clash) = existing
            .iter()
            .find(|entry| entry.display.eq_ignore_ascii_case(name))
        {
            return Err(CoreError::invalid(format!(
                "{name:?} already exists on the volume ({:?})",
                clash.display
            )));
        }
        let render = Self::unique_short(&existing, name)?;
        let field = dirent::short_field(&render);
        let needs_lfn = dirent::needs_lfn(name, &render);
        let units = dirent::units_of(name);
        let piece_count = if needs_lfn {
            dirent::lfn_entry_count(units.len())
        } else {
            0
        };
        Ok(PlannedEntry {
            field,
            units,
            piece_count,
        })
    }

    /// The short render for a name, tail-free first and with `~1`..
    /// `~999999` tails on collision, against the directory's existing
    /// short fields.
    fn unique_short(existing: &[Existing], name: &str) -> Result<dirent::SfnRender> {
        let mut render = dirent::sfn_candidate(name, None);
        let mut field = dirent::short_field(&render);
        if !existing.iter().any(|entry| entry.short == field) {
            return Ok(render);
        }
        // NOTE: `render` is re-assigned inside the loop only; the
        // tail-free field never returns after a collision was found.
        for number in 1..=SFN_TAIL_LIMIT {
            render = dirent::sfn_candidate(name, Some(number));
            field = dirent::short_field(&render);
            if !existing.iter().any(|entry| entry.short == field) {
                return Ok(render);
            }
        }
        Err(CoreError::invalid(format!(
            "every numeric tail up to ~{SFN_TAIL_LIMIT} collides for {name:?}, no 8.3 name fits"
        )))
    }

    /// Every existing entry of the directory (names and short fields).
    fn collect_existing(&self, dir_first: u32) -> Result<Vec<Existing>> {
        let mut out = Vec::new();
        self.walk_dir_entries(dir_first, &mut |entry| {
            if !entry.is_label {
                out.push(Existing {
                    short: entry.short,
                    display: entry.display.clone(),
                });
            }
            Ok(false)
        })?;
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Internal: directory slot management
    // ------------------------------------------------------------------

    /// Reserve a run of `need` consecutive free slots in the directory:
    /// the first fitting free run (free = end-of-directory marker or a
    /// deleted entry — both are reusable), growing the directory chain
    /// with as many zeroed clusters as the run needs when nothing fits
    /// (an in-place, legal, non-contiguous growth).
    ///
    /// The growth covers the *whole* run: `ceil(need / slots)` fresh
    /// clusters, linked as one chain tail, so a 21-slot name on a
    /// 512-byte-cluster volume spans two fresh clusters rather than
    /// one. A single-cluster growth made every run longer than one
    /// cluster unwritable — the run then failed inside
    /// [`stamp_entry`](Fat32::stamp_entry) after the cluster was
    /// already journaled, leaking it as an orphan (fsck: "Reclaimed 1
    /// unused cluster").
    fn reserve_slot_run(&mut self, dir_first: u32, need: u32) -> Result<SlotRun> {
        if let Some(run) = self.find_free_slot_run(dir_first, need)? {
            return Ok(run);
        }
        let slots_per_cluster = u32::try_from(self.cluster_slots()?)
            .map_err(|_| CoreError::invalid("a cluster's slots do not fit a u32"))?;
        // `need` comes from a validated plan (at most 21 slots: 20 LFN
        // pieces + the short entry), so this caps at 2 fresh clusters
        // on 512-byte-cluster volumes — the math itself stays general.
        let fresh_needed = need.div_ceil(slots_per_cluster);
        let mut fresh = Vec::new();
        for _ in 0..fresh_needed {
            let (cluster, _) = self.allocate_contiguous(self.geometry.cluster_bytes())?;
            self.zero_cluster(cluster)?;
            fresh.push(cluster);
        }
        let tail = self.dir_chain_tail(dir_first)?;
        // Link the tail into the first fresh cluster and the fresh
        // clusters onwards; the allocator already marked the last one
        // EoC, so the chain ends there.
        let mut previous = tail;
        for &cluster in &fresh {
            self.journal.set(previous, cluster);
            previous = cluster;
        }
        let start = fresh
            .first()
            .copied()
            .ok_or_else(|| CoreError::invalid("a slot run cannot be zero clusters long"))?;
        Ok(SlotRun {
            start: SlotPos {
                cluster: start,
                index: 0,
            },
            count: need,
        })
    }

    /// The first run of `need` free slots of a directory chain
    /// (`Some`... or `None` when the chain has no fitting run).
    fn find_free_slot_run(&self, dir_first: u32, need: u32) -> Result<Option<SlotRun>> {
        let mut scan = self.dir_slots(dir_first)?;
        let mut run_len = 0_u32;
        let mut run_start = None;
        while let Some((pos, bytes)) = scan.next_slot()? {
            // Free means reusable: the end-of-directory marker, a
            // deleted lead (0xE5) or its KANJI alias (0x05). The 0x05
            // rule is short-entry-only (see [`dirent::is_usable`]):
            // inside an LFN run that byte is the legitimate ordinal of
            // piece 5, and re-using that slot while the run survives
            // corrupts the name on disk (fsck: "Start may have been
            // overwritten").
            let first = bytes.first().copied().unwrap_or(0);
            let free = matches!(first, dirent::END_OF_DIR_MARKER | dirent::DELETED_MARKER)
                || (first == dirent::KANJI_DELETED_MARKER
                    && dirent::attr_of(&bytes) != dirent::ATTR_LONG_NAME);
            if free {
                if run_len == 0 {
                    run_start = Some(pos);
                }
                run_len = run_len.saturating_add(1);
                if run_len >= need {
                    return Ok(Some(SlotRun {
                        start: run_start
                            .ok_or_else(|| CoreError::invalid("a run lost its start slot"))?,
                        count: need,
                    }));
                }
            } else {
                run_len = 0;
                run_start = None;
            }
        }
        Ok(None)
    }

    /// The slot positions of a run, walking the directory's chain as
    /// needed (they may cross clusters).
    fn run_slot_positions(&self, run: SlotRun) -> Result<Vec<SlotPos>> {
        let cluster_slots = self.cluster_slots()?;
        let mut positions = Vec::with_capacity(
            usize::try_from(run.count).map_err(|_| CoreError::invalid("a slot run > usize"))?,
        );
        let mut cluster = run.start.cluster;
        let mut index = usize::try_from(run.start.index)
            .map_err(|_| CoreError::invalid("a slot index does not fit this machine"))?;
        for step in 0..run.count {
            positions.push(SlotPos {
                cluster,
                index: u32::try_from(index)
                    .map_err(|_| CoreError::invalid("a slot index does not fit a u32"))?,
            });
            if step + 1 == run.count {
                break; // the run is complete: no need to read the next link
            }
            index = index.saturating_add(1);
            if index == cluster_slots {
                cluster = self.chain_next(cluster)?.ok_or_else(|| {
                    CoreError::invalid("a directory chain ended while its slots were still running")
                })?;
                index = 0;
            }
        }
        Ok(positions)
    }

    /// Slots per cluster (32-byte tower); the geometry caps the cluster
    /// at the buffer's size.
    fn cluster_slots(&self) -> Result<usize> {
        u64::try_from(ENTRY_LEN)
            .ok()
            .and_then(|entry| {
                let per_cluster = self.geometry.cluster_bytes() / entry;
                usize::try_from(per_cluster).ok()
            })
            .ok_or_else(|| CoreError::invalid("a cluster's slots do not fit this machine"))
    }

    /// The chain walk bounds: `.chain()` is bounded by the cluster
    /// count; anything longer is a hostile loop.
    fn dir_chain_tail(&self, dir_first: u32) -> Result<u32> {
        let mut cluster = dir_first;
        for _ in 0..=self.geometry.cluster_count {
            match self.chain_next(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(cluster),
            }
        }
        Err(CoreError::invalid(format!(
            "the directory chain at cluster {dir_first} runs past every cluster the volume has"
        )))
    }

    /// Write one planned entry into its run: the LFN pieces in reverse
    /// physical order (seq ascending with slots, the flagged first-in-
    /// order piece directly before the short entry), then the 32-byte
    /// short entry itself.
    fn stamp_entry(
        &mut self,
        planned: &PlannedEntry,
        run: SlotRun,
        first_cluster: u32,
        size_bytes: u64,
        is_dir: bool,
    ) -> Result<()> {
        let positions = self.run_slot_positions(run)?;
        let size_field = u32::try_from(size_bytes)
            .map_err(|_| CoreError::invalid("an entry size does not fit the u32 field"))?;
        let attr = if is_dir {
            dirent::ATTR_DIRECTORY
        } else {
            dirent::ATTR_ARCHIVE
        };
        let checksum = dirent::sfn_checksum(&planned.field);
        let short_image =
            dirent::entry_image(&planned.field, attr, first_cluster, size_field, self.now);
        let (short_slot, piece_slots) = positions
            .split_last()
            .ok_or_else(|| CoreError::invalid("a run without any slots"))?;
        if piece_slots.len() != planned.piece_count {
            return Err(CoreError::invalid(format!(
                "the reserved run holds {} slots for {} planned lfn pieces",
                piece_slots.len(),
                planned.piece_count
            )));
        }
        // Physical slot r (within the piece tail) carries logical piece
        // seq N−r: slot 0 is the `0x40` first-in-order piece, and the
        // sequence numbers descend to 1, which sits next to the short
        // entry — the layout every FAT reader expects.
        for (run_slot, pos) in piece_slots.iter().enumerate() {
            let seq = piece_slots.len().saturating_sub(run_slot) as u8;
            let logical = usize::from(seq).saturating_sub(1);
            let tagged = if run_slot == 0 { seq | 0x40 } else { seq };
            let units = dirent::lfn_piece_units(&planned.units, logical);
            let image = dirent::lfn_piece_image(tagged, checksum, &units);
            self.write_slot(*pos, &image)?;
        }
        self.write_slot(*short_slot, &short_image)?;
        Ok(())
    }

    /// Absolute byte address of a slot.
    fn slot_address(&self, pos: SlotPos) -> Result<u64> {
        let base = self.geometry.cluster_offset(pos.cluster).ok_or_else(|| {
            CoreError::invalid(format!(
                "cluster {} does not resolve on this volume",
                pos.cluster
            ))
        })?;
        base.checked_add(
            u64::from(pos.index)
                .checked_mul(u64::try_from(ENTRY_LEN).ok().unwrap_or(u64::MAX >> 4))
                .ok_or_else(|| CoreError::invalid("a slot address overflows a u64"))?,
        )
        .ok_or_else(|| CoreError::invalid("a slot address overflows a u64"))
    }

    fn read_slot(&self, pos: SlotPos) -> Result<[u8; ENTRY_LEN]> {
        let address = self.slot_address(pos)?;
        let mut slot = [0u8; ENTRY_LEN];
        self.volume.read_exact_at(address, &mut slot)?;
        Ok(slot)
    }

    fn write_slot(&mut self, pos: SlotPos, image: &[u8; ENTRY_LEN]) -> Result<()> {
        let address = self.slot_address(pos)?;
        self.volume.write_all_at(address, image)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: path resolution
    // ------------------------------------------------------------------

    /// The components of a user path: `None` for the root (`"/"`), else
    /// component names — an optional single leading slash tolerated, an
    /// empty (trailing, or doubled `<`,`>`..) component refused, every
    /// component validated by [`dirent::validate_name`].
    fn split_path(path: &str) -> Result<Option<Vec<&str>>> {
        if path.is_empty() {
            return Err(CoreError::invalid("a path is empty"));
        }
        if path == "/" {
            return Ok(None); // the root itself
        }
        let components: Vec<&str> = path.split('/').collect();
        // An optional single leading slash is tolerated ("/a" == "a");
        // anything more is an empty component and refuses below.
        let start = if components.first() == Some(&"") {
            1
        } else {
            0
        };
        let mut out: Vec<&str> = Vec::with_capacity(components.len());
        for comp in components.iter().skip(start).copied() {
            if comp.is_empty() {
                return Err(CoreError::invalid(format!(
                    "path {path:?} carries an empty path component (a trailing or doubled slash)"
                )));
            }
            dirent::validate_name(comp)?;
            out.push(comp);
        }
        if out.is_empty() {
            // Only leading reached here ("/a" would push "a"); "" holds
            // slash-only paths.
            return Err(CoreError::invalid(format!(
                "path {path:?} names nothing but slashes"
            )));
        }
        Ok(Some(out))
    }

    /// Walk the component chain to the directory the components live
    /// in: every hop must exist and name a directory (errors name the
    /// offending component).
    fn dir_of_components(&self, components: &[&str]) -> Result<u32> {
        let mut current = ROOT_CLUSTER;
        for comp in components {
            let Some(hit) = self.lookup(current, comp)? else {
                return Err(CoreError::invalid(format!(
                    "path component {comp:?} does not exist on the volume"
                )));
            };
            if !hit.is_dir {
                return Err(CoreError::invalid(format!(
                    "{comp:?} names a file, not a directory, in the path"
                )));
            }
            current = hit.first_cluster;
        }
        Ok(current)
    }

    /// Resolve a path into the (parent directory, final component) pair
    /// a create/mkdir/link call needs; the root itself refuses (it
    /// always exists and nothing re-creates it).
    fn split_leaf<'a>(&self, path: &'a str) -> Result<(u32, &'a str)> {
        let Some(components) = Self::split_path(path)? else {
            return Err(CoreError::invalid(
                "the root directory exists on every volume, create or mkdir needs a name",
            ));
        };
        let leaf = components
            .iter()
            .copied()
            .last()
            .ok_or_else(|| CoreError::invalid("a path without a final component"))?;
        let parents = components.len().saturating_sub(1);
        let parent_components: Vec<&str> = components.iter().take(parents).copied().collect();
        let dir_first = self.dir_of_components(&parent_components)?;
        Ok((dir_first, leaf))
    }

    /// Resolve a full path into its entry (`None` when absent).
    fn resolve_entry(&self, path: &str) -> Result<Option<DirHit>> {
        let Some(components) = Self::split_path(path)? else {
            return Ok(None); // the root is never an entry
        };
        let leaf = components
            .iter()
            .copied()
            .last()
            .ok_or_else(|| CoreError::invalid("a path without a final component"))?;
        let parents = components.len().saturating_sub(1);
        let parent_components: Vec<&str> = components.iter().take(parents).copied().collect();
        let dir_first = self.dir_of_components(&parent_components)?;
        self.lookup(dir_first, leaf)
    }

    /// Resolve a path naming a directory, into its chain head.
    fn resolve_dir(&self, path: &str) -> Result<u32> {
        match Self::split_path(path)? {
            None => Ok(self.geometry.root_cluster),
            Some(components) => self.dir_of_components(&components),
        }
    }

    /// Case-insensitive lookup inside one directory: the first entry
    /// whose display name or short name matches lowers equal.
    fn lookup(&self, dir_first: u32, name: &str) -> Result<Option<DirHit>> {
        let lowered = name.to_ascii_lowercase();
        let mut hit = None;
        self.walk_dir_entries(dir_first, &mut |entry| {
            if !entry.is_label
                && (entry.display.to_ascii_lowercase() == lowered
                    || dirent::short_name_text(&entry.short).to_ascii_lowercase() == lowered)
            {
                hit = Some(DirHit {
                    slot: entry.slot,
                    is_dir: entry.is_dir,
                    first_cluster: entry.first_cluster,
                    size_bytes: entry.size_bytes,
                });
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(hit)
    }

    // ------------------------------------------------------------------
    // Internal: the directory walker
    // ------------------------------------------------------------------

    /// Clone-free slot iterator over one directory's chain.
    fn dir_slots(&self, dir_first: u32) -> Result<DirSlots<'_>> {
        DirSlots::new(
            &*self.volume,
            &self.geometry,
            Some(&self.journal),
            dir_first,
        )
    }

    /// Walk a directory's real entries with LFN reassembly: deleted
    /// slots end any pending run (an orphan's own tail was deleted along);
    /// LFN pieces accumulate (capped); every real entry reassembles its
    /// long name when the run and every checksum fit — falling back to
    /// the short name (never an error) otherwise. `.` and `..` never
    /// visit; volume-label entries visit with `is_label` set.
    fn walk_dir_entries(
        &self,
        dir_first: u32,
        visit: &mut dyn FnMut(WalkEntry) -> Result<bool>,
    ) -> Result<()> {
        let mut slots = self.dir_slots(dir_first)?;
        let mut pending: Vec<([u8; ENTRY_LEN], [u16; dirent::LFN_PIECE_UNITS])> = Vec::new();
        while let Some((pos, bytes)) = slots.next_slot()? {
            if !dirent::is_usable(&bytes) {
                pending.clear();
                continue;
            }
            if dirent::is_lfn(&bytes) {
                pending.push((bytes, dirent::lfn_piece_units_of(&bytes)));
                if pending.len() > LFN_PIECE_CAP {
                    pending.clear(); // a hostile run: bounded, corrupt, ignored
                }
                continue;
            }
            let short = dirent::short_field_of(&bytes);
            let checksum = dirent::sfn_checksum(&short);
            let display = dirent::reassemble_lfn(&pending, checksum)
                .unwrap_or_else(|| dirent::short_name_text(&short));
            pending.clear();
            let is_label = dirent::is_volume_label(&bytes);
            let entry = WalkEntry {
                slot: pos,
                short,
                display,
                is_label,
                is_dir: dirent::is_directory(&bytes),
                first_cluster: dirent::first_cluster_of(&bytes),
                size_bytes: dirent::size_of(&bytes),
                write_times: dirent::write_times_of(&bytes),
            };
            if visit(entry)? {
                return Ok(());
            }
        }
        Ok(())
    }
}

impl PlannedEntry {
    /// Slots the entry occupies: the pieces when an LFN run is needed,
    /// always topped by the short entry itself.
    fn entry_slots(&self) -> u32 {
        u32::try_from(self.piece_count.saturating_add(1)).unwrap_or(u32::MAX)
    }
}

/// One cluster-significant slot iterator over a directory chain:
/// clusters loaded one 64 KiB window at a time, slots copied out one by
/// one, the chain stepped through the FAT (journal-aware).
struct DirSlots<'a> {
    volume: &'a dyn Volume,
    geometry: &'a Geometry,
    journal: Option<&'a FatDelta>,
    cluster: Option<u32>,
    loaded: u32,
    buf: [u8; DIR_CLUSTER_BYTES],
    cluster_slots: usize,
    index: usize,
    done: bool,
}

impl<'a> DirSlots<'a> {
    fn new(
        volume: &'a dyn Volume,
        geometry: &'a Geometry,
        journal: Option<&'a FatDelta>,
        dir_first: u32,
    ) -> Result<Self> {
        if dir_first < ROOT_CLUSTER || dir_first > geometry.cluster_count.saturating_add(1) {
            return Err(CoreError::invalid(format!(
                "cluster {dir_first} is not a data cluster, so no directory can live there"
            )));
        }
        let cluster_slots = usize::try_from(geometry.cluster_bytes() / 32)
            .map_err(|_| CoreError::invalid("a cluster's slots do not fit this machine"))?;
        Ok(Self {
            volume,
            geometry,
            journal,
            cluster: Some(dir_first),
            loaded: 0,
            buf: [0u8; DIR_CLUSTER_BYTES],
            cluster_slots,
            index: 0,
            done: false,
        })
    }

    /// The next slot, or `None` when the chain ended; a corrupt or
    /// free-marked chain entry refuses instead of dereferencing.
    fn next_slot(&mut self) -> Result<Option<(SlotPos, [u8; ENTRY_LEN])>> {
        if self.done {
            return Ok(None);
        }
        let Some(mut cluster) = self.cluster else {
            self.done = true;
            return Ok(None);
        };
        if self.index >= self.cluster_slots {
            let raw = fat::read_entry(self.volume, self.geometry, self.journal, cluster)?;
            match fat::classify(raw, self.geometry.cluster_count) {
                fat::FatEntry::End => {
                    self.cluster = None;
                    self.done = true;
                    return Ok(None);
                }
                fat::FatEntry::Link(next) => {
                    cluster = next;
                    self.cluster = Some(next);
                    self.index = 0;
                }
                fat::FatEntry::Free => {
                    return Err(CoreError::invalid(format!(
                        "a directory chain hits a free fat value at cluster {cluster}"
                    )));
                }
                fat::FatEntry::Corrupt(raw) => {
                    return Err(CoreError::invalid(format!(
                        "a directory chain carries corrupt fat value {raw:#010x} at cluster {cluster}"
                    )));
                }
            }
        }
        if self.loaded != cluster {
            let offset = self.geometry.cluster_offset(cluster).ok_or_else(|| {
                CoreError::invalid(format!("cluster {cluster} does not resolve on this volume"))
            })?;
            let cluster_bytes = usize::try_from(self.geometry.cluster_bytes())
                .map_err(|_| CoreError::invalid("a cluster longer than the machine's usize"))?;
            let window = self
                .buf
                .get_mut(..cluster_bytes)
                .ok_or_else(|| CoreError::invalid("a directory window vanished"))?;
            self.volume.read_exact_at(offset, window)?;
            self.loaded = cluster;
        }
        let at = self
            .index
            .checked_mul(ENTRY_LEN)
            .ok_or_else(|| CoreError::invalid("a slot offset overflows usize"))?;
        let mut bytes = [0u8; ENTRY_LEN];
        let window = self
            .buf
            .get(at..at + ENTRY_LEN)
            .ok_or_else(|| CoreError::invalid("a directory slot window vanished"))?;
        bytes.copy_from_slice(window);
        let pos = SlotPos {
            cluster,
            index: u32::try_from(self.index)
                .map_err(|_| CoreError::invalid("a slot index does not fit a u32"))?,
        };
        self.index += 1;
        Ok(Some((pos, bytes)))
    }
}

/// The little-endian `u16` of a boot image (checked gets, padded 0).
fn le_u16(boot: &[u8], at: usize) -> u16 {
    (u16::from(boot.get(at + 1).copied().unwrap_or(0)) << 8)
        | u16::from(boot.get(at).copied().unwrap_or(0))
}

/// The little-endian `u32` of an FSInfo image (as [`le_u16`]).
fn le_u32(image: &[u8], at: usize) -> u32 {
    u32::from(le_u16(image, at)) | u32::from(le_u16(image, at + 2)) << 16
}

/// A struck-out slot image: the deleted marker and zeros.
fn deleted_slot_image() -> [u8; ENTRY_LEN] {
    let mut slot = [0u8; ENTRY_LEN];
    if let Some(first) = slot.get_mut(0) {
        *first = dirent::DELETED_MARKER;
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::fat32::bpb::DEFAULT_OEM;
    use std::sync::OnceLock;

    /// 34 MiB: a geometry-test-pinned size class, the smallest this
    /// file API can legally format (the "8 MiB" shape of the brief is
    /// below the 65,525-data-cluster FAT32 floor, so 34 MiB carries the
    /// open() round-trip instead — see the test).
    const THIRTY_FOUR_MIB: u64 = 34 * 1024 * 1024;
    /// 64 MiB in bytes, the canonical small target here.
    const SIXTY_FOUR_MIB: u64 = 64 * 1024 * 1024;

    fn options<'a>() -> FormatOptions<'a> {
        FormatOptions {
            label: Some("RUFUS"),
            volume_id: 0x1A2B_3C4D,
            oem: DEFAULT_OEM,
        }
    }

    fn live(size: u64) -> Fat32 {
        Fat32::format(
            Box::new(VecVolume::new(size, 512).expect("ram")),
            &options(),
        )
        .expect("the volume formats and loads")
    }

    /// A fixed stamp the clock tests inject: 2026-10-30 noon.
    fn fixed_stamps() -> FatTime {
        dirent::FatTime::from_ymdhms(2026, 10, 30, 12, 0, 0).expect("the stamp")
    }

    /// The pinned "34 MiB" geometry row (spc 1, FAT 537, 68,526
    /// clusters) for the open() round trip.
    fn pinned_thirty_four() -> &'static Geometry {
        static GEOMETRY: OnceLock<Geometry> = OnceLock::new();
        GEOMETRY.get_or_init(|| {
            crate::fs::fat32::geometry::geometry(THIRTY_FOUR_MIB, 512).expect("34 MiB geometry")
        })
    }

    /// The raw FSInfo numbers on the live volume's own store.
    fn fsinfo_numbers(fs: &Fat32) -> (u32, u32) {
        let sector = fs.fsinfo_sector.expect("the fsinfo pointer");
        let mut image = [0u8; bpb::BOOT_SECTOR_BYTES];
        fs.volume
            .read_exact_at(
                u64::from(sector) * u64::from(fs.geometry.bytes_per_sector),
                &mut image,
            )
            .expect("fsinfo read");
        (
            le_u32(&image, FSINFO_FREE_AT),
            le_u32(&image, FSINFO_NEXT_AT),
        )
    }

    // ------------------------------------------------------------------
    // The 3-level tree: create → write → read with content spanning
    // cluster boundaries
    // ------------------------------------------------------------------

    #[test]
    fn create_write_read_a_three_level_tree() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/a").expect("mkdir /a");
        fs.mkdir("/a/b").expect("mkdir /a/b");
        fs.mkdir("/a/b/c").expect("mkdir /a/b/c");
        // 3000 bytes over 512-byte clusters: 6 clusters, every one
        // spanning a boundary pattern
        let content: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let first = fs
            .create_file("/a/b/c/file.bin", content.len() as u64)
            .expect("the file is created");
        assert!(first >= 2, "the data chain starts at a real cluster");
        fs.flush().expect("the pass flushes");
        // writing through cluster boundaries
        fs.write_at("/a/b/c/file.bin", 0, &content[..1500])
            .expect("the first half writes");
        fs.write_at("/a/b/c/file.bin", 1500, &content[1500..])
            .expect("the second half writes");
        let read_back = fs.read_file("/a/b/c/file.bin").expect("read back");
        assert_eq!(read_back, content, "the content survives the round trip");
        // the entry's views agree
        let listed = fs.list_dir("/a/b/c").expect("list_dir");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "file.bin");
        assert_eq!(listed[0].size_bytes, 3000);
        assert!(!listed[0].is_dir);
        // and the entry's first cluster is the one create_file handed back
        assert_eq!(listed[0].first_cluster, first);
    }

    // ------------------------------------------------------------------
    // list_dir shapes
    // ------------------------------------------------------------------

    #[test]
    fn list_dir_reports_names_flags_sizes_and_skips_structural_entries() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/docs").expect("mkdir");
        let first = fs
            .create_file("/docs/notes.txt", 1234)
            .expect("the file exists");
        // the label entry hides, the dot entries hide
        let root = fs.list_dir("/").expect("list_dir");
        assert_eq!(root.len(), 1, "only the directory lists");
        assert!(root[0].is_dir);
        assert_eq!(root[0].name, "docs");
        let docs = fs.list_dir("/docs").expect("list_dir");
        assert_eq!(docs.len(), 1, "the file lists on its own");
        assert!(!docs[0].is_dir);
        assert_eq!(docs[0].size_bytes, 1234);
        assert_eq!(docs[0].first_cluster, first);
        // a file path is not a directory view
        let error = fs.list_dir("/docs/notes.txt").expect_err("file path");
        assert!(
            error.to_string().contains("notes.txt"),
            "the refusal names the path"
        );
        // ... and a missing path refuses with the component named
        let error = fs.list_dir("/ghost").expect_err("missing");
        assert!(error.to_string().contains("ghost"), "{error}");
    }

    // ------------------------------------------------------------------
    // LFN round trips
    // ------------------------------------------------------------------

    #[test]
    fn lfn_names_round_trip_and_lose_nothing() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/lfn").expect("mkdir");
        let name = "RufusLongFileNameForAnLfnRoundTrip.bin";
        let first = fs
            .create_file("/lfn/RufusLongFileNameForAnLfnRoundTrip.bin", 4096)
            .expect("created with a long name");
        fs.write_at(
            "/lfn/RufusLongFileNameForAnLfnRoundTrip.bin",
            100,
            b"payload",
        )
        .expect("written");
        let listed = fs.list_dir("/lfn").expect("list_dir");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, name, "the long name reassembles");
        // the short field is the uppercase truncated base
        assert_eq!(listed[0].short_name, "RUFUSLON.BIN");
        // lookup works by the long name
        let read = fs
            .read_file("/lfn/RufusLongFileNameForAnLfnRoundTrip.bin")
            .expect("read through the long path");
        assert_eq!(read.len(), 4096);
        assert_eq!(&read[100..107], b"payload");
        // and by the short name
        let read_short = fs.read_file("/lfn/RUFUSLON.BIN").expect("read short");
        assert_eq!(read_short.len(), 4096);
        let _ = first;
    }

    #[test]
    fn lossless_short_names_leave_no_lfn_run() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/plain").expect("mkdir");
        fs.create_file("/plain/NO-LFN.BIN", 8).expect("created");
        // `.` and `..` take the first two slots, so the file's own entry is
        // the third: the slot before it is `..`, not an LFN piece, and the
        // slot after it stays the end-of-directory marker.
        let dir_cluster = fs.resolve_dir("/plain").expect("resolve");
        let offsets = fs.geometry.cluster_offset(dir_cluster).expect("resolve");
        let mut entry = [0u8; 32];
        fs.volume
            .read_exact_at(offsets + 2 * 32, &mut entry)
            .expect("the file's slot");
        assert_eq!(
            entry.get(..11),
            Some(&b"NO-LFN  BIN"[..]),
            "the short field: base padded to 8, then the extension"
        );
        assert!(!dirent::is_lfn(&entry), "the entry is not an LFN piece");
        let mut parent = [0u8; 32];
        fs.volume
            .read_exact_at(offsets + 32, &mut parent)
            .expect("the .. slot");
        assert!(
            !dirent::is_lfn(&parent),
            "no LFN run precedes a lossless name"
        );
        let mut after = [0u8; 32];
        fs.volume
            .read_exact_at(offsets + 3 * 32, &mut after)
            .expect("the slot after the entry");
        assert!(
            after.iter().all(|&byte| byte == 0),
            "no LFN run follows the entry either"
        );
        let listed = fs.list_dir("/plain").expect("list");
        assert_eq!(listed[0].name, "NO-LFN.BIN");
        assert_eq!(listed[0].short_name, "NO-LFN.BIN");
    }

    #[test]
    fn collision_tails_stay_unique_and_checksummed() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/coll").expect("mkdir");
        fs.create_file("/coll/LONGFILE.TXT", 16).expect("first");
        // the next name truncates to the same short field: a tail lands
        let second = fs
            .create_file("/coll/LongFilename05.txt", 16)
            .expect("second");
        let third = fs
            .create_file("/coll/LongFilename06.txt", 16)
            .expect("third");
        let listed = fs.list_dir("/coll").expect("list");
        let shorts: Vec<String> = listed
            .iter()
            .map(|entry| entry.short_name.clone())
            .collect();
        assert!(shorts.contains(&"LONGFILE.TXT".to_owned()));
        assert!(shorts.contains(&"LONGFI~1.TXT".to_owned()));
        assert!(shorts.contains(&"LONGFI~2.TXT".to_owned()));
        assert_eq!(shorts.len(), 3, "all three stay listable");
        // lookups through the long names all work
        let read_second = fs
            .read_file("/coll/LongFilename05.txt")
            .expect("read second");
        assert_eq!(read_second.len(), 16);
        let read_third = fs
            .read_file("/coll/LongFilename06.txt")
            .expect("read third");
        assert_eq!(read_third.len(), 16);
        let _ = (second, third);
        // a duplicate of the long name refuses (case-insensitively)
        let error = fs
            .create_file("/coll/longfile.txt", 16)
            .expect_err("case-insensitive duplicate");
        assert!(error.to_string().contains("already exists"), "{error}");
    }

    // ------------------------------------------------------------------
    // The dot linkage
    // ------------------------------------------------------------------

    #[test]
    fn dots_link_to_self_and_the_parent_or_zero() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/parent").expect("mkdir /parent");
        fs.mkdir("/parent/child").expect("mkdir /parent/child");
        let parent_cluster = fs.resolve_dir("/parent").expect("resolve parent");
        let child_cluster = fs.resolve_dir("/parent/child").expect("resolve child");
        // `..` OF a directory under the root reads 0
        let base = fs.geometry.cluster_offset(parent_cluster).expect("resolve");
        let mut dotdot_slot = [0u8; 32];
        fs.volume
            .read_exact_at(base + 32, &mut dotdot_slot)
            .expect("the .. slot");
        assert_eq!(
            dirent::first_cluster_of(&dotdot_slot),
            0,
            ".. = 0 under the root"
        );
        assert!(dirent::is_directory(&dotdot_slot));
        // the grandchild's `..` names its parent; `.` names itself
        let base = fs.geometry.cluster_offset(child_cluster).expect("resolve");
        let mut dot_slot = [0u8; 32];
        fs.volume
            .read_exact_at(base, &mut dot_slot)
            .expect("the . slot");
        assert_eq!(
            dirent::first_cluster_of(&dot_slot),
            child_cluster,
            ". = self"
        );
        fs.volume
            .read_exact_at(base + 32, &mut dotdot_slot)
            .expect("the grandchild .. slot");
        assert_eq!(
            dirent::first_cluster_of(&dotdot_slot),
            parent_cluster,
            ".. = the parent's cluster"
        );
        // and a listing of the parent shows only the child
        let listed = fs.list_dir("/parent").expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "child");
    }

    // ------------------------------------------------------------------
    // Directory growth
    // ------------------------------------------------------------------

    #[test]
    fn growing_a_directory_keeps_every_entry_readable() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/many").expect("mkdir");
        // a 512-byte cluster holds 16 slots; 17 SFN-only names force
        // one growth, 20 spread over 2 clusters
        for index in 1..=20 {
            let name = format!("FILE{index:02}.BIN");
            fs.create_file(&format!("/many/{name}"), 32)
                .unwrap_or_else(|error| panic!("create {name}: {error}"));
        }
        let listed = fs.list_dir("/many").expect("list");
        assert_eq!(listed.len(), 20, "all entries survive the growth");
        for index in 1..=20 {
            let name = format!("FILE{index:02}.BIN");
            assert!(
                listed.iter().any(|entry| entry.name == name),
                "the entry {name} is listed"
            );
        }
        // ... and the directory chain now spans 2 clusters
        let dir_cluster = fs.resolve_dir("/many").expect("resolve");
        let raw = fat::read_entry(&*fs.volume, &fs.geometry, Some(&fs.journal), dir_cluster)
            .expect("dir fat entry");
        assert_ne!(raw, fat::EOC, "the chain grew");
    }

    // ------------------------------------------------------------------
    // Contiguity
    // ------------------------------------------------------------------

    #[test]
    fn create_file_allocates_contiguous_runs() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/big").expect("mkdir");
        let first = fs
            .create_file("/big/contig.bin", 8 * 512) // 8 clusters
            .expect("created");
        fs.write_at("/big/contig.bin", 0, &[0xAB; 8 * 512])
            .expect("written");
        // FAT chain: n → n+1 → ... → n+7 → EoC (both copies agree)
        for offset in 0..8_u32 {
            let cluster = first + offset;
            let raw = fat::read_entry(&*fs.volume, &fs.geometry, Some(&fs.journal), cluster)
                .expect("chain read");
            let want = if offset == 7 { fat::EOC } else { cluster + 1 };
            assert_eq!(raw, want, "chain entry {cluster}");
        }
        // the dir entry carries the first cluster and size
        let listed = fs.list_dir("/big").expect("list");
        assert_eq!(listed[0].first_cluster, first);
        assert_eq!(listed[0].size_bytes, 8 * 512);
        // and reading back proves the bytes map through the chain
        let read = fs.read_file("/big/contig.bin").expect("read");
        assert!(read.iter().all(|&byte| byte == 0xAB));
    }

    #[test]
    fn link_file_matches_preallocated_chains_and_refuses_the_rest() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/pre").expect("mkdir");
        let (first, clusters) = fs.allocate_contiguous(2 * 512).expect("the pre-allocation");
        assert_eq!(clusters, 2);
        fs.link_file("/pre/link.bin", first, 2 * 512 - 1)
            .expect("the matching link");
        let listed = fs.list_dir("/pre").expect("list");
        assert_eq!(listed[0].name, "link.bin");
        assert_eq!(listed[0].first_cluster, first);
        assert_eq!(listed[0].size_bytes, 2 * 512 - 1);
        // refusals, each naming the mismatchisation
        let error = fs.link_file("/pre/low.bin", 1, 512).expect_err("cluster 1");
        assert!(
            error.to_string().contains("below the fat32 data"),
            "{error}"
        );
        let error = fs
            .link_file("/pre/empty.bin", 1, 0)
            .expect_err("zero size with a cluster");
        assert!(
            error.to_string().contains("empty file carries none"),
            "{error}"
        );
        let error = fs
            .link_file("/pre/mid.bin", first, 3 * 512)
            .expect_err("a 3-cluster claim on a 2-chain");
        assert!(error.to_string().contains("chain mismatch"), "{error}");
        let error = fs
            .link_file("/pre/free.bin", first + 40, 512)
            .expect_err("a cluster with no chain");
        assert!(error.to_string().contains("0x00000000"), "{error}");
        // the failed links leave no entries behind
        assert_eq!(fs.list_dir("/pre").expect("list").len(), 1);
    }

    // ------------------------------------------------------------------
    // Free space accounting
    // ------------------------------------------------------------------

    #[test]
    fn allocation_refuses_when_full_and_names_the_shortfall() {
        let mut fs = live(THIRTY_FOUR_MIB);
        let cluster_raw = fs.geometry().cluster_bytes();
        // carve out everything but the final 2 clusters
        let free_at_start = fs.free_bytes() / cluster_raw;
        let (first, count) = fs
            .allocate_contiguous((free_at_start - 2) * cluster_raw)
            .expect("the big allocation");
        assert!(first >= 2);
        assert_eq!(u64::from(count), free_at_start - 2);
        assert_eq!(fs.free_bytes(), 2 * cluster_raw, "2 clusters remain");
        // a 3-cluster claim now over-runs: the refusal names the need,
        // the largest run and the true total
        let error = fs
            .allocate_contiguous(3 * cluster_raw)
            .expect_err("the volume cannot pay");
        let text = error.to_string();
        assert!(text.contains("3 contiguous clusters"), "{text}");
        assert!(text.contains("largest free run holds 2"), "{text}");
        assert!(text.contains("2 free clusters in total"), "{text}");
        // the still-fitting tail takes the last 2 clusters ...
        fs.allocate_contiguous(2 * cluster_raw)
            .expect("the tail fits");
        // ... and a full volume refuses a 1-cluster claim with both zeros
        let error = fs
            .allocate_contiguous(cluster_raw)
            .expect_err("the volume is full");
        let text = error.to_string();
        assert!(text.contains("1 contiguous clusters"), "{text}");
        assert!(text.contains("0 free clusters in total"), "{text}");
    }

    #[test]
    fn free_accounting_agrees_with_fsinfo_and_the_rescan() {
        let mut fs = live(THIRTY_FOUR_MIB);
        let cluster_raw = fs.geometry().cluster_bytes();
        fs.mkdir("/acc").expect("mkdir");
        fs.create_file("/acc/one.bin", 4 * cluster_raw)
            .expect("one");
        fs.create_file("/acc/two.bin", 2 * cluster_raw)
            .expect("two");
        let cached = fs.free_bytes();
        assert_eq!(
            cached / cluster_raw,
            u64::from(fs.geometry().cluster_count - 1 - 1 - 6)
        );
        // after the flush, the FSInfo carries exactly the cached count
        fs.flush().expect("the pass flushes");
        let (disk_free, _hint) = fsinfo_numbers(&fs);
        assert_eq!(
            disk_free, fs.free_clusters,
            "the fsinfo published the count"
        );
        // and a full rescan of the fat agrees with both
        let (rescan_free, _) =
            fat::recount(&*fs.volume, &fs.geometry, &fs.journal).expect("rescan");
        assert_eq!(rescan_free, fs.free_clusters, "the fat scan agrees");
        assert_eq!(u64::from(rescan_free) * cluster_raw, cached);
    }

    // ------------------------------------------------------------------
    // Labels
    // ------------------------------------------------------------------

    #[test]
    fn set_label_round_trips_bpb_and_root_entry() {
        let mut fs = live(SIXTY_FOUR_MIB);
        // set: an 11-byte-lover shaped label. The bpB + the entry agree.
        fs.set_label(Some("rushmor3")).expect("set a first label");
        let (bpb_field, entry_field) = label_pair(&fs);
        assert_eq!(bpb_field, *b"RUSHMOR3   ");
        assert_eq!(entry_field, bpb_field);
        // change
        fs.set_label(Some("TOTAL CHANGE"))
            .expect("the label changes");
        let (bpb_field, entry_field) = label_pair(&fs);
        assert_eq!(bpb_field, *b"TOTAL CHANG");
        assert_eq!(entry_field, bpb_field);
        // removal clears both
        fs.set_label(None).expect("the label goes");
        let (bpb_field, entry_field) = label_pair(&fs);
        assert_eq!(bpb_field, *b"NO NAME    ");
        assert!(
            entry_field[0] == dirent::DELETED_MARKER,
            "the entry is struck out"
        );
        // re-set after removal inserts again
        fs.set_label(Some("back again")).expect("re-set");
        let (bpb_field, entry_field) = label_pair(&fs);
        assert_eq!(bpb_field, *b"BACK AGAIN ");
        assert_eq!(entry_field, bpb_field);
        // cropping is set_label's call: 12 characters land as 11
        fs.set_label(Some("TWELVE CHARS"))
            .expect("a long label crops");
        let (bpb_field, _) = label_pair(&fs);
        assert_eq!(bpb_field, *b"TWELVE CHAR");
        // the Windows-forbidden set still refuses
        let error = fs.set_label(Some("a*b")).expect_err("forbidden char");
        assert!(error.to_string().contains('*'), "{error}");
    }

    /// The BPB's 11 label bytes and the root label entry's, read back
    /// straight from the store.
    fn label_pair(fs: &Fat32) -> ([u8; 11], [u8; 11]) {
        let mut boot = [0u8; bpb::BOOT_SECTOR_BYTES];
        fs.volume
            .read_exact_at(0, &mut boot)
            .expect("the boot sector");
        let mut field = [b' '; 11];
        field.clone_from_slice(boot.get(71..82).expect("the label window"));
        let root = fs
            .geometry
            .cluster_offset(fs.geometry.root_cluster)
            .expect("root");
        let mut slot = [0u8; 32];
        fs.volume.read_exact_at(root, &mut slot).expect("root head");
        let mut entry = [b' '; 11];
        entry.clone_from_slice(slot.get(..11).expect("the name window"));
        (field, entry)
    }

    // ------------------------------------------------------------------

    #[test]
    fn write_refusals_and_the_zero_length_no_op() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/wr").expect("mkdir");
        fs.create_file("/wr/padded.bin", 1000).expect("created");
        let stamps = fixed_stamps();
        fs.set_times("/wr/padded.bin", stamps).expect("stamped");
        // past EOF
        let error = fs
            .write_at("/wr/padded.bin", 990, &[0u8; 20])
            .expect_err("past the end");
        assert!(error.to_string().contains("past the"), "{error}");
        // zero-length write: Ok, no I/O, and the times untouched
        fs.write_at("/wr/padded.bin", 1000, &[])
            .expect("a zero write is a no-op");
        let listed = fs.list_dir("/wr").expect("list");
        assert_eq!(listed[0].times, stamps, "write_at does not touch times");
        // zero-length write past EOF refuses like any other write
        let error = fs
            .write_at("/wr/padded.bin", 1001, &[])
            .expect_err("offset beyond the end");
        assert!(error.to_string().contains("past the"), "{error}");
        // a zero-size file refuses data...
        fs.create_file("/wr/empty.bin", 0).expect("created empty");
        let error = fs
            .write_at("/wr/empty.bin", 0, &[0xAA])
            .expect_err("size 0 with data");
        assert!(error.to_string().contains("size 0"), "{error}");
        // ...while its zero-length write stays Ok
        fs.write_at("/wr/empty.bin", 0, &[])
            .expect("no-op on empty");
        // writes do not cross into other entries' space
        fs.write_at("/wr/padded.bin", 500, &[0x55; 500])
            .expect("the tail writes");
        let first = fs.read_file("/wr/padded.bin").expect("read back");
        assert_eq!(first.len(), 1000);
        assert!(
            first[..500].iter().all(|&byte| byte == 0),
            "the head is untouched"
        );
        assert!(first[500..].iter().all(|&byte| byte == 0x55));
    }

    // ------------------------------------------------------------------
    // open() round trip
    // ------------------------------------------------------------------

    #[test]
    fn open_reproduces_geometry_and_lists_the_root() {
        // The brief's "8 MiB" shape is below the FAT32 floor (65,525
        // data clusters, the 34 MiB minimum); the pinned 34 MiB size
        // class carries the round trip.
        let mut volume = VecVolume::new(THIRTY_FOUR_MIB, 512).expect("34 MiB of RAM");
        let options = options();
        crate::fs::fat32::format::format(&mut volume, &options).expect("the free formatter");
        let mut fs = Fat32::open(Box::new(volume)).expect("the volume opens");
        let pinned = pinned_thirty_four();
        assert_eq!(fs.geometry().sectors_per_cluster, 1);
        assert_eq!(fs.geometry().fat_sectors, 537);
        assert_eq!(fs.geometry().cluster_count, 68_526);
        assert_eq!(
            fs.geometry(),
            pinned,
            "the parsed geometry is the derived one"
        );
        assert_eq!(fs.geometry().total_bytes, THIRTY_FOUR_MIB);
        // the fresh counts: everything except the root cluster
        assert_eq!(fs.free_bytes(), (68_526 - 1) * 512);
        // and the root directory lists empty (the label entry hidden)
        assert!(fs.list_dir("/").expect("list").is_empty());
    }

    #[test]
    fn unknown_fsinfo_counts_trigger_the_recount() {
        // Format through the free function (which leaves the counts
        // unknown, exactly the fresh-image shape), operate, then check
        // that open() counted them rather than freezing "unknown".
        let mut volume = VecVolume::new(THIRTY_FOUR_MIB, 512).expect("ram");
        crate::fs::fat32::format::format(&mut volume, &options()).expect("format");
        // the unknown reading is on the image
        let mut image = [0u8; 512];
        volume
            .read_exact_at(512, &mut image) // reserved sector 1 = byte 512
            .expect("fsinfo");
        assert_eq!(
            u32::MAX,
            le_u32(&image, FSINFO_FREE_AT),
            "the counts are unknown"
        );
        // the open counts them
        let mut fs = Fat32::open(Box::new(volume)).expect("open");
        assert_eq!(
            fs.free_clusters,
            fs.geometry().cluster_count - 1,
            "the recount tracks the fat"
        );
        // and the flush publishes the counted values (the fsinfo stops
        // being unknown)
        fs.flush().expect("flush");
        let (disk_free, _) = fsinfo_numbers(&fs);
        assert_eq!(disk_free, fs.geometry().cluster_count - 1);
    }

    // ------------------------------------------------------------------
    // The stamp seam
    // ------------------------------------------------------------------

    #[test]
    fn stamps_carry_the_injected_now() {
        let mut fs = live(SIXTY_FOUR_MIB);
        // deterministic default: the DOS epoch
        let stamps = FatTime::default();
        fs.mkdir("/tip").expect("mkdir");
        fs.create_file("/tip/x.bin", 8).expect("created");
        let listed = fs.list_dir("/tip").expect("list");
        assert_eq!(
            listed[0].times, stamps,
            "the default 'now' is the DOS epoch"
        );
        let root = fs.list_dir("/").expect("list");
        assert_eq!(root[0].times, stamps, "the directory's own stamp too");
        // injecting a clock moves every new stamp
        let fixed = fixed_stamps();
        fs.set_now(fixed);
        fs.mkdir("/late").expect("mkdir after the clock");
        let root = fs.list_dir("/").expect("list");
        let late = root
            .iter()
            .find(|entry| entry.name == "late")
            .expect("late");
        assert_eq!(late.times, fixed, "the injected clock stamps new entries");
        // set_times moves an entry explicitly
        let older = dirent::FatTime::from_ymdhms(1999, 12, 31, 23, 59, 58).expect("older");
        fs.set_times("/late", older).expect("set_times");
        let root = fs.list_dir("/").expect("list");
        let late = root
            .iter()
            .find(|entry| entry.name == "late")
            .expect("late");
        assert_eq!(late.times, older);
    }

    // ------------------------------------------------------------------

    #[test]
    fn hostile_paths_refuse_without_panicking() {
        let mut fs = live(SIXTY_FOUR_MIB);
        // forbidden characters, control bytes, non-ascii
        for path in [
            "/a*b",
            "/a:b",
            "/a<b",
            "/a?b",
            "/a\\b",
            "/a|b",
            "/a\"b",
            "/ctrl\u{1}x",
            "/utf-8\u{fc}",
            "",
            "trailing/",
            "/ trailed/",
            "/deep/missing/x",
            "a/",
            "//double",
            "/..",
            "/.",
            "/root/../x",
        ] {
            let result = fs.mkdir(path);
            assert!(result.is_err(), "mkdir must refuse {path:?}");
            let result = fs.create_file(path, 8);
            assert!(result.is_err(), "create must refuse {path:?}");
        }
        // long-path (256 units) refusal naming the 255 limit
        let long = format!("/{}", "x".repeat(256));
        let error = fs.create_file(&long, 8).expect_err("256 units");
        assert!(error.to_string().contains("255"), "{error}");
        // the name is stored nowhere
        assert!(fs.list_dir("/").expect("list").is_empty());
    }

    #[test]
    fn a_corrupt_fat_table_reports_instead_of_panicking() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/cor").expect("mkdir");
        fs.create_file("/cor/chain.bin", 2 * 512).expect("created");
        // Commit the real chain first: reads apply the in-memory journal
        // over the on-disk table, so an unflushed allocation would shadow
        // the poison below and the corruption would never be observed.
        fs.flush().expect("the real chain is on disk");
        // poison the first cluster's fat entry (both copies, as any
        // tampering would leave): the read side must refuse, not unwrap
        let chain = fs
            .resolve_entry("/cor/chain.bin")
            .expect("resolve")
            .expect("the file");
        let poison = 1_u32.to_le_bytes();
        for copy in 0..2_u32 {
            let offset =
                fat::fat_copy_offset(&fs.geometry, copy, chain.first_cluster).expect("offset");
            fs.volume.write_all_at(offset, &poison).expect("the poison");
        }
        // read_file refuses on the corrupt link before any byte reads
        let error = fs
            .read_file("/cor/chain.bin")
            .expect_err("the corrupt chain");
        assert!(error.to_string().contains("corrupt fat value"), "{error}");
        // write_at walks the chain only when it needs the next cluster:
        // a write crossing into the second cluster hits the poison
        let error = fs
            .write_at("/cor/chain.bin", 512, &[0x5A; 512])
            .expect_err("the corrupt chain");
        assert!(error.to_string().contains("corrupt fat value"), "{error}");
        // a write fully inside the first cluster still serves it
        fs.write_at("/cor/chain.bin", 0, &[0x11; 512])
            .expect("the first cluster lives");
        // the read side keeps refusing (the poison does not un-write)
        let error = fs
            .read_file("/cor/chain.bin")
            .expect_err("the chain read still refuses");
        assert!(error.to_string().contains("corrupt"), "{error}");
    }

    // ------------------------------------------------------------------
    // Long-name edges and allocation bookkeeping
    // ------------------------------------------------------------------

    #[test]
    fn a_maximum_length_lfn_round_trips() {
        let mut fs = live(SIXTY_FOUR_MIB);
        let name = format!("{}.txt", "a".repeat(251));
        assert_eq!(name.chars().count(), 255, "the longest legal long name");
        fs.create_file(&format!("/{name}"), 0)
            .expect("the longest legal name is created");
        let listed = fs.list_dir("/").expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].name, name,
            "all twenty pieces reassemble in order"
        );
        assert_eq!(fs.read_file(&format!("/{name}")).expect("read").len(), 0);
    }

    #[test]
    fn a_long_lfn_is_not_read_as_a_deleted_entry() {
        let mut fs = live(SIXTY_FOUR_MIB);
        // sixty-six units: six pieces. The physical order is 6|0x40,
        // then plain 5, 4, 3, 2, 1, so the second slot's raw byte is
        // 0x05 - the kanji alias of "deleted". Only pieces with six or
        // more slots carry an unflagged 0x05, which is why a five-piece
        // name cannot exercise the rule.
        let name = format!("{}.txt", "b".repeat(62));
        assert_eq!(name.chars().count(), 66);
        fs.create_file(&format!("/{name}"), 512).expect("created");
        let listed = fs.list_dir("/").expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, name, "the sequence-5 piece is live");
        assert_eq!(fs.read_file(&format!("/{name}")).expect("read").len(), 512);
        // a later short entry must not claim the sequence-5 slot
        fs.create_file("/SHORT.TXT", 0).expect("second create");
        assert_eq!(fs.list_dir("/").expect("list").len(), 2);
        assert_eq!(
            fs.read_file(&format!("/{name}"))
                .expect("still readable after the neighbour")
                .len(),
            512
        );
    }

    #[test]
    fn an_exactly_fitting_free_slot_run_is_used() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/exact").expect("mkdir");
        // sixteen slots per cluster; "." and ".." take two, so thirteen
        // short names leave exactly one free slot
        for index in 1..=13 {
            fs.create_file(&format!("/exact/F{index:02}.BIN"), 0)
                .expect("fill the first cluster");
        }
        let dir_cluster = fs.resolve_dir("/exact").expect("resolve");
        let before = fat::read_entry(&*fs.volume, &fs.geometry, Some(&fs.journal), dir_cluster)
            .expect("dir entry");
        assert_eq!(before, fat::EOC, "thirteen entries fit one cluster");
        fs.create_file("/exact/LAST.BIN", 0)
            .expect("a run of exactly one slot serves the entry");
        let after = fat::read_entry(&*fs.volume, &fs.geometry, Some(&fs.journal), dir_cluster)
            .expect("dir entry");
        assert_eq!(
            after,
            fat::EOC,
            "an exactly-fitting run must not grow the directory"
        );
        assert_eq!(fs.list_dir("/exact").expect("list").len(), 14);
    }

    #[test]
    fn a_refused_create_leaves_the_free_count_untouched() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/r").expect("mkdir");
        let before = fs.free_bytes();
        let too_long = format!("{}.txt", "c".repeat(252));
        fs.create_file(&format!("/r/{too_long}"), 0)
            .expect_err("one unit past the long-name limit");
        assert_eq!(fs.free_bytes(), before, "a refusal allocates nothing");
        assert!(fs.list_dir("/r").expect("list").is_empty());
    }

    #[test]
    fn a_refused_link_after_growing_the_directory_rolls_the_allocation_back() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.mkdir("/g").expect("mkdir");
        // a 512-byte cluster holds sixteen slots; "." and ".." take two,
        // so fourteen names leave the directory exactly full. The next
        // entry forces a growth, and the bad chain is rejected only
        // afterwards - the grown cluster has to be given back.
        for index in 1..=14 {
            fs.create_file(&format!("/g/F{index:02}.BIN"), 0)
                .expect("fill the first cluster");
        }
        let before_free = fs.free_bytes();
        let before_rows = fs.list_dir("/g").expect("list").len();
        fs.link_file("/g/BB.BIN", 1, 512)
            .expect_err("cluster 1 is not a data cluster");
        assert_eq!(
            fs.free_bytes(),
            before_free,
            "the cluster grown for the refused entry is returned"
        );
        assert_eq!(fs.list_dir("/g").expect("list").len(), before_rows);
        let dir_cluster = fs.resolve_dir("/g").expect("resolve");
        assert_eq!(
            fat::read_entry(&*fs.volume, &fs.geometry, Some(&fs.journal), dir_cluster)
                .expect("dir entry"),
            fat::EOC,
            "the directory keeps its single-cluster chain"
        );
    }

    // ------------------------------------------------------------------
    // write_boot_code: the backup mirror
    // ------------------------------------------------------------------

    /// A synthetic VBR: a real-shaped entry (a jump landing at 0x5A
    /// plus an OEM name), a foreign BPB and a recognizable code window,
    /// so the graft proof below can tell every window apart.
    fn test_vbr() -> [u8; bpb::BOOT_SECTOR_BYTES] {
        let mut vbr = [0xCCu8; bpb::BOOT_SECTOR_BYTES];
        vbr[0..11].copy_from_slice(b"\xEB\x58\x90SYSLINUX");
        for (index, slot) in vbr[bpb::BOOT_CODE_AREA].iter_mut().enumerate() {
            *slot = (index % 251) as u8;
        }
        vbr
    }

    /// One raw 512-byte sector of the live volume's own store.
    fn raw_sector(fs: &Fat32, index: u64) -> [u8; bpb::BOOT_SECTOR_BYTES] {
        let bps = u64::from(fs.geometry.bytes_per_sector);
        let mut sector = [0u8; bpb::BOOT_SECTOR_BYTES];
        fs.volume
            .read_exact_at(index * bps, &mut sector)
            .expect("the test sector reads");
        sector
    }

    #[test]
    fn write_boot_code_mirrors_the_grafted_record_into_the_backup_sector() {
        // The mirror proof on a real 64 MiB image: the grafted record
        // lands at sector 0 (the payload entry and code win, the
        // volume's own BPB window survives), the identical 512 bytes
        // land at the backup boot sector (reserved sector 6, matching
        // WritePBR's two-pass loop in src/format.c), and every sector
        // between — FSInfo (1) through 5 — stays byte-identical.
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.flush().expect("the pre-write flush runs");
        let before = raw_sector(&fs, 0);
        let before_mid: Vec<[u8; bpb::BOOT_SECTOR_BYTES]> = (1..u64::from(BACKUP_BOOT_SECTOR))
            .map(|index| raw_sector(&fs, index))
            .collect();
        let vbr = test_vbr();
        fs.write_boot_code(&vbr).expect("the graft writes");
        let primary = raw_sector(&fs, 0);
        assert_eq!(
            &primary[0..11],
            &vbr[0..11],
            "the payload jump and oem name win"
        );
        assert_eq!(
            &primary[11..bpb::BOOT_CODE_AREA.start],
            &before[11..bpb::BOOT_CODE_AREA.start],
            "the volume geometry survives the graft"
        );
        assert_eq!(
            &primary[bpb::BOOT_CODE_AREA],
            &vbr[bpb::BOOT_CODE_AREA],
            "the boot code is the payload's"
        );
        assert_eq!(
            &primary[510..512],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );
        assert_eq!(
            raw_sector(&fs, u64::from(BACKUP_BOOT_SECTOR)),
            primary,
            "the backup boot sector is byte-identical to the primary"
        );
        for (position, want) in before_mid.iter().enumerate() {
            let index = position as u64 + 1;
            assert_eq!(
                &raw_sector(&fs, index),
                want,
                "sector {index} between primary and backup stays untouched"
            );
        }
    }

    #[test]
    fn write_boot_code_is_idempotent_over_both_sectors() {
        // A second graft over the same VBR changes neither sector 0
        // nor the backup: the mirror is a pure function of the same
        // bytes.
        let mut fs = live(SIXTY_FOUR_MIB);
        let vbr = test_vbr();
        fs.write_boot_code(&vbr).expect("the first graft writes");
        let primary = raw_sector(&fs, 0);
        let backup = raw_sector(&fs, u64::from(BACKUP_BOOT_SECTOR));
        fs.write_boot_code(&vbr).expect("the second graft writes");
        assert_eq!(raw_sector(&fs, 0), primary, "sector 0 is stable");
        assert_eq!(
            raw_sector(&fs, u64::from(BACKUP_BOOT_SECTOR)),
            backup,
            "the backup sector is stable"
        );
        assert_eq!(backup, primary, "the mirror still holds");
    }

    /// A [`Volume`](crate::fs::Volume) over shared bytes whose reported
    /// extent can shrink after format: formatting needs the full 64
    /// MiB, then the visible size drops so the backup boot sector falls
    /// outside the volume without moving any byte.
    #[derive(Debug, Clone)]
    struct ShrinkVolume {
        bytes: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
        visible: std::rc::Rc<std::cell::Cell<u64>>,
    }

    impl crate::fs::Volume for ShrinkVolume {
        fn total_bytes(&self) -> u64 {
            self.visible.get()
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let total = self.visible.get();
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("a test read offset overflows a u64"))?;
            if end > total {
                return Err(CoreError::invalid(format!(
                    "read of {} bytes at offset {offset} runs past the {total} byte test volume",
                    buf.len()
                )));
            }
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let window = borrowed
                .get(start..start + buf.len())
                .expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            let total = self.visible.get();
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("a test write offset overflows a u64"))?;
            if end > total {
                return Err(CoreError::invalid(format!(
                    "write of {} bytes at offset {offset} runs past the {total} byte test volume",
                    buf.len()
                )));
            }
            let mut borrowed = self.bytes.borrow_mut();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let window = borrowed
                .get_mut(start..start + buf.len())
                .expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    #[test]
    fn write_boot_code_refuses_when_the_backup_falls_outside_the_volume() {
        // Format at full size, then shrink the visible extent to 2048
        // bytes: the backup boot sector (6 * 512 = 3072) falls outside,
        // so the graft refuses naming the sector and the volume size —
        // before the first write, so sector 0 still carries the
        // formatter's record (no half-applied mirror).
        let bytes = std::rc::Rc::new(std::cell::RefCell::new(vec![0u8; SIXTY_FOUR_MIB as usize]));
        let visible = std::rc::Rc::new(std::cell::Cell::new(SIXTY_FOUR_MIB));
        let store = ShrinkVolume {
            bytes: bytes.clone(),
            visible: visible.clone(),
        };
        let mut fs =
            Fat32::format(Box::new(store), &options()).expect("the volume formats and loads");
        fs.flush().expect("the pre-write flush runs");
        let before = {
            let borrowed = bytes.borrow();
            let mut sector = [0u8; bpb::BOOT_SECTOR_BYTES];
            sector.copy_from_slice(&borrowed[..bpb::BOOT_SECTOR_BYTES]);
            sector
        };
        visible.set(2048);
        let vbr = test_vbr();
        let error = fs
            .write_boot_code(&vbr)
            .expect_err("an out-of-range backup refuses");
        let text = error.to_string();
        assert!(
            text.contains(&BACKUP_BOOT_SECTOR.to_string()),
            "the refusal names the backup sector: {text}"
        );
        assert!(
            text.contains("2048"),
            "the refusal names the volume size: {text}"
        );
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
        let after = {
            let borrowed = bytes.borrow();
            let mut sector = [0u8; bpb::BOOT_SECTOR_BYTES];
            sector.copy_from_slice(&borrowed[..bpb::BOOT_SECTOR_BYTES]);
            sector
        };
        assert_eq!(
            after, before,
            "sector 0 is untouched: the refusal lands before the first write"
        );
    }

    #[test]
    fn read_file_refuses_a_chain_that_loops_before_its_claim() {
        let mut fs = live(SIXTY_FOUR_MIB);
        fs.create_file("/loop.bin", 1024).expect("two clusters");
        fs.flush().expect("the chain is on disk");
        let hit = fs
            .resolve_entry("/loop.bin")
            .expect("resolve")
            .expect("the file");
        // claim one cluster more than the chain really links, so the walk
        // has to step onto the repeat
        let mut entry = [0u8; ENTRY_LEN];
        let address = fs.slot_address(hit.slot).expect("slot address");
        fs.volume.read_exact_at(address, &mut entry).expect("entry");
        super::super::put_u32(&mut entry, 28, 1536).expect("the size field");
        fs.volume
            .write_all_at(address, &entry)
            .expect("patched size");
        // make the last real cluster point back at the first
        let second = fs
            .chain_next(hit.first_cluster)
            .expect("the second cluster")
            .expect("a link");
        let offset = fat::fat_copy_offset(&fs.geometry, 0, second).expect("offset");
        fs.volume
            .write_all_at(offset, &hit.first_cluster.to_le_bytes())
            .expect("the loop");
        let error = fs.read_file("/loop.bin").expect_err("the loop refuses");
        assert!(error.to_string().contains("loops back"), "{error}");
    }
}
