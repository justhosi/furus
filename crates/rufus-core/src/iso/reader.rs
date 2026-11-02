//! ISO9660/Joliet reader: label, lookup, listings and file reads (S14,
//! slices 1-2).
//!
//! *Measured* — everything here walks the structures [`descriptor`] and
//! [`record`] parse, over sectors the [`SectorCache`](crate::iso::SectorCache)
//! serves: the walked tree is the primary one, or the Joliet
//! supplementary tree with the highest escape level when one exists;
//! Joliet identifiers decode from UCS-2BE (surrogate pairs combine per
//! Unicode) and strip `;1`/trailing-dot on the decoded text; path
//! segments match decoded names byte-exactly (UTF-8 bytes, no case
//! folding); `.`/`..` records never appear in listings but `..`
//! traversal resolves; multi-extent files join their adjacent
//! same-name records in order and read concatenated; and file bytes
//! come from the recorded extents through the cache.
//!
//! *Inferred* — that preferring the highest Joliet level is what users
//! want (as libcdio does), and that loading a whole file into RAM in
//! `read_file` stays acceptable (a streaming read belongs to a later
//! slice; huge files fail gracefully through `try_reserve`, never with
//! a panicking allocator call).
//!
//! Refusals, not panics: a malformed Joliet name (odd length, unpaired
//! surrogate, interior NUL) refuses naming the path and the byte
//! offset; a non-adjacent or truncated multi-extent chain refuses
//! naming the path, as does a multi-extent directory (with its own
//! message) or an overflowing joined length; `..` past the root
//! refuses, empty path segments refuse, nesting past
//! [`MAX_DIR_DEPTH`](crate::iso::MAX_DIR_DEPTH) refuses as a possible
//! directory loop, and any extent running past the store extent refuses
//! as truncation. A directory whose length is not a sector multiple
//! reads its last partial sector (only the valid prefix carries
//! records, per ECMA-119); a volume cut inside that sector refuses,
//! because the sector is not fully present.

use std::cell::RefCell;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::iso::MAX_DIR_DEPTH;
use crate::iso::MAX_PATH_COMPONENTS;
use crate::iso::SECTOR_BYTES;
use crate::iso::SECTOR_BYTES_U64;
use crate::iso::cache::SectorCache;
use crate::iso::descriptor::BootRecord;
use crate::iso::descriptor::PrimaryDescriptor;
use crate::iso::descriptor::SupplementaryDescriptor;
use crate::iso::descriptor::read_descriptor_set;
use crate::iso::joliet::decode_name;
use crate::iso::joliet::strip_version as strip_joliet_version;
use crate::iso::record::DirRecord;
use crate::iso::record::parse_records;
use crate::iso::record::strip_version;
use crate::text::device_text;

/// Which directory tree an [`IsoReader`] walks: the primary tree, or
/// the Joliet supplementary tree at escape level 1, 2 or 3 (the
/// highest level present wins; ties keep the first in sequence order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    /// The primary tree: always present, walked when no Joliet
    /// supplementary descriptor exists.
    Primary,
    /// The Joliet supplementary tree at the given escape level.
    Joliet { level: u8 },
}

/// One directory entry: the raw identifier plus the decoded name, the
/// ordered extents, the total length and the raw recording date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Full identifier bytes exactly as stored (including any `;1`
    /// version suffix — see [`Entry::file_name`] for the display form).
    /// Empty for the root (which has no name).
    pub identifier: Vec<u8>,
    /// Display/matching form of the identifier: the primary tree
    /// strips `;1`/trailing-dot on the raw bytes, the Joliet tree on
    /// the UCS-2BE-decoded text (UTF-8 bytes here). Read it with
    /// [`Entry::file_name`].
    name: Vec<u8>,
    /// True for directories (flag bit 1), false for files.
    pub is_dir: bool,
    /// Ordered extent LBAs of the file or directory data: one element
    /// for plain files and directories, one per joined member for
    /// multi-extent files.
    pub extents: Vec<u32>,
    /// Data length in bytes: the joined total for multi-extent files.
    pub data_len: u32,
    /// Raw 7-byte recording date, kept for a later slice to decode.
    pub recorded: [u8; 7],
    /// Raw flag byte of the first record (hidden, associated and
    /// multi-extent bits survive here for later slices).
    pub flags: u8,
}

impl Entry {
    /// Display/matching form of the identifier: `;1` and one trailing
    /// `.` stripped, decoded from UCS-2BE on the Joliet tree.
    #[must_use]
    pub fn file_name(&self) -> Vec<u8> {
        self.name.clone()
    }

    /// True for files (convenience inverse of [`Entry::is_dir`]).
    #[must_use]
    pub fn is_file(&self) -> bool {
        !self.is_dir
    }
}

/// An opened file: the ordered extents with their byte lengths, the
/// total length, and the identifier for error messages. Read it with
/// [`IsoReader::read_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    /// Ordered file extents as `(extent LBA, byte length)` pairs, one
    /// per multi-extent member in join order (one pair for plain
    /// files).
    pub extents: Vec<(u32, u32)>,
    /// Total file length in bytes (the sum of the member lengths).
    pub size: u32,
    /// Full identifier bytes, for error messages only.
    pub identifier: Vec<u8>,
    /// Display form of the identifier (decoded on the Joliet tree).
    /// Read it with [`OpenFile::file_name`].
    name: Vec<u8>,
}

impl OpenFile {
    /// File length in bytes.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.size
    }

    /// True when the file holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Display form of the identifier (suffix stripped, decoded from
    /// UCS-2BE on the Joliet tree).
    #[must_use]
    pub fn file_name(&self) -> Vec<u8> {
        self.name.clone()
    }
}

/// One path component after splitting: `.`, `..`, or a name matched
/// against display names (stripped raw bytes on the primary tree,
/// decoded UCS-2BE on the Joliet tree).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    /// `.`: stay in the current directory.
    Current,
    /// `..`: move to the parent directory (refused at the root).
    Parent,
    /// A name segment (never empty).
    Name(String),
}

/// Error-message form of a path: sanitised to ASCII through the one
/// device-text sanitiser and capped at 200 characters so a hostile path
/// cannot flood a log line.
fn short_path(path: &str) -> String {
    let clean = device_text(path);
    let mut out: String = clean.chars().take(200).collect();
    if clean.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

/// Error-message form of one wanted segment (always valid UTF-8, still
/// sanitised so refusals stay ASCII).
fn short_segment(segment: &str) -> String {
    device_text(segment)
}

/// Split `path` on `/`: a leading `/` is optional, `.`/`..` become
/// [`Component::Current`]/[`Component::Parent`], anything else becomes a
/// [`Component::Name`]. Empty segments (`A//B`, trailing `/`) are
/// refused, as are paths with more than
/// [`MAX_PATH_COMPONENTS`](crate::iso::MAX_PATH_COMPONENTS) components.
/// The empty path and `/` both mean the root.
fn split_path(path: &str) -> Result<Vec<Component>> {
    let body = path.strip_prefix('/').unwrap_or(path);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for segment in body.split('/') {
        if segment.is_empty() {
            return Err(CoreError::invalid(format!(
                "path `{}` has an empty segment: empty segments are refused",
                short_path(path)
            )));
        }
        if out.len() >= MAX_PATH_COMPONENTS {
            return Err(CoreError::invalid(format!(
                "path `{}` has more than {MAX_PATH_COMPONENTS} components",
                short_path(path)
            )));
        }
        if segment == "." {
            out.push(Component::Current);
        } else if segment == ".." {
            out.push(Component::Parent);
        } else {
            out.push(Component::Name(segment.to_string()));
        }
    }
    Ok(out)
}

/// ISO9660 reader over an owned byte store: the primary tree, or the
/// Joliet tree with the highest escape level when one exists.
#[derive(Debug)]
pub struct IsoReader {
    /// Sector cache (behind a cell so every API takes `&self`; the
    /// borrow is statement-scoped and never re-entered, and a
    /// still-borrowed cache refuses instead of panicking). The cell
    /// keeps the reader single-threaded (`!Sync`): sharing one across
    /// threads would need a `Mutex`, left for a later slice.
    cache: RefCell<SectorCache>,
    /// Volume identifier of the chosen tree (UCS-2BE-decoded for
    /// Joliet).
    label: String,
    /// Volume space size in logical sectors, from the primary.
    volume_space_size: u32,
    /// Total store extent in bytes, for window checks with context.
    total_bytes: u64,
    /// Root directory record of the chosen tree.
    root_record: DirRecord,
    /// Which tree the reader walks.
    tree: TreeKind,
    /// The primary descriptor: always present, even when the reader
    /// walks the Joliet tree (the walked tree is reported by
    /// [`IsoReader::tree`]).
    primary: PrimaryDescriptor,
    /// Supplementary descriptors in sequence order (the Joliet walk
    /// uses the chosen one, reported by [`IsoReader::tree`]).
    supplementary: Vec<SupplementaryDescriptor>,
    /// Boot records, retained and never executed.
    boot_records: Vec<BootRecord>,
}

/// First record of a resolved chain: every chain is non-empty by
/// construction, so this only fails on an internal programming error,
/// naming the path.
fn first_record<'chain>(chain: &'chain [DirRecord], path: &str) -> Result<&'chain DirRecord> {
    chain.first().ok_or_else(|| {
        CoreError::invalid(format!(
            "path `{}` resolved to no records: refusing an empty chain",
            short_path(path)
        ))
    })
}

/// Join an adjacent same-name chain into ordered `(extent, length)`
/// pairs plus the total length: a single record with the flag cleared
/// passes through; otherwise every member but the last must carry the
/// flag and the last must clear it, all members must be files, and the
/// lengths must add without overflowing. Refuses a truncated or broken
/// chain, a multi-extent directory (with its own message) and an
/// overflowing total, naming the path throughout.
fn join_extents(chain: &[DirRecord], path: &str) -> Result<(Vec<(u32, u32)>, u32)> {
    let first = first_record(chain, path)?;
    if chain.len() == 1 && !first.is_multi_extent() {
        return Ok((vec![(first.extent_lba, first.data_len)], first.data_len));
    }
    let mut parts = Vec::with_capacity(chain.len());
    let mut total: u32 = 0;
    let members = chain.len();
    for (index, member) in chain.iter().enumerate() {
        if member.is_dir() {
            return Err(CoreError::invalid(format!(
                "path `{}` is a multi-extent directory: multi-extent directories are \
                 not supported",
                short_path(path)
            )));
        }
        let last = index + 1 == members;
        if member.is_multi_extent() == last {
            if last {
                return Err(CoreError::invalid(format!(
                    "path `{}` has a truncated multi-extent chain: the last member still \
                     carries the multi-extent flag",
                    short_path(path)
                )));
            }
            return Err(CoreError::invalid(format!(
                "path `{}` has a broken multi-extent chain: only the last member may \
                 clear the multi-extent flag",
                short_path(path)
            )));
        }
        parts.push((member.extent_lba, member.data_len));
        total = total.checked_add(member.data_len).ok_or_else(|| {
            CoreError::invalid(format!(
                "path `{}` multi-extent lengths add past u32: adding member length {} \
                 to the running total {total} overflows",
                short_path(path),
                member.data_len
            ))
        })?;
    }
    Ok((parts, total))
}

impl IsoReader {
    /// Open the image `volume`: parse the descriptor sequence from
    /// sector 16, walk the Joliet tree with the highest escape level
    /// when one exists (the primary tree otherwise), and retain the
    /// primary, the supplementary descriptors and the boot records. Any
    /// malformed sequence refuses here, before any path is resolved.
    pub fn open(volume: Box<dyn Volume>) -> Result<Self> {
        let total_bytes = volume.total_bytes();
        let mut cache = SectorCache::new(volume);
        let set = read_descriptor_set(&mut cache)?;
        let mut choice: Option<(&SupplementaryDescriptor, u8)> = None;
        for supp in &set.supplementary {
            if let Some(level) = supp.joliet_level {
                let higher = match &choice {
                    Some((_, top)) => level > *top,
                    None => true,
                };
                if higher {
                    choice = Some((supp, level));
                }
            }
        }
        let (label, root_record, tree) = match choice {
            Some((supp, level)) => (
                supp.label.clone(),
                supp.root.clone(),
                TreeKind::Joliet { level },
            ),
            None => (
                set.primary.label.clone(),
                set.primary.root.clone(),
                TreeKind::Primary,
            ),
        };
        Ok(Self {
            cache: RefCell::new(cache),
            label,
            volume_space_size: set.primary.volume_space_size,
            total_bytes,
            root_record,
            tree,
            primary: set.primary,
            supplementary: set.supplementary,
            boot_records: set.boot_records,
        })
    }

    /// Volume label of the chosen tree: the primary volume identifier,
    /// or the UCS-2BE-decoded supplementary identifier on the Joliet
    /// tree (trailing spaces trimmed either way).
    #[must_use]
    pub fn volume_label(&self) -> &str {
        &self.label
    }

    /// Which tree the reader walks (see [`TreeKind`]).
    #[must_use]
    pub fn tree(&self) -> TreeKind {
        self.tree
    }

    /// Volume space size in logical sectors, from the primary.
    #[must_use]
    pub fn volume_space_size(&self) -> u32 {
        self.volume_space_size
    }

    /// Total store extent in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The primary descriptor: always present, even when the reader
    /// walks the Joliet tree (see [`IsoReader::tree`]).
    #[must_use]
    pub fn primary(&self) -> &PrimaryDescriptor {
        &self.primary
    }

    /// Supplementary descriptors in sequence order (the walked tree is
    /// reported by [`IsoReader::tree`]).
    #[must_use]
    pub fn supplementary(&self) -> &[SupplementaryDescriptor] {
        &self.supplementary
    }

    /// Boot records in sequence order, retained and never executed.
    #[must_use]
    pub fn boot_records(&self) -> &[BootRecord] {
        &self.boot_records
    }

    /// The root directory entry (empty identifier, always a directory).
    #[must_use]
    pub fn root(&self) -> Entry {
        Entry {
            identifier: Vec::new(),
            name: Vec::new(),
            is_dir: self.root_record.is_dir(),
            extents: vec![self.root_record.extent_lba],
            data_len: self.root_record.data_len,
            recorded: self.root_record.recorded,
            flags: self.root_record.flags,
        }
    }

    /// Look up `path` (leading `/` optional, `.`/`..` allowed):
    /// `Some` entry for files and directories alike, `None` when the
    /// path does not resolve — not found, climbs above the root, has an
    /// empty segment, or hits any traversal refusal (use [`IsoReader::read_dir`]
    /// or [`IsoReader::open_file`] for the refusal text). The reason is
    /// collapsed here on purpose; the `Result` APIs report it.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<Entry> {
        match self.resolve(path) {
            // The root record compares equal to itself (a byte-identical
            // duplicate reachable by name cannot exist: `find_chain`
            // never returns the `.`/`..` records, and only dot-component
            // traversal ends back at the root).
            Ok(chain) => {
                let at_root = chain.len() == 1 && chain.first() == Some(&self.root_record);
                if at_root {
                    Some(self.root())
                } else {
                    self.entry_from_chain(&chain, path).ok()
                }
            }
            Err(_) => None,
        }
    }

    /// List the directory at `path`: the `.`/`..` records are skipped,
    /// adjacent same-name records join into one entry, everything else
    /// comes back with raw identifiers plus the decoded display name.
    /// Refuses paths that do not
    /// resolve, that resolve to a file, and any malformed directory
    /// data, naming the path.
    pub fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let chain = self.resolve(path)?;
        if chain.len() != 1 {
            if chain.iter().any(|record| record.is_dir()) {
                return Err(CoreError::invalid(format!(
                    "path `{}` is a multi-extent directory: multi-extent directories are \
                     not supported",
                    short_path(path)
                )));
            }
            return Err(CoreError::invalid(format!(
                "cannot list `{}`: it is a file, not a directory",
                short_path(path)
            )));
        }
        let record = first_record(&chain, path)?;
        if !record.is_dir() {
            return Err(CoreError::invalid(format!(
                "cannot list `{}`: it is a file, not a directory",
                short_path(path)
            )));
        }
        let records = self.read_dir_records(record).map_err(|error| {
            CoreError::invalid(format!("cannot list `{}`: {error}", short_path(path)))
        })?;
        // Group adjacent same-identifier records: each run joins into
        // one entry (multi-extent files list once, with the total).
        let mut runs: Vec<Vec<DirRecord>> = Vec::new();
        for child in records {
            if child.is_dot() || child.is_parent() {
                continue;
            }
            let continues = runs
                .last()
                .and_then(|run: &Vec<DirRecord>| run.first())
                .is_some_and(|first| first.identifier.as_slice() == child.identifier.as_slice());
            if continues {
                if let Some(run) = runs.last_mut() {
                    run.push(child);
                }
            } else {
                runs.push(vec![child]);
            }
        }
        let mut out = Vec::new();
        for run in &runs {
            let entry = self.entry_from_chain(run, path).map_err(|error| {
                CoreError::invalid(format!("cannot list `{}`: {error}", short_path(path)))
            })?;
            out.push(entry);
        }
        Ok(out)
    }

    /// Open the file at `path` for reading with [`IsoReader::read_open`].
    /// Multi-extent files join their members in order. Refuses
    /// directories, missing paths and broken chains, naming the path.
    pub fn open_file(&self, path: &str) -> Result<OpenFile> {
        let chain = self.resolve(path)?;
        let (parts, total) = join_extents(&chain, path)?;
        let first = first_record(&chain, path)?;
        if first.is_dir() {
            return Err(CoreError::invalid(format!(
                "cannot open `{}`: it is a directory, not a file",
                short_path(path)
            )));
        }
        Ok(OpenFile {
            extents: parts,
            size: total,
            identifier: first.identifier.clone(),
            name: self.display_name(first)?,
        })
    }

    /// Read the whole file at `path` into RAM.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let file = self.open_file(path)?;
        self.read_open(&file).map_err(|error| {
            CoreError::invalid(format!("cannot read `{}`: {error}", short_path(path)))
        })
    }

    /// Read the whole opened file into RAM through the sector cache:
    /// every `(extent, length)` pair reads its own sectors in order and
    /// concatenates. An empty file reads nothing; any part running past
    /// the store extent (`total_bytes`, not the declared volume space
    /// size) refuses as truncation with the numbers named, as does a
    /// handle whose parts do not add up to its size.
    pub fn read_open(&self, file: &OpenFile) -> Result<Vec<u8>> {
        let size = u64::from(file.size);
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut parts_total: u64 = 0;
        for part in file.extents.iter() {
            parts_total = parts_total.checked_add(u64::from(part.1)).ok_or_else(|| {
                CoreError::invalid("file extent lengths overflow the byte arithmetic")
            })?;
        }
        if parts_total != size {
            return Err(CoreError::invalid(format!(
                "file handle of {size} bytes disagrees with its extent parts totalling \
                 {parts_total} bytes: refusing an inconsistent handle"
            )));
        }
        let mut out = Vec::new();
        out.try_reserve(size as usize).map_err(|_| {
            CoreError::invalid(format!(
                "file of {size} bytes cannot be buffered: the allocation failed"
            ))
        })?;
        out.resize(size as usize, 0);
        let mut pos: usize = 0;
        for (extent_lba, part_len) in file.extents.iter().map(|part| (part.0, part.1)) {
            let part = u64::from(part_len);
            let start = u64::from(extent_lba)
                .checked_mul(SECTOR_BYTES_U64)
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "file extent {extent_lba} overflows the byte offset arithmetic"
                    ))
                })?;
            let end = start.checked_add(part).ok_or_else(|| {
                CoreError::invalid(format!(
                    "file of {part} bytes at extent {extent_lba} overflows the byte offset arithmetic"
                ))
            })?;
            if end > self.total_bytes {
                return Err(CoreError::invalid(format!(
                    "file of {part} bytes at extent {extent_lba} (bytes {start}..{end}) runs past \
                     the {} byte volume end: the volume is truncated",
                    self.total_bytes
                )));
            }
            let count = part.div_ceil(SECTOR_BYTES_U64);
            let mut remaining = part;
            for index in 0..count {
                let sector_no = extent_lba.checked_add(index as u32).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "file extent {extent_lba} plus sector {index} overflows the sector number"
                    ))
                })?;
                let bytes = self.read_sector_cached(sector_no)?;
                let take = remaining.min(SECTOR_BYTES_U64);
                let take_usize = take as usize;
                let dest = out.get_mut(pos..pos + take_usize).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "file read window {pos}..{} runs past the {size} byte buffer",
                        pos + take_usize
                    ))
                })?;
                let src = bytes.get(..take_usize).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "sector {sector_no} read of {take} bytes runs past the sector"
                    ))
                })?;
                dest.copy_from_slice(src);
                pos = pos.checked_add(take_usize).ok_or_else(|| {
                    CoreError::invalid("file read position overflows the offset arithmetic")
                })?;
                remaining -= take;
            }
        }
        Ok(out)
    }

    /// Resolve `path` to its final record chain (one record for plain
    /// files and directories, the adjacent same-name run for
    /// multi-extent files), following `.`/`..` and descending into
    /// directories. A name matching outside a single adjacent run
    /// refuses; nesting past [`MAX_DIR_DEPTH`](crate::iso::MAX_DIR_DEPTH)
    /// refuses as a possible directory loop; `..` past the root refuses.
    fn resolve(&self, path: &str) -> Result<Vec<DirRecord>> {
        let components = split_path(path)?;
        let mut stack: Vec<DirRecord> = Vec::new();
        let mut current = self.root_record.clone();
        let total = components.len();
        for (index, component) in components.iter().enumerate() {
            match component {
                Component::Current => {}
                Component::Parent => match stack.pop() {
                    Some(parent) => {
                        current = parent;
                    }
                    None => {
                        return Err(CoreError::invalid(format!(
                            "path `{}` climbs above the root: `..` at the root is refused",
                            short_path(path)
                        )));
                    }
                },
                Component::Name(want) => {
                    let chain = self.find_chain(&current, want.as_str(), path)?;
                    let last = index + 1 == total;
                    if last {
                        return Ok(chain);
                    }
                    // Validate the chain even mid-path (fail-closed),
                    // then require a plain directory to descend into.
                    join_extents(&chain, path)?;
                    let first = first_record(&chain, path)?;
                    if !first.is_dir() {
                        return Err(CoreError::invalid(format!(
                            "path `{}` passes through a file, not a directory",
                            short_path(path)
                        )));
                    }
                    stack.push(current);
                    if stack.len() > MAX_DIR_DEPTH {
                        return Err(CoreError::invalid(format!(
                            "path `{}` nests past {MAX_DIR_DEPTH} directories: \
                             refusing as a possible directory loop",
                            short_path(path)
                        )));
                    }
                    current = first.clone();
                }
            }
        }
        Ok(vec![current])
    }

    /// Display/matching form of one record's identifier: stripped raw
    /// bytes on the primary tree, UCS-2BE-decoded and stripped text
    /// (UTF-8 bytes) on the Joliet tree. Malformed Joliet names refuse
    /// with the byte offset named; callers add the path.
    fn display_name(&self, record: &DirRecord) -> Result<Vec<u8>> {
        if matches!(self.tree, TreeKind::Joliet { .. }) {
            let decoded = decode_name(&record.identifier)?;
            Ok(strip_joliet_version(&decoded).into_bytes())
        } else {
            Ok(strip_version(&record.identifier))
        }
    }

    /// Build the directory entry for one adjacent same-name run:
    /// joined extents with the total length, plus the decoded name.
    fn entry_from_chain(&self, chain: &[DirRecord], path: &str) -> Result<Entry> {
        let (parts, total) = join_extents(chain, path)?;
        let first = first_record(chain, path)?;
        let name = self.display_name(first)?;
        Ok(Entry {
            identifier: first.identifier.clone(),
            name,
            is_dir: first.is_dir(),
            extents: parts.iter().map(|part| part.0).collect(),
            data_len: total,
            recorded: first.recorded,
            flags: first.flags,
        })
    }

    /// Every record in directory `dir` matching `want`, as one
    /// adjacent run (`.`/`..` records never match). Refuses naming the
    /// path and the wanted name when absent, when the same name
    /// appears outside the run (duplicates and split chains are
    /// ambiguous), or when a name will not decode.
    fn find_chain(&self, dir: &DirRecord, want: &str, path: &str) -> Result<Vec<DirRecord>> {
        let records = self.read_dir_records(dir).map_err(|error| {
            CoreError::invalid(format!("cannot resolve `{}`: {error}", short_path(path)))
        })?;
        let mut chain = Vec::new();
        let mut in_run = false;
        let mut run_ended = false;
        for record in &records {
            if record.is_dot() || record.is_parent() {
                if in_run {
                    in_run = false;
                    run_ended = true;
                }
                continue;
            }
            let same = self
                .display_name(record)
                .map_err(|error| {
                    CoreError::invalid(format!("cannot resolve `{}`: {error}", short_path(path)))
                })?
                .as_slice()
                == want.as_bytes();
            if same {
                if run_ended {
                    return Err(CoreError::invalid(format!(
                        "path `{}` matches `{}` outside a single adjacent run: duplicate names \
                         and split multi-extent chains are refused",
                        short_path(path),
                        short_segment(want)
                    )));
                }
                in_run = true;
                chain.push(record.clone());
            } else if in_run {
                in_run = false;
                run_ended = true;
            }
        }
        if chain.is_empty() {
            return Err(CoreError::invalid(format!(
                "path `{}` not found: no entry matches `{}`",
                short_path(path),
                short_segment(want)
            )));
        }
        Ok(chain)
    }

    /// Every record in directory `dir` (including `.`/`..` — callers
    /// filter): whole sectors through the cache, with the last partial
    /// sector limited to its valid prefix.
    fn read_dir_records(&self, dir: &DirRecord) -> Result<Vec<DirRecord>> {
        if dir.is_multi_extent() {
            return Err(CoreError::invalid(format!(
                "directory at extent {} is multi-extent: multi-extent directories are \
                 not supported",
                dir.extent_lba
            )));
        }
        let data_len = u64::from(dir.data_len);
        if data_len == 0 {
            return Ok(Vec::new());
        }
        let count = data_len.div_ceil(SECTOR_BYTES_U64);
        let count32 = u32::try_from(count).map_err(|_| {
            CoreError::invalid(format!(
                "directory at extent {} of {data_len} bytes needs {count} sectors: \
                 the sector count does not fit",
                dir.extent_lba
            ))
        })?;
        let mut out = Vec::new();
        for index in 0..count32 {
            let sector_no = dir.extent_lba.checked_add(index).ok_or_else(|| {
                CoreError::invalid(format!(
                    "directory at extent {} plus sector {index} overflows the sector number",
                    dir.extent_lba
                ))
            })?;
            let consumed = u64::from(index) * SECTOR_BYTES_U64;
            let remaining = data_len.saturating_sub(consumed);
            let valid = usize::try_from(remaining.min(SECTOR_BYTES_U64)).map_err(|_| {
                CoreError::invalid(format!(
                    "directory sector {sector_no} valid length {remaining} does not fit"
                ))
            })?;
            let bytes = self.read_sector_cached(sector_no).map_err(|error| {
                CoreError::invalid(format!(
                    "directory at extent {} is unreadable at sector {sector_no} ({error}): \
                     the volume is truncated",
                    dir.extent_lba
                ))
            })?;
            out.extend(parse_records(&bytes, valid, sector_no)?);
        }
        Ok(out)
    }

    /// One sector through the cache, copied out so the cache borrow ends
    /// with the statement.
    fn read_sector_cached(&self, sector: u32) -> Result<[u8; SECTOR_BYTES]> {
        let mut cache = self.cache.try_borrow_mut().map_err(|_| {
            CoreError::invalid("iso sector cache is already borrowed: re-entrant use is refused")
        })?;
        let bytes = cache.read_sector(sector)?;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::iso::descriptor::TYPE_BOOT;
    use crate::iso::descriptor::TYPE_PRIMARY;
    use crate::iso::descriptor::TYPE_SUPPLEMENTARY;
    use crate::iso::descriptor::TYPE_TERMINATOR;
    use crate::iso::record::FLAG_DIRECTORY;
    use crate::iso::record::FLAG_MULTI_EXTENT;
    use crate::iso::record::RECORD_FIXED_LEN;

    /// Sectors of the shared fixture image (32 sectors total).
    const ROOT_SECTOR: u32 = 20;
    const DIR_A_SECTOR: u32 = 21;
    const FILE_B_SECTOR: u32 = 22;
    const FILE_ROOT_SECTOR: u32 = 23;
    const FILE_CAFE_SECTOR: u32 = 24;
    const JOLIET_ROOT_SECTOR: u32 = 25;
    const JOLIET_A_SECTOR: u32 = 26;
    const JOLIET_SUB_SECTOR: u32 = 27;
    const IMAGE_SECTORS: u32 = 32;

    /// Encode one directory record, mirroring the on-disk layout the
    /// parser reads (both-endian words, zero date, sequence 1, the
    /// even-length pad). Test-only encoding, not a second parser.
    fn encode_record(extent: u32, data_len: u32, flags: u8, identifier: &[u8]) -> Vec<u8> {
        let pad = if identifier.len().is_multiple_of(2) {
            1
        } else {
            0
        };
        let len = RECORD_FIXED_LEN + identifier.len() + pad;
        let mut out = vec![0u8; len];
        out[0] = len as u8;
        out[2..6].copy_from_slice(&extent.to_le_bytes());
        out[6..10].copy_from_slice(&extent.to_be_bytes());
        out[10..14].copy_from_slice(&data_len.to_le_bytes());
        out[14..18].copy_from_slice(&data_len.to_be_bytes());
        out[25] = flags;
        out[28..30].copy_from_slice(&1u16.to_le_bytes());
        out[30..32].copy_from_slice(&1u16.to_be_bytes());
        out[32] = identifier.len() as u8;
        out[33..33 + identifier.len()].copy_from_slice(identifier);
        out
    }

    /// Encode `text` as UCS-2BE bytes (BMP-only fixtures, so every
    /// character is one unit). Test-only encoding of the Joliet
    /// identifier layout.
    fn ucs2(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_be_bytes());
        }
        out
    }

    /// Encode one Joliet directory record: same fixed part as
    /// [`encode_record`], UCS-2BE identifier (always an even byte
    /// count, so the pad byte always applies).
    fn encode_joliet_record(extent: u32, data_len: u32, flags: u8, name: &str) -> Vec<u8> {
        encode_record(extent, data_len, flags, &ucs2(name))
    }

    /// Primary-descriptor sector with `label` and the root at
    /// (`root_extent`, `root_len`).
    fn primary_sector(label: &str, root_extent: u32, root_len: u32) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_PRIMARY;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        let label_bytes = label.as_bytes();
        let take = label_bytes.len().min(32);
        sector[40..40 + take].copy_from_slice(&label_bytes[..take]);
        for byte in sector.iter_mut().skip(40 + take).take(32 - take) {
            *byte = b' ';
        }
        sector[80..84].copy_from_slice(&IMAGE_SECTORS.to_le_bytes());
        sector[84..88].copy_from_slice(&IMAGE_SECTORS.to_be_bytes());
        sector[120..122].copy_from_slice(&1u16.to_le_bytes());
        sector[122..124].copy_from_slice(&1u16.to_be_bytes());
        sector[124..126].copy_from_slice(&1u16.to_le_bytes());
        sector[126..128].copy_from_slice(&1u16.to_be_bytes());
        sector[128..130].copy_from_slice(&2048u16.to_le_bytes());
        sector[130..132].copy_from_slice(&2048u16.to_be_bytes());
        let root = encode_record(root_extent, root_len, FLAG_DIRECTORY, b"\x00");
        sector[156..156 + root.len()].copy_from_slice(&root);
        sector
    }

    /// Supplementary-descriptor sector: UCS-2BE volume identifier
    /// (space-padded like real mastering tools), the given escape
    /// opening, and the root at (`root_extent`, `root_len`).
    fn joliet_sector(
        label: &str,
        escape: &[u8],
        root_extent: u32,
        root_len: u32,
    ) -> [u8; SECTOR_BYTES] {
        let mut sector = primary_sector("SUPP", root_extent, root_len);
        sector[0] = TYPE_SUPPLEMENTARY;
        let mut field = [0u8; 32];
        for pair in field.chunks_mut(2) {
            pair.copy_from_slice(&0x0020u16.to_be_bytes());
        }
        let encoded = ucs2(label);
        let take = encoded.len().min(32);
        field[..take].copy_from_slice(&encoded[..take]);
        sector[40..72].copy_from_slice(&field);
        for byte in sector.iter_mut().skip(88).take(32) {
            *byte = 0;
        }
        let take_escape = escape.len().min(32);
        sector[88..88 + take_escape].copy_from_slice(&escape[..take_escape]);
        sector
    }

    /// Boot-record sector.
    fn boot_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_BOOT;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Terminator sector.
    fn terminator_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_TERMINATOR;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Pack records back to back at the start of one zeroed sector.
    fn dir_sector(records: &[Vec<u8>]) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        let mut offset = 0;
        for record in records {
            sector[offset..offset + record.len()].copy_from_slice(record);
            offset += record.len();
        }
        sector
    }

    /// Whole primary-only fixture image bytes: descriptors at 16..19,
    /// root at 20 (`.`, `..`, `A/`, `ROOT.TXT;1`), `A/` at 21 (`.`,
    /// `..`, `B.TXT;1`, non-ASCII `CAFE.TXT;1`), file contents after.
    /// Synthetic layout only, claims nothing about real mastering tools.
    fn fixture_bytes() -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"A"),
                encode_record(FILE_ROOT_SECTOR, 5, 0, b"ROOT.TXT;1"),
            ]),
        );
        put(
            &mut image,
            DIR_A_SECTOR,
            &dir_sector(&[
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_B_SECTOR, 11, 0, b"B.TXT;1"),
                encode_record(FILE_CAFE_SECTOR, 3, 0, b"CAF\xC3\xA9.TXT;1"),
            ]),
        );
        put(&mut image, FILE_B_SECTOR, b"hello world");
        put(&mut image, FILE_ROOT_SECTOR, b"root!");
        put(&mut image, FILE_CAFE_SECTOR, &[1, 2, 3]);
        image
    }

    /// Whole Joliet fixture image bytes: the primary tree exactly as in
    /// [`fixture_bytes`], plus a level-1 Joliet supplementary descriptor
    /// at 17 (label `JOLI\u{c9}T VOL`, root at 25) with its own UCS-2BE
    /// directory tree sharing the primary file contents: root at 25
    /// (`.`, `..`, `a/`, `Root.txt;1`), `a/` at 26 (`.`, `..`,
    /// `b.txt;1`, `caf\u{e9}.txt;1`, `Sub./`), the sub-directory at 27.
    /// Synthetic layout only, claims nothing about real mastering tools.
    fn joliet_fixture_bytes() -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(
            &mut image,
            17,
            &joliet_sector(
                "JOLI\u{c9}T VOL",
                b"%/@",
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
            ),
        );
        put(&mut image, 18, &boot_sector());
        put(&mut image, 19, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"A"),
                encode_record(FILE_ROOT_SECTOR, 5, 0, b"ROOT.TXT;1"),
            ]),
        );
        put(
            &mut image,
            DIR_A_SECTOR,
            &dir_sector(&[
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_B_SECTOR, 11, 0, b"B.TXT;1"),
                encode_record(FILE_CAFE_SECTOR, 3, 0, b"CAF\xC3\xA9.TXT;1"),
            ]),
        );
        put(&mut image, FILE_B_SECTOR, b"hello world");
        put(&mut image, FILE_ROOT_SECTOR, b"root!");
        put(&mut image, FILE_CAFE_SECTOR, &[1, 2, 3]);
        put(
            &mut image,
            JOLIET_ROOT_SECTOR,
            &dir_sector(&[
                encode_record(
                    JOLIET_ROOT_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x00",
                ),
                encode_record(
                    JOLIET_ROOT_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x01",
                ),
                encode_joliet_record(JOLIET_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, "a"),
                encode_joliet_record(FILE_ROOT_SECTOR, 5, 0, "Root.txt;1"),
            ]),
        );
        put(
            &mut image,
            JOLIET_A_SECTOR,
            &dir_sector(&[
                encode_record(
                    JOLIET_A_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x00",
                ),
                encode_record(
                    JOLIET_ROOT_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x01",
                ),
                encode_joliet_record(FILE_B_SECTOR, 11, 0, "b.txt;1"),
                encode_joliet_record(FILE_CAFE_SECTOR, 3, 0, "caf\u{e9}.txt;1"),
                encode_joliet_record(
                    JOLIET_SUB_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    "Sub.",
                ),
            ]),
        );
        put(
            &mut image,
            JOLIET_SUB_SECTOR,
            &dir_sector(&[
                encode_record(
                    JOLIET_SUB_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x00",
                ),
                encode_record(
                    JOLIET_A_SECTOR,
                    SECTOR_BYTES as u32,
                    FLAG_DIRECTORY,
                    b"\x01",
                ),
            ]),
        );
        image
    }

    /// Fixture image opened as a reader.
    fn fixture_reader() -> IsoReader {
        let bytes = fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        IsoReader::open(Box::new(volume)).expect("the fixture opens")
    }

    /// Joliet fixture image opened as a reader (walks the Joliet tree).
    fn joliet_fixture_reader() -> IsoReader {
        let bytes = joliet_fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        IsoReader::open(Box::new(volume)).expect("the fixture opens")
    }

    /// Primary-only image with `root_records` packed as the root
    /// directory at sector 20 (32 sectors; contents stay zeroed — the
    /// multi-extent refusal tests fail before any file read).
    fn image_with_root(root_records: &[Vec<u8>]) -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(&mut image, ROOT_SECTOR, &dir_sector(root_records));
        image
    }

    /// Joliet image with `root_records` packed as the Joliet root
    /// directory at sector 25: a primary descriptor plus one level-3
    /// supplementary descriptor, so the reader walks the Joliet tree.
    /// The primary tree carries a minimal valid root that is never
    /// walked (the refusal tests fail before any primary read).
    fn joliet_image_with_root(root_records: &[Vec<u8>]) -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(
            &mut image,
            17,
            &joliet_sector("JOL", b"%/E", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 18, &boot_sector());
        put(&mut image, 19, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            ]),
        );
        put(&mut image, JOLIET_ROOT_SECTOR, &dir_sector(root_records));
        image
    }

    /// Image holding `descriptors` from sector 16 on (32 sectors, zeroed
    /// elsewhere): opening only parses descriptors, so no directory
    /// areas are needed for tree-selection tests.
    fn desc_only_image(descriptors: &[&[u8; SECTOR_BYTES]]) -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        for (index, descriptor) in descriptors.iter().enumerate() {
            let base = (16 + index) * SECTOR_BYTES;
            image[base..base + SECTOR_BYTES].copy_from_slice(*descriptor);
        }
        image
    }

    /// Reader over `bytes` (any synthetic variant the refusal tests
    /// need).
    fn reader_over(bytes: &[u8]) -> Result<IsoReader> {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the variant fits in RAM");
        volume.write_all_at(0, bytes).expect("the variant writes");
        IsoReader::open(Box::new(volume))
    }

    #[test]
    fn primary_only_image_walks_the_primary_tree() {
        let reader = fixture_reader();
        assert_eq!(reader.tree(), TreeKind::Primary);
        assert_eq!(reader.volume_label(), "LABEL");
        assert_eq!(reader.primary().label, "LABEL");
        assert_eq!(reader.volume_space_size(), IMAGE_SECTORS);
        assert_eq!(
            reader.total_bytes(),
            IMAGE_SECTORS as u64 * SECTOR_BYTES as u64
        );
        assert!(reader.supplementary().is_empty());
        assert_eq!(reader.boot_records().len(), 1);
        let root = reader.root();
        assert!(root.is_dir);
        assert_eq!(root.extents, vec![ROOT_SECTOR]);
        assert_eq!(root.identifier, b"");
    }

    #[test]
    fn nested_tree_lookup_by_path() {
        let reader = fixture_reader();
        let entry = reader.lookup("A/B.TXT").expect("A/B.TXT resolves");
        assert!(entry.is_file());
        assert_eq!(entry.extents, vec![FILE_B_SECTOR]);
        assert_eq!(entry.data_len, 11);
        assert_eq!(entry.identifier, b"B.TXT;1");
        assert_eq!(entry.file_name(), b"B.TXT");
        // A leading slash is optional; matching is byte-exact.
        assert_eq!(reader.lookup("/A/B.TXT"), Some(entry.clone()));
        assert!(reader.lookup("a/b.txt").is_none());
        assert!(reader.lookup("A/MISSING").is_none());
        assert!(reader.lookup("B.TXT/A").is_none());
    }

    #[test]
    fn read_dir_on_root_and_subdirectory() {
        let reader = fixture_reader();
        let mut root_names: Vec<Vec<u8>> = reader
            .read_dir("/")
            .expect("the root lists")
            .iter()
            .map(|entry| entry.file_name())
            .collect();
        root_names.sort();
        assert_eq!(root_names, vec![b"A".to_vec(), b"ROOT.TXT".to_vec()]);
        let mut a_names: Vec<Vec<u8>> = reader
            .read_dir("A")
            .expect("A lists")
            .iter()
            .map(|entry| entry.file_name())
            .collect();
        a_names.sort();
        assert_eq!(
            a_names,
            vec![b"B.TXT".to_vec(), b"CAF\xC3\xA9.TXT".to_vec()]
        );
    }

    #[test]
    fn version_suffix_stripped_and_non_ascii_preserved() {
        let reader = fixture_reader();
        let entries = reader.read_dir("A").expect("A lists");
        let cafe = entries
            .iter()
            .find(|entry| entry.file_name() == b"CAF\xC3\xA9.TXT")
            .expect("the non-ASCII name lists");
        assert_eq!(cafe.identifier, b"CAF\xC3\xA9.TXT;1");
        let entry = reader
            .lookup("A/CAF\u{00e9}.TXT")
            .expect("the non-ASCII path resolves byte-exactly");
        assert_eq!(entry, *cafe);
    }

    #[test]
    fn dot_entries_skipped_in_listings_but_resolve() {
        let reader = fixture_reader();
        for path in ["/", "A"] {
            let entries = reader.read_dir(path).expect("the directory lists");
            assert!(
                entries
                    .iter()
                    .all(|entry| !entry.identifier.as_slice().is_empty())
                    && entries.iter().all(|entry| entry.identifier != b"\x00")
                    && entries.iter().all(|entry| entry.identifier != b"\x01"),
                "no `.`/`..` in listings"
            );
        }
        // `.`/`..` still resolve for traversal.
        assert_eq!(reader.lookup("A/."), reader.lookup("A"));
        assert_eq!(reader.lookup("A/.."), Some(reader.root()));
        assert_eq!(reader.lookup("."), Some(reader.root()));
        assert_eq!(reader.lookup("/"), Some(reader.root()));
        assert_eq!(reader.lookup(""), Some(reader.root()));
        assert_eq!(
            reader
                .lookup("A/../ROOT.TXT")
                .expect("dot-dot resolves")
                .file_name(),
            b"ROOT.TXT"
        );
    }

    #[test]
    fn record_running_past_its_sector_refused() {
        let mut bytes = fixture_bytes();
        // Shrink the root directory to a partial sector so the last
        // record can genuinely overrun it: only the first 150 bytes of
        // sector 20 carry records (a full-sector record can never claim
        // past 2048 with one length byte).
        let desc_base = 16 * SECTOR_BYTES;
        let root_at = desc_base + 156;
        bytes[root_at + 10..root_at + 14].copy_from_slice(&150u32.to_le_bytes());
        bytes[root_at + 14..root_at + 18].copy_from_slice(&150u32.to_be_bytes());
        // Corrupt the last root record (ROOT.TXT;1) to claim 60 bytes:
        // it starts at offset 102, so 102 + 60 runs past the 150 valid
        // bytes. Found by its identifier tail, like the tests below.
        let base = ROOT_SECTOR as usize * SECTOR_BYTES;
        let window = base..base + SECTOR_BYTES;
        let needle = b"ROOT.TXT;1";
        let start = bytes[window]
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("ROOT.TXT is there");
        let record_start = base + start - RECORD_FIXED_LEN;
        bytes[record_start] = 60;
        let reader = reader_over(&bytes).expect("descriptors still parse");
        let error = reader.read_dir("/").expect_err("the overrun refuses");
        let text = error.to_string();
        assert!(text.contains("60"), "{text}");
        assert!(text.contains("straddle"), "{text}");
    }

    #[test]
    fn interleave_refused() {
        let mut bytes = fixture_bytes();
        // Set file unit size 1 on the B.TXT record in directory A: find
        // the record by its identifier tail.
        let base = DIR_A_SECTOR as usize * SECTOR_BYTES;
        let window = base..base + SECTOR_BYTES;
        let needle = b"B.TXT;1";
        let start = bytes[window]
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("B.TXT is there");
        // The identifier starts at record offset 33, so the record starts
        // RECORD_FIXED_LEN bytes before the identifier.
        let record_start = base + start - RECORD_FIXED_LEN;
        bytes[record_start + 26] = 1;
        let reader = reader_over(&bytes).expect("descriptors still parse");
        assert!(reader.lookup("A/B.TXT").is_none());
        let error = reader.read_dir("A").expect_err("interleave refuses");
        let text = error.to_string();
        assert!(
            text.contains("interleaved files are not supported"),
            "{text}"
        );
    }

    #[test]
    fn lone_multi_extent_flag_refused_as_truncated() {
        let mut bytes = fixture_bytes();
        let base = DIR_A_SECTOR as usize * SECTOR_BYTES;
        let window = base..base + SECTOR_BYTES;
        let needle = b"B.TXT;1";
        let start = bytes[window]
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("B.TXT is there");
        let record_start = base + start - RECORD_FIXED_LEN;
        bytes[record_start + 25] |= FLAG_MULTI_EXTENT;
        let reader = reader_over(&bytes).expect("descriptors still parse");
        assert!(reader.lookup("A/B.TXT").is_none());
        let error = reader
            .open_file("A/B.TXT")
            .expect_err("a lone flagged record is a truncated chain");
        let text = error.to_string();
        assert!(text.contains("A/B.TXT"), "{text}");
        assert!(text.contains("truncated"), "{text}");
    }

    #[test]
    fn truncated_volume_refused() {
        // Cut the image before B.TXT's extent: directory A still parses,
        // but the file data is gone.
        let bytes = fixture_bytes();
        let cut = (bytes.len() - 3 * SECTOR_BYTES).min(FILE_B_SECTOR as usize * SECTOR_BYTES);
        let short = &bytes[..cut];
        let reader = reader_over(short).expect("descriptors still parse");
        let error = reader.read_file("A/B.TXT").expect_err("the cut refuses");
        let text = error.to_string();
        assert!(text.contains("truncated"), "{text}");
        assert!(text.contains(FILE_B_SECTOR.to_string().as_str()), "{text}");
    }

    #[test]
    fn dotdot_above_the_root_refused() {
        let reader = fixture_reader();
        assert!(reader.lookup("../X").is_none());
        assert!(reader.lookup("A/../../X").is_none());
        let error = reader.read_dir("..").expect_err("above the root refuses");
        let text = error.to_string();
        assert!(text.contains("above the root"), "{text}");
    }

    #[test]
    fn empty_segments_refused() {
        let reader = fixture_reader();
        assert!(reader.lookup("A//B.TXT").is_none());
        let error = reader
            .read_dir("A//B.TXT")
            .expect_err("empty segment refuses");
        assert!(error.to_string().contains("empty segment"), "{error}");
        let error = reader.read_dir("/A/").expect_err("trailing slash refuses");
        assert!(error.to_string().contains("empty segment"), "{error}");
    }

    #[test]
    fn open_and_read_files() {
        let reader = fixture_reader();
        assert_eq!(
            reader.read_file("A/B.TXT").expect("B.TXT reads"),
            b"hello world"
        );
        assert_eq!(
            reader.read_file("/ROOT.TXT").expect("ROOT.TXT reads"),
            b"root!"
        );
        let open = reader.open_file("A/B.TXT").expect("B.TXT opens");
        assert_eq!(open.len(), 11);
        assert!(!open.is_empty());
        assert_eq!(open.file_name(), b"B.TXT");
        assert_eq!(
            reader.read_open(&open).expect("the handle reads"),
            b"hello world"
        );
        let error = reader
            .open_file("A")
            .expect_err("a directory never opens as a file");
        assert!(error.to_string().contains("directory"), "{error}");
        let error = reader.read_dir("A/B.TXT").expect_err("a file never lists");
        assert!(error.to_string().contains("not a directory"), "{error}");
        let error = reader.open_file("A/MISSING").expect_err("missing refuses");
        assert!(error.to_string().contains("not found"), "{error}");
    }

    #[test]
    fn looping_directory_refused_past_the_depth_bound() {
        // Directory L points at itself: L/L/.../L nests forever without
        // the bound.
        let loop_sector: u32 = 25;
        let mut image = vec![0u8; IMAGE_SECTORS as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LOOP", ROOT_SECTOR, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(
            &mut image,
            ROOT_SECTOR,
            &dir_sector(&[
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(loop_sector, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"L"),
            ]),
        );
        put(
            &mut image,
            loop_sector,
            &dir_sector(&[
                encode_record(loop_sector, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(loop_sector, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"L"),
            ]),
        );
        let reader = reader_over(&image).expect("descriptors still parse");
        let deep = (0..40).map(|_| "L").collect::<Vec<_>>().join("/");
        assert!(reader.lookup(&deep).is_none());
        let error = reader.read_dir(&deep).expect_err("the loop refuses");
        let text = error.to_string();
        assert!(text.contains("32"), "{text}");
        assert!(text.contains("loop"), "{text}");
    }

    #[test]
    fn wrong_identifier_refused_at_open() {
        let mut bytes = fixture_bytes();
        bytes[16 * SECTOR_BYTES + 1..16 * SECTOR_BYTES + 6].copy_from_slice(b"XX001");
        let error = reader_over(&bytes).expect_err("XX001 refuses the open");
        assert!(error.to_string().contains("CD001"), "{error}");
    }

    #[test]
    fn missing_terminator_refused_at_open() {
        let mut bytes = fixture_bytes();
        // Blank the terminator sector (18 here: this fixture is
        // primary-only, with the boot record at 17): the sequence then
        // runs into zeroed sectors, whose blank identifier refuses.
        for byte in bytes.iter_mut().skip(18 * SECTOR_BYTES).take(SECTOR_BYTES) {
            *byte = 0;
        }
        let error = reader_over(&bytes).expect_err("no terminator refuses the open");
        let text = error.to_string();
        assert!(text.contains("18") || text.contains("CD001"), "{text}");
    }

    #[test]
    fn joliet_tree_names_differ_from_primary() {
        let reader = joliet_fixture_reader();
        assert_eq!(reader.tree(), TreeKind::Joliet { level: 1 });
        // The primary descriptor stays available on the reader.
        assert_eq!(reader.primary().label, "LABEL");
        assert_eq!(reader.supplementary().len(), 1);
        // Joliet names resolve; the primary spellings do not.
        let entry = reader.lookup("a/b.txt").expect("the Joliet path resolves");
        assert!(entry.is_file());
        assert_eq!(entry.extents, vec![FILE_B_SECTOR]);
        assert_eq!(entry.file_name(), b"b.txt".to_vec());
        assert!(reader.lookup("A/B.TXT").is_none());
        assert!(reader.lookup("a/B.TXT").is_none());
        let mut names: Vec<Vec<u8>> = reader
            .read_dir("a")
            .expect("a lists")
            .iter()
            .map(|entry| entry.file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "Sub".as_bytes().to_vec(),
                b"b.txt".to_vec(),
                "caf\u{e9}.txt".as_bytes().to_vec(),
            ]
        );
        let mut root_names: Vec<Vec<u8>> = reader
            .read_dir("/")
            .expect("the root lists")
            .iter()
            .map(|entry| entry.file_name())
            .collect();
        root_names.sort();
        assert_eq!(root_names, vec![b"Root.txt".to_vec(), b"a".to_vec()]);
    }

    #[test]
    fn joliet_label_read_from_the_chosen_tree() {
        let reader = joliet_fixture_reader();
        assert_eq!(reader.volume_label(), "JOLI\u{c9}T VOL");
    }

    #[test]
    fn highest_joliet_level_wins_with_first_kept_on_ties() {
        let primary = primary_sector("LABEL", ROOT_SECTOR, SECTOR_BYTES as u32);
        let low = joliet_sector("LOW", b"%/@", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let mid = joliet_sector("MID", b"%/C", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let high = joliet_sector("HIGH", b"%/E", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let terminator = terminator_sector();
        // Sequence order L1, L3, L2: level 3 wins whatever the order.
        let image = desc_only_image(&[&primary, &low, &high, &mid, &terminator]);
        let reader = reader_over(&image).expect("three levels parse");
        assert_eq!(reader.tree(), TreeKind::Joliet { level: 3 });
        assert_eq!(reader.volume_label(), "HIGH");
        // Ties keep the first descriptor in sequence order.
        let first = joliet_sector("FIRST", b"%/C", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let second = joliet_sector("SECOND", b"%/C", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let image = desc_only_image(&[&primary, &first, &second, &terminator]);
        let reader = reader_over(&image).expect("tied levels parse");
        assert_eq!(reader.tree(), TreeKind::Joliet { level: 2 });
        assert_eq!(reader.volume_label(), "FIRST");
        // A supplementary descriptor without a Joliet opening is kept
        // but never walked: the primary tree stays chosen.
        let plain = joliet_sector("PLAIN", b"", JOLIET_ROOT_SECTOR, SECTOR_BYTES as u32);
        let image = desc_only_image(&[&primary, &plain, &terminator]);
        let reader = reader_over(&image).expect("a plain supplementary parses");
        assert_eq!(reader.tree(), TreeKind::Primary);
        assert_eq!(reader.volume_label(), "LABEL");
        assert_eq!(reader.supplementary().len(), 1);
        assert_eq!(reader.supplementary()[0].joliet_level, None);
    }

    #[test]
    fn joliet_version_suffix_stripped_on_decoded_text() {
        let reader = joliet_fixture_reader();
        let entry = reader.lookup("a/b.txt").expect("b.txt resolves");
        assert_eq!(entry.identifier, ucs2("b.txt;1"));
        assert_eq!(entry.file_name(), b"b.txt".to_vec());
        // One trailing dot strips on the decoded text too.
        let sub = reader.lookup("a/Sub").expect("Sub. resolves as Sub");
        assert!(sub.is_dir);
        assert_eq!(sub.file_name(), b"Sub".to_vec());
    }

    #[test]
    fn odd_length_joliet_name_refused() {
        // A one-byte identifier is odd, so UCS-2BE decoding refuses it.
        let image = joliet_image_with_root(&[
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x00",
            ),
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x01",
            ),
            encode_record(FILE_B_SECTOR, 11, 0, b"X"),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        assert!(reader.lookup("X").is_none());
        let error = reader.read_dir("/").expect_err("the odd name refuses");
        let text = error.to_string();
        assert!(text.contains('/'), "{text}");
        assert!(text.contains("odd"), "{text}");
    }

    #[test]
    fn unpaired_surrogate_joliet_name_refused() {
        // Lone high surrogate D800 with no low surrogate following it.
        let image = joliet_image_with_root(&[
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x00",
            ),
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x01",
            ),
            encode_record(FILE_B_SECTOR, 11, 0, &[0xD8, 0x00]),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        assert!(reader.lookup("X").is_none());
        let error = reader
            .read_dir("/")
            .expect_err("the lone surrogate refuses");
        let text = error.to_string();
        assert!(text.contains("surrogate"), "{text}");
        assert!(text.contains('0'), "{text}");
    }

    #[test]
    fn nul_inside_joliet_name_refused() {
        // "A", NUL, "B" as UCS-2BE units: the interior NUL refuses.
        let image = joliet_image_with_root(&[
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x00",
            ),
            encode_record(
                JOLIET_ROOT_SECTOR,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY,
                b"\x01",
            ),
            encode_record(FILE_B_SECTOR, 11, 0, &[0, b'A', 0, 0, 0, b'B']),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        let error = reader.read_dir("/").expect_err("the interior NUL refuses");
        let text = error.to_string();
        assert!(text.contains("NUL"), "{text}");
        assert!(text.contains('2'), "{text}");
    }

    #[test]
    fn two_extent_file_joined_and_read_across_the_join() {
        let mut image = image_with_root(&[
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(28, 100, FLAG_MULTI_EXTENT, b"BIG.DAT;1"),
            encode_record(29, 50, 0, b"BIG.DAT;1"),
        ]);
        for byte in image.iter_mut().skip(28 * SECTOR_BYTES).take(100) {
            *byte = 0x41;
        }
        for byte in image.iter_mut().skip(29 * SECTOR_BYTES).take(50) {
            *byte = 0x42;
        }
        let reader = reader_over(&image).expect("descriptors still parse");
        let open = reader.open_file("BIG.DAT").expect("the chain joins");
        assert_eq!(open.extents, vec![(28, 100), (29, 50)]);
        assert_eq!(open.len(), 150);
        assert_eq!(open.file_name(), b"BIG.DAT".to_vec());
        let bytes = reader.read_file("BIG.DAT").expect("the join reads");
        assert_eq!(bytes.len(), 150);
        assert!(
            bytes[..100].iter().all(|byte| *byte == 0x41),
            "the first extent comes first"
        );
        assert!(
            bytes[100..].iter().all(|byte| *byte == 0x42),
            "the second extent is appended"
        );
        let entry = reader.lookup("BIG.DAT").expect("the join looks up");
        assert_eq!(entry.extents, vec![28, 29]);
        assert_eq!(entry.data_len, 150);
        let listed = reader.read_dir("/").expect("the root lists the join once");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], entry);
    }

    #[test]
    fn non_adjacent_chain_refused() {
        let image = image_with_root(&[
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(28, 10, FLAG_MULTI_EXTENT, b"SPLIT.DAT;1"),
            encode_record(29, 10, 0, b"OTHER.DAT;1"),
            encode_record(30, 10, 0, b"SPLIT.DAT;1"),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        assert!(reader.lookup("SPLIT.DAT").is_none());
        let error = reader
            .open_file("SPLIT.DAT")
            .expect_err("the split chain refuses");
        let text = error.to_string();
        assert!(text.contains("SPLIT.DAT"), "{text}");
        assert!(text.contains("adjacent"), "{text}");
    }

    #[test]
    fn multi_extent_directory_refused() {
        let image = image_with_root(&[
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(
                28,
                SECTOR_BYTES as u32,
                FLAG_DIRECTORY | FLAG_MULTI_EXTENT,
                b"D",
            ),
            encode_record(29, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"D"),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        let error = reader
            .open_file("D")
            .expect_err("a multi-extent directory refuses");
        assert!(
            error.to_string().contains("multi-extent directory"),
            "{error}"
        );
        let error = reader.read_dir("/").expect_err("listing refuses too");
        assert!(
            error.to_string().contains("multi-extent directory"),
            "{error}"
        );
    }

    #[test]
    fn overflowing_multi_extent_total_refused() {
        let image = image_with_root(&[
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(28, u32::MAX, FLAG_MULTI_EXTENT, b"HUGE.DAT;1"),
            encode_record(29, 1, 0, b"HUGE.DAT;1"),
        ]);
        let reader = reader_over(&image).expect("descriptors still parse");
        let error = reader
            .open_file("HUGE.DAT")
            .expect_err("the overflowing total refuses");
        let text = error.to_string();
        assert!(text.contains("HUGE.DAT"), "{text}");
        assert!(text.contains("overflows"), "{text}");
    }
}
