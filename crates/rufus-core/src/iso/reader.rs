//! Primary-tree reader: label, lookup, listings and file reads (S14,
//! slice 1).
//!
//! *Measured* — everything here walks the structures [`descriptor`] and
//! [`record`] parse, over sectors the [`SectorCache`](crate::iso::SectorCache)
//! serves: path segments match stripped identifiers byte-exactly,
//! `.`/`..` records never appear in listings but `..` traversal resolves,
//! and file bytes come from the recorded extent through the cache.
//!
//! *Inferred* — that byte-exact matching is what users want (no case
//! folding: ECMA-119 names are uppercase by construction, and folding
//! would corrupt the non-ASCII bytes slice 2 decodes), and that loading
//! a whole file into RAM in `read_file` is acceptable for slice 1 (a
//! streaming read belongs to a later slice; huge files fail gracefully
//! through `try_reserve`, never with a panicking allocator call).
//!
//! Refusals, not panics: multi-extent records refuse naming the path
//! (slice 2 joins the extents), `..` past the root refuses, empty path
//! segments refuse, nesting past [`MAX_DIR_DEPTH`](crate::iso::MAX_DIR_DEPTH)
//! refuses as a possible directory loop, and any extent running past the
//! volume end refuses as truncation. A directory whose length is not a
//! sector multiple reads its last partial sector (only the valid prefix
//! carries records, per ECMA-119); a volume cut inside that sector
//! refuses, because the sector is not fully present.

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
use crate::iso::descriptor::SupplementaryDescriptor;
use crate::iso::descriptor::read_descriptor_set;
use crate::iso::record::DirRecord;
use crate::iso::record::parse_records;
use crate::iso::record::strip_version;
use crate::text::device_text;

/// One directory entry: the full identifier plus the extent, the length
/// and the raw recording date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Full identifier bytes exactly as stored (including any `;1`
    /// version suffix — see [`Entry::file_name`] for the stripped form).
    /// Empty for the root (which has no name).
    pub identifier: Vec<u8>,
    /// True for directories (flag bit 1), false for files.
    pub is_dir: bool,
    /// Logical sector number of the file or directory data.
    pub extent_lba: u32,
    /// Data length in bytes.
    pub data_len: u32,
    /// Raw 7-byte recording date, kept for a later slice to decode.
    pub recorded: [u8; 7],
    /// Raw flag byte (hidden, associated and multi-extent bits survive
    /// here for later slices).
    pub flags: u8,
}

impl Entry {
    /// Display/matching form of the identifier: the `;1` version suffix
    /// and one trailing `.` stripped, the rest byte-exact.
    #[must_use]
    pub fn file_name(&self) -> Vec<u8> {
        strip_version(&self.identifier)
    }

    /// True for files (convenience inverse of [`Entry::is_dir`]).
    #[must_use]
    pub fn is_file(&self) -> bool {
        !self.is_dir
    }
}

impl From<&DirRecord> for Entry {
    /// The record's full identifier, directory bit, extent, length, raw
    /// date and raw flags.
    fn from(record: &DirRecord) -> Self {
        Self {
            identifier: record.identifier.clone(),
            is_dir: record.is_dir(),
            extent_lba: record.extent_lba,
            data_len: record.data_len,
            recorded: record.recorded,
            flags: record.flags,
        }
    }
}

/// An opened file: the extent and length to read, plus the identifier
/// for error messages. Read it with [`IsoReader::read_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    /// Logical sector number of the file data.
    pub extent_lba: u32,
    /// File length in bytes.
    pub size: u32,
    /// Full identifier bytes, for error messages only.
    pub identifier: Vec<u8>,
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

    /// Display form of the identifier (suffix stripped, byte-exact).
    #[must_use]
    pub fn file_name(&self) -> Vec<u8> {
        strip_version(&self.identifier)
    }
}

/// One path component after splitting: `.`, `..`, or a name matched
/// byte-exactly against stripped identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    /// `.`: stay in the current directory.
    Current,
    /// `..`: move to the parent directory (refused at the root).
    Parent,
    /// A name segment (`&str` bytes, never empty).
    Name(Vec<u8>),
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
            out.push(Component::Name(segment.as_bytes().to_vec()));
        }
    }
    Ok(out)
}

/// ISO9660 primary-tree reader over an owned byte store.
#[derive(Debug)]
pub struct IsoReader {
    /// Sector cache (behind a cell so every API takes `&self`; the
    /// borrow is statement-scoped and never re-entered, and a
    /// still-borrowed cache refuses instead of panicking). The cell
    /// keeps the reader single-threaded (`!Sync`): sharing one across
    /// threads would need a `Mutex`, left for a later slice.
    cache: RefCell<SectorCache>,
    /// Volume identifier from the primary descriptor.
    label: String,
    /// Volume space size in logical sectors, from the primary.
    volume_space_size: u32,
    /// Total store extent in bytes, for window checks with context.
    total_bytes: u64,
    /// Root directory record from the primary descriptor.
    root_record: DirRecord,
    /// Supplementary descriptors, kept for slice 2 (Joliet decoding).
    supplementary: Vec<SupplementaryDescriptor>,
    /// Boot records, retained and never executed.
    boot_records: Vec<BootRecord>,
}

impl IsoReader {
    /// Open the image `volume`: parse the descriptor sequence from
    /// sector 16 and retain the primary, the supplementary descriptors
    /// and the boot records. Any malformed sequence refuses here, before
    /// any path is resolved.
    pub fn open(volume: Box<dyn Volume>) -> Result<Self> {
        let total_bytes = volume.total_bytes();
        let mut cache = SectorCache::new(volume);
        let set = read_descriptor_set(&mut cache)?;
        Ok(Self {
            cache: RefCell::new(cache),
            label: set.primary.label,
            volume_space_size: set.primary.volume_space_size,
            total_bytes,
            root_record: set.primary.root,
            supplementary: set.supplementary,
            boot_records: set.boot_records,
        })
    }

    /// Volume label: the primary descriptor's 32-byte volume identifier
    /// with trailing spaces trimmed.
    #[must_use]
    pub fn volume_label(&self) -> &str {
        &self.label
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

    /// Supplementary descriptors in sequence order, kept for slice 2
    /// (Joliet decoding and the supplementary trees).
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
        let mut entry = Entry::from(&self.root_record);
        entry.identifier = Vec::new();
        entry
    }

    /// Look up `path` (leading `/` optional, `.`/`..` allowed):
    /// `Some` entry for files and directories alike, `None` when the
    /// path does not resolve — not found, climbs above the root, has an
    /// empty segment, or hits any traversal refusal (use [`IsoReader::read_dir`]
    /// or [`IsoReader::open_file`] for the refusal text). The reason is
    /// collapsed here on purpose; slice 2's Joliet walk may need the
    /// distinction, which the `Result` APIs already report.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<Entry> {
        match self.resolve(path) {
            // The root record compares equal to itself (a byte-identical
            // duplicate reachable by name cannot exist: `find_child`
            // never returns the `.`/`..` records, and only dot-component
            // traversal ends back at the root).
            Ok(record) if record == self.root_record => Some(self.root()),
            Ok(record) => Some(Entry::from(&record)),
            Err(_) => None,
        }
    }

    /// List the directory at `path`: the `.`/`..` records are skipped,
    /// everything else comes back with full identifiers. Refuses paths
    /// that do not resolve, that resolve to a file, and any malformed
    /// directory data, naming the path.
    pub fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let record = self.resolve(path)?;
        if !record.is_dir() {
            return Err(CoreError::invalid(format!(
                "cannot list `{}`: it is a file, not a directory",
                short_path(path)
            )));
        }
        let records = self.read_dir_records(&record).map_err(|error| {
            CoreError::invalid(format!("cannot list `{}`: {error}", short_path(path)))
        })?;
        let mut out = Vec::new();
        for child in &records {
            if child.is_dot() || child.is_parent() {
                continue;
            }
            out.push(Entry::from(child));
        }
        Ok(out)
    }

    /// Open the file at `path` for reading with [`IsoReader::read_open`].
    /// Refuses directories, missing paths and multi-extent files (slice
    /// 2 joins the extents), naming the path.
    pub fn open_file(&self, path: &str) -> Result<OpenFile> {
        let record = self.resolve(path)?;
        if record.is_dir() {
            return Err(CoreError::invalid(format!(
                "cannot open `{}`: it is a directory, not a file",
                short_path(path)
            )));
        }
        Ok(OpenFile {
            extent_lba: record.extent_lba,
            size: record.data_len,
            identifier: record.identifier,
        })
    }

    /// Read the whole file at `path` into RAM.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let file = self.open_file(path)?;
        self.read_open(&file).map_err(|error| {
            CoreError::invalid(format!("cannot read `{}`: {error}", short_path(path)))
        })
    }

    /// Read the whole opened file into RAM through the sector cache.
    /// An empty file reads nothing; any extent running past the store
    /// extent (`total_bytes`, not the declared volume space size)
    /// refuses as truncation with the numbers named.
    pub fn read_open(&self, file: &OpenFile) -> Result<Vec<u8>> {
        let size = u64::from(file.size);
        if size == 0 {
            return Ok(Vec::new());
        }
        let start = u64::from(file.extent_lba)
            .checked_mul(SECTOR_BYTES_U64)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "file extent {} overflows the byte offset arithmetic",
                    file.extent_lba
                ))
            })?;
        let end = start.checked_add(size).ok_or_else(|| {
            CoreError::invalid(format!(
                "file of {size} bytes at extent {} overflows the byte offset arithmetic",
                file.extent_lba
            ))
        })?;
        if end > self.total_bytes {
            return Err(CoreError::invalid(format!(
                "file of {size} bytes at extent {} (bytes {start}..{end}) runs past \
                 the {} byte volume end: the volume is truncated",
                file.extent_lba, self.total_bytes
            )));
        }
        let mut out = Vec::new();
        out.try_reserve(size as usize).map_err(|_| {
            CoreError::invalid(format!(
                "file of {size} bytes cannot be buffered: the allocation failed"
            ))
        })?;
        out.resize(size as usize, 0);
        let count = size.div_ceil(SECTOR_BYTES_U64);
        let mut pos: usize = 0;
        let mut remaining = size;
        for index in 0..count {
            let sector_no = file.extent_lba.checked_add(index as u32).ok_or_else(|| {
                CoreError::invalid(format!(
                    "file extent {} plus sector {index} overflows the sector number",
                    file.extent_lba
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
        Ok(out)
    }

    /// Resolve `path` to its directory record, following `.`/`..` and
    /// descending into directories. Multi-extent records refuse naming
    /// the path; nesting past [`MAX_DIR_DEPTH`](crate::iso::MAX_DIR_DEPTH)
    /// refuses as a possible directory loop; `..` past the root refuses.
    fn resolve(&self, path: &str) -> Result<DirRecord> {
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
                    let child = self.find_child(&current, want, path)?;
                    if child.is_multi_extent() {
                        return Err(CoreError::invalid(format!(
                            "path `{}` is a multi-extent file: joining extents is not \
                             supported in this slice",
                            short_path(path)
                        )));
                    }
                    let last = index + 1 == total;
                    if last {
                        return Ok(child);
                    }
                    if !child.is_dir() {
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
                    current = child;
                }
            }
        }
        Ok(current)
    }

    /// The child of directory `dir` whose stripped identifier matches
    /// `want` byte-exactly (`.`/`..` records never match). Refuses
    /// naming the path and the wanted name when absent or unreadable.
    fn find_child(&self, dir: &DirRecord, want: &[u8], path: &str) -> Result<DirRecord> {
        let records = self.read_dir_records(dir).map_err(|error| {
            CoreError::invalid(format!("cannot resolve `{}`: {error}", short_path(path)))
        })?;
        for record in &records {
            if record.is_dot() || record.is_parent() {
                continue;
            }
            if strip_version(&record.identifier).as_slice() == want {
                return Ok(record.clone());
            }
        }
        Err(CoreError::invalid(format!(
            "path `{}` not found: no entry matches `{}`",
            short_path(path),
            short_segment(&String::from_utf8_lossy(want))
        )))
    }

    /// Every record in directory `dir` (including `.`/`..` — callers
    /// filter): whole sectors through the cache, with the last partial
    /// sector limited to its valid prefix.
    fn read_dir_records(&self, dir: &DirRecord) -> Result<Vec<DirRecord>> {
        if dir.is_multi_extent() {
            return Err(CoreError::invalid(format!(
                "directory at extent {} is multi-extent: joining extents is not \
                 supported in this slice",
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

    /// Supplementary-descriptor sector with a Joliet level-1 escape.
    fn supplementary_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = primary_sector("SUPP", ROOT_SECTOR, SECTOR_BYTES as u32);
        sector[0] = TYPE_SUPPLEMENTARY;
        sector[88..91].copy_from_slice(b"%/@");
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

    /// Whole fixture image bytes: descriptors at 16..20, root at 20
    /// (`.`, `..`, `A/`, `ROOT.TXT;1`), `A/` at 21 (`.`, `..`,
    /// `B.TXT;1`, non-ASCII `CAFE.TXT;1`), file contents after.
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
        put(&mut image, 17, &supplementary_sector());
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

    /// Reader over `bytes` (any synthetic variant the refusal tests
    /// need).
    fn reader_over(bytes: &[u8]) -> Result<IsoReader> {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the variant fits in RAM");
        volume.write_all_at(0, bytes).expect("the variant writes");
        IsoReader::open(Box::new(volume))
    }

    #[test]
    fn fixture_opens_with_label_and_kept_supplementary() {
        let reader = fixture_reader();
        assert_eq!(reader.volume_label(), "LABEL");
        assert_eq!(reader.volume_space_size(), IMAGE_SECTORS);
        assert_eq!(
            reader.total_bytes(),
            IMAGE_SECTORS as u64 * SECTOR_BYTES as u64
        );
        assert_eq!(reader.supplementary().len(), 1);
        assert_eq!(reader.supplementary()[0].joliet_level, Some(1));
        assert_eq!(reader.boot_records().len(), 1);
        let root = reader.root();
        assert!(root.is_dir);
        assert_eq!(root.extent_lba, ROOT_SECTOR);
        assert_eq!(root.identifier, b"");
    }

    #[test]
    fn nested_tree_lookup_by_path() {
        let reader = fixture_reader();
        let entry = reader.lookup("A/B.TXT").expect("A/B.TXT resolves");
        assert!(entry.is_file());
        assert_eq!(entry.extent_lba, FILE_B_SECTOR);
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
    fn multi_extent_refused_naming_the_path() {
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
            .expect_err("multi-extent refuses");
        let text = error.to_string();
        assert!(text.contains("A/B.TXT"), "{text}");
        assert!(text.contains("multi-extent"), "{text}");
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
        put(&mut image, 17, &supplementary_sector());
        put(&mut image, 18, &boot_sector());
        put(&mut image, 19, &terminator_sector());
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
        // Blank the terminator sector: the sequence then runs into zeroed
        // sectors, whose blank identifier refuses.
        for byte in bytes.iter_mut().skip(19 * SECTOR_BYTES).take(SECTOR_BYTES) {
            *byte = 0;
        }
        let error = reader_over(&bytes).expect_err("no terminator refuses the open");
        let text = error.to_string();
        assert!(text.contains("19") || text.contains("CD001"), "{text}");
    }
}
