//! Who supplies the bytes the copy walks: a path-addressed view over
//! one ISO or UDF tree.
//!
//! [`Source`] is deliberately narrow — root listing, children of one
//! directory, an entry's name/kind/size, and a chunked read of a
//! file's bytes — because that is all [`walk`](super::walk) needs.
//! Paths are stacks of raw name bytes (`&[Vec<u8>]`, relative to the
//! root): byte stacks round-trip UDF's decoded names exactly, while
//! the ISO adapter renders the reader's `/`-separated path form from
//! them (see [`IsoSource`] for that fidelity boundary).
//!
//! What is NOT here yet, by slice plan: entry metadata (modes,
//! stamps, link targets) and symlinks. Part A found those fields on
//! both readers (`Entry::symlink_target`/`posix`/`times` on ISO,
//! `FileEntry::file_type` on UDF) but slices 3-4 decide their
//! handling — this slice copies data only, so an entry the adapters
//! cannot size as data refuses here, before any byte moves, instead
//! of copying something wrong.

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::IsoReader;
use crate::udf::UdfReader;

/// One listed entry: name, kind and size. Metadata (modes, stamps,
/// link targets) is deliberately absent — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// File name as stored: raw identifier bytes on ISO
    /// ([`file_name`](crate::iso::reader::Entry::file_name)), UTF-8 on
    /// UDF.
    pub name: Vec<u8>,
    /// True for directories.
    pub is_dir: bool,
    /// File size in bytes; 0 for directories.
    pub size: u64,
}

/// A readable filesystem tree: listings plus chunked file reads. The
/// adapters below are thin — they translate listings and resolve
/// paths, and every byte still comes from the reader they wrap.
pub trait Source {
    /// Children of the root directory, in store order (the caller
    /// sorts).
    fn root_entries(&self) -> Result<Vec<Entry>>;

    /// Children of the directory at `dir` (name bytes from the root),
    /// in store order (the caller sorts).
    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>>;

    /// Read up to `buf.len()` bytes of the file at `file` (name bytes
    /// from the root) at `offset`: returns the bytes placed, 0 at end
    /// of file. Refuses offsets past the length, naming both.
    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// [`Source`] over an [`IsoReader`]: listings translate
/// [`Entry`](crate::iso::reader::Entry) runs 1:1 (store order kept,
/// `.`/`..` already skipped by the reader), sizes come from the
/// joined `data_len`, and reads stream through `open_file` plus
/// `read_open_at` without ever buffering a whole file.
///
/// Two fidelity boundaries, both inherited from the reader, never
/// invented here: paths render in the reader's `/`-separated form
/// (names that are not valid UTF-8 cannot round-trip through its
/// `&str` lookup — the same lossy boundary its `walk` documents),
/// and Rock Ridge alternate names resolve like the reader resolves
/// them (preferred on a SUSP volume). Symlinks refuse at listing
/// time: they are never followed, and a silent skip would lose data.
#[derive(Debug)]
pub struct IsoSource {
    reader: IsoReader,
}

impl IsoSource {
    /// Wrap an opened [`IsoReader`].
    pub fn new(reader: IsoReader) -> Self {
        Self { reader }
    }

    /// The reader's `/`-separated path form for `dir` (empty means
    /// the root).
    fn path_str(dir: &[Vec<u8>]) -> String {
        let mut path = String::new();
        for component in dir {
            path.push('/');
            path.push_str(&String::from_utf8_lossy(component));
        }
        if path.is_empty() {
            path.push('/');
        }
        path
    }

    /// Translate one reader listing, refusing symlink entries: they
    /// are never followed, and skipping them would lose data.
    fn translate(&self, entries: Vec<crate::iso::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            if entry.symlink_target.is_some() {
                return Err(CoreError::invalid(format!(
                    "copy refuses '{}': it is a symbolic link, and this slice copies data only",
                    String::from_utf8_lossy(&entry.file_name())
                )));
            }
            out.push(Entry {
                name: entry.file_name(),
                is_dir: entry.is_dir,
                size: if entry.is_dir {
                    0
                } else {
                    u64::from(entry.data_len)
                },
            });
        }
        Ok(out)
    }
}

impl Source for IsoSource {
    fn root_entries(&self) -> Result<Vec<Entry>> {
        self.translate(self.reader.read_dir("/")?)
    }

    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
        self.translate(self.reader.read_dir(&Self::path_str(dir))?)
    }

    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let path = Self::path_str(file);
        let handle = self.reader.open_file(&path)?;
        self.reader
            .read_open_at(&handle, offset, buf)
            .map_err(|error| {
                CoreError::invalid(format!("cannot read `{path}` at offset {offset}: {error}"))
            })
    }
}

/// [`Source`] over a [`UdfReader`]: paths resolve by descending from
/// the root matching exact name bytes (UDF names are decoded strings,
/// so the round trip is exact), sizes come from the opened file's
/// information length, and reads stream through `open_file` plus
/// `read_open_at` without ever buffering a whole file.
///
/// Entries the reader cannot open as data (symlinks, FIFOs and the
/// rest — each refuses with its kind named) fail the listing that
/// contains them: failing fast before any byte moves, exactly like
/// the ISO side's symlink refusal.
#[derive(Debug)]
pub struct UdfSource {
    reader: UdfReader,
}

impl UdfSource {
    /// Wrap an opened [`UdfReader`].
    pub fn new(reader: UdfReader) -> Self {
        Self { reader }
    }

    /// Resolve `dir` (name bytes from the root) to its reader entry by
    /// descending from the root; an empty path is the root itself.
    fn resolve(&self, dir: &[Vec<u8>]) -> Result<crate::udf::reader::Entry> {
        let mut current = self.reader.root();
        for component in dir {
            let children = self.reader.read_dir(&current)?;
            let next = children
                .iter()
                .find(|child| child.name.as_bytes() == component.as_slice())
                .ok_or_else(|| {
                    CoreError::invalid(format!(
                        "copy cannot resolve '{}': no such entry",
                        String::from_utf8_lossy(component)
                    ))
                })?;
            current = next.clone();
        }
        Ok(current)
    }

    /// Translate one reader listing, sizing files through `open_file`
    /// (which is also what refuses symlinks and special files with
    /// their kind named).
    fn translate(&self, entries: Vec<crate::udf::reader::Entry>) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in &entries {
            let size = if entry.is_directory {
                0
            } else {
                self.reader.open_file(entry)?.len()
            };
            out.push(Entry {
                name: entry.name.clone().into_bytes(),
                is_dir: entry.is_directory,
                size,
            });
        }
        Ok(out)
    }
}

impl Source for UdfSource {
    fn root_entries(&self) -> Result<Vec<Entry>> {
        let root = self.reader.root();
        self.translate(self.reader.read_dir(&root)?)
    }

    fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
        let resolved = self.resolve(dir)?;
        self.translate(self.reader.read_dir(&resolved)?)
    }

    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
        let resolved = self.resolve(file)?;
        let handle = self.reader.open_file(&resolved)?;
        self.reader.read_open_at(&handle, offset, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::iso::FLAG_DIRECTORY;
    use crate::iso::SECTOR_BYTES;
    use crate::iso::descriptor::TYPE_BOOT;
    use crate::iso::descriptor::TYPE_PRIMARY;
    use crate::iso::descriptor::TYPE_TERMINATOR;
    use crate::iso::record::RECORD_FIXED_LEN;

    const ROOT_SECTOR: u32 = 20;
    const DIR_A_SECTOR: u32 = 21;
    const DIR_B_SECTOR: u32 = 22;
    const FILE_TOP_SECTOR: u32 = 23;
    const FILE_NESTED_SECTOR: u32 = 24;
    const IMAGE_SECTORS: u32 = 32;

    /// Encode one directory record, mirroring the on-disk layout the
    /// parser reads (both-endian words, zero date, sequence 1, the
    /// even-length pad, no system-use tail). Copied from the
    /// `iso/reader.rs` test builders, not refactored: those helpers
    /// are private to their module on purpose.
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

    /// Pack records back to back at the start of one zeroed sector.
    /// Copied from the `iso/reader.rs` test builders (see
    /// [`encode_record`]).
    fn dir_sector(records: &[Vec<u8>]) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        let mut offset = 0;
        for record in records {
            sector[offset..offset + record.len()].copy_from_slice(record);
            offset += record.len();
        }
        sector
    }

    /// Primary-descriptor sector with `label` and the root at
    /// (`root_extent`, `root_len`). Copied from the `iso/reader.rs`
    /// test builders (see [`encode_record`]).
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
        sector[128..130].copy_from_slice(&2048u16.to_le_bytes());
        sector[130..132].copy_from_slice(&2048u16.to_be_bytes());
        let root = encode_record(root_extent, root_len, FLAG_DIRECTORY, b"\x00");
        sector[156..156 + root.len()].copy_from_slice(&root);
        sector
    }

    /// Boot-record sector. Copied from the `iso/reader.rs` test
    /// builders (see [`encode_record`]).
    fn boot_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_BOOT;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Terminator sector. Copied from the `iso/reader.rs` test builders
    /// (see [`encode_record`]).
    fn terminator_sector() -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[0] = TYPE_TERMINATOR;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        sector
    }

    /// Whole primary-only fixture image: descriptors at 16..18, root
    /// at 20 holding `B/`, `TOP.TXT;1` and `A/` in that (unsorted)
    /// on-disk order, `A/` at 21 holding `NESTED.TXT;1`, `B/` at 22
    /// empty, file contents after. Synthetic layout only, claims
    /// nothing about real mastering tools.
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
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"B"),
                encode_record(FILE_TOP_SECTOR, 7, 0, b"TOP.TXT;1"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"A"),
            ]),
        );
        put(
            &mut image,
            DIR_A_SECTOR,
            &dir_sector(&[
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_A_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_NESTED_SECTOR, 6, 0, b"NESTED.TXT;1"),
            ]),
        );
        put(
            &mut image,
            DIR_B_SECTOR,
            &dir_sector(&[
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(DIR_B_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            ]),
        );
        put(&mut image, FILE_TOP_SECTOR, b"top-txt");
        put(&mut image, FILE_NESTED_SECTOR, b"nested");
        image
    }

    /// Fixture image opened as an [`IsoSource`].
    fn fixture_source() -> IsoSource {
        let bytes = fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"))
    }

    /// A no-op [`Progress`](super::super::Progress) for the walk test
    /// below (ordering and contents are the assertions, not the meter).
    struct Sink;

    impl super::super::Progress for Sink {
        fn report(&mut self, _done_bytes: u64, _total_bytes: u64) {}
    }

    #[test]
    fn copies_an_iso_tree_byte_for_byte() {
        // The fixture tree (two directories, one nested file) lands
        // byte-for-byte in a scratch directory with exact summary
        // counts: A/ and B/ created, TOP.TXT and NESTED.TXT written.
        let source = fixture_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions { free_bytes: None },
            &mut Sink,
        )
        .expect("the iso tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 2,
                files: 2,
                bytes: 13,
                renamed: 0,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
        assert!(
            std::fs::read_dir(scratch.path().join("B"))
                .expect("B lists")
                .count()
                == 0
        );
    }

    /// Second fixture image: root at 20 holding `DOC.;12` and
    /// `SUB.;2` (multi-digit versions the reader does NOT strip — only
    /// exact `;1` strips there — so the walk's own rules fire), `SUB.;2`
    /// at 25 holding `F.TXT;1`, contents after. Synthetic layout only,
    /// claims nothing about real mastering tools.
    fn version_dot_fixture_bytes() -> Vec<u8> {
        const SUB_SECTOR: u32 = 25;
        const FILE_DOC_SECTOR: u32 = 26;
        const FILE_F_SECTOR: u32 = 27;
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
                encode_record(FILE_DOC_SECTOR, 3, 0, b"DOC.;12"),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"SUB.;2"),
            ]),
        );
        put(
            &mut image,
            SUB_SECTOR,
            &dir_sector(&[
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(SUB_SECTOR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(FILE_F_SECTOR, 5, 0, b"F.TXT;1"),
            ]),
        );
        put(&mut image, FILE_DOC_SECTOR, b"doc");
        put(&mut image, FILE_F_SECTOR, b"data!");
        image
    }

    #[test]
    fn copies_versioned_and_dotted_iso_names_sanitised() {
        // End to end through the reader: `DOC.;12` stores as `DOC`
        // (version stripped past the reader's exact-`;1` rule, then
        // the trailing dot trimmed) and `SUB.;2/` as `SUB`, with
        // contents intact and both entries counted as renamed.
        // `F.TXT;1` arrives pre-stripped by the reader, so the walk
        // stores it unchanged.
        let bytes = version_dot_fixture_bytes();
        let total = bytes.len() as u64;
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        volume.write_all_at(0, &bytes).expect("the fixture writes");
        let source = IsoSource::new(IsoReader::open(Box::new(volume)).expect("the fixture opens"));
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let summary = super::super::walk(
            &source,
            scratch.path(),
            &super::super::CopyOptions { free_bytes: None },
            &mut Sink,
        )
        .expect("the dotted tree copies");
        assert_eq!(
            summary,
            super::super::Summary {
                directories: 1,
                files: 2,
                bytes: 8,
                renamed: 2,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("DOC")).expect("stripped reads back"),
            b"doc"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("SUB").join("F.TXT")).expect("nested reads back"),
            b"data!"
        );
    }

    #[test]
    fn iso_adapter_lists_in_store_order_and_reads_in_chunks() {
        // Root children arrive in on-disk order (B, TOP.TXT, A) —
        // sorting is the walk's job, pinned there. Directory entries
        // size 0, files carry their data length.
        let source = fixture_source();
        let root = source.root_entries().expect("the root lists");
        assert_eq!(
            root.iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>(),
            [b"B".to_vec(), b"TOP.TXT".to_vec(), b"A".to_vec()]
        );
        assert!(root[0].is_dir && root[0].size == 0);
        assert!(!root[1].is_dir && root[1].size == 7);
        // Children resolve under their directory.
        let children = source.child_entries(&[b"A".to_vec()]).expect("A/ lists");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, b"NESTED.TXT".to_vec());
        assert_eq!(children[0].size, 6);
        // Reads stream in caller-sized chunks with 0 past the end.
        let mut first = [0u8; 4];
        let placed = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 0, &mut first)
            .expect("the head reads");
        assert_eq!(placed, 4);
        assert_eq!(&first, b"top-");
        let mut rest = [0u8; 4];
        let placed = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 4, &mut rest)
            .expect("the tail reads");
        assert_eq!(placed, 3);
        assert_eq!(&rest[..3], b"txt");
        let mut past = [0u8; 4];
        assert_eq!(
            source
                .read_bytes(&[b"TOP.TXT".to_vec()], 7, &mut past)
                .expect("the end reads"),
            0
        );
        // Offsets past the length refuse naming both numbers.
        let mut buf = [0u8; 1];
        let error = source
            .read_bytes(&[b"TOP.TXT".to_vec()], 8, &mut buf)
            .expect_err("a past-the-end read refuses");
        assert!(error.to_string().contains('8'), "{error:?}");
        assert!(error.to_string().contains('7'), "{error:?}");
    }
}
