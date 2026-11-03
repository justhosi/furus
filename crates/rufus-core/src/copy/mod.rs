//! File-tree copy foundation (S18, slice 1 of 7): move an ISO/UDF
//! filesystem onto a real directory, exactly as Rufus does — one
//! directory at a time, deterministic order, progress by bytes.
//!
//! PLAN §S18 asks for the image's tree on the target the way Rufus
//! lays it down. This slice builds only the foundation, on purpose:
//!
//! * [`Source`] (see [`source`]) abstracts the two readers behind the
//!   minimum a copy needs — listings, names, kinds, sizes, chunked
//!   reads — with thin [`IsoSource`] and [`UdfSource`] adapters. The
//!   readers themselves are untouched.
//! * [`DestDir`] writes into one existing directory on
//!   a real filesystem (Rufus copies into a mounted filesystem, never
//!   into a raw image).
//! * [`walk`] copies depth-first in byte-sorted name order with a
//!   fixed-size buffer, refuses a bad destination and a short
//!   filesystem before any write, and reports [`Summary`] counts.
//!   Nesting past the depth cap refuses as a possible directory loop,
//!   in both passes; re-running into a partial destination resumes
//!   it — existing directories are reused and files rewritten whole —
//!   so an interrupted copy recovers by running again.
//!
//! Not here yet: entry metadata (modes, stamps, link targets — the
//! Part A audit found the fields, slices 3-4 decide them), symlinks
//! (refused, never skipped: skipping would lose data silently),
//! boot/extended attributes, and any CLI wiring.
//!
//! On progress reporting: [`Progress`] is one method on purpose. The
//! pipeline's [`Event`](crate::pipeline::Event)/[`Reporter`](crate::pipeline::Reporter) would
//! drag the step-machine vocabulary (step starts, step finishes, step
//! names) into a module that has no steps, and
//! [`Logger`](crate::log::Logger) is a text log with a file sink and
//! a record cap — a log, not a meter, and progress is a
//! high-frequency numeric signal. A later slice adapts [`Progress`]
//! to the CLI's JSONL stream; until then tests record with a three-line
//! struct.
//!
//! [`Source`]: source::Source

pub mod dest;
pub mod source;

pub use dest::DestDir;
pub use source::Entry;
pub use source::IsoSource;
pub use source::Source;
pub use source::UdfSource;

use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use crate::error::CoreError;
use crate::error::Result;

/// Fixed copy buffer in bytes (128 KiB): every file streams through
/// this one allocation, so even a huge file costs no more RAM.
const COPY_BUF_LEN: usize = 128 * 1024;

/// Hard ceiling on directory nesting in either pass: a deeper tree is
/// a directory loop (or hostile nesting), refused rather than
/// recursed into a stack overflow. Same order of magnitude as the
/// readers' own caps (`MAX_DIR_DEPTH`/`MAX_WALK_DEPTH`, 32 each).
const MAX_COPY_DEPTH: usize = 64;

/// Copy options: capacity only, for now. Later slices add knobs here
/// (filters, symlink policy, metadata handling) without touching
/// [`walk`]'s signature shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOptions {
    /// Free bytes on the destination filesystem, when the caller knows
    /// them (`None` skips the up-front capacity check). `std` has no
    /// `statvfs`, so supplying this is the CLI/adapter's job; the copy
    /// refuses before any write when the tree's declared total exceeds
    /// it.
    pub free_bytes: Option<u64>,
}

/// What one [`walk`] moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Directories created under the destination (the destination
    /// root itself pre-exists and is not counted).
    pub directories: u64,
    /// Regular files written.
    pub files: u64,
    /// File payload bytes copied.
    pub bytes: u64,
}

/// Progress sink for [`walk`]: `done_bytes` of `total_bytes` copied
/// so far. Called once up front with `(0, total)`, after every file
/// chunk, and once at completion — a consumer can always tell "done
/// instantly" from "never reported".
pub trait Progress {
    /// Report progress: `done_bytes` of `total_bytes` copied so far.
    fn report(&mut self, done_bytes: u64, total_bytes: u64);
}

/// Copy `source` under the existing directory `dest`: depth-first,
/// children sorted by name bytes at every level, files streamed
/// through one fixed buffer. Returns the [`Summary`] counts.
///
/// Order of checks: the destination must exist as a directory, then
/// the tree's declared total is summed (a second traversal — sources
/// are cheap listings, and the total must be known before any write),
/// then the capacity check, then the copy. An I/O error mid-copy
/// surfaces as [`CoreError::io`](crate::error::CoreError::io) naming
/// the path, and whatever landed before it stays (a copy is not a
/// transaction); cancellation arrives in a later slice.
pub fn walk(
    source: &dyn Source,
    dest: &Path,
    options: &CopyOptions,
    progress: &mut dyn Progress,
) -> Result<Summary> {
    let dest = DestDir::open(dest)?;
    let total = total_bytes(source)?;
    match options.free_bytes {
        Some(free) if total > free => {
            return Err(CoreError::invalid(format!(
                "copy needs {total} bytes but the destination reports {free} free: refusing before any write"
            )));
        }
        _ => {}
    }
    let mut copier = Copier {
        source,
        dest,
        buf: vec![0u8; COPY_BUF_LEN],
        summary: Summary {
            directories: 0,
            files: 0,
            bytes: 0,
        },
        done: 0,
        total,
        progress,
    };
    copier.progress.report(0, total);
    let mut rel = Vec::new();
    let mut abs = copier.dest.root().to_path_buf();
    copier.copy_dir(&mut rel, &mut abs, 0)?;
    let (done, total) = (copier.done, copier.total);
    copier.progress.report(done, total);
    Ok(copier.summary)
}

/// Children of `dir` (empty means the root) in byte-sorted name
/// order: the one place ordering happens, so every listing the walk
/// consumes is deterministic whatever order the store keeps.
fn sorted_children(source: &dyn Source, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
    let mut children = if dir.is_empty() {
        source.root_entries()?
    } else {
        source.child_entries(dir)?
    };
    children.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(children)
}

/// Refuse descent past [`MAX_COPY_DEPTH`]: a deeper tree is a
/// directory loop (or hostile nesting), refused rather than recursed
/// into a stack overflow. Names the source-side path, which is what
/// loops — the depth probe consults nothing else, so a cyclic
/// [`Source`] fails here in both passes before any byte moves.
fn check_depth(rel: &[Vec<u8>], depth: usize) -> Result<()> {
    if depth > MAX_COPY_DEPTH {
        let mut shown = String::from("/");
        for name in rel {
            shown.push_str(&String::from_utf8_lossy(name));
            shown.push('/');
        }
        return Err(CoreError::invalid(format!(
            "copy of '{shown}' nests past {MAX_COPY_DEPTH} directories: refusing as a possible directory loop"
        )));
    }
    Ok(())
}

/// Refuse entry names that could escape the destination or confuse
/// the walk: empty names, `.`/`..`, and anything holding `/` (one
/// component must stay one component). A NUL byte needs no rule here
/// — the OS refuses it as an I/O error naming the path.
fn check_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::invalid(
            "copy refuses an entry with an empty name".to_string(),
        ));
    }
    if name == b"." || name == b".." {
        return Err(CoreError::invalid(format!(
            "copy refuses the reserved entry name '{}'",
            String::from_utf8_lossy(name)
        )));
    }
    if name.contains(&b'/') {
        return Err(CoreError::invalid(format!(
            "copy refuses the entry name '{}': one component must stay one component",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(())
}

/// The walk state: everything [`copy_dir`](Copier::copy_dir) threads
/// through the recursion in one struct instead of nine arguments.
struct Copier<'a> {
    source: &'a dyn Source,
    dest: DestDir,
    buf: Vec<u8>,
    summary: Summary,
    done: u64,
    total: u64,
    progress: &'a mut dyn Progress,
}

impl Copier<'_> {
    /// Copy the directory at `rel` (name bytes from the source root)
    /// into `abs`: create each child directory and recurse, stream
    /// each file through the fixed buffer. `depth` counts descents
    /// from the root for [`check_depth`].
    fn copy_dir(&mut self, rel: &mut Vec<Vec<u8>>, abs: &mut PathBuf, depth: usize) -> Result<()> {
        check_depth(rel, depth)?;
        for child in sorted_children(self.source, rel)? {
            check_name(&child.name)?;
            rel.push(child.name.clone());
            abs.push(OsStr::from_bytes(&child.name));
            if child.is_dir {
                self.dest.create_dir(abs)?;
                self.summary.directories =
                    self.summary.directories.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("copy directory count overflows the counter".to_string())
                    })?;
                self.copy_dir(rel, abs, depth.saturating_add(1))?;
            } else {
                let mut file = self.dest.replace_file(abs)?;
                let mut offset = 0u64;
                while offset < child.size {
                    let placed = self.source.read_bytes(rel, offset, &mut self.buf)?;
                    if placed == 0 {
                        return Err(CoreError::invalid(format!(
                            "copy of '{}' ends at {offset} of {} bytes: refusing a short read",
                            abs.display(),
                            child.size
                        )));
                    }
                    let window = self.buf.get(..placed).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "copy window of {placed} bytes runs past the {} byte buffer",
                            self.buf.len()
                        ))
                    })?;
                    file.write_all(window)
                        .map_err(|error| CoreError::io(abs.as_path(), error))?;
                    offset = offset.checked_add(placed as u64).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "copy offset of '{}' overflows past {} bytes",
                            abs.display(),
                            child.size
                        ))
                    })?;
                    self.done = self.done.checked_add(placed as u64).ok_or_else(|| {
                        CoreError::invalid("copy byte count overflows the counter".to_string())
                    })?;
                    self.progress.report(self.done, self.total);
                }
                self.summary.files = self.summary.files.checked_add(1).ok_or_else(|| {
                    CoreError::invalid("copy file count overflows the counter".to_string())
                })?;
                self.summary.bytes =
                    self.summary.bytes.checked_add(child.size).ok_or_else(|| {
                        CoreError::invalid("copy byte count overflows the counter".to_string())
                    })?;
            }
            rel.pop().ok_or_else(|| {
                CoreError::invalid("copy path stack underflows its push".to_string())
            })?;
            abs.pop();
        }
        Ok(())
    }
}

/// Sum every file size in the tree: the up-front total the capacity
/// check and the progress meter need before any write. A second
/// traversal is deliberate (see [`walk`]); it enforces the same
/// depth bound and name rules as the copy pass, so both passes agree
/// on which trees are copyable.
fn total_bytes(source: &dyn Source) -> Result<u64> {
    fn sum(source: &dyn Source, dir: &mut Vec<Vec<u8>>, depth: usize) -> Result<u64> {
        check_depth(dir, depth)?;
        let mut total = 0u64;
        for child in sorted_children(source, dir)? {
            check_name(&child.name)?;
            if child.is_dir {
                dir.push(child.name.clone());
                let sub = sum(source, dir, depth.saturating_add(1))?;
                dir.pop().ok_or_else(|| {
                    CoreError::invalid("copy path stack underflows its push".to_string())
                })?;
                total = total.checked_add(sub).ok_or_else(|| {
                    CoreError::invalid("copy total overflows the byte arithmetic".to_string())
                })?;
            } else {
                total = total.checked_add(child.size).ok_or_else(|| {
                    CoreError::invalid("copy total overflows the byte arithmetic".to_string())
                })?;
            }
        }
        Ok(total)
    }

    sum(source, &mut Vec::new(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// One in-memory file: payload bytes under a name.
    #[derive(Debug, Clone)]
    struct MemFile {
        name: Vec<u8>,
        bytes: Vec<u8>,
    }

    /// One in-memory directory: child files and child directory names.
    /// Children keep insertion order on purpose (unsorted, to prove
    /// the walk sorts).
    #[derive(Debug, Clone, Default)]
    struct MemDir {
        files: Vec<MemFile>,
        dirs: Vec<Vec<u8>>,
    }

    /// An in-memory [`Source`] over a `BTreeMap` of directories keyed
    /// by name-byte path (empty is the root), recording every file
    /// read in order. Listings come back in the deliberately unsorted
    /// insertion order; the walk must still visit sorted.
    #[derive(Debug, Default)]
    struct MemSource {
        dirs: BTreeMap<Vec<Vec<u8>>, MemDir>,
        reads: Rc<RefCell<Vec<Vec<Vec<u8>>>>>,
    }

    impl MemSource {
        fn dir(&mut self, path: &[Vec<u8>]) -> &mut MemDir {
            self.dirs.entry(path.to_vec()).or_default()
        }
    }

    impl Source for MemSource {
        fn root_entries(&self) -> Result<Vec<Entry>> {
            self.child_entries(&[])
        }

        fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            let found = self.dirs.get(dir).ok_or_else(|| {
                CoreError::invalid(format!(
                    "test source has no directory '{}'",
                    dir.iter()
                        .map(|name| String::from_utf8_lossy(name).into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                ))
            })?;
            let mut out = Vec::new();
            for file in &found.files {
                out.push(Entry {
                    name: file.name.clone(),
                    is_dir: false,
                    size: file.bytes.len() as u64,
                });
            }
            for dir in &found.dirs {
                out.push(Entry {
                    name: dir.clone(),
                    is_dir: true,
                    size: 0,
                });
            }
            Ok(out)
        }

        fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
            let (name, parent) = file.split_last().ok_or_else(|| {
                CoreError::invalid("test source cannot read the root as a file".to_string())
            })?;
            let found = self.dirs.get(parent).ok_or_else(|| {
                CoreError::invalid("test source has no parent for the read".to_string())
            })?;
            let payload = found
                .files
                .iter()
                .find(|file| file.name.as_slice() == name.as_slice())
                .ok_or_else(|| CoreError::invalid("test source has no such file".to_string()))?;
            self.reads.borrow_mut().push(file.to_vec());
            let start = offset as usize;
            if start > payload.bytes.len() {
                return Err(CoreError::invalid(format!(
                    "test read at offset {offset} runs past the {} byte file",
                    payload.bytes.len()
                )));
            }
            let end = (start + buf.len()).min(payload.bytes.len());
            let window = payload
                .bytes
                .get(start..end)
                .ok_or_else(|| CoreError::invalid("test read window runs past its file"))?;
            let dest = buf
                .get_mut(..window.len())
                .ok_or_else(|| CoreError::invalid("test read window runs past its buffer"))?;
            dest.copy_from_slice(window);
            Ok(window.len())
        }
    }

    /// A recording [`Progress`]: every `(done, total)` report in order.
    #[derive(Debug, Default)]
    struct Recorder {
        reports: Vec<(u64, u64)>,
    }

    impl Progress for Recorder {
        fn report(&mut self, done_bytes: u64, total_bytes: u64) {
            self.reports.push((done_bytes, total_bytes));
        }
    }

    /// [`CopyOptions`] with no capacity limit.
    fn no_limit() -> CopyOptions {
        CopyOptions { free_bytes: None }
    }

    /// Two directories under the root (`B/` before `A/` on purpose),
    /// a nested file in `A/`, nothing anywhere else. Every named
    /// directory gets its own map entry (pushing a name alone does
    /// not create the directory it names).
    fn two_dir_source() -> MemSource {
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"B".to_vec());
        source.dir(&[]).dirs.push(b"A".to_vec());
        source.dir(&[b"B".to_vec()]);
        source.dir(&[]).files.push(MemFile {
            name: b"TOP.TXT".to_vec(),
            bytes: b"top-txt".to_vec(),
        });
        source.dir(&[b"A".to_vec()]).files.push(MemFile {
            name: b"NESTED.TXT".to_vec(),
            bytes: b"nested".to_vec(),
        });
        source
    }

    #[test]
    fn copies_directories_depth_first_in_sorted_order() {
        // Children arrive files-first and reverse-alphabetical, but
        // the file reads land in sorted depth-first order: A/ and its
        // file, then B/, then TOP.TXT — every file exactly once.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("a small tree copies");
        assert_eq!(
            source.reads.borrow().clone(),
            [
                vec![b"A".to_vec(), b"NESTED.TXT".to_vec()],
                vec![b"TOP.TXT".to_vec()],
            ]
        );
        assert_eq!(
            summary,
            Summary {
                directories: 2,
                files: 2,
                bytes: 13,
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
        // Progress opens at zero, never exceeds the total, and ends
        // exactly on it.
        assert_eq!(progress.reports.first().copied(), Some((0, 13)));
        assert_eq!(progress.reports.last().copied(), Some((13, 13)));
        assert!(
            progress.reports.iter().all(|&(done, _)| done <= 13),
            "no report past the total: {:?}",
            progress.reports
        );
    }

    #[test]
    fn refuses_a_destination_that_is_a_file() {
        // The destination is a regular file: the invalid refusal names
        // it, and its bytes are untouched.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"untouched").expect("the decoy writes");
        let mut progress = Recorder::default();
        let error = walk(&source, &file, &no_limit(), &mut progress)
            .expect_err("a file destination refuses");
        assert!(error.to_string().contains("not a directory"), "{error:?}");
        assert!(error.to_string().contains("file"), "{error:?}");
        assert_eq!(
            std::fs::read(&file).expect("the decoy reads back"),
            b"untouched"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn refuses_short_free_space_before_any_write() {
        // The tree holds 13 bytes and the destination reports 12: the
        // refusal names both counts, and the destination stays empty.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(
            &source,
            scratch.path(),
            &CopyOptions {
                free_bytes: Some(12),
            },
            &mut progress,
        )
        .expect_err("short space refuses");
        let text = error.to_string();
        assert!(text.contains("13"), "{text}");
        assert!(text.contains("12"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created before the check"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn refuses_reserved_entry_names() {
        // A `..` entry would escape the destination: the walk refuses
        // naming it, and nothing lands.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"..".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("a dot-dot entry refuses");
        assert!(error.to_string().contains(".."), "{error:?}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created"
        );
    }

    /// A [`Source`] listing one directory under every directory it is
    /// asked about: a cyclic tree that would recurse forever without
    /// the depth bound.
    #[derive(Debug, Default)]
    struct LoopSource;

    impl Source for LoopSource {
        fn root_entries(&self) -> Result<Vec<Entry>> {
            Ok(vec![Entry {
                name: b"X".to_vec(),
                is_dir: true,
                size: 0,
            }])
        }

        fn child_entries(&self, _dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            Ok(vec![Entry {
                name: b"X".to_vec(),
                is_dir: true,
                size: 0,
            }])
        }

        fn read_bytes(&self, _file: &[Vec<u8>], _offset: u64, _buf: &mut [u8]) -> Result<usize> {
            Err(CoreError::invalid("loop source holds no files".to_string()))
        }
    }

    #[test]
    fn cyclic_tree_refuses_instead_of_overflowing() {
        // Every directory lists itself: without the depth bound the
        // walk recurses until the stack overflows. It must return Err
        // naming the loop instead, from the sizing pass — before any
        // write, with nothing reported.
        let source = LoopSource;
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("a cyclic tree refuses");
        let text = error.to_string();
        assert!(text.contains('X'), "{text}");
        assert!(text.contains("possible directory loop"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn second_run_into_the_same_destination_resumes() {
        // Copy twice into the same destination: existing directories
        // are reused and files rewritten whole, so the second run
        // succeeds with identical counts and bytes.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let first =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("first copy runs");
        let mut progress = Recorder::default();
        let second =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("second copy resumes");
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read(scratch.path().join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
    }
}
