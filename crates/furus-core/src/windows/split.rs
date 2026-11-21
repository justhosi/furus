//! Split an oversized `install.wim` into FAT32-sized `.swm` parts (S21, slice 4 of 12).
//!
//! A FAT32 data partition cannot hold a file of 4 GiB or more, so an
//! installer image that outgrew the limit must be split before it is
//! copied: `install.wim` becomes `install.swm`, `install2.swm`, ...
//! through `wimlib_split`, each part small enough to land on FAT32.
//! This module owns that step; the copy engine and the pipeline wire it
//! up in later slices.
//!
//! Contract, in order:
//! a. [`split_for_fat32`] reads `source` metadata; when the file fits
//!    the FAT32 limit it refuses with [`CoreError::InvalidInput`]
//!    naming the size and the limit. Otherwise it delegates to
//!    [`split_with_part_size`] with [`PART_BYTES`].
//! b. [`split_with_part_size`] refuses a zero `part_size` with
//!    `InvalidInput` and opens `source` read-only (`OpenFlags::EMPTY`).
//!    No `WRITE_ACCESS` is needed: a C probe on wimlib 1.14.5 showed
//!    `wimlib_open_wim` with flags `0` followed by `wimlib_split`
//!    succeeding, so splitting only reads the source.
//! c. An existing destination part (`dest_dir/install.swm` or any name
//!    matching `stem[N].swm`) refuses with `InvalidInput` naming the
//!    file: splitting never clobbers.
//! d. `dest_dir` must exist (`Io` naming it otherwise). The first part
//!    is `dest_dir/{source file stem}.swm` (for example
//!    `sources/install.wim` becomes `sources/install.swm`).
//! e. The split runs through a progress adapter that mirrors the apply
//!    bridge: a [`RateEma`] sampled on every callback, throttled
//!    through `emit_progress_to` on step `"write"` with
//!    `Some(total_bytes)` and a forced final sample; `cancelled`
//!    returns false from the callback so wimlib aborts. One `info`
//!    message opens the run (`splitting '<source>' into parts of N
//!    bytes`) and one closes it (`split '<source>' into N parts (M
//!    bytes)`).
//! f. After the call the expected names are computed from the
//!    library-reported `total_parts` (the last progress sample) via
//!    [`part_name`], each is checked to exist, and the next index is
//!    checked to be absent (no unexpected extra part). The directory
//!    is snapshotted before the call, so the pre-flight (c) and the
//!    cleanup (g) can tell this run's parts from stale files: the
//!    pre-flight guarantees no expected name exists beforehand, so any
//!    expected name found afterwards is this run's. A directory diff
//!    alone cannot prove the tail is complete (a missing part and a
//!    concurrent writer look alike), which is why the authoritative
//!    count is the library's `total_parts`, not the listing.
//! g. Cleanup rule: on any failure (wimlib error, cancellation,
//!    verification) every part this call created is removed; a failed
//!    removal warns and never replaces the original error.
//!    Cancellation maps to [`CoreError::Cancelled`], `NotLinked` to
//!    [`CoreError::WimUnavailable`], `InvalidPath` to `InvalidInput`,
//!    and other codes to [`CoreError::Wim`].
//! h. A part larger than the requested `part_size` warns naming the
//!    part (the documented single-resource overshoot: the format
//!    cannot split one resource across parts). A part above
//!    [`FAT32_MAX_FILE_BYTES`] cannot land on FAT32.
//!
//! No `unsafe` here: all library contact goes through the safe
//! `wimlib-sys` facade.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use wimlib_sys::WimlibError;
use wimlib_sys::safe::ERR_ABORTED_BY_PROGRESS;
use wimlib_sys::safe::OpenFlags;
use wimlib_sys::safe::SplitProgress;

use crate::error::CoreError;
use crate::error::Result;
use crate::pipeline::event::Event;
use crate::pipeline::event::Reporter;
use crate::pipeline::write::RateEma;
use crate::pipeline::write::emit_progress_to;

/// Largest file FAT32 can hold: 4 GiB minus one byte.
pub const FAT32_MAX_FILE_BYTES: u64 = 4_294_967_295;

/// Split target size: one MiB below the FAT32 limit, so a part that
/// slightly overshoots its budget (a single unsplittable resource)
/// still lands on FAT32. A part above [`FAT32_MAX_FILE_BYTES`] cannot.
pub const PART_BYTES: u64 = FAT32_MAX_FILE_BYTES - 1_048_576;

/// True when `len` no longer fits on FAT32 (strictly greater than the
/// limit; exactly the limit still fits).
pub fn needs_split(len: u64) -> bool {
    len > FAT32_MAX_FILE_BYTES
}

/// Computed part name for 1-based `index`: `1` returns `first`
/// unchanged, `2` appends `2` before the suffix (`install.swm` becomes
/// `install2.swm`), `10` becomes `install10.swm`, and so on.
///
/// Refuses `index == 0` (part numbers are 1-based) and any `first`
/// that does not end in `.swm`, both with [`CoreError::InvalidInput`]
/// naming the file.
pub fn part_name(first: &Path, index: u32) -> Result<PathBuf> {
    if index == 0 {
        return Err(CoreError::invalid(format!(
            "split part index 0 is out of range: part numbers start at 1 (first part '{}')",
            first.display(),
        )));
    }
    let is_swm = first.extension().is_some_and(|ext| ext == "swm");
    if !is_swm {
        return Err(CoreError::invalid(format!(
            "split first part '{}' must end in '.swm': cannot compute part {index}",
            first.display(),
        )));
    }
    if index == 1 {
        return Ok(first.to_path_buf());
    }
    let stem = match first.file_stem() {
        Some(stem) => stem.to_os_string(),
        None => {
            return Err(CoreError::invalid(format!(
                "split first part '{}' has no file stem: cannot compute part {index}",
                first.display(),
            )));
        }
    };
    let mut name = stem;
    name.push(index.to_string());
    name.push(".swm");
    Ok(first.with_file_name(name))
}

/// What one split laid down: the part paths in order, the requested
/// per-part budget, and the source file size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    /// Part paths in 1-based order (`install.swm`, `install2.swm`, ...).
    pub parts: Vec<PathBuf>,
    /// Requested maximum bytes per part ([`PART_BYTES`] for FAT32).
    pub part_size: u64,
    /// Source file size in bytes.
    pub bytes: u64,
}

/// Translate a facade error into [`CoreError`]: `NotLinked` becomes
/// [`CoreError::WimUnavailable`], `InvalidPath` becomes invalid input,
/// and any code carries the path, the code, and the library message.
fn map_facade_error(path: &Path, error: WimlibError) -> CoreError {
    match error {
        WimlibError::NotLinked => CoreError::WimUnavailable,
        WimlibError::InvalidPath { path: bad } => {
            CoreError::invalid(format!("wim path is not usable: '{bad}'"))
        }
        WimlibError::Code { code, message } => CoreError::Wim {
            path: path.display().to_string(),
            code,
            message,
        },
    }
}

/// True when `file_name` looks like a part of the `stem` set:
/// `stem.swm` (the first) or `stem` plus ASCII digits plus `.swm`
/// (later parts). Used for the never-clobber pre-flight and for
/// cleanup, so this run's parts are never confused with stale files.
fn is_split_part_name(file_name: &OsStr, stem: &OsStr) -> bool {
    let name_bytes = file_name.as_bytes();
    let stem_bytes = stem.as_bytes();
    let Some(rest) = name_bytes.strip_prefix(stem_bytes) else {
        return false;
    };
    let Some(middle) = rest.strip_suffix(b".swm") else {
        return false;
    };
    if middle.is_empty() {
        return true;
    }
    middle.iter().all(|byte| byte.is_ascii_digit())
}

/// File names currently in `dest_dir`: the pre-split snapshot that
/// tells this run's parts from stale files. A missing or unreadable
/// directory reports [`CoreError::Io`] naming it.
fn snapshot_dir(dest_dir: &Path) -> Result<HashSet<OsString>> {
    let listing = std::fs::read_dir(dest_dir).map_err(|source| CoreError::io(dest_dir, source))?;
    let mut names = HashSet::new();
    for entry in listing {
        let entry = entry.map_err(|source| CoreError::io(dest_dir, source))?;
        names.insert(entry.file_name());
    }
    Ok(names)
}

/// Remove every file this call created: names in `dest_dir` that match
/// the `stem` set and were absent from `before`. A failed listing or
/// removal warns and never fails: cleanup must not replace the
/// original error.
fn cleanup_new_parts(
    dest_dir: &Path,
    before: &HashSet<OsString>,
    stem: &OsStr,
    reporter: &mut dyn Reporter,
) {
    let listing = match std::fs::read_dir(dest_dir) {
        Ok(listing) => listing,
        Err(source) => {
            reporter.event(Event::Message {
                level: "warn",
                text: format!(
                    "failed to list '{}' during split cleanup: {source}; continuing",
                    dest_dir.display(),
                ),
            });
            return;
        }
    };
    for entry in listing {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                reporter.event(Event::Message {
                    level: "warn",
                    text: format!(
                        "failed to read an entry of '{}' during split cleanup: {source}; continuing",
                        dest_dir.display(),
                    ),
                });
                continue;
            }
        };
        let name = entry.file_name();
        if before.contains(&name) {
            continue;
        }
        if !is_split_part_name(&name, stem) {
            continue;
        }
        let path = dest_dir.join(&name);
        if let Err(source) = std::fs::remove_file(&path) {
            reporter.event(Event::Message {
                level: "warn",
                text: format!(
                    "failed to remove split part '{}' during cleanup: {source}; continuing",
                    path.display(),
                ),
            });
        }
    }
}

/// Split `source` for FAT32: refuses files that already fit with
/// `InvalidInput` naming the size and the limit, then delegates to
/// [`split_with_part_size`] with [`PART_BYTES`].
pub fn split_for_fat32(
    source: &Path,
    dest_dir: &Path,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<Split> {
    let len = std::fs::metadata(source)
        .map_err(|source_error| CoreError::io(source, source_error))?
        .len();
    if !needs_split(len) {
        return Err(CoreError::invalid(format!(
            "wim file '{}' is {len} bytes, which fits the FAT32 limit of {FAT32_MAX_FILE_BYTES} bytes; no split is needed",
            source.display(),
        )));
    }
    split_with_part_size(source, dest_dir, PART_BYTES, reporter, cancelled)
}

/// Split `source` into parts of at most `part_size` bytes under
/// `dest_dir`, with progress, cancellation, and the never-clobber and
/// cleanup rules from the module docs.
///
/// `source` opens read-only: splitting only reads it (see the module
/// docs for the evidence). `bytes` in the returned [`Split`] is the
/// source file size, not the parts' summed sizes.
pub fn split_with_part_size(
    source: &Path,
    dest_dir: &Path,
    part_size: u64,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<Split> {
    if part_size == 0 {
        return Err(CoreError::invalid(format!(
            "split part size must be non-zero (from '{}')",
            source.display(),
        )));
    }
    let source_len = std::fs::metadata(source)
        .map_err(|source_error| CoreError::io(source, source_error))?
        .len();
    // The snapshot both proves `dest_dir` exists (Io naming it
    // otherwise) and records this run's baseline for the pre-flight
    // and the cleanup.
    let before = snapshot_dir(dest_dir)?;
    let source_stem = match source.file_stem() {
        Some(stem) => stem.to_os_string(),
        None => {
            return Err(CoreError::invalid(format!(
                "wim source '{}' has no file stem: cannot name the first split part",
                source.display(),
            )));
        }
    };
    let mut first_name = source_stem.clone();
    first_name.push(".swm");
    let first = dest_dir.join(first_name);
    // Never clobber: any name matching the part pattern refuses before
    // a single byte is written.
    let source_stem_ref: &OsStr = &source_stem;
    for name in &before {
        if is_split_part_name(name, source_stem_ref) {
            let path = dest_dir.join(name);
            return Err(CoreError::invalid(format!(
                "split part '{}' already exists: refusing to clobber an existing part",
                path.display(),
            )));
        }
    }
    // Read-only open: the source is never modified by a split (see
    // the module docs for the C-probe evidence).
    let facade = wimlib_sys::safe::Wim::open(source, OpenFlags::EMPTY)
        .map_err(|error| map_facade_error(source, error))?;

    reporter.event(Event::Message {
        level: "info",
        text: format!(
            "splitting '{}' into parts of {part_size} bytes",
            source.display(),
        ),
    });

    let mut last: Option<SplitProgress> = None;
    let mut ema = RateEma::new();
    let mut last_sample = Instant::now();
    let mut last_emit = Instant::now();
    let mut done = 0u64;
    let outcome = facade.split(&first, part_size, &mut |sample: &SplitProgress| {
        if sample.completed_bytes > done {
            ema.observe(sample.completed_bytes - done, last_sample.elapsed());
        }
        last_sample = Instant::now();
        done = sample.completed_bytes;
        let force = sample.completed_bytes >= sample.total_bytes;
        emit_progress_to(
            &mut *reporter,
            "write",
            sample.completed_bytes,
            Some(sample.total_bytes),
            &ema,
            &mut last_emit,
            force,
        );
        last = Some(sample.clone());
        !cancelled()
    });

    if let Err(error) = outcome {
        cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
        match error {
            WimlibError::NotLinked => return Err(CoreError::WimUnavailable),
            WimlibError::InvalidPath { path: bad } => {
                return Err(CoreError::invalid(format!(
                    "wim path is not usable: '{bad}'"
                )));
            }
            WimlibError::Code { code, .. } if code == ERR_ABORTED_BY_PROGRESS => {
                return Err(CoreError::Cancelled);
            }
            WimlibError::Code { code, message } => {
                return Err(CoreError::Wim {
                    path: source.display().to_string(),
                    code,
                    message,
                });
            }
        }
    }

    let total_parts = match last {
        Some(ref sample) => sample.total_parts,
        None => {
            cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
            return Err(CoreError::Verify {
                message: format!(
                    "split of '{}' reported no progress: cannot verify the parts",
                    source.display(),
                ),
            });
        }
    };
    if total_parts == 0 {
        cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
        return Err(CoreError::Verify {
            message: format!(
                "split of '{}' reported zero parts: cannot verify the parts",
                source.display(),
            ),
        });
    }
    let mut parts: Vec<PathBuf> = Vec::new();
    for index in 1..=total_parts {
        let expected = match part_name(&first, index) {
            Ok(path) => path,
            Err(error) => {
                cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
                return Err(error);
            }
        };
        let len = match std::fs::metadata(&expected) {
            Ok(meta) if meta.is_file() => meta.len(),
            _ => {
                cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
                return Err(CoreError::Verify {
                    message: format!(
                        "split of '{}' is missing part {} ('{}'): expected {total_parts} parts",
                        source.display(),
                        index,
                        expected.display(),
                    ),
                });
            }
        };
        if len > part_size {
            reporter.event(Event::Message {
                level: "warn",
                text: format!(
                    "split part '{}' is {len} bytes, which exceeds the requested part size of {part_size} bytes: a single resource larger than the part size cannot be split",
                    expected.display(),
                ),
            });
        }
        parts.push(expected);
    }
    // No unexpected extra part may appear: the next index must be absent.
    if let Some(next) = total_parts.checked_add(1)
        && let Ok(next_name) = part_name(&first, next)
        && std::fs::metadata(&next_name).is_ok()
    {
        cleanup_new_parts(dest_dir, &before, source_stem_ref, reporter);
        return Err(CoreError::Verify {
            message: format!(
                "split of '{}' wrote an unexpected extra part '{}': expected {total_parts} parts",
                source.display(),
                next_name.display(),
            ),
        });
    }

    reporter.event(Event::Message {
        level: "info",
        text: format!(
            "split '{}' into {} parts ({source_len} bytes)",
            source.display(),
            parts.len(),
        ),
    });
    Ok(Split {
        parts,
        part_size,
        bytes: source_len,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;
    use crate::pipeline::event::VecReporter;

    /// Skip gate (the `skip:` convention): one line naming what was
    /// missing — the library probe first, then the `wimlib-imagex`
    /// presence probe — then `true`.
    fn skip_without_backend() -> bool {
        if !wimlib_sys::linked() {
            eprintln!(
                "skip: wim split needs libwim, which this build did not link (wimlib_present is off)"
            );
            return true;
        }
        if Command::new("wimlib-imagex")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!(
                "skip: wim split needs wimlib-imagex, which this host does not ship \
                 (install wimlib and re-run)"
            );
            return true;
        }
        false
    }

    /// Scratch tree of `files` 16 KiB incompressible files: deterministic
    /// xorshift bytes (no new dependency) that LZX cannot shrink, so a
    /// 64 KiB part size yields many parts (96 files is ~1.5 MiB).
    fn write_random_tree(dir: &Path, files: usize) {
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).expect("scratch tree must create");
        // One small text file so the image also holds a tiny resource.
        fs::write(src.join("sub").join("note.txt"), b"split fixture\n")
            .expect("scratch file must write");
        for index in 0..files {
            let mut state: u32 = (index as u32)
                .wrapping_mul(0x9E37_79B1)
                .wrapping_add(0x1234_5678);
            let mut buf = vec![0u8; 16 * 1024];
            for slot in &mut buf {
                state ^= state.wrapping_shl(13);
                state ^= state.wrapping_shr(17);
                state ^= state.wrapping_shl(5);
                *slot = (state >> 8) as u8;
            }
            fs::write(src.join(format!("f{index:03}.bin")), &buf).expect("scratch file must write");
        }
    }

    /// Capture `dir/src` into `dir/cap.wim` with image name `testimg`;
    /// panics past the skip gate when the tool fails.
    fn capture_fixture_wim(dir: &Path) -> PathBuf {
        let wim = dir.join("cap.wim");
        let run = Command::new("wimlib-imagex")
            .arg("capture")
            .arg(dir.join("src"))
            .arg(&wim)
            .arg("testimg")
            .arg("--compress=LZX")
            .output()
            .expect("wimlib-imagex capture must spawn past the skip gate");
        assert!(
            run.status.success(),
            "capture failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        wim
    }

    /// Count directory entries: the cleanup probes compare counts
    /// before and after, so a leaked part fails the test.
    fn entry_count(dir: &Path) -> usize {
        fs::read_dir(dir).expect("scratch dir must list").count()
    }

    /// Every `Progress` event as `(step, done, total)`, in order.
    fn progresses(reporter: &VecReporter) -> Vec<(&'static str, u64, Option<u64>)> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Progress {
                    step, done, total, ..
                } => Some((*step, *done, *total)),
                _ => None,
            })
            .collect()
    }

    /// Every `info` message text, in order.
    fn infos(reporter: &VecReporter) -> Vec<String> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message {
                    level: "info",
                    text,
                } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    /// Every `warn` message text, in order.
    fn warns(reporter: &VecReporter) -> Vec<String> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message {
                    level: "warn",
                    text,
                } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn needs_split_boundaries() {
        assert!(!needs_split(0));
        assert!(!needs_split(FAT32_MAX_FILE_BYTES));
        assert!(needs_split(FAT32_MAX_FILE_BYTES + 1));
        assert_eq!(PART_BYTES, FAT32_MAX_FILE_BYTES - 1_048_576);
    }

    #[test]
    fn part_name_shapes() {
        let first = Path::new("/tmp/out/install.swm");
        assert_eq!(
            part_name(first, 1).expect("part 1 must be the first"),
            PathBuf::from("/tmp/out/install.swm")
        );
        assert_eq!(
            part_name(first, 2).expect("part 2 must append 2"),
            PathBuf::from("/tmp/out/install2.swm")
        );
        assert_eq!(
            part_name(first, 10).expect("part 10 must append 10"),
            PathBuf::from("/tmp/out/install10.swm")
        );
        let err = part_name(first, 0).expect_err("part 0 must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "part 0 must be InvalidInput, got {err}"
        );
        let bad = Path::new("/tmp/out/install.wim");
        let err = part_name(bad, 2).expect_err("a non-swm first must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "a non-swm first must be InvalidInput, got {err}"
        );
        assert!(
            err.to_string().contains("install.wim"),
            "the refusal must name the file: {err}"
        );
    }

    #[test]
    fn real_split_at_64kib_yields_ordered_parts() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        write_random_tree(root.path(), 96);
        let wim_renamed = root.path().join("install.wim");
        let captured = capture_fixture_wim(root.path());
        fs::rename(&captured, &wim_renamed).expect("wim must rename");
        let source_len = fs::metadata(&wim_renamed).expect("wim must stat").len();
        assert!(
            source_len > 1024 * 1024,
            "the fixture must stay near 1.5 MiB, got {source_len}"
        );

        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let mut reporter = VecReporter::new();
        let split = split_with_part_size(&wim_renamed, &dest, 64 * 1024, &mut reporter, &|| false)
            .expect("a 1.5 MiB LZX wim must split at 64 KiB");
        assert!(
            split.parts.len() >= 3,
            "a 1.5 MiB fixture at 64 KiB must yield at least 3 parts, got {}",
            split.parts.len()
        );
        assert_eq!(split.part_size, 64 * 1024);
        assert_eq!(split.bytes, source_len);
        // Names are exactly install.swm, install2.swm, ... in order.
        for (position, part) in split.parts.iter().enumerate() {
            let index = position as u32 + 1;
            let expected = part_name(&dest.join("install.swm"), index)
                .expect("expected part name must compute");
            assert_eq!(part, &expected, "part {index} must be named {expected:?}");
            assert!(part.is_file(), "part {index} must exist");
        }
        // The first part re-opens as a spanned set.
        let facade = wimlib_sys::safe::Wim::open(&split.parts[0], OpenFlags::EMPTY)
            .expect("first split part must open");
        let info = facade.info().expect("first part must report info");
        assert_eq!(info.part_number, 1, "{info:?}");
        assert!(info.spanned, "{info:?}");
        assert_eq!(info.total_parts as usize, split.parts.len(), "{info:?}");
        // On-disk sizes stay within budget; any overshoot is reported
        // through the test log (the 16 KiB resources make none
        // expected, but a single unsplittable resource would).
        for part in &split.parts {
            let len = fs::metadata(part).expect("split part must stat").len();
            if len > split.part_size {
                eprintln!(
                    "overshoot: part {} is {len} bytes, over {}",
                    part.display(),
                    split.part_size
                );
            } else {
                assert!(
                    len <= split.part_size,
                    "part {} is {len} bytes, over {}",
                    part.display(),
                    split.part_size
                );
            }
        }
        // Progress ran on step write with a terminal done == total.
        let progress = progresses(&reporter);
        assert!(!progress.is_empty(), "splitting must report progress");
        assert!(
            progress.iter().all(|(step, _, _)| *step == "write"),
            "every progress sample is step write: {progress:?}"
        );
        let (_, done, total) = progress.last().copied().expect("samples must exist");
        assert_eq!(
            Some(done),
            total,
            "terminal sample must complete every byte"
        );
        let messages = infos(&reporter);
        assert!(
            messages.iter().any(|text| text.contains("splitting")),
            "an opening info message must name the split: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|text| text.contains(&split.parts.len().to_string())),
            "a closing info message must name the part count: {messages:?}"
        );
    }

    #[test]
    fn split_for_fat32_refuses_a_small_wim() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        write_random_tree(root.path(), 2);
        let captured = capture_fixture_wim(root.path());
        let len = fs::metadata(&captured).expect("wim must stat").len();
        assert!(
            !needs_split(len),
            "the small fixture must fit FAT32, got {len}"
        );
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let mut reporter = VecReporter::new();
        let err = split_for_fat32(&captured, &dest, &mut reporter, &|| false)
            .expect_err("a fitting wim must refuse the FAT32 split");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "a fitting wim must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&len.to_string()), "{text}");
        assert!(text.contains(&FAT32_MAX_FILE_BYTES.to_string()), "{text}");
        assert_eq!(entry_count(&dest), 0, "a refused split must create no part");
    }

    #[test]
    fn existing_destination_part_refuses_untouched() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        write_random_tree(root.path(), 96);
        let captured = capture_fixture_wim(root.path());
        let wim_renamed = root.path().join("install.wim");
        fs::rename(&captured, &wim_renamed).expect("wim must rename");
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let blocker = dest.join("install.swm");
        fs::write(&blocker, b"keep me\n").expect("blocker must write");
        let before = fs::read(&blocker).expect("blocker must read");

        let mut reporter = VecReporter::new();
        let err = split_with_part_size(&wim_renamed, &dest, 64 * 1024, &mut reporter, &|| false)
            .expect_err("an existing first part must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "an existing part must be InvalidInput, got {err}"
        );
        assert!(
            err.to_string().contains("install.swm"),
            "the refusal must name the file: {err}"
        );
        let after = fs::read(&blocker).expect("blocker must survive");
        assert_eq!(
            before, after,
            "the pre-existing part must survive untouched"
        );
        assert_eq!(entry_count(&dest), 1, "no extra part may appear");
    }

    #[test]
    fn pre_cancelled_split_returns_cancelled_without_parts() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        write_random_tree(root.path(), 96);
        let captured = capture_fixture_wim(root.path());
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let before = entry_count(&dest);
        let mut reporter = VecReporter::new();
        let err = split_with_part_size(&captured, &dest, 64 * 1024, &mut reporter, &|| true)
            .expect_err("a pre-cancelled split must stop");
        assert!(
            matches!(err, CoreError::Cancelled),
            "a pre-cancelled split must be Cancelled, got {err}"
        );
        assert_eq!(
            entry_count(&dest),
            before,
            "a cancelled split must leave no part behind"
        );
    }

    #[test]
    fn mid_split_cancellation_leaves_no_part_behind() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        write_random_tree(root.path(), 96);
        let captured = capture_fixture_wim(root.path());
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let before = entry_count(&dest);
        // Cancel after a few callbacks: enough parts start that the
        // cleanup has something to remove.
        let seen = std::cell::Cell::new(0u32);
        let mut reporter = VecReporter::new();
        let err = split_with_part_size(&captured, &dest, 64 * 1024, &mut reporter, &|| {
            let next = seen.get().saturating_add(1);
            seen.set(next);
            next > 3
        })
        .expect_err("a mid-split cancellation must stop");
        assert!(
            matches!(err, CoreError::Cancelled),
            "mid-split cancellation must be Cancelled, got {err}"
        );
        assert_eq!(
            entry_count(&dest),
            before,
            "a cancelled split must leave no part behind"
        );
    }

    #[test]
    fn non_wim_source_reports_wim_naming_the_path() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let junk = root.path().join("junk.wim");
        fs::write(&junk, b"not a wim at all").expect("scratch file must write");
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let mut reporter = VecReporter::new();
        let err = split_with_part_size(&junk, &dest, 64 * 1024, &mut reporter, &|| false)
            .expect_err("a non-wim must not split");
        assert!(
            matches!(err, CoreError::Wim { .. }),
            "a non-wim source must be Wim, got {err}"
        );
        assert!(
            err.to_string().contains(&junk.display().to_string()),
            "the error must name the path: {err}"
        );
        assert_eq!(entry_count(&dest), 0, "a failed split must leave no part");
    }

    #[test]
    fn unlinked_build_reports_unavailable() {
        if wimlib_sys::linked() {
            eprintln!(
                "skip: the unavailable build is not this one; run with WIMLIB_SYS_FORCE_UNLINKED=1"
            );
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let source = root.path().join("install.wim");
        fs::write(&source, b"not a wim").expect("scratch file must write");
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let mut reporter = VecReporter::new();
        let err = split_with_part_size(&source, &dest, 64 * 1024, &mut reporter, &|| false)
            .expect_err("an unlinked build must not split");
        assert!(
            matches!(err, CoreError::WimUnavailable),
            "without libwim the split must be WimUnavailable, got {err}"
        );
        // The pure helpers never need the library.
        assert!(!needs_split(0));
        assert_eq!(
            part_name(Path::new("/tmp/out/install.swm"), 2)
                .expect("part names never need the library"),
            PathBuf::from("/tmp/out/install2.swm")
        );
    }

    #[test]
    fn oversized_part_warns_but_succeeds() {
        if skip_without_backend() {
            return;
        }
        // One 200 KiB incompressible resource cannot be split at 64
        // KiB: the part holding it overshoots, which warns but still
        // succeeds.
        let root = tempfile::tempdir().expect("scratch dir must create");
        let src = root.path().join("src");
        fs::create_dir_all(&src).expect("scratch tree must create");
        let mut state: u32 = 0x1234_5678;
        let mut buf = vec![0u8; 200 * 1024];
        for slot in &mut buf {
            state ^= state.wrapping_shl(13);
            state ^= state.wrapping_shr(17);
            state ^= state.wrapping_shl(5);
            *slot = (state >> 8) as u8;
        }
        fs::write(src.join("big.bin"), &buf).expect("scratch file must write");
        let wim = root.path().join("cap.wim");
        let run = Command::new("wimlib-imagex")
            .arg("capture")
            .arg(&src)
            .arg(&wim)
            .arg("testimg")
            .arg("--compress=LZX")
            .output()
            .expect("wimlib-imagex capture must spawn past the skip gate");
        assert!(
            run.status.success(),
            "capture failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let dest = root.path().join("parts");
        fs::create_dir_all(&dest).expect("parts dir must create");
        let mut reporter = VecReporter::new();
        let split = split_with_part_size(&wim, &dest, 64 * 1024, &mut reporter, &|| false)
            .expect("a single-resource overshoot must still split");
        let mut overshoot = 0usize;
        for part in &split.parts {
            let len = fs::metadata(part).expect("split part must stat").len();
            if len > split.part_size {
                overshoot += 1;
                eprintln!(
                    "overshoot: part {} is {len} bytes, over {}",
                    part.display(),
                    split.part_size
                );
            }
        }
        assert!(
            overshoot > 0,
            "the 200 KiB resource at 64 KiB must overshoot at least one part"
        );
        assert!(
            warns(&reporter)
                .iter()
                .any(|text| text.contains("exceeds the requested part size")),
            "an overshooting part must warn: {:?}",
            warns(&reporter)
        );
    }
}
