//! WIM apply onto the mounted data partition (S21, slice 3 of 12).
//!
//! Why a [`MountedPartition`](crate::pipeline::opener::MountedPartition)
//! rather than a node path or a volume: the mount seam is the copy
//! arm's. The opener mounts the freshly formatted data partition once,
//! core works through the directory, and release stays with the caller.
//! Apply reuses that seam so mounting, free-space reporting, and
//! teardown need no second implementation: the caller mounts, calls
//! [`apply`], then releases. The mount is never released here, mirroring
//! the copy arm's rule that the owner releases, never the step.
//!
//! Contract, in order:
//! a. `wim.info()` first: a malformed or absent image refuses before the
//!    target is touched.
//! b. Empty-target check: read the mount directory; when any entry
//!    exists refuse with [`CoreError::InvalidInput`] naming the target
//!    path and the entry count. A missing or unreadable target reports
//!    [`CoreError::Io`] naming the path, never invalid input.
//! c. Free-space pre-flight: the image's uncompressed payload total from
//!    [`Wim::uncompressed_bytes`] (`TOTALBYTES`), raised by a deliberately
//!    conservative NTFS overhead reserve — the larger of a 64 MiB floor
//!    and 2% of the payload (see `required_with_ntfs_overhead`). The
//!    reserve is generous on purpose: exact NTFS metadata/compression
//!    overhead cannot be predicted from the WIM alone. A mount that holds
//!    less than payload plus reserve refuses with `InvalidInput` in the
//!    copy arm's style. When the image reports no uncompressed total the
//!    check falls back to `info.total_bytes` (the WIM file's own size)
//!    with one `warn` saying so, since that fallback may pass a short
//!    target.
//! d. One `info` message naming the 1-based image index (plus the image
//!    name when `images()` can supply one; a lookup failure only drops
//!    the name, never the apply).
//! e. Extraction through a [`Progress`](crate::windows::wim::Progress)
//!    adapter that mirrors the copy bridge: [`RateEma`] sampling,
//!    throttling through `emit_progress_to` on step `"write"` with a
//!    forced final sample at `done >= total`, and `cancelled`
//!    delegating to the caller's probe. The facade counters are
//!    per-phase, so monotonicity is never asserted. Forced emissions
//!    repeat: the metadata and end messages also arrive with
//!    `done == total`, so several identical terminal `Progress` events
//!    are expected and consumers must not assume the terminal sample is
//!    unique. A set probe also refuses before extraction starts, so an
//!    apply whose probe is already set never touches the target.
//! f. After a successful extract, walk the mount recursively and count
//!    regular-file directory entries (no symlinks followed; directories,
//!    symlinks, and special files excluded) plus their apparent byte
//!    total. The walk is reporting only: no byte or file-count equality
//!    is asserted, because none holds. The facade file pair is per-phase
//!    (`end_file_count` covers only directories and empty files on the
//!    UNIX backend, see `wimlib.h:1039-1053`), hard links extract once
//!    but appear once per name, and reparse data counted by wimlib never
//!    lands as file bytes. The only sound gate is empty extraction: when
//!    the library reports `summary.bytes > 0` yet the walk found zero
//!    regular files, verification fails. True verification of the source
//!    is `wimlib-imagex verify` in the acceptance slices, not this walk.
//! g. One final `info` message with the reported entry and byte counts.
//!
//! A failed or cancelled extraction leaves a partial tree behind; apply
//! never cleans up, so the caller must reformat before retrying.
//!
//! Not here yet: pipeline wiring, CLI surfacing, BCD editing, and
//! Windows To Go.

use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use crate::error::CoreError;
use crate::error::Result;
use crate::pipeline::event::Event;
use crate::pipeline::event::Reporter;
use crate::pipeline::opener::MountedPartition;
use crate::pipeline::write::RateEma;
use crate::pipeline::write::emit_progress_to;
use crate::windows::wim::Wim;

/// What one [`apply`] or [`apply_ntfs`] laid down: file and byte totals.
///
/// For [`apply`], numbers come from a reporting tree walk of the mounted
/// target: `files` counts regular-file directory entries and `bytes` sums each
/// entry's `metadata.len()`. For [`apply_ntfs`], numbers come from wimlib's
/// terminal progress sample (`ExtractFlags::ntfs()`).
///
/// In both cases, these are best-effort numbers for display and tests, not a
/// checksum, not a verification of the source, and must not be used for strict
/// equality across different producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Regular-file directory entries (directory apply) or processed files
    /// (NTFS apply).
    pub files: u64,
    /// Apparent byte total (directory apply) or payload bytes (NTFS apply).
    pub bytes: u64,
}

/// Count top-level entries in `target`: the empty-target gate. A
/// missing or unreadable directory reports [`CoreError::Io`] naming
/// the path; the caller turns a non-zero count into the merge refusal.
fn target_entry_count(target: &Path) -> Result<u64> {
    let listing = std::fs::read_dir(target).map_err(|source| CoreError::io(target, source))?;
    let mut count = 0u64;
    for entry in listing {
        entry.map_err(|source| CoreError::io(target, source))?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

/// Walk `root` recursively and report regular-file entries plus their
/// apparent byte total. Symlinks are never followed and never counted;
/// directories and special files are excluded. Every I/O failure
/// reports [`CoreError::Io`] naming the path it hit. Reporting only:
/// callers must not compare these numbers to wimlib progress totals.
fn count_tree(root: &Path) -> Result<(u64, u64)> {
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let listing = std::fs::read_dir(&dir).map_err(|source| CoreError::io(&dir, source))?;
        for entry in listing {
            let entry = entry.map_err(|source| CoreError::io(&dir, source))?;
            let path: PathBuf = entry.path();
            let meta =
                std::fs::symlink_metadata(&path).map_err(|source| CoreError::io(&path, source))?;
            let kind = meta.file_type();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(meta.len());
            } else {
                continue;
            }
        }
    }
    Ok((files, bytes))
}

/// Conservative NTFS overhead added to the decoded uncompressed payload
/// during free-space pre-flight: the larger of a 64 MiB floor and 2% of the
/// payload. The reserve is deliberately generous — exact NTFS
/// metadata/compression overhead cannot be predicted from the WIM alone —
/// and saturating arithmetic keeps a near-`MAX` payload from panicking.
fn required_with_ntfs_overhead(required: u64) -> u64 {
    const FLOOR: u64 = 64 * 1024 * 1024;
    const SLACK_DIVISOR: u64 = 50; // 2%
    let reserve = FLOOR.max(required.saturating_div(SLACK_DIVISOR));
    required.saturating_add(reserve)
}

/// The [`Progress`](crate::windows::wim::Progress) bridge to the run's
/// event stream: every facade report becomes a step-`"write"`
/// [`Progress`](Event::Progress) rated by the shared [`RateEma`] (no
/// second estimator). Reports throttle through [`emit_progress_to`] at
/// the pipeline cadence, with a forced emit at `done >= total` that can
/// repeat: the metadata and end messages also carry `done == total`, so
/// several identical terminal events are the normal shape, not a bug.
/// `last` is the EMA sampler clock and sees every report, throttled or
/// not; `last_emit` is the throttle clock alone. `cancelled` delegates
/// to the caller's probe.
struct ApplyProgress<'a, 'b> {
    reporter: &'a mut dyn Reporter,
    cancelled: &'b dyn Fn() -> bool,
    ema: RateEma,
    last: Instant,
    last_emit: Instant,
    done: u64,
}

impl<'a, 'b> ApplyProgress<'a, 'b> {
    fn new(reporter: &'a mut dyn Reporter, cancelled: &'b dyn Fn() -> bool) -> Self {
        let now = Instant::now();
        Self {
            reporter,
            cancelled,
            ema: RateEma::new(),
            last: now,
            last_emit: now,
            done: 0,
        }
    }
}

impl crate::windows::wim::Progress for ApplyProgress<'_, '_> {
    fn report(&mut self, done_bytes: u64, total_bytes: u64, _done_files: u64, _total_files: u64) {
        let now = Instant::now();
        if done_bytes > self.done {
            self.ema
                .observe(done_bytes - self.done, now.duration_since(self.last));
        }
        self.last = now;
        self.done = done_bytes;
        emit_progress_to(
            &mut *self.reporter,
            "write",
            done_bytes,
            Some(total_bytes),
            &self.ema,
            &mut self.last_emit,
            done_bytes >= total_bytes,
        );
    }

    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
}

/// Apply (extract) the 1-based `index` of `wim` onto the already
/// mounted data partition, with progress, cancellation, and the refusal
/// paths.
///
/// The mount is borrowed, never released: the caller owns release,
/// mirroring the copy arm's rule. A successful return holds the
/// reported counts (see step f); a failed or cancelled extraction leaves
/// a partial tree the caller must reformat before retrying.
///
/// Free-space pre-flight compares the reported free bytes against the
/// uncompressed payload plus a conservative NTFS overhead reserve (the
/// larger of 64 MiB and 2% of the payload); see step c of the module doc.
pub fn apply(
    mounted: &mut dyn MountedPartition,
    wim: &Wim,
    index: u32,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<Applied> {
    // a. Image facts first: a malformed image refuses before the target
    // is touched.
    let info = wim.info()?;
    // Clone the mount path once so no borrow of `mounted` crosses the
    // calls below; cloning names no file, so the target is still
    // untouched here.
    let target: PathBuf = mounted.path().to_path_buf();
    // b. Empty-target gate: refuse to merge into unknown content.
    let entries = target_entry_count(target.as_path())?;
    if entries > 0 {
        return Err(CoreError::invalid(format!(
            "apply target '{}' holds {entries} entries: refusing to merge an image into unknown content",
            target.display(),
        )));
    }
    // c. Free-space pre-flight against the uncompressed payload total.
    // `TOTALBYTES` is what the target must hold; the WIM file's own
    // size (`info.total_bytes`) is only the fallback when the image
    // reports nothing, and then only with a warning.
    let want = match wim.uncompressed_bytes(index)? {
        Some(total) => total,
        None => {
            let size = info.total_bytes;
            reporter.event(Event::Message {
                level: "warn",
                text: format!(
                    "image {index} reports no uncompressed total: using the WIM file size {size} for the free-space check, which may pass a short target"
                ),
            });
            size
        }
    };
    let free = mounted.free_bytes()?;
    let need = required_with_ntfs_overhead(want);
    if free < need {
        let reserve = need.saturating_sub(want);
        return Err(CoreError::invalid(format!(
            "apply needs {need} bytes ({want} uncompressed plus a conservative {reserve}-byte NTFS overhead reserve) but the destination reports {free} free: refusing before any write",
        )));
    }
    // A set probe refuses before extraction starts, so an apply whose
    // probe is already set never touches the target. Cancellation
    // mid-extraction still leaves a partial tree (see the module doc).
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    // d. One info line naming the image; the name is best effort.
    let name: Option<String> = wim
        .images()
        .ok()
        .and_then(|images| {
            images
                .into_iter()
                .find(|image| image.index == index)
                .map(|image| image.name)
        })
        .filter(|name| !name.is_empty());
    let opening = match name {
        Some(name) => format!("applying image {index} (\"{name}\") to the mounted data partition"),
        None => format!("applying image {index} to the mounted data partition"),
    };
    reporter.event(Event::Message {
        level: "info",
        text: opening,
    });
    // e. Extract through the throttled bridge.
    let summary = {
        let mut progress = ApplyProgress::new(&mut *reporter, cancelled);
        wim.extract(index, target.as_path(), &mut progress)?
    };
    // f. Reporting walk plus the one sound gate: data claimed but no
    // regular file found. Nothing else here may fail on the numbers.
    let (files, bytes) = count_tree(target.as_path())?;
    if summary.bytes > 0 && files == 0 {
        return Err(CoreError::Verify {
            message: format!(
                "apply extracted {} bytes but the target holds {files} regular files ({bytes} bytes): the extracted tree holds no regular files",
                summary.bytes,
            ),
        });
    }
    // g. One final info line from the reported counts.
    reporter.event(Event::Message {
        level: "info",
        text: format!("applied {files} entries ({bytes} bytes)"),
    });
    Ok(Applied { bytes, files })
}

/// Apply (extract) the 1-based `index` of `wim` directly to the raw NTFS block
/// device in NTFS-volume mode, with progress, cancellation, and the refusal
/// paths.
///
/// Unlike [`apply`], extraction targets a raw block device node instead of a
/// mounted directory and preserves all NTFS metadata. Preflight checks `capacity`
/// instead of mounted free space, comparing it against the uncompressed payload
/// plus the same conservative NTFS overhead reserve as [`apply`] (the larger of
/// 64 MiB and 2% of the payload). Returns [`Applied`] directly from the summary
/// counters (no directory tree walk).
///
/// Note: in production `device` is a raw block device node (e.g.
/// `partition_path()`), but wimlib NTFS mode also accepts an unmounted volume
/// image file, so test seams may pass a scratch image file.
pub fn apply_ntfs(
    device: &Path,
    capacity: u64,
    wim: &Wim,
    index: u32,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<Applied> {
    // a. Image facts first: a malformed image refuses before the target
    // is touched.
    let info = wim.info()?;
    // b. Free-space pre-flight against the uncompressed payload total.
    let want = match wim.uncompressed_bytes(index)? {
        Some(total) => total,
        None => {
            let size = info.total_bytes;
            reporter.event(Event::Message {
                level: "warn",
                text: format!(
                    "image {index} reports no uncompressed total: using the WIM file size {size} for the free-space check, which may pass a short target"
                ),
            });
            size
        }
    };
    let need = required_with_ntfs_overhead(want);
    if capacity < need {
        let reserve = need.saturating_sub(want);
        return Err(CoreError::invalid(format!(
            "apply needs {need} bytes ({want} uncompressed plus a conservative {reserve}-byte NTFS overhead reserve) but the destination reports {capacity} total bytes: refusing before any write",
        )));
    }
    // A set probe refuses before extraction starts.
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    // c. One info line naming the image; the name is best effort.
    let name: Option<String> = wim
        .images()
        .ok()
        .and_then(|images| {
            images
                .into_iter()
                .find(|image| image.index == index)
                .map(|image| image.name)
        })
        .filter(|name| !name.is_empty());
    let opening = match name {
        Some(name) => format!(
            "applying image {index} (\"{name}\") to NTFS volume '{}'",
            device.display()
        ),
        None => format!(
            "applying image {index} to NTFS volume '{}'",
            device.display()
        ),
    };
    reporter.event(Event::Message {
        level: "info",
        text: opening,
    });
    // d. Extract through the throttled bridge using NTFS-volume mode.
    let summary = {
        let mut progress = ApplyProgress::new(&mut *reporter, cancelled);
        wim.extract_ntfs(index, device, &mut progress)?
    };
    // e. One final info line from the reported summary counts.
    reporter.event(Event::Message {
        level: "info",
        text: format!(
            "applied {} entries ({} bytes)",
            summary.files, summary.bytes
        ),
    });
    Ok(Applied {
        bytes: summary.bytes,
        files: summary.files,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;
    use crate::error::CoreError;
    use crate::pipeline::event::Event;
    use crate::pipeline::event::VecReporter;

    /// Local fake [`MountedPartition`]: a directory path, a fixed
    /// `free_bytes` answer, and a counted `release` the apply must
    /// never call.
    struct FakeMount {
        path: PathBuf,
        free: u64,
        releases: usize,
    }

    impl FakeMount {
        fn new(path: PathBuf, free: u64) -> Self {
            Self {
                path,
                free,
                releases: 0,
            }
        }
    }

    impl MountedPartition for FakeMount {
        fn path(&self) -> &Path {
            &self.path
        }

        fn free_bytes(&self) -> Result<u64> {
            Ok(self.free)
        }

        fn release(&mut self) -> Result<()> {
            self.releases = self.releases.saturating_add(1);
            Ok(())
        }
    }

    /// Skip gate (the `skip:` convention): one line naming what was
    /// missing, then true. The library probe comes first, then the
    /// `wimlib-imagex` presence probe.
    fn skip_without_backend() -> bool {
        if !wimlib_sys::linked() {
            eprintln!(
                "skip: wim apply needs libwim, which this build did not link (wimlib_present is off)"
            );
            return true;
        }
        if Command::new("wimlib-imagex")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!(
                "skip: wim apply needs wimlib-imagex, which this host does not ship (install wimlib and re-run)"
            );
            return true;
        }
        false
    }

    /// Capture a three-file scratch tree into `dir/cap.wim` with image
    /// name `testimg`: `a.txt` (6 bytes), `sub/b.txt` (10 bytes), and
    /// an empty `empty.txt`. Returns the WIM path.
    fn capture_three_file_wim(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).expect("scratch tree must create");
        fs::write(src.join("a.txt"), b"alpha\n").expect("scratch file must write");
        fs::write(src.join("sub").join("b.txt"), b"beta beta\n").expect("scratch file must write");
        fs::write(src.join("empty.txt"), b"").expect("scratch file must write");
        let wim = dir.join("cap.wim");
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
        wim
    }

    /// Capture a 1 MiB-zero plus 3-byte scratch tree into
    /// `dir/big.wim` with image name `testimg` (`big.bin` 1048576
    /// bytes, `small.txt` 3 bytes). LZX shrinks the zeros to a few KiB,
    /// so the uncompressed total dwarfs the WIM file size on purpose.
    fn capture_big_wim(dir: &Path) -> PathBuf {
        let src = dir.join("bigsrc");
        fs::create_dir_all(&src).expect("scratch tree must create");
        fs::write(src.join("big.bin"), vec![0u8; 1024 * 1024]).expect("scratch file must write");
        fs::write(src.join("small.txt"), b"hi\n").expect("scratch file must write");
        let wim = dir.join("big.wim");
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
        wim
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
    fn infos(reporter: &VecReporter) -> Vec<&str> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message {
                    level: "info",
                    text,
                } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn happy_path_extracts_three_files_with_progress() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_three_file_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let info = wim.info().expect("open wim must report info");
        assert_eq!(info.image_count, 1, "{info:?}");

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), u64::MAX);
        let mut reporter = VecReporter::new();
        let applied = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect("image 1 must apply onto the empty target");
        assert_eq!(applied.files, 3, "{applied:?}");
        assert_eq!(applied.bytes, 16, "6 + 10 + 0 bytes, got {applied:?}");
        assert_eq!(mounted.releases, 0, "apply never releases the mount");

        for (name, want) in [
            ("a.txt", b"alpha\n".as_slice()),
            ("sub/b.txt", b"beta beta\n".as_slice()),
            ("empty.txt", b"".as_slice()),
        ] {
            let got = fs::read(target.join(name)).expect("extracted file must read");
            assert_eq!(got, want, "extracted {name} must match the source bytes");
        }

        let progress = progresses(&reporter);
        assert!(
            !progress.is_empty(),
            "extraction must report at least one write sample"
        );
        assert!(
            progress.iter().all(|(step, _, _)| *step == "write"),
            "every progress sample is step write: {progress:?}"
        );
        let (step, done, total) = progress.last().copied().expect("samples must exist");
        assert_eq!(step, "write");
        assert_eq!(
            Some(done),
            total,
            "terminal sample must complete every byte: {progress:?}"
        );

        let messages = infos(&reporter);
        assert!(
            messages.iter().any(|text| text.contains("3 entries")),
            "final info message must mention 3 entries: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|text| text.contains("applying image 1")),
            "opening info message must name image 1: {messages:?}"
        );
    }

    #[test]
    fn non_empty_target_refuses_and_keeps_the_file() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_three_file_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        fs::write(target.join("existing.txt"), b"keep me\n").expect("blocker must write");
        let before = fs::read(target.join("existing.txt")).expect("blocker must read");

        let mut mounted = FakeMount::new(target.clone(), u64::MAX);
        let mut reporter = VecReporter::new();
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect_err("a non-empty target must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "a non-empty target must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&target.display().to_string()), "{text}");
        assert!(text.contains('1'), "{text}");
        assert!(
            text.ends_with(": refusing to merge an image into unknown content"),
            "{text}"
        );
        assert!(text.is_ascii(), "{text}");

        let after = fs::read(target.join("existing.txt")).expect("blocker must survive");
        assert_eq!(
            before, after,
            "the pre-existing file must survive untouched"
        );
        let mut names: Vec<String> = fs::read_dir(&target)
            .expect("target must list")
            .map(|entry| {
                entry
                    .expect("target entry must read")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["existing.txt".to_string()], "{names:?}");
        assert_eq!(mounted.releases, 0, "a refused apply never releases");
    }

    #[test]
    fn short_free_space_refuses_on_the_uncompressed_total() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let compressed = wim.info().expect("info must report").total_bytes;
        assert!(
            uncompressed > compressed,
            "the LZX fixture must prove the compressed size is not used: uncompressed {uncompressed} vs WIM size {compressed}"
        );
        let free = uncompressed.saturating_sub(1);

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), free);
        let mut reporter = VecReporter::new();
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect_err("a short mount must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "short free space must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&uncompressed.to_string()), "{text}");
        assert!(text.contains(&free.to_string()), "{text}");
        assert!(text.contains("refusing before any write"), "{text}");
        assert!(text.is_ascii(), "{text}");

        let count = fs::read_dir(&target).expect("target must list").count();
        assert_eq!(count, 0, "the refused target must stay empty");
        assert_eq!(mounted.releases, 0, "a refused apply never releases");
    }

    #[test]
    fn apply_ntfs_short_capacity_refuses_on_the_uncompressed_total() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let compressed = wim.info().expect("info must report").total_bytes;
        assert!(
            uncompressed > compressed,
            "the LZX fixture must prove the compressed size is not used: uncompressed {uncompressed} vs WIM size {compressed}"
        );
        let capacity = uncompressed.saturating_sub(1);
        let dev = Path::new("/dev/nonexistent_fake_device");
        let mut reporter = VecReporter::new();
        let err = apply_ntfs(dev, capacity, &wim, 1, &mut reporter, &|| false)
            .expect_err("a short capacity must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "short capacity must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&uncompressed.to_string()), "{text}");
        assert!(text.contains(&capacity.to_string()), "{text}");
        assert!(text.contains("refusing before any write"), "{text}");
        assert!(text.is_ascii(), "{text}");
    }

    /// Pre-flight only: an available byte count exactly equal to the
    /// payload plus reserve must pass the check. A pre-set probe then
    /// cancels before extraction, so a `Cancelled` result (and not the
    /// free-space `InvalidInput`) proves the check accepted the exact fit
    /// without ever touching the target.
    #[test]
    fn apply_exact_fit_passes_preflight() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let need = required_with_ntfs_overhead(uncompressed);
        assert!(
            need > uncompressed,
            "the reserve must make the need exceed the raw payload"
        );

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), need);
        let mut reporter = VecReporter::new();
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| true)
            .expect_err("a pre-set probe must cancel after pre-flight passes");
        assert!(
            matches!(err, CoreError::Cancelled),
            "an exact fit must pass pre-flight (probe then cancels), got {err}"
        );
        let count = fs::read_dir(&target).expect("target must list").count();
        assert_eq!(count, 0, "an exact fit must not start extraction here");
        assert_eq!(mounted.releases, 0, "apply never releases the mount");
    }

    /// One byte below payload plus reserve must refuse, and the refusal
    /// must name both the raw payload and the required-with-overhead
    /// total so it is actionable. `need - 1` is still far above the raw
    /// payload, so this can only fail because of the new reserve.
    #[test]
    fn apply_under_margin_refuses_with_both_totals() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let need = required_with_ntfs_overhead(uncompressed);
        let available = need - 1;
        assert!(
            available > uncompressed,
            "the under-margin value must exceed the raw payload"
        );

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), available);
        let mut reporter = VecReporter::new();
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect_err("one byte under the reserve must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "an under-margin target must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&uncompressed.to_string()), "{text}");
        assert!(text.contains(&need.to_string()), "{text}");
        assert!(text.contains(&available.to_string()), "{text}");
        assert!(text.contains("refusing before any write"), "{text}");
        assert!(text.is_ascii(), "{text}");

        let count = fs::read_dir(&target).expect("target must list").count();
        assert_eq!(count, 0, "the refused target must stay empty");
        assert_eq!(mounted.releases, 0, "a refused apply never releases");
    }

    /// Ample space must pass pre-flight; a pre-set probe then cancels
    /// before extraction, proving the check accepted the generous value.
    #[test]
    fn apply_ample_space_passes_preflight() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let need = required_with_ntfs_overhead(
            wim.uncompressed_bytes(1)
                .expect("TOTALBYTES must read")
                .expect("the LZX image must report TOTALBYTES"),
        );

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), need.saturating_add(1024 * 1024));
        let mut reporter = VecReporter::new();
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| true)
            .expect_err("a pre-set probe must cancel after pre-flight passes");
        assert!(
            matches!(err, CoreError::Cancelled),
            "ample space must pass pre-flight (probe then cancels), got {err}"
        );
    }

    /// NTFS path: capacity exactly equal to payload plus reserve passes
    /// pre-flight; a pre-set probe cancels before the fake device is used.
    #[test]
    fn apply_ntfs_exact_fit_passes_preflight() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let need = required_with_ntfs_overhead(uncompressed);
        let dev = Path::new("/dev/nonexistent_fake_device");
        let mut reporter = VecReporter::new();
        let err = apply_ntfs(dev, need, &wim, 1, &mut reporter, &|| true)
            .expect_err("a pre-set probe must cancel after pre-flight passes");
        assert!(
            matches!(err, CoreError::Cancelled),
            "an exact capacity must pass pre-flight (probe then cancels), got {err}"
        );
    }

    /// NTFS path: one byte below payload plus reserve refuses with an
    /// actionable message naming both totals.
    #[test]
    fn apply_ntfs_under_margin_refuses_with_both_totals() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let uncompressed = wim
            .uncompressed_bytes(1)
            .expect("TOTALBYTES must read")
            .expect("the LZX image must report TOTALBYTES");
        let need = required_with_ntfs_overhead(uncompressed);
        let capacity = need - 1;
        assert!(
            capacity > uncompressed,
            "the under-margin capacity must exceed the raw payload"
        );
        let dev = Path::new("/dev/nonexistent_fake_device");
        let mut reporter = VecReporter::new();
        let err = apply_ntfs(dev, capacity, &wim, 1, &mut reporter, &|| false)
            .expect_err("one byte under the reserve must refuse");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "an under-margin capacity must be InvalidInput, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains(&uncompressed.to_string()), "{text}");
        assert!(text.contains(&need.to_string()), "{text}");
        assert!(text.contains(&capacity.to_string()), "{text}");
        assert!(text.contains("refusing before any write"), "{text}");
        assert!(text.is_ascii(), "{text}");
    }

    /// NTFS path: ample capacity passes pre-flight; a pre-set probe then
    /// cancels before the fake device is used.
    #[test]
    fn apply_ntfs_ample_space_passes_preflight() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_big_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let need = required_with_ntfs_overhead(
            wim.uncompressed_bytes(1)
                .expect("TOTALBYTES must read")
                .expect("the LZX image must report TOTALBYTES"),
        );
        let dev = Path::new("/dev/nonexistent_fake_device");
        let mut reporter = VecReporter::new();
        let err = apply_ntfs(
            dev,
            need.saturating_add(1024 * 1024),
            &wim,
            1,
            &mut reporter,
            &|| true,
        )
        .expect_err("a pre-set probe must cancel after pre-flight passes");
        assert!(
            matches!(err, CoreError::Cancelled),
            "ample capacity must pass pre-flight (probe then cancels), got {err}"
        );
    }

    #[test]
    fn apply_ntfs_pre_set_probe_refuses_before_extraction_starts() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_three_file_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let dev = Path::new("/dev/nonexistent_fake_device");
        let mut reporter = VecReporter::new();
        let err = apply_ntfs(dev, u64::MAX, &wim, 1, &mut reporter, &|| true)
            .expect_err("an already-set probe must refuse");
        assert!(
            matches!(err, CoreError::Cancelled),
            "an already-set probe must be Cancelled, got {err}"
        );
    }

    #[test]
    fn pre_set_probe_refuses_before_extraction_starts() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_three_file_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), u64::MAX);
        let mut reporter = VecReporter::new();
        // Only what this proves: a probe already set before the call
        // refuses without touching the target. Cancellation
        // mid-extraction still leaves a partial tree (see module doc).
        let err = apply(&mut mounted, &wim, 1, &mut reporter, &|| true)
            .expect_err("an already-set probe must refuse");
        assert!(
            matches!(err, CoreError::Cancelled),
            "an already-set probe must be Cancelled, got {err}"
        );
        let count = fs::read_dir(&target).expect("target must list").count();
        assert_eq!(count, 0, "a pre-set probe leaves the target untouched");
        assert_eq!(mounted.releases, 0, "a refused apply never releases");
    }

    #[test]
    fn hard_links_count_once_per_name() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let src = root.path().join("hardsrc");
        fs::create_dir_all(&src).expect("scratch tree must create");
        fs::write(src.join("big.bin"), vec![0u8; 1024 * 1024]).expect("scratch file must write");
        fs::hard_link(src.join("big.bin"), src.join("biglink.bin")).expect("hard link must create");
        fs::write(src.join("small.txt"), b"abc").expect("scratch file must write");
        let wim_path = root.path().join("hard.wim");
        let run = Command::new("wimlib-imagex")
            .arg("capture")
            .arg(&src)
            .arg(&wim_path)
            .arg("testimg")
            .arg("--compress=LZX")
            .output()
            .expect("wimlib-imagex capture must spawn past the skip gate");
        assert!(
            run.status.success(),
            "capture failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let wim = Wim::open(&wim_path).expect("captured wim must open");

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), u64::MAX);
        let mut reporter = VecReporter::new();
        let applied = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect("an image with a hard link must apply");
        assert_eq!(applied.files, 3, "{applied:?}");
        assert_eq!(applied.bytes, 1024 * 1024 + 1024 * 1024 + 3, "{applied:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let first = fs::metadata(target.join("big.bin")).expect("hard link target must stat");
            let second =
                fs::metadata(target.join("biglink.bin")).expect("hard link peer must stat");
            assert_eq!(
                first.ino(),
                second.ino(),
                "the extraction must preserve the hard link"
            );
        }
        // The tree apparent total counts the shared payload twice, while
        // wimlib reports the extracted stream bytes once: the walk must
        // not be compared to the progress total.
        let progress = progresses(&reporter);
        let (_, _, total) = progress.last().copied().expect("samples must exist");
        let total = total.expect("wimlib must report a total");
        assert!(
            applied.bytes > total,
            "hard-linked data counts per name ({}) but extracts once ({total})",
            applied.bytes,
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_image_is_restored_but_not_counted() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let src = root.path().join("linksrc");
        fs::create_dir_all(&src).expect("scratch tree must create");
        fs::write(src.join("real.txt"), b"0123456789ABCDEF").expect("scratch file must write");
        std::os::unix::fs::symlink("real.txt", src.join("link.txt")).expect("symlink must create");
        let wim_path = root.path().join("link.wim");
        let run = Command::new("wimlib-imagex")
            .arg("capture")
            .arg(&src)
            .arg(&wim_path)
            .arg("testimg")
            .arg("--compress=LZX")
            .output()
            .expect("wimlib-imagex capture must spawn past the skip gate");
        assert!(
            run.status.success(),
            "capture failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let wim = Wim::open(&wim_path).expect("captured wim must open");

        let target = root.path().join("target");
        fs::create_dir_all(&target).expect("target dir must create");
        let mut mounted = FakeMount::new(target.clone(), u64::MAX);
        let mut reporter = VecReporter::new();
        let applied = apply(&mut mounted, &wim, 1, &mut reporter, &|| false)
            .expect("an image with a symlink must apply");
        assert_eq!(applied.files, 1, "{applied:?}");
        assert_eq!(applied.bytes, 16, "{applied:?}");
        let meta = fs::symlink_metadata(target.join("link.txt")).expect("link must stat");
        assert!(
            meta.file_type().is_symlink(),
            "the link must be restored as a link"
        );
        let got = fs::read(target.join("real.txt")).expect("real file must read");
        assert_eq!(got, b"0123456789ABCDEF", "real file bytes must survive");
    }

    #[test]
    fn count_tree_counts_regular_files_only() {
        let root = tempfile::tempdir().expect("scratch dir must create");
        fs::create_dir_all(root.path().join("sub")).expect("subdir must create");
        fs::write(root.path().join("a.txt"), b"12345").expect("file must write");
        fs::write(root.path().join("sub").join("b.txt"), b"12").expect("file must write");
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", root.path().join("link")).expect("symlink must create");
        let (files, bytes) = count_tree(root.path()).expect("the fixture tree must walk");
        assert_eq!(files, 2, "symlink and directory are excluded");
        assert_eq!(bytes, 7, "5 + 2 apparent bytes");
    }

    /// The adapter's `report` is a plain Rust call: a panicking
    /// reporter unwinds through it, never swallowed and never turned
    /// into a cancellation. The wimlib C trampoline (already covered in
    /// `wim`) never sees this path because apply owns its adapter; the
    /// caller supplies a `Reporter`, not a `Progress`.
    struct PanicReporter;

    impl Reporter for PanicReporter {
        fn event(&mut self, _event: Event) {
            panic!("boom");
        }
    }

    #[test]
    fn adapter_report_is_a_plain_call() {
        use crate::windows::wim::Progress as WimProgress;
        let mut reporter = PanicReporter;
        let never = || false;
        let mut progress = ApplyProgress::new(&mut reporter, &never);
        // Force the emit past the throttle (`done >= total`
        // always emits); a throttled sample would return early without
        // touching the reporter and prove nothing.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            progress.report(2, 2, 0, 0);
        }));
        let payload = outcome.expect_err("a panicking reporter must unwind, not be swallowed");
        assert!(
            payload
                .downcast_ref::<&str>()
                .is_some_and(|text| *text == "boom"),
            "the panic payload must survive the round trip"
        );
    }

    const FLOOR: u64 = 64 * 1024 * 1024;

    /// The 64 MiB floor dominates for payloads below the 2% crossover
    /// (payload < 3.2 GiB, since `floor * 50 == 3.2 GiB`).
    #[test]
    fn ntfs_overhead_applies_64_mib_floor() {
        assert_eq!(required_with_ntfs_overhead(0), FLOOR);
        assert_eq!(required_with_ntfs_overhead(1), 1 + FLOOR);
        assert_eq!(
            required_with_ntfs_overhead(1024 * 1024),
            1024 * 1024 + FLOOR
        );
        // Just below the crossover the floor still wins.
        let just_below = FLOOR * 50 - 1;
        assert_eq!(required_with_ntfs_overhead(just_below), just_below + FLOOR);
    }

    /// At and above the crossover the 2% slack dominates. Expected values
    /// are computed independently of the helper under test.
    #[test]
    fn ntfs_overhead_uses_two_percent_above_crossover() {
        // required / 50 == FLOOR + 1, so the slack beats the floor.
        let required = FLOOR * 50 + 50;
        assert_eq!(required / 50, FLOOR + 1);
        assert_eq!(required_with_ntfs_overhead(required), required + FLOOR + 1);
        // Exactly at the crossover both branches give the 64 MiB floor.
        let crossover = FLOOR * 50;
        assert_eq!(required_with_ntfs_overhead(crossover), crossover + FLOOR);
    }

    /// Saturating arithmetic keeps a near-`MAX` payload from overflowing
    /// into a panic; the result clamps to `u64::MAX`.
    #[test]
    fn ntfs_overhead_saturates() {
        assert_eq!(required_with_ntfs_overhead(u64::MAX), u64::MAX);
        assert_eq!(required_with_ntfs_overhead(u64::MAX - 1), u64::MAX);
    }
}
