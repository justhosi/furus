//! WIM apply over the safe `wimlib-sys` facade (S21, slice 2 of 12).
//!
//! This layer is thin and typed on purpose: it owns no wimlib logic
//! itself (open flags, the progress trampoline, and error strings all
//! live in `wimlib-sys`), it only translates between that facade and
//! [`CoreError`](crate::error::CoreError) — the same decoupling the
//! copy step uses with its own [`Progress`](crate::copy::Progress).
//! The [`Progress`] trait here is deliberately pipeline-free (four
//! counters, no step names): the pipeline's event vocabulary names
//! steps, and an apply has none — a later slice adapts this sink to
//! whatever the UI meters.
//!
//! Cancellation: when [`Progress::cancelled`] turns true the callback
//! answers `false`, wimlib aborts with code 76, and [`Wim::extract`]
//! returns [`CoreError::Cancelled`] — never a wimlib message, so a
//! cancelled apply reads as cancelled in every log.
//!
//! Not here yet: integrity-checked opens, NTFS-mode extraction, and
//! split-WIM handling (see the [`crate::windows`] module docs).

use std::path::Path;
use std::path::PathBuf;

use wimlib_sys::WimlibError;
use wimlib_sys::safe::Compression as SafeCompression;
use wimlib_sys::safe::ERR_ABORTED_BY_PROGRESS;
use wimlib_sys::safe::ExtractFlags;
use wimlib_sys::safe::OpenFlags;

use crate::error::CoreError;
use crate::error::Result;

/// Progress sink for [`Wim::extract`]: byte and file counters, in the
/// same decoupled spirit as [`Progress`](crate::copy::Progress) — no
/// pipeline types leak into an apply, so the UI adapts this sink
/// instead of the other way round.
pub trait Progress {
    /// Report progress: `done_bytes` of `total_bytes` extracted so
    /// far, and `done_files` of `total_files` in the current
    /// structure/metadata phase. Called after every wimlib progress
    /// message, including a terminal sample with
    /// `done_bytes == total_bytes`.
    ///
    /// The file pair is per-phase, not monotonic: the counters restart
    /// when the metadata phase begins, so completion is judged on the
    /// byte pair, never on the files.
    fn report(&mut self, done_bytes: u64, total_bytes: u64, done_files: u64, total_files: u64);

    /// True stops the extraction with [`CoreError::Cancelled`]. Polled
    /// after every progress report; the default never cancels.
    fn cancelled(&self) -> bool {
        false
    }
}

/// One image inside a WIM: its 1-based index plus its XML metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// 1-based image index (the value [`Wim::extract`] takes).
    pub index: u32,
    /// Image name (empty when the image is unnamed).
    pub name: String,
    /// Image description (`None` when the WIM carries none).
    pub description: Option<String>,
}

/// Whole-WIM facts for display and planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Number of images in the WIM.
    pub image_count: u32,
    /// 1-based bootable image index, or 0 when none is bootable.
    pub boot_index: u32,
    /// WIM size in bytes, excluding XML data and integrity table.
    pub total_bytes: u64,
    /// Compression name: `"none"`, `"XPRESS"`, `"LZX"`, `"LZMS"`, or
    /// `"unknown(<n>)"` for a header value S21 does not know.
    pub compression: String,
    /// True when the WIM is one part of a split set.
    pub is_split: bool,
}

/// What one [`Wim::extract`] laid down, from the final progress
/// sample: the terminal `completed` counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// File payload bytes extracted.
    pub bytes: u64,
    /// Files processed in the structure/metadata phase.
    pub files: u64,
}

/// An open WIM, ready to inspect and apply.
///
/// Owns the facade handle plus the path it was opened from (kept for
/// error context). Created by [`Wim::open`]; opening uses no flags —
/// integrity verification stays a later slice, so open is cheap and
/// never refuses a healthy WIM for a checksum reason.
pub struct Wim {
    /// Facade handle (owns the library `WIMStruct`).
    inner: wimlib_sys::safe::Wim,
    /// Path the WIM was opened from, for error context.
    path: PathBuf,
}

impl std::fmt::Debug for Wim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The facade handle is an opaque library pointer: only the
        // path (the stable, log-safe half) shows in debug output.
        formatter
            .debug_struct("Wim")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Translate a facade error into [`CoreError`]: `NotLinked` becomes
/// [`CoreError::WimUnavailable`], anything else carries the path, the
/// wimlib code, and the library message.
fn map_error(path: &Path, error: WimlibError) -> CoreError {
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

/// Name the facade compression the way `wimlib-imagex info` prints it.
fn compression_name(compression: SafeCompression) -> String {
    match compression {
        SafeCompression::None => "none",
        SafeCompression::Xpress => "XPRESS",
        SafeCompression::Lzx => "LZX",
        SafeCompression::Lzms => "LZMS",
        SafeCompression::Other(code) => return format!("unknown({code})"),
    }
    .to_string()
}

impl Wim {
    /// Open the WIM at `path`.
    ///
    /// On a build without `libwim` this returns
    /// [`CoreError::WimUnavailable`] (the facade reports `NotLinked`
    /// before touching anything).
    pub fn open(path: &Path) -> Result<Wim> {
        let inner = wimlib_sys::safe::Wim::open(path, OpenFlags::EMPTY)
            .map_err(|error| map_error(path, error))?;
        Ok(Wim {
            inner,
            path: path.to_path_buf(),
        })
    }

    /// Whole-WIM facts for display and planning.
    pub fn info(&self) -> Result<Info> {
        let raw = self
            .inner
            .info()
            .map_err(|error| map_error(&self.path, error))?;
        Ok(Info {
            image_count: raw.image_count,
            boot_index: raw.boot_index,
            total_bytes: raw.total_bytes,
            compression: compression_name(raw.compression),
            is_split: raw.total_parts > 1,
        })
    }

    /// Every image in index order (empty only when the WIM holds no
    /// images, which a healthy WIM never does).
    pub fn images(&self) -> Result<Vec<Image>> {
        let count = self.info()?.image_count;
        let mut out = Vec::new();
        for index in 1..=count {
            let name = self
                .inner
                .image_name(index)
                .map_err(|error| map_error(&self.path, error))?
                .unwrap_or_default();
            let description = self
                .inner
                .image_description(index)
                .map_err(|error| map_error(&self.path, error))?;
            out.push(Image {
                index,
                name,
                description,
            });
        }
        Ok(out)
    }

    /// Uncompressed payload total of the 1-based `index`, from the
    /// image's `TOTALBYTES` XML property.
    ///
    /// Validates `index` exactly like [`Wim::extract`]: `0` and anything
    /// past `image_count` fail with [`CoreError::InvalidInput`] naming
    /// the index and the count. Otherwise reads `TOTALBYTES`, trims
    /// ASCII whitespace, and accepts only all-digit strings that parse
    /// as `u64`; absent, empty, non-digit, or overflowing values read as
    /// `Ok(None)`, never an error. Library failures map the way the
    /// other methods map them (`NotLinked` to
    /// [`CoreError::WimUnavailable`], the rest through the path, code,
    /// and message).
    pub fn uncompressed_bytes(&self, index: u32) -> Result<Option<u64>> {
        if index == 0 {
            return Err(CoreError::invalid(format!(
                "wim image index 0 is out of range: indices start at 1 (from '{}')",
                self.path.display(),
            )));
        }
        let count = self.info()?.image_count;
        if index > count {
            return Err(CoreError::invalid(format!(
                "wim image index {index} is out of range: '{}' holds {count} image(s)",
                self.path.display(),
            )));
        }
        let raw = self
            .inner
            .image_property(index, "TOTALBYTES")
            .map_err(|error| map_error(&self.path, error))?;
        let Some(text) = raw else {
            return Ok(None);
        };
        let trimmed = text.trim_matches(|slot: char| slot.is_ascii_whitespace());
        if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(None);
        }
        match trimmed.parse::<u64>() {
            Ok(total) => Ok(Some(total)),
            Err(_) => Ok(None),
        }
    }

    /// Extract (`apply`) the 1-based `index` into `target`, reporting
    /// through `progress` and honouring [`Progress::cancelled`].
    ///
    /// Validation runs before any wimlib extraction call: an index
    /// outside `1..=image_count` fails with [`CoreError::InvalidInput`]
    /// naming the index and the count (index `0` is refused without
    /// even asking the library, since indices start at 1), and a
    /// `target` that is not an existing directory fails with
    /// [`CoreError::InvalidInput`] too — a missing target is a bad
    /// argument, not a filesystem failure mid-operation, so it reads
    /// as invalid input rather than an I/O error. A callback that
    /// panics unwinds out of this function (never a cancellation and
    /// never across the C boundary).
    pub fn extract(
        &self,
        index: u32,
        target: &Path,
        progress: &mut dyn Progress,
    ) -> Result<Summary> {
        if index == 0 {
            return Err(CoreError::invalid(format!(
                "wim image index 0 is out of range: indices start at 1 (from '{}')",
                self.path.display(),
            )));
        }
        let count = self.info()?.image_count;
        if index > count {
            return Err(CoreError::invalid(format!(
                "wim image index {index} is out of range: '{}' holds {count} image(s)",
                self.path.display(),
            )));
        }
        if !target.is_dir() {
            return Err(CoreError::invalid(format!(
                "wim extract target '{}' is not an existing directory: create it first",
                target.display(),
            )));
        }
        let mut last = Summary { bytes: 0, files: 0 };
        let outcome =
            self.inner
                .extract_image(index, target, ExtractFlags::empty(), &mut |sample| {
                    last = Summary {
                        bytes: sample.completed_bytes,
                        files: sample.completed_files,
                    };
                    progress.report(
                        sample.completed_bytes,
                        sample.total_bytes,
                        sample.completed_files,
                        sample.total_files,
                    );
                    !progress.cancelled()
                });
        match outcome {
            Ok(()) => Ok(last),
            Err(WimlibError::Code { code, .. }) if code == ERR_ABORTED_BY_PROGRESS => {
                Err(CoreError::Cancelled)
            }
            Err(error) => Err(map_error(&self.path, error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    /// Recording [`Progress`] sink: keeps every report plus a
    /// cancellation flag the test flips.
    struct Sink {
        /// Every `(done_bytes, total_bytes, done_files, total_files)`
        /// report in order.
        reports: Vec<(u64, u64, u64, u64)>,
        /// Returned by [`Progress::cancelled`].
        cancel: bool,
    }

    impl Progress for Sink {
        fn report(&mut self, done_bytes: u64, total_bytes: u64, done_files: u64, total_files: u64) {
            self.reports
                .push((done_bytes, total_bytes, done_files, total_files));
        }

        fn cancelled(&self) -> bool {
            self.cancel
        }
    }

    /// Skip gate (the `skip:` convention): one line naming what was
    /// missing — the library probe first, then the `wimlib-imagex`
    /// presence probe — then `true`.
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
                "skip: wim apply needs wimlib-imagex, which this host does not ship \
                 (install wimlib and re-run)"
            );
            return true;
        }
        false
    }

    /// Capture a two-file scratch tree into `dir/cap.wim` with a fixed
    /// image name; panics past the skip gate when the tool fails.
    fn capture_sample_wim(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).expect("scratch tree must create");
        fs::write(src.join("a.txt"), b"hello wim a\n").expect("scratch file must write");
        fs::write(src.join("sub").join("b.txt"), b"hello wim b\n")
            .expect("scratch file must write");
        let wim = dir.join("cap.wim");
        let run = Command::new("wimlib-imagex")
            .arg("capture")
            .arg(&src)
            .arg(&wim)
            .arg("wimtest")
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

    #[test]
    fn open_without_library_reports_unavailable() {
        if wimlib_sys::linked() {
            eprintln!(
                "skip: the unavailable build is not this one; run with WIMLIB_SYS_FORCE_UNLINKED=1"
            );
            return;
        }
        let err = Wim::open(Path::new("no-such.wim")).expect_err("open must fail without libwim");
        assert!(
            matches!(err, CoreError::WimUnavailable),
            "open without libwim must be WimUnavailable, got {err}"
        );
    }

    #[test]
    fn open_info_images_extract_roundtrip() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_sample_wim(root.path());

        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let info = wim.info().expect("open wim must report info");
        assert_eq!(info.image_count, 1, "{info:?}");
        assert_eq!(info.compression, "LZX", "{info:?}");
        assert!(!info.is_split, "{info:?}");

        let images = wim.images().expect("open wim must list images");
        assert_eq!(images.len(), 1, "{images:?}");
        assert_eq!(images[0].index, 1, "{images:?}");
        assert!(!images[0].name.is_empty(), "{images:?}");

        let out = root.path().join("out");
        fs::create_dir_all(&out).expect("output dir must create");
        let mut sink = Sink {
            reports: Vec::new(),
            cancel: false,
        };
        let summary = wim
            .extract(1, &out, &mut sink)
            .expect("image 1 must extract");
        assert_eq!(summary.bytes, 24, "two 12-byte files, got {summary:?}");
        assert!(!sink.reports.is_empty(), "extraction must report progress");
        let (done, total, _, _) = sink.reports.last().expect("reports must exist");
        assert_eq!(done, total, "terminal sample must complete every byte");
        assert!(
            sink.reports.iter().any(|(_, total, _, _)| *total > 0),
            "at least one sample must report total_bytes > 0"
        );

        for (name, want) in [
            ("a.txt", b"hello wim a\n".as_slice()),
            ("sub/b.txt", b"hello wim b\n".as_slice()),
        ] {
            let got = fs::read(out.join(name)).expect("extracted file must read");
            assert_eq!(got, want, "extracted {name} must match the source bytes");
        }
    }

    #[test]
    fn pre_cancelled_extract_reports_cancelled() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_sample_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let out = root.path().join("out");
        fs::create_dir_all(&out).expect("output dir must create");
        let mut sink = Sink {
            reports: Vec::new(),
            cancel: true,
        };
        let err = wim
            .extract(1, &out, &mut sink)
            .expect_err("a pre-cancelled sink must stop the extraction");
        assert!(
            matches!(err, CoreError::Cancelled),
            "cancellation must be Cancelled, got {err}"
        );
    }

    #[test]
    fn out_of_range_index_is_invalid_input() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_sample_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let out = root.path().join("out");
        fs::create_dir_all(&out).expect("output dir must create");
        let mut sink = Sink {
            reports: Vec::new(),
            cancel: false,
        };
        for index in [0, 2, 99] {
            let err = wim
                .extract(index, &out, &mut sink)
                .expect_err(&format!("index {index} must not extract"));
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "index {index} must be InvalidInput, got {err}"
            );
            let text = err.to_string();
            assert!(text.contains(&index.to_string()), "{text}");
        }
        assert!(
            sink.reports.is_empty(),
            "refused indices must never reach the progress callback"
        );
    }

    #[test]
    fn non_directory_target_is_invalid_input() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_sample_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let blocker = root.path().join("blocker");
        fs::write(&blocker, b"in the way").expect("scratch file must write");
        let mut sink = Sink {
            reports: Vec::new(),
            cancel: false,
        };
        let err = wim
            .extract(1, &blocker, &mut sink)
            .expect_err("a file target must not extract");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "a file target must be InvalidInput, got {err}"
        );
        assert!(
            sink.reports.is_empty(),
            "a refused target must never reach the progress callback"
        );
    }

    #[test]
    fn interior_nul_path_is_invalid_input() {
        if skip_without_backend() {
            return;
        }
        let err = Wim::open(Path::new("a\0b")).expect_err("a NUL path must not open");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "a NUL path must be InvalidInput, got {err}"
        );
    }

    /// A sink that panics inside `report`: the panic must unwind out
    /// of `extract` (re-raised by the facade after the wimlib call
    /// returns), never surface as a cancellation or a wimlib error,
    /// and never abort the process.
    struct PanicSink;

    impl Progress for PanicSink {
        fn report(
            &mut self,
            _done_bytes: u64,
            _total_bytes: u64,
            _done_files: u64,
            _total_files: u64,
        ) {
            panic!("boom");
        }
    }

    #[test]
    fn panicking_sink_unwinds_not_cancelled() {
        if skip_without_backend() {
            return;
        }
        let root = tempfile::tempdir().expect("scratch dir must create");
        let wim_path = capture_sample_wim(root.path());
        let wim = Wim::open(&wim_path).expect("captured wim must open");
        let out = root.path().join("out");
        fs::create_dir_all(&out).expect("output dir must create");
        let mut sink = PanicSink;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wim.extract(1, &out, &mut sink)
        }));
        let payload = outcome.expect_err("a panicking sink must unwind, not return");
        assert!(
            payload
                .downcast_ref::<&str>()
                .is_some_and(|text| *text == "boom"),
            "the panic payload must survive the round trip"
        );
    }
}
