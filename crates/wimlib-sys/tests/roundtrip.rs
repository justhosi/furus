//! Capture/apply round trip through the public safe facade (S21).
//!
//! The tests drive the real library: `wimlib-imagex capture` builds a
//! one-image LZX WIM from a scratch tree, then the [`Wim`] facade
//! opens it, reports on it, and applies it back. A library-less build
//! (or a host without `wimlib-imagex`) skips with one `skip:` line
//! naming what was missing — the file still compiles either way, and
//! the `FORCE_UNLINKED` gate runs the skip path.
//!
//! Not here yet: split WIMs, integrity-checked opens, and NTFS-mode
//! extraction — S21 only exercises the plain open/info/extract flow.

use std::fs;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use wimlib_sys::safe::ExtractFlags;
use wimlib_sys::safe::ExtractProgress;
use wimlib_sys::safe::OpenFlags;
use wimlib_sys::safe::Wim;

/// Skip gate: one `skip:` line naming what was missing, then `true`.
/// The library probe comes first (no tool needed when unlinked); the
/// tool probe uses `--version`, a presence check only — a tool that
/// spawns but misbehaves fails loudly afterwards.
fn skip_without_backend() -> bool {
    if !wimlib_sys::linked() {
        eprintln!(
            "skip: roundtrip needs libwim, which this build did not link (wimlib_present is off)"
        );
        return true;
    }
    if Command::new("wimlib-imagex")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!(
            "skip: roundtrip needs wimlib-imagex, which this host does not ship \
             (install wimlib and re-run)"
        );
        return true;
    }
    false
}

/// Capture `src` (two files plus one subdir, written by the caller)
/// into `dir/cap.wim` with a fixed image name; panics with the tool
/// output when the capture itself fails (past the skip gate a missing
/// tool is a real failure, not a skip).
fn capture_sample_wim(dir: &Path, src: &Path) -> PathBuf {
    let wim = dir.join("cap.wim");
    let run = Command::new("wimlib-imagex")
        .arg("capture")
        .arg(src)
        .arg(&wim)
        .arg("roundtrip")
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

/// Scratch source tree: `a.txt` plus `sub/b.txt`, both with content.
fn write_source_tree(root: &Path) {
    let src = root.join("src");
    fs::create_dir_all(src.join("sub")).expect("scratch tree must create");
    fs::write(src.join("a.txt"), b"hello wim a\n").expect("scratch file must write");
    fs::write(src.join("sub").join("b.txt"), b"hello wim b\n").expect("scratch file must write");
}

#[test]
fn capture_info_extract_roundtrip() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let info = wim.info().expect("open wim must report info");
    assert_eq!(info.image_count, 1, "{info:?}");
    assert_eq!(info.compression, wimlib_sys::Compression::Lzx, "{info:?}");

    let name = wim.image_name(1).expect("image 1 must resolve");
    assert!(
        name.as_deref().is_some_and(|text| !text.is_empty()),
        "image 1 must have a non-empty name, got {name:?}"
    );
    assert!(
        wim.image_description(1).is_ok(),
        "image 1 description must resolve"
    );
    assert_eq!(wim.image_name(0).expect("index 0 must resolve"), None);
    assert_eq!(wim.image_name(2).expect("index 2 must resolve"), None);

    let out = root.path().join("out");
    fs::create_dir_all(&out).expect("output dir must create");
    let mut samples: Vec<ExtractProgress> = Vec::new();
    wim.extract_image(1, &out, ExtractFlags::empty(), &mut |sample| {
        samples.push(sample.clone());
        true
    })
    .expect("image 1 must extract");

    for (name, want) in [
        ("a.txt", b"hello wim a\n".as_slice()),
        ("sub/b.txt", b"hello wim b\n".as_slice()),
    ] {
        let got = fs::read(out.join(name)).expect("extracted file must read");
        assert_eq!(got, want, "extracted {name} must match the source bytes");
    }
    assert!(
        samples.iter().any(|sample| sample.total_bytes > 0),
        "at least one sample must report total_bytes > 0"
    );
    let last = samples
        .last()
        .expect("extraction must report at least one sample");
    assert_eq!(
        last.completed_bytes, last.total_bytes,
        "terminal sample must complete every byte: {last:?}"
    );
    for sample in &samples {
        assert!(
            sample.completed_bytes <= sample.total_bytes,
            "no sample may over-report: {sample:?}"
        );
    }
}

#[test]
fn abort_on_first_sample_reports_aborted() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let out = root.path().join("out");
    fs::create_dir_all(&out).expect("output dir must create");
    let err = wim
        .extract_image(1, &out, ExtractFlags::empty(), &mut |_| false)
        .expect_err("refusing the first sample must abort the extraction");
    assert_eq!(
        err.code(),
        Some(wimlib_sys::safe::ERR_ABORTED_BY_PROGRESS),
        "abort must surface as code 76, got {err}"
    );
}

#[test]
fn open_non_wim_reports_code_with_message() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    let junk = root.path().join("junk.bin");
    fs::write(&junk, b"not a wim at all").expect("scratch file must write");
    let err = match Wim::open(&junk, OpenFlags::EMPTY) {
        Ok(_) => panic!("a non-wim must not open"),
        Err(err) => err,
    };
    let code = err.code().expect("a failed open must carry a code");
    assert_ne!(code, 0, "a failed open must not report success");
    match err {
        wimlib_sys::WimlibError::Code { message, .. } => {
            assert!(!message.is_empty(), "a failed open must name its reason");
        }
        other => panic!("a failed open must be Code, got {other}"),
    }
}

#[test]
fn panicking_callback_unwinds_through_facade() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let out = root.path().join("out");
    fs::create_dir_all(&out).expect("output dir must create");
    // The panic must unwind out of `extract_image` (re-raised after the
    // wimlib call returns, never across C): `catch_unwind` catches it,
    // and the process is still alive to assert on the payload.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        wim.extract_image(1, &out, ExtractFlags::empty(), &mut |_| -> bool {
            panic!("boom");
        })
    }));
    let payload = outcome.expect_err("a panicking callback must unwind, not return");
    assert!(
        payload
            .downcast_ref::<&str>()
            .is_some_and(|text| *text == "boom"),
        "the panic payload must survive the round trip"
    );
}

#[test]
fn interior_nul_path_is_invalid() {
    if skip_without_backend() {
        return;
    }
    let err = match Wim::open(Path::new("a\0b"), OpenFlags::EMPTY) {
        Ok(_) => panic!("a NUL path must not open"),
        Err(err) => err,
    };
    assert!(
        matches!(err, wimlib_sys::WimlibError::InvalidPath { .. }),
        "a NUL path must be InvalidPath, got {err}"
    );
    assert!(err.code().is_none(), "InvalidPath carries no code");
}

/// Non-76 failure branch: extracting onto a regular file fails at
/// directory creation (`WIMLIB_ERR_MKDIR`), and the message is the
/// library text — never a cancellation report. Compile-gated on the
/// link: the constant only exists when the library is linked.
#[cfg(wimlib_present)]
#[test]
fn extract_onto_file_reports_mkdir_not_cancelled() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let blocker = root.path().join("blocker");
    fs::write(&blocker, b"in the way").expect("scratch file must write");
    let err = match wim.extract_image(1, &blocker, ExtractFlags::empty(), &mut |_| true) {
        Ok(()) => panic!("extracting onto a file must not succeed"),
        Err(err) => err,
    };
    assert_eq!(
        err.code(),
        Some(wimlib_sys::WIMLIB_ERR_MKDIR),
        "extracting onto a file must fail at directory creation, got {err}"
    );
    match err {
        wimlib_sys::WimlibError::Code { message, .. } => {
            assert!(
                !message.is_empty(),
                "the library error must name its reason"
            );
        }
        other => panic!("a failed extract must be Code, got {other}"),
    }
}
