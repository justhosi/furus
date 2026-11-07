//! Capture/apply/split round trip through the public safe facade (S21).
//!
//! The tests drive the real library: `wimlib-imagex capture` builds a
//! one-image LZX WIM from a scratch tree, then the [`Wim`] facade
//! opens it, reports on it, applies it back, and splits it into
//! FAT32-sized parts. A library-less build (or a host without
//! `wimlib-imagex`) skips with one `skip:` line naming what was
//! missing — the file still compiles either way, and the
//! `FORCE_UNLINKED` gate runs the skip path.
//!
//! Not here yet: integrity-checked opens and NTFS-mode extraction —
//! S21 only exercises the plain open/info/extract/split flow.

use std::fs;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use wimlib_sys::safe::ExtractFlags;
use wimlib_sys::safe::ExtractProgress;
use wimlib_sys::safe::OpenFlags;
use wimlib_sys::safe::SplitProgress;
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

/// Scratch tree of `files` 16 KiB incompressible files: deterministic
/// xorshift bytes (no new dependency) that LZX cannot shrink, so a 64
/// KiB part size yields many parts (64 files is ~1 MiB on disk).
fn write_random_tree(root: &Path, files: usize) {
    let src = root.join("bigsrc");
    fs::create_dir_all(&src).expect("scratch tree must create");
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

/// Capture the random tree into `dir/big.wim` with image name
/// `roundtrip`; panics past the skip gate when the tool fails.
fn capture_big_wim(dir: &Path) -> PathBuf {
    let wim = dir.join("big.wim");
    let run = Command::new("wimlib-imagex")
        .arg("capture")
        .arg(dir.join("bigsrc"))
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

/// Expected part name for `index` (1-based): `first` unchanged, the
/// rest `stem2.swm`, `stem3.swm`, ... in the same directory.
fn expected_part_name(first: &Path, index: u32) -> PathBuf {
    if index <= 1 {
        return first.to_path_buf();
    }
    let stem = first
        .file_stem()
        .expect("first part must have a stem")
        .to_string_lossy()
        .into_owned();
    first.with_file_name(format!("{stem}{index}.swm"))
}

#[test]
fn split_many_small_files_yields_ordered_parts() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_random_tree(root.path(), 64);
    let wim_path = capture_big_wim(root.path());
    let source_len = fs::metadata(&wim_path)
        .expect("captured wim must stat")
        .len();
    assert!(
        source_len > 512 * 1024,
        "the LZX fixture must stay near 1 MiB for a 64 KiB split, got {source_len}"
    );

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let dest_dir = root.path().join("parts");
    fs::create_dir_all(&dest_dir).expect("parts dir must create");
    let first = dest_dir.join("big.swm");
    const PART_SIZE: u64 = 64 * 1024;
    let mut samples: Vec<SplitProgress> = Vec::new();
    wim.split(&first, PART_SIZE, &mut |sample| {
        samples.push(sample.clone());
        true
    })
    .expect("a 1 MiB LZX wim must split at 64 KiB");

    assert!(
        samples.len() >= 4,
        "splitting must report begin/end per part, got {} samples",
        samples.len()
    );
    let last = samples
        .last()
        .expect("split must report at least one sample");
    let total_parts = last.total_parts;
    assert!(
        total_parts >= 3,
        "a 1 MiB fixture at 64 KiB must yield several parts, got {total_parts}"
    );
    assert_eq!(
        last.completed_bytes, last.total_bytes,
        "terminal sample must complete every byte: {last:?}"
    );
    assert!(
        last.total_bytes > 0,
        "split must report a non-zero total: {last:?}"
    );
    for sample in &samples {
        assert!(
            sample.completed_bytes <= sample.total_bytes,
            "no sample may over-report: {sample:?}"
        );
        assert!(
            sample.part >= 1 && sample.part <= total_parts,
            "part numbers are 1-based: {sample:?}"
        );
        assert_eq!(sample.total_parts, total_parts, "{sample:?}");
    }

    // Every expected name exists; the first part re-opens as a spanned
    // set whose info matches the files on disk.
    let mut names: Vec<PathBuf> = Vec::new();
    for index in 1..=total_parts {
        names.push(expected_part_name(&first, index));
    }
    for name in &names {
        assert!(
            name.is_file(),
            "expected split part must exist: {}",
            name.display()
        );
    }
    let opened = Wim::open(&first, OpenFlags::EMPTY).expect("first split part must open");
    let info = opened.info().expect("first part must report info");
    assert!(info.spanned, "first split part must be spanned: {info:?}");
    assert_eq!(info.part_number, 1, "{info:?}");
    assert_eq!(
        u32::from(info.total_parts),
        total_parts,
        "info total must match the files on disk: {info:?}"
    );
    let on_disk = fs::read_dir(&dest_dir)
        .expect("parts dir must list")
        .count();
    assert_eq!(
        on_disk as u32, total_parts,
        "the parts dir must hold exactly the split set"
    );

    // Every part except the last stays within the requested size. A
    // single resource larger than the part size cannot be split, so an
    // overshoot is allowed but must be reported, never silent.
    let mut overshoot: Vec<(PathBuf, u64)> = Vec::new();
    for (position, name) in names.iter().enumerate() {
        let len = fs::metadata(name).expect("split part must stat").len();
        let is_last = position + 1 == names.len();
        if !is_last && len > PART_SIZE {
            eprintln!(
                "overshoot: part {} is {len} bytes, exceeding the {PART_SIZE} byte part size",
                name.display()
            );
            overshoot.push((name.clone(), len));
        } else if !is_last {
            assert!(
                len <= PART_SIZE,
                "non-terminal part {} is {len} bytes, over {PART_SIZE}",
                name.display()
            );
        }
    }
    if !overshoot.is_empty() {
        eprintln!(
            "observed {} oversized non-terminal part(s): the single-resource overshoot is allowed",
            overshoot.len()
        );
    }
}

#[test]
fn split_zero_part_size_is_invalid_param() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let dest = root.path().join("zero.swm");
    let err = match wim.split(&dest, 0, &mut |_| true) {
        Ok(()) => panic!("a zero part size must not split"),
        Err(err) => err,
    };
    // `WIMLIB_ERR_INVALID_PARAM` is 24 in the 1.14.5 header; the
    // `ffi` constant only exists when linked, so the unlinked build
    // (which skips above) compares the literal to stay compilable.
    assert_eq!(
        err.code(),
        Some(24),
        "a zero part size must be INVALID_PARAM, got {err}"
    );
    assert!(!dest.exists(), "a refused split must create no part");
}

#[test]
fn split_panicking_callback_unwinds_through_facade() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_random_tree(root.path(), 64);
    let wim_path = capture_big_wim(root.path());

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let dest_dir = root.path().join("parts");
    fs::create_dir_all(&dest_dir).expect("parts dir must create");
    let first = dest_dir.join("big.swm");
    // The panic must unwind out of `split` (re-raised after the wimlib
    // call returns, never across C): `catch_unwind` catches it, and
    // the process is still alive to assert on the payload.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        wim.split(&first, 64 * 1024, &mut |_| -> bool {
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
fn split_interior_nul_dest_is_invalid() {
    if skip_without_backend() {
        return;
    }
    let root = tempfile::tempdir().expect("scratch dir must create");
    write_source_tree(root.path());
    let wim_path = capture_sample_wim(root.path(), &root.path().join("src"));

    let wim = Wim::open(&wim_path, OpenFlags::EMPTY).expect("captured wim must open");
    let err = match wim.split(Path::new("a\0b"), 64 * 1024, &mut |_| true) {
        Ok(()) => panic!("a NUL dest must not split"),
        Err(err) => err,
    };
    assert!(
        matches!(err, wimlib_sys::WimlibError::InvalidPath { .. }),
        "a NUL dest must be InvalidPath, got {err}"
    );
    assert!(err.code().is_none(), "InvalidPath carries no code");
}
