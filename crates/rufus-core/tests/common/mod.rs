#![allow(dead_code)] // Each suite uses only the subset of this harness it needs.
//! Shared harness for the external-tool acceptance suites.
//!
//! The `tests/{exfat,ext,fat32,ntfs,udf}_format.rs` suites each drove the
//! same shape - a sparse image file, a captured tool run, a byte reader,
//! a loop-device guard - from their own copy. The copies that were
//! byte-identical now live here; everything family-specific (label
//! readers, geometry assertions, skip-gate wordings, refusal shapes)
//! stays in its suite. `mod common;` in a suite is enough: Cargo never
//! builds `tests/common/` as its own test target.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;

/// One captured invocation of an external tool, both streams verbatim.
pub struct ToolRun {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl ToolRun {
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Run `program` with `args` under `LC_ALL=C` (the crate's own spawn
/// environment, so diagnostics read the same way), or `None` when the
/// program could not be spawned at all (the everyday reason: it is not
/// on this host's PATH).
pub fn run_tool(program: &str, args: &[&str]) -> Option<ToolRun> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    Some(ToolRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run `program` with `args` with no locale override, or `None` when the
/// program is missing. The exFAT suite's spelling: its tools are read
/// without the `LC_ALL=C` the other suites pin.
pub fn run_tool_plain(program: &str, args: &[&str]) -> Option<ToolRun> {
    let output = Command::new(program).args(args).output().ok()?;
    Some(ToolRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Create `path` (or truncate it) as a sparse image of `total` bytes:
/// `set_len` on a fresh file is a hole, not a write, so the image costs
/// almost nothing on disk before the formatter touches it.
pub fn sparse_image(path: &Path, total: u64) {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .expect("the sparse image opens");
    file.set_len(total).expect("the sparse image extends");
}

/// Read `len` bytes at `offset` from the image.
pub fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let file = std::fs::File::open(path).expect("the image opens");
    let mut buffer = vec![0u8; len];
    file.read_exact_at(&mut buffer, offset)
        .expect("the read works");
    buffer
}

/// A deterministic byte pattern, so a mismatch points at the exact offset.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// The loop-device guard: attach the image, hand out the node, and
/// detach it on every exit path.
pub struct Mounted {
    pub device: String,
    pub mountpoint: PathBuf,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mountpoint).status();
        let _ = Command::new("losetup").args(["-d", &self.device]).status();
    }
}

/// Attach `path` as a fresh loop device and return the node string.
/// `--direct-io=off` matches the mount bookkeeping: the image is
/// page-cached. The caller wraps the node in [`Mounted`], which unmounts
/// and detaches on every exit path.
pub fn attach_loop(path: &Path, what: &str) -> String {
    let attached = Command::new("losetup")
        .args(["--find", "--show", "--direct-io=off"])
        .arg(path)
        .output()
        .expect("losetup runs");
    assert!(
        attached.status.success(),
        "losetup failed ({what}): {}",
        String::from_utf8_lossy(&attached.stderr)
    );
    let device = String::from_utf8_lossy(&attached.stdout).trim().to_owned();
    assert!(!device.is_empty(), "losetup printed no node ({what})");
    device
}

pub fn is_root() -> bool {
    // euid 0 is the only thing that can mount; a non-root run reports a
    // skip rather than pretending the check passed.
    std::fs::metadata("/proc/self").is_ok()
        && Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}
