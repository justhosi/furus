//! Shared process/path/hash helpers used by every xtask submodule.

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use sha2::Digest;

#[cfg(test)]
use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::atomic::Ordering;

/// Workspace root: the directory containing `xtask/` (`CARGO_MANIFEST_DIR`
/// is `<root>/xtask` both for `cargo xtask` and for unit tests).
pub(crate) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one level below the repo root")
        .to_path_buf()
}

/// Run a command with inherited stdio; fail on non-zero exit.
pub(crate) fn run(cmd: &str, args: &[&str], cwd: &Path) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("`{cmd} {}` exited with {status}", args.join(" "))
    }
}

/// Run a command with captured output (keeps scratch paths out of the log);
/// fail on non-zero exit.
pub(crate) fn run_quiet(cmd: &str, args: &[&str], cwd: &Path) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;
    if !out.status.success() {
        bail!(
            "`{cmd} {}` exited with {}\n{}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True when `<tool> --version` runs successfully.
pub(crate) fn tool_present(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub(crate) fn sha256_of(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Shared test-only scratch directory helper
// ---------------------------------------------------------------------------

/// Unique scratch directory per test, cleaned up on drop. The process id
/// plus an atomic counter keeps names distinct even when tests run in
/// parallel inside the same test binary (no external tempfile crate).
#[cfg(test)]
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) struct TempDir(PathBuf);

#[cfg(test)]
impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("furus-dist-test-{tag}-{}-{n}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
