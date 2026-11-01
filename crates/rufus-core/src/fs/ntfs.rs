//! NTFS integration: drive the external `mkntfs` tool, then verify the VBR (S11).
//!
//! PLAN lines 661-679 mandate NTFS volumes that Windows and the UEFI:NTFS
//! driver accept, built by shelling out to
//! `mkntfs -f -L <label> -c <cluster>` — the one external-tool exception for
//! filesystems (PLAN decision A4), since a pure-Rust NTFS writer is a
//! multi-year project. There is no native writer here and no dependency on
//! `rufus-linux` / `rufus-helper`: the tool path arrives as a target path,
//! the tool runs as a bounded capture, and the only bytes this module parses
//! are the 512 VBR bytes read back from the target.
//!
//! The S21 post-format hook for the NTFS VBR fix (PLAN lines 948-949) is
//! explicitly deferred — this module ships no hook code, only this note
//! that the hook has nowhere to live until S21 re-verifies the problem on
//! Linux.
//!
//! Test discipline: the real NTFS toolchain is absent on this host, so
//! every test below drives `#!/bin/sh` stubs or synthetic VBRs and claims
//! nothing about real `mkntfs` output.

use std::env;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::exfat::get_u16;
use crate::fs::exfat::get_u64;
use crate::log::Level;
use crate::log::Logger;
use crate::text::device_text;

/// Tool names in probe order: `mkntfs` first, then its `mkfs.ntfs` alias.
const TOOL_NAMES: [&str; 2] = ["mkntfs", "mkfs.ntfs"];

/// Smallest cluster size the options accept, in bytes.
const MIN_CLUSTER_BYTES: u32 = 512;

/// Largest cluster size the options accept, in bytes.
const MAX_CLUSTER_BYTES: u32 = 65536;

/// Cluster size [`Options::new`] defaults to, in bytes.
const DEFAULT_CLUSTER_BYTES: u32 = 4096;

/// How many of the tool's trailing stderr lines a failure report carries.
const MAX_TAIL_LINES: usize = 8;

/// Refusal when no usable NTFS formatter is on `PATH`.
const MISSING_TOOL_HINT: &str =
    "no NTFS formatter found (mkntfs or mkfs.ntfs): install the ntfs-3g package";

/// Locate the NTFS formatter: `mkntfs`, falling back to `mkfs.ntfs`.
///
/// Each `PATH` directory is scanned by hand (existence plus the owner execute
/// bit — never a shell, never a `PATH` mutation), and the first candidate
/// whose `--version` probe exits successfully wins; a candidate whose probe
/// fails is treated as absent. The package mapping (`ntfs-3g` provides both
/// names) follows PLAN.md line 137.
pub fn find_tool() -> Result<&'static str> {
    find_tool_in(&path_dirs()).map(|(name, _)| name)
}

/// The `PATH` directories of this process, in order (empty when `PATH` is
/// unset — the probe below then finds nothing and reports the package).
fn path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

/// [`find_tool`] over an explicit directory list, so tests can point the
/// probe at scratch directories without touching the process environment
/// (`std::env::set_var` is `unsafe` under this crate's edition and
/// `forbid(unsafe_code)` leaves no room for it).
fn find_tool_in(dirs: &[PathBuf]) -> Result<(&'static str, PathBuf)> {
    for name in TOOL_NAMES {
        for dir in dirs {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            if probe_tool(&candidate) {
                return Ok((name, candidate));
            }
            // A candidate whose `--version` probe fails is treated as
            // absent, and the scan moves on to the next candidate.
        }
    }
    Err(missing_tool_error())
}

/// A regular file with at least one execute bit set.
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
        && path
            .metadata()
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// Run `candidate --version` and report whether it exits successfully.
/// Output is captured and dropped — the probe only asks "are you there".
fn probe_tool(candidate: &Path) -> bool {
    Command::new(candidate)
        .arg("--version")
        .env("LC_ALL", "C")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// The shared refusal: spawn failures map onto this text too, so every
/// "the toolchain is missing" path names the same package.
fn missing_tool_error() -> CoreError {
    CoreError::invalid(MISSING_TOOL_HINT)
}

/// The write-side options of [`format`]: the label and the cluster size.
#[derive(Debug, Clone)]
pub struct Options {
    /// Volume label passed as `mkntfs -L`; `None` omits the flag entirely.
    pub label: Option<String>,
    /// Cluster size in bytes; see [`Options::with_cluster_bytes`].
    pub cluster_bytes: u32,
}

impl Options {
    /// Options with `label` and the default 4096-byte clusters.
    pub fn new(label: Option<String>) -> Self {
        Self {
            label,
            cluster_bytes: DEFAULT_CLUSTER_BYTES,
        }
    }

    /// Options with an explicit cluster size, refused unless it is a power
    /// of two in 512..=65536 bytes.
    pub fn with_cluster_bytes(mut self, cluster_bytes: u32) -> Result<Self> {
        if !cluster_bytes.is_power_of_two()
            || !(MIN_CLUSTER_BYTES..=MAX_CLUSTER_BYTES).contains(&cluster_bytes)
        {
            return Err(CoreError::invalid(format!(
                "cluster size {cluster_bytes} is not supported: \
                 cluster size must be a power of two from {MIN_CLUSTER_BYTES} \
                 to {MAX_CLUSTER_BYTES} bytes"
            )));
        }
        self.cluster_bytes = cluster_bytes;
        Ok(self)
    }
}

/// The verified NTFS VBR fields [`format`] reads back from the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boot {
    /// Bytes per sector from VBR offset 11: 512 or 4096.
    pub bytes_per_sector: u32,
    /// Cluster size in bytes (sectors-per-cluster times bytes-per-sector).
    pub cluster_bytes: u32,
    /// Volume serial from VBR offset 0x48.
    pub volume_serial: u64,
}

/// Verify a 512-byte NTFS volume boot record.
///
/// Checks, in order: the `NTFS    ` magic at 3..11; bytes-per-sector (`u16`
/// LE at 11) is 512 or 4096 — the only sizes the house
/// [`Volume`](crate::fs::Volume) trait admits; sectors-per-cluster (`u8`
/// at 13) is non-zero and the resulting cluster size lands in
/// 512..=65536 bytes; the `0x55 0xAA` signature at 510..512. Returns the
/// parsed sector size, cluster size and the `u64` LE volume serial at 0x48.
///
/// The field reads reuse the exFAT side's checked getters — one helper set
/// for the whole `fs` tree, no second implementation to drift.
pub fn boot_sector(vbr: &[u8; 512]) -> Result<Boot> {
    if vbr.get(3..11) != Some(b"NTFS    ".as_slice()) {
        return Err(CoreError::invalid(
            "not an NTFS volume: bytes 3..11 do not read `NTFS    `",
        ));
    }
    let bytes_per_sector = get_u16(vbr, 11).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the bytes-per-sector field at offset 11")
    })?;
    if !matches!(bytes_per_sector, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "NTFS bytes per sector {bytes_per_sector} is not supported: \
             only 512 and 4096 are allowed"
        )));
    }
    let sectors_per_cluster = vbr.get(13).copied().ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the sectors-per-cluster field at offset 13")
    })?;
    if sectors_per_cluster == 0 {
        return Err(CoreError::invalid(
            "NTFS sectors per cluster is zero: the VBR names no cluster size",
        ));
    }
    // With bytes-per-sector restricted to 512/4096 above, every cluster
    // size in 512..=65536 is a positive sectors-per-cluster ratio
    // (1..=128 at 512 bytes, 1..=16 at 4096 bytes), so the range check
    // below doubles as the encoding check — a zero ratio is still refused
    // explicitly above, and no claim is made here about which cluster
    // sizes real `mkntfs` runs emit.
    let cluster_bytes = u32::from(sectors_per_cluster)
        .checked_mul(u32::from(bytes_per_sector))
        .ok_or_else(|| CoreError::invalid("NTFS cluster size overflows a u32"))?;
    if !(MIN_CLUSTER_BYTES..=MAX_CLUSTER_BYTES).contains(&cluster_bytes) {
        return Err(CoreError::invalid(format!(
            "NTFS cluster size {cluster_bytes} is out of range: \
             cluster size must be from {MIN_CLUSTER_BYTES} to {MAX_CLUSTER_BYTES} bytes"
        )));
    }
    let signature: &[u8] = &[0x55, 0xAA];
    if vbr.get(510..512) != Some(signature) {
        return Err(CoreError::invalid(
            "not an NTFS boot sector: bytes 510..511 are not 0x55 0xAA",
        ));
    }
    let volume_serial = get_u64(vbr, 0x48).ok_or_else(|| {
        CoreError::invalid("NTFS VBR ends before the volume serial at offset 0x48")
    })?;
    Ok(Boot {
        bytes_per_sector: u32::from(bytes_per_sector),
        cluster_bytes,
        volume_serial,
    })
}

/// Format `target` as NTFS with the external formatter.
///
/// Runs `mkntfs -f [-L <label>] -c <cluster> <target>` (the target path is
/// always the last argument) as a bounded capture — both streams piped and
/// drained via `output()`, `LC_ALL=C` in the child environment — then reads
/// back bytes 0..512 and verifies them with [`boot_sector`]. Every
/// non-empty captured line (stdout then stderr, each through
/// [`device_text`]) is logged verbatim at `Info` under the `ntfs` target;
/// a failing exit becomes a refusal naming the tool, the status and the
/// last [`MAX_TAIL_LINES`] stderr lines.
pub fn format(target: &Path, options: &Options, logger: &Logger) -> Result<Boot> {
    let (tool, tool_path) = find_tool_in(&path_dirs())?;
    format_with(target, options, logger, tool, &tool_path)
}

/// [`format`] with the tool already resolved, so tests can point the run at
/// a stub by absolute path without touching the process environment.
fn format_with(
    target: &Path,
    options: &Options,
    logger: &Logger,
    tool: &str,
    tool_path: &Path,
) -> Result<Boot> {
    let mut command = Command::new(tool_path);
    command.arg("-f");
    if let Some(label) = options.label.as_deref() {
        command.arg("-L").arg(label);
    }
    command
        .arg("-c")
        .arg(options.cluster_bytes.to_string())
        .arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture: the tool is this slice's external mandate
    // (PLAN lines 661-679), and `output` drains both pipes so a chatty
    // tool cannot block on a full buffer.
    let output = command.output().map_err(|_| missing_tool_error())?;

    let stdout_lines = captured_lines(&output.stdout);
    let stderr_lines = captured_lines(&output.stderr);
    for line in stdout_lines.iter().chain(stderr_lines.iter()) {
        logger.log(Level::Info, "ntfs", line);
    }

    if !output.status.success() {
        return Err(format_failure(
            tool,
            &output.status.to_string(),
            &stderr_lines,
        ));
    }

    let boot = boot_sector(&read_vbr(target)?)?;
    logger.log(
        Level::Info,
        "ntfs",
        &format!(
            "{tool} finished ({}): verified NTFS volume with {} byte sectors and {} byte clusters",
            output.status, boot.bytes_per_sector, boot.cluster_bytes,
        ),
    );
    Ok(boot)
}

/// Split captured output into sanitised, non-empty log lines.
fn captured_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(device_text)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Refusal for a failing tool exit: the tool name, the status text and the
/// last [`MAX_TAIL_LINES`] stderr lines (empty when the tool said nothing).
fn format_failure(tool: &str, status: &str, stderr_lines: &[String]) -> CoreError {
    let mut tail: Vec<&str> = stderr_lines
        .iter()
        .rev()
        .take(MAX_TAIL_LINES)
        .map(String::as_str)
        .collect();
    tail.reverse();
    if tail.is_empty() {
        CoreError::invalid(format!("{tool} failed ({status}) with no error output"))
    } else {
        CoreError::invalid(format!("{tool} failed ({status}): {}", tail.join("; ")))
    }
}

/// Read bytes 0..512 of `target` — the VBR the tool is expected to have
/// written — for [`boot_sector`] verification.
fn read_vbr(target: &Path) -> Result<[u8; 512]> {
    let file = std::fs::File::open(target).map_err(|err| CoreError::io(target, err))?;
    let mut vbr = [0u8; 512];
    file.read_exact_at(&mut vbr, 0)
        .map_err(|err| CoreError::io(target, err))?;
    Ok(vbr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed serial baked into every synthetic VBR, so the round-trip
    /// pins the exact `u64` LE field rather than "some serial".
    const SYNTHETIC_SERIAL: u64 = 0x0123_4567_89AB_CDEF;

    /// Build a synthetic 512-byte VBR for (`bytes_per_sector`,
    /// `cluster_bytes`). Stub/synthetic only: pins the layout this module
    /// parses, claims nothing about real `mkntfs` output.
    fn synthetic_vbr(bytes_per_sector: u16, cluster_bytes: u32) -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[3..11].copy_from_slice(b"NTFS    ");
        vbr[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        let ratio = cluster_bytes / u32::from(bytes_per_sector);
        vbr[13] = ratio as u8;
        vbr[0x48..0x50].copy_from_slice(&SYNTHETIC_SERIAL.to_le_bytes());
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        vbr
    }

    /// Write an executable `#!/bin/sh` stub into `dir`. Stub behaviour
    /// only: exercises the probe/spawn plumbing, never the real tool.
    fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("the stub writes");
        let mut permissions = std::fs::metadata(&path)
            .expect("the stub exists")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("the stub is executable");
        path
    }

    /// The discovery tests inject scratch directories (see
    /// [`find_tool_in`]): no test here mutates the process environment,
    /// so every test in this module runs in parallel safely.
    fn probe_dirs(dir: &Path) -> Vec<PathBuf> {
        vec![dir.to_path_buf()]
    }

    #[test]
    fn boot_sector_accepts_synthetic_vbrs() {
        // Every power-of-two cluster size the options admit at 512-byte
        // sectors, plus the 4096-byte-sector corner (65536 / 4096 = 16
        // sectors per cluster). Synthetic only.
        let cases = [
            (512u16, 512u32),
            (512, 1024),
            (512, 4096),
            (512, 16384),
            (512, 65536),
            (4096, 65536),
        ];
        for (bps, cluster) in cases {
            let vbr = synthetic_vbr(bps, cluster);
            let boot = boot_sector(&vbr).expect("the synthetic VBR parses");
            assert_eq!(boot.bytes_per_sector, u32::from(bps));
            assert_eq!(boot.cluster_bytes, cluster);
            assert_eq!(boot.volume_serial, SYNTHETIC_SERIAL);
        }
    }

    #[test]
    fn boot_sector_refuses_a_wrong_magic() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[3..11].copy_from_slice(b"FAT32   ");
        let error = boot_sector(&vbr).expect_err("the magic is wrong");
        assert!(error.to_string().contains("NTFS"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_a_bad_sector_size() {
        let vbr = synthetic_vbr(1024, 4096);
        let error = boot_sector(&vbr).expect_err("1024 byte sectors are refused");
        let text = error.to_string();
        assert!(text.contains("1024"), "{text}");
        assert!(text.contains("512"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_a_zero_ratio() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[13] = 0;
        let error = boot_sector(&vbr).expect_err("zero sectors per cluster is refused");
        assert!(error.to_string().contains("zero"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_an_oversize_cluster() {
        // 512-byte sectors with the 0xFF ratio: 130560 bytes, past the
        // 65536 ceiling. Synthetic encoding, not a real-tool claim.
        let mut vbr = synthetic_vbr(512, 512);
        vbr[13] = 0xFF;
        let error = boot_sector(&vbr).expect_err("the cluster is too large");
        let text = error.to_string();
        assert!(text.contains("out of range"), "{text}");
        assert!(text.contains("130560"), "{text}");
    }

    #[test]
    fn boot_sector_refuses_a_missing_signature() {
        let mut vbr = synthetic_vbr(512, 4096);
        vbr[510] = 0x00;
        vbr[511] = 0x00;
        let error = boot_sector(&vbr).expect_err("the 55AA signature is missing");
        assert!(error.to_string().contains("0x55"), "{error}");
    }

    #[test]
    fn boot_sector_refuses_non_ntfs_bytes() {
        // A full 512 bytes of vowels: no magic, no fields, no signature.
        // Synthetic garbage, pinned so "any bytes parse" can never creep in.
        let vbr = [b'e'; 512];
        let error = boot_sector(&vbr).expect_err("vowel bytes are not a VBR");
        assert!(error.to_string().contains("NTFS"), "{error}");
    }

    #[test]
    fn options_default_to_4k_clusters() {
        let options = Options::new(Some("LABEL".to_string()));
        assert_eq!(options.cluster_bytes, DEFAULT_CLUSTER_BYTES);
        assert_eq!(options.label.as_deref(), Some("LABEL"));
    }

    #[test]
    fn cluster_sizes_must_be_powers_of_two_in_range() {
        for valid in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
            Options::new(None)
                .with_cluster_bytes(valid)
                .expect("a power of two in range is accepted");
        }
        for invalid in [0, 1, 511, 513, 1000, 4095, 65535, 65537, 131_072] {
            let error = Options::new(None)
                .with_cluster_bytes(invalid)
                .expect_err("a non-power-of-two or out-of-range size is refused");
            let text = error.to_string();
            assert!(text.contains("power of two"), "{text}");
            assert!(text.contains("512"), "{text}");
            assert!(text.contains("65536"), "{text}");
        }
    }

    #[test]
    fn probe_finds_an_mkntfs_stub() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        let (name, path) = find_tool_in(&probe_dirs(scratch.path())).expect("the stub probes");
        assert_eq!(name, "mkntfs");
        assert_eq!(path, stub);
    }

    #[test]
    fn probe_falls_back_to_mkfs_ntfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkfs.ntfs", "#!/bin/sh\nexit 0\n");
        let (name, _) = find_tool_in(&probe_dirs(scratch.path())).expect("the alias probes");
        assert_eq!(name, "mkfs.ntfs");
    }

    #[test]
    fn probe_prefers_mkntfs_over_mkfs_ntfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 0\n");
        write_stub(scratch.path(), "mkfs.ntfs", "#!/bin/sh\nexit 0\n");
        let (name, _) = find_tool_in(&probe_dirs(scratch.path())).expect("a stub probes");
        assert_eq!(name, "mkntfs");
    }

    #[test]
    fn probe_with_no_directories_names_the_package() {
        let error = find_tool_in(&[]).expect_err("nothing can be found");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
            "the empty-PATH text is pinned exactly"
        );
    }

    #[test]
    fn probe_treats_a_failing_version_check_as_absent() {
        // A +x stub that exits 1 on `--version`: the probe fails, so the
        // scan reports the same package error as the empty directory list.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkntfs", "#!/bin/sh\nexit 1\n");
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("the failing probe is absent");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
    }

    #[test]
    fn probe_skips_files_that_are_not_executable() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        std::fs::write(scratch.path().join("mkntfs"), "#!/bin/sh\nexit 0\n")
            .expect("the non-executable file writes");
        let error =
            find_tool_in(&probe_dirs(scratch.path())).expect_err("a non-executable is skipped");
        assert!(error.to_string().contains("ntfs-3g"), "{error}");
    }

    #[test]
    fn format_drives_the_stub_and_verifies_the_vbr() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\necho stub-stdout-line\necho stub-stderr-line >&2\nexit 0\n",
        );
        // The target already carries a synthetic VBR at offset 0 — the
        // stub never touches it, the read-back below verifies it.
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_vbr(512, 4096)).expect("the target VBR writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Some("TESTLABEL".to_string()))
            .with_cluster_bytes(4096)
            .expect("4096 is valid");

        let boot = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.cluster_bytes, 4096);
        assert_eq!(boot.volume_serial, SYNTHETIC_SERIAL);

        let snapshot = logger.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|record| record.target == "ntfs" && record.level == Level::Info),
            "every line is logged at Info under the ntfs target"
        );
        let messages: Vec<&str> = snapshot
            .iter()
            .map(|record| record.message.as_str())
            .collect();
        assert!(messages.contains(&"stub-stdout-line"), "{messages:?}");
        assert!(messages.contains(&"stub-stderr-line"), "{messages:?}");
        // The stub echoes its own argv: pins `-f`, the label flag, the
        // cluster flag and the target path as the last argument.
        let expected = format!("got: -f -L TESTLABEL -c 4096 {}", target.display());
        assert!(messages.contains(&expected.as_str()), "{messages:?}");
        // The final line names the tool, the exit and the verified sizes.
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("mkntfs"), "{summary}");
        assert!(summary.contains("exit status: 0"), "{summary}");
        assert!(summary.contains("512"), "{summary}");
        assert!(summary.contains("4096"), "{summary}");
    }

    #[test]
    fn format_without_a_label_omits_the_label_flag() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\nexit 0\n",
        );
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_vbr(512, 4096)).expect("the target VBR writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(None);

        format_with(&target, &options, &logger, "mkntfs", &tool_path).expect("the stub exits 0");
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        let expected = format!("got: -f -c 4096 {}", target.display());
        assert!(messages.contains(&expected), "{messages:?}");
    }

    #[test]
    fn format_failure_carries_the_status_and_the_tail() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mkntfs",
            "#!/bin/sh\necho wiping\necho\n\
             echo l01 >&2\necho l02 >&2\necho l03 >&2\necho l04 >&2\necho l05 >&2\n\
             echo l06 >&2\necho l07 >&2\necho l08 >&2\necho l09 >&2\necho l10 >&2\n\
             exit 3\n",
        );
        // No target file is created: the run fails before any read-back.
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Some("TESTLABEL".to_string()));

        let error = format_with(&target, &options, &logger, "mkntfs", &tool_path)
            .expect_err("the stub exits 3");
        let text = error.to_string();
        assert!(text.contains("exit status: 3"), "{text}");
        assert!(text.contains("l10"), "{text}");
        assert!(text.contains("l03"), "{text}");
        assert!(!text.contains("l01"), "{text}");
        assert!(!text.contains("l02"), "{text}");
        assert!(
            !text.contains("wiping"),
            "stdout lines are logged, never part of the refusal: {text}"
        );

        // The stdout lines were still logged before the failure, and the
        // blank echo never became a record.
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        assert!(messages.contains(&"wiping".to_string()), "{messages:?}");
        assert!(
            messages.iter().all(|message| !message.is_empty()),
            "{messages:?}"
        );
    }
}
