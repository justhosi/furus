//! The A4 external-tool policy in one place: how the NTFS, ext and UDF
//! formatter families locate and probe their external tools.
//!
//! Every rule here is what the families previously duplicated: the `PATH`
//! directory list, the executable-file check, the names-major/dirs-minor
//! scan, the version-probe shape (`LC_ALL=C`, capture, drop the output,
//! read `status.success()`), and the spawn-error rule. The only per-family
//! inputs are the probe flag (`-V` for the e2fsprogs family, `--version`
//! for the NTFS family) and the absent-tool refusal each family reports —
//! except the UDF family, whose tool answers no flag with success and is
//! probed by its usage banner instead (see [`probe_banner`]).
//!
//! The `ETXTBSY` retry and the spawn-error rule are measured facts, kept in
//! the wording both families carried: a busy exec fails with `ETXTBSY`
//! (errno 26, mapped to [`io::ErrorKind::ExecutableFileBusy`] - measured on
//! this host with rustc 1.99.0, see [`output_retrying`]), and a spawn
//! failure is returned, never swallowed (see [`probe_with`] and
//! [`scan_candidates`]).
//!
//! The captured-output transcript shape lives here too: [`captured_lines`]
//! splits a stream into sanitised log lines, [`log_captured_lines`] logs a
//! run's transcript under the family's own target, and [`output_failure`]
//! builds the failing-exit refusal — one implementation for every family,
//! so the tails cannot drift (the NTFS family still carries its own
//! copies; moving them is later-slice debt).

use std::env;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::time::Duration;

use crate::error::CoreError;
use crate::error::Result;
use crate::log::Level;
use crate::log::Logger;
use crate::text::device_text;

/// How many of the tool's trailing stderr lines a failure report carries.
pub(crate) const MAX_TAIL_LINES: usize = 8;

/// The `PATH` directories of this process, in order (empty when `PATH` is
/// unset — the probe below then finds nothing and reports the package).
pub(crate) fn path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

/// A regular file with at least one execute bit set.
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
        && path
            .metadata()
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// Run `candidate` with `flag` and report whether it exits successfully.
///
/// The flag is a parameter because the families disagree: the e2fsprogs
/// family rejects `--version` as an invalid option (measured on this host
/// against e2fsprogs 1.47.4 during this slice — `mke2fs --version` exits 1,
/// `e2fsck --version` exits 16, while `-V` exits 0 for both), so a
/// `--version` probe would refuse the real toolchain on every host that has
/// it; callers pass `-V` for that family and `--version` for the NTFS
/// family. Output is captured and dropped — the probe only asks "are you
/// there", never reads what came out. The family stub tests pin the flag as
/// sent.
///
/// A spawn failure is returned, never swallowed: `NotFound` means the
/// candidate vanished between the executable check and the spawn (the scan
/// treats it as absent), while any other error — including a busy exec that
/// survives [`output_retrying`] — becomes [`CoreError::io`] at the scan.
fn probe_with(candidate: &Path, flag: &'static str) -> io::Result<bool> {
    let mut command = Command::new(candidate);
    command.arg(flag).env("LC_ALL", "C");
    output_retrying(&mut command).map(|output| output.status.success())
}

/// Run `cmd` as a bounded capture, retrying a busy exec — and only a busy
/// exec.
///
/// A script or executable file that another thread still holds open for
/// writing fails `execve` with `ETXTBSY` (errno 26, mapped to
/// [`io::ErrorKind::ExecutableFileBusy`] — measured on this host with rustc
/// 1.99.0: holding a write descriptor open makes `Command::output` fail with
/// `Text file busy (os error 26)`, and the same command succeeds after the
/// descriptor closes). The failure means the child never started, so
/// retrying is safe: at most three attempts with 10 ms sleeps between busy
/// failures (at most about 20 ms of added delay), and every other error
/// returns immediately.
pub(crate) fn output_retrying(cmd: &mut Command) -> io::Result<Output> {
    let mut attempt = 0;
    loop {
        match cmd.output() {
            Ok(output) => return Ok(output),
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 2 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Probe `names` in order over `dirs` with `flag`, returning the first entry
/// that is an executable file whose version check exits successfully;
/// nothing found, nothing executable, or a probe that ran and failed reports
/// the `missing` refusal for this tool family. A probe that could not be
/// spawned at all (other than a vanishing `NotFound`) refuses as an I/O
/// error naming the candidate path, never the package hint.
///
/// The scan runs names-major over dirs-minor: every directory is tried for
/// the first name before the second name is considered.
pub(crate) fn scan_candidates(
    dirs: &[PathBuf],
    names: &[&'static str],
    flag: &'static str,
    missing: fn() -> CoreError,
) -> Result<(&'static str, PathBuf)> {
    scan_with(dirs, names, missing, |candidate| {
        probe_with(candidate, flag)
    })
}

/// Probe `names` in order over `dirs` with a caller-owned banner predicate,
/// returning the first entry that is an executable file whose probe reports
/// present; nothing found, nothing executable, or a probe that ran and
/// reported absent gives the `missing` refusal for this tool family. A
/// probe that could not be spawned at all (other than a vanishing
/// `NotFound`) refuses as an I/O error naming the candidate path, never
/// the package hint.
///
/// The scan runs names-major over dirs-minor, exactly like
/// [`scan_candidates`]: the flag families keep calling that thin wrapper,
/// and only the banner-probed UDF family calls this seam.
///
/// The predicate captures nothing (a `fn` pointer, not a closure): the
/// UDF banner prefix is a module constant, so no environment needs
/// capturing.
pub(crate) fn scan_candidates_with(
    dirs: &[PathBuf],
    names: &[&'static str],
    probe: fn(&Path) -> io::Result<bool>,
    missing: fn() -> CoreError,
) -> Result<(&'static str, PathBuf)> {
    scan_with(dirs, names, missing, probe)
}

/// The shared scan behind [`scan_candidates`] and [`scan_candidates_with`]:
/// names-major over dirs-minor, the executable-file check, and the
/// spawn-error rule live in exactly one loop, so the two entry points
/// cannot drift.
fn scan_with(
    dirs: &[PathBuf],
    names: &[&'static str],
    missing: fn() -> CoreError,
    probe: impl Fn(&Path) -> io::Result<bool>,
) -> Result<(&'static str, PathBuf)> {
    for name in names.iter().copied() {
        for dir in dirs {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            match probe(&candidate) {
                Ok(true) => return Ok((name, candidate)),
                Ok(false) => {
                    // A candidate whose probe runs and fails is
                    // treated as absent, and the scan moves on.
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // A candidate that vanished between the executable
                    // check and the spawn is absent too.
                }
                Err(error) => return Err(CoreError::io(&candidate, error)),
            }
        }
    }
    Err(missing())
}

/// Run `candidate` with no arguments and return its first stderr line.
///
/// The UDF family needs this shape because `mkudffs` has no version or
/// help flag that succeeds: every flag exits non-zero (measured with
/// udftools 2.3 inside the `archlinux:latest` container — `--version`
/// reports an unrecognized option, `-V` an invalid option, `--help` and
/// `-h` exit 1), so the probe reads the usage banner instead, which
/// `mkudffs` prints to stderr with exit code 1 when run with no
/// arguments. Returns `Ok(Some(line))` only when the exit code is
/// `Some(1)` and stderr carries a first line, otherwise `Ok(None)` — the
/// caller matches the line against its banner prefix. Spawn failures are
/// returned, never swallowed (the scan maps them like any other probe's),
/// and the `ETXTBSY` retry of [`output_retrying`] applies.
pub(crate) fn probe_banner(candidate: &Path) -> io::Result<Option<String>> {
    let mut command = Command::new(candidate);
    command.env("LC_ALL", "C");
    let output = output_retrying(&mut command)?;
    if output.status.code() != Some(1) {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stderr)
        .lines()
        .next()
        .map(str::to_string))
}

/// Split captured output into sanitised, non-empty log lines.
pub(crate) fn captured_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(device_text)
        .filter(|line| !line.is_empty())
        .collect()
}

/// Log every non-empty captured line of a tool run (stdout then stderr,
/// each through the one device-text sanitiser) verbatim at `Info` under
/// `target` — the family's own log target (`"ext"`, `"udf"`), so each
/// family's transcript keeps its shape while sharing the code.
pub(crate) fn log_captured_lines(logger: &Logger, target: &str, output: &Output) {
    let stdout_lines = captured_lines(&output.stdout);
    let stderr_lines = captured_lines(&output.stderr);
    for line in stdout_lines.iter().chain(stderr_lines.iter()) {
        logger.log(Level::Info, target, line);
    }
}

/// The last at most [`MAX_TAIL_LINES`] entries of a diagnostic sequence,
/// oldest first — the shared cap behind every tool refusal tail.
pub(crate) fn capped_tail(lines: &[String]) -> Vec<&str> {
    let mut tail: Vec<&str> = lines
        .iter()
        .rev()
        .take(MAX_TAIL_LINES)
        .map(String::as_str)
        .collect();
    tail.reverse();
    tail
}

/// Refusal for a failing tool exit: the tool name, the status text and the
/// last [`MAX_TAIL_LINES`] lines of the given sequence (empty when the tool
/// said nothing) — the callers choose the sequence (the ext formatter
/// passes stderr only; its checker and persistence writer pass stderr
/// followed by stdout; the UDF formatter passes stderr only).
pub(crate) fn output_failure(tool: &str, status: &str, tail_lines: &[String]) -> CoreError {
    let tail = capped_tail(tail_lines);
    if tail.is_empty() {
        CoreError::invalid(format!("{tool} failed ({status}) with no error output"))
    } else {
        CoreError::invalid(format!("{tool} failed ({status}): {}", tail.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Refusal text for the shared scan tests: names the stub family and a
    /// package the busy-exec assertions must never see.
    const TEST_MISSING_HINT: &str = "no test tool found (stub-tool): install the test-package";

    /// The absent refusal the shared scan tests report.
    fn test_missing() -> CoreError {
        CoreError::invalid(TEST_MISSING_HINT)
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
    /// [`scan_candidates`]): no test here mutates the process environment,
    /// so every test in this module runs in parallel safely.
    fn probe_dirs(dir: &Path) -> Vec<PathBuf> {
        vec![dir.to_path_buf()]
    }

    #[test]
    fn scan_reports_a_busy_executable_as_an_io_refusal_with_dash_v() {
        // Holding the stub open for writing makes every exec fail with
        // ETXTBSY (measured on this host with rustc 1.99.0), so the scan
        // must refuse as I/O naming the path - never the package hint. The
        // held descriptor stays open across the whole scan, so the bounded
        // retry budget cannot recover: no timing dependency. Stub behaviour
        // only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "stub-tool", "#!/bin/sh\nexit 0\n");
        let _held = std::fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("the write descriptor holds");
        let error = scan_candidates(
            &probe_dirs(scratch.path()),
            &["stub-tool"],
            "-V",
            test_missing,
        )
        .expect_err("a busy stub refuses");
        let text = error.to_string();
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&stub.display().to_string()), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::ExecutableFileBusy);
        assert!(!text.contains(TEST_MISSING_HINT), "{text}");
        assert!(!text.contains("test-package"), "{text}");
    }

    #[test]
    fn scan_retries_a_busy_executable_until_it_executes_with_dash_v() {
        // The held write descriptor drops about 10 ms later, inside the
        // retry budget, so the scan recovers and finds the stub. Stub
        // behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "stub-tool", "#!/bin/sh\nexit 0\n");
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("the write descriptor holds");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(held);
        });
        let (name, path) = scan_candidates(
            &probe_dirs(scratch.path()),
            &["stub-tool"],
            "-V",
            test_missing,
        )
        .expect("the retry probes");
        assert_eq!(name, "stub-tool");
        assert_eq!(path, stub);
        assert!(releaser.join().is_ok());
    }

    #[test]
    fn scan_reports_a_busy_executable_as_an_io_refusal_with_long_version() {
        // The same busy-exec refusal through the long `--version` flag the
        // NTFS family probes with: the flag does not change the spawn-error
        // policy. The held descriptor stays open across the whole scan, so
        // the bounded retry budget cannot recover: no timing dependency.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "stub-tool", "#!/bin/sh\nexit 0\n");
        let _held = std::fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("the write descriptor holds");
        let error = scan_candidates(
            &probe_dirs(scratch.path()),
            &["stub-tool"],
            "--version",
            test_missing,
        )
        .expect_err("a busy stub refuses");
        let text = error.to_string();
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&stub.display().to_string()), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::ExecutableFileBusy);
        assert!(!text.contains(TEST_MISSING_HINT), "{text}");
        assert!(!text.contains("test-package"), "{text}");
    }

    #[test]
    fn scan_retries_a_busy_executable_until_it_executes_with_long_version() {
        // The same retry recovery through the long `--version` flag the
        // NTFS family probes with: the held write descriptor drops about
        // 10 ms later, inside the retry budget, so the scan recovers and
        // finds the stub. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "stub-tool", "#!/bin/sh\nexit 0\n");
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&stub)
            .expect("the write descriptor holds");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            drop(held);
        });
        let (name, path) = scan_candidates(
            &probe_dirs(scratch.path()),
            &["stub-tool"],
            "--version",
            test_missing,
        )
        .expect("the retry probes");
        assert_eq!(name, "stub-tool");
        assert_eq!(path, stub);
        assert!(releaser.join().is_ok());
    }
}
