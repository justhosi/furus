//! Streaming decompression for the write step (S17 slice 5).
//!
//! No new dependencies are allowed, so compressed images are decoded
//! by streaming a host tool (`gzip`, `xz`, `bzip2`, `zstd` — each with
//! `-dc --`, so one process both decompresses and writes to stdout)
//! into the same chunk loop the raw path uses. Spawning lives in this
//! one small module through `std::process` directly, like the
//! [`fs::tool`](crate::fs::tool) families do: the table ([`tool_for`]),
//! the child handle ([`ToolStream`]) and the no-zombie contract are all
//! here, so the write step only picks a source and drains it.
//!
//! Evidence ported here: `0x140010a40` is the write thread (`Writing
//! compressed image:`, `Could not write compressed image: %lld`), and
//! the straight-through loop shares its 256 KiB (`0x40000`) chunk
//! buffer with the compressed path — which is why [`ToolStream`] is a
//! byte pipe the caller pulls, not a writer the tool pushes into.
//!
//! Retained text vs the pipe: the 4 KiB cap ([`STDERR_CAP`]) bounds
//! only what a refusal *keeps*; the pipe itself is drained
//! concurrently by a dedicated thread from `spawn` until EOF, so a
//! chatty child can never fill the kernel pipe (64 KiB) and wedge the
//! stdout pulls — the between-chunks cancellation check stays
//! reachable. Past the cap the thread keeps reading and discards the
//! excess, and the refusal notes the cut.
//!
//! Cancellation is honoured between chunks only, so a decompressor
//! that stalls its stdout delays Ctrl-C until it produces more or
//! exits: measured, a tool that spent 30 s on stderr before producing
//! delayed the exit by 38 s, and a tool that sleeps without producing
//! cannot be cancelled at all (SIGKILL only, the child orphaned).

use std::io::Read;
use std::path::Path;
use std::process::Child;
use std::process::ChildStderr;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;
use std::thread::JoinHandle;

use rufus_proto::ImageKind;

use crate::error::CoreError;
use crate::error::Result;
use crate::text::device_text;

/// One host decompressor invocation: the program plus its fixed
/// arguments (`-dc --`: decompress to stdout, with `--` so an image
/// path starting with `-` is a file, never an option — no shell is
/// ever involved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tool {
    /// Binary name as spawned (`PATH` lookup, no absolute path).
    pub(crate) program: &'static str,
    /// Fixed arguments; the image path is appended by [`ToolStream::spawn`].
    pub(crate) args: &'static [&'static str],
}

/// The decompressor for a compressed [`ImageKind`]: each tool gets
/// `-dc --`, so one process both decompresses and streams to stdout.
/// Every other kind returns `None` and stays on the raw path. This and
/// [`kind_name`] are the only kind-to-tool mappings (the planner's
/// kind-to-`WriteMode` table in `rufus-cli` is a separate, older
/// decision).
pub(crate) fn tool_for(kind: &ImageKind) -> Option<Tool> {
    match kind {
        ImageKind::Gzip => Some(Tool {
            program: "gzip",
            args: &["-dc", "--"],
        }),
        ImageKind::Xz => Some(Tool {
            program: "xz",
            args: &["-dc", "--"],
        }),
        ImageKind::Bzip2 => Some(Tool {
            program: "bzip2",
            args: &["-dc", "--"],
        }),
        ImageKind::Zstd => Some(Tool {
            program: "zstd",
            args: &["-dc", "--"],
        }),
        _ => None,
    }
}

/// The lowercase kind tag a refusal names (`gzip`, `xz`, ...): the
/// serde wire spelling, so messages cannot drift from the plan.
pub(crate) fn kind_name(kind: &ImageKind) -> &'static str {
    match kind {
        ImageKind::Gzip => "gzip",
        ImageKind::Xz => "xz",
        ImageKind::Bzip2 => "bzip2",
        ImageKind::Zstd => "zstd",
        ImageKind::Iso => "iso",
        ImageKind::Wim => "wim",
        ImageKind::Vhd => "vhd",
        ImageKind::Vhdx => "vhdx",
        ImageKind::Ffu => "ffu",
        ImageKind::Pe => "pe",
        ImageKind::Qcow2 => "qcow2",
        ImageKind::Raw => "raw",
        ImageKind::Unknown => "unknown",
    }
}

/// How much of a failing tool's stderr a refusal carries: enough for
/// the one-line diagnostics these tools print, bounded so a chatty
/// child cannot bloat the error.
const STDERR_CAP: usize = 4096;

/// A running decompressor piped into the write loop: the caller pulls
/// bytes with [`read`](ToolStream::read), then reaps with
/// [`finish`](ToolStream::finish) on every path — success, read error,
/// overflow, or cancellation. Stderr is drained concurrently from
/// `spawn` (see the module docs): stdout pulls can never wedge behind
/// a full stderr pipe, so cancellation stays reachable. A forgotten
/// stream is still reaped by [`Drop`], so no path leaks a zombie:
/// `cancel` kills, waits and joins; `finish` joins, waits and reports;
/// `Drop` kills-joins-waits whatever is left. The drain thread holds
/// only the stderr pipe, never the child handle.
#[derive(Debug)]
pub(crate) struct ToolStream {
    /// Binary name, for errors that name the program.
    program: &'static str,
    /// The child; always present (never taken, so `Drop` always sees
    /// it).
    child: Child,
    /// The stdout pipe; taken by [`finish`](ToolStream::finish) to
    /// close it before joining the drain.
    stdout: Option<ChildStdout>,
    /// The stderr drain thread; taken (never joined twice) by
    /// [`finish`](ToolStream::finish), [`cancel`](ToolStream::cancel)
    /// and [`Drop`].
    drain: Option<JoinHandle<(Vec<u8>, bool)>>,
    /// Set by [`cancel`](ToolStream::cancel): the child is already
    /// reaped, so a later [`finish`](ToolStream::finish) only reports
    /// `Ok` — the run's error is already decided by the caller.
    reaped: bool,
}

impl ToolStream {
    /// Spawn `tool` over the image at `path`: `program args path`
    /// with stdin nulled and both outputs piped. A missing binary
    /// refuses naming both the program and the image kind; any other
    /// spawn failure is an I/O error naming the program.
    pub(crate) fn spawn(path: &Path, tool: Tool, kind: &'static str) -> Result<Self> {
        Self::spawn_impl(tool.program, tool.args, path, kind)
    }

    /// Spawn shared by [`spawn`](ToolStream::spawn): kept separate so
    /// the `#[cfg(test)]` constructors below can pass an arbitrary
    /// program name without a [`Tool`].
    fn spawn_impl(
        program: &'static str,
        args: &[&str],
        path: &Path,
        kind: &'static str,
    ) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .args(args)
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CoreError::invalid(format!(
                    "decompressor '{program}' is not installed (needed for a {kind} image)"
                ))
            } else {
                CoreError::io(program, error)
            }
        })?;
        let stdout = child.stdout.take();
        // Stderr drains on its own thread from here until EOF: without
        // this a child filling the kernel pipe would wedge the stdout
        // pulls (and with them cancellation) forever. The thread holds
        // only the pipe, never the child handle.
        let drain = match child.stderr.take() {
            Some(pipe) => {
                match std::thread::Builder::new()
                    .name(format!("rufus-stderr-{program}"))
                    .spawn(move || drain_stderr(pipe))
                {
                    Ok(handle) => Some(handle),
                    Err(error) => {
                        // No reader, no run: kill and reap so the
                        // failed spawn leaves no zombie behind.
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(CoreError::io(program, error));
                    }
                }
            }
            None => None,
        };
        Ok(Self {
            program,
            child,
            stdout,
            drain,
            reaped: false,
        })
    }

    /// Spawn an arbitrary program name for tests: exercises the
    /// `NotFound` refusal without depending on an absent binary.
    #[cfg(test)]
    pub(crate) fn spawn_for_test(program: &'static str) -> Result<Self> {
        Self::spawn_impl(program, &[], Path::new("test-image"), "test")
    }

    /// Spawn an arbitrary program with arguments for tests: the
    /// hermetic route to a chatty fake tool (see
    /// `chatty_tool_does_not_deadlock_the_pipe`), without a [`Tool`].
    #[cfg(test)]
    pub(crate) fn spawn_for_test_argv(program: &'static str, args: &[&str]) -> Result<Self> {
        Self::spawn_impl(program, args, Path::new("test-image"), "test")
    }

    /// Pull up to `buf.len()` decompressed bytes: `0` at EOF, an I/O
    /// error naming the program otherwise. A closed stream (after
    /// [`finish`](ToolStream::finish)) reads as EOF.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.stdout.as_mut() {
            Some(stdout) => stdout
                .read(buf)
                .map_err(|error| CoreError::io(self.program, error)),
            None => Ok(0),
        }
    }

    /// Kill the child and reap it, ignoring every error, then join
    /// the drain (the pipe is at EOF once the child is dead, so the
    /// thread ends promptly): the child is gone either way (SIGKILL
    /// always lands), no thread is left behind, and the caller's error
    /// — cancellation, overflow — is already decided.
    pub(crate) fn cancel(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
        let _ = self.join_drain();
    }

    /// Join the stderr drain thread, taking the handle so it is never
    /// joined twice. Joining a finished thread returns at once; a
    /// thread join failure (the drain never panics — see
    /// [`drain_stderr`]) degrades to an empty tail, never a panic.
    fn join_drain(&mut self) -> (Vec<u8>, bool) {
        match self.drain.take() {
            // A finished thread joins at once; the drain never panics,
            // so the default only fires defensively, never in practice.
            Some(handle) => handle.join().unwrap_or_default(),
            None => (Vec::new(), false),
        }
    }

    /// Reap the child and report: close stdout, join the stderr drain
    /// (bounded retained text, truncation noted), wait, and refuse on a
    /// non-zero exit naming the program, the status and the stderr
    /// tail. A decompressor that exits non-zero after producing a
    /// prefix (a truncated archive) must not be reported as success,
    /// which is why the write loop calls this even after reaching EOF:
    /// EOF only means the pipe closed, not that the tool is happy.
    /// After [`cancel`](ToolStream::cancel) this reports `Ok` (see the
    /// `reaped` contract on the struct).
    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        // Close stdout first: the child is past producing (EOF or an
        // error stopped the pulls).
        drop(self.stdout.take());
        let (kept, truncated) = self.join_drain();
        let tail = sanitise_tail(&kept);
        let status = self
            .child
            .wait()
            .map_err(|error| CoreError::io(self.program, error))?;
        if status.success() {
            return Ok(());
        }
        let mut message = format!("decompressor '{}' failed ({status})", self.program);
        if tail.is_empty() {
            message.push_str(" with no error output");
        } else {
            message.push_str(&format!(": {tail}"));
            if truncated {
                message.push_str(" (stderr truncated to 4 KiB)");
            }
        }
        Err(CoreError::invalid(message))
    }
}

/// Read a stderr pipe to EOF, keeping at most [`STDERR_CAP`] bytes:
/// once the cap is reached the rest is still read but discarded, so a
/// chatty child can neither bloat the refusal nor wedge the pipe, and
/// the caller learns the text was cut. Read errors end the drain (the
/// exit status, not the transcript, decides the run), and the function
/// never panics, so the drain thread cannot poison its join.
fn drain_stderr(mut pipe: ChildStderr) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut truncated = false;
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if kept.len() < STDERR_CAP {
                    let room = STDERR_CAP.saturating_sub(kept.len());
                    // The first `read` bytes are fresh (`read` never
                    // exceeds the buffer by the `Read` contract); the
                    // iterator form keeps this panic-free even so.
                    kept.extend(chunk.iter().take(read.min(room)).copied());
                    if read > room {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (kept, truncated)
}

/// One sanitised line per tool line, joined for a refusal: the
/// sanitiser strips control bytes (including newlines), so the join
/// keeps the message one ASCII line.
fn sanitise_tail(kept: &[u8]) -> String {
    String::from_utf8_lossy(kept)
        .lines()
        .map(device_text)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

impl Drop for ToolStream {
    /// Reap whatever is left, ignoring every error and never panicking:
    /// the write loop cancels or finishes on every path, so this only
    /// fires if a future path forgets — and a leaked zombie (or a
    /// lingering drain thread) would be worse than waiting on a
    /// SIGKILLed child here. The handle is taken, so a previous
    /// `cancel`/`finish` is never joined twice.
    fn drop(&mut self) {
        match self.child.try_wait() {
            // Still running: kill, then reap.
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            // Exited but unreaped: reap.
            Ok(Some(_)) => {
                let _ = self.child.wait();
            }
            // Already reaped: nothing left.
            Err(_) => {}
        }
        let _ = self.join_drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_table_maps_the_four_compressed_kinds() {
        // Exact program and args per kind: one process both
        // decompresses and writes to stdout, with `--` so an image
        // path starting with `-` is a file, never an option.
        for (kind, program) in [
            (ImageKind::Gzip, "gzip"),
            (ImageKind::Xz, "xz"),
            (ImageKind::Bzip2, "bzip2"),
            (ImageKind::Zstd, "zstd"),
        ] {
            let tool = tool_for(&kind).expect("a compressed kind maps");
            assert_eq!(tool.program, program);
            assert_eq!(tool.args, &["-dc", "--"]);
        }
        // Every other kind stays on the raw path.
        for kind in [
            ImageKind::Iso,
            ImageKind::Raw,
            ImageKind::Unknown,
            ImageKind::Wim,
        ] {
            assert_eq!(tool_for(&kind), None, "{kind:?} stays raw");
        }
    }

    #[test]
    fn missing_decompressor_names_program_and_kind() {
        // A program name that cannot exist: the refusal names it (and
        // would name the kind through `spawn`, which this path shares).
        let error = ToolStream::spawn_for_test("rufus-test-no-such-decompressor")
            .expect_err("an absent binary refuses");
        assert!(
            matches!(error, CoreError::InvalidInput { .. }),
            "a missing tool is misuse, not I/O: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("rufus-test-no-such-decompressor"), "{text}");
    }

    /// A fake tool writing far more than the 64 KiB kernel pipe to
    /// stderr, then a small payload to stdout, then exiting non-zero.
    /// POSIX `sh` is the only host dependency (the repo's CLI tests
    /// already shell out the same way); the script text is a `static`
    /// so no temporary lifetime reaches the spawn.
    #[cfg(test)]
    static CHATTY_TOOL_SCRIPT: &str = "i=0; while [ $i -lt 6000 ]; do echo \"chatty diagnostic line $i, padding padding padding padding\"; i=$((i + 1)); done >&2; printf '0123456789abcdef'; exit 3";

    #[test]
    fn chatty_tool_does_not_deadlock_the_pipe() {
        // Regression: stderr used to be drained only in `finish`, so a
        // child filling the pipe wedged the stdout pulls forever (and
        // with them cancellation). The drain thread reads concurrently,
        // so this completes inside the test's normal runtime with the
        // payload intact and the tail capped. Covers the drain
        // concurrency only — not real tool output (see the gzip
        // streaming tests) nor the cancel joins (see the cancelled
        // stream test).
        let mut stream =
            ToolStream::spawn_for_test_argv("sh", &["-c", CHATTY_TOOL_SCRIPT]).expect("sh spawns");
        let mut out = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let read = stream.read(&mut chunk).expect("stdout pulls");
            if read == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(out, b"0123456789abcdef");
        let error = stream.finish().expect_err("exit 3 refuses");
        let text = error.to_string();
        assert!(text.contains("sh"), "{text}");
        assert!(text.contains("exit status: 3"), "{text}");
        assert!(text.contains("chatty diagnostic line 0"), "{text}");
        assert!(text.contains("stderr truncated to 4 KiB"), "{text}");
    }
}
