//! Supervised child processes (S06 part 4).
//!
//! S07/S17 need external tools (mkfs, dd, losetup, …); the device
//! writing itself stays theirs. This module is the one sanctioned way
//! for the helper to run a program: one child, both output streams
//! piped, log events streamed through the
//! [`ProgressSink`](crate::progress::ProgressSink) while the child
//! writes, and a cooperative [`Cancel`] honoured the whole time — a
//! user cancel never leaves a half-dead tool behind.
//!
//! # The shape
//!
//! [`run_program`] takes the program, its argv and a [`RunCtx`]. Two
//! reader threads pump `(is_stderr, String)` lines over one `mpsc`
//! channel; the calling thread runs a `recv_timeout` drain loop that
//! emits `Event::Log` lines — `Info` with a `stdout: …` message for the
//! child's stdout, `Warn` with `stderr: …` for stderr — and checks the
//! cancel flag at every line and every quiet gap. On cancel the child
//! is `kill()`ed and then `wait()`ed on (reaped, never left a zombie),
//! the channel is drained, and both reader threads are joined — all
//! before the [`Cancelled`](ProgramOutcome::Cancelled) outcome is
//! returned, so no log event can escape after it.
//!
//! # Documented caps and limits
//!
//! * Every emitted line is sanitised with
//!   [`rufus_core::text::device_text`] (tool output is untrusted) and
//!   capped at [`MAX_LOG_MESSAGE_CHARS`] characters *including* the
//!   stream prefix; the sanitiser's output is pure ASCII, so the cap is
//!   bytes too. Lines that sanitise to empty (blank lines) are dropped
//!   rather than spammed into the JSONL stream.
//! * `stdin` is detached (`Stdio::null`): a tool that reads input must
//!   fail fast, not inhale the caller's stdin.
//! * A child that forks a descendant which inherits and holds the
//!   output pipes can delay EOF past the child's own exit; the final
//!   drain + join waits for it. Supervised tools (mkfs, dd, losetup,
//!   …) do not do that, and with the workspace's
//!   `#![forbid(unsafe_code)]` there is no libc escape hatch to harden
//!   against it — the boundary is documented, not hidden. `sh -c`
//!   shells have long exec'd a single simple command (no descendant
//!   survives the exec), which is how the tests exercise the whole
//!   contract.
//
// The whole seam below is complete but only *wired* by the S07/S17
// writing executor (the device-writing step itself stays their slice);
// everything is transitively dead until then, which the tests pin. The
// allow is module-level for that one reason — remove it when the
// executor arrives. (House style keeps per-item allows where single
// items are dead; here the entry point and its transitive callees are
// all in the same intended-not-yet-consuming state.)
#![allow(dead_code)]

use std::io;
use std::io::BufReader;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use rufus_core::text::device_text;
use rufus_proto::Event;
use rufus_proto::LogLevel;
use rufus_proto::LogLine;

use crate::exec::Cancel;
use crate::progress::ProgressSink;

/// Longest log message (`stdout: `/`stderr: ` prefix included) emitted
/// for one child line; longer lines are cut at this many characters
/// (bytes, since [`device_text`] output is ASCII). The cap keeps tool
/// noise from flooding the JSONL stream unbounded.
pub const MAX_LOG_MESSAGE_CHARS: usize = 2_000;

/// The cancel check cadence: the poll step of the supervising drain
/// loop, so an output-silent child is noticed at the next interval and
/// a chatty one at its next line.
const CANCEL_POLL: Duration = Duration::from_millis(50);

/// Wait step between status polls once all pipes are EOF: the child is
/// exiting, and this only damps the busy loop.
const CHILD_EXIT_POLL: Duration = Duration::from_millis(10);

/// What the child's behaviour and the supervision produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramOutcome {
    /// The child exited with status 0.
    Success,
    /// The child exited without success; `code` is the exit code the OS
    /// reports (`0..=255` on Linux), or the shell convention
    /// `128 + signal number` when the child was killed by a signal on
    /// its own — a cancel kill never arrives here, because that case
    /// returns [`Cancelled`](ProgramOutcome::Cancelled).
    Exit {
        /// The exit code as reported above.
        code: u32,
    },
    /// The cancel flag was honoured: the child was killed and reaped.
    Cancelled,
}

/// A spawn/read/wait failure, shaped like `Reject` (code plus ASCII
/// message) because this module feeds the same reporting. Codes:
/// `"spawn"` (the program could not start) and `"io"` (thread setup or
/// wait failure). The message always names the program and the OS error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramError {
    /// Machine-readable class, e.g. `"spawn"`.
    pub code: String,
    /// ASCII explanation for the human half (sanitised on the way in).
    pub message: String,
}

impl std::fmt::Display for ProgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProgramError {}

impl ProgramError {
    fn spawn(program: &Path, source: &io::Error) -> Self {
        Self {
            code: "spawn".to_string(),
            message: device_text(&format!("cannot start '{}': {source}", program.display())),
        }
    }

    fn io(program: &Path, what: &str, source: &io::Error) -> Self {
        Self {
            code: "io".to_string(),
            message: device_text(&format!("cannot {what} '{}': {source}", program.display())),
        }
    }
}

/// What [`run_program`] sees while it supervises, mirroring
/// `exec::StepCtx`'s style: progress/log delivery, the shared
/// [`Cancel`] and the session id to label events with.
pub struct RunCtx<'a> {
    /// Where the child's output lines are delivered (already sanitised
    /// and capped by [`MAX_LOG_MESSAGE_CHARS`]).
    pub sink: &'a mut dyn ProgressSink,
    /// The shared cancellation flag, checked continuously.
    pub cancel: &'a Cancel,
    /// The session id (labels every emitted log line).
    pub session: &'a str,
}

/// Run `program` (`args`) under supervision: stream its output as log
/// events through `ctx.sink`, honour `ctx.cancel` (killing and reaping
/// the child when it is set), and map the result onto
/// [`ProgramOutcome`].
///
/// The returned [`Result`] is produced only after the reader threads
/// were drained and joined, i.e. no event can arrive after the return.
pub fn run_program(
    program: &Path,
    args: &[String],
    ctx: &mut RunCtx<'_>,
) -> Result<ProgramOutcome, ProgramError> {
    // stdin detached (module docs); both output streams piped so the
    // child cannot talk straight to the helper's own stdout/stderr.
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|source| ProgramError::spawn(program, &source))?;

    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let (mut handles, spawn_error) = attach_readers(&mut child, &tx);
    if let Some(source) = spawn_error {
        // attach_readers reaped the child as part of its cleanup; only
        // the queued lines and the live reader threads remain.
        drop(tx);
        drain_and_join(&rx, &mut handles, ctx.sink, ctx.session);
        return Err(ProgramError::io(
            program,
            "start a reader thread for",
            &source,
        ));
    }
    // The reader threads now own the only senders; the channel closes
    // when both of them are done. Without this drop, the drain loop
    // would never see `Disconnected`.
    drop(tx);

    let end = match supervise(&mut child, &rx, ctx) {
        Err(source) => {
            // The child was already shot by supervise's cleanup; the
            // readers see EOF from that, finish their lines and get
            // joined here. The OS error surfaces as the failure.
            drain_and_join(&rx, &mut handles, ctx.sink, ctx.session);
            return Err(ProgramError::io(program, "wait for", &source));
        }
        Ok(end) => end,
    };
    match end {
        End::Cancel => {
            // kill first, best effort: its only failure mode is "the
            // child is already a zombie", which the `wait` below reaps.
            // A user cancel must not be turned into an error by a
            // SIGKILL that had nothing left to kill.
            let _ = child.kill();
            if let Err(source) = child.wait() {
                drain_and_join(&rx, &mut handles, ctx.sink, ctx.session);
                return Err(ProgramError::io(program, "wait for", &source));
            }
            drain_and_join(&rx, &mut handles, ctx.sink, ctx.session);
            Ok(ProgramOutcome::Cancelled)
        }
        End::Ended(status) => {
            // All pipes are closed and the child is reaped: the readers
            // are done, so what remains queued is child output, still
            // emitted before the outcome (never after it).
            drain_and_join(&rx, &mut handles, ctx.sink, ctx.session);
            Ok(exit_outcome(&status))
        }
    }
}

/// What the supervision ended on, ahead of building the outcome.
enum End {
    /// The cancel flag was set; the child still needs kill + wait.
    Cancel,
    /// All pipes hit EOF and the child turned up in the wait table.
    Ended(ExitStatus),
}

/// The drain loop (module docs): deliver every line the readers queued,
/// poll the child only after EOF, and check `cancel` on every line and
/// every quiet gap. Ends on [`End`]; an `Err` means the wait table
/// failed *after* the child was shot (cleanup done, finalisation left
/// to the caller).
fn supervise(
    child: &mut Child,
    rx: &Receiver<(bool, String)>,
    ctx: &mut RunCtx<'_>,
) -> Result<End, io::Error> {
    let end = 'supervised: loop {
        match rx.recv_timeout(CANCEL_POLL) {
            Ok((is_stderr, raw)) => {
                emit_line(ctx.sink, ctx.session, is_stderr, &raw);
                if ctx.cancel.is_set() {
                    break 'supervised End::Cancel;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if ctx.cancel.is_set() {
                    break 'supervised End::Cancel;
                }
            }
            // Both reader threads dropped their senders: the child's
            // stdout and stderr (and every other copy of that pipe's
            // write end this helper can see) are closed now.
            Err(RecvTimeoutError::Disconnected) => {
                loop {
                    if ctx.cancel.is_set() {
                        // Cancellation survives the EOF race too.
                        break 'supervised End::Cancel;
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => break 'supervised End::Ended(status),
                        Ok(None) => thread::sleep(CHILD_EXIT_POLL),
                        Err(source) => {
                            // The wait status is unreadable: shoot what
                            // is left (best effort) and surface the OS
                            // error to the caller, which then closes
                            // the supervision (drain + join).
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(source);
                        }
                    }
                }
            }
        }
    };
    Ok(end)
}

/// Attach one reader thread per piped output stream; on a failure the
/// child is reaped (kill + wait, best effort) and whatever threads are
/// already running are returned together with the error, so the caller
/// can still drain and join them.
fn attach_readers(
    child: &mut Child,
    tx: &Sender<(bool, String)>,
) -> (Vec<thread::JoinHandle<()>>, Option<io::Error>) {
    let mut handles = Vec::<thread::JoinHandle<()>>::new();
    // One reader per piped stream; `Stdio::piped()` guarantees both,
    // and a `None` stream would simply contribute no lines but skip
    // its reader.
    let stdout = child.stdout.take();
    match stdout.map(|pipe| spawn_reader(BufReader::new(pipe), false, tx.clone())) {
        Some(Ok(handle)) => handles.push(handle),
        Some(Err(source)) => {
            // No half-supervised tool exits this module killing
            // nothing: reap the child, and keep already-running
            // readers for the caller's final join.
            let _ = child.kill();
            let _ = child.wait();
            return (handles, Some(source));
        }
        None => {} // no stdout pipe, so no reader for it
    }
    let stderr = child.stderr.take();
    match stderr.map(|pipe| spawn_reader(BufReader::new(pipe), true, tx.clone())) {
        Some(Ok(handle)) => handles.push(handle),
        Some(Err(source)) => {
            // Same posture as above (any stdout reader keeps running).
            let _ = child.kill();
            let _ = child.wait();
            return (handles, Some(source));
        }
        None => {} // no stderr pipe, so no reader for it
    }
    (handles, None)
}

/// Spawn one reader thread around `reader` (an already buffered child
/// output pipe; the caller hands in the `BufReader` since the child
/// pipes are `Read` only). Fails hard when the thread cannot be
/// created — a spawn that silently reported success while reading
/// nothing would hide output.
fn spawn_reader<R>(
    reader: R,
    is_stderr: bool,
    tx: Sender<(bool, String)>,
) -> io::Result<thread::JoinHandle<()>>
where
    R: io::BufRead + Send + 'static,
{
    thread::Builder::new().spawn(move || reader_loop(reader, is_stderr, tx))
}

/// One reader thread: block on the pipe and forward whole lines (byte
/// sequences up to their `\n`, final partial line included) into the
/// channel; a failed send means the supervisor is gone, and the thread
/// ends quietly (the child dies right after on all our paths anyway).
fn reader_loop<R: io::BufRead>(mut reader: R, is_stderr: bool, tx: Sender<(bool, String)>) {
    let mut buf = Vec::<u8>::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return, // EOF: the child closed its side
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf).into_owned();
                if tx.send((is_stderr, line)).is_err() {
                    return;
                }
            }
            Err(source) => {
                // Read errors are not silent drops: they surface as a
                // line with the same prefix (the sanitiser in the
                // receiver handles any odd bytes), then the stream ends.
                let _ = tx.send((is_stderr, format!("(stream read failed: {source})")));
                return;
            }
        }
    }
}

/// Drain `rx` and then join the reader threads: this is the one place
/// that closes the supervision, so no log event can escape after the
/// caller continues past here.
///
/// `recv()` blocks; every caller reached this point with all pipes
/// closed (reaped or killed child), so the stream is finite by
/// construction — see the module docs for the documented descendant
/// caveat.
fn drain_and_join(
    rx: &Receiver<(bool, String)>,
    handles: &mut Vec<thread::JoinHandle<()>>,
    sink: &mut dyn ProgressSink,
    session: &str,
) {
    while let Ok((is_stderr, raw)) = rx.recv() {
        emit_line(sink, session, is_stderr, &raw);
    }
    for handle in std::mem::take(handles) {
        let _ = handle.join();
    }
}

/// Map a wait status to the outcome, with the documented code
/// conventions (see [`ProgramOutcome::Exit`]).
#[must_use]
fn exit_outcome(status: &ExitStatus) -> ProgramOutcome {
    if status.success() {
        return ProgramOutcome::Success;
    }
    let code = if let Some(code) = status.code() {
        // Linux exit codes live in 0..=255; the cast is lossless there.
        code as u32
    } else if let Some(signal) = status.signal() {
        // The shell convention for a foreign signal death.
        128 + signal as u32
    } else {
        // Neither code nor signal is not producible on Linux; the
        // neutral code keeps the function total without a panic.
        255
    };
    ProgramOutcome::Exit { code }
}

/// One child line out as a log event — `Info` with `stdout: …` for the
/// child's stdout, `Warn` with `stderr: …` for its stderr.
fn emit_line(sink: &mut dyn ProgressSink, session: &str, is_stderr: bool, raw_line: &str) {
    let (level, stream) = if is_stderr {
        (LogLevel::Warn, "stderr")
    } else {
        (LogLevel::Info, "stdout")
    };
    // `device_text` is the one sanitiser for untrusted text (its trims
    // on both ends are part of it); the cap applies to the whole
    // message, prefix included.
    let clean = device_text(raw_line);
    if clean.is_empty() {
        return; // a blank child line is dropped, not spammed
    }
    let budget = MAX_LOG_MESSAGE_CHARS.saturating_sub(stream.len() + 2);
    let mut capped = String::with_capacity(budget);
    capped.extend(clean.chars().take(budget));
    sink.event(&Event::Log(LogLine {
        session: session.to_string(),
        level,
        message: format!("{stream}: {capped}"),
    }));
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;
    use std::time::Instant;

    use rufus_proto::Event;
    use rufus_proto::LogLevel;

    use super::MAX_LOG_MESSAGE_CHARS;
    use super::ProgramOutcome;
    use super::RunCtx;
    use super::run_program;
    use crate::exec::Cancel;
    use crate::progress::VecSink;

    const SESSION: &str = "s-1";
    /// Anything above the cap, still fully read within microseconds:
    /// pinned by the truncation test below.
    const PAYLOAD_XS: usize = 2_400;

    fn argv(script: &str) -> Vec<String> {
        vec!["-c".to_string(), script.to_string()]
    }

    /// The log lines a sink collected, as `(level, message)` pairs.
    fn lines(sink: &VecSink) -> Vec<(LogLevel, String)> {
        let mut found = Vec::new();
        for event in sink.events() {
            if let Event::Log(line) = event {
                found.push((line.level, line.message.clone()));
            }
        }
        found
    }

    /// A fresh ctx over `cancel`/`sink`, [`RunCtx`]'s whole surface.
    fn ctx<'a>(cancel: &'a Cancel, sink: &'a mut VecSink) -> RunCtx<'a> {
        RunCtx {
            sink,
            cancel,
            session: SESSION,
        }
    }

    // -- the core contract --------------------------------------------------

    #[test]
    fn stdout_lines_arrive_in_order_and_success_follows() {
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let outcome = run_program(
            Path::new("sh"),
            &argv("printf \"one\\ntwo\\n\""),
            &mut ctx(&cancel, &mut sink),
        )
        .expect("sh runs here");

        assert_eq!(outcome, ProgramOutcome::Success);
        assert_eq!(
            lines(&sink),
            vec![
                (LogLevel::Info, "stdout: one".to_string()),
                (LogLevel::Info, "stdout: two".to_string()),
            ],
            "whole lines, in order"
        );
    }

    #[test]
    fn nonzero_exit_maps_to_the_code() {
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let outcome = run_program(
            Path::new("sh"),
            &argv("exit 3"),
            &mut ctx(&cancel, &mut sink),
        )
        .expect("sh runs here");
        assert_eq!(outcome, ProgramOutcome::Exit { code: 3 });
    }

    #[test]
    fn a_stderr_line_arrives_as_warn() {
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let outcome = run_program(
            Path::new("sh"),
            &argv("echo >&2 boom"),
            &mut ctx(&cancel, &mut sink),
        )
        .expect("sh runs here");

        assert_eq!(outcome, ProgramOutcome::Success);
        assert_eq!(
            lines(&sink),
            vec![(LogLevel::Warn, "stderr: boom".to_string())]
        );
    }

    // -- spawn failures -------------------------------------------------------

    #[test]
    fn missing_program_errs_and_names_it_without_panic() {
        let missing = "/no/such/rufus-helper-test-missing-program";
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let no_args = Vec::<String>::new();

        let err = run_program(Path::new(missing), &no_args, &mut ctx(&cancel, &mut sink))
            .expect_err("a missing program is a failure, not a panic");

        assert_eq!(err.code, "spawn", "{err}");
        assert!(
            err.message.contains(missing),
            "the message names the program: {}",
            err.message
        );
        assert!(
            lines(&sink).is_empty(),
            "a failed spawn logs nothing: {:?}",
            lines(&sink)
        );
    }

    // -- cancellation ----------------------------------------------------------

    #[test]
    fn cancel_kills_and_reaps_a_long_child_in_time() {
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let killer = cancel.clone();
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            // Canceled from "the other thread", like the handler of the
            // D-Bus order would.
            killer.set();
        });
        let started = Instant::now();

        let outcome = run_program(
            Path::new("sh"),
            &argv("sleep 5"),
            &mut ctx(&cancel, &mut sink),
        )
        .expect("sh runs here");
        late.join().expect("the killer thread ends");

        assert_eq!(outcome, ProgramOutcome::Cancelled);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cancellation arrives in time: {:?}",
            started.elapsed()
        );
        // The `sleep 5` never printed anything, and `sh -c` execs its
        // single command (no descendant): whatever survived the kill
        // would show up here as a hanging drain. The Cancelled outcome
        // itself is only produced after `wait()` reaped the child.
        assert!(
            lines(&sink).is_empty(),
            "nothing leaks from a killed child: {:?}",
            lines(&sink)
        );
    }

    // -- the documented cap ------------------------------------------------------

    #[test]
    fn a_line_longer_than_the_cap_is_truncated_in_the_message() {
        let cancel = Cancel::new();
        let mut sink = VecSink::new();
        let script = format!("printf '%s\\n' {}", "x".repeat(PAYLOAD_XS));
        let outcome = run_program(
            Path::new("sh"),
            &argv(script.as_str()),
            &mut ctx(&cancel, &mut sink),
        )
        .expect("sh runs here");

        assert_eq!(outcome, ProgramOutcome::Success);
        let found = lines(&sink);
        assert_eq!(found.len(), 1, "one line out: {found:?}");
        let (level, message) = &found[0];
        assert_eq!(*level, LogLevel::Info);
        // The cap accounts for the whole message: the 8-character
        // `stdout: ` prefix plus the payload kept inside the budget
        // add up to exactly [`MAX_LOG_MESSAGE_CHARS`].
        assert_eq!(message.len(), MAX_LOG_MESSAGE_CHARS, "{message:?}");
        assert!(message.starts_with("stdout: "), "{message:?}");
        let kept = &message["stdout: ".len()..];
        assert_eq!(kept.len(), MAX_LOG_MESSAGE_CHARS - "stdout: ".len());
        assert!(kept.chars().all(|c| c == 'x'), "kept the start of the line");
    }
}
