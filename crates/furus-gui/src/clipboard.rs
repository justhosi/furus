//! Clipboard copy support for the run log (S36.3).
//!
//! Slint-free and display-server-free: this module only spawns one of the
//! three well-known Linux clipboard helpers and maps its result into a small
//! enum. No Slint API, device or pkexec is touched here, so the fallback
//! chain is fully unit-testable with fake backends.
//!
//! Pipe hygiene is the reason this module exists instead of a bare
//! `Command::new(...).output()`. Helpers such as `wl-copy` and `xclip`
//! daemonize: the clipboard owner outlives the process we spawned and
//! inherits its stdout/stderr. Reading those pipes to EOF (what
//! `wait_with_output` does) therefore blocks forever. We null stdout, never
//! read stderr to EOF, close stdin explicitly so the helper sees EOF, and
//! wait only for the *spawned* process's exit status on a background thread.

use std::io::Write;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

/// Outcome of one clipboard write attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOutcome {
    /// A helper accepted the text and exited successfully.
    Copied,
    /// No helper is installed (`ErrorKind::NotFound`); try the next one.
    Unavailable,
    /// A helper exists but failed; the string is a short ASCII cause.
    Failed(String),
}

/// One clipboard helper. The trait exists so the chain logic can be tested
/// with fakes and no display server.
trait ClipboardBackend {
    fn copy(&self, text: &str) -> ClipboardOutcome;
}

/// A helper launched as an external process with fixed arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandBackend {
    program: &'static str,
    args: &'static [&'static str],
}

impl CommandBackend {
    const fn new(program: &'static str, args: &'static [&'static str]) -> Self {
        Self { program, args }
    }
}

impl ClipboardBackend for CommandBackend {
    fn copy(&self, text: &str) -> ClipboardOutcome {
        let mut child = match Command::new(self.program)
            .args(self.args)
            .stdin(Stdio::piped())
            // Never pipe stdout: a daemonized clipboard owner inherits it and
            // keeps the write end open forever. Null it unconditionally.
            .stdout(Stdio::null())
            // stderr is piped per the design but deliberately never read to
            // EOF (same daemonization hazard). Error causes are reported from
            // the exit status, not from helper output.
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ClipboardOutcome::Unavailable;
            }
            Err(error) => return ClipboardOutcome::Failed(sanitize(&error.to_string())),
        };

        // Feed the helper and close stdin so it observes EOF and commits the
        // selection. Dropping the handle at the end of this scope is the EOF.
        if let Some(mut stdin) = child.stdin.take()
            && let Err(error) = stdin.write_all(text.as_bytes())
        {
            let _ = child.kill();
            return ClipboardOutcome::Failed(sanitize(&error.to_string()));
        }

        // Wait for the spawned process on a short-lived background thread.
        // `child.wait()` does not read the piped stderr, so it cannot hang on
        // a daemon that inherited the descriptor; the caller joins this
        // thread to obtain the status synchronously.
        let program = self.program;
        let waiter = thread::Builder::new()
            .name("furus-clipboard-wait".to_string())
            .spawn(move || child.wait());
        let status = match waiter {
            Ok(handle) => match handle.join() {
                Ok(status) => status,
                Err(_) => {
                    return ClipboardOutcome::Failed(
                        "clipboard helper waiter panicked".to_string(),
                    );
                }
            },
            Err(_) => {
                return ClipboardOutcome::Failed(
                    "could not start clipboard helper waiter".to_string(),
                );
            }
        };
        status_outcome(program, status)
    }
}

/// Map a helper's exit result into an outcome. Kept pure so the success and
/// non-zero-exit paths are unit-testable without spawning a process.
fn status_outcome(program: &'static str, status: std::io::Result<ExitStatus>) -> ClipboardOutcome {
    match status {
        Ok(status) if status.success() => ClipboardOutcome::Copied,
        Ok(status) => {
            ClipboardOutcome::Failed(sanitize(&format!("{program} exited with {status}")))
        }
        Err(error) => ClipboardOutcome::Failed(sanitize(&error.to_string())),
    }
}

/// Keep failure strings short and ASCII: they end up in a Slint status line
/// and in logs, which must never receive control characters or unbounded
/// helper output.
fn sanitize(message: &str) -> String {
    let cleaned: String = message
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(120)
        .collect();
    if cleaned.is_empty() {
        "unknown error".to_string()
    } else {
        cleaned
    }
}

const WL_COPY: CommandBackend = CommandBackend::new("wl-copy", &[]);
const XCLIP: CommandBackend = CommandBackend::new("xclip", &["-selection", "clipboard"]);
const XSEL: CommandBackend = CommandBackend::new("xsel", &["--clipboard", "--input"]);

/// Build the default helper chain. The session flag is passed in rather than
/// read here so the ordering is testable without touching process-global
/// environment variables.
fn default_chain(wayland: bool) -> Vec<CommandBackend> {
    if wayland {
        vec![WL_COPY, XCLIP, XSEL]
    } else {
        vec![XCLIP, XSEL, WL_COPY]
    }
}

/// Try backends in order. `Copied` short-circuits; `Unavailable` means the
/// tool is absent and the next backend is tried; a real `Failed` is returned
/// to the caller. An exhausted chain reports `Unavailable`.
fn copy_with_chain(chain: &[impl ClipboardBackend], text: &str) -> ClipboardOutcome {
    for backend in chain {
        match backend.copy(text) {
            ClipboardOutcome::Copied => return ClipboardOutcome::Copied,
            ClipboardOutcome::Unavailable => continue,
            failed => return failed,
        }
    }
    ClipboardOutcome::Unavailable
}

/// Copy `text` to the desktop clipboard using the first available helper.
///
/// Safe to call from a worker thread: no Slint API is used. The caller
/// (`main.rs`) runs this on a short-lived `"furus-clipboard"` thread.
#[must_use]
pub fn copy_text(text: &str) -> ClipboardOutcome {
    // Nothing to copy: do not launch any helper. Pinned by a unit test.
    if text.is_empty() {
        return ClipboardOutcome::Failed("no text to copy".to_string());
    }
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let chain = default_chain(wayland);
    copy_with_chain(&chain, text)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    /// Records each `copy` call and returns a configured outcome, so chain
    /// order and short-circuiting can be asserted without a display server.
    struct FakeBackend {
        name: &'static str,
        outcome: ClipboardOutcome,
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeBackend {
        fn new(
            name: &'static str,
            outcome: ClipboardOutcome,
            calls: &Rc<RefCell<Vec<&'static str>>>,
        ) -> Self {
            Self {
                name,
                outcome,
                calls: Rc::clone(calls),
            }
        }
    }

    impl ClipboardBackend for FakeBackend {
        fn copy(&self, _text: &str) -> ClipboardOutcome {
            self.calls.borrow_mut().push(self.name);
            self.outcome.clone()
        }
    }

    #[test]
    fn empty_text_is_rejected_without_spawning() {
        // The public boundary must reject empty input before building a chain,
        // so the outcome is the distinct "no text" failure even in an
        // environment where no clipboard helper exists.
        assert_eq!(
            copy_text(""),
            ClipboardOutcome::Failed("no text to copy".to_string())
        );
    }

    #[test]
    fn wayland_session_prefers_wl_copy() {
        let chain = default_chain(true);
        let programs: Vec<_> = chain.iter().map(|backend| backend.program).collect();
        assert_eq!(programs, ["wl-copy", "xclip", "xsel"]);
    }

    #[test]
    fn x11_session_prefers_xclip() {
        let chain = default_chain(false);
        let programs: Vec<_> = chain.iter().map(|backend| backend.program).collect();
        assert_eq!(programs, ["xclip", "xsel", "wl-copy"]);
    }

    #[test]
    fn unavailable_backend_falls_back_to_next() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let chain = vec![
            FakeBackend::new("first", ClipboardOutcome::Unavailable, &calls),
            FakeBackend::new("second", ClipboardOutcome::Copied, &calls),
        ];
        assert_eq!(
            copy_with_chain(&chain, "log text"),
            ClipboardOutcome::Copied
        );
        assert_eq!(*calls.borrow(), ["first", "second"]);
    }

    #[test]
    fn copied_backend_short_circuits() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let chain = vec![
            FakeBackend::new("first", ClipboardOutcome::Copied, &calls),
            FakeBackend::new("second", ClipboardOutcome::Unavailable, &calls),
        ];
        assert_eq!(
            copy_with_chain(&chain, "log text"),
            ClipboardOutcome::Copied
        );
        assert_eq!(*calls.borrow(), ["first"]);
    }

    #[test]
    fn failed_backend_is_reported() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let chain = vec![FakeBackend::new(
            "only",
            ClipboardOutcome::Failed("xclip exited with status 1".to_string()),
            &calls,
        )];
        assert_eq!(
            copy_with_chain(&chain, "log text"),
            ClipboardOutcome::Failed("xclip exited with status 1".to_string())
        );
        assert_eq!(*calls.borrow(), ["only"]);
    }

    #[test]
    fn exhausted_chain_is_unavailable() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let chain = vec![
            FakeBackend::new("first", ClipboardOutcome::Unavailable, &calls),
            FakeBackend::new("second", ClipboardOutcome::Unavailable, &calls),
        ];
        assert_eq!(
            copy_with_chain(&chain, "log text"),
            ClipboardOutcome::Unavailable
        );
        assert_eq!(*calls.borrow(), ["first", "second"]);
    }

    #[test]
    fn missing_program_maps_to_unavailable() {
        let backend = CommandBackend::new("furus-no-such-clipboard-tool-9f3a2c", &[]);
        assert_eq!(backend.copy("log text"), ClipboardOutcome::Unavailable);
    }

    #[test]
    fn zero_exit_maps_to_copied() {
        assert_eq!(
            status_outcome("wl-copy", Ok(ExitStatus::from_raw(0))),
            ClipboardOutcome::Copied
        );
    }

    #[test]
    fn non_zero_exit_maps_to_short_ascii_failure() {
        let outcome = status_outcome("xclip", Ok(ExitStatus::from_raw(7 << 8)));
        let expected = ClipboardOutcome::Failed("xclip exited with exit status: 7".to_string());
        assert_eq!(outcome, expected);
        match outcome {
            ClipboardOutcome::Failed(message) => {
                assert!(message.is_ascii());
                assert!(message.len() <= 120);
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_replaces_control_and_non_ascii_bytes() {
        assert_eq!(sanitize("ok"), "ok");
        assert_eq!(sanitize("a\nb"), "a?b");
        assert_eq!(sanitize("caf\u{e9}"), "caf?");
        assert_eq!(sanitize(""), "unknown error");
    }
}
