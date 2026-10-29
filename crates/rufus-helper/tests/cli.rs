//! `rufus-helper` CLI integration tests (S06).
//!
//! Each test drives the real binary via `std::process::Command` +
//! `CARGO_BIN_EXE_rufus_helper` (no extra dev-dependency crates), the
//! same style the `rufus` CLI tests use. Everything here runs
//! unprivileged, on purpose: the assertions pin the unprivileged
//! surface (version/help, argv-shaped usage errors) and the ordering
//! guarantee that the root check precedes any file read.
//!
//! The helper is handed **no** test hooks (no `--sysfs-root` and
//! friends, ever); the inline unit tests cover validation through
//! `Env` fixtures instead.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Run {
    /// Process exit code (`None` means killed by a signal — a failure).
    code: i32,
    stdout: String,
    stderr: String,
}

/// Spawn the helper binary with the given arguments.
fn run(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_rufus-helper"))
        .args(args)
        .output()
        .expect("spawn rufus-helper binary");
    Run {
        code: out.status.code().expect("killed by a signal"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The single-session root /run/rufus-linux, if it exists and can be
/// listed; `None` otherwise (unprivileged tests cannot create it, and a
/// legitimate root run elsewhere may have).
fn session_entries() -> Option<Vec<PathBuf>> {
    let root = Path::new("/run/rufus-linux");
    let mut list: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();
    list.sort();
    Some(list)
}

// ---------------------------------------------------------------------------
// Unprivileged surface: --version/--help
// ---------------------------------------------------------------------------

#[test]
fn version_works_unprivileged() {
    let invocation = run(&["--version"]);
    assert_eq!(invocation.code, 0, "the version answers without privileges");
    assert!(invocation.stderr.is_empty(), "{:?}", invocation.stderr);
    assert!(
        invocation.stdout.starts_with("rufus-helper "),
        "the version line names the helper: {}",
        invocation.stdout
    );
}

#[test]
fn help_works_unprivileged_long_and_short() {
    for flag in ["--help", "-h"] {
        let invocation = run(&[flag]);
        assert_eq!(invocation.code, 0, "{flag} answers without privileges");
        assert!(
            invocation.stdout.contains("usage: rufus-helper"),
            "{flag} prints the usage: {}",
            invocation.stdout
        );
        assert!(
            invocation.stdout.contains("--plan <FILE>"),
            "the usage documents --plan: {}",
            invocation.stdout
        );
        assert!(
            invocation.stdout.contains("--progress jsonl"),
            "the usage documents --progress: {}",
            invocation.stdout
        );
    }
}

// ---------------------------------------------------------------------------
// Usage errors (all precede the root check: a bad argument must not
// first demand privileges)
// ---------------------------------------------------------------------------

#[test]
fn unknown_argument_is_a_usage_error() {
    let invocation = run(&["--bogus"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("unexpected argument '--bogus'"),
        "the offending flag is named: {:?}",
        invocation.stderr
    );
    assert!(
        invocation.stderr.contains("usage: rufus-helper"),
        "usage is on stderr: {:?}",
        invocation.stderr
    );
    assert!(invocation.stdout.is_empty());
}

#[test]
fn extra_positional_value_is_a_usage_error() {
    let invocation = run(&["--plan", "plan.json", "stray"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("unexpected argument 'stray'"),
        "{:?}",
        invocation.stderr
    );
    assert!(
        invocation.stderr.contains("usage: rufus-helper"),
        "{:?}",
        invocation.stderr
    );
}

#[test]
fn missing_values_are_usage_errors() {
    let invocation = run(&["--plan"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("'--plan'") && invocation.stderr.contains("value"),
        "the flag needing a value is named: {:?}",
        invocation.stderr
    );
    let invocation = run(&["--progress"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("'--progress'"),
        "{:?}",
        invocation.stderr
    );
}

#[test]
fn missing_plan_is_a_usage_error() {
    // No arguments at all: neither the run form nor the service form
    // was asked for.
    let invocation = run(&[]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("no --plan and no --dbus given"),
        "{:?}",
        invocation.stderr
    );
    assert!(
        invocation.stderr.contains("usage: rufus-helper"),
        "{:?}",
        invocation.stderr
    );
    // --progress without --plan: still missing the plan.
    let invocation = run(&["--progress", "jsonl"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("no --plan and no --dbus given"),
        "{:?}",
        invocation.stderr
    );
}

#[test]
fn progress_value_must_be_jsonl() {
    let invocation = run(&["--plan", "whatever.json", "--progress", "xml"]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation
            .stderr
            .contains("--progress expects 'jsonl', got 'xml'"),
        "the bad value is named: {:?}",
        invocation.stderr
    );
    assert!(
        invocation.stderr.contains("usage: rufus-helper"),
        "{:?}",
        invocation.stderr
    );
    // An empty value refuses the same way.
    let invocation = run(&["--plan", "whatever.json", "--progress", ""]);
    assert_eq!(invocation.code, 1);
    assert!(
        invocation.stderr.contains("'jsonl'"),
        "the value rule is named: {:?}",
        invocation.stderr
    );
}

#[test]
fn version_and_help_act_alone() {
    let invocation = run(&["--version", "--plan", "x"]);
    assert_eq!(invocation.code, 1, "flags after --version are unexpected");
    assert!(
        invocation.stderr.contains("unexpected argument '--plan'"),
        "{:?}",
        invocation.stderr
    );
    let invocation = run(&["--help", "--bogus"]);
    assert_eq!(invocation.code, 1);
}

// ---------------------------------------------------------------------------
// The root gate, proven to precede any file read
// ---------------------------------------------------------------------------

#[test]
fn root_check_precedes_any_file_read() {
    // A plan path that does not exist: if the helper read the plan
    // first, this invocation would answer with a plan error instead of
    // the privilege one — the exact ordering PLAN §6 wants.
    let before = session_entries();
    let invocation = run(&[
        "--plan",
        "/nonexistent/rufus-helper/no-such-plan.json",
        "--progress",
        "jsonl",
    ]);
    let after = session_entries();

    assert_eq!(invocation.code, 1);
    assert_eq!(
        invocation.stderr, "rufus-helper: must run as root (use pkexec)\n",
        "the root gate speaks, exact and first: {:?}",
        invocation.stderr
    );
    assert!(invocation.stdout.is_empty());
    // No session state may have been created (or removed) by the run:
    // the invocation never got past the root check.
    assert_eq!(before, after, "the session root stayed untouched");
}

#[test]
fn dbus_mode_refuses_a_plan_and_a_progress_stream() {
    // The service owns the plans it receives on the bus: an argv plan
    // or an argv JSONL stream next to `--dbus` is a contradiction, and
    // both are caught before the root check (the usage text is the
    // same for root and non-root).
    for args in [
        vec!["--dbus", "--plan", "/tmp/x.json"],
        vec!["--dbus", "--progress", "jsonl"],
        vec!["--plan", "/tmp/x.json", "--dbus"],
    ] {
        let invocation = run(&args);
        assert_eq!(invocation.code, 1, "{args:?}: {:?}", invocation.stderr);
        assert!(
            invocation.stderr.contains("--dbus"),
            "{args:?}: {:?}",
            invocation.stderr
        );
        assert!(
            invocation.stderr.contains("usage: rufus-helper"),
            "{args:?}: {:?}",
            invocation.stderr
        );
    }
}

#[test]
fn dbus_mode_is_privileged_before_it_touches_the_bus() {
    // Unprivileged, `--dbus` must stop at the root gate with the same
    // sentence as the argv path — never reach for the system bus, and
    // never create a session.
    let before = session_entries();
    let invocation = run(&["--dbus"]);
    assert_eq!(invocation.code, 1, "{:?}", invocation.stderr);
    assert_eq!(
        invocation.stderr.trim(),
        "rufus-helper: must run as root (use pkexec)",
        "{:?}",
        invocation.stderr
    );
    assert_eq!(session_entries(), before, "a session directory appeared");
}
