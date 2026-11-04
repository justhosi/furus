//! `rufus-helper`: the privileged write helper (S06).
//!
//! One small root component that validates a plan and runs it, nothing
//! else (PLAN §6):
//!
//! ```text
//! rufus-helper --version | --help         unprivileged
//! rufus-helper --plan <FILE> --progress jsonl   under pkexec
//! rufus-helper --dbus                     system-bus service
//! ```
//!
//! Exit codes (mirroring the CLI table via
//! [`rufus_proto::Outcome::exit_code`]): 0 ok, 3 refused, 4 failed,
//! 6 cancelled; usage failures and the unprivileged-invocation refusal
//! exit 1.
//!
//! # Termination
//!
//! There is no SIGTERM handler: `signal-hook-registry`'s `register` is
//! `unsafe` and this crate carries `#![forbid(unsafe_code)]`, so the
//! process takes the default action (immediate exit). Cleanup still
//! happens: every mount
//! lives in the run's private mount namespace, which the kernel tears
//! down with the process, and the next helper start sweeps the session
//! directories of dead pids (`session::sweep`). A cancel that must not
//! wait for a kill goes through the D-Bus `Cancel` method instead.
//!
//! # No test hooks in argv
//!
//! The helper takes **no** `--sysfs-root`/`--mountinfo`/`--swaps`/
//! `--device-file` flags. Those exist only in the unprivileged CLI; a
//! root helper must look at the genuine system, so validation always
//! runs on [`validate::Env::live`]. Unit tests inject fixtures through
//! `Env`, never via argv - see the module docs of `crate::validate`.

#![forbid(unsafe_code)]

mod dbus;
mod exec;
// The mount seam lives in `rufus-linux` now (copy wiring): this
// re-export keeps every existing `crate::mount::...` path working.
// Only the `namespace` tests name it, so the allow keeps normal builds
// quiet without hiding a genuinely dropped use (the tests pin it).
#[allow(unused_imports)]
pub(crate) use rufus_linux::mount;
mod namespace;
mod process;
mod progress;
mod session;
mod validate;

use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use rufus_core::error::CoreError;
use rufus_core::text::device_text;
use rufus_proto::Completion;
use rufus_proto::EVENT_STREAM_VERSION;
use rufus_proto::Event;
use rufus_proto::Outcome;

use exec::CurrentExecutor;
use progress::JsonlSink;
use progress::NullSink;
use progress::ProgressSink;

/// Parsed surface of the privileged run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunArgs {
    /// `--plan <FILE>`: the plan to load and judge.
    plan: PathBuf,
    /// `--progress jsonl` was given: every event also leaves as JSONL.
    progress: bool,
}

/// What the argv wants the helper to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// `--version`, unprivileged.
    Version,
    /// `--help`/`-h`, unprivileged.
    Help,
    /// The one privileged argv form.
    Run(RunArgs),
    /// Serve the D-Bus object instead of running one plan (S06 5b).
    Serve(RunArgs),
}

fn usage() -> &'static str {
    "usage: rufus-helper [--version] [--help]\n\
       \x20      or: rufus-helper --plan <FILE> [--progress jsonl]\n\
       \x20      or: rufus-helper --dbus\n\
     privileged write helper; validates a plan and runs it as root \
     (pkexec).\n\
       --plan <FILE>       the plan JSON to validate and run\n\
       --progress jsonl    stream one JSON event per line to stdout\n\
       --dbus              serve org.rufuslinux.Helper1 on the system bus"
}

/// Parse argv into an [`Action`]; a `Err(message)` is a usage failure
/// (`main` prefixes the helper name and appends the usage text).
///
/// Strictness notes: `--version`/`--help` act alone (any other argument
/// next to them is unexpected); an unexpected value for `--progress`
/// (anything but `jsonl`) is caught here, before the root check, so an
/// unprivileged caller gets the usage error rather than a privilege
/// one; `--plan` is the only remaining required flag.
fn parse(args: &[String]) -> Result<Action, String> {
    let mut version = false;
    let mut help = false;
    let mut plan: Option<PathBuf> = None;
    let mut progress: Option<String> = None;
    let mut serve = false;

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if version || help {
            return Err(format!("unexpected argument '{arg}'"));
        }
        match arg {
            "--version" => version = true,
            "--dbus" => {
                if serve {
                    return Err("unexpected duplicate argument '--dbus'".to_string());
                }
                serve = true;
            }
            "--help" | "-h" => help = true,
            "--plan" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("unexpected argument '--plan' (it needs a value)".to_string());
                };
                if plan.is_some() {
                    return Err("unexpected duplicate argument '--plan'".to_string());
                }
                plan = Some(PathBuf::from(value));
                index += 1;
            }
            "--progress" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("unexpected argument '--progress' (it needs a value)".to_string());
                };
                if progress.is_some() {
                    return Err("unexpected duplicate argument '--progress'".to_string());
                }
                progress = Some(value.clone());
                index += 1;
            }
            other => return Err(format!("unexpected argument '{other}'")),
        }
        index += 1;
    }

    if version {
        return Ok(Action::Version);
    }
    if help {
        return Ok(Action::Help);
    }
    if serve {
        if plan.is_some() {
            return Err("--dbus runs the service, --plan runs one plan: pick one".to_string());
        }
        if progress.is_some() {
            return Err("--progress belongs to --plan, not to --dbus".to_string());
        }
        // The service has no plan or sink of its own; the struct is
        // only a carrier so `main` has one privileged entry point.
        return Ok(Action::Serve(RunArgs {
            plan: PathBuf::new(),
            progress: false,
        }));
    }
    let Some(plan) = plan else {
        return Err("no --plan and no --dbus given".to_string());
    };
    if progress.as_deref() != Some("jsonl") {
        // `jsonl` is the only wired transport; anything else (including
        // an empty value) is a usage failure, exit 1.
        let value = progress.as_deref().unwrap_or("");
        return Err(format!("--progress expects 'jsonl', got '{value}'"));
    }
    Ok(Action::Run(RunArgs {
        plan,
        progress: true,
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit_code = match parse(&args) {
        Err(message) => {
            eprintln!("rufus-helper: {message}\n\n{}", usage());
            1
        }
        Ok(Action::Version) => {
            println!("rufus-helper {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Action::Help) => {
            println!("{}", usage());
            0
        }
        Ok(Action::Run(run_args)) => run(&run_args),
        Ok(Action::Serve(_)) => serve(),
    };
    let _ = io::stdout().flush();
    // No destructor needs running at this point (sessions were dropped
    // by `run`), so a bare exit is safe.
    std::process::exit(exit_code);
}

/// The service path: root check first, then export
/// `org.rufuslinux.Helper1` on the system bus and serve until killed.
///
/// See `packaging/README.md` for the `busctl` calls that exercise it.
fn serve() -> i32 {
    if rustix::process::geteuid().as_raw() != 0 {
        eprintln!("rufus-helper: must run as root (use pkexec)");
        return 1;
    }

    let connection = match zbus::block_on(zbus::Connection::system()) {
        Ok(connection) => connection,
        Err(err) => {
            eprintln!(
                "rufus-helper: failed: cannot connect to the system bus: {}",
                device_text(&err.to_string())
            );
            return 4;
        }
    };
    let authorization: std::sync::Arc<dyn dbus::Authorizer> =
        std::sync::Arc::new(dbus::PolkitAuthorizer::new(connection.clone()));
    let emitter: std::sync::Arc<dyn dbus::EventEmitter> =
        std::sync::Arc::new(dbus::SignalEmitter::new(connection.clone()));
    let registry = std::sync::Arc::new(dbus::Registry::new(
        PathBuf::from(session::SESSION_ROOT),
        validate::Env::live(),
        authorization,
        emitter,
    ));
    if let Err(err) = zbus::block_on(
        connection
            .object_server()
            .at(dbus::OBJECT_PATH, dbus::Helper1::new(registry)),
    ) {
        eprintln!(
            "rufus-helper: failed: cannot export {}: {}",
            dbus::OBJECT_PATH,
            device_text(&err.to_string())
        );
        return 4;
    }
    if let Err(err) = zbus::block_on(connection.request_name(dbus::BUS_NAME)) {
        eprintln!(
            "rufus-helper: failed: cannot own {}: {}",
            dbus::BUS_NAME,
            device_text(&err.to_string())
        );
        return 4;
    }

    // The reading is that the connection keeps serving on the
    // `block_on` helper thread once those setup calls return, so the
    // main thread only sleeps to stay alive (the process is killed by
    // the service manager, which drops every session with it). What was
    // measured, on a private session bus with zbus 6.2.0 and zruntime
    // 0.2.2: a service set up this way (`Connection::session`,
    // `object_server().at(...)`, `request_name(...)`, each via
    // `zbus::block_on`) still answered a method call from a second
    // connection after setup returned while the serving thread only
    // slept (`RESULT call returned: pong`).
    // The probe used a private session bus only and says nothing about
    // the system bus or polkit.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3_600));
    }
}

/// The privileged path: root check first (never read a file as a
/// lesser user), then load → validate → session → run → the final
/// `Done` event → stderr lines → exit code.
fn run(args: &RunArgs) -> i32 {
    // The root check precedes any file read; a non-root invocation must
    // not learn anything about the plan (or even whether it exists).
    if rustix::process::geteuid().as_raw() != 0 {
        eprintln!("rufus-helper: must run as root (use pkexec)");
        return 1;
    }

    let env = validate::Env::live();
    let mut sink: Option<JsonlSink<io::Stdout>> =
        args.progress.then(|| JsonlSink::new(io::stdout()));
    let mut discard = NullSink::new();
    // Empty until the session exists; pre-session failures stream no
    // events but still end their stream on exactly one `Done`.
    let mut session_id = String::new();

    let outcome = match validate::load(&args.plan) {
        Err(reject) => Outcome::Failed {
            code: reject.code,
            message: reject.message,
        },
        Ok(plan) => match validate::validate(&plan, &env) {
            Err(reject) => Outcome::Refused {
                code: reject.code,
                message: reject.message,
            },
            Ok(validated) => {
                let mut executor = CurrentExecutor;
                match session::Session::create(Path::new(session::SESSION_ROOT), &validated.plan) {
                    Err(err) => Outcome::Failed {
                        code: err.code,
                        message: err.message,
                    },
                    Ok(session) => {
                        match namespace::enter_mount_namespace() {
                            Err(err) => {
                                // The namespace isolation is the last
                                // pre-step gate (S06 part 4): the plan
                                // has not run yet, so the run ends here
                                // with nothing written — and no session
                                // left behind (the drop reclaims the
                                // directory and the lock). The stream
                                // still ends on exactly one `Done`, now
                                // with an empty session id, like the
                                // other pre-run stops.
                                drop(session);
                                Outcome::Failed {
                                    code: namespace::MOUNT_NAMESPACE_CODE.to_string(),
                                    message: format!(
                                        "cannot isolate mounts: {}",
                                        isolation_message(err)
                                    ),
                                }
                            }
                            Ok(()) => {
                                session_id = session.id().to_string();
                                let cancel = exec::Cancel::new();
                                let outcome = exec::run_plan(
                                    &validated.plan,
                                    &validated.device,
                                    &mut executor,
                                    sink_for(&mut sink, &mut discard),
                                    &cancel,
                                    &session_id,
                                );
                                // The session closes (dir + lock removed)
                                // before any terminal reporting happens.
                                drop(session);
                                outcome
                            }
                        }
                    }
                }
            }
        },
    };

    // A failed sink outranks the run's own result (PLAN §2): events the
    // reader never saw cannot back a success report.
    if let Some(sink) = &mut sink
        && sink.failed()
    {
        return fail_sink();
    }

    // The one terminal event, whatever the outcome (the stream always
    // ends on exactly one `Done`).
    emit(
        sink.as_mut(),
        &mut discard,
        &Event::Done(Completion {
            session: std::mem::take(&mut session_id),
            version: EVENT_STREAM_VERSION,
            outcome: outcome.clone(),
        }),
    );

    // A sink failure during the terminal event itself still counts.
    if let Some(sink) = &mut sink
        && sink.failed()
    {
        return fail_sink();
    }

    match &outcome {
        Outcome::Refused { message, .. } => {
            eprintln!("rufus-helper: refused: {}", device_text(message));
        }
        Outcome::Failed { message, .. } => {
            eprintln!("rufus-helper: failed: {}", device_text(message));
        }
        Outcome::Ok | Outcome::Cancelled => {}
    }

    outcome.exit_code()
}

/// Choose the sink the run talks to: the JSONL transport, or the
/// discarding sink when no `--progress` was given.
fn sink_for<'a>(
    sink: &'a mut Option<JsonlSink<io::Stdout>>,
    discard: &'a mut NullSink,
) -> &'a mut dyn ProgressSink {
    match sink {
        Some(sink) => sink,
        None => discard,
    }
}

/// One event out through whichever sink exists.
fn emit(sink: Option<&mut JsonlSink<io::Stdout>>, discard: &mut NullSink, event: &Event) {
    match sink {
        Some(sink) => ProgressSink::event(sink, event),
        None => ProgressSink::event(discard, event),
    }
}

/// A `CoreError` message for the run-failure line. The namespace module
/// only builds [`CoreError::InvalidInput`], whose Display adds an
/// `"invalid input: "` wrapper that is noise in a run sentence, so the
/// message itself is what the stderr line carries; the catch-all keeps
/// the match honest against (non-exhaustive) additions, reusing the
/// Display then.
fn isolation_message(err: CoreError) -> String {
    match err {
        CoreError::InvalidInput { message } => message,
        other => other.to_string(),
    }
}

/// The recorded sink failure reports as an execution failure, exit 4.
fn fail_sink() -> i32 {
    eprintln!("rufus-helper: failed: the progress stream could not be written");
    4
}
