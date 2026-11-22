//! The D-Bus service layer, minus the bus (S06 part 5a).
//!
//! `main`'s argv mode is one synchronous run: load, validate, run, exit.
//! The service mode is one long-lived privileged process taking
//! `Execute(plan_json)` calls from the bus, and a write run must not
//! decide *when* an answer comes: a 4 GiB stick write outruns any
//! method call, so `Execute` replies with the session id while the plan
//! still runs, and the front end follows the run through the event
//! stream ([`Event`]s) plus `Cancel(session_id)`.
//!
//! This module is the whole service in two halves: the pure service
//! layer (the busy claim, the worker thread, the authorisation seam
//! and the event seam) and, since part 5b landed, the bus half right
//! after it — the polkit-backed [`PolkitAuthorizer`], the
//! signal-backed [`EventEmitter`] and the exported [`Helper1`] object.
//! The split inside this file keeps the service logic bus-free: only
//! the second half reaches for `zbus`.
//!
//! # The async shape (zbus 6)
//!
//! zbus 6 is async-only: there is no `blocking` API, and every bus
//! call (`Connection::system`, `Proxy::new`, `call_method`,
//! `emit_signal`, `request_name`, `ObjectServer::at`) is an `async fn`
//! on the connection's runtime (the default `default-rt` feature, so
//! no extra dependency). The sync internals above stay sync on
//! purpose — [`Registry::execute`] and the [`Authorizer`] /
//! [`EventEmitter`] traits are unchanged, with all their tests — and
//! the bus half bridges the two worlds in one direction only:
//!
//! * The bus-facing [`PolkitAuthorizer`] and [`SignalEmitter`] hold a
//!   plain async [`zbus::Connection`] and drive it with
//!   [`zbus::block_on`] from inside their sync trait methods. That is
//!   safe exactly because those methods always run on ordinary
//!   `std::thread`s (the `furus-session` worker, or the short-lived
//!   `furus-accept` thread below) — never on the connection's own
//!   runtime. The never half is measured, not assumed: calling
//!   `zbus::block_on` from a task the runtime drives panics instead of
//!   hanging — on zbus 6.2.0 with zruntime 0.2.2 the panic (at
//!   `zruntime-0.2.2/src/driver.rs:797:9`) reads `block_on called from
//!   a task this runtime is running: the call would wait for the very
//!   thread it is on` — so a misplaced call fails fast instead of
//!   wedging the service silently.
//! * The exported [`Helper1`] methods are `async`, so they run on the
//!   runtime. `execute` therefore never calls the sync registry
//!   directly: it hands the whole accept path to a `furus-accept`
//!   thread and awaits a [`Handoff`], a one-shot slot woken by the
//!   thread's completion. `cancel` needs no thread — it only touches
//!   the in-memory claim lock, performing no bus I/O at all.
//!
//! The deadlock rule, in one sentence: `zbus::block_on` runs only on
//! threads the runtime does not drive, and runtime tasks never block
//! on a thread — they `await` its [`Handoff`]. Reversing the first half
//! (blocking the runtime on a thread whose bus calls need the runtime)
//! would wedge the service; reversing the second (driving `block_on`
//! from a runtime task) panics as measured above, which is why the
//! shape is pinned this way.
//!
//! The serve side is measured too: a throwaway probe (not in this repo)
//! followed the same setup shape as `serve()` —
//! `object_server().at(...)`, `request_name(...)`, each via
//! `zbus::block_on` — but on a private session bus
//! (`Connection::session`; `serve()` uses `Connection::system`)
//! under zbus 6.2.0 and zruntime 0.2.2, and a method call from a second
//! connection still answered after the setup calls had returned while
//! the serving thread only slept (`RESULT call returned: pong`). That
//! probe says nothing about the system bus or polkit, which it did not
//! exercise.
//!
//! # The life of a session
//!
//! ```text
//! Execute(caller, plan_json)                      Cancel(caller, session_id)
//!    │ 1. authorization.authorize(caller)                │ the claim's Cancel is
//!    │ 2. claim the busy slot (one lock acquisition)     │ set — by the caller
//!    │    (Busy when one is running)                     │ that `execute`
//!    │ 3. parse + validate (synchronous, claim held)     │ recorded — and the
//!    │ 4. spawn the `furus-session` thread               │ worker sees it
//!    │    ↕ the worker creates the session and publishes its id
//!    │                                                   │ before its first
//!    │                                                   │ step and warns
//!    ├──► return Ok(session_id)   — the plan keeps running on the thread
//! ```
//!
//! The run itself follows the argv pipeline one step per worker:
//! [`session::Session::create`] (session id + directory) →
//! [`namespace::enter_mount_namespace`] → the run's
//! [`PlanRunner`](crate::pipeline::PlanRunner) (the real core pipeline
//! in production), every [`Event`] forwarded through the
//! [`EventEmitter`], and exactly one final
//! `Event::Done`([`Completion`]).
//!
//! # Why isolation is gated on the uid here
//!
//! The worker isolates its mounts only when the process is privileged
//! (`isolation_wanted`): `unshare(CLONE_NEWNS)` needs `CAP_SYS_ADMIN`
//! and fails hard for everyone else. The argv path in `main` refuses
//! non-root invocations up front, so production runs are always root
//! and always isolate; the gate exists so unprivileged *unit* runs
//! (which must not root, per this crate's test contract) can execute
//! the rest of the pipeline truthfully. Nothing is weakened: a
//! non-root run that got here still faces every plan rule, and 5b's
//! service starts as root exactly like `main`'s argv path.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use furus_core::error::CoreError;
use furus_core::text::device_text;
use furus_proto::Completion;
use furus_proto::EVENT_STREAM_VERSION;
use furus_proto::Event;
use furus_proto::Outcome;
use furus_proto::Progress;
use furus_proto::service;

use crate::exec;
use crate::namespace;
use crate::pipeline::PlanRunner;
use crate::pipeline::RealRunner;
use crate::progress::ProgressSink;
use crate::session;
use crate::validate;

// These identifiers are the single-sourced GUI / helper / packaging contract
// in `furus_proto::service`. They stay as `pub const` aliases here so the
// existing API used by `main.rs` and the tests below is unchanged, but their
// values now have exactly one definition. `xtask contract --check` reads the
// shared module and validates the installed packaging files against it.

/// The well-known bus name part 5b requests for the helper service.
pub const BUS_NAME: &str = service::BUS_NAME;

/// The object path carrying the helper interface (part 5b).
pub const OBJECT_PATH: &str = service::OBJECT_PATH;

/// The polkit action a caller must hold to run a plan (fail closed:
/// [`Registry::execute`] asks [`Authorizer`] before it looks at a
/// plan).
pub const POLKIT_ACTION: &str = service::POLKIT_ACTION;

/// D-Bus error name of an authorization that denied a caller, or whose
/// check itself failed — the name [`ServiceError::code`] maps.
pub const ERROR_NOT_AUTHORIZED: &str = service::ERROR_NOT_AUTHORIZED;

/// D-Bus error name of a refused request while another session runs.
pub const ERROR_BUSY: &str = service::ERROR_BUSY;

/// D-Bus error name of a `Cancel` naming nothing running.
pub const ERROR_UNKNOWN_SESSION: &str = service::ERROR_UNKNOWN_SESSION;

/// D-Bus error name of a plan that failed to parse or to validate.
pub const ERROR_INVALID_PLAN: &str = service::ERROR_INVALID_PLAN;

/// Name of the worker thread one accepted run executes on (pinned for
/// `top`/reporting; the worker shares no state with the bus except
/// through [`Registry`]'s own locks).
const WORKER_THREAD_NAME: &str = "furus-session";

/// One method-call failure of the service. `code` is always the ASCII
/// class the bus half maps onto a D-Bus error name — one of the
/// `ERROR_*` constants above, or a stable code it maps to a generic
/// error (`"io"`, the session layer's `"random"`, an unknown
/// `"session"`). Display prints only the message, which is one ASCII
/// line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    code: &'static str,
    message: String,
}

impl ServiceError {
    /// The machine-readable class (see the struct docs).
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    fn not_authorized(message: String) -> Self {
        Self {
            code: ERROR_NOT_AUTHORIZED,
            message,
        }
    }

    fn busy(message: String) -> Self {
        Self {
            code: ERROR_BUSY,
            message,
        }
    }

    fn invalid_plan(message: String) -> Self {
        Self {
            code: ERROR_INVALID_PLAN,
            message,
        }
    }

    fn unknown_session(message: String) -> Self {
        Self {
            code: ERROR_UNKNOWN_SESSION,
            message,
        }
    }

    /// A failure of the service itself (thread launch, worker
    /// plumbing): a stable `"io"` class, never one of the
    /// plan-meaning classes.
    fn internal(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    /// A [`session::Session`] creation failure forwarded to `execute`:
    /// the session's own stable code (`"busy"` becomes the busy class
    /// here — the same lock contention `Busy` means elsewhere; `"io"`
    /// and `"random"` pass through for a generic mapping).
    fn from_session(code: String, message: String) -> Self {
        let mapped: &'static str = match code.as_str() {
            "busy" => ERROR_BUSY,
            "io" => "io",
            "random" => "random",
            _ => "session",
        };
        Self {
            code: mapped,
            message,
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Who may run a plan. The bus half (5b) implements this over polkit
/// (an `org.freedesktop.PolicyKit1.Authority` check for the caller's
/// unique name against [`POLKIT_ACTION`]); unit tests use plain
/// yes/no fakes.
///
/// `Err` means "the check could not be made" — a *transient* failure,
/// which [`Registry::execute`] treats as denial (fail closed): the
/// caller is never served on a policy verdict nobody got.
pub trait Authorizer: Send + Sync {
    /// Grant (`Ok(true)`) or deny (`Ok(false)`) `caller`; a failed
    /// check is `Err(detail)`.
    fn authorize(&self, caller: &str) -> Result<bool, String>;
}

/// Where run events go while a plan executes. The bus half (5b)
/// implements this over the helper object's D-Bus signals; unit tests
/// collect events in memory.
///
/// The run must not depend on delivery: [`EventEmitter::emit`]
/// reporting `Err` means the transport is gone (a vanished front
/// end), and the run's own result still reaches the final `Done` —
/// only the delivery is broken (see [`SignalSink`]).
pub trait EventEmitter: Send + Sync {
    /// Deliver one event (`Ok` once handed to a transport).
    fn emit(&self, event: &Event) -> Result<(), String>;
}

/// A worker pause hook between the session existing and the plan
/// running. [`Registry::new`] never sets one; tests do (see
/// `install_run_pause`), so they can cancel or probe the claim at a
/// deterministic point — a pause hook here avoids any dependency on
/// how fast the runner happens to execute its steps.
type RunPause = Arc<dyn Fn() + Send + Sync>;

/// The one live run: from `execute`'s claim to the worker's end.
///
/// `id` is `None` until the session exists — the worker publishes the
/// id under the same lock *before* reporting it over the channel, so
/// a `cancel(id)` given right after `execute` returns aims at the
/// run it names.
struct Claim {
    /// The run's cancellation flag, shared with the step loop from its
    /// first byte (and settable through the claim from the start).
    cancel: exec::Cancel,
    /// The session id once [`session::Session::create`] returned.
    id: Option<String>,
    /// The unique bus name of the caller [`Registry::execute`]
    /// accepted. `Cancel` acts only for this caller: any local user
    /// can enumerate the session ids under the sessions root, so a
    /// cancel scoped by id alone would let one user abort another
    /// user's disk write.
    owner: String,
}

/// Releases the busy claim whenever the worker's frame ends — normal
/// return, early return or unwind alike. Built as the *first* binding
/// of the worker body: locals drop in reverse order, so the claim
/// outlives exactly the run and a worker panic can never wedge the
/// service busy for good (`Registry::execute` itself releases in its
/// no-spawn worlds: refusals before step 4, and failing launches).
struct ClaimGuard {
    state: Arc<Mutex<Option<Claim>>>,
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// What the worker reports to the waiting `execute`: the session id
/// (published first — see [`Claim`]) or the synchronous failure of the
/// session's creation. Exactly one report is sent, whichever branch.
enum Opening {
    Started(String),
    Failed(String, String),
}

/// The worker's own body: everything one accepted run needs after
/// `execute` stopped waiting. `Send`-only — it lives on one thread.
struct WorkerRun {
    /// The claim's backing state, shared with [`Registry`]; the
    /// [`ClaimGuard`] clears it when this frame ends.
    state: Arc<Mutex<Option<Claim>>>,
    /// The sessions root (`/run/furus-linux` in the service — see
    /// [`session::SESSION_ROOT`]; unit tests pass a scratch tempdir).
    root: PathBuf,
    /// The validated run: plan (confirm intact), device, verdict
    /// input.
    plan: validate::Validated,
    /// The claim's cancel flag (sharing state with the slot on
    /// purpose: one flag per run).
    cancel: exec::Cancel,
    emitter: Arc<dyn EventEmitter>,
    /// How this run executes its plan: the real pipeline in the
    /// service, a hermetic stub in the fixtures.
    runner: Arc<dyn PlanRunner>,
    /// The one shot to report [`Opening`] back to `execute`.
    tx: mpsc::Sender<Opening>,
    /// The pause hook ([`Registry::new`] leaves it `None`).
    pause: Option<RunPause>,
}

impl WorkerRun {
    /// The whole run, on its own thread. See the module docs for the
    /// pinned order (create → isolate → loop → exactly one `Done`).
    fn run(self) {
        // Destructured once: the claim's state and the cancel flag are
        // the only things shared back out, via the guard's `Arc`.
        let WorkerRun {
            state,
            root,
            plan,
            cancel,
            emitter,
            runner,
            tx,
            pause,
        } = self;

        // First binding on purpose: the claim is released when this
        // frame ends, however it ends (see [`ClaimGuard`]).
        let _claim_guard = ClaimGuard {
            state: state.clone(),
        };

        // The session: its fresh random id, its 0700 directory, the
        // single-session lock — the argv pipeline's call, byte for
        // byte.
        let session = match session::Session::create(&root, &plan.plan) {
            Ok(session) => session,
            Err(err) => {
                // Without a session id there is no stream: the failure
                // rides the `execute` result, not an event.
                let _ = tx.send(Opening::Failed(err.code, err.message));
                return;
            }
        };
        let id = session.id().to_string();
        // Publish before reporting: `cancel` takes the same lock, so a
        // reported id is a cancellable id.
        reserve_id(&state, &id);
        let _ = tx.send(Opening::Started(id.clone()));

        // The test pause (see `install_run_pause`): parked here, the
        // run is claimed, its id known, and not one step in yet.
        if let Some(pause) = pause.clone() {
            pause();
        }

        // The run's own sink: every event of the loop, and the final
        // `Done`, goes through the emitter (delivery breakage is
        // recorded, never propagated — see [`SignalSink`]).
        let mut sink = SignalSink::new(emitter.clone());

        // Privileged only (see the module docs): the mount isolation,
        // before anything of the plan happens — the argv pipeline's
        // same order.
        if Registry::isolation_wanted()
            && let Err(err) = namespace::enter_mount_namespace()
        {
            // The argv pipeline's shape again: the plan has not
            // started, the session (dir + lock) is reclaimed, and
            // the stream still ends on exactly one `Done`.
            let message = match err {
                CoreError::InvalidInput { message } => message,
                other => other.to_string(),
            };
            finish_run(
                session,
                &id,
                &mut sink,
                Outcome::Failed {
                    code: namespace::MOUNT_NAMESPACE_CODE.to_string(),
                    message: format!("cannot isolate mounts: {message}"),
                },
            );
            return;
        }

        // The real write pipeline (a hermetic stub in the fixtures).
        // The runner owns the event grammar and the outcome mapping;
        // this worker only owns the session, the sink and the cancel
        // flag it probes.
        let outcome = runner.run(&plan, &mut sink, &cancel, &id);
        finish_run(session, &id, &mut sink, outcome);
    }
}

/// Close the run: the session reclaimed (its directory and the lock
/// go with its [`Drop`]), then the stream's exactly-one `Done` — the
/// run's result, whatever it was.
fn finish_run(session: session::Session, id: &str, sink: &mut SignalSink, outcome: Outcome) {
    drop(session);
    sink.event(&Event::Done(Completion {
        session: id.to_string(),
        version: EVENT_STREAM_VERSION,
        outcome,
    }));
}

/// Publish the session id into the claim. The claim is necessarily
/// still alive here: only the worker's guard ever clears it, and it
/// lives past this call.
fn reserve_id(state: &Mutex<Option<Claim>>, id: &str) {
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(claim) = state.as_mut() {
        claim.id = Some(id.to_string());
    }
}

/// The run-to-event bridge: the [`ProgressSink`] the step loop talks
/// to, forwarding every [`Event`] to the service's [`EventEmitter`].
///
/// Delivery failure is *recorded*, never propagated (PLAN §2): a
/// vanished front end must not fail a run whose bytes the device
/// already saw, and the run's final `Done` carries the result
/// regardless. `failed` is the loss record the bus half (5b) surfaces
/// — mirroring `JsonlSink::failed` in `progress.rs`, whose reader
/// decides how to penalise it.
struct SignalSink {
    emitter: Arc<dyn EventEmitter>,
    /// `true` from the first failed delivery on.
    #[allow(dead_code)] // surfaced by 5b's connection instrumentation; the record is the rule
    failed: AtomicBool,
}

impl SignalSink {
    fn new(emitter: Arc<dyn EventEmitter>) -> Self {
        Self {
            emitter,
            failed: AtomicBool::new(false),
        }
    }
}

impl ProgressSink for SignalSink {
    fn event(&mut self, event: &Event) {
        if self.emitter.emit(event).is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
    }
}

/// The pure service layer behind the D-Bus object (S06 part 5a): at
/// most one accepted run, always on its own `furus-session` thread.
///
/// Every method is synchronous and blocking-safe: the bus half (5b)
/// shares a `Registry` across the async [`Helper1`] handlers by way
/// of plain worker threads (see the module docs), never by calling
/// these methods on the runtime itself (pinned `Send + Sync` by the
/// tests below). Nothing here talks to a bus — [`Registry::new`]
/// takes only the seams ([`Authorizer`], [`EventEmitter`]) and the
/// shared facts (sessions root validation env).
pub struct Registry {
    /// Where session directories live (`Session::create`'s parameter,
    /// so unit tests point it at a scratch tempdir instead of the
    /// real root).
    sessions_root: PathBuf,
    /// The validation facts (fixture sysfs/tables in tests, the live
    /// system in the service). Validation runs on the calling
    /// thread, in step 3 of `execute`.
    env: validate::Env,
    authorization: Arc<dyn Authorizer>,
    emitter: Arc<dyn EventEmitter>,
    /// The busy claim, behind an `Arc` so the worker's guard can
    /// release it after `execute` has returned: `Some` exactly while
    /// a run is claimed — from an accepted `execute` to the worker's
    /// last line — except for the refusals `execute` releases itself
    /// (invalid plan, launch failure).
    state: Arc<Mutex<Option<Claim>>>,
    /// How each accepted run executes its plan. `new` wires the real
    /// pipeline; the fixtures select the hermetic stub through
    /// [`Registry::with_runner`].
    runner: Arc<dyn PlanRunner>,
    /// The test pause hook — see [`RunPause`] and `install_run_pause`.
    pause: Mutex<Option<RunPause>>,
}

impl Registry {
    /// A registry over `sessions_root`, validating through `env`,
    /// authorising through `authorization`, streaming events into
    /// `emitter`. No run is claimed yet.
    #[must_use]
    pub fn new(
        sessions_root: PathBuf,
        env: validate::Env,
        authorization: Arc<dyn Authorizer>,
        emitter: Arc<dyn EventEmitter>,
    ) -> Registry {
        // The validation env already knows which sysfs root the
        // device came from; the runner reuses it, so no run
        // re-enumerates the system.
        let sysfs = env.sysfs.clone();
        Self::with_runner(
            sessions_root,
            env,
            authorization,
            emitter,
            Arc::new(RealRunner::new(sysfs)),
        )
    }

    /// The same registry with an explicit runner. Production uses
    /// [`Registry::new`]; tests pass a stub so no fixture needs root
    /// or a real block device. The authorization, claim, session and
    /// `Done` semantics are identical for every runner.
    #[must_use]
    pub fn with_runner(
        sessions_root: PathBuf,
        env: validate::Env,
        authorization: Arc<dyn Authorizer>,
        emitter: Arc<dyn EventEmitter>,
        runner: Arc<dyn PlanRunner>,
    ) -> Registry {
        Registry {
            sessions_root,
            env,
            authorization,
            emitter,
            state: Arc::new(Mutex::new(None)),
            runner,
            pause: Mutex::new(None),
        }
    }

    /// Accept a plan JSON for `caller`, run it on the
    /// `furus-session` thread, and return the session id as soon as
    /// the session exists — **not** when the plan is over (the
    /// outcome arrives through the [`EventEmitter`] as the stream's
    /// final `Done`; that is the point of the service).
    ///
    /// Refusals, in the order they can happen (fail closed):
    /// 1. the [`Authorizer`] denies `caller`, or its check itself
    ///    fails → the action is never granted, and the plan JSON is
    ///    never even read;
    /// 2. a session is running → `Busy` (the claim is one lock
    ///    acquisition: there is no gap between "is one running?" and
    ///    "mine now") — this beats a later parse of the same call;
    /// 3. the plan JSON does not parse, or [`validate::validate`]
    ///    rejects it → `InvalidPlan` carrying the validator's rule
    ///    code (e.g. `confirm_mismatch: …`), with the claim released
    ///    before the error returns.
    ///
    /// A returned `Ok` holds the busy claim until the worker exits.
    /// The one pre-run failure that can still strike after the claim,
    /// the session's own creation error (disk, entropy), surfaces
    /// here instead of as an event, since no session id existed to
    /// stream with (see [`ServiceError::from_session`]).
    pub fn execute(&self, caller: &str, plan_json: &str) -> Result<String, ServiceError> {
        // 1. Authorisation decides first: an unauthorized caller must
        //    learn nothing about the plan — not even its JSON shape.
        match self.authorization.authorize(caller) {
            Ok(true) => {}
            Ok(false) => {
                return Err(ServiceError::not_authorized(device_text(&format!(
                    "the action {POLKIT_ACTION} is not allowed for {caller}"
                ))));
            }
            Err(detail) => {
                return Err(ServiceError::not_authorized(device_text(&format!(
                    "the authorization check for {caller} itself failed: {detail}"
                ))));
            }
        }

        // 2. + 3. Claim the single slot under ONE lock acquisition,
        //    installing this run's fresh `Cancel` at the same breath
        //    (a cancelled leftover of a previous run must never leak
        //    into a new one), then parse/validate with the claim held
        //    — a concurrent `execute` sees `Busy` meanwhile, even
        //    before its own parse runs.
        let (cancel, pause, tx, rx) = {
            let mut state = self.lock_state();
            if state.is_some() {
                return Err(ServiceError::busy(
                    "another session is running; cancel it or wait for it to finish".to_string(),
                ));
            }
            let (tx, rx) = mpsc::channel();
            let claim = Claim {
                cancel: exec::Cancel::new(),
                id: None,
                // The authorisation above succeeded for exactly this
                // caller, so it is the one recorded owner of the run.
                owner: caller.to_string(),
            };
            let cancel = claim.cancel.clone();
            *state = Some(claim);
            let pause = self
                .pause
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            (cancel, pause, tx, rx)
        };

        // 3. Parse and validate synchronously; the claim makes any
        //    concurrent run refuse first.
        let plan = match Self::validated_plan(plan_json, &self.env) {
            Ok(plan) => plan,
            Err(err) => {
                // No worker exists yet: the claim is released here, so
                // the service is idle again before the error returns.
                self.release_claim();
                return Err(err);
            }
        };

        // 4. The worker owns the claim from here: its guard releases
        //    it when the thread's frame ends, unwinding included.
        let worker = WorkerRun {
            state: self.state.clone(),
            root: self.sessions_root.clone(),
            plan,
            cancel,
            emitter: self.emitter.clone(),
            runner: self.runner.clone(),
            tx,
            pause,
        };
        match std::thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || worker.run())
        {
            // The join handle is dropped deliberately: the run is a
            // self-completing unit (its guard, its events, its `Done`),
            // and the claim is the worker's business from now on.
            Ok(_join) => {}
            Err(source) => {
                self.release_claim();
                return Err(ServiceError::internal(
                    "io",
                    device_text(&format!("cannot run the plan in its own thread: {source}")),
                ));
            }
        }

        // The worker publishes the session id right after the session
        // exists (disk metadata only, sub-millisecond): this `recv` is
        // the one wait `execute` makes, so the returned id is exactly
        // the one every event of the run carries.
        match rx.recv() {
            Ok(Opening::Started(session)) => Ok(session),
            Ok(Opening::Failed(code, message)) => Err(ServiceError::from_session(code, message)),
            Err(_disconnected) => Err(ServiceError::internal(
                "io",
                "the furus-session worker ended without reporting its session (a helper bug)"
                    .to_string(),
            )),
        }
    }

    /// Cancel the run named by `session_id` — **for `caller` only**.
    /// The caller recorded at `execute` time is the run's owner: the
    /// session ids under the sessions root are enumerable by every
    /// local user, so a cancel scoped by id alone would hand anyone
    /// the power to abort another user's write. When `caller` does
    /// not match the owner, the refusal is exactly the
    /// unknown-session one below — a foreign caller must not even
    /// learn that the run exists.
    ///
    /// Its first stopping point
    /// — the check before each step of the loop (S06 part 3), and from
    /// S07/S17 the step executors between bytes — reports
    /// [`Outcome::Cancelled`].
    ///
    /// Unknown ids refuse: no session by that id was started (a cancel
    /// racing ahead of `execute`'s own reply included) or it already
    /// finished — the claim then no longer names anything. Blank ids
    /// refuse the same way, with their own sentence, for there is
    /// nothing they could name.
    pub fn cancel(&self, caller: &str, session_id: &str) -> Result<(), ServiceError> {
        let id = session_id.trim();
        if id.is_empty() {
            return Err(ServiceError::unknown_session(
                "no session id was given to cancel".to_string(),
            ));
        }
        let state = self.lock_state();
        if let Some(claim) = state.as_ref()
            && claim.owner == caller
            && claim.id.as_deref() == Some(id)
        {
            claim.cancel.set();
            return Ok(());
        }
        // One refusal for every miss: wrong id, wrong caller, no run
        // at all — the external answer must not distinguish them.
        Err(ServiceError::unknown_session(device_text(&format!(
            "no session {id} is running (it never started or has already finished)"
        ))))
    }

    /// `true` while nothing is claimed: no run accepted, none alive.
    /// Test-only: the bus half has no "idle" property (a client learns
    /// the state from its own session's `Done`).
    #[cfg(test)]
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.lock_state().is_none()
    }

    /// The running session's id, when one has been published. For
    /// tests; a run between its claim and its session is `None` here —
    /// nothing can know that id yet, so nothing may ask.
    #[cfg(test)]
    #[must_use]
    pub fn running(&self) -> Option<String> {
        self.lock_state()
            .as_ref()
            .and_then(|claim| claim.id.clone())
    }

    /// Set the worker's pause hook (test seam — see [`RunPause`]).
    #[cfg(test)]
    pub fn install_run_pause(&self, pause: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.pause.lock().unwrap_or_else(PoisonError::into_inner) = pause;
    }

    /// Whether this process should isolate its mounts before running:
    /// only a privileged helper has mounts worth isolating (the argv
    /// path refuses non-root invocations before any file read), and an
    /// unprivileged process cannot `unshare(CLONE_NEWNS)` at all — the
    /// gate keeps the unprivileged unit runs truthful without touching
    /// the production shape (see the module docs).
    #[must_use]
    fn isolation_wanted() -> bool {
        rustix::process::geteuid().as_raw() == 0
    }

    /// A poison-recovering lock of the claim state. Nothing here
    /// holds a lock across a fallible step, so a poison would need a
    /// helper bug — but recovery beats a panic.
    fn lock_state(&self) -> MutexGuard<'_, Option<Claim>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Release the claim for worlds of `execute` where no worker was
    /// ever spawned (refusals, failed launches).
    fn release_claim(&self) {
        *self.lock_state() = None;
    }

    /// Parse `plan_json` and run the validator; both refusals are the
    /// one `InvalidPlan` class, carrying their rule code in the
    /// message (`device_text` as the belt over the suspenders, like
    /// `validate::reject` composes its messages).
    fn validated_plan(
        plan_json: &str,
        env: &validate::Env,
    ) -> Result<validate::Validated, ServiceError> {
        let plan: furus_proto::Plan = serde_json::from_str(plan_json).map_err(|source| {
            ServiceError::invalid_plan(device_text(&format!(
                "the plan is not valid JSON: {source}"
            )))
        })?;
        validate::validate(&plan, env).map_err(|reject| {
            ServiceError::invalid_plan(device_text(&format!("{}: {}", reject.code, reject.message)))
        })
    }
}

// ---------------------------------------------------------------------
// The bus half (part 5b): the polkit authorizer, the signal emitter and
// the object every front end talks to.
// ---------------------------------------------------------------------

/// The interface name the object exports. Conventionally equal to
/// [`BUS_NAME`], kept separate so a rename of one is a compile-visible
/// decision for the other. The `#[zbus::interface(name = "...")]` literal
/// below is checked against this constant by `xtask contract --check`.
pub const INTERFACE_NAME: &str = service::INTERFACE_NAME;

/// Polkit's authority: a well-known service of its own, never ours.
const POLKIT_SERVICE: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// `AllowUserInteraction`: a caller the policy lets in only after
/// authenticating may be asked to (the S06 action is
/// `auth_admin_keep`, so this is what makes `pkexec`-style prompts
/// possible from the service path).
const POLKIT_FLAG_ALLOW_USER_INTERACTION: u32 = 1;

/// The polkit subject naming the caller: the `(sa{sv})` tuple of
/// `system-bus-name` plus the unique bus name.
///
/// Kept a free function so the wire shape is unit-testable without a
/// bus, which is the only part of a polkit check a test can pin here.
#[must_use]
pub fn polkit_subject(caller: &str) -> zbus::Variant<'static> {
    let mut fields: HashMap<&str, zbus::Variant<'static>> = HashMap::new();
    fields.insert("name", zbus::Variant::from(device_text(caller)));
    zbus::Variant::from(("system-bus-name", fields))
}

/// The verdict of a polkit `CheckAuthorization` reply
/// `(is_authorized, is_challenge, details)`: only an explicit `true`
/// authorises a disk write. This is the gate between a local bus
/// caller and a disk write, so it deliberately reads nothing else —
/// a challenge that was not answered is polkit's business (the S06
/// action is `auth_admin_keep`) and stays a denial, and the details
/// map is advisory text that can never upgrade a `false` into a
/// grant. Kept a free function so the gate is unit-testable without
/// a bus or running polkit.
fn polkit_disk_write_verdict(reply: (bool, bool, HashMap<String, String>)) -> bool {
    let (authorized, _challenge, _details) = reply;
    authorized
}

/// The real [`Authorizer`]: ask polkit's authority whether `caller` may
/// run [`POLKIT_ACTION`] (S06: `auth_admin_keep`).
///
/// **Where it may be called from:** every bus call below is `async`
/// and is driven with [`zbus::block_on`], which panics inside a task
/// the connection's runtime is driving. The sync [`Registry`] path
/// therefore runs this only on plain worker threads (the
/// `furus-session` worker via [`Registry::execute`], itself invoked
/// from the `furus-accept` thread — see [`Helper1::execute`]), never
/// on the object server's own task.
pub struct PolkitAuthorizer {
    connection: zbus::Connection,
}

impl PolkitAuthorizer {
    /// Wrap an already-open (system) bus connection.
    #[must_use]
    pub fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }

    /// The async body of [`Authorizer::authorize`], driven with
    /// [`zbus::block_on`] by the sync trait method below.
    async fn check(&self, caller: &str) -> Result<bool, String> {
        let proxy = zbus::Proxy::new(
            &self.connection,
            POLKIT_SERVICE,
            POLKIT_PATH,
            POLKIT_INTERFACE,
        )
        .await
        .map_err(|err| device_text(&format!("cannot reach polkit: {err}")))?;
        let details: HashMap<&str, &str> = HashMap::new();
        let reply = proxy
            .call_method(
                "CheckAuthorization",
                &(
                    polkit_subject(caller),
                    POLKIT_ACTION,
                    details,
                    POLKIT_FLAG_ALLOW_USER_INTERACTION,
                    "",
                ),
            )
            .await
            .map_err(|err| device_text(&format!("the polkit check failed: {err}")))?;
        // `(is_authorized, is_challenge, details)` — the gate reads
        // only the verdict (see [`polkit_disk_write_verdict`]).
        let reply: (bool, bool, HashMap<String, String>) = reply
            .body()
            .deserialize()
            .map_err(|err| device_text(&format!("cannot read the polkit answer: {err}")))?;
        Ok(polkit_disk_write_verdict(reply))
    }
}

impl Authorizer for PolkitAuthorizer {
    fn authorize(&self, caller: &str) -> Result<bool, String> {
        zbus::block_on(self.check(caller))
    }
}

/// The outcome as the `Done` signal's argument: compact JSON, so a bus
/// consumer needs no typed plan/outcome decoding.
#[must_use]
pub fn outcome_json(outcome: &Outcome) -> String {
    serde_json::to_string(outcome)
        .unwrap_or_else(|_| "{\"outcome\":\"failed\",\"code\":\"json\",\"message\":\"the outcome could not be encoded\"}".to_string())
}

/// The `total` argument's "no known size" sentinel (the D-Bus wire has
/// no `Option<u64>`; see [`progress_args`]).
pub const UNKNOWN_TOTAL: i64 = -1;

/// The `percent` argument's "unknown" sentinel.
pub const UNKNOWN_PERCENT: i16 = -1;

/// The flat argument list of one `Progress` signal, extracted from an
/// [`Progress`] event by [`progress_args`].
struct ProgressArgs {
    session: String,
    step: u32,
    op: String,
    done: u64,
    total: i64,
    percent: i16,
}

/// Collapse a [`Progress`] event onto the flat `Progress` signal
/// argument list (the pure half of [`EventEmitter`]'s `Progress` arm,
/// split out so the mapping is unit-testable without a bus).
///
/// Absent sizes ride the bus as the documented `-1` sentinels
/// (the wire has no `Option<u64>` type, and a separate "known" boolean
/// would be noise). A total too large for the `i64` wire saturates to
/// `i64::MAX` instead of collapsing into the sentinel: an honest huge
/// total must stay positive and distinct from "size unknown".
/// Similarly `step` is a `usize` on the event and a `u32` on the wire;
/// an index beyond that range saturates rather than panicking the
/// worker thread.
fn progress_args(progress: &Progress) -> ProgressArgs {
    ProgressArgs {
        session: device_text(&progress.session),
        step: u32::try_from(progress.step).unwrap_or(u32::MAX),
        op: device_text(&progress.op),
        done: progress.done,
        total: progress.total.map_or(UNKNOWN_TOTAL, |value| {
            i64::try_from(value).unwrap_or(i64::MAX)
        }),
        percent: progress.percent.map_or(UNKNOWN_PERCENT, i16::from),
    }
}

/// The real [`EventEmitter`]: every run event becomes one signal on
/// [`INTERFACE_NAME`] at [`OBJECT_PATH`].
///
/// The emitter is called from the `furus-session` worker thread, never
/// from the object server's task, so driving the async send with
/// [`zbus::block_on`] below is the intended one (see
/// [`PolkitAuthorizer`] for the same rule).
pub struct SignalEmitter {
    connection: zbus::Connection,
}

impl SignalEmitter {
    /// Wrap the connection the object is exported on.
    #[must_use]
    pub fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }

    async fn send_async<B>(&self, signal: &'static str, body: &B) -> Result<(), String>
    where
        B: serde::Serialize + zbus::DynamicType,
    {
        self.connection
            .emit_signal(None::<&str>, OBJECT_PATH, INTERFACE_NAME, signal, body)
            .await
            .map_err(|err| device_text(&format!("cannot emit {signal}: {err}")))
    }

    fn send<B>(&self, signal: &'static str, body: &B) -> Result<(), String>
    where
        B: serde::Serialize + zbus::DynamicType,
    {
        zbus::block_on(self.send_async(signal, body))
    }
}

impl EventEmitter for SignalEmitter {
    fn emit(&self, event: &Event) -> Result<(), String> {
        match event {
            Event::Progress(progress) => {
                // The mapping is pure (see [`progress_args`]); this
                // arm only serialises its result.
                let args = progress_args(progress);
                self.send(
                    "Progress",
                    &(
                        args.session.as_str(),
                        args.step,
                        args.op.as_str(),
                        args.done,
                        args.total,
                        args.percent,
                    ),
                )
            }
            Event::Log(line) => {
                let session = device_text(&line.session);
                let level = line.level.as_str();
                let message = device_text(&line.message);
                self.send("Log", &(session.as_str(), level, message.as_str()))
            }
            Event::Done(completion) => {
                let session = device_text(&completion.session);
                let outcome = outcome_json(&completion.outcome);
                self.send("Done", &(session.as_str(), outcome.as_str()))
            }
        }
    }
}

/// Map a [`ServiceError`] onto a `zbus` error: the authorization class
/// becomes the bus standard `AccessDenied`, everything else `Failed`
/// prefixed with its stable code (`busy: …`) so a client can still
/// branch on it without a custom error type.
#[must_use]
pub fn to_dbus_error(error: &ServiceError) -> zbus::fdo::Error {
    if error.code() == ERROR_NOT_AUTHORIZED {
        return zbus::fdo::Error::AccessDenied(error.to_string());
    }
    zbus::fdo::Error::Failed(device_text(&format!("{}: {error}", error.code())))
}

/// The answer reported when the `furus-accept` worker ends without one
/// (it unwound before [`Handoff::complete`]): the sentence the old
/// channel-disconnect path reported, kept byte-identical so clients see
/// no change.
const WORKER_NO_ANSWER_MESSAGE: &str = "the helper thread ended without an answer";

/// Map the `furus-accept` worker's outcome onto the bus answer: a
/// returned session id passes through, a returned [`ServiceError`]
/// becomes its D-Bus error (see [`to_dbus_error`]), and an unwound
/// worker becomes the [`WORKER_NO_ANSWER_MESSAGE`] failure.
fn worker_answer(
    outcome: std::thread::Result<Result<String, ServiceError>>,
) -> zbus::fdo::Result<String> {
    match outcome {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => Err(to_dbus_error(&error)),
        Err(_) => Err(zbus::fdo::Error::Failed(
            WORKER_NO_ANSWER_MESSAGE.to_string(),
        )),
    }
}

/// The exported object: `org.furuslinux.Helper1`.
///
/// `Execute` blocks its caller for as long as authorization (a polkit
/// prompt may wait on a human) plus validation (the image is hashed)
/// take; the *run* itself never blocks it — `Execute` returns the
/// session id as soon as the session exists. Method calls may run
/// concurrently (`Interface::spawn_tasks_for_methods` defaults to true,
/// as in zbus 5.19), so a `Cancel` arriving while `Execute` is still
/// authorizing finds no claim yet, and one arriving after the claim but
/// before the worker publishes the id finds `Claim::id` still `None`;
/// [`Registry::cancel`] refuses both as `UnknownSession` — it only sets
/// the flag when the claim's owner and published id both match (see
/// [`Registry::execute`]'s claim-then-`Opening::Started` order) — so a
/// caller must wait for `Execute`'s session-id reply before cancelling.
///
/// Both methods are `async` (zbus 6 has no sync dispatch): `execute`
/// hands the sync accept path to a short-lived `furus-accept` thread
/// and awaits its [`Handoff`], so the runtime task never blocks;
/// `cancel` runs inline, touching only the in-memory claim lock.
pub struct Helper1 {
    registry: Arc<Registry>,
}

impl Helper1 {
    /// Wrap the service registry.
    #[must_use]
    pub fn new(registry: Arc<Registry>) -> Self {
        Self { registry }
    }
}

/// A one-shot handoff from a plain worker thread to an async service
/// method: the thread publishes its answer with [`Handoff::complete`],
/// the method awaits it with [`Handoff::wait`], parking its task on
/// the stored waker instead of blocking the runtime thread.
///
/// The parked wait is what keeps [`Helper1::execute`] deadlock-free:
/// the `furus-accept` thread drives its polkit bus calls with
/// [`zbus::block_on`] on its own thread, while the runtime task
/// sleeps until woken — neither side ever waits on the other holding
/// the runtime. Lock poisoning is recovered like
/// [`Registry::lock_state`]: a poisoned lock still yields its value
/// rather than panicking the service.
struct Handoff<T> {
    /// The worker's answer once published.
    slot: Mutex<Option<T>>,
    /// The parked task's waker, registered while waiting.
    waker: Mutex<Option<std::task::Waker>>,
}

impl<T> Handoff<T> {
    /// An empty handoff, awaiting its worker's answer.
    fn new() -> Self {
        Self {
            slot: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// Publish the worker's answer and wake the parked task, if any.
    /// In builds that unwind (dev and test, where the tests run), a
    /// worker that unwound never reaches this: `execute`'s
    /// `catch_unwind` answers for it, so every waiter wakes. The
    /// release profile sets `panic = "abort"` (see the workspace
    /// `Cargo.toml`), so a panicking worker in the shipped helper
    /// aborts the service exactly as before — no containment beyond
    /// unwinding builds is claimed here.
    fn complete(&self, value: T) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
        if let Some(waker) = self
            .waker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            waker.wake();
        }
    }

    /// The waiter's poll: the answer if published, else park with the
    /// current waker registered. The slot is re-checked after
    /// registering, so an answer racing the registration is never
    /// missed (the worker's `complete` either finds the waker or lands
    /// before the re-check).
    fn poll(&self, context: &mut std::task::Context<'_>) -> std::task::Poll<T> {
        if let Some(value) = self
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            return std::task::Poll::Ready(value);
        }
        *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = Some(context.waker().clone());
        match self
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            Some(value) => {
                *self.waker.lock().unwrap_or_else(PoisonError::into_inner) = None;
                std::task::Poll::Ready(value)
            }
            None => std::task::Poll::Pending,
        }
    }

    /// Wait for the worker's answer without blocking the calling
    /// runtime thread.
    async fn wait(&self) -> T {
        std::future::poll_fn(|context| self.poll(context)).await
    }
}

#[zbus::interface(name = "org.furuslinux.Helper1")]
impl Helper1 {
    /// Authorize the caller, then start a plan; replies with the
    /// session id.
    async fn execute(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        plan_json: String,
    ) -> zbus::fdo::Result<String> {
        let Some(caller) = header.sender() else {
            return Err(zbus::fdo::Error::AccessDenied(
                "the call carries no sender to authorize".to_string(),
            ));
        };
        let caller = caller.to_string();
        // The check may prompt, and its bus calls run under
        // `block_on` — which must not run on the object server's task
        // (see `PolkitAuthorizer`). Hand the whole sync accept path to
        // a plain thread and await its handoff instead of blocking.
        let registry = Arc::clone(&self.registry);
        let handoff = Arc::new(Handoff::new());
        let worker = Arc::clone(&handoff);
        std::thread::Builder::new()
            .name(ACCEPT_THREAD_NAME.to_string())
            .spawn(move || {
                // In builds that unwind (dev and test), a worker that
                // unwound still owes the waiter an answer: without
                // this, the `Handoff` would park the task forever. The
                // sentence stays the one the old channel-disconnect
                // path reported (see `WORKER_NO_ANSWER_MESSAGE`). In the
                // release profile (`panic = "abort"`) a panicking worker
                // aborts the service instead, exactly as before.
                let answer = worker_answer(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || registry.execute(&caller, &plan_json),
                )));
                worker.complete(answer);
            })
            .map_err(|err| {
                zbus::fdo::Error::Failed(device_text(&format!("cannot start a worker: {err}")))
            })?;
        handoff.wait().await
    }

    /// Ask the run named by `session_id` to stop. Only the connection
    /// that started the run may stop it (the sender recorded at
    /// `execute` time; see [`Registry::cancel`]).
    ///
    /// Inline on the runtime task on purpose: cancelling only takes
    /// the claim lock and sets a flag — no bus I/O, no `block_on`, so
    /// no thread is needed.
    async fn cancel(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        session_id: String,
    ) -> zbus::fdo::Result<()> {
        // The same no-sender rule as `execute`: without a sender there
        // is no identity that could own a run, so the call is not
        // authored at all.
        let Some(caller) = header.sender() else {
            return Err(zbus::fdo::Error::AccessDenied(
                "the call carries no sender to authorize".to_string(),
            ));
        };
        self.registry
            .cancel(&caller.to_string(), &session_id)
            .map_err(|error| to_dbus_error(&error))
    }

    /// One step's progress, as the worker reports it.
    #[zbus(signal)]
    async fn progress(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        session: &str,
        step: u32,
        op: &str,
        done: u64,
        total: i64,
        percent: i16,
    ) -> zbus::Result<()>;

    /// One log line of the running plan.
    #[zbus(signal)]
    async fn log(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        session: &str,
        level: &str,
        message: &str,
    ) -> zbus::Result<()>;

    /// The run's single terminal event; `outcome_json` is
    /// [`outcome_json`]'s compact form.
    #[zbus(signal)]
    async fn done(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        session: &str,
        outcome_json: &str,
    ) -> zbus::Result<()>;
}

/// Name of the short-lived thread `Execute` waits on (pinned for
/// reporting; it lives for one accept).
const ACCEPT_THREAD_NAME: &str = "furus-accept";

#[cfg(test)]
#[path = "dbus_tests.rs"]
mod tests;
