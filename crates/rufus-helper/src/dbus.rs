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
//!   `std::thread`s (the `rufus-session` worker, or the short-lived
//!   `rufus-accept` thread below) — never on the connection's own
//!   runtime. The never half is measured, not assumed: calling
//!   `zbus::block_on` from a task the runtime drives panics instead of
//!   hanging — on zbus 6.2.0 with zruntime 0.2.2 the panic (at
//!   `zruntime-0.2.2/src/driver.rs:797:9`) reads `block_on called from
//!   a task this runtime is running: the call would wait for the very
//!   thread it is on` — so a misplaced call fails fast instead of
//!   wedging the service silently.
//! * The exported [`Helper1`] methods are `async`, so they run on the
//!   runtime. `execute` therefore never calls the sync registry
//!   directly: it hands the whole accept path to a `rufus-accept`
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
//!    │ 4. spawn the `rufus-session` thread               │ worker sees it
//!    │    ↕ the worker creates the session and publishes its id
//!    │                                                   │ before its first
//!    │                                                   │ step and warns
//!    ├──► return Ok(session_id)   — the plan keeps running on the thread
//! ```
//!
//! The run itself follows the argv pipeline one step per worker:
//! [`session::Session::create`] (session id + directory) →
//! [`namespace::enter_mount_namespace`] → [`exec::run_plan`] with
//! [`exec::CurrentExecutor`], every [`Event`] forwarded through the
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
//! non-root run that got here could still write nothing (the plan
//! rules stand, executors refuse), and 5b's service starts as root
//! exactly like `main`'s argv path.

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

use rufus_core::error::CoreError;
use rufus_core::text::device_text;
use rufus_proto::Completion;
use rufus_proto::EVENT_STREAM_VERSION;
use rufus_proto::Event;
use rufus_proto::Outcome;
use rufus_proto::Progress;

use crate::exec;
use crate::namespace;
use crate::progress::ProgressSink;
use crate::session;
use crate::validate;

/// The well-known bus name part 5b requests for the helper service.
pub const BUS_NAME: &str = "org.rufuslinux.Helper1";

/// The object path carrying the helper interface (part 5b).
pub const OBJECT_PATH: &str = "/org/rufuslinux/Helper1";

/// The polkit action a caller must hold to run a plan (fail closed:
/// [`Registry::execute`] asks [`Authorizer`] before it looks at a
/// plan).
pub const POLKIT_ACTION: &str = "org.rufuslinux.write-device";

/// D-Bus error name of an authorization that denied a caller, or whose
/// check itself failed — the name [`ServiceError::code`] maps.
pub const ERROR_NOT_AUTHORIZED: &str = "org.rufuslinux.Error.NotAuthorized";

/// D-Bus error name of a refused request while another session runs.
pub const ERROR_BUSY: &str = "org.rufuslinux.Error.Busy";

/// D-Bus error name of a `Cancel` naming nothing running.
pub const ERROR_UNKNOWN_SESSION: &str = "org.rufuslinux.Error.UnknownSession";

/// D-Bus error name of a plan that failed to parse or to validate.
pub const ERROR_INVALID_PLAN: &str = "org.rufuslinux.Error.InvalidPlan";

/// Name of the worker thread one accepted run executes on (pinned for
/// `top`/reporting; the worker shares no state with the bus except
/// through [`Registry`]'s own locks).
const WORKER_THREAD_NAME: &str = "rufus-session";

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
/// deterministic point — the S06 placeholder executor finishes every
/// step in microseconds, and a real mid-step pause belongs to
/// S07/S17's step executors honouring the `ctx.cancel` flag.
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
    /// The sessions root (`/run/rufus-linux` in the service — see
    /// [`session::SESSION_ROOT`]; unit tests pass a scratch tempdir).
    root: PathBuf,
    /// The validated run: plan (confirm intact), device, verdict
    /// input.
    plan: validate::Validated,
    /// The claim's cancel flag (sharing state with the slot on
    /// purpose: one flag per run).
    cancel: exec::Cancel,
    emitter: Arc<dyn EventEmitter>,
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

        // The step loop (S06 part 3) with the placeholder executor:
        // every step but `Finalize` refuses until S07/S17 arrive,
        // which is the honest state of this build.
        let mut executor = exec::CurrentExecutor;
        let outcome = exec::run_plan(
            &plan.plan,
            &plan.device,
            &mut executor,
            &mut sink,
            &cancel,
            &id,
        );
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
/// most one accepted run, always on its own `rufus-session` thread.
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
        Registry {
            sessions_root,
            env,
            authorization,
            emitter,
            state: Arc::new(Mutex::new(None)),
            pause: Mutex::new(None),
        }
    }

    /// Accept a plan JSON for `caller`, run it on the
    /// `rufus-session` thread, and return the session id as soon as
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
                "the rufus-session worker ended without reporting its session (a helper bug)"
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
        let plan: rufus_proto::Plan = serde_json::from_str(plan_json).map_err(|source| {
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
/// decision for the other.
pub const INTERFACE_NAME: &str = "org.rufuslinux.Helper1";

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
/// `rufus-session` worker via [`Registry::execute`], itself invoked
/// from the `rufus-accept` thread — see [`Helper1::execute`]), never
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
/// The emitter is called from the `rufus-session` worker thread, never
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

/// The answer reported when the `rufus-accept` worker ends without one
/// (it unwound before [`Handoff::complete`]): the sentence the old
/// channel-disconnect path reported, kept byte-identical so clients see
/// no change.
const WORKER_NO_ANSWER_MESSAGE: &str = "the helper thread ended without an answer";

/// Map the `rufus-accept` worker's outcome onto the bus answer: a
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

/// The exported object: `org.rufuslinux.Helper1`.
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
/// hands the sync accept path to a short-lived `rufus-accept` thread
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
/// the `rufus-accept` thread drives its polkit bus calls with
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

#[zbus::interface(name = "org.rufuslinux.Helper1")]
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
const ACCEPT_THREAD_NAME: &str = "rufus-accept";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::Mutex;
    use std::sync::PoisonError;
    use std::time::Duration;

    use rufus_core::hash::hash_file;
    use rufus_linux::SysfsRoot;
    use rufus_proto::DeviceRef;
    use rufus_proto::Event;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::PLAN_VERSION;
    use rufus_proto::Plan;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target as Firmware;

    use crate::validate;

    use super::Authorizer;
    use super::BUS_NAME;
    use super::ERROR_BUSY;
    use super::ERROR_INVALID_PLAN;
    use super::ERROR_NOT_AUTHORIZED;
    use super::ERROR_UNKNOWN_SESSION;
    use super::EVENT_STREAM_VERSION;
    use super::EventEmitter;
    use super::Handoff;
    use super::OBJECT_PATH;
    use super::POLKIT_ACTION;
    use super::Registry;
    use super::ServiceError;
    use super::UNKNOWN_PERCENT;
    use super::UNKNOWN_TOTAL;
    use super::outcome_json;
    use super::polkit_disk_write_verdict;
    use super::polkit_subject;
    use super::progress_args;
    use super::to_dbus_error;

    // ----------------------------------------------------------------------
    // Part 5b: the wire shapes a bus half must not drift from.
    // ----------------------------------------------------------------------

    #[test]
    fn polkit_subject_carries_the_caller_as_a_system_bus_name() {
        let subject = polkit_subject(":1.42");
        assert_eq!(subject.value_signature().to_string(), "(sa{sv})");
        let printed = format!("{subject:?}");
        assert!(printed.contains("system-bus-name"), "{printed}");
        assert!(printed.contains(":1.42"), "{printed}");
    }

    #[test]
    fn outcome_json_pins_all_four_outcomes() {
        assert_eq!(outcome_json(&super::Outcome::Ok), r#"{"outcome":"ok"}"#);
        assert_eq!(
            outcome_json(&super::Outcome::Cancelled),
            r#"{"outcome":"cancelled"}"#
        );
        assert_eq!(
            outcome_json(&super::Outcome::Refused {
                code: "mounted".to_string(),
                message: "device is mounted at /media/x".to_string(),
            }),
            r#"{"outcome":"refused","code":"mounted","message":"device is mounted at /media/x"}"#
        );
        assert_eq!(
            outcome_json(&super::Outcome::Failed {
                code: "io".to_string(),
                message: "boom".to_string(),
            }),
            r#"{"outcome":"failed","code":"io","message":"boom"}"#
        );
    }

    #[test]
    fn dbus_error_mapping_keeps_authorization_denials_distinct() {
        let denied = to_dbus_error(&ServiceError::not_authorized("nope".to_string()));
        assert!(
            matches!(&denied, zbus::fdo::Error::AccessDenied(message) if message == "nope"),
            "{denied:?}"
        );
        let busy = to_dbus_error(&ServiceError::busy("one at a time".to_string()));
        assert!(
            matches!(&busy, zbus::fdo::Error::Failed(message) if message == "org.rufuslinux.Error.Busy: one at a time"),
            "{busy:?}"
        );
        let invalid = to_dbus_error(&ServiceError::invalid_plan(
            "confirm_mismatch: x".to_string(),
        ));
        assert!(
            matches!(&invalid, zbus::fdo::Error::Failed(message) if message.starts_with("org.rufuslinux.Error.InvalidPlan: confirm_mismatch")),
            "{invalid:?}"
        );
    }

    // -- the polkit verdict: the gate between a local bus caller and
    //    a disk write -----------------------------------------------------

    #[test]
    fn polkit_disk_write_verdict_pins_the_grant_table() {
        // The rule, and nothing more: only an explicit `true` in the
        // first field authorises a write. The challenge flag stays
        // read-only for the verdict (a prompt nobody answered is
        // polkit's `auth_admin_keep` business) and the details map can
        // never upgrade a `false` into a grant.
        let answered: HashMap<String, String> = HashMap::from([(
            "polkitDetails".to_string(),
            "present-but-advisory".to_string(),
        )]);
        assert!(
            polkit_disk_write_verdict((true, false, HashMap::new())),
            "an explicit yes authorises"
        );
        assert!(
            polkit_disk_write_verdict((true, true, answered.clone())),
            "the challenge flag must not veto a granted verdict"
        );
        assert!(
            !polkit_disk_write_verdict((false, false, HashMap::new())),
            "a plain no denies"
        );
        assert!(
            !polkit_disk_write_verdict((false, true, answered.clone())),
            "a no stays a no with a challenge and non-empty details"
        );
    }

    // -- the Progress signal mapping (the pure half of the emitter) --------

    #[test]
    fn progress_args_pass_know_sizes_through_unchanged() {
        let progress = rufus_proto::Progress::new(":1.7", 3, "write", 10, Some(10));
        let args = progress_args(&progress);
        assert_eq!(args.session, ":1.7", "unique bus names are already ASCII");
        assert_eq!(args.step, 3);
        assert_eq!(args.op, "write");
        assert_eq!(args.done, 10);
        assert_eq!(args.total, 10, "a known total rides the wire as itself");
        assert_eq!(args.percent, 100, "the derived percent rides verbatim");
    }

    #[test]
    fn progress_args_maps_absent_sizes_to_the_negative_one_sentinels() {
        let progress = rufus_proto::Progress::new(":1.7", 0, "wipe", 0, None);
        let args = progress_args(&progress);
        assert_eq!(args.total, UNKNOWN_TOTAL);
        assert_eq!(args.percent, UNKNOWN_PERCENT);
    }

    #[test]
    fn progress_args_saturates_a_u64_max_total_instead_of_collapsing_it() {
        let progress = rufus_proto::Progress::new(":1.7", 0, "write", 0, Some(u64::MAX));
        let args = progress_args(&progress);
        assert!(
            args.total > 0,
            "an honest huge total must not read as the unknown sentinel"
        );
        assert_ne!(args.total, UNKNOWN_TOTAL);
        assert_eq!(args.total, i64::MAX, "the saturation target is i64::MAX");
    }

    #[test]
    fn progress_args_saturates_a_step_beyond_u32_instead_of_panicking() {
        // The "a usize-wide plan no real device list can produce" case
        // (see `progress_args`): saturation, no panic, no wrap.
        let progress = rufus_proto::Progress::new(":1.7", u32::MAX as usize + 1, "wipe", 0, None);
        let args = progress_args(&progress);
        assert_eq!(args.step, u32::MAX);
    }

    // ----------------------------------------------------------------------
    // Fakes: a fixed authoriser and an in-memory emitter (the bus half's
    // polkit/signal seams). Their shape mirrors `progress::VecSink`, which
    // serves the same role on the argv path but through the ProgressSink
    // seam — the event stream itself is identical.
    // ----------------------------------------------------------------------

    struct FixedAuthorizer(bool);

    impl Authorizer for FixedAuthorizer {
        fn authorize(&self, _caller: &str) -> Result<bool, String> {
            Ok(self.0)
        }
    }

    /// An authoriser whose check cannot be made (transient "the check
    /// itself failed"); `execute` must fail closed on it.
    struct FailingAuthorizer(&'static str);

    impl Authorizer for FailingAuthorizer {
        fn authorize(&self, _caller: &str) -> Result<bool, String> {
            Err(self.0.to_string())
        }
    }

    #[derive(Clone)]
    struct VecEmitter {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl VecEmitter {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn snapshot(&self) -> Vec<Event> {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn completions(&self) -> Vec<rufus_proto::Completion> {
            self.snapshot()
                .into_iter()
                .filter_map(|event| match event {
                    Event::Done(completion) => Some(completion),
                    _ => None,
                })
                .collect()
        }
    }

    impl EventEmitter for VecEmitter {
        fn emit(&self, event: &Event) -> Result<(), String> {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event.clone());
            Ok(())
        }
    }

    // ----------------------------------------------------------------------
    // Bounded drain helpers: the worker outlives its `execute`, so every
    // follow-up assertion waits on a predicate with a hard deadline
    // instead of sleeping blind.
    // ----------------------------------------------------------------------

    const WAIT_STEP: Duration = Duration::from_millis(10);
    const WAIT_STEPS: u32 = 500; // 5 s in 10 ms increments

    fn wait_until(what: &str, check: impl Fn() -> bool) {
        for _ in 0..WAIT_STEPS {
            if check() {
                return;
            }
            std::thread::sleep(WAIT_STEP);
        }
        panic!("{what} never happened within 5 s");
    }

    /// All the stream's `Done` events so far, waiting for at least one.
    fn wait_completions(emitter: &VecEmitter) -> Vec<rufus_proto::Completion> {
        wait_until("an event Done", || !emitter.completions().is_empty());
        emitter.completions()
    }

    fn wait_idle(registry: &Registry) {
        wait_until("the service going idle", || registry.is_idle());
    }

    // ----------------------------------------------------------------------
    // Registry assembly: a scratch tempdir as the sessions root (never
    // /run/rufus-linux), the fixture env, and the caller's authoriser.
    // ----------------------------------------------------------------------

    fn registry_with(
        env: validate::Env,
        authorization: Arc<dyn Authorizer>,
        sessions: &tempfile::TempDir,
    ) -> (Registry, VecEmitter) {
        let emitter = VecEmitter::new();
        let registry = Registry::new(
            sessions.path().to_path_buf(),
            env,
            authorization,
            Arc::new(emitter.clone()),
        );
        (registry, emitter)
    }

    fn execute_json(plan: &Plan) -> String {
        serde_json::to_string(plan).expect("a test-built plan serialises")
    }

    // ----------------------------------------------------------------------
    // Fixtures: a copied subset of `validate::tests::Fixture` — that
    // module is private, so its helpers are unreachable from here; the
    // same seed shape (synthetic sysfs stick, sparse device stand-in,
    // sparse image, signed plan) is required to make `validate` accept
    // a plan hermetically. Uses no root and no real device.
    // ----------------------------------------------------------------------

    /// The device-tree chain every seeded stick links in at.
    const STICK_CHAIN: &str = "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0";
    /// The whole disk's kernel name (and the plan's `/dev/<name>`).
    const NAME: &str = "sdb";
    const DISK_DEVNUM: &str = "8:16";
    const PART_DEVNUM: &str = "8:17";
    /// sysfs `size` is in 512-byte units regardless of media geometry.
    const SECTOR: u64 = 512;
    const STICK_UNITS: u64 = 8192; // 4 MiB of synthetic stick
    const STICK_BYTES: u64 = STICK_UNITS * SECTOR;
    /// The image the samples describe: 1.5 MiB, well inside the stick.
    const IMAGE_LEN: u64 = 1_572_864;
    /// The stick fixture's serial (rides into show-all tests).
    const SERIAL: &str = "SER123";

    struct Fixture {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Self {
                _scratch: scratch,
                root,
            }
        }

        fn write_text(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent directories");
            }
            fs::write(&path, content).unwrap_or_else(|err| panic!("seed {rel}: {err}"));
            path
        }

        fn symlink(&self, target: &Path, link: &str) {
            if let Some(parent) = self.root.join(link).parent() {
                fs::create_dir_all(parent).unwrap_or_else(|err| panic!("link dirs: {err}"));
            }
            let link_path = self.root.join(link);
            if let Ok(meta) = std::fs::symlink_metadata(&link_path) {
                assert!(
                    meta.file_type().is_symlink(),
                    "refusing to overwrite a real file at {link}"
                );
                std::fs::remove_file(&link_path)
                    .unwrap_or_else(|err| panic!("drop stale link {link}: {err}"));
            }
            std::os::unix::fs::symlink(target, &link_path)
                .unwrap_or_else(|err| panic!("link {link}: {err}"));
        }

        /// A sparse stand-in or image file: `len` zero bytes on disk.
        fn sparse(&self, rel: &str, len: u64) -> PathBuf {
            let path = self.root.join(rel);
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("sparse {rel}: {err}"));
            file.set_len(len)
                .unwrap_or_else(|err| panic!("length {rel}: {err}"));
            path
        }

        /// Seed the synthetic stick exactly like live sysfs: the S04
        /// chain (`devices/<chain>/block/<name>`), device identity on
        /// the four-up USB node, and class/block sibling links whose
        /// partitions carry the `partition` attribute.
        fn seed_stick(&self, removable: bool) {
            let real = format!("{STICK_CHAIN}/block/{NAME}");
            self.write_text(&format!("{real}/size"), &STICK_UNITS.to_string());
            self.write_text(
                &format!("{real}/removable"),
                if removable { "1" } else { "0" },
            );
            self.write_text(&format!("{real}/ro"), "0");
            self.write_text(&format!("{real}/dev"), DISK_DEVNUM);
            self.write_text(&format!("{STICK_CHAIN}/vendor"), "SanDisk");
            self.write_text(&format!("{STICK_CHAIN}/model"), "Test Stick");
            self.write_text(&format!("{STICK_CHAIN}/serial"), SERIAL);
            let part = format!("{real}/{NAME}1");
            self.write_text(&format!("{part}/size"), "6144");
            self.write_text(&format!("{part}/dev"), PART_DEVNUM);
            self.write_text(&format!("{part}/partition"), "1");

            self.symlink(&self.root.join(STICK_CHAIN), &format!("{real}/device"));
            self.symlink(&self.root.join(&real), &format!("class/block/{NAME}"));
            self.symlink(&self.root.join(&part), &format!("class/block/{NAME}1"));
        }

        /// A mountinfo file carrying one extra foreign line (never the
        /// fixture's own devnums, so the seeded stick is unmounted).
        fn foreign_mountinfo(&self) -> PathBuf {
            self.write_text(
                "mountinfo.tsv",
                "1 0 252:0 / / rw,relatime - ext4 /dev/simroot rw\n",
            )
        }

        /// A `/proc/swaps` file with the header row and nothing on it.
        fn empty_swaps(&self) -> PathBuf {
            self.write_text("swaps.tsv", "Filename Type Size Used Priority\n")
        }

        /// The full test window for `validate`: fixture sysfs, fixture
        /// tables and the regular-file stand-in that plays the device
        /// node (`Env::device_file`).
        fn env(&self, stand_in: &Path) -> validate::Env {
            validate::Env {
                sysfs: SysfsRoot::new(self.root.clone()),
                mountinfo: Some(self.foreign_mountinfo()),
                swaps: Some(self.empty_swaps()),
                device_file: Some(stand_in.to_path_buf()),
            }
        }

        /// A plan for the seeded stick (the canonical good-path steps
        /// of the CLI plan, starting with a `Wipe`).
        fn plan_for(&self, image: &Path, image_len: u64, sha: &str) -> Plan {
            Plan {
                version: PLAN_VERSION,
                created_by: "rufus-helper tests".to_string(),
                device: DeviceRef {
                    path: format!("/dev/{NAME}"),
                    block_device: true,
                    size_bytes: Some(STICK_BYTES),
                    serial: Some(SERIAL.to_string()),
                    model: Some("Test Stick".to_string()),
                    sysfs: Some(format!("/sys/class/block/{NAME}")),
                },
                image: ImageRef {
                    path: image.display().to_string(),
                    size_bytes: image_len,
                    sha256: sha.to_string(),
                    kind: ImageKind::Raw,
                },
                options: Options {
                    scheme: Scheme::Mbr,
                    target: Firmware::Uefi,
                    filesystem: Filesystem::Fat32,
                    label: Some("RUFUS".to_string()),
                    cluster_bytes: Some(32768),
                    quick_format: true,
                    bad_blocks: false,
                    verify: false,
                    persistence: false,
                    show_all: false,
                    confirmed_serial: None,
                },
                steps: vec![
                    Step::Wipe,
                    Step::Mklabel {
                        scheme: Scheme::Mbr,
                    },
                    Step::Mkpart {
                        scheme: Scheme::Mbr,
                        layout: rufus_proto::Layout::Single,
                    },
                    Step::Mkfs {
                        filesystem: Filesystem::Fat32,
                        label: Some("RUFUS".to_string()),
                        cluster_bytes: Some(32768),
                        quick: true,
                    },
                    Step::Write {
                        mode: rufus_proto::WriteMode::Dd,
                    },
                    Step::Bootloader {
                        mode: rufus_proto::BootloaderMode::Auto,
                    },
                    Step::Finalize,
                ],
                confirm: String::new(),
            }
        }

        /// Sparse image of `len` zero bytes plus its SHA-256.
        fn image(&self, rel: &str, len: u64) -> (PathBuf, String) {
            let path = self.sparse(rel, len);
            let sha = hash_file(&path).expect("image hashes");
            (path, sha)
        }

        /// The canonical good case: a clean removable stick, blank
        /// device bytes, an image the plan describes exactly.
        fn good(&self, removable: bool) -> (Plan, validate::Env, PathBuf) {
            self.seed_stick(removable);
            let device = self.sparse("device.img", STICK_BYTES);
            let (image, sha) = self.image("image.img", IMAGE_LEN);
            let plan = signed(self.plan_for(&image, IMAGE_LEN, &sha));
            let env = self.env(&device);
            (plan, env, device)
        }
    }

    /// A plan whose confirm hash is freshly recomputed from its own
    /// contents (the CLI's contract).
    fn signed(mut plan: Plan) -> Plan {
        plan.confirm = plan
            .confirm()
            .expect("tests build JSON-native plans that always serialise");
        plan
    }

    /// The good plan pared to a single `Finalize`: the only shape the
    /// placeholder executor runs to `Ok`.
    fn finalize_only(mut plan: Plan) -> Plan {
        plan.steps = vec![Step::Finalize];
        signed(plan)
    }

    // -- pinned machine-facing strings -----------------------------------

    #[test]
    fn wire_names_are_pinned_for_the_bus_half() {
        assert_eq!(BUS_NAME, "org.rufuslinux.Helper1");
        assert_eq!(OBJECT_PATH, "/org/rufuslinux/Helper1");
        assert_eq!(POLKIT_ACTION, "org.rufuslinux.write-device");
        assert_eq!(ERROR_NOT_AUTHORIZED, "org.rufuslinux.Error.NotAuthorized");
        assert_eq!(ERROR_BUSY, "org.rufuslinux.Error.Busy");
        assert_eq!(ERROR_UNKNOWN_SESSION, "org.rufuslinux.Error.UnknownSession");
        assert_eq!(ERROR_INVALID_PLAN, "org.rufuslinux.Error.InvalidPlan");
        // CARGO-LOCKED: the stream version the `Done` events must carry.
        assert_eq!(EVENT_STREAM_VERSION, 1);
    }

    // -- authorisation ---------------------------------------------------

    #[test]
    fn denied_authorization_runs_nothing_and_leaves_the_service_idle() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(false)), &sessions);

        let refused = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect_err("an unauthorized caller is refused");
        assert_eq!(refused.code(), ERROR_NOT_AUTHORIZED);
        assert!(
            refused.to_string().contains(POLKIT_ACTION),
            "the message names the missing action: {refused}"
        );
        assert!(registry.is_idle(), "a refused caller holds no claim");
        assert_eq!(
            fs::read_dir(sessions.path())
                .expect("the sessions root exists (tempdir made it)")
                .count(),
            0,
            "an unauthorized caller's plan never reached the sessions root"
        );
    }

    #[test]
    fn a_failing_authorizer_check_fails_closed() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, _emitter) = registry_with(
            env,
            Arc::new(FailingAuthorizer("the audit bus refused to answer")),
            &sessions,
        );

        let refused = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect_err("a failed check is never a grant");
        assert_eq!(refused.code(), ERROR_NOT_AUTHORIZED);
        let message = refused.to_string();
        assert!(
            message.contains("itself failed"),
            "the message says the check failed: {message}"
        );
        assert!(
            message.contains("the audit bus refused to answer"),
            "the check's own detail is reported: {message}"
        );
        assert_eq!(
            fs::read_dir(sessions.path())
                .expect("the sessions root exists (tempdir made it)")
                .count(),
            0,
            "the fail-closed refusal never touched the sessions root"
        );
        assert!(registry.is_idle(), "the fail-closed refusal holds no claim");
    }

    // -- the busy claim --------------------------------------------------

    #[test]
    fn a_running_session_keeps_the_service_busy() {
        let fixture = Fixture::new();
        let (good, _env, _) = fixture.good(true);
        let plan = finalize_only(good);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, emitter) = registry_with(_env, Arc::new(FixedAuthorizer(true)), &sessions);

        // Park the worker between "session exists" and "plan starts": the
        // claim is provably held while the test calls again (see
        // `install_run_pause`; the placeholder executor would finish a
        // Finalize-only run in microseconds, with no real pause).
        let barrier = Arc::new(Barrier::new(2));
        let parked = barrier.clone();
        registry.install_run_pause(Some(Arc::new(move || {
            parked.wait();
        })));

        let first = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("the first run claims the service");
        assert!(
            registry.running().as_deref() == Some(first.as_str()),
            "the parked run's claim names its session id"
        );
        assert!(!registry.is_idle());

        let second = registry
            .execute("com.example.gui", "{}")
            .expect_err("a claimed service refuses a second run");
        assert_eq!(second.code(), ERROR_BUSY);
        assert!(
            second.to_string().contains("another session"),
            "the message names the condition: {second}"
        );

        // Release the worker; the Finalize-only plan then runs to `Ok`
        // (never declined, never cancelled) and frees its claim.
        barrier.wait();
        wait_idle(&registry);
        assert_eq!(registry.running(), None);

        let completions = wait_completions(&emitter);
        assert_eq!(completions.len(), 1, "exactly one terminal event");
        assert_eq!(completions[0].session, first, "the id is echoed");
        assert_eq!(completions[0].outcome, rufus_proto::Outcome::Ok);
    }

    // -- plan refusals -----------------------------------------------------

    #[test]
    fn malformed_plan_json_refuses_and_leaves_the_service_idle() {
        let fixture = Fixture::new();
        let (_plan, env, _device) = fixture.good(true);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let refused = registry
            .execute("com.example.gui", "{oops")
            .expect_err("rot JSON refuses");
        assert_eq!(refused.code(), ERROR_INVALID_PLAN);
        assert!(
            refused.to_string().contains("not valid JSON"),
            "the message says what is wrong: {refused}"
        );
        assert!(
            registry.is_idle(),
            "the claim is released before the error returns"
        );
    }

    #[test]
    fn a_tampered_confirm_refuses_naming_the_validator_code() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.confirm = format!("sha256:{}", "0".repeat(64)); // any tamper the recompute maths
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let refused = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect_err("an integrity refusal is the service's InvalidPlan");
        assert_eq!(refused.code(), ERROR_INVALID_PLAN);
        assert!(
            refused.to_string().contains("confirm_mismatch"),
            "the validator's rule code is carried in the message: {refused}"
        );
        assert!(
            registry.is_idle(),
            "the claim is released before the error returns"
        );
    }

    // -- cancel ------------------------------------------------------------

    #[test]
    fn cancel_of_an_unknown_or_blank_id_refuses() {
        let fixture = Fixture::new();
        let (_plan, env, _device) = fixture.good(true);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, _emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        for id in ["deadbeefdeadbeefdeadbeefdeadbeef", "", "   \t"] {
            let refused = registry
                .cancel("com.example.gui", id)
                .expect_err("nothing under this id runs");
            assert_eq!(
                refused.code(),
                ERROR_UNKNOWN_SESSION,
                "cancelling {id:?} on an idle service"
            );
        }
        assert!(registry.is_idle());
    }

    #[test]
    fn a_foreign_caller_cannot_cancel_and_learns_nothing_of_the_run() {
        let fixture = Fixture::new();
        let (good, env, _device) = fixture.good(true);
        let plan = finalize_only(good);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let barrier = Arc::new(Barrier::new(2));
        let parked = barrier.clone();
        registry.install_run_pause(Some(Arc::new(move || {
            parked.wait();
        })));

        let id = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("a valid plan is accepted immediately");

        // A second bus connection (or plain local user) knows the id
        // from /run and tries to abort: refused, with the same
        // sentence a wrong id would draw — nothing leaks about whose
        // run it is.
        let refused = registry
            .cancel("com.example.other", &id)
            .expect_err("another caller cannot cancel the run");
        assert_eq!(refused.code(), ERROR_UNKNOWN_SESSION);
        assert_eq!(
            refused.to_string(),
            format!("no session {id} is running (it never started or has already finished)"),
            "the refusal is indistinguishable from a wrong id"
        );
        assert!(
            registry.running().as_deref() == Some(id.as_str()),
            "the run kept its claim and owner"
        );

        // The run was untouched by the foreign cancel: released
        // unchecked, it reaches Ok, not Cancelled.
        barrier.wait();
        wait_idle(&registry);
        let completions = wait_completions(&emitter);
        assert_eq!(completions.len(), 1, "exactly one Done");
        assert_eq!(completions[0].session, id);
        assert_eq!(
            completions[0].outcome,
            rufus_proto::Outcome::Ok,
            "the foreign cancel never reached the run"
        );
    }

    // -- the run's own stream ----------------------------------------------

    #[test]
    fn a_finalize_only_plan_runs_ok_and_cleans_the_session() {
        let fixture = Fixture::new();
        let (good, env, _device) = fixture.good(true);
        let plan = finalize_only(good);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let id = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("a valid plan is accepted immediately");
        assert_eq!(id.len(), 32, "the id is a 32-hex session id");

        wait_idle(&registry);
        let events = emitter.snapshot();
        let completions = wait_completions(&emitter);
        assert_eq!(completions.len(), 1, "exactly one Done: {events:#?}");
        assert_eq!(completions[0].session, id);
        assert_eq!(completions[0].version, EVENT_STREAM_VERSION);
        assert_eq!(completions[0].outcome, rufus_proto::Outcome::Ok);

        // The loop's grammar: at least one Progress and one Log, every
        // event echoing the session id.
        let mut progress = false;
        let mut log = false;
        for event in &events {
            match event {
                rufus_proto::Event::Progress(p) => {
                    progress = true;
                    assert_eq!(p.session, id);
                }
                rufus_proto::Event::Log(l) => {
                    log = true;
                    assert_eq!(l.session, id);
                }
                rufus_proto::Event::Done(_) => {}
            }
        }
        assert!(progress && log, "the stream moved and spoke: {events:#?}");

        // The session is gone, lock and directory, root itself left
        // standing: nothing persists under the sessions root.
        assert!(
            !sessions.path().join(&id).exists(),
            "the session directory is removed with the run"
        );
        assert_eq!(
            fs::read_dir(sessions.path())
                .expect("the sessions root exists")
                .count(),
            0,
            "no .lock, no session directory, nothing but the root"
        );
    }

    #[test]
    fn cancel_mid_run_reports_cancelled_and_frees_the_service() {
        let fixture = Fixture::new();
        let (good, env, _device) = fixture.good(true);
        let plan = finalize_only(good);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let barrier = Arc::new(Barrier::new(2));
        let parked = barrier.clone();
        registry.install_run_pause(Some(Arc::new(move || {
            parked.wait();
        })));

        let id = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("a valid plan is accepted immediately");

        // The worker is parked with its claim open: the cancel lands on
        // a run the service genuinely holds (the S06 executor has no
        // mid-step pause; the step loop's very-first check is the
        // earliest real stop, and it keeps the same `Cancelled`
        // contract).
        registry
            .cancel("com.example.gui", &id)
            .expect("the claimed run is cancellable");
        barrier.wait(); // release the worker; the loop's cancel check fires
        wait_idle(&registry);

        let completions = wait_completions(&emitter);
        assert_eq!(completions.len(), 1, "the cancelled run's own Done");
        assert_eq!(completions[0].session, id);
        assert_eq!(
            completions[0].outcome,
            rufus_proto::Outcome::Cancelled,
            "the cancellation is the run's outcome"
        );

        // A cancel for a session that already finished refuses now.
        assert_eq!(
            registry
                .cancel("com.example.gui", &id)
                .expect_err("the run is over")
                .code(),
            ERROR_UNKNOWN_SESSION
        );

        // The freed service accepts the next run, which completes Ok.
        registry.install_run_pause(None);
        let second = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("the freed claim is fresh");
        wait_idle(&registry);
        let completions = emitter.completions();
        assert_eq!(completions.len(), 2, "one Done per run: {completions:#?}");
        assert_eq!(
            completions[1].session, second,
            "the second run's own terminal event"
        );
        assert_eq!(completions[1].outcome, rufus_proto::Outcome::Ok);
    }

    #[test]
    fn a_wiped_plan_reports_a_failed_done_from_the_placeholder_executor() {
        let fixture = Fixture::new();
        // The good plan starts with `Wipe`: validation passes (rules
        // carry), the placeholder executor refuses the step.
        let (plan, env, _device) = fixture.good(true);
        let sessions = tempfile::tempdir().expect("sessions root");
        let (registry, emitter) = registry_with(env, Arc::new(FixedAuthorizer(true)), &sessions);

        let id = registry
            .execute("com.example.gui", &execute_json(&plan))
            .expect("a valid plan is accepted; its run may still fail");
        wait_idle(&registry);

        let completions = wait_completions(&emitter);
        assert_eq!(completions.len(), 1, "exactly one Done");
        assert_eq!(completions[0].session, id);
        assert_eq!(
            completions[0].outcome,
            rufus_proto::Outcome::Failed {
                code: "unsupported".to_string(),
                message: "step 'wipe' needs the S07 pipeline".to_string(),
            },
            "the placeholder executor's refusal is the run's outcome"
        );
        assert!(
            emitter
                .snapshot()
                .iter()
                .any(|event| matches!(event, rufus_proto::Event::Progress(_))),
            "the wipe step reported progress before the refusal"
        );
        assert!(registry.is_idle());
    }

    // -- the Handoff (the one-shot accept bridge) ----------------------------

    #[test]
    fn handoff_complete_before_wait_returns_the_value() {
        // The slot-already-set path: the worker answered before the
        // waiter ever parked, so `wait` returns without blocking.
        let handoff = Handoff::new();
        handoff.complete(41u32);
        let got = zbus::block_on(handoff.wait());
        assert_eq!(got, 41u32, "an answer published before waiting is returned");
    }

    /// Wait for a [`Handoff`] with a hard bound: the wait runs on a
    /// spawned thread and the answer rides an `mpsc` channel, so a lost
    /// wake fails fast instead of hanging the harness until it kills
    /// the test. The bound (seconds) is far above the real wait
    /// (milliseconds).
    fn wait_handoff<T>(handoff: Arc<Handoff<T>>) -> T
    where
        T: Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let answer = zbus::block_on(handoff.wait());
                let _ = tx.send(answer);
            })
            .expect("the handoff wait thread spawns");
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|err| panic!("the handoff wait timed out after 5 s: {err}"))
    }

    #[test]
    fn handoff_wakes_a_waiter_parked_before_complete() {
        // The register-then-wake path: the waiter parks first and the
        // worker's `complete` must wake it. The worker sleeps a few
        // tens of milliseconds so the waiter is reliably parked when
        // it answers, without pushing the test near a second.
        let handoff = Arc::new(Handoff::new());
        let worker = Arc::clone(&handoff);
        let worker_thread = std::thread::Builder::new()
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                worker.complete("late".to_string());
            })
            .expect("the handoff test worker spawns");
        let got = wait_handoff(Arc::clone(&handoff));
        worker_thread.join().expect("the handoff test worker joins");
        assert_eq!(
            got,
            "late".to_string(),
            "a parked waiter wakes with the worker's answer"
        );
    }

    #[test]
    fn handoff_catch_unwind_answers_a_worker_that_unwound() {
        // Pins `Helper1::execute`'s containment where it holds (dev
        // and test unwind; release aborts — see `Handoff::complete`):
        // a worker that panics still answers the waiter with the
        // disconnect sentence instead of parking it forever.
        assert_eq!(
            super::WORKER_NO_ANSWER_MESSAGE,
            "the helper thread ended without an answer",
            "the fallback sentence stays byte-identical"
        );
        let handoff = Arc::new(Handoff::<zbus::fdo::Result<String>>::new());
        let worker = Arc::clone(&handoff);
        let worker_thread = std::thread::Builder::new()
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<String, ServiceError> {
                        panic!("a worker bug in a test");
                    },
                ));
                worker.complete(super::worker_answer(outcome));
            })
            .expect("the handoff test worker spawns");
        let got = wait_handoff(Arc::clone(&handoff));
        worker_thread.join().expect("the handoff test worker joins");
        assert!(
            matches!(&got, Err(zbus::fdo::Error::Failed(message)) if message == super::WORKER_NO_ANSWER_MESSAGE),
            "the unwind fallback answers with the disconnect sentence: {got:?}"
        );
    }

    // -- the compile-time contract -----------------------------------------

    /// The bus half (5b) shares a `Registry` across async handlers
    /// and raises a `ServiceError` into a `zbus` error; both must be
    /// `Send + Sync`-grade so the wiring cannot break silently.
    #[test]
    fn registry_and_service_error_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Registry>();
        assert_send_sync::<ServiceError>();
    }
}
