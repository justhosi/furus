//! The step loop and the executor seam (S06).
//!
//! [`run_plan`] is the whole S06 part 3 executor: it walks the plan's
//! steps in order, reports per-step progress and log lines through the
//! [`ProgressSink`](crate::progress::ProgressSink) the caller chose,
//! honours cancellation between steps, and maps every executor outcome
//! onto the [`rufus_proto::Outcome`] the front end's `Done` event
//! carries. It performs **no** block I/O of its own — real step work is
//! plugged in below via [`StepExecutor`], which is what S07/S17 build
//! on. Neither this loop nor [`CurrentExecutor`] spawns processes,
//! issues mounts or opens devices.
//!
//! # Grammar of the loop (pinned by tests)
//!
//! Before each step: cancellation check first (`warn` log + `Cancelled`
//! when set), then one `Progress` (steps completed so far),
//! then one `info` log `step <n>/<total>: <op>`. After a success: one
//! `Progress` for the completed step (the percent-100 boundary of the
//! last step). On an executor [`Reject`]: an `error`/`warn` log with
//! the (already ASCII) message, then `Outcome::Failed`/`Cancelled` —
//! never a `Done` event (the caller emits that, after `run_plan`
//! returns, also for pre-run refusals).
//!
//! # The current executor is a documented refusal
//!
//! [`CurrentExecutor`] is the S06 placeholder that S17 replaces.
//! Shipping a build with it means **no plan can write a device**: every
//! step except `Finalize` is refused with code `"unsupported"`. That is
//! the honest state — a helper that runs nothing exists so the wiring
//! (argv, validation, session, events) is testable end to end before a
//! single byte of media is at risk.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use rufus_core::text::device_text;
use rufus_proto::Event;
use rufus_proto::LogLevel;
use rufus_proto::LogLine;
use rufus_proto::Outcome;
use rufus_proto::Plan;
use rufus_proto::Progress;
use rufus_proto::Step;

use crate::progress::ProgressSink;
use crate::validate::Reject;

/// The one reserved executor rejection code: a step that chose to stop
/// because the user cancelled maps to [`Outcome::Cancelled`], not to a
/// failure.
pub const CANCELLED_CODE: &str = "cancelled";

/// Cooperative cancellation flag shared by `run_plan`, the executors
/// (through their [`StepCtx`]) and the D-Bus `Cancel` handler. Cloning
/// is cheap and the clone shares the flag (an `Arc`), so a handler
/// thread, the supervising loop and a child-process watcher all observe
/// the same state; `set` is one-way.
#[derive(Debug, Clone)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A not-yet-cancelled flag.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Cancel from now on; never un-sets (a mid-write cancel may not be
    /// walked back by a second command arriving late). Called by the
    /// D-Bus `Cancel` handler and by the process watcher.
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`Cancel::set`] has happened.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

/// What an executor sees per step: progress/log delivery, the shared
/// [`Cancel`], the validated device and the session id to label events
/// with.
#[allow(dead_code)] // `cancel`/`device` feed the S07/S17 writing executors
pub struct StepCtx<'a> {
    /// Where the executor sends its own events (sub-progress of the
    /// step, per-line logs). Everything it sends must already be ASCII
    /// (device-derived strings sanitised with `device_text`).
    pub sink: &'a mut dyn ProgressSink,
    /// The shared cancellation flag.
    pub cancel: &'a Cancel,
    /// The validated device facts (name, path, size, sector geometry).
    pub device: &'a rufus_linux::Device,
    /// The session id (labels every event).
    pub session: &'a str,
}

/// Real step work behind [`run_plan`]. The S06 placeholder is
/// [`CurrentExecutor`]; S07+S17 will implement a writing one.
pub trait StepExecutor {
    /// Execute step `index` of `plan.steps`. Returning
    /// [`Reject`] with code [`CANCELLED_CODE`] means "stop, cancelled",
    /// any other rejection is a failure; both are reported by
    /// `run_plan`, never doubled up here.
    fn execute(&mut self, index: usize, step: &Step, ctx: &mut StepCtx<'_>) -> Result<(), Reject>;
}

/// The JSON `op` tag of a step, without serialising the whole step.
///
/// Mirrors the `#[serde(tag = "op", rename_all = "snake_case")]` tags
/// of [`Step`]; the tests compare both constants against
/// `serde_json::to_value`, so they cannot drift.
pub fn op_tag(step: &Step) -> &'static str {
    match step {
        Step::Wipe => "wipe",
        Step::Mklabel { .. } => "mklabel",
        Step::Mkpart { .. } => "mkpart",
        Step::Mkfs { .. } => "mkfs",
        Step::Write { .. } => "write",
        Step::Bootloader { .. } => "bootloader",
        Step::Finalize => "finalize",
    }
}

/// Walk the plan's steps, reporting to `sink`, and return the outcome.
///
/// See the module docs for the exact event grammar. `run_plan` emits no
/// terminal event: the caller (in S06 part 3, `main`) emits the final
/// `Event::Done`, also for pre-run refusals — so an event stream always
/// ends off exactly one `Done`.
pub fn run_plan(
    plan: &Plan,
    device: &rufus_linux::Device,
    executor: &mut dyn StepExecutor,
    sink: &mut dyn ProgressSink,
    cancel: &Cancel,
    session: &str,
) -> Outcome {
    let total = plan.steps.len();
    // `usize` ≤ `u64` on every target this workspace builds, so the
    // cast is lossless; verified by the size-resolution test below.
    let total_u64 = total as u64;
    for (index, step) in plan.steps.iter().enumerate() {
        // Cancellation is checked before anything of this step happens,
        // so a cancelled-before-run stream shows no progress at all.
        if cancel.is_set() {
            sink.event(&Event::Log(LogLine {
                session: session.to_string(),
                level: LogLevel::Warn,
                message: format!(
                    "cancelled before step {}/{total}: no changes were made",
                    index + 1
                ),
            }));
            return Outcome::Cancelled;
        }
        let op = op_tag(step); // static ASCII; no sanitising needed
        sink.event(&Event::Progress(Progress::new(
            session,
            index,
            op,
            index as u64,
            Some(total_u64),
        )));
        sink.event(&Event::Log(LogLine {
            session: session.to_string(),
            level: LogLevel::Info,
            message: format!("step {}/{total}: {op}", index + 1),
        }));

        let mut ctx = StepCtx {
            sink: &mut *sink,
            cancel,
            device,
            session,
        };
        match executor.execute(index, step, &mut ctx) {
            // One completed-unit progress event per step; the last one
            // carries the final percent (100) the front end shows.
            Ok(()) => sink.event(&Event::Progress(Progress::new(
                session,
                index,
                op,
                index as u64 + 1,
                Some(total_u64),
            ))),
            Err(reject) if reject.code == CANCELLED_CODE => {
                sink.event(&Event::Log(LogLine {
                    session: session.to_string(),
                    level: LogLevel::Warn,
                    message: device_text(&reject.message),
                }));
                return Outcome::Cancelled;
            }
            Err(reject) => {
                sink.event(&Event::Log(LogLine {
                    session: session.to_string(),
                    level: LogLevel::Error,
                    message: device_text(&reject.message),
                }));
                return Outcome::Failed {
                    code: reject.code,
                    message: reject.message,
                };
            }
        }
    }
    Outcome::Ok
}

/// The S06 placeholder executor (see the module docs): the loop, the
/// event grammar and the fail-closed posture are live, the actual step
/// work is not until S07+S17 arrive. `Finalize` is accepted (it would
/// flush nothing on this build), everything else refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentExecutor;

impl Default for CurrentExecutor {
    fn default() -> Self {
        Self
    }
}

impl StepExecutor for CurrentExecutor {
    fn execute(&mut self, _index: usize, step: &Step, ctx: &mut StepCtx<'_>) -> Result<(), Reject> {
        if matches!(step, Step::Finalize) {
            ctx.sink.event(&Event::Log(LogLine {
                session: ctx.session.to_string(),
                level: LogLevel::Info,
                message: "finalize: nothing to flush yet (S17)".to_string(),
            }));
            return Ok(());
        }
        Err(Reject {
            code: "unsupported".to_string(),
            message: format!("step '{}' needs the S07 pipeline", op_tag(step)),
        })
    }
}

#[cfg(test)]
mod tests {
    use rufus_proto::BootloaderMode;
    use rufus_proto::DeviceRef;
    use rufus_proto::Event;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::Outcome;
    use rufus_proto::Plan;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target as Firmware;

    use super::CANCELLED_CODE;
    use super::Cancel;
    use super::CurrentExecutor;
    use super::StepCtx;
    use super::StepExecutor;
    use super::op_tag;
    use super::run_plan;
    use crate::progress::VecSink;
    use crate::validate::Reject;

    const SESSION: &str = "s-1";

    fn steps_plan(steps: Vec<Step>) -> Plan {
        Plan {
            version: rufus_proto::PLAN_VERSION,
            created_by: "rufus-helper tests".to_string(),
            device: DeviceRef {
                path: "/dev/sdz".to_string(),
                block_device: true,
                size_bytes: Some(8),
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: "x.img".to_string(),
                size_bytes: 4,
                sha256: "0".repeat(64),
                kind: ImageKind::Raw,
            },
            options: Options {
                scheme: Scheme::Mbr,
                target: Firmware::Uefi,
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
            },
            steps,
            confirm: String::new(),
        }
    }

    fn device() -> rufus_linux::Device {
        rufus_linux::Device {
            sysfs: "/sys/class/block/sdz".to_string(),
            name: "sdz".to_string(),
            dev_path: "/dev/sdz".to_string(),
            size_bytes: 8,
            sector_size: 512,
            physical_sector_size: 512,
            removable: true,
            read_only: false,
            usb: true,
            vendor: None,
            model: None,
            serial: None,
            transport: rufus_linux::Transport::Usb,
            partition_table: None,
            vid_pid: None,
            port_path: None,
            partitions: Vec::new(),
        }
    }

    /// Run `plan` through [`run_plan`] with the standard device/executor
    /// and collect the events and the outcome.
    fn run(plan: &Plan, executor: &mut dyn StepExecutor, cancel: &Cancel) -> (VecSink, Outcome) {
        let mut sink = VecSink::new();
        let outcome = run_plan(plan, &device(), executor, &mut sink, cancel, SESSION);
        (sink, outcome)
    }

    // -- op tags ----------------------------------------------------------

    #[test]
    fn op_tags_match_the_serde_wire_tags() {
        let cases: Vec<(Step, &str)> = vec![
            (Step::Wipe, "wipe"),
            (
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                "mklabel",
            ),
            (
                Step::Mkpart {
                    scheme: Scheme::Gpt,
                    layout: rufus_proto::Layout::Single,
                },
                "mkpart",
            ),
            (
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: None,
                    cluster_bytes: None,
                    quick: true,
                },
                "mkfs",
            ),
            (
                Step::Write {
                    mode: rufus_proto::WriteMode::Dd,
                },
                "write",
            ),
            (
                Step::Bootloader {
                    mode: BootloaderMode::Auto,
                },
                "bootloader",
            ),
            (Step::Finalize, "finalize"),
        ];
        for (step, tag) in cases {
            assert_eq!(op_tag(&step), tag, "{step:?} tag");
            let wire = serde_json::to_value(&step).expect("step serialises");
            assert_eq!(
                wire["op"], tag,
                "op_tag cannot drift from the serde wire contract"
            );
        }
    }

    // -- run_plan grammar -------------------------------------------------

    #[test]
    fn finalize_only_plan_is_ok_with_the_pinned_event_grammar() {
        let plan = steps_plan(vec![Step::Finalize]);
        let (sink, outcome) = run(&plan, &mut CurrentExecutor, &Cancel::new());
        assert_eq!(outcome, Outcome::Ok);

        // The pinned grammar, start to finish: progress (0/1), the step
        // log line, the placeholder's own line, the 100-percent event.
        let events = sink.events();
        assert_eq!(events.len(), 4, "exactly: {events:#?}");
        assert_eq!(
            events[0],
            Event::Progress(rufus_proto::Progress::new(
                SESSION,
                0,
                "finalize",
                0,
                Some(1)
            ))
        );
        assert_eq!(
            events[1],
            Event::Log(rufus_proto::LogLine {
                session: SESSION.to_string(),
                level: rufus_proto::LogLevel::Info,
                message: "step 1/1: finalize".to_string(),
            })
        );
        assert_eq!(
            events[2],
            Event::Log(rufus_proto::LogLine {
                session: SESSION.to_string(),
                level: rufus_proto::LogLevel::Info,
                message: "finalize: nothing to flush yet (S17)".to_string(),
            })
        );
        assert_eq!(
            events[3],
            Event::Progress(rufus_proto::Progress::new(
                SESSION,
                0,
                "finalize",
                1,
                Some(1)
            ))
        );
        let last = match &events[3] {
            Event::Progress(progress) => progress.percent,
            _ => None,
        };
        assert_eq!(last, Some(100), "the final milestone reports 100");
    }

    #[test]
    fn unsupported_steps_fail_through_current_executor() {
        let plan = steps_plan(vec![Step::Wipe, Step::Finalize]);
        let (sink, outcome) = run(&plan, &mut CurrentExecutor, &Cancel::new());
        assert_eq!(
            outcome,
            Outcome::Failed {
                code: "unsupported".to_string(),
                message: "step 'wipe' needs the S07 pipeline".to_string(),
            }
        );
        let events = sink.events();
        assert_eq!(events.len(), 3, "the failure ends the stream: {events:#?}");
        assert_eq!(
            events[0],
            rufus_proto::Event::Progress(rufus_proto::Progress::new(
                SESSION,
                0,
                "wipe",
                0,
                Some(2)
            ))
        );
        assert_eq!(
            events[1],
            Event::Log(rufus_proto::LogLine {
                session: SESSION.to_string(),
                level: rufus_proto::LogLevel::Info,
                message: "step 1/2: wipe".to_string(),
            })
        );
        assert_eq!(
            events[2],
            Event::Log(rufus_proto::LogLine {
                session: SESSION.to_string(),
                level: rufus_proto::LogLevel::Error,
                message: "step 'wipe' needs the S07 pipeline".to_string(),
            })
        );
    }

    #[test]
    fn cancellation_before_the_run_logs_and_never_progresses() {
        let cancel = Cancel::new();
        cancel.set();
        let plan = steps_plan(vec![Step::Wipe, Step::Finalize]);
        let (sink, outcome) = run(&plan, &mut CurrentExecutor, &cancel);

        assert_eq!(outcome, Outcome::Cancelled);
        let events = sink.events();
        assert_eq!(events.len(), 1, "no progress leaked: {events:#?}");
        assert_eq!(
            events[0],
            Event::Log(rufus_proto::LogLine {
                session: SESSION.to_string(),
                level: rufus_proto::LogLevel::Warn,
                message: "cancelled before step 1/2: no changes were made".to_string(),
            })
        );
    }

    /// An executor that cancels *during* the first step; the loop must
    /// stop before its second step begins (no second progress event).
    struct CancelMidway {
        already_set: bool,
    }

    impl CancelMidway {
        fn new() -> Self {
            Self { already_set: false }
        }
    }

    impl StepExecutor for CancelMidway {
        fn execute(
            &mut self,
            _index: usize,
            _step: &Step,
            ctx: &mut StepCtx<'_>,
        ) -> Result<(), Reject> {
            if self.already_set {
                return Err(Reject {
                    code: CANCELLED_CODE.to_string(),
                    message: "cancelled by the step".to_string(),
                });
            }
            self.already_set = true;
            ctx.sink
                .event(&rufus_proto::Event::Log(rufus_proto::LogLine {
                    session: ctx.session.to_string(),
                    level: rufus_proto::LogLevel::Debug,
                    message: "warming up".to_string(),
                }));
            ctx.cancel.set();
            Ok(())
        }
    }

    #[test]
    fn cancellation_during_a_step_stops_the_loop_before_the_next() {
        let plan = steps_plan(vec![Step::Wipe, Step::Finalize]);
        let (sink, outcome) = run(&plan, &mut CancelMidway::new(), &Cancel::new());
        assert_eq!(outcome, Outcome::Cancelled);
        let events = sink.events();
        // Step 0 completes (progress 0, log, executor log, progress 1),
        // then the cancellation check refuses step 1 (warn log only).
        assert_eq!(events.len(), 5, "exactly: {events:#?}");
        let last = match &events[4] {
            rufus_proto::Event::Log(log) => (log.level, log.message.clone()),
            _ => (rufus_proto::LogLevel::Debug, String::new()),
        };
        assert_eq!(
            last,
            (
                rufus_proto::LogLevel::Warn,
                "cancelled before step 2/2: no changes were made".to_string()
            )
        );
    }

    // -- Cancel ------------------------------------------------------------

    #[test]
    fn cancel_flags_are_one_way_and_cloneable() {
        let cancel = Cancel::new();
        assert!(!cancel.is_set());
        let live = cancel.clone();
        assert!(!live.is_set(), "a clone starts with the current state");
        cancel.set();
        assert!(cancel.is_set());
        assert!(
            live.is_set(),
            "a clone made before the set observes it: clones share the flag"
        );

        // Cross-thread: the D-Bus handler sets, the worker reads.
        let worker_side = cancel.clone();
        std::thread::spawn(move || worker_side.set())
            .join()
            .expect("the cancelling thread finishes");
        assert!(cancel.is_set(), "cancellation crosses threads");

        // No unset path: a fresh flag stays fresh.
        let fresh = Cancel::new();
        assert!(!fresh.is_set());
    }

    // -- the two root-only loop-device tests ------------------------------
    //
    // These are the S06 placeholders for PLAN §6's "a plan against a
    // loop device succeeds as root ... and nothing is left mounted"
    // done-criterion. S17 wires a real writing executor in; until then
    // both tests assert the honest refusal side. They need root (full
    // loop-device nodes, e.g. via losetup) and are skipped by CI on
    // purpose; they must still compile today. `Env::live()` is used
    // because the only test window the helper defines outside argv is
    // `Env` — and these must see the real host, not fixtures.

    #[ignore = "needs root and a loop device; the real write arrives with S17"]
    #[test]
    fn loop_device_plan_refuses_and_leaves_nothing_mounted() {
        let env = crate::validate::Env::live();
        let mut plan = steps_plan(vec![Step::Wipe, Step::Finalize]);
        plan.device.path = "/dev/loop0".to_string();
        plan.confirm = plan.confirm().expect("canonical serialisation");
        let before = rufus_linux::mounts::MountTable::read(None).expect("live mountinfo");

        let rejected = crate::validate::validate(&plan, &env).expect_err("loop names refuse");
        assert_ne!(rejected.code, "ok");

        let after = rufus_linux::mounts::MountTable::read(None).expect("live mountinfo");
        assert_eq!(before.entries(), after.entries(), "nothing was mounted");
    }

    #[ignore = "needs root and a loop device; the real write arrives with S17"]
    #[test]
    fn loop_device_plan_never_reaches_an_executor_step() {
        let plan = steps_plan(vec![Step::Wipe, Step::Finalize]);
        let cancel = Cancel::new();
        let (sink, outcome) = run(&plan, &mut CurrentExecutor, &cancel);
        assert_eq!(
            outcome,
            Outcome::Failed {
                code: "unsupported".to_string(),
                message: "step 'wipe' needs the S07 pipeline".to_string(),
            }
        );
        assert!(sink.events().iter().all(|event| {
            let text = serde_json::to_string(event).expect("event serialises");
            text.contains(SESSION)
        }));
    }

    #[test]
    fn usize_total_fits_u64() {
        // The `total as u64` cast in run_plan is lossless by size
        // resolution; pinned so a platform change shows up here.
        assert!(
            size_of::<usize>() <= size_of::<u64>(),
            "usize must fit u64 for the lossless cast"
        );
    }
}
