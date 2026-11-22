//! The real write pipeline behind both helper entry points (S35.1).
//!
//! [`RealRunner`] is the production [`PlanRunner`]: it derives the
//! opener's table/layout from the plan's own `Mklabel`/`Mkpart` steps
//! (never from `options.scheme` alone), builds a
//! [`DeviceOpener`](furus_linux::DeviceOpener) over the already-validated
//! device and calls [`furus_core::pipeline::run`]. Nothing here enumerates
//! devices again: `validate` handed us the one it resolved.
//!
//! [`HelperReporter`] is the bridge from core's [`CoreEvent`] stream to
//! the helper's [`ProtoEvent`] stream. Every string that can carry
//! device/kernel/image text goes through
//! [`device_text`](furus_core::text::device_text) before it reaches a
//! sink; the step index a core `Progress` sample belongs to comes from
//! the last `StepStarted` (so `verify`/`badblocks` pseudo-step samples
//! ride on the plan step that produced them).
//!
//! [`outcome_from_core_error`] is the single error classification for
//! the helper's `Done`: step wrappers are transparent for the code but
//! keep their prefix in the message, like the CLI's `Fail::from_core`.
//!
//! The hermetic test seam is the [`PlanRunner`] trait itself: fixtures
//! pass a stub that wraps [`crate::exec::run_plan`], so no unit test
//! needs root or a real block device.

use std::time::Duration;

use furus_core::error::CoreError;
use furus_core::part::TableKind;
use furus_core::part::plan::LayoutKind;
use furus_core::pipeline::Event as CoreEvent;
use furus_core::pipeline::Reporter;
use furus_core::pipeline::RunOptions;
use furus_core::text::device_text;
use furus_linux::DeviceOpener;
use furus_linux::SysfsRoot;
use furus_proto::Event as ProtoEvent;
use furus_proto::Layout;
use furus_proto::LogLevel;
use furus_proto::LogLine;
use furus_proto::Outcome;
use furus_proto::Plan;
use furus_proto::Progress;
use furus_proto::Scheme;
use furus_proto::Step;

use crate::exec;
use crate::progress::ProgressSink;
use crate::validate::Validated;

/// The code a plan whose steps disagree gets before any device is
/// opened (the same class a hand-built invalid plan gets from
/// validation).
const INVALID_PLAN_CODE: &str = "invalid_input";

/// Where the run's events go, and which session id and plan step they
/// are tagged with.
pub struct HelperReporter<'a> {
    sink: &'a mut dyn ProgressSink,
    session: &'a str,
    step: usize,
}

impl<'a> HelperReporter<'a> {
    /// Report into `sink` with every event tagged `session`; the first
    /// core event is normally a `StepStarted` that sets the index.
    #[must_use]
    pub fn new(sink: &'a mut dyn ProgressSink, session: &'a str) -> Self {
        Self {
            sink,
            session,
            step: 0,
        }
    }
}

impl Reporter for HelperReporter<'_> {
    fn event(&mut self, event: CoreEvent) {
        let session = device_text(self.session);
        match event {
            CoreEvent::StepStarted { index, total, step } => {
                // Every following Progress sample belongs to this plan
                // step until the next boundary — including the verify
                // and badblocks pseudo-steps of a write.
                self.step = index;
                self.sink.event(&ProtoEvent::Log(LogLine {
                    session,
                    level: LogLevel::Info,
                    message: device_text(&format!("step {}/{total}: {}", index + 1, step)),
                }));
            }
            CoreEvent::StepFinished {
                index,
                step,
                millis,
            } => {
                self.sink.event(&ProtoEvent::Log(LogLine {
                    session,
                    level: LogLevel::Info,
                    message: device_text(&format!("step {index} ({step}) finished in {millis} ms")),
                }));
            }
            CoreEvent::Progress {
                step, done, total, ..
            } => self.sink.event(&ProtoEvent::Progress(Progress::new(
                session,
                self.step,
                device_text(step),
                done,
                total,
            ))),
            CoreEvent::Message { level, text } => {
                self.sink.event(&ProtoEvent::Log(LogLine {
                    session,
                    level: LogLevel::parse(&device_text(level)).unwrap_or(LogLevel::Info),
                    message: device_text(&text),
                }));
            }
            CoreEvent::Finished { millis } => {
                self.sink.event(&ProtoEvent::Log(LogLine {
                    session,
                    level: LogLevel::Info,
                    message: device_text(&format!("run finished in {millis} ms")),
                }));
            }
        }
    }
}

/// The failure classes that decide a `Done` outcome. Mirrors the
/// CLI's exit mapping, with the two user-fault classes becoming a
/// refusal rather than a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Cancelled,
    NotImplemented,
    InvalidInput,
    Io,
    Verify,
    Other,
}

fn class_of(error: &CoreError) -> Class {
    match error {
        CoreError::Cancelled => Class::Cancelled,
        CoreError::NotImplemented { .. } => Class::NotImplemented,
        CoreError::InvalidInput { .. } => Class::InvalidInput,
        CoreError::Io { .. } => Class::Io,
        CoreError::Verify { .. } => Class::Verify,
        // A step wrapper never changes the class of what it wraps;
        // the message below still carries the step prefix.
        CoreError::Step { source, .. } => class_of(source),
        _ => Class::Other,
    }
}

/// Map a core run error onto the helper's terminal outcome.
///
/// `Cancelled` (including inside a [`CoreError::Step`]) is not a
/// failure; `NotImplemented` and `InvalidInput` are refusals; I/O,
/// verification and every other class fail. The message is the full
/// `Display` of the *outer* error, so a step name is never lost.
#[must_use]
pub fn outcome_from_core_error(error: CoreError) -> Outcome {
    let message = device_text(&error.to_string());
    match class_of(&error) {
        Class::Cancelled => Outcome::Cancelled,
        Class::NotImplemented => Outcome::Refused {
            code: "not_implemented".to_string(),
            message,
        },
        Class::InvalidInput => Outcome::Refused {
            code: INVALID_PLAN_CODE.to_string(),
            message,
        },
        Class::Io => Outcome::Failed {
            code: "io".to_string(),
            message,
        },
        Class::Verify => Outcome::Failed {
            code: "verify".to_string(),
            message,
        },
        Class::Other => Outcome::Failed {
            code: "pipeline".to_string(),
            message,
        },
    }
}

/// The `(table, layout)` pair the opener plans its partition window
/// and node spelling for: read off the plan's `Mklabel`/`Mkpart`
/// steps — the authority for what `Mkpart` stamps — never off
/// `options.scheme`, which is the planner's intent. A plan whose
/// steps disagree refuses before touching the device.
pub fn opener_table_kind(plan: &Plan) -> Result<(TableKind, LayoutKind), String> {
    let mut label: Option<Scheme> = None;
    let mut part: Option<Scheme> = None;
    let mut layout: Option<Layout> = None;
    for step in &plan.steps {
        match step {
            Step::Mklabel { scheme } => label = Some(scheme.clone()),
            Step::Mkpart {
                scheme,
                layout: step_layout,
            } => {
                part = Some(scheme.clone());
                if let Some(seen) = &layout {
                    if seen != step_layout {
                        return Err(format!(
                            "plan steps disagree: mkpart asks for '{}' but also for '{}': refusing before touching the device",
                            human_layout(seen),
                            human_layout(step_layout),
                        ));
                    }
                } else {
                    layout = Some(step_layout.clone());
                }
            }
            _ => {}
        }
    }
    let table = match (label, part) {
        (Some(label), Some(part)) if label != part => {
            return Err(format!(
                "plan steps disagree: mklabel asks for '{}' but mkpart asks for '{}': refusing before touching the device",
                human_scheme(&label),
                human_scheme(&part),
            ));
        }
        (Some(scheme), _) | (None, Some(scheme)) => table_kind(&scheme),
        (None, None) => table_kind(&plan.options.scheme),
    };
    // A hand-built plan without an `Mkpart` step keeps the single
    // layout, the planner's default.
    let layout = layout.map_or(LayoutKind::Single, |step_layout| layout_kind(&step_layout));
    Ok((table, layout))
}

fn table_kind(scheme: &Scheme) -> TableKind {
    match scheme {
        Scheme::Mbr => TableKind::Mbr,
        Scheme::Gpt => TableKind::Gpt,
    }
}

fn layout_kind(layout: &Layout) -> LayoutKind {
    match layout {
        Layout::Single => LayoutKind::Single,
        Layout::UefiNtfs => LayoutKind::UefiNtfs,
        Layout::WindowsToGo => LayoutKind::WindowsToGo,
        Layout::Persistence => LayoutKind::Persistence,
    }
}

fn human_scheme(scheme: &Scheme) -> &'static str {
    match scheme {
        Scheme::Mbr => "mbr",
        Scheme::Gpt => "gpt",
    }
}

fn human_layout(layout: &Layout) -> &'static str {
    match layout {
        Layout::Single => "single",
        Layout::UefiNtfs => "uefi_ntfs",
        Layout::WindowsToGo => "windows_to_go",
        Layout::Persistence => "persistence",
    }
}

/// The reference retry policy: three retries, five seconds apart, no
/// USB reset (the helper exposes no reset flag).
fn run_options(plan: &Plan) -> RunOptions {
    RunOptions {
        verify: plan.options.verify,
        badblocks: plan.options.bad_blocks,
        retries: 3,
        retry_delay: Duration::from_secs(5),
        reset_usb: false,
    }
}

/// How one validated plan gets run. The seam both entry points use:
/// production wires [`RealRunner`], hermetic fixtures a stub wrapping
/// [`crate::exec::run_plan`].
pub trait PlanRunner: Send + Sync {
    /// Run `validated`, streaming through `sink` under `session` and
    /// probing `cancel` for cooperative cancellation.
    fn run(
        &self,
        validated: &Validated,
        sink: &mut dyn ProgressSink,
        cancel: &exec::Cancel,
        session: &str,
    ) -> Outcome;
}

/// The production runner: derive the opener's geometry from the plan,
/// open the validated device and run the real core pipeline.
pub struct RealRunner {
    sysfs: SysfsRoot,
}

impl RealRunner {
    /// Record the sysfs root the device was discovered under. The
    /// caller (validation env) already knows it, so no re-enumeration
    /// is needed here.
    #[must_use]
    pub fn new(sysfs: SysfsRoot) -> Self {
        Self { sysfs }
    }
}

impl PlanRunner for RealRunner {
    fn run(
        &self,
        validated: &Validated,
        sink: &mut dyn ProgressSink,
        cancel: &exec::Cancel,
        session: &str,
    ) -> Outcome {
        let (table, layout) = match opener_table_kind(&validated.plan) {
            Ok(kinds) => kinds,
            Err(message) => {
                return Outcome::Refused {
                    code: INVALID_PLAN_CODE.to_string(),
                    message: device_text(&message),
                };
            }
        };
        let opener = match DeviceOpener::new(&validated.device, table, layout, self.sysfs.clone()) {
            Ok(opener) => opener,
            Err(error) => return outcome_from_core_error(error),
        };
        let options = run_options(&validated.plan);
        let mut reporter = HelperReporter::new(sink, session);
        match furus_core::pipeline::run(&validated.plan, &opener, &options, &mut reporter, &|| {
            cancel.is_set()
        }) {
            Ok(_report) => Outcome::Ok,
            Err(error) => outcome_from_core_error(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use furus_core::error::CoreError;
    use furus_core::part::TableKind;
    use furus_core::part::plan::LayoutKind;
    use furus_core::pipeline::Reporter as _;
    use furus_proto::Event;
    use furus_proto::Layout;
    use furus_proto::LogLevel;
    use furus_proto::Outcome;
    use furus_proto::Plan;
    use furus_proto::Progress;
    use furus_proto::Scheme;
    use furus_proto::Step;
    use furus_proto::Target;

    use super::HelperReporter;
    use super::opener_table_kind;
    use super::outcome_from_core_error;
    use crate::progress::VecSink;

    const SESSION: &str = "s-1";

    fn plan(steps: Vec<Step>, scheme: Scheme) -> Plan {
        Plan {
            version: furus_proto::PLAN_VERSION,
            created_by: "furus-helper tests".to_string(),
            device: furus_proto::DeviceRef {
                path: "/dev/sdz".to_string(),
                block_device: true,
                size_bytes: Some(8),
                serial: None,
                model: None,
                sysfs: None,
            },
            image: furus_proto::ImageRef {
                path: "x.img".to_string(),
                size_bytes: 4,
                sha256: "0".repeat(64),
                kind: furus_proto::ImageKind::Raw,
            },
            options: furus_proto::Options {
                scheme,
                target: Target::Uefi,
                filesystem: furus_proto::Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: None,
            },
            steps,
            confirm: String::new(),
        }
    }

    fn mkpart(scheme: Scheme, layout: Layout) -> Step {
        Step::Mkpart { scheme, layout }
    }

    fn mklabel(scheme: Scheme) -> Step {
        Step::Mklabel { scheme }
    }

    // -- HelperReporter --------------------------------------------------

    #[test]
    fn reporter_maps_step_started_to_a_log_and_tracks_the_index() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, SESSION);
            reporter.event(furus_core::pipeline::Event::StepStarted {
                index: 2,
                total: 4,
                step: "write",
            });
        }
        assert_eq!(
            sink.events(),
            &[Event::Log(furus_proto::LogLine {
                session: SESSION.to_string(),
                level: LogLevel::Info,
                message: "step 3/4: write".to_string(),
            })]
        );
    }

    #[test]
    fn reporter_maps_step_finished_to_a_log() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, SESSION);
            reporter.event(furus_core::pipeline::Event::StepFinished {
                index: 1,
                step: "wipe",
                millis: 7,
            });
        }
        assert_eq!(
            sink.events(),
            &[Event::Log(furus_proto::LogLine {
                session: SESSION.to_string(),
                level: LogLevel::Info,
                message: "step 1 (wipe) finished in 7 ms".to_string(),
            })]
        );
    }

    #[test]
    fn reporter_maps_progress_to_proto_progress_on_the_active_step() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, SESSION);
            reporter.event(furus_core::pipeline::Event::StepStarted {
                index: 4,
                total: 7,
                step: "write",
            });
            reporter.event(furus_core::pipeline::Event::Progress {
                step: "verify",
                done: 30,
                total: Some(100),
                bytes_per_second: 0,
                eta_seconds: None,
            });
            reporter.event(furus_core::pipeline::Event::Progress {
                step: "badblocks",
                done: 2,
                total: None,
                bytes_per_second: 9,
                eta_seconds: Some(3),
            });
        }
        assert_eq!(
            sink.events(),
            &[
                Event::Log(furus_proto::LogLine {
                    session: SESSION.to_string(),
                    level: LogLevel::Info,
                    message: "step 5/7: write".to_string(),
                }),
                Event::Progress(Progress::new(SESSION, 4, "verify", 30, Some(100))),
                Event::Progress(Progress::new(SESSION, 4, "badblocks", 2, None)),
            ]
        );
    }

    #[test]
    fn reporter_maps_message_levels_and_sanitizes_all_strings() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, "s\u{7}\u{1b}[2J1");
            reporter.event(furus_core::pipeline::Event::Message {
                level: "warn",
                text: "bad \u{1b}[2J model\n".to_string(),
            });
            reporter.event(furus_core::pipeline::Event::Message {
                level: "not-a-level",
                text: "\u{e6}b".to_string(),
            });
        }
        // `device_text` trims first, then maps every control/non-ASCII
        // char to `?`: BEL+ESC give two `?`, and the trailing `\n` is
        // trimmed away rather than becoming a `?`.
        assert_eq!(
            sink.events(),
            &[
                Event::Log(furus_proto::LogLine {
                    session: "s??[2J1".to_string(),
                    level: LogLevel::Warn,
                    message: "bad ?[2J model".to_string(),
                }),
                Event::Log(furus_proto::LogLine {
                    session: "s??[2J1".to_string(),
                    level: LogLevel::Info,
                    message: "?b".to_string(),
                }),
            ]
        );
    }

    #[test]
    fn reporter_sanitizes_the_progress_op() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, SESSION);
            reporter.event(furus_core::pipeline::Event::Progress {
                step: "w\u{1b}ipe",
                done: 1,
                total: Some(1),
                bytes_per_second: 0,
                eta_seconds: None,
            });
        }
        assert_eq!(
            sink.events(),
            &[Event::Progress(Progress::new(
                SESSION,
                0,
                "w?ipe",
                1,
                Some(1)
            ))]
        );
    }

    #[test]
    fn reporter_maps_finished_to_a_log() {
        let mut sink = VecSink::new();
        {
            let mut reporter = HelperReporter::new(&mut sink, SESSION);
            reporter.event(furus_core::pipeline::Event::Finished { millis: 42 });
        }
        assert_eq!(
            sink.events(),
            &[Event::Log(furus_proto::LogLine {
                session: SESSION.to_string(),
                level: LogLevel::Info,
                message: "run finished in 42 ms".to_string(),
            })]
        );
    }

    // -- outcome_from_core_error ----------------------------------------

    fn wrapped(source: CoreError) -> CoreError {
        CoreError::Step {
            step: "wipe",
            source: Box::new(source),
        }
    }

    #[test]
    fn outcome_mapping_cancels_direct_and_step_wrapped_cancellation() {
        assert_eq!(
            outcome_from_core_error(CoreError::Cancelled),
            Outcome::Cancelled
        );
        assert_eq!(
            outcome_from_core_error(wrapped(CoreError::Cancelled)),
            Outcome::Cancelled
        );
    }

    #[test]
    fn outcome_mapping_refuses_user_faults_keeping_the_step_prefix() {
        let not_implemented = wrapped(CoreError::NotImplemented {
            what: "copy of a wim image",
        });
        assert_eq!(
            outcome_from_core_error(not_implemented),
            Outcome::Refused {
                code: "not_implemented".to_string(),
                message: "step 'wipe': not implemented yet: copy of a wim image".to_string(),
            }
        );
        let invalid = wrapped(CoreError::invalid("bad sector size"));
        assert_eq!(
            outcome_from_core_error(invalid),
            Outcome::Refused {
                code: "invalid_input".to_string(),
                message: "step 'wipe': invalid input: bad sector size".to_string(),
            }
        );
    }

    #[test]
    fn outcome_mapping_fails_io_verify_and_other_classes() {
        let io = wrapped(CoreError::io("disk", io::Error::other("media error")));
        assert_eq!(
            outcome_from_core_error(io),
            Outcome::Failed {
                code: "io".to_string(),
                message: "step 'wipe': I/O error at 'disk': media error".to_string(),
            }
        );
        let verify = wrapped(CoreError::Verify {
            message: "digest differs at 4".to_string(),
        });
        assert_eq!(
            outcome_from_core_error(verify),
            Outcome::Failed {
                code: "verify".to_string(),
                message: "step 'wipe': image verification failed: digest differs at 4".to_string(),
            }
        );
        let other = CoreError::WimUnavailable;
        assert_eq!(
            outcome_from_core_error(other),
            Outcome::Failed {
                code: "pipeline".to_string(),
                message: "wimlib is not available: this build has no libwim".to_string(),
            }
        );
    }

    #[test]
    fn outcome_mapping_sanitizes_the_message() {
        let invalid = CoreError::invalid("bad \u{1b}[2J input");
        assert_eq!(
            outcome_from_core_error(invalid),
            Outcome::Refused {
                code: "invalid_input".to_string(),
                message: "invalid input: bad ?[2J input".to_string(),
            }
        );
    }

    // -- opener geometry derivation -------------------------------------

    #[test]
    fn derivation_reads_table_and_layout_from_the_steps() {
        let agreeing_plan = plan(
            vec![
                mklabel(Scheme::Gpt),
                mkpart(Scheme::Gpt, Layout::WindowsToGo),
            ],
            Scheme::Mbr, // the planner's intent disagrees; steps win
        );
        assert_eq!(
            opener_table_kind(&agreeing_plan).expect("agreeing steps derive"),
            (TableKind::Gpt, LayoutKind::WindowsToGo)
        );

        let uefi_plan = plan(vec![mkpart(Scheme::Gpt, Layout::UefiNtfs)], Scheme::Mbr);
        assert_eq!(
            opener_table_kind(&uefi_plan).expect("mkpart alone derives"),
            (TableKind::Gpt, LayoutKind::UefiNtfs)
        );
    }

    #[test]
    fn derivation_falls_back_to_options_scheme_and_single_layout() {
        let plan = plan(vec![Step::Wipe, Step::Finalize], Scheme::Gpt);
        assert_eq!(
            opener_table_kind(&plan).expect("fallback derives"),
            (TableKind::Gpt, LayoutKind::Single)
        );
    }

    #[test]
    fn derivation_refuses_disagreeing_mklabel_and_mkpart_steps() {
        let plan = plan(
            vec![mklabel(Scheme::Mbr), mkpart(Scheme::Gpt, Layout::Single)],
            Scheme::Mbr,
        );
        let message = opener_table_kind(&plan).expect_err("disagreeing steps refuse");
        assert!(message.contains("mklabel asks for 'mbr'"), "{message}");
        assert!(message.contains("mkpart asks for 'gpt'"), "{message}");
    }

    #[test]
    fn derivation_refuses_disagreeing_mkpart_steps() {
        let plan = plan(
            vec![
                mkpart(Scheme::Mbr, Layout::Single),
                mkpart(Scheme::Mbr, Layout::Persistence),
            ],
            Scheme::Mbr,
        );
        let message = opener_table_kind(&plan).expect_err("disagreeing layouts refuse");
        assert!(message.contains("asks for 'single'"), "{message}");
        assert!(message.contains("also for 'persistence'"), "{message}");
    }
}
