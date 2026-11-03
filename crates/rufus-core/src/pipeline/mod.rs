//! The S17 write pipeline (slice 1 of 10): the step machine that turns
//! a [`Plan`] into block I/O with progress,
//! cancellation and an honest refusal contract.
//!
//! The machine walks `plan.steps` in order through [`run`], emitting
//! [`Event`]s to a [`Reporter`] and timing every step. Step coverage
//! this slice is [`Finalize`](rufus_proto::Step::Finalize) only; every
//! other step refuses by name (see [`run`]). Later slices fill the
//! machine without changing its shape:
//!
//! * slice 2: wipe, mklabel, mkpart, mkfs;
//! * slice 3: write (and with it mid-step cancellation);
//! * S19: bootloader.
//!
//! [`step_name`] is the one shared snake_case vocabulary for step
//! identifiers, so the CLI and the machine cannot drift apart.

pub mod event;
pub mod opener;
pub mod target;

pub use event::Event;
pub use event::NullReporter;
pub use event::Reporter;
pub use opener::Opener;
pub use target::Target;

use std::time::Instant;

use rufus_proto::Plan;
use rufus_proto::Step;

use crate::error::CoreError;
use crate::error::Result;

/// Run options. `verify` (read-back check, slice 7) and `badblocks`
/// (surface scan, slice 9) are carried now and honoured then; passing
/// them today keeps the CLI signature stable. Accepted without acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    /// Read back and verify the written image (honoured from slice 7).
    pub verify: bool,
    /// Scan the surface for bad blocks (honoured from slice 9).
    pub badblocks: bool,
}

/// Wall time of one finished step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepTiming {
    /// Snake-case step identifier (see [`step_name`]).
    pub step: &'static str,
    /// Step wall time in milliseconds, from the same clock as
    /// [`RunReport::millis`].
    pub millis: u64,
}

/// What a finished [`run`] hands back: per-step timings plus the whole
/// run's wall time. This is [`run`]'s output, not a validated ledger —
/// every field is plain data. A refused or cancelled run returns `Err`
/// instead — the timings of the steps that ran survive only in the
/// [`Reporter`]'s event log (see the `report_counts_only_completed_steps`
/// test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// One entry per step that ran to completion, in run order.
    pub steps: Vec<StepTiming>,
    /// Whole-run wall time in milliseconds.
    pub millis: u64,
}

/// The snake_case identifier of a plan step (`wipe`, `mklabel`,
/// `mkpart`, `mkfs`, `write`, `bootloader`, `finalize`): the one shared
/// vocabulary for [`Event`] payloads, so the CLI and the machine cannot
/// drift. The match is exhaustive — a new [`Step`] variant fails to
/// compile here until it is named.
pub fn step_name(step: &Step) -> &'static str {
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

/// Run one step. Only [`Finalize`](rufus_proto::Step::Finalize) is
/// implemented: flush the device, re-read its partitions and report the
/// target size. Later slices add arms here without touching [`run`].
fn run_step(step: &Step, opener: &dyn Opener, reporter: &mut dyn Reporter) -> Result<()> {
    match step {
        Step::Finalize => {
            let device = opener.device()?;
            device.flush()?;
            device.reread_partitions()?;
            reporter.event(Event::Message {
                level: "info",
                text: format!("finalized {} byte target", device.size()),
            });
            Ok(())
        }
        other => Err(CoreError::invalid(format!(
            "pipeline step '{}' is not implemented yet",
            step_name(other)
        ))),
    }
}

/// Run `plan.steps` in order against `opener`'s stores, reporting to
/// `reporter`.
///
/// Per step the machine emits [`Event::StepStarted`], runs the step,
/// emits [`Event::StepFinished`] and records a [`StepTiming`]; a clean
/// run ends with [`Event::Finished`] and a [`RunReport`]. Cancellation
/// is checked at every step boundary and reports
/// `CoreError::invalid("the write was cancelled before step '<name>'")`
/// with the step named; mid-step cancellation (at most 200 ms between
/// checks) arrives with the write loop in slice 3, the only
/// long-running step. Refusing is the honest contract throughout: an
/// unimplemented step errors by name rather than silently skipping, so
/// no plan can ship a half-written stick, and unknown/future plan steps
/// refuse at parse time (serde) rather than guessing here. Flush
/// policy: only `Finalize` flushes today, so a plan whose later step
/// fails is not flushed afterwards; the write step will flush before
/// reporting its own failure from slice 3.
pub fn run(
    plan: &Plan,
    opener: &dyn Opener,
    options: &RunOptions,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<RunReport> {
    // Carried for slice 7/9; accepted without acting this slice.
    let _ = options;
    let run_started = Instant::now();
    let total = plan.steps.len();
    let mut steps = Vec::new();
    for (index, step) in plan.steps.iter().enumerate() {
        if cancelled() {
            return Err(CoreError::invalid(format!(
                "the write was cancelled before step '{}'",
                step_name(step)
            )));
        }
        reporter.event(Event::StepStarted {
            index,
            total,
            step: step_name(step),
        });
        let step_started = Instant::now();
        run_step(step, opener, reporter)?;
        let millis = step_started.elapsed().as_millis() as u64;
        reporter.event(Event::StepFinished {
            index,
            step: step_name(step),
            millis,
        });
        steps.push(StepTiming {
            step: step_name(step),
            millis,
        });
    }
    let millis = run_started.elapsed().as_millis() as u64;
    reporter.event(Event::Finished { millis });
    Ok(RunReport { steps, millis })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use rufus_proto::BootloaderMode;
    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::Scheme;
    use rufus_proto::WriteMode;

    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::pipeline::event::VecReporter;
    use crate::pipeline::target::Target;
    use crate::pipeline::target::VecTarget;

    /// A test [`Opener`] sharing one [`VecTarget`] as its device, so the
    /// test observes flushes and bytes after the run.
    #[derive(Debug, Clone)]
    struct TestOpener {
        target: VecTarget,
    }

    impl TestOpener {
        fn new(len: u64) -> Self {
            Self {
                target: VecTarget::new(len, 512).expect("fixture target fits"),
            }
        }
    }

    impl Opener for TestOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }
    }

    /// A plan carrying exactly `steps`; device, image and options are
    /// fixed dummy values (the skeleton never reads them).
    fn test_plan(steps: Vec<Step>) -> Plan {
        Plan {
            version: rufus_proto::PLAN_VERSION,
            created_by: "pipeline-test".to_string(),
            device: DeviceRef {
                path: "/dev/test".to_string(),
                block_device: false,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: "test.iso".to_string(),
                size_bytes: 0,
                sha256: "0".repeat(64),
                kind: ImageKind::Raw,
            },
            options: Options {
                scheme: Scheme::Mbr,
                target: rufus_proto::Target::Dual,
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

    fn run_options() -> RunOptions {
        RunOptions {
            verify: false,
            badblocks: false,
        }
    }

    #[test]
    fn headline_types_reexport_at_the_pipeline_root() {
        // Pin for the lib.rs docs and external users: these resolve at
        // `pipeline::`, not only at the submodules.
        use crate::pipeline::Event;
        use crate::pipeline::Opener;
        use crate::pipeline::Reporter;
        use crate::pipeline::Target;

        fn takes_reporter(_: &dyn Reporter) {}
        fn takes_opener(_: &dyn Opener) {}
        fn takes_target(_: &dyn Target) {}

        let opener = TestOpener::new(512);
        takes_opener(&opener);
        takes_target(&opener.target);
        takes_reporter(&VecReporter::new());
        assert!(matches!(
            Event::Finished { millis: 0 },
            Event::Finished { .. }
        ));
    }

    #[test]
    fn finalize_only_plan_flushes_and_reseconds() {
        let opener = TestOpener::new(8 * 1024 * 1024);
        let mut reporter = VecReporter::new();
        let report = run(
            &test_plan(vec![Step::Finalize]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("finalize runs");
        assert_eq!(opener.target.flushes(), 1);
        assert_eq!(opener.target.rereads(), 1);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].step, "finalize");
    }

    #[test]
    fn unimplemented_step_is_refused_by_name() {
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("wipe is not implemented yet");
        let text = error.to_string();
        assert!(text.contains("wipe"), "{text}");
        assert!(text.contains("not implemented"), "{text}");
    }

    #[test]
    fn events_are_emitted_in_order() {
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Finalize]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("finalize runs");
        assert!(
            matches!(
                reporter.events(),
                [
                    Event::StepStarted {
                        index: 0,
                        total: 1,
                        step: "finalize"
                    },
                    Event::Message { .. },
                    Event::StepFinished {
                        index: 0,
                        step: "finalize",
                        ..
                    },
                    Event::Finished { .. }
                ]
            ),
            "events out of order: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn cancellation_before_a_step_is_reported() {
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        // False for the first boundary check, true ever after: the
        // second step never starts.
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan(vec![Step::Finalize, Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 1
            },
        )
        .expect_err("the second step cancels");
        let text = error.to_string();
        assert!(text.contains("cancelled"), "{text}");
        assert!(text.contains("wipe"), "{text}");
    }

    #[test]
    fn step_names_match_the_plan_variants() {
        for (step, name) in [
            (Step::Wipe, "wipe"),
            (
                Step::Mklabel {
                    scheme: Scheme::Gpt,
                },
                "mklabel",
            ),
            (
                Step::Mkpart {
                    scheme: Scheme::Mbr,
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
                    mode: WriteMode::Dd,
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
        ] {
            assert_eq!(step_name(&step), name);
        }
    }

    #[test]
    fn report_counts_only_completed_steps() {
        // A refusal returns Err, so the completed timings survive only
        // in the reporter's event log: one finished step, no run
        // Finished.
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![
                Step::Finalize,
                Step::Write {
                    mode: WriteMode::Dd,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("write is not implemented yet");
        let finished: Vec<&str> = reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::StepFinished { step, .. } => Some(*step),
                _ => None,
            })
            .collect();
        assert_eq!(finished, ["finalize"]);
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::Finished { .. })),
            "no run Finished after a refusal: {:?}",
            reporter.events()
        );
    }
}
