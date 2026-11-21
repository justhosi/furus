//! The S17 write pipeline: the step machine that turns a [`Plan`]
//! into block I/O with progress, cancellation and an honest refusal
//! contract.
//!
//! The machine walks `plan.steps` in order through [`run`], emitting
//! [`Event`]s to a [`Reporter`] and timing every step. Every step is
//! wired: wipe, mklabel, mkpart, mkfs and finalize, both write paths
//! (the [`Dd`](furus_proto::WriteMode::Dd) stream and the
//! [`Copy`](furus_proto::WriteMode::Copy) file-tree copy), and the
//! bootloader step ([`bootloader`] installs Syslinux, GRUB2 BIOS,
//! GRUB4DOS, FreeDOS, KolibriOS or MS-DOS on a FAT32 data partition,
//! or the UEFI:NTFS shim for an NTFS or exFAT one; `Auto` probes the
//! tree-backed families in that order). Later features (persistence
//! and the rest) stay unwired.
//!
//! [`step_name`] is the one shared snake_case vocabulary for step
//! identifiers, so the CLI and the machine cannot drift apart.

pub mod badblocks;
pub(crate) mod bootloader;
pub(crate) mod decompress;
pub mod event;
pub mod mkfs;
pub mod mklabel;
pub mod mkpart;
pub mod opener;
pub mod steps;
pub mod target;
pub mod wipe;
pub mod write;

pub use event::Event;
pub use event::NullReporter;
pub use event::Reporter;
pub use opener::MountedPartition;
pub use opener::Opener;
pub use target::Target;

use std::time::Duration;
use std::time::Instant;

use furus_proto::Plan;
use furus_proto::Step;

use crate::error::CoreError;
use crate::error::Result;
use crate::log::Level;
use crate::log::Logger;

/// Run options. `verify` reads the written bytes back and compares
/// them to the plan digest; `retries`, `retry_delay` and `reset_usb`
/// tune the write chunk retry policy (see `write_chunk` in
/// [`write`](crate::pipeline::write)); `badblocks` runs the surface
/// scan at the end of [`Wipe`](crate::pipeline::wipe::run) when set.
/// The format label does not live here: it comes from the plan step,
/// and image-derived label defaults stay future work (the formatter
/// default applies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    /// Read back and verify the written image against the plan
    /// digest. Runs without a write step (say `[Wipe]` alone) verify
    /// nothing and warn about nothing: there are no written bytes to
    /// compare.
    pub verify: bool,
    /// Scan the surface for bad blocks: runs at the end of
    /// [`Wipe`](crate::pipeline::wipe::run) after the zeroing when
    /// set (see [`badblocks`](crate::pipeline::badblocks) for the
    /// placement and the destructive-scan contract).
    pub badblocks: bool,
    /// Chunk write retries after the initial attempt: 3 is the
    /// reference policy (`0x140010a40` gives up with `if (3 < uVar4)`),
    /// and the seam that keeps tests instant (they pass small counts
    /// with a zero delay).
    pub retries: u32,
    /// Delay between retries: 5 s is the reference policy (`Sleep(5000)`
    /// after each `Retrying in %d seconds...`).
    pub retry_delay: Duration,
    /// Reset the USB device once the retry budget is spent, then retry
    /// the chunk once more. Off by default: a reset re-enumerates the
    /// bus and is only worth it on a flaky stick.
    pub reset_usb: bool,
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
/// every field is plain data, and a formatter refusal can leave the
/// partition partially written (at least a zeroed data area), so a
/// failed run is not a rollback. A refused or cancelled run returns
/// `Err` instead — the timings of the steps that ran survive only in
/// the [`Reporter`]'s event log (see the
/// `report_counts_only_completed_steps` test).
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

/// Run one step through the run context: wipe, label, partition,
/// filesystem, write and bootloader stages live in their own modules
/// (the bootloader arm runs [`bootloader::run`]: Syslinux, GRUB2 BIOS,
/// GRUB4DOS, FreeDOS, KolibriOS or MS-DOS on FAT32, the UEFI:NTFS shim on NTFS
/// or exFAT).
/// The match is exhaustive, so a new
/// [`Step`] variant fails to compile here (and in [`step_name`]) until
/// it is handled.
fn run_step(plan: &Plan, step: &Step, ctx: &mut steps::RunContext<'_>) -> Result<()> {
    match step {
        Step::Wipe => wipe::run(ctx),
        Step::Mklabel { scheme } => mklabel::run(ctx, scheme),
        Step::Mkpart { scheme, layout } => {
            mkpart::run(ctx, scheme, layout, &plan.options.filesystem)
        }
        Step::Mkfs {
            filesystem,
            label,
            cluster_bytes,
            quick,
        } => mkfs::run(ctx, filesystem, label, cluster_bytes, *quick),
        Step::Write { mode } => write::run(ctx, mode, &plan.image, &plan.options.filesystem),
        Step::Bootloader { mode } => {
            // The plan's user-supplied MS-DOS directory rides in for
            // the `MsDos` arm only; every other arm ignores it (`None`
            // elsewhere). An `msdos` plan carries no write step, so the
            // image reference here is the still-required detection
            // record — the arm never opens it, so it needs no
            // readable tree.
            let msdos_dir = plan.options.msdos_dir.as_deref().map(std::path::Path::new);
            bootloader::run(ctx, mode, &plan.image, &plan.options.filesystem, msdos_dir)
        }
        Step::Finalize => {
            let size = ctx.device()?.size();
            ctx.device()?.flush()?;
            ctx.device()?.reread_partitions()?;
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!("finalized {size} byte target"),
            });
            Ok(())
        }
    }
}
///
/// Per step the machine emits [`Event::StepStarted`], runs the step,
/// emits [`Event::StepFinished`] and records a [`StepTiming`]; a clean
/// run ends with [`Event::Finished`] and a [`RunReport`]. Cancellation
/// is checked at every step boundary; a boundary hit refuses wrapped in
/// [`Step`](CoreError::Step) like every in-run error, so the pending
/// step is named. Mid-step cancellation is checked between chunks in
/// the only long-running steps (the write loop, the full-format zero
/// pass). Refusing is the honest contract throughout: an unimplemented
/// step errors by name rather than silently skipping, so no plan can
/// ship a half-written stick, and unknown/future plan steps refuse at
/// parse time (serde) rather than guessing here. Flush policy: write,
/// mkpart and finalize flush before reporting `Ok` (the native
/// formatters flush their volume too); wipe deliberately does not —
/// `Finalize` owns the run's flush there. A step that fails leaves its
/// buffers unflushed, and no later step flushes on its behalf.
pub fn run(
    plan: &Plan,
    opener: &dyn Opener,
    options: &RunOptions,
    reporter: &mut dyn Reporter,
    cancelled: &dyn Fn() -> bool,
) -> Result<RunReport> {
    // `Wipe` reads `badblocks` (the surface scan, see
    // `pipeline::badblocks`); the write step reads `verify`.
    let run_started = Instant::now();
    let total = plan.steps.len();
    let mut ctx = steps::RunContext {
        opener,
        target: None,
        table: None,
        partitioned: None,
        logger: Logger::new(Level::Info),
        reporter,
        cancelled,
        options: *options,
    };
    let mut steps = Vec::new();
    for (index, step) in plan.steps.iter().enumerate() {
        if (ctx.cancelled)() {
            // Wrapped like every in-run error below, so the step that
            // never started is named too.
            return Err(CoreError::Step {
                step: step_name(step),
                source: Box::new(CoreError::Cancelled),
            });
        }
        ctx.reporter.event(Event::StepStarted {
            index,
            total,
            step: step_name(step),
        });
        let step_started = Instant::now();
        // Every step error carries its step — except `NotImplemented`,
        // whose `what` already names the step (wrapping it would
        // stutter): the JSONL consumer can otherwise only infer the
        // step from the last `step_started`.
        run_step(plan, step, &mut ctx).map_err(|error| match error {
            CoreError::NotImplemented { .. } => error,
            other => CoreError::Step {
                step: step_name(step),
                source: Box::new(other),
            },
        })?;
        let millis = step_started.elapsed().as_millis() as u64;
        ctx.reporter.event(Event::StepFinished {
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
    ctx.reporter.event(Event::Finished { millis });
    Ok(RunReport { steps, millis })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
