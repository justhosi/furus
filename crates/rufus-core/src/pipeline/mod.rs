//! The S17 write pipeline: the step machine that turns a [`Plan`]
//! into block I/O with progress, cancellation and an honest refusal
//! contract.
//!
//! The machine walks `plan.steps` in order through [`run`], emitting
//! [`Event`]s to a [`Reporter`] and timing every step. Five of the
//! seven steps run: wipe, mklabel, mkpart, mkfs and finalize, plus the
//! [`Dd`](rufus_proto::WriteMode::Dd) write path. Two refuse by name:
//! [`Bootloader`](rufus_proto::Step::Bootloader) (no installer until
//! S19) and [`Copy`](rufus_proto::WriteMode::Copy) (file-tree copying
//! is implemented; its plan and write-path wiring arrives in slice
//! 19).
//!
//! [`step_name`] is the one shared snake_case vocabulary for step
//! identifiers, so the CLI and the machine cannot drift apart.

pub mod badblocks;
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
pub use opener::Opener;
pub use target::Target;

use std::time::Duration;
use std::time::Instant;

use rufus_proto::Plan;
use rufus_proto::Step;

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
/// filesystem and write stages live in their own modules; the
/// bootloader arm refuses until S19. The match is exhaustive, so a new
/// [`Step`] variant fails to compile here (and in [`step_name`]) until
/// it is handled.
fn run_step(plan: &Plan, step: &Step, ctx: &mut steps::RunContext<'_>) -> Result<()> {
    match step {
        Step::Wipe => wipe::run(ctx),
        Step::Mklabel { scheme } => mklabel::run(ctx, scheme),
        Step::Mkpart { scheme } => mkpart::run(ctx, scheme),
        Step::Mkfs {
            filesystem,
            label,
            cluster_bytes,
            quick,
        } => mkfs::run(ctx, filesystem, label, cluster_bytes, *quick),
        Step::Write { mode } => write::run(ctx, mode, &plan.image),
        Step::Bootloader { .. } => Err(CoreError::NotImplemented {
            what: "bootloader installation (S19)",
        }),
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
    // `badblocks` is carried for slice 9; the write step reads
    // `verify` today.
    let run_started = Instant::now();
    let total = plan.steps.len();
    let mut ctx = steps::RunContext {
        opener,
        target: None,
        table: None,
        partitioned: false,
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
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

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
    use crate::hash::Algo;
    use crate::hash::hash_file_with;
    use crate::pipeline::event::VecReporter;
    use crate::pipeline::target::Target;
    use crate::pipeline::target::VecTarget;

    /// A test [`Opener`] sharing one [`VecTarget`] as its device, so the
    /// test observes flushes and bytes after the run. Counts `device()`
    /// calls so tests can pin the lazy open.
    #[derive(Debug, Clone)]
    struct TestOpener {
        target: VecTarget,
        device_calls: Cell<usize>,
    }

    impl TestOpener {
        fn new(len: u64) -> Self {
            Self {
                target: VecTarget::new(len, 512).expect("fixture target fits"),
                device_calls: Cell::new(0),
            }
        }

        fn device_calls(&self) -> usize {
            self.device_calls.get()
        }
    }

    impl Opener for TestOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            self.device_calls.set(self.device_calls.get() + 1);
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            // The shared fixture has no partition node; layout tests
            // use LayoutOpener instead.
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Volume`] view over a [`VecTarget`]'s bytes at a base offset:
    /// the test-only stand-in for a partition volume. `VecVolume` owns
    /// its bytes and cannot share them, so this thin offset wrapper
    /// over the same shared store lets `Mkfs` write into the target
    /// image the table described.
    #[derive(Debug, Clone)]
    struct PartView {
        target: VecTarget,
        base: u64,
        len: u64,
    }

    impl PartView {
        fn new(target: &VecTarget, base: u64, len: u64) -> Result<Self> {
            let end = base.checked_add(len).ok_or_else(|| {
                CoreError::invalid(format!(
                    "test partition view at offset {base} with length {len} overflows"
                ))
            })?;
            if end > target.size() {
                return Err(CoreError::invalid(format!(
                    "test partition view {base}..{end} runs past the {} byte target",
                    target.size()
                )));
            }
            Ok(Self {
                target: target.clone(),
                base,
                len,
            })
        }
    }

    impl Volume for PartView {
        fn total_bytes(&self) -> u64 {
            self.len
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("test partition read overflows"))?;
            if end > self.len {
                return Err(CoreError::invalid(format!(
                    "test partition read of {} bytes at offset {offset} runs past the {} byte view",
                    buf.len(),
                    self.len
                )));
            }
            self.target.read_at(self.base + offset, buf)
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("test partition write overflows"))?;
            if end > self.len {
                return Err(CoreError::invalid(format!(
                    "test partition write of {} bytes at offset {offset} runs past the {} byte view",
                    buf.len(),
                    self.len
                )));
            }
            self.target.write_all_at(self.base + offset, buf)
        }

        fn flush(&mut self) -> Result<()> {
            self.target.flush()
        }

        fn sector_size(&self) -> u32 {
            self.target.sector_size()
        }
    }

    /// A fixture [`Opener`] whose partition is a [`PartView`] over the
    /// target bytes at the planned data offset, so `Mkfs` formats the
    /// bytes the table described. `part_path` is a scratch node path
    /// the tool-based formatters would run against (never touched by
    /// the covered native paths).
    #[derive(Debug, Clone)]
    struct LayoutOpener {
        target: VecTarget,
        part_base: u64,
        part_len: u64,
        part_path: std::path::PathBuf,
    }

    impl LayoutOpener {
        fn new(len: u64, part_base: u64, part_len: u64, part_path: std::path::PathBuf) -> Self {
            Self {
                target: VecTarget::new(len, 512).expect("fixture target fits"),
                part_base,
                part_len,
                part_path,
            }
        }
    }

    impl Opener for LayoutOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(PartView::new(
                &self.target,
                self.part_base,
                self.part_len,
            )?))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Ok(self.part_path.clone())
        }
    }

    /// A plan carrying exactly `steps`; device, image and options are
    /// fixed dummy values (only the write step reads the image).
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
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        }
    }

    /// [`run_options`] with the read-back check on.
    fn verify_options() -> RunOptions {
        RunOptions {
            verify: true,
            badblocks: false,
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        }
    }

    /// A plan carrying `steps` over the image file at `path`, sealed
    /// with the file's real SHA-256: verify tests must describe the
    /// digest the read-back compares against.
    fn test_plan_verified(steps: Vec<Step>, path: &std::path::Path, size: u64) -> Plan {
        let mut plan = test_plan_image(steps, path, size);
        plan.image.sha256 = hash_file_with(Algo::Sha256, path).expect("fixture hashes");
        plan
    }

    /// 16 MiB layout target with the data partition at the 1 MiB grid
    /// (LBA 2048): the `Single` layout the planner pins, verified by
    /// `mkpart_stamps_a_signed_mbr` below rather than assumed silently.
    /// 64 MiB so FAT32 formats fit: the filesystem needs at least 65525
    /// data clusters, which a 15 MiB partition cannot provide.
    const LAYOUT_LEN: u64 = 64 * 1024 * 1024;
    /// Partition base in bytes (LBA 2048 at 512-byte sectors).
    const PART_BASE: u64 = 1024 * 1024;
    /// Partition length in bytes (to the last LBA).
    const PART_LEN: u64 = 63 * 1024 * 1024;
    /// One mebibyte, for window arithmetic in assertions.
    const MIB: u64 = 1024 * 1024;

    /// A layout opener over a fresh target with a scratch node path;
    /// the scratch dir returns alongside so it outlives the run.
    fn layout_opener() -> (tempfile::TempDir, LayoutOpener) {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let opener =
            LayoutOpener::new(LAYOUT_LEN, PART_BASE, PART_LEN, scratch.path().join("part"));
        (scratch, opener)
    }

    /// Fill the whole target with `byte`.
    fn prefill(opener: &LayoutOpener, byte: u8) {
        opener
            .target
            .write_all_at(0, &vec![byte; LAYOUT_LEN as usize])
            .expect("prefill writes");
    }

    /// Deterministic patterned bytes: byte `i` holds `i % 251`.
    fn pattern_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Write `bytes` to a temp file; returns its path and length.
    fn image_file(
        scratch: &tempfile::TempDir,
        name: &str,
        bytes: &[u8],
    ) -> (std::path::PathBuf, u64) {
        let path = scratch.path().join(name);
        std::fs::write(&path, bytes).expect("fixture image writes");
        (path, bytes.len() as u64)
    }

    /// A plan carrying `steps` over the image file at `path` (`size`
    /// bytes): write tests point it at temp files.
    fn test_plan_image(steps: Vec<Step>, path: &std::path::Path, size: u64) -> Plan {
        let mut plan = test_plan(steps);
        plan.image.path = path.to_str().expect("scratch path is UTF-8").to_string();
        plan.image.size_bytes = size;
        plan
    }

    /// A [`Target`] reporting one byte short of every cancellable write
    /// without cancelling: the faulty device behind the short-count
    /// test, delegating everything else to an inner [`VecTarget`].
    #[derive(Debug, Clone)]
    struct ShortTarget {
        inner: VecTarget,
    }

    impl Target for ShortTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            let done = self
                .inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)?;
            Ok(done.saturating_sub(1))
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`ShortTarget`].
    #[derive(Debug, Clone)]
    struct ShortOpener {
        target: ShortTarget,
    }

    /// A [`Target`] reporting one byte *more* than every cancellable
    /// write moved: the impossible count behind the over-count refusal,
    /// delegating everything else to an inner [`VecTarget`].
    #[derive(Debug, Clone)]
    struct OverTarget {
        inner: VecTarget,
    }

    impl Target for OverTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            let done = self
                .inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)?;
            Ok(done.saturating_add(1))
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`OverTarget`].
    #[derive(Debug, Clone)]
    struct OverOpener {
        target: OverTarget,
    }

    impl Opener for OverOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    impl Opener for ShortOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Target`] reporting `size` while storing into a small shared
    /// [`VecTarget`]: the stand-in for a multi-gigabyte device no test
    /// may allocate. All I/O must stay inside the backing store; the
    /// tests only ever touch the image window.
    #[derive(Debug, Clone)]
    struct BigTarget {
        inner: VecTarget,
        size: u64,
    }

    impl Target for BigTarget {
        fn size(&self) -> u64 {
            self.size
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`BigTarget`].
    #[derive(Debug, Clone)]
    struct BigOpener {
        target: BigTarget,
    }

    impl Opener for BigOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// Collect `(done, total)` from every `Progress` event, in order.
    fn progresses(reporter: &VecReporter) -> Vec<(u64, Option<u64>)> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Progress { done, total, .. } => Some((*done, *total)),
                _ => None,
            })
            .collect()
    }

    /// Collect the texts of every warning `Message`, in order.
    fn warnings(reporter: &VecReporter) -> Vec<&str> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message {
                    level: "warn",
                    text,
                } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    fn write_dd() -> Step {
        Step::Write {
            mode: WriteMode::Dd,
        }
    }

    /// Compress `bytes` with the host `program -c` (stdout capture)
    /// into `name` under `scratch`; returns the archive path and its
    /// length. Deterministic input, no network, no fixtures: every
    /// format test below shares this helper so the four tools cannot
    /// drift apart in how they are fed.
    fn compressed_image(
        scratch: &tempfile::TempDir,
        name: &str,
        program: &str,
        bytes: &[u8],
    ) -> (std::path::PathBuf, u64) {
        let raw = scratch.path().join(format!("{name}.raw"));
        std::fs::write(&raw, bytes).expect("raw fixture writes");
        let output = std::process::Command::new(program)
            .arg("-c")
            .arg(&raw)
            .output()
            .expect("the host tool runs");
        assert!(output.status.success(), "{program} compresses");
        let path = scratch.path().join(name);
        std::fs::write(&path, &output.stdout).expect("archive writes");
        (path, output.stdout.len() as u64)
    }

    /// A plan carrying `steps` over the archive at `path` (`size`
    /// compressed bytes) of container `kind`.
    fn test_plan_compressed(
        steps: Vec<Step>,
        path: &std::path::Path,
        size: u64,
        kind: ImageKind,
    ) -> Plan {
        let mut plan = test_plan_image(steps, path, size);
        plan.image.kind = kind;
        plan
    }

    /// Every `Progress` event as `(done, total)`, in emission order.
    fn full_progress(reporter: &VecReporter) -> Vec<(u64, Option<u64>, u64, Option<u64>)> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Progress {
                    done,
                    total,
                    bytes_per_second,
                    eta_seconds,
                    ..
                } => Some((*done, *total, *bytes_per_second, *eta_seconds)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn gzip_stream_is_written_verbatim() {
        // Two chunks of patterned payload (256 KiB each plus a byte, so
        // the loop runs more than once) through `[Write, Finalize]`.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let payload = pattern_bytes(2 * 256 * 1024 + 1);
        let (path, size) = compressed_image(&scratch, "image.gz", "gzip", &payload);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let report = run(
            &test_plan_compressed(
                vec![write_dd(), Step::Finalize],
                &path,
                size,
                ImageKind::Gzip,
            ),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a gzip image streams");
        assert_eq!(report.steps.len(), 2);
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[..payload.len()], &payload[..]);
        let progress = full_progress(&reporter);
        assert!(!progress.is_empty(), "a stream still reports");
        let (last_done, last_total, last_rate, _) =
            progress.last().copied().expect("a final progress event");
        // Exactly one final event with the total known: at EOF the
        // decoded size is honest, while every intermediate carries no
        // total (and no ETA — nothing remains to estimate mid-stream).
        assert_eq!(
            (last_done, last_total),
            (payload.len() as u64, Some(payload.len() as u64))
        );
        assert!(
            progress[..progress.len() - 1]
                .iter()
                .all(|(_, total, _, eta)| total.is_none() && eta.is_none()),
            "no intermediate event claims a total: {progress:?}"
        );
        assert!(last_rate > 0, "the rate is measured: {progress:?}");
    }

    #[test]
    fn xz_bzip2_and_zstd_stream_too() {
        // The other three formats through the same helper and the same
        // assertions, so no tool gets a private code path.
        let scratch = tempfile::tempdir().expect("scratch fits");
        for (program, kind, suffix) in [
            ("xz", ImageKind::Xz, "image.xz"),
            ("bzip2", ImageKind::Bzip2, "image.bz2"),
            ("zstd", ImageKind::Zstd, "image.zst"),
        ] {
            let payload = pattern_bytes(50_000);
            let (path, size) = compressed_image(&scratch, suffix, program, &payload);
            let opener = TestOpener::new(8 * MIB);
            let mut reporter = VecReporter::new();
            run(
                &test_plan_compressed(vec![write_dd(), Step::Finalize], &path, size, kind),
                &opener,
                &run_options(),
                &mut reporter,
                &|| false,
            )
            .expect("{program} streams");
            let bytes = opener.target.bytes().expect("bytes read back");
            assert_eq!(
                &bytes[..payload.len()],
                &payload[..],
                "{program} is verbatim"
            );
            let progress = progresses(&reporter);
            assert_eq!(
                progress.last().copied(),
                Some((payload.len() as u64, Some(payload.len() as u64))),
                "{program} ends with a known total"
            );
        }
    }

    #[test]
    fn corrupt_stream_fails_and_is_not_reported_as_success() {
        // A valid gzip header followed by garbage: the tool emits a
        // prefix (maybe nothing at all), then exits non-zero — the run
        // must fail, never `Ok`, and never `step_finished` for `write`.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let payload = pattern_bytes(10_000);
        let (path, _) = compressed_image(&scratch, "image.gz", "gzip", &payload);
        let mut archive = std::fs::read(&path).expect("archive reads");
        archive.truncate(20);
        archive.extend_from_slice(b"garbage-garbage-garbage");
        let (path, size) = image_file(&scratch, "broken.gz", &archive);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_compressed(vec![write_dd()], &path, size, ImageKind::Gzip),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a corrupt archive refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("gzip"), "{text}");
        assert!(text.contains("failed"), "{text}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { step: "write", .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn oversized_stream_is_refused_before_the_target_overflows() {
        // A 2 MiB payload decoded onto a 1 MiB target: four full chunks
        // stream, then the fifth would cross the end — refuse naming
        // both counts instead of writing past it.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let payload = pattern_bytes(2 * MIB as usize);
        let (path, size) = compressed_image(&scratch, "image.gz", "gzip", &payload);
        let opener = TestOpener::new(MIB);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_compressed(vec![write_dd()], &path, size, ImageKind::Gzip),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an overflowing archive refuses");
        let text = error.to_string();
        assert!(text.contains("1310720"), "{text}");
        assert!(text.contains("1048576"), "{text}");
        assert!(text.contains("write"), "{text}");
        // The prefix streamed before the refusal is real decoded bytes;
        // nothing past the device end was ever written.
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(bytes.len() as u64, MIB);
        assert_eq!(&bytes[..MIB as usize], &payload[..MIB as usize]);
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { step: "write", .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn cancelled_stream_kills_the_decompressor() {
        // Twelve chunks of payload with the flag flipping after three
        // checks: the run refuses as cancelled (step-wrapped, no
        // `step_finished`), the child is reaped by the cancel — and a
        // control run right after still spawns cleanly, which is the
        // observable proof no zombie wedged the helper.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let payload = pattern_bytes(3 * MIB as usize);
        let (path, size) = compressed_image(&scratch, "image.gz", "gzip", &payload);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan_compressed(vec![write_dd()], &path, size, ImageKind::Gzip),
            &opener,
            &run_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 3
            },
        )
        .expect_err("a cancelled stream refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { step: "write", .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
        // Control run on a fresh target: spawning still works.
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        run(
            &test_plan_compressed(vec![write_dd()], &path, size, ImageKind::Gzip),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a control run spawns cleanly after the cancel");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[..payload.len()], &payload[..]);
    }

    #[test]
    fn raw_write_copies_the_image_and_reports_full_progress() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(5 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let report = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("raw write runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[..size as usize], &content[..]);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].step, "write");
        let progress = progresses(&reporter);
        assert!(!progress.is_empty(), "a fast write still reports 100%");
        let (last_done, last_total) = progress.last().copied().expect("a final progress event");
        assert_eq!((last_done, last_total), (size, Some(size)));
        assert!(
            progress.iter().all(|(done, _)| *done <= size),
            "no progress past the total"
        );
    }

    #[test]
    fn raw_write_refuses_an_image_larger_than_the_target() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(4 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(2 * MIB);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an oversize image refuses before writing");
        let text = error.to_string();
        assert!(text.contains("4194304"), "{text}");
        assert!(text.contains("2097152"), "{text}");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes.iter().all(|&byte| byte == 0), "zero bytes written");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { .. })),
            "no step finished: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn raw_write_refuses_a_plan_size_that_disagrees_with_the_file() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size + 1),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a disagreeing plan size refuses");
        let text = error.to_string();
        assert!(text.contains(&size.to_string()), "{text}");
        assert!(text.contains(&(size + 1).to_string()), "{text}");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "refused before writing"
        );
    }

    #[test]
    fn raw_write_zeroes_only_the_partial_tail_sector() {
        // 2 sectors plus 17 bytes at 512-byte sectors: the tail zeroes
        // up to byte 1536, and byte 1536 keeps its old pattern.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(2 * 512 + 17);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        assert_eq!(size, 1041);
        let opener = TestOpener::new(8 * MIB);
        opener
            .target
            .write_all_at(0, &vec![0xAAu8; 8 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("raw write runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[..size as usize], &content[..]);
        assert!(
            bytes[size as usize..1536].iter().all(|&byte| byte == 0),
            "the tail zeroes to the sector boundary"
        );
        assert_eq!(bytes[1536], 0xAA, "past the boundary the pattern survives");
    }

    #[test]
    fn short_cancellable_write_is_reported_as_cancelled() {
        // The faulty target reports one byte short without cancelling:
        // the run must refuse with the cancellation wording rather than
        // reporting success.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(2 * 256 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = ShortOpener {
            target: ShortTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a short count refuses");
        let text = error.to_string();
        assert!(text.contains("cancelled"), "{text}");
        assert!(text.contains("write"), "{text}");
    }

    #[test]
    fn over_count_write_is_refused_as_impossible() {
        // The faulty target reports one byte more than the chunk holds:
        // that is a broken target, not a cancellation, so the run
        // refuses naming both numbers.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = OverOpener {
            target: OverTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an over count refuses");
        assert!(
            matches!(error, CoreError::Step { .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("1025"), "{text}");
        assert!(text.contains("1024"), "{text}");
        assert!(text.contains("write"), "{text}");
    }

    #[test]
    fn empty_image_emits_one_zero_progress() {
        // A zero-byte image has no chunks to report, but the run still
        // emits exactly one `done: 0, total: Some(0)` progress event —
        // "done instantly" must be distinguishable from "never
        // reported".
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = image_file(&scratch, "empty.bin", &[]);
        assert_eq!(size, 0);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("an empty image writes nothing and succeeds");
        let progress = progresses(&reporter);
        assert_eq!(progress, [(0, Some(0))]);
    }

    #[test]
    fn large_device_warns_and_small_device_does_not() {
        use crate::pipeline::write::LARGE_DRIVE_SLACK;

        let image_len = MIB;
        // Exactly at the boundary: no warning.
        let opener = BigOpener {
            target: BigTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
                size: image_len + LARGE_DRIVE_SLACK,
            },
        };
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = image_file(&scratch, "image.bin", &pattern_bytes(image_len as usize));
        assert_eq!(size, image_len);
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("boundary write runs");
        assert!(
            warnings(&reporter).is_empty(),
            "exactly 4 GiB of slack stays quiet"
        );
        // One byte over: one warning naming the untouched remainder.
        let opener = BigOpener {
            target: BigTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
                size: image_len + LARGE_DRIVE_SLACK + 1,
            },
        };
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("warned write runs");
        let found: Vec<&str> = warnings(&reporter);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("left untouched"), "{}", found[0]);
        let bytes = opener.target.inner.bytes().expect("bytes read back");
        assert_eq!(&bytes[..size as usize], &pattern_bytes(size as usize)[..]);
    }

    #[test]
    fn write_mode_copy_is_refused_by_name() {
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Write {
                mode: WriteMode::Copy,
            }]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("copy is not implemented yet");
        let text = error.to_string();
        assert!(text.contains("copy"), "{text}");
        assert!(text.contains("not implemented"), "{text}");
    }

    #[test]
    fn cancellation_before_the_first_chunk_writes_nothing() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 1
            },
        )
        .expect_err("the first chunk cancels");
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes.iter().all(|&byte| byte == 0), "nothing written");
    }

    #[test]
    fn wipe_zeroes_both_megabyte_windows() {
        let opener = TestOpener::new(8 * MIB);
        opener
            .target
            .write_all_at(0, &vec![0xAAu8; 8 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes[..MIB as usize].iter().all(|&byte| byte == 0));
        assert!(
            bytes[MIB as usize..MIB as usize + 16]
                .iter()
                .all(|&byte| byte == 0xAA)
        );
        assert!(
            bytes[7 * MIB as usize..8 * MIB as usize]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert!(
            bytes[7 * MIB as usize - 16..7 * MIB as usize]
                .iter()
                .all(|&byte| byte == 0xAA)
        );
        assert_eq!(opener.target.discards(), [(0, MIB), (7 * MIB, MIB)]);
        assert_eq!(opener.target.rereads(), 1);
    }

    #[test]
    fn wipe_of_a_tiny_device_zeroes_everything() {
        let opener = TestOpener::new(MIB);
        opener
            .target
            .write_all_at(0, &vec![0xAAu8; MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes.iter().all(|&byte| byte == 0));
        assert_eq!(opener.target.discards(), [(0, MIB)]);
        assert_eq!(opener.target.rereads(), 1);
    }

    #[test]
    fn wipe_uses_the_whole_device_when_smaller_than_two_windows() {
        // Exactly 2 MiB: not smaller, so the two adjacent windows cover
        // the whole device with no overlap.
        let opener = TestOpener::new(2 * MIB);
        opener
            .target
            .write_all_at(0, &vec![0xAAu8; 2 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes.iter().all(|&byte| byte == 0));
        assert_eq!(opener.target.discards(), [(0, MIB), (MIB, MIB)]);
        assert_eq!(opener.target.rereads(), 1);
    }

    #[test]
    fn mklabel_records_without_writing() {
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Mklabel {
                scheme: Scheme::Gpt,
            }]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("mklabel runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(bytes.iter().all(|&byte| byte == 0));
        let messages: Vec<&str> = reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("gpt"), "{}", messages[0]);
    }

    #[test]
    fn mkpart_stamps_a_signed_mbr() {
        let opener = TestOpener::new(LAYOUT_LEN);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("mklabel and mkpart run");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(bytes[510], 0x55);
        assert_eq!(bytes[511], 0xAA);
        assert_eq!(bytes[450], 0x07, "one Microsoft basic data entry");
        for entry in [462, 478, 494] {
            assert_eq!(bytes[entry + 4], 0x00, "slot at {entry} stays empty");
        }
        let start = u32::from_le_bytes([bytes[454], bytes[455], bytes[456], bytes[457]]);
        let count = u32::from_le_bytes([bytes[458], bytes[459], bytes[460], bytes[461]]);
        assert_eq!(start, 2048, "the data partition starts on the 1 MiB grid");
        assert_eq!(
            u64::from(start) + u64::from(count) - 1,
            131071,
            "the partition runs to the last LBA"
        );
        assert_eq!(opener.target.rereads(), 1);
    }

    #[test]
    fn mkpart_stamps_a_gpt_with_backup_header() {
        let opener = TestOpener::new(LAYOUT_LEN);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Gpt,
                },
                Step::Mkpart {
                    scheme: Scheme::Gpt,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("mklabel and mkpart run");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[512..520], b"EFI PART", "primary header at LBA1");
        assert_eq!(
            &bytes[131071 * 512..131071 * 512 + 8],
            b"EFI PART",
            "backup header at the last LBA"
        );
        assert_ne!(
            &bytes[1024..1040],
            &[0u8; 16],
            "the entry array holds one entry"
        );
        assert!(
            bytes[1152..1280].iter().all(|&byte| byte == 0),
            "the second entry stays empty"
        );
        assert_eq!(bytes[510], 0x55);
        assert_eq!(bytes[511], 0xAA);
        assert_eq!(bytes[450], 0xEE, "protective MBR is present");
        assert_eq!(opener.target.rereads(), 1);
    }

    #[test]
    fn mkpart_refuses_a_scheme_that_disagrees_with_mklabel() {
        let opener = TestOpener::new(LAYOUT_LEN);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Gpt,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a disagreeing scheme refuses");
        let text = error.to_string();
        assert!(text.contains("gpt"), "{text}");
        assert!(text.contains("mbr"), "{text}");
    }

    #[test]
    fn mkpart_refuses_a_target_smaller_than_a_sector() {
        let opener = TestOpener::new(100);
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a sub-sector target refuses");
        assert!(error.to_string().contains("100"), "{error:?}");
    }

    #[test]
    fn mkfs_fat32_writes_a_bpb_with_the_label() {
        let (_scratch, opener) = layout_opener();
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: Some("TESTLABEL".to_string()),
                    cluster_bytes: None,
                    quick: true,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("label, part and format run");
        let bytes = opener.target.bytes().expect("bytes read back");
        let base = PART_BASE as usize;
        // The entry the table stamped pins the view the format saw.
        let start = u32::from_le_bytes([bytes[454], bytes[455], bytes[456], bytes[457]]);
        assert_eq!(start, 2048);
        assert_eq!(&bytes[base + 82..base + 90], b"FAT32   ");
        assert_eq!(&bytes[base + 71..base + 80], b"TESTLABEL");
        assert_ne!(
            &bytes[base + 67..base + 71],
            &[0u8; 4],
            "serial is non-zero"
        );
        // Mkfs alone, without Mkpart, is refused by name.
        let (_scratch, bare) = layout_opener();
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Mkfs {
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick: true,
            }]),
            &bare,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("mkfs without mkpart refuses");
        let text = error.to_string();
        assert!(text.contains("mkfs"), "{text}");
        assert!(text.contains("mkpart"), "{text}");
    }

    #[test]
    fn full_format_zeroes_before_formatting() {
        let fat32 = || Step::Mkfs {
            filesystem: Filesystem::Fat32,
            label: Some("T".to_string()),
            cluster_bytes: None,
            quick: true,
        };
        let prefix = || {
            vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
            ]
        };
        // Quick format leaves the old pattern past the metadata.
        let (_scratch, opener) = layout_opener();
        prefill(&opener, 0xAA);
        let mut reporter = VecReporter::new();
        let mut steps = prefix();
        steps.push(fat32());
        run(
            &test_plan(steps),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("quick format runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        let base = PART_BASE as usize;
        let probe = MIB as usize;
        assert!(
            bytes[base + probe..base + probe + 16]
                .iter()
                .all(|&byte| byte == 0xAA),
            "the old pattern survives beyond the FAT area"
        );
        // Full format leaves no old bytes in the data area.
        let (_scratch, opener) = layout_opener();
        prefill(&opener, 0xAA);
        let mut reporter = VecReporter::new();
        let mut steps = prefix();
        steps.push(Step::Mkfs {
            filesystem: Filesystem::Fat32,
            label: Some("T".to_string()),
            cluster_bytes: None,
            quick: false,
        });
        run(
            &test_plan(steps),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("full format runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(
            bytes[base + probe..base + probe + MIB as usize]
                .iter()
                .all(|&byte| byte == 0),
            "no old bytes survive in the data area"
        );
    }

    #[test]
    fn cancellation_before_mkfs_zeroing_is_reported() {
        let (_scratch, opener) = layout_opener();
        prefill(&opener, 0xAA);
        let mut reporter = VecReporter::new();
        // False across the three boundary checks and the one Mkpart
        // piece write, true at the zero pass's first check: the "during
        // step" wording fires from inside Mkfs with nothing zeroed.
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: None,
                    cluster_bytes: None,
                    quick: false,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 4
            },
        )
        .expect_err("the zero pass cancels");
        let text = error.to_string();
        assert!(text.contains("mkfs"), "{text}");
        assert!(
            matches!(error, CoreError::Step { .. }),
            "cancellation surfaces wrapped: {text}"
        );
        let bytes = opener.target.bytes().expect("bytes read back");
        let base = PART_BASE as usize;
        let probe = MIB as usize;
        assert!(
            bytes[base + probe..base + probe + 16]
                .iter()
                .all(|&byte| byte == 0xAA),
            "the volume is untouched"
        );
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
    fn device_opens_lazily_once_per_run() {
        // An unimplemented-only plan never touches the device...
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Bootloader {
                mode: BootloaderMode::Auto,
            }]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("bootloader is not implemented yet");
        assert_eq!(opener.device_calls(), 0);
        // ...nor does a run cancelled before the first step...
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| true,
        )
        .expect_err("the first step cancels");
        assert_eq!(opener.device_calls(), 0);
        // ...while a two-step run that touches the device opens it
        // exactly once across both steps.
        let opener = TestOpener::new(4096);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe, Step::Finalize]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe and finalize run");
        assert_eq!(opener.device_calls(), 1);
    }

    #[test]
    fn cancelled_mkpart_reports_without_stamping() {
        // Cancellation inside the single MBR sector write: the short
        // count refuses instead of reporting success, so no signature
        // lands and the step never counts as partitioned.
        let opener = TestOpener::new(LAYOUT_LEN);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 2
            },
        )
        .expect_err("a cancelled sector write refuses");
        let text = error.to_string();
        assert!(text.contains("mkpart"), "{text}");
        assert!(text.contains("cancelled"), "{text}");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_ne!(&bytes[510..512], &[0x55, 0xAA], "no signature stamped");
        assert!(
            !reporter.events().iter().any(|event| matches!(
                event,
                Event::StepFinished { step: "mkpart", .. } | Event::Finished { .. }
            )),
            "no finish events after a cancelled stamp: {:?}",
            reporter.events()
        );
    }

    /// A [`Target`] that fails every zeroing call with an injected I/O
    /// error, delegating everything else to an inner [`VecTarget`].
    #[derive(Debug, Clone)]
    struct FailingTarget {
        inner: VecTarget,
    }

    impl Target for FailingTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, _offset: u64, _len: u64, _cancelled: &dyn Fn() -> bool) -> Result<()> {
            Err(CoreError::io(
                "test-device",
                std::io::Error::other("injected media error"),
            ))
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`FailingTarget`].
    #[derive(Debug, Clone)]
    struct FailingOpener {
        target: FailingTarget,
    }

    impl Opener for FailingOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn io_failure_inside_a_step_keeps_its_class() {
        // Wipe's zero pass hits the injected media error: the run error
        // is the Step wrapper (not InvalidInput), its source is Io, and
        // the text still names the step — so exit mapping still sees I/O.
        let opener = FailingOpener {
            target: FailingTarget {
                inner: VecTarget::new(4096, 512).expect("fixture target fits"),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("injected I/O refuses");
        assert!(
            matches!(error, CoreError::Step { .. }),
            "I/O surfaces wrapped, not flattened: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("step 'wipe'"), "{text}");
        assert!(text.contains("injected media error"), "{text}");
        assert!(
            matches!(&error, CoreError::Step { source, .. } if matches!(&**source, CoreError::Io { .. })),
            "the wrapped source stays I/O: {text}"
        );
    }

    #[test]
    fn step_errors_name_the_step() {
        // A formatter refusal surfaces wrapped: the step name first,
        // then the formatter's own words — and the variant, not just
        // the text, so exit mapping keeps working.
        let (_scratch, opener) = layout_opener();
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![
                Step::Mklabel {
                    scheme: Scheme::Mbr,
                },
                Step::Mkpart {
                    scheme: Scheme::Mbr,
                },
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: Some("a label far too long".to_string()),
                    cluster_bytes: None,
                    quick: true,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an overlong label refuses");
        let text = error.to_string();
        assert!(text.contains("mkfs"), "{text}");
        assert!(text.contains("volume label"), "{text}");
        assert!(
            matches!(error, CoreError::Step { .. }),
            "formatter refusal is wrapped: {text}"
        );
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
            &test_plan(vec![Step::Bootloader {
                mode: BootloaderMode::Auto,
            }]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("bootloader is not implemented yet");
        let text = error.to_string();
        assert!(text.contains("bootloader"), "{text}");
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
            &test_plan(vec![
                Step::Finalize,
                Step::Write {
                    mode: WriteMode::Dd,
                },
            ]),
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
        assert!(text.contains("write"), "{text}");
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

    /// What a flaky write fails with: a retryable media error or a
    /// validation refusal that must fail fast.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FlakyKind {
        Eio,
        Invalid,
    }

    /// Shared flakiness behind [`FlakyTarget`]: how many more
    /// `write_all_at_cancellable` calls fail, and how many calls
    /// happened. `Rc`-shared so every cloned handle (the opener clones
    /// per `device()` call, the run caches one) reports to the same
    /// counters.
    #[derive(Debug)]
    struct FlakyState {
        remaining: Cell<u32>,
        attempts: Cell<u32>,
    }

    /// A [`Target`] failing its next `remaining` cancellable writes
    /// with an [`FlakyKind`] error, then succeeding; `attempts` counts
    /// every cancellable call. Everything else delegates to an inner
    /// [`VecTarget`].
    #[derive(Debug, Clone)]
    struct FlakyTarget {
        inner: VecTarget,
        shared: Rc<FlakyState>,
        kind: FlakyKind,
    }

    impl FlakyTarget {
        fn new(len: u64, failures: u32, kind: FlakyKind) -> Self {
            Self {
                inner: VecTarget::new(len, 512).expect("fixture target fits"),
                shared: Rc::new(FlakyState {
                    remaining: Cell::new(failures),
                    attempts: Cell::new(0),
                }),
                kind,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.inner.bytes().expect("bytes read back")
        }
    }

    impl Target for FlakyTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.shared.attempts.set(self.shared.attempts.get() + 1);
            if self.shared.remaining.get() > 0 {
                self.shared.remaining.set(self.shared.remaining.get() - 1);
                return match self.kind {
                    FlakyKind::Eio => Err(CoreError::io(
                        "test-device",
                        std::io::Error::from_raw_os_error(5),
                    )),
                    FlakyKind::Invalid => Err(CoreError::invalid("injected validation failure")),
                };
            }
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`FlakyTarget`].
    #[derive(Debug, Clone)]
    struct FlakyOpener {
        target: FlakyTarget,
    }

    impl Opener for FlakyOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// An [`Opener`] serving one [`FlakyTarget`] whose
    /// [`reset_device`](Opener::reset_device) answers `Ok(true)` and
    /// counts its calls.
    #[derive(Debug, Clone)]
    struct ResetOpener {
        target: FlakyTarget,
        resets: Rc<Cell<u32>>,
    }

    impl Opener for ResetOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }

        fn reset_device(&self) -> Result<bool> {
            self.resets.set(self.resets.get() + 1);
            Ok(true)
        }
    }

    /// [`RunOptions`] with an instant retry policy for the retry tests:
    /// `retries` attempts past the first, no delay, USB reset per
    /// `reset_usb`.
    fn retry_options(retries: u32, reset_usb: bool) -> RunOptions {
        RunOptions {
            verify: false,
            badblocks: false,
            retries,
            retry_delay: std::time::Duration::ZERO,
            reset_usb,
        }
    }

    #[test]
    fn retry_succeeds_on_the_second_attempt() {
        // One `EIO` failure, then success: the run is `Ok`, the payload
        // complete, three cancellable calls (failed chunk, retried
        // chunk, second chunk), and exactly one warning naming the
        // first attempt.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlakyOpener {
            target: FlakyTarget::new(8 * MIB, 1, FlakyKind::Eio),
        };
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(3, false),
            &mut reporter,
            &|| false,
        )
        .expect("one retry heals the write");
        assert_eq!(&opener.target.bytes()[..size as usize], &content[..]);
        assert_eq!(opener.target.shared.attempts.get(), 3);
        let found = warnings(&reporter);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("attempt 1 of 4"), "{}", found[0]);
        assert!(found[0].contains("offset 0"), "{}", found[0]);
    }

    #[test]
    fn retry_gives_up_after_three_attempts() {
        // Always failing: four write attempts (initial + 3), a flush
        // before each retry, and a step-wrapped I/O error — never a
        // silent success, never a second wrapper.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlakyOpener {
            target: FlakyTarget::new(8 * MIB, u32::MAX, FlakyKind::Eio),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(3, false),
            &mut reporter,
            &|| false,
        )
        .expect_err("an always-failing chunk gives up");
        assert_eq!(opener.target.shared.attempts.get(), 4);
        assert_eq!(opener.target.inner.flushes(), 3);
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped once: {error:?}"
        );
        assert!(error.to_string().contains("I/O error"), "{error:?}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { .. })),
            "no step finished: {:?}",
            reporter.events()
        );
    }

    /// A [`Target`] shrinking below the failing offset on its first
    /// failed write: the size the retry re-reads no longer holds the
    /// chunk. `Rc`-shared like [`FlakyTarget`].
    #[derive(Debug, Clone)]
    struct ShrinkTarget {
        inner: VecTarget,
        size: Rc<Cell<u64>>,
        attempts: Rc<Cell<u32>>,
        shrunk: Rc<Cell<bool>>,
    }

    impl Target for ShrinkTarget {
        fn size(&self) -> u64 {
            self.size.get()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.attempts.set(self.attempts.get() + 1);
            if !self.shrunk.get() {
                self.shrunk.set(true);
                self.size.set(1024);
                return Err(CoreError::io(
                    "test-device",
                    std::io::Error::from_raw_os_error(5),
                ));
            }
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`ShrinkTarget`].
    #[derive(Debug, Clone)]
    struct ShrinkOpener {
        target: ShrinkTarget,
    }

    impl Opener for ShrinkOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn retry_rechecks_the_device_size() {
        // The first chunk fails, then the device reports 1024 bytes:
        // the retry refuses at once naming the new size, with exactly
        // the one attempt that observed the shrink.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = ShrinkOpener {
            target: ShrinkTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
                size: Rc::new(Cell::new(8 * MIB)),
                attempts: Rc::new(Cell::new(0)),
                shrunk: Rc::new(Cell::new(false)),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(3, false),
            &mut reporter,
            &|| false,
        )
        .expect_err("a vanished device refuses");
        assert_eq!(opener.target.attempts.get(), 1);
        let text = error.to_string();
        assert!(text.contains("1024"), "{text}");
        assert!(text.contains("offset 0"), "{text}");
    }

    #[test]
    fn non_retryable_errors_are_not_retried() {
        // A validation failure is not `EIO`/`ENOSPC`: one attempt, no
        // warning, no flush, straight to the step wrapper.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlakyOpener {
            target: FlakyTarget::new(8 * MIB, u32::MAX, FlakyKind::Invalid),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(3, false),
            &mut reporter,
            &|| false,
        )
        .expect_err("a validation failure fails fast");
        assert_eq!(opener.target.shared.attempts.get(), 1);
        assert!(
            warnings(&reporter).is_empty(),
            "no retry, no warning: {:?}",
            reporter.events()
        );
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        assert!(error.to_string().contains("injected"), "{error:?}");
    }

    #[test]
    fn retry_stops_when_cancelled() {
        // Always failing, with the probe flipping true on its third
        // consultation (the step boundary, the chunk check, then the
        // pre-sleep check): one attempt, `Cancelled`, no retry.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlakyOpener {
            target: FlakyTarget::new(8 * MIB, u32::MAX, FlakyKind::Eio),
        };
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(3, false),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 2
            },
        )
        .expect_err("a cancelled retry stops");
        assert_eq!(opener.target.shared.attempts.get(), 1);
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
    }

    #[test]
    fn usb_reset_is_attempted_after_the_retries() {
        // Two failures then success, one retry of budget, reset on: the
        // reset fires exactly once between the attempts, its message
        // names it, and the run succeeds with a complete payload.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = ResetOpener {
            target: FlakyTarget::new(8 * MIB, 2, FlakyKind::Eio),
            resets: Rc::new(Cell::new(0)),
        };
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(1, true),
            &mut reporter,
            &|| false,
        )
        .expect("a reset heals the chunk");
        assert_eq!(opener.resets.get(), 1);
        // Three cancellable calls for the healed chunk (fail, fail,
        // post-reset success) plus one for the clean second chunk.
        assert_eq!(opener.target.shared.attempts.get(), 4);
        assert_eq!(&opener.target.bytes()[..size as usize], &content[..]);
        let found: Vec<&str> = reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            found.iter().any(|text| text.contains("reset")),
            "a message names the reset: {found:?}"
        );
    }

    #[test]
    fn usb_reset_is_skipped_without_the_flag() {
        // Same two failures, reset off: no reset call, and the second
        // failure is the terminal one — the run reports the I/O error.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = ResetOpener {
            target: FlakyTarget::new(8 * MIB, u32::MAX, FlakyKind::Eio),
            resets: Rc::new(Cell::new(0)),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &retry_options(1, false),
            &mut reporter,
            &|| false,
        )
        .expect_err("an unhealed chunk fails");
        assert_eq!(opener.resets.get(), 0);
        assert_eq!(opener.target.shared.attempts.get(), 2);
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        assert!(error.to_string().contains("I/O error"), "{error:?}");
    }

    #[test]
    fn retry_returns_promptly_when_cancelled_during_the_delay() {
        // Always failing with a 600 ms retry delay, cancelled on the
        // fourth probe consultation (the step boundary, the chunk
        // check, the pre-sleep check, then the first 100 ms slice end):
        // the sliced sleep notices after one slice, so the run reports
        // `Cancelled` with one attempt in ~100 ms — not after 600 ms.
        // A blocking sleep would sleep the delay out and retry instead
        // (four attempts, an I/O error), so every assertion below
        // fails on the old shape.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(512 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlakyOpener {
            target: FlakyTarget::new(8 * MIB, u32::MAX, FlakyKind::Eio),
        };
        let mut reporter = VecReporter::new();
        let options = RunOptions {
            verify: false,
            badblocks: false,
            retries: 3,
            retry_delay: std::time::Duration::from_millis(600),
            reset_usb: false,
        };
        let calls = Cell::new(0u32);
        let started = std::time::Instant::now();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &options,
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 3
            },
        )
        .expect_err("a cancelled delay stops");
        let elapsed = started.elapsed();
        assert_eq!(opener.target.shared.attempts.get(), 1);
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        assert!(
            elapsed < std::time::Duration::from_millis(300),
            "a cancel during the delay returns promptly, not after 600 ms: {elapsed:?}"
        );
    }

    /// A [`Target`] sleeping `delay` on every cancellable write call
    /// before delegating: the cancellation-response test pins
    /// wall-time behaviour through this. Everything else delegates to
    /// an inner [`VecTarget`].
    #[derive(Debug, Clone)]
    struct DelayTarget {
        inner: VecTarget,
        delay: std::time::Duration,
    }

    impl Target for DelayTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            std::thread::sleep(self.delay);
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`DelayTarget`].
    #[derive(Debug, Clone)]
    struct DelayOpener {
        target: DelayTarget,
    }

    impl Opener for DelayOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn write_stops_within_200_ms_of_cancellation() {
        // A 2 MiB image (eight 256 KiB chunks) over a target sleeping
        // 50 ms per chunk write, with a flipper thread setting the
        // flag 120 ms in: the run must report `Cancelled` within
        // 200 ms of the flip — at most the in-flight chunk (50 ms)
        // plus loop overhead can follow it, so the bound carries 4x
        // headroom. The first chunk lands before the flip, the last
        // never runs, and no `step_finished` for `write` follows
        // either.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(2 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = DelayOpener {
            target: DelayTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
                delay: std::time::Duration::from_millis(50),
            },
        };
        let mut reporter = VecReporter::new();
        let flag = Arc::new(AtomicBool::new(false));
        let flipped_at = Arc::new(Mutex::new(None));
        let flipper = {
            let flag = Arc::clone(&flag);
            let flipped_at = Arc::clone(&flipped_at);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(120));
                flag.store(true, Ordering::SeqCst);
                *flipped_at.lock().expect("flip instant records") = Some(std::time::Instant::now());
            })
        };
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| flag.load(Ordering::SeqCst),
        )
        .expect_err("a mid-write cancel stops");
        let returned_at = std::time::Instant::now();
        flipper.join().expect("the flipper finishes");
        let flipped = flipped_at
            .lock()
            .expect("flip instant reads")
            .expect("the flipper ran");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        assert!(
            returned_at.duration_since(flipped) < std::time::Duration::from_millis(200),
            "the run stops within 200 ms of the flip: {:?}",
            returned_at.duration_since(flipped)
        );
        let bytes = opener.target.inner.bytes().expect("bytes read back");
        assert_eq!(
            &bytes[..256 * 1024],
            &content[..256 * 1024],
            "the first chunk lands before the flip"
        );
        assert!(
            bytes[size as usize - 256 * 1024..]
                .iter()
                .all(|&byte| byte == 0),
            "the last chunk never runs"
        );
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { step: "write", .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    /// [`RunOptions`] with the surface scan on and an instant retry
    /// policy: the bad-blocks tests never fail a write, so the delay
    /// stays zero.
    fn badblocks_options() -> RunOptions {
        RunOptions {
            verify: false,
            badblocks: true,
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        }
    }

    /// Every `badblocks` progress sample as `(done, total)`, in
    /// emission order.
    fn badblocks_progress(reporter: &VecReporter) -> Vec<(u64, Option<u64>)> {
        stepped_progress(reporter)
            .into_iter()
            .filter_map(|(step, done, total)| (step == "badblocks").then_some((done, total)))
            .collect()
    }

    /// A [`Target`] recording every `write_all_at` call as
    /// `(offset, len, first byte)` over a shared [`VecTarget`]: the
    /// coverage test pins per-pattern bytes through these. The wipe's
    /// zeroing runs through `zero_range`, never through this call, so
    /// the record isolates scan writes. Calls ride in an `Rc` so every
    /// cloned handle shares them.
    #[derive(Debug, Clone)]
    struct CountingTarget {
        inner: VecTarget,
        calls: Rc<RefCell<Vec<(u64, u64, u8)>>>,
    }

    impl CountingTarget {
        fn new(len: u64) -> Self {
            Self {
                inner: VecTarget::new(len, 512).expect("fixture target fits"),
                calls: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl Target for CountingTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            if let Some(first) = buf.first() {
                self.calls
                    .borrow_mut()
                    .push((offset, buf.len() as u64, *first));
            }
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`CountingTarget`].
    #[derive(Debug, Clone)]
    struct CountingOpener {
        target: CountingTarget,
    }

    impl Opener for CountingOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Target`] corrupting one window on read-back: writes land
    /// intact, but every read flips the bytes in
    /// `[torn_offset, torn_offset + torn_len)`, so the scan's compare
    /// sees exactly one torn range however many passes run.
    #[derive(Debug, Clone)]
    struct TornTarget {
        inner: VecTarget,
        torn_offset: u64,
        torn_len: u64,
    }

    impl Target for TornTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)?;
            let start = offset.max(self.torn_offset);
            let end = (offset + buf.len() as u64).min(self.torn_offset + self.torn_len);
            if start < end {
                let from = (start - offset) as usize;
                let to = (end - offset) as usize;
                for byte in &mut buf[from..to] {
                    *byte ^= 0xFF;
                }
            }
            Ok(())
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`TornTarget`].
    #[derive(Debug, Clone)]
    struct TornOpener {
        target: TornTarget,
    }

    impl Opener for TornOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Target`] rotting the first 64 bytes of every 512-byte block
    /// on read-back (12.5% bad, far over the 1% abort threshold), so
    /// the scan aborts on its first block.
    #[derive(Debug, Clone)]
    struct RottenTarget {
        inner: VecTarget,
    }

    impl Target for RottenTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)?;
            for (index, byte) in buf.iter_mut().enumerate() {
                if (offset + index as u64) % 512 < 64 {
                    *byte ^= 0xFF;
                }
            }
            Ok(())
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`RottenTarget`].
    #[derive(Debug, Clone)]
    struct RottenOpener {
        target: RottenTarget,
    }

    impl Opener for RottenOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Target`] corrupting different windows per most-recently-written
    /// pattern: each `write_all_at` of a uniform buffer arms that byte
    /// as the current pattern (the scan always writes uniform pattern
    /// buffers; the wipe never calls this), and reads flip the windows
    /// ruled for it. The cross-pass merge test pins multi-pass
    /// bookkeeping through this: regions torn in different passes must
    /// all survive with exact counts.
    #[derive(Debug, Clone)]
    struct PatternTarget {
        inner: VecTarget,
        rules: Vec<(u8, u64, u64)>,
        current: Rc<Cell<u8>>,
    }

    impl Target for PatternTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)?;
            for rule in &self.rules {
                if rule.0 != self.current.get() {
                    continue;
                }
                let start = offset.max(rule.1);
                let end = (offset + buf.len() as u64).min(rule.1 + rule.2);
                if start < end {
                    let from = (start - offset) as usize;
                    let to = (end - offset) as usize;
                    for byte in &mut buf[from..to] {
                        *byte ^= 0xFF;
                    }
                }
            }
            Ok(())
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            if let Some(first) = buf.first() {
                self.current.set(*first);
            }
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`PatternTarget`].
    #[derive(Debug, Clone)]
    struct PatternOpener {
        target: PatternTarget,
    }

    impl Opener for PatternOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn badblocks_find_nothing_on_a_clean_target() {
        // A clean 64 KiB target: wipe plus scan succeed, four pass
        // starts go out, the summary reports no bad blocks, and the
        // final progress lands exactly on the device size.
        let opener = TestOpener::new(64 * 1024);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a clean device scans");
        let texts = messages(&reporter);
        assert_eq!(
            texts
                .iter()
                .filter(|text| text.contains("badblocks pass"))
                .count(),
            4,
            "one start per pattern pass: {texts:?}"
        );
        assert!(
            texts.iter().any(|text| text.contains("no bad bytes found")),
            "the summary reports clean: {texts:?}"
        );
        let progress = badblocks_progress(&reporter);
        assert_eq!(
            progress.last().copied(),
            Some((64 * 1024, Some(64 * 1024))),
            "the final sample lands on the device size: {progress:?}"
        );
    }

    #[test]
    fn badblocks_name_a_torn_block() {
        // One torn 512-byte block at the end of a 64 KiB device: the
        // scan completes (one block in 128 stays far under the 1%
        // abort), then refuses — summary and error both name the
        // offset, and the bad count is exactly the torn block.
        const LEN: u64 = 64 * 1024;
        const TORN: u64 = 64 * 1024 - 512;
        let opener = TornOpener {
            target: TornTarget {
                inner: VecTarget::new(LEN, 512).expect("fixture target fits"),
                torn_offset: TORN,
                torn_len: 512,
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a torn block refuses");
        assert!(
            matches!(error, CoreError::Step { step: "wipe", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("512"), "{text}");
        assert!(text.contains("65024"), "{text}");
        let texts = messages(&reporter);
        assert!(
            texts
                .iter()
                .any(|line| line.contains("512 bad bytes (first at offset 65024)")),
            "the summary names the count and the offset too: {texts:?}"
        );
    }

    #[test]
    fn badblocks_abort_above_the_threshold() {
        // Every block rotten in its first 64 bytes: the first piece
        // already holds 8192 bad bytes of a 64 KiB device (12.5%),
        // far over the 1% abort threshold, so the scan stops at once
        // naming the count, the device size, the first offset and the
        // threshold.
        let opener = RottenOpener {
            target: RottenTarget {
                inner: VecTarget::new(64 * 1024, 512).expect("fixture target fits"),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a rotten device aborts");
        assert!(
            matches!(error, CoreError::Step { step: "wipe", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("8192"), "{text}");
        assert!(text.contains("65536"), "{text}");
        assert!(text.contains("offset 0"), "{text}");
        assert!(text.contains("1%"), "{text}");
        let texts = messages(&reporter);
        assert!(
            texts
                .iter()
                .any(|line| line.contains("8192 bad bytes (first at offset 0)")),
            "the summary names the count and the offset too: {texts:?}"
        );
    }

    #[test]
    fn badblocks_merge_ranges_across_passes() {
        // Two regions torn in different passes only (96 KiB during the
        // 0x00 pass, 0 during the 0xFF pass) on a 128 KiB device: the
        // report keeps both — 1024 bad bytes in 2 ranges from offset
        // 0 — instead of folding the earlier region into the later
        // pass's ascending order. The ascending-only merge reported
        // 512 bytes in 1 range here.
        const LEN: u64 = 128 * 1024;
        let opener = PatternOpener {
            target: PatternTarget {
                inner: VecTarget::new(LEN, 512).expect("fixture target fits"),
                rules: vec![(0x00, 96 * 1024, 512), (0xFF, 0, 512)],
                current: Rc::new(Cell::new(0x00)),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("torn regions refuse");
        assert!(
            matches!(error, CoreError::Step { step: "wipe", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("1024"), "{text}");
        assert!(text.contains("2 ranges"), "{text}");
        assert!(text.contains("offset 0"), "{text}");
        let texts = messages(&reporter);
        assert!(
            texts
                .iter()
                .any(|line| line.contains("1024 bad bytes (first at offset 0)")),
            "the summary names the count and the offset too: {texts:?}"
        );
    }

    #[test]
    fn badblocks_abort_threshold_pins_at_one_percent_of_the_device() {
        // 102400-byte device, so 1% is exactly 1024 bytes: a 1024-byte
        // bad prefix completes the scan (strictly-exceed never fires)
        // while a 1025-byte prefix aborts on the first piece — the
        // threshold is a density over the device, not over the bytes
        // scanned so far.
        const LEN: u64 = 102400;
        for (prefix, aborts) in [(1024u64, false), (1025u64, true)] {
            let opener = TornOpener {
                target: TornTarget {
                    inner: VecTarget::new(LEN, 512).expect("fixture target fits"),
                    torn_offset: 0,
                    torn_len: prefix,
                },
            };
            let mut reporter = VecReporter::new();
            let error = run(
                &test_plan(vec![Step::Wipe]),
                &opener,
                &badblocks_options(),
                &mut reporter,
                &|| false,
            )
            .expect_err("a bad prefix refuses");
            assert!(
                matches!(error, CoreError::Step { step: "wipe", .. }),
                "the refusal is step-wrapped: {error:?}"
            );
            let text = error.to_string();
            if aborts {
                assert!(text.contains("1025"), "{text}");
                assert!(text.contains("abort"), "{text}");
                assert!(text.contains("1%"), "{text}");
            } else {
                assert!(
                    !text.contains("abort"),
                    "exactly 1% bad still scans: {text}"
                );
                assert!(text.contains("found 1024 bad bytes"), "{text}");
            }
        }
    }

    #[test]
    fn badblocks_are_skipped_without_the_flag() {
        // Flag off: the wipe zeroes its windows and nothing else — the
        // prefill survives between them, and no badblocks progress
        // event exists.
        let opener = TestOpener::new(8 * MIB);
        opener
            .target
            .write_all_at(0, &vec![0xAAu8; 8 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe runs");
        let bytes = opener.target.bytes().expect("bytes read back");
        assert!(
            bytes[MIB as usize..7 * MIB as usize]
                .iter()
                .all(|&byte| byte == 0xAA),
            "no scan writes outside the wipe windows"
        );
        assert!(
            badblocks_progress(&reporter).is_empty(),
            "no badblocks progress without the flag: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn badblocks_cover_the_whole_device() {
        // A 4 KiB device (eight 512-byte blocks): every pattern pass
        // writes exactly the device extent — four times the size in
        // total — with each pass tiling [0, size) once, in order.
        const LEN: u64 = 4096;
        let opener = CountingOpener {
            target: CountingTarget::new(LEN),
        };
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a clean device scans");
        let calls = opener.target.calls.borrow();
        let total: u64 = calls.iter().map(|call| call.1).sum();
        assert_eq!(total, 4 * LEN, "one full extent per pattern");
        for pattern in [0x00u8, 0xFF, 0xAA, 0x55] {
            let mut expected = 0u64;
            for call in calls.iter().filter(|call| call.2 == pattern) {
                assert_eq!(
                    call.0, expected,
                    "pass 0x{pattern:02X} tiles in order: {calls:?}"
                );
                expected += call.1;
            }
            assert_eq!(expected, LEN, "pass 0x{pattern:02X} covers the device");
        }
    }

    #[test]
    fn badblocks_stop_when_cancelled() {
        // Cancel after a few blocks (past the wipe's own checks): bare
        // `Cancelled` wrapped once as step 'wipe', no summary message,
        // no finished step.
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &badblocks_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 12
            },
        )
        .expect_err("a cancelled scan stops");
        assert!(
            matches!(error, CoreError::Step { step: "wipe", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        let texts = messages(&reporter);
        assert!(
            !texts.iter().any(|text| text.contains("bad bytes found")
                || text.contains("bad bytes (first at offset")),
            "no summary after cancel: {texts:?}"
        );
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { step: "wipe", .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    /// A [`Target`] counting its cancellable writes, zero calls and
    /// target reads over a shared [`VecTarget`]: the sparse tests pin
    /// call counts through these. Counters ride in an `Rc` so every
    /// cloned handle shares them (the opener clones per `device()`
    /// call); single-threaded only, like [`VecTarget`].
    #[derive(Debug, Clone)]
    struct CountTarget {
        inner: VecTarget,
        write_calls: Rc<Cell<usize>>,
        write_bytes: Rc<Cell<u64>>,
        zero_calls: Rc<Cell<usize>>,
        reads: Rc<Cell<usize>>,
    }

    impl CountTarget {
        fn new(len: u64) -> Self {
            Self {
                inner: VecTarget::new(len, 512).expect("fixture target fits"),
                write_calls: Rc::new(Cell::new(0)),
                write_bytes: Rc::new(Cell::new(0)),
                zero_calls: Rc::new(Cell::new(0)),
                reads: Rc::new(Cell::new(0)),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.inner.bytes().expect("bytes read back")
        }
    }

    impl Target for CountTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            let done = self
                .inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)?;
            self.write_calls.set(self.write_calls.get() + 1);
            self.write_bytes.set(self.write_bytes.get() + done);
            Ok(done)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.zero_calls.set(self.zero_calls.get() + 1);
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// A fixture [`Opener`] reporting caller-chosen `ranges` (or `None`
    /// for the default straight-copy answer) over one [`CountTarget`].
    #[derive(Debug, Clone)]
    struct SparseOpener {
        target: CountTarget,
        ranges: Option<Vec<(u64, u64)>>,
    }

    impl Opener for SparseOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }

        fn data_ranges(&self, _path: &Path) -> Result<Option<Vec<(u64, u64)>>> {
            Ok(self.ranges.clone())
        }
    }

    #[test]
    fn sparse_write_zeroes_holes_and_streams_only_data() {
        // 6 MiB image with data at [1 MiB, 2 MiB) and [4 MiB, 4.5 MiB):
        // the data lands verbatim, the three hole windows zero (wiping
        // the prefill), writes cover data only, and progress ends at
        // the image size.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(6 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        assert_eq!(size, 6 * MIB);
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(MIB, MIB), (4 * MIB, MIB / 2)]),
        };
        opener
            .target
            .inner
            .write_all_at(0, &vec![0xAAu8; 6 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a sparse write runs");
        let bytes = opener.target.bytes();
        assert_eq!(
            &bytes[MIB as usize..2 * MIB as usize],
            &content[MIB as usize..2 * MIB as usize]
        );
        assert_eq!(
            &bytes[4 * MIB as usize..9 * MIB as usize / 2],
            &content[4 * MIB as usize..9 * MIB as usize / 2]
        );
        // The three hole windows read zero: the prefill is gone there.
        for window in [
            0..MIB as usize,
            2 * MIB as usize..4 * MIB as usize,
            9 * MIB as usize / 2..6 * MIB as usize,
        ] {
            assert!(
                bytes[window.clone()].iter().all(|&byte| byte == 0),
                "hole {window:?} is zeroed"
            );
        }
        // Four 256 KiB data chunks plus two: holes cost zero calls,
        // never writes.
        assert_eq!(opener.target.write_calls.get(), 6);
        assert_eq!(opener.target.write_bytes.get(), 3 * MIB / 2);
        assert_eq!(opener.target.zero_calls.get(), 3);
        let progress = progresses(&reporter);
        assert!(
            progress.iter().all(|(_, total)| *total == Some(6 * MIB)),
            "one stream at the image size: {progress:?}"
        );
        assert_eq!(
            progress.last().copied(),
            Some((6 * MIB, Some(6 * MIB))),
            "holes included, the final event is done == total"
        );
    }

    #[test]
    fn sparse_write_refuses_ranges_that_contradict_the_plan_size() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(6 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        // A range running past the image size: 5 MiB + 2 MiB ends at
        // 7340032 against a 6291456 byte image.
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(5 * MIB, 2 * MIB)]),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a past-the-end range refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("7340032"), "{text}");
        assert!(text.contains("6291456"), "{text}");
        assert!(
            opener.target.bytes().iter().all(|&byte| byte == 0),
            "nothing written"
        );
        // An overlapping pair: the second range starts at 1.5 MiB,
        // inside the first range's 1..2 MiB.
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(MIB, MIB), (3 * MIB / 2, MIB)]),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an overlapping pair refuses");
        let text = error.to_string();
        assert!(text.contains("1572864"), "{text}");
        assert!(text.contains("2097152"), "{text}");
        assert!(
            opener.target.bytes().iter().all(|&byte| byte == 0),
            "nothing written"
        );
        // A zero-length entry: refused naming its offset.
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(MIB, MIB), (2 * MIB, 0)]),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an empty entry refuses");
        let text = error.to_string();
        assert!(text.contains("2097152"), "{text}");
        assert!(
            opener.target.bytes().iter().all(|&byte| byte == 0),
            "nothing written"
        );
        // An unsorted pair: the second range starts at 0, before the
        // first range's 1..2 MiB.
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(MIB, MIB), (0, MIB)]),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an unsorted pair refuses");
        let text = error.to_string();
        assert!(text.contains("2097152"), "{text}");
        assert!(
            opener.target.bytes().iter().all(|&byte| byte == 0),
            "nothing written"
        );
        // An `offset + len` overflow: refused naming the range, never
        // wrapped around into the image.
        let opener = SparseOpener {
            target: CountTarget::new(6 * MIB),
            ranges: Some(vec![(u64::MAX - 10, 20)]),
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("an overflowing range refuses");
        let text = error.to_string();
        assert!(text.contains("18446744073709551605"), "{text}");
        assert!(
            opener.target.bytes().iter().all(|&byte| byte == 0),
            "nothing written"
        );
    }

    #[test]
    fn no_data_ranges_means_a_straight_copy() {
        // The default (`None`) answer keeps today's straight-through
        // behaviour: the whole 1 MiB image streams in four 256 KiB
        // writes, no zero calls, progress to the image size.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = SparseOpener {
            target: CountTarget::new(8 * MIB),
            ranges: None,
        };
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("the default answer copies straight through");
        let bytes = opener.target.bytes();
        assert_eq!(&bytes[..size as usize], &content[..]);
        assert_eq!(opener.target.write_calls.get(), 4);
        assert_eq!(opener.target.write_bytes.get(), MIB);
        assert_eq!(opener.target.zero_calls.get(), 0);
        assert_eq!(
            progresses(&reporter).last().copied(),
            Some((MIB, Some(MIB)))
        );
    }

    #[test]
    fn all_holes_means_the_whole_image_is_zeroed() {
        // No data at all over a 2 MiB image: one hole window zeroes the
        // whole target, progress still reaches the total, and no read
        // — of the target or the file — ever happens.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(2 * MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = SparseOpener {
            target: CountTarget::new(2 * MIB),
            ranges: Some(Vec::new()),
        };
        opener
            .target
            .inner
            .write_all_at(0, &vec![0xAAu8; 2 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(
            &test_plan_image(vec![write_dd()], &path, size),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("an all-hole image zeroes");
        assert!(opener.target.bytes().iter().all(|&byte| byte == 0));
        assert_eq!(opener.target.write_calls.get(), 0);
        assert_eq!(opener.target.zero_calls.get(), 1);
        assert_eq!(opener.target.reads.get(), 0);
        assert_eq!(
            progresses(&reporter).last().copied(),
            Some((2 * MIB, Some(2 * MIB)))
        );
    }

    /// A [`Target`] flipping the byte at `flip_at` on every read,
    /// delegating everything else to an inner [`VecTarget`]: the
    /// corrupted byte behind the verify-mismatch test. Writes are
    /// unaffected, so the write lands and only the read-back differs.
    #[derive(Debug, Clone)]
    struct FlipTarget {
        inner: VecTarget,
        flip_at: u64,
    }

    impl Target for FlipTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)?;
            if self.flip_at >= offset
                && let Some(byte) = buf.get_mut((self.flip_at - offset) as usize)
            {
                *byte ^= 0xFF;
            }
            Ok(())
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`FlipTarget`].
    #[derive(Debug, Clone)]
    struct FlipOpener {
        target: FlipTarget,
    }

    impl Opener for FlipOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// A [`Target`] whose reads fail past 512 KiB while writes succeed:
    /// the short device behind the verify short-read test.
    #[derive(Debug, Clone)]
    struct ShortReadTarget {
        inner: VecTarget,
    }

    impl Target for ShortReadTarget {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("test read overflows"))?;
            if end > 512 * 1024 {
                return Err(CoreError::io(
                    "test-device",
                    std::io::Error::other(format!(
                        "short read: bytes past {} are unreadable",
                        512 * 1024
                    )),
                ));
            }
            self.inner.read_at(offset, buf)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.inner.write_all_at(offset, buf)
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            self.inner
                .write_all_at_cancellable(offset, buf, chunk, cancelled)
        }

        fn zero_range(&self, offset: u64, len: u64, cancelled: &dyn Fn() -> bool) -> Result<()> {
            self.inner.zero_range(offset, len, cancelled)
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// An [`Opener`] serving one [`ShortReadTarget`].
    #[derive(Debug, Clone)]
    struct ShortReadOpener {
        target: ShortReadTarget,
    }

    impl Opener for ShortReadOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    /// Every `Message` text, in emission order.
    fn messages(reporter: &VecReporter) -> Vec<&str> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Every `Progress` event as `(step, done, total)`, in order.
    fn stepped_progress(reporter: &VecReporter) -> Vec<(&str, u64, Option<u64>)> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Progress {
                    step, done, total, ..
                } => Some((*step, *done, *total)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn verify_accepts_a_correct_write() {
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let report = run(
            &test_plan_verified(vec![write_dd()], &path, size),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a correct write verifies");
        // The step list is unchanged: verification is a pass inside
        // the write step, not a plan step.
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].step, "write");
        // One message before and after the pass.
        assert_eq!(
            messages(&reporter),
            [
                "verifying 1048576 bytes against the plan digest",
                "verified 1048576 bytes"
            ]
        );
        // Verify progress ends at done == total.
        let verify: Vec<(u64, Option<u64>)> = stepped_progress(&reporter)
            .into_iter()
            .filter(|(step, _, _)| *step == "verify")
            .map(|(_, done, total)| (done, total))
            .collect();
        assert!(!verify.is_empty(), "the pass reports progress");
        assert_eq!(verify.last().copied(), Some((size, Some(size))));
    }

    #[test]
    fn verify_refuses_a_corrupted_byte() {
        // 600 000 bytes span three chunks; the flip at 300 000 sits in
        // the middle one, so the locator must look past the first.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(600_000);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = FlipOpener {
            target: FlipTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
                flip_at: 300_000,
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_verified(vec![write_dd()], &path, size),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a corrupted byte refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("300000"), "{text}");
        assert!(text.contains("expected digest"), "{text}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn verify_never_lies_on_a_short_device() {
        // The 1 MiB image writes whole, but reads fail past 512 KiB:
        // the pass refuses instead of hashing a prefix as success.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = ShortReadOpener {
            target: ShortReadTarget {
                inner: VecTarget::new(8 * MIB, 512).expect("fixture target fits"),
            },
        };
        let mut reporter = VecReporter::new();
        let error = run(
            &test_plan_verified(vec![write_dd()], &path, size),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("a short device refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        assert!(error.to_string().contains("short"), "{error:?}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn verify_is_skipped_for_compressed_images() {
        // The plan digest covers the archive, not the decoded stream,
        // so there is nothing honest to compare: one warning, then the
        // write as usual — and no read-back.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let payload = pattern_bytes(50_000);
        let (path, size) = compressed_image(&scratch, "image.gz", "gzip", &payload);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        run(
            &test_plan_compressed(vec![write_dd()], &path, size, ImageKind::Gzip),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| false,
        )
        .expect("a compressed write runs without verifying");
        let found = warnings(&reporter);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("skipped"), "{}", found[0]);
        assert!(
            stepped_progress(&reporter)
                .iter()
                .all(|(step, _, _)| *step != "verify"),
            "no read-back ran: {:?}",
            reporter.events()
        );
        let bytes = opener.target.bytes().expect("bytes read back");
        assert_eq!(&bytes[..payload.len()], &payload[..]);
    }

    #[test]
    fn verify_cancelled_mid_read_is_not_success() {
        // A 256 KiB image: three probe consultations precede the
        // verify loop (the step boundary, the one write chunk, the
        // target's own piece check), so the fourth — the read loop's
        // first, seeing count 3 — cancels before a byte is hashed.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(256 * 1024);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let error = run(
            &test_plan_verified(vec![write_dd()], &path, size),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 3
            },
        )
        .expect_err("a mid-read cancel refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "cancellation surfaces wrapped: {error:?}"
        );
        assert!(error.to_string().contains("cancelled"), "{error:?}");
        assert!(
            !reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::StepFinished { .. })),
            "no success is reported: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn verify_refuses_a_plan_without_a_digest() {
        // A hand-written plan with an empty digest: the write lands,
        // then verification refuses up front — there is nothing to
        // compare against. Usage error, not a device failure.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let content = pattern_bytes(MIB as usize);
        let (path, size) = image_file(&scratch, "image.bin", &content);
        let mut plan = test_plan_image(vec![write_dd()], &path, size);
        plan.image.sha256 = String::new();
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        let error = run(&plan, &opener, &verify_options(), &mut reporter, &|| false)
            .expect_err("a digestless plan refuses");
        assert!(
            matches!(error, CoreError::Step { step: "write", .. }),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("no digest"), "{text}");
    }

    #[test]
    fn verify_is_skipped_without_a_write_step() {
        // A `[Wipe]`-only plan with verification on: nothing written,
        // nothing to compare — no warning, no verify progress.
        let opener = TestOpener::new(8 * MIB);
        let mut reporter = VecReporter::new();
        run(
            &test_plan(vec![Step::Wipe]),
            &opener,
            &verify_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe runs");
        assert!(
            warnings(&reporter)
                .iter()
                .all(|warning| !warning.contains("verify")),
            "no verify warning: {:?}",
            reporter.events()
        );
        assert!(
            stepped_progress(&reporter)
                .iter()
                .all(|(step, _, _)| *step != "verify"),
            "no read-back ran: {:?}",
            reporter.events()
        );
    }

    #[test]
    fn verify_hashes_the_logical_image_when_sparse() {
        use std::io::Seek as _;
        use std::io::Write as _;

        // A real sparse file: a hole over [0, 1 MiB), data over
        // [1 MiB, 2 MiB). The digest covers the logical bytes (holes
        // read as zeros), and so does the target after the run — the
        // hole window was zeroed, not skipped.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let path = scratch.path().join("sparse.bin");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("sparse file creates");
        file.seek(std::io::SeekFrom::Start(MIB))
            .expect("hole seeks");
        file.write_all(&pattern_bytes(MIB as usize))
            .expect("tail writes");
        file.set_len(2 * MIB).expect("sparse file sizes");
        drop(file);
        let mut plan = test_plan_image(vec![write_dd()], &path, 2 * MIB);
        plan.image.sha256 = hash_file_with(Algo::Sha256, &path).expect("fixture hashes");
        let opener = SparseOpener {
            target: CountTarget::new(2 * MIB),
            ranges: Some(vec![(MIB, MIB)]),
        };
        opener
            .target
            .inner
            .write_all_at(0, &vec![0xAAu8; 2 * MIB as usize])
            .expect("prefill writes");
        let mut reporter = VecReporter::new();
        run(&plan, &opener, &verify_options(), &mut reporter, &|| false)
            .expect("a sparse write verifies against its logical bytes");
        assert!(
            messages(&reporter)
                .iter()
                .any(|message| message.contains("verified 2097152 bytes")),
            "the pass closes: {:?}",
            reporter.events()
        );
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
                Step::Bootloader {
                    mode: BootloaderMode::Auto,
                },
            ]),
            &opener,
            &run_options(),
            &mut reporter,
            &|| false,
        )
        .expect_err("bootloader is not implemented yet");
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
