//! The display-independent run state machine: START, the confirmation
//! gate and the helper's event stream (S25 slice 4).
//!
//! [`Run`] owns the lifecycle of one plan:
//!
//! ```text
//! Idle --start()--> Confirming --confirm()--> Running --Done/cancel()--> Finished
//! ```
//!
//! # The confirmation gate
//!
//! [`Run::start`] derives the plan through [`GuiState::build_plan`], so the
//! S23 planner stays the only place a plan is constructed, and captures the
//! device facts the form was showing. It then **strips** the confirm hash:
//! `furus_core::planner::build` seals a provisional `sha256:` token of its
//! own, but that token is an integrity hash of the plan's bytes — not a
//! statement that a human approved writing this device. While the machine is
//! `Confirming` the plan therefore carries `confirm == ""`, and
//! [`Run::confirmed_plan`] refuses with [`RunError::ConfirmationRequired`]:
//! START alone can never hand a runnable plan to a transport. [`Run::confirm`]
//! recomputes [`Plan::confirm`] over that same plan and attaches it, so the
//! token the helper finally validates is exactly the planner's — only the
//! moment it exists changes.
//!
//! # Transports live in `ipc`
//!
//! Nothing here spawns a helper, a `pkexec`, a bus or a thread. The machine
//! consumes the [`furus_proto::Event`]s a transport delivers through
//! `ipc::EventStream` and turns them into display state; slice 5 starts the
//! transport with [`Run::confirmed_plan`] and feeds this machine. Cancellation
//! is an injected [`CancelRequest`] for the same reason: the state machine
//! only needs to *ask*.
//!
//! # Time and throughput
//!
//! Rate and ETA come from the wire `done`/`total` plus an **explicit** elapsed
//! [`Duration`] supplied by the caller ([`Run::apply`]), never from the wall
//! clock, so the UI owns the clock and tests stay deterministic. The rate is
//! the average for the current step — `done` over the time since that step's
//! first sample — which is why a step's first sample has no rate yet. The ETA
//! is the step's remaining units at that rate. An indeterminate total, zero
//! elapsed time and a zero rate all yield `None` rather than a nonsense
//! figure.
//!
//! Samples never move the display backwards: an event naming an earlier step,
//! or fewer units within the current step, is a stale sample and is ignored,
//! and the percent within a step never decreases. A step advance legitimately
//! restarts the percent, because the helper reports progress per step.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use furus_core::units::{format_duration, human_bytes};
use furus_proto::{Event, LogLevel, Outcome, Plan, Progress};

use crate::state::{DeviceSelection, GuiError, GuiState};

/// Upper bound on buffered log lines kept for the log drawer.
pub const LOG_LIMIT: usize = 500;

/// Display label of the step currently running.
///
/// The wire carries the plan's `op` tags; the drawer shows the label, so the
/// two spellings live next to each other in [`StepLabel::from_op`] and
/// [`StepLabel::as_str`] and cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepLabel {
    /// `wipe`.
    Wipe,
    /// `mklabel`.
    Table,
    /// `mkpart`.
    Partition,
    /// `mkfs`.
    Format,
    /// `write`.
    Write,
    /// `bootloader`.
    Bootloader,
    /// `finalize` on the wire, `finalise` on screen.
    Finalise,
}

impl StepLabel {
    /// Map a helper wire `op` tag onto its display label.
    ///
    /// Only the seven tags the helper's `op_tag` writes are accepted; an
    /// unknown tag returns `None` and the caller keeps the last known label
    /// instead of inventing one.
    #[must_use]
    pub fn from_op(op: &str) -> Option<Self> {
        match op {
            "wipe" => Some(Self::Wipe),
            "mklabel" => Some(Self::Table),
            "mkpart" => Some(Self::Partition),
            "mkfs" => Some(Self::Format),
            "write" => Some(Self::Write),
            "bootloader" => Some(Self::Bootloader),
            "finalize" => Some(Self::Finalise),
            _ => None,
        }
    }

    /// The label shown for this step.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wipe => "wipe",
            Self::Table => "table",
            Self::Partition => "partition",
            Self::Format => "format",
            Self::Write => "write",
            Self::Bootloader => "bootloader",
            Self::Finalise => "finalise",
        }
    }
}

impl fmt::Display for StepLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The run lifecycle and the progress the drawer shows while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunState {
    /// No plan has been requested.
    Idle,
    /// START built a plan and the user has not approved it yet.
    Confirming,
    /// The plan is confirmed and its events are being consumed.
    Running {
        /// The step being executed; `None` until the first progress sample.
        step: Option<StepLabel>,
        /// Percent of the current step, as reported by the helper.
        percent: Option<u8>,
        /// Current step throughput, e.g. `"1.50 MiB/s"`; `None` when unknown.
        rate: Option<String>,
        /// Estimated time left for the current step, e.g. `"0:05"`.
        eta: Option<String>,
    },
    /// The terminal event arrived (or the user cancelled); nothing follows.
    Finished(Outcome),
}

/// The device facts captured when START was pressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFacts {
    /// Human-readable model, when discovery found one.
    pub model: Option<String>,
    /// Device path as shown, e.g. `/dev/sdz`.
    pub path: String,
    /// Stable serial, when discovery found one.
    pub serial: Option<String>,
    /// Capacity in bytes.
    pub size_bytes: u64,
    /// Mount summary shown next to the device.
    pub mount_summary: String,
}

impl From<&DeviceSelection> for DeviceFacts {
    fn from(selection: &DeviceSelection) -> Self {
        Self {
            model: selection.model.clone(),
            path: selection.path.clone(),
            serial: selection.serial.clone(),
            size_bytes: selection.size_bytes,
            mount_summary: selection.mount_summary.clone(),
        }
    }
}

/// One buffered helper log line, ready for the log drawer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Severity the helper reported.
    pub level: LogLevel,
    /// Message text, verbatim from the (already sanitised) wire.
    pub message: String,
}

/// The one-shot action behind a [`CancelRequest`].
type CancelAction = Box<dyn FnOnce() + Send + 'static>;

/// Cloneable, one-shot cancellation request for the running helper.
///
/// Production wires this to the transport's own cancellation handle; tests
/// inject a counter. It lives here, not in `ipc`, so the state machine keeps
/// no dependency on any transport.
#[derive(Clone, Default)]
pub struct CancelRequest {
    action: Arc<Mutex<Option<CancelAction>>>,
}

impl CancelRequest {
    /// Build a request that runs `action` the first time it is asked.
    pub fn new(action: impl FnOnce() + Send + 'static) -> Self {
        Self {
            action: Arc::new(Mutex::new(Some(Box::new(action)))),
        }
    }

    /// Run the action at most once across clones; `true` when it ran.
    fn request(&self) -> bool {
        let Ok(mut slot) = self.action.lock() else {
            return false;
        };
        let Some(action) = slot.take() else {
            return false;
        };
        action();
        true
    }
}

impl fmt::Debug for CancelRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancelRequest")
            .finish_non_exhaustive()
    }
}

/// A refusal from the run state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// A runnable plan was requested before [`Run::confirm`].
    ConfirmationRequired,
    /// [`Run::start`] was called outside `Idle`.
    NotIdle,
    /// [`Run::confirm`] was called outside `Confirming`.
    NotConfirming,
    /// [`Run::cancel`] was called while no run is in flight.
    NotRunning,
    /// The planner refused the current selection.
    Plan(GuiError),
    /// The plan's confirm hash could not be computed.
    Confirm(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfirmationRequired => {
                formatter.write_str("The run must be confirmed before its plan can start.")
            }
            Self::NotIdle => formatter.write_str("A run has already been started."),
            Self::NotConfirming => formatter.write_str("No plan is waiting for confirmation."),
            Self::NotRunning => formatter.write_str("No run is in progress."),
            Self::Plan(error) => error.fmt(formatter),
            Self::Confirm(message) => {
                write!(
                    formatter,
                    "Could not compute the plan confirmation: {message}"
                )
            }
        }
    }
}

impl std::error::Error for RunError {}

/// The plan and the device facts captured at START.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Prepared {
    plan: Plan,
    device: DeviceFacts,
}

/// Where the accepted samples have got to, for rate and staleness.
#[derive(Debug, Clone, Copy, Default)]
struct ProgressTrack {
    /// 0-based index of the step the last accepted sample named.
    step_index: usize,
    /// Elapsed time at the current step's first accepted sample.
    step_started: Option<Duration>,
    /// `done` of the last accepted sample in the current step.
    last_done: u64,
}

/// The run state machine for one plan.
#[derive(Debug, Clone)]
pub struct Run {
    state: RunState,
    prepared: Option<Prepared>,
    logs: VecDeque<LogEntry>,
    cancel: CancelRequest,
    track: ProgressTrack,
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}

impl Run {
    /// A run in `Idle` with a cancellation seam that does nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RunState::Idle,
            prepared: None,
            logs: VecDeque::new(),
            cancel: CancelRequest::default(),
            track: ProgressTrack::default(),
        }
    }

    /// A run in `Idle` whose cancellation asks `cancel`.
    #[must_use]
    pub fn with_cancel(cancel: CancelRequest) -> Self {
        Self {
            cancel,
            ..Self::new()
        }
    }

    /// The current lifecycle state and progress.
    #[must_use]
    pub fn state(&self) -> &RunState {
        &self.state
    }

    /// The device facts captured when START was pressed; `None` in `Idle`.
    #[must_use]
    pub fn device(&self) -> Option<&DeviceFacts> {
        self.prepared.as_ref().map(|prepared| &prepared.device)
    }

    /// The plan currently shown, with or without its confirmation token;
    /// `None` in `Idle`.
    #[must_use]
    pub fn plan(&self) -> Option<&Plan> {
        self.prepared.as_ref().map(|prepared| &prepared.plan)
    }

    /// Buffered helper log lines, oldest first.
    #[must_use]
    pub fn logs(&self) -> &VecDeque<LogEntry> {
        &self.logs
    }

    /// Whether the configuration controls must be locked.
    ///
    /// True while a plan awaits confirmation and while it runs: changing
    /// the device, image or options then would describe something other
    /// than the plan in flight. Unlocked again once the run has finished.
    #[must_use]
    pub fn configuration_locked(&self) -> bool {
        matches!(&self.state, RunState::Confirming | RunState::Running { .. })
    }

    /// Derive the plan from `gui`, capture the displayed device facts and
    /// wait for confirmation.
    ///
    /// The plan is left without a confirm token, so nothing is runnable yet
    /// (see the module docs on the gate).
    pub fn start(&mut self, gui: &mut GuiState) -> Result<(), RunError> {
        if self.state != RunState::Idle {
            return Err(RunError::NotIdle);
        }
        let mut plan = gui.build_plan().map_err(RunError::Plan)?;
        let device = gui
            .device
            .as_ref()
            .map(DeviceFacts::from)
            .ok_or(RunError::Plan(GuiError::NoDevice))?;
        // `planner::build` seals its own provisional integrity hash; that is
        // not the user's approval, so the gate opens with no token at all.
        plan.confirm.clear();
        self.prepared = Some(Prepared { plan, device });
        self.state = RunState::Confirming;
        Ok(())
    }

    /// The runnable plan, available only once [`Run::confirm`] has attached
    /// the token. Before that the refusal is [`RunError::ConfirmationRequired`].
    pub fn confirmed_plan(&self) -> Result<&Plan, RunError> {
        match &self.state {
            RunState::Running { .. } | RunState::Finished(_) => self
                .prepared
                .as_ref()
                .map(|prepared| &prepared.plan)
                .ok_or(RunError::ConfirmationRequired),
            RunState::Idle | RunState::Confirming => Err(RunError::ConfirmationRequired),
        }
    }

    /// Recompute and attach the plan's confirm token, then start running.
    ///
    /// This is the only path from `Confirming` to `Running`, so a plan
    /// without a token is never fed to a transport.
    pub fn confirm(&mut self) -> Result<&Plan, RunError> {
        if self.state != RunState::Confirming {
            return Err(RunError::NotConfirming);
        }
        let prepared = self.prepared.as_mut().ok_or(RunError::NotConfirming)?;
        let token = prepared
            .plan
            .confirm()
            .map_err(|error| RunError::Confirm(error.to_string()))?;
        prepared.plan.confirm = token;
        self.state = RunState::Running {
            step: None,
            percent: None,
            rate: None,
            eta: None,
        };
        self.track = ProgressTrack::default();
        Ok(&prepared.plan)
    }

    /// Consume one helper event.
    ///
    /// `elapsed` is the time since the run started, used only by progress
    /// samples (see the module docs on time). Events outside `Running` are
    /// ignored, which is what makes a terminal event final.
    pub fn apply(&mut self, event: &Event, elapsed: Duration) {
        if !matches!(&self.state, RunState::Running { .. }) {
            return;
        }
        match event {
            Event::Progress(progress) => self.apply_progress(progress, elapsed),
            Event::Log(line) => self.push_log(line.level, &line.message),
            Event::Done(completion) => {
                self.state = RunState::Finished(completion.outcome.clone());
            }
        }
    }

    /// Ask the injected seam to stop the helper and finish as `Cancelled`.
    ///
    /// The terminal state is entered here, once; a second call refuses and
    /// no later progress or completion can move it.
    pub fn cancel(&mut self) -> Result<(), RunError> {
        if !matches!(&self.state, RunState::Running { .. }) {
            return Err(RunError::NotRunning);
        }
        self.cancel.request();
        self.state = RunState::Finished(Outcome::Cancelled);
        Ok(())
    }

    fn apply_progress(&mut self, progress: &Progress, elapsed: Duration) {
        // Stale samples: an earlier step, or fewer units within the current
        // step. Ignoring them outright is what keeps the display monotonic.
        if self.track.step_started.is_some() {
            if progress.step < self.track.step_index {
                return;
            }
            if progress.step == self.track.step_index && progress.done < self.track.last_done {
                return;
            }
        }

        let advanced = self.track.step_started.is_none() || progress.step > self.track.step_index;
        if advanced {
            self.track.step_index = progress.step;
            self.track.step_started = Some(elapsed);
        }
        let in_step = self
            .track
            .step_started
            .map_or(Duration::ZERO, |started| elapsed.saturating_sub(started));
        self.track.last_done = progress.done;

        let (last_step, last_percent) = match &self.state {
            RunState::Running { step, percent, .. } => (*step, *percent),
            _ => (None, None),
        };
        let percent = if advanced {
            progress.percent
        } else {
            match (last_percent, progress.percent) {
                // Within a step the percent only ever moves forward; a
                // sample that cannot size the step (no total) makes it
                // indeterminate again instead of freezing a stale figure.
                (Some(old), Some(new)) => Some(old.max(new)),
                (_, new) => new,
            }
        };
        let rate = rate_bytes_per_second(progress.done, in_step);
        self.state = RunState::Running {
            step: StepLabel::from_op(&progress.op).or(last_step),
            percent,
            rate: rate.map(|rate| format!("{}/s", human_bytes(rate))),
            eta: eta_seconds(progress.total, progress.done, rate).map(format_duration),
        };
    }

    fn push_log(&mut self, level: LogLevel, message: &str) {
        if self.logs.len() == LOG_LIMIT {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry {
            level,
            message: message.to_string(),
        });
    }
}

/// Average throughput of the current step in bytes per second.
///
/// `None` when there is nothing to divide: no units yet, no elapsed time, or
/// a rate that rounds down to zero (the drawer would otherwise show
/// `0 B/s` as if the step had stalled).
fn rate_bytes_per_second(done: u64, elapsed: Duration) -> Option<u64> {
    let micros = elapsed.as_micros();
    if done == 0 || micros == 0 {
        return None;
    }
    let rate = u64::try_from((u128::from(done) * 1_000_000) / micros).unwrap_or(u64::MAX);
    (rate > 0).then_some(rate)
}

/// Seconds left for `total - done` units at `rate`, rounded up.
///
/// `None` without a total or a rate; a completed step is `0:00`, not absent.
fn eta_seconds(total: Option<u64>, done: u64, rate: Option<u64>) -> Option<Duration> {
    let rate = rate?;
    let remaining = total?.saturating_sub(done);
    let seconds = (u128::from(remaining) + u128::from(rate) - 1) / u128::from(rate);
    Some(Duration::from_secs(
        u64::try_from(seconds).unwrap_or(u64::MAX),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use furus_linux::{Device, Partition, Transport};
    use furus_proto::{
        Completion, EVENT_STREAM_VERSION, Event, LogLevel, LogLine, Outcome, Progress,
    };

    use super::{CancelRequest, LOG_LIMIT, Run, RunError, RunState, StepLabel};
    use crate::state::GuiState;

    const SESSION: &str = "s-1";
    const MIB: u64 = 1_048_576;

    static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

    /// A 4 KiB sector image with no recognised container magic.
    struct ImageFile(PathBuf);

    impl ImageFile {
        fn raw() -> Self {
            let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("furus-gui-run-{}-{serial}.img", std::process::id()));
            fs::write(&path, [0xA5; 4096]).expect("write raw fixture");
            Self(path)
        }
    }

    impl Drop for ImageFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn sample_device() -> Device {
        Device {
            sysfs: "/sys/class/block/sdz".to_string(),
            name: "sdz".to_string(),
            dev_path: "/dev/sdz".to_string(),
            size_bytes: 32_010_928_128,
            sector_size: 512,
            physical_sector_size: 4096,
            removable: true,
            read_only: false,
            usb: true,
            vendor: Some("Furus".to_string()),
            model: Some("Test Stick".to_string()),
            serial: Some("ABC123".to_string()),
            transport: Transport::Usb,
            partition_table: None,
            vid_pid: Some("1234:5678".to_string()),
            port_path: Some("usb-1:2".to_string()),
            partitions: vec![Partition {
                name: "sdz1".to_string(),
                number: Some(1),
                size_bytes: 1_048_576,
                fstype: Some("vfat".to_string()),
            }],
        }
    }

    /// A ready-to-plan form; the fixture file stays alive with the tuple.
    fn selected() -> (GuiState, ImageFile) {
        let image = ImageFile::raw();
        let mut gui = GuiState::default();
        gui.select_device(&sample_device(), "not mounted");
        gui.select_image(&image.0, false).expect("inspect fixture");
        (gui, image)
    }

    fn running(
        run: &Run,
    ) -> (
        Option<StepLabel>,
        Option<u8>,
        Option<String>,
        Option<String>,
    ) {
        match run.state() {
            RunState::Running {
                step,
                percent,
                rate,
                eta,
            } => (*step, *percent, rate.clone(), eta.clone()),
            other => panic!("expected Running, got {other:?}"),
        }
    }

    fn progress(step: usize, op: &str, done: u64, total: Option<u64>) -> Event {
        Event::Progress(Progress::new(SESSION, step, op, done, total))
    }

    fn done(outcome: Outcome) -> Event {
        Event::Done(Completion {
            session: SESSION.to_string(),
            version: EVENT_STREAM_VERSION,
            outcome,
        })
    }

    #[test]
    fn start_never_yields_a_runnable_plan_before_the_confirmation_gate() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        run.start(&mut gui).expect("START builds a plan");

        assert_eq!(run.state(), &RunState::Confirming);
        assert!(run.configuration_locked());
        let plan = run.plan().expect("the provisional plan is shown");
        assert_eq!(
            plan.confirm, "",
            "START must not carry a confirmation token"
        );
        assert_eq!(
            run.confirmed_plan().err(),
            Some(RunError::ConfirmationRequired),
            "START alone can never produce a runnable plan"
        );
        assert_eq!(run.device().expect("captured facts").path, "/dev/sdz");
        assert_eq!(
            run.device().expect("captured facts").model.as_deref(),
            Some("Test Stick")
        );
        assert_eq!(
            run.device().expect("captured facts").serial.as_deref(),
            Some("ABC123")
        );
        assert_eq!(
            run.device().expect("captured facts").mount_summary,
            "not mounted"
        );
        assert_eq!(
            run.device().expect("captured facts").size_bytes,
            32_010_928_128
        );

        assert_eq!(run.start(&mut gui).err(), Some(RunError::NotIdle));
    }

    #[test]
    fn confirm_attaches_exactly_the_recomputed_sha256_token() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        run.start(&mut gui).expect("START builds a plan");

        let provisional = run.plan().expect("provisional plan").clone();
        assert_eq!(provisional.confirm, "", "no token before confirmation");

        let token = run
            .confirm()
            .expect("confirm attaches the token")
            .confirm
            .clone();
        assert_eq!(
            token,
            provisional.confirm().expect("recompute the plan hash"),
            "the attached token is the plan's own confirm hash"
        );
        assert!(token.starts_with("sha256:"));
        assert_eq!(token.len(), "sha256:".len() + 64);

        assert_eq!(
            run.state(),
            &RunState::Running {
                step: None,
                percent: None,
                rate: None,
                eta: None,
            }
        );
        assert_eq!(
            run.confirmed_plan().expect("gate open").confirm,
            token,
            "the runnable plan carries the same token"
        );
        assert_eq!(run.confirm().err(), Some(RunError::NotConfirming));
    }

    #[test]
    fn progress_maps_every_wire_op_and_never_regresses() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        run.start(&mut gui).expect("START");
        run.confirm().expect("confirm");

        let cases = [
            ("wipe", StepLabel::Wipe),
            ("mklabel", StepLabel::Table),
            ("mkpart", StepLabel::Partition),
            ("mkfs", StepLabel::Format),
            ("write", StepLabel::Write),
            ("bootloader", StepLabel::Bootloader),
            ("finalize", StepLabel::Finalise),
        ];
        let mut elapsed = Duration::from_secs(1);
        for (index, (op, label)) in cases.into_iter().enumerate() {
            let done = u64::try_from(index + 1).expect("small index");
            run.apply(&progress(index, op, done, Some(10)), elapsed);
            let (step, percent, _, _) = running(&run);
            assert_eq!(step, Some(label), "the {op} tag maps to {label}");
            assert_eq!(percent, Some((done * 10) as u8), "percent from the wire");
            elapsed += Duration::from_secs(1);
        }

        // A stale sample from an earlier step changes nothing.
        run.apply(&progress(2, "mkpart", 9, Some(10)), elapsed);
        let (step, percent, _, _) = running(&run);
        assert_eq!(step, Some(StepLabel::Finalise));
        assert_eq!(percent, Some(70));

        // Fewer units in the same step is stale too.
        run.apply(&progress(6, "finalize", 1, Some(10)), elapsed);
        let (step, percent, _, _) = running(&run);
        assert_eq!(step, Some(StepLabel::Finalise));
        assert_eq!(percent, Some(70));

        // More units but a lower reported percent (the total moved) still
        // never regresses the displayed percent.
        run.apply(&progress(6, "finalize", 8, Some(100)), elapsed);
        let (step, percent, _, _) = running(&run);
        assert_eq!(step, Some(StepLabel::Finalise));
        assert_eq!(percent, Some(70), "percent never decreases within a step");

        // An unknown op keeps the last known label instead of inventing one.
        run.apply(&progress(6, "future_op", 9, Some(100)), elapsed);
        assert_eq!(running(&run).0, Some(StepLabel::Finalise));
    }

    #[test]
    fn rate_and_eta_use_the_injected_elapsed_and_stay_unknown_without_data() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        run.start(&mut gui).expect("START");
        run.confirm().expect("confirm");

        // The first sample of a step only starts its clock.
        run.apply(
            &progress(4, "write", 0, Some(6 * MIB)),
            Duration::from_secs(2),
        );
        let (_, percent, rate, eta) = running(&run);
        assert_eq!(percent, Some(0));
        assert_eq!(rate, None, "a rate needs two points");
        assert_eq!(eta, None);

        // 3 MiB in 2 s → 1.50 MiB/s, 3 MiB left at that rate → 0:02.
        run.apply(
            &progress(4, "write", 3 * MIB, Some(6 * MIB)),
            Duration::from_secs(4),
        );
        let (_, percent, rate, eta) = running(&run);
        assert_eq!(percent, Some(50));
        assert_eq!(rate.as_deref(), Some("1.50 MiB/s"));
        assert_eq!(eta.as_deref(), Some("0:02"));

        // An indeterminate total keeps the rate but has no ETA.
        run.apply(&progress(4, "write", 6 * MIB, None), Duration::from_secs(6));
        let (_, percent, rate, eta) = running(&run);
        assert_eq!(percent, None, "no total, no percent");
        assert_eq!(rate.as_deref(), Some("1.50 MiB/s"));
        assert_eq!(eta, None);

        // A step advance starts a new clock: zero elapsed, no rate or ETA.
        run.apply(
            &progress(5, "bootloader", 0, Some(0)),
            Duration::from_secs(6),
        );
        let (step, percent, rate, eta) = running(&run);
        assert_eq!(step, Some(StepLabel::Bootloader));
        assert_eq!(percent, Some(100), "zero units is vacuously complete");
        assert_eq!(rate, None);
        assert_eq!(eta, None);

        // Zero units at a non-zero elapsed time is a zero rate, not 0 B/s.
        run.apply(
            &progress(5, "bootloader", 0, Some(0)),
            Duration::from_secs(8),
        );
        let (_, _, rate, eta) = running(&run);
        assert_eq!(rate, None);
        assert_eq!(eta, None);
    }

    #[test]
    fn cancel_mid_write_yields_exactly_one_cancelled_terminal_state() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let (mut gui, _image) = selected();
        let mut run = Run::with_cancel(CancelRequest::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
        run.start(&mut gui).expect("START");
        run.confirm().expect("confirm");

        run.apply(
            &progress(4, "write", MIB, Some(4 * MIB)),
            Duration::from_secs(1),
        );
        assert!(matches!(run.state(), RunState::Running { .. }));

        run.cancel().expect("cancel mid-write");
        assert_eq!(calls.load(Ordering::Relaxed), 1, "the seam was asked once");
        assert_eq!(run.state(), &RunState::Finished(Outcome::Cancelled));
        assert_eq!(run.cancel().err(), Some(RunError::NotRunning));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a repeat cancel never re-asks the seam"
        );

        // Nothing after the terminal event is accepted.
        run.apply(
            &progress(4, "write", 3 * MIB, Some(4 * MIB)),
            Duration::from_secs(2),
        );
        run.apply(
            &Event::Log(LogLine {
                session: SESSION.to_string(),
                level: LogLevel::Warn,
                message: "late line".to_string(),
            }),
            Duration::from_secs(2),
        );
        run.apply(&done(Outcome::Ok), Duration::from_secs(3));
        assert_eq!(run.state(), &RunState::Finished(Outcome::Cancelled));
        assert!(run.logs().is_empty(), "no post-cancel log lines");
    }

    #[test]
    fn configuration_is_locked_while_confirming_and_running_and_after_finish_unlocked() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        assert!(!run.configuration_locked(), "Idle is editable");

        run.start(&mut gui).expect("START");
        assert!(run.configuration_locked(), "Confirming locks the form");

        run.confirm().expect("confirm");
        assert!(run.configuration_locked(), "Running locks the form");

        run.apply(&done(Outcome::Ok), Duration::from_secs(1));
        assert_eq!(run.state(), &RunState::Finished(Outcome::Ok));
        assert!(!run.configuration_locked(), "Finished unlocks the form");

        // The terminal state is final: progress after Done changes nothing.
        run.apply(
            &progress(4, "write", MIB, Some(2 * MIB)),
            Duration::from_secs(2),
        );
        assert_eq!(run.state(), &RunState::Finished(Outcome::Ok));
    }

    #[test]
    fn log_lines_are_buffered_in_order_and_bounded() {
        let (mut gui, _image) = selected();
        let mut run = Run::new();
        run.start(&mut gui).expect("START");
        run.confirm().expect("confirm");

        let total = LOG_LIMIT + 5;
        for index in 0..total {
            run.apply(
                &Event::Log(LogLine {
                    session: SESSION.to_string(),
                    level: LogLevel::Info,
                    message: format!("line {index}"),
                }),
                Duration::ZERO,
            );
        }

        assert_eq!(run.logs().len(), LOG_LIMIT);
        assert_eq!(
            run.logs().front().map(|entry| entry.message.as_str()),
            Some("line 5"),
            "the oldest lines are dropped first"
        );
        assert_eq!(
            run.logs().back().map(|entry| entry.message.as_str()),
            Some("line 504")
        );
        assert_eq!(
            run.logs().back().map(|entry| entry.level),
            Some(LogLevel::Info)
        );
    }

    #[test]
    fn run_errors_have_pinned_display_strings() {
        use crate::state::GuiError;

        assert_eq!(
            RunError::ConfirmationRequired.to_string(),
            "The run must be confirmed before its plan can start."
        );
        assert_eq!(
            RunError::NotIdle.to_string(),
            "A run has already been started."
        );
        assert_eq!(
            RunError::NotConfirming.to_string(),
            "No plan is waiting for confirmation."
        );
        assert_eq!(RunError::NotRunning.to_string(), "No run is in progress.");
        assert_eq!(
            RunError::Plan(GuiError::NoDevice).to_string(),
            GuiError::NoDevice.to_string()
        );
        assert_eq!(
            RunError::Confirm("bad bytes".to_string()).to_string(),
            "Could not compute the plan confirmation: bad bytes"
        );
    }
}
