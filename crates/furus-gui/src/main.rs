//! `furus-gui`: the Slint front end for the Furus-for-Linux rewrite.
//!
//! Slice S24-C C2 wires the declarative shell (`ui/main.slint`) to the
//! headless [`GuiState`] view model from `src/state.rs`. The window is
//! pure presentation plus callbacks: every value the UI shows is pushed
//! from `GuiState`, every interaction is routed back through `GuiState`
//! (whose rules live behind the S23 planner), and START only ever
//! *plans* — this crate never writes to a device.
//!
//! Startup policy (contract 0.4.3/0.4.6, S24-T4):
//! * `--version` and `--help`/`-h` exit `0` before any Slint or display
//!   initialization, so they work with `DISPLAY` and `WAYLAND_DISPLAY`
//!   both absent;
//! * the GUI refuses to run as root (pure [`startup_refusal`] of the
//!   euid): the GUI is the unprivileged half of the split, all
//!   privileged device work belongs to the separate `furus-helper`
//!   privileged helper.
//!
//! Lint note (S24-C C2 deviation, recorded in the handoff):
//! `src/lib.rs` keeps `#![forbid(unsafe_code)]`; this binary target
//! uses `#![deny(unsafe_code)]` because Slint's generated code (via
//! `slint::include_modules!()` → `vtable-macro`'s
//! `ItemTreeVTable_static!`) hardcodes `#[allow(unsafe_code)]`, which
//! is the hard error E0453 under a crate-level `forbid`:
//!
//! ```text
//! error[E0453]: allow(unsafe_code) incompatible with previous forbid
//!     ItemTreeVTable_static ! (static VT for self :: InnerComboBox_root_1_popup_9) ;
//! ```
//!
//! `deny` keeps every hand-written line in this file free of `unsafe`
//! (no `#[allow(unsafe_code)]` appears anywhere in this crate's
//! sources); only Slint's macro expansions — which `forbid` cannot
//! legally coexist with in any crate — are exempt. The alternative is
//! moving `include_modules!` into a separate codegen-only crate.
//!
//! S24-C C3 adds the hotplug path: `src/devices.rs` (Slint-free, in the
//! library) owns discovery, the candidate filter, the watcher worker and
//! the epoch/sequence selection guard. This binary only marshals the
//! worker's publications onto the event loop through
//! `slint::invoke_from_event_loop`, so every `GuiState` and Slint
//! mutation still happens on the UI thread, and joins both threads
//! (`DeviceWorker::shutdown` + the dispatcher) after `ui.run()` returns.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use furus_core::planner::BootloaderOpt;
use furus_gui::analyzer::{AnalysisCoordinator, AnalysisResult, AnalyzerSender, AnalyzerWorker};
use furus_gui::checksum::{
    ChecksumCoordinator, ChecksumOutcome, ChecksumResult, ChecksumSender, ChecksumWorker,
};
use furus_gui::config_bridge::GuiPrefs;
use furus_gui::i18n_bridge::LocaleCatalog;
use furus_gui::ipc::{IpcError, PkexecTransport, open_helper, start_with_fallback};
use furus_gui::picker::PickerOutcome;
use furus_gui::run::{CancelRequest, DeviceFacts, LogEntry, Run, RunState};
use furus_gui::state::{GuiState, WindowsImageOption};
use furus_linux::Device;
use furus_linux::sysfs::{self, SysfsRoot};
use furus_proto::{
    Completion, EVENT_STREAM_VERSION, Event, Filesystem, Outcome, Plan, Scheme, Step, Target,
};
use rustix::process;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

slint::include_modules!();

/// Pure startup policy: refuse to run the GUI as root (A9).
///
/// The GUI is deliberately unprivileged; everything that needs root
/// (device writes, mkfs, bootloader installation) belongs to the
/// separate `furus-helper` privileged helper. There is no override
/// flag. Takes the effective uid so the rule is unit-testable without
/// being root.
#[must_use]
fn startup_refusal(euid: u32) -> Option<String> {
    if euid == 0 {
        Some(
            "furus-gui refuses to run as root (euid 0).\n\
             The GUI runs unprivileged by design; all privileged work\n\
             (device writes, mkfs, bootloader installation) belongs to\n\
             the separate furus-helper privileged helper, which the GUI\n\
             contacts over a restricted protocol. Run furus-gui as a\n\
             normal desktop user — there is no override flag."
                .to_string(),
        )
    } else {
        None
    }
}

fn print_version() {
    println!("furus-gui {}", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    println!(
        "furus-gui {} — graphical USB imaging front end (Slint)\n\
         \n\
         usage: furus-gui [OPTION] [IMAGE_PATH]\n\
         \n\
         options:\n\
         \x20 --version   print the version and exit\n\
         \x20 --help, -h  print this help and exit\n\
         \n\
         With no argument the GUI window opens. An optional positional\n\
         IMAGE_PATH pre-selects and analyzes the image at startup (e.g.\n\
         from a file manager's \"Open With\"). The GUI runs unprivileged\n\
         and refuses to start as root: privileged device work belongs to\n\
         the separate furus-helper privileged helper.",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> std::process::ExitCode {
    // Fast paths first: no Slint, no display, no euid check — these
    // must work headless in CI (contract 0.4.6). Parse OsString so an
    // arbitrary (non-UTF-8) filesystem path is accepted verbatim.
    let first = std::env::args_os().nth(1);
    if let Some(flag) = first.as_deref().and_then(|arg| arg.to_str()) {
        match flag {
            "--version" => {
                print_version();
                return std::process::ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print_help();
                return std::process::ExitCode::SUCCESS;
            }
            _ if flag.starts_with('-') => {
                eprintln!("furus-gui: unknown option '{flag}'");
                print_help();
                return std::process::ExitCode::FAILURE;
            }
            _ => {}
        }
    }

    if let Some(message) = startup_refusal(process::geteuid().as_raw()) {
        eprintln!("{message}");
        return std::process::ExitCode::FAILURE;
    }

    let startup_path = first.map(PathBuf::from);
    match run_gui(startup_path) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("furus-gui: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Label tables: the pure display domain of the form values. The strings
// shown in every combo are provided by Rust; `ui/main.slint` never holds
// lists or defaults. All compatibility rules stay in `furus_core::planner`
// behind `GuiState`.
// ---------------------------------------------------------------------------

const SCHEME_LABELS: &[&str] = &["MBR", "GPT"];
const TARGET_LABELS: &[&str] = &["BIOS", "UEFI", "Dual (BIOS/UEFI)"];
const FS_LABELS: &[&str] = &["FAT32", "exFAT", "NTFS", "UDF", "ext2", "ext3", "ext4"];
const IMAGE_OPTION_LABELS: &[&str] = &["Standard Windows installation", "Windows To Go"];
const BOOT_LABELS: &[&str] = &[
    "Auto",
    "Syslinux",
    "GRUB 2",
    "GRUB4DOS",
    "UEFI:NTFS",
    "FreeDOS",
    "KolibriOS",
    "MS-DOS",
    "Windows installer",
    "None (non-bootable)",
];
const CLUSTER_LABELS: &[&str] = &[
    "Default",
    "512 bytes",
    "1 KB",
    "2 KB",
    "4 KB",
    "8 KB",
    "16 KB",
    "32 KB",
    "64 KB",
];
const CLUSTER_BYTES: &[Option<u32>] = &[
    None,
    Some(512),
    Some(1024),
    Some(2048),
    Some(4096),
    Some(8192),
    Some(16384),
    Some(32768),
    Some(65536),
];
const PASSES_LABELS: &[&str] = &["1", "2", "3", "4"];

fn scheme_label(value: &Scheme) -> &'static str {
    match value {
        Scheme::Mbr => "MBR",
        Scheme::Gpt => "GPT",
    }
}

fn scheme_value(label: &str) -> Scheme {
    match label {
        "GPT" => Scheme::Gpt,
        _ => Scheme::Mbr,
    }
}

fn target_label(value: &Target) -> &'static str {
    match value {
        Target::Bios => "BIOS",
        Target::Uefi => "UEFI",
        Target::Dual => "Dual (BIOS/UEFI)",
    }
}

fn target_value(label: &str) -> Target {
    match label {
        "BIOS" => Target::Bios,
        "Dual (BIOS/UEFI)" => Target::Dual,
        _ => Target::Uefi,
    }
}

fn fs_label(value: &Filesystem) -> &'static str {
    match value {
        Filesystem::Fat32 => "FAT32",
        Filesystem::Exfat => "exFAT",
        Filesystem::Ntfs => "NTFS",
        Filesystem::Udf => "UDF",
        Filesystem::Ext2 => "ext2",
        Filesystem::Ext3 => "ext3",
        Filesystem::Ext4 => "ext4",
    }
}

fn fs_value(label: &str) -> Filesystem {
    match label {
        "exFAT" => Filesystem::Exfat,
        "NTFS" => Filesystem::Ntfs,
        "UDF" => Filesystem::Udf,
        "ext2" => Filesystem::Ext2,
        "ext3" => Filesystem::Ext3,
        "ext4" => Filesystem::Ext4,
        _ => Filesystem::Fat32,
    }
}

fn image_option_label(value: &WindowsImageOption) -> &'static str {
    match value {
        WindowsImageOption::Standard => "Standard Windows installation",
        WindowsImageOption::WindowsToGo => "Windows To Go",
    }
}

fn image_option_value(label: &str) -> WindowsImageOption {
    match label {
        "Windows To Go" => WindowsImageOption::WindowsToGo,
        _ => WindowsImageOption::Standard,
    }
}

fn boot_label(value: &BootloaderOpt) -> &'static str {
    match value {
        BootloaderOpt::Auto => "Auto",
        BootloaderOpt::Syslinux => "Syslinux",
        BootloaderOpt::Grub2 => "GRUB 2",
        BootloaderOpt::Grub4dos => "GRUB4DOS",
        BootloaderOpt::UefiNtfs => "UEFI:NTFS",
        BootloaderOpt::Freedos => "FreeDOS",
        BootloaderOpt::Kolibri => "KolibriOS",
        BootloaderOpt::MsDos => "MS-DOS",
        BootloaderOpt::Windows => "Windows installer",
        BootloaderOpt::None => "None (non-bootable)",
    }
}

fn boot_value(label: &str) -> BootloaderOpt {
    match label {
        "Syslinux" => BootloaderOpt::Syslinux,
        "GRUB 2" => BootloaderOpt::Grub2,
        "GRUB4DOS" => BootloaderOpt::Grub4dos,
        "UEFI:NTFS" => BootloaderOpt::UefiNtfs,
        "FreeDOS" => BootloaderOpt::Freedos,
        "KolibriOS" => BootloaderOpt::Kolibri,
        "MS-DOS" => BootloaderOpt::MsDos,
        "Windows installer" => BootloaderOpt::Windows,
        "None (non-bootable)" => BootloaderOpt::None,
        _ => BootloaderOpt::Auto,
    }
}

fn cluster_label(value: Option<u32>) -> &'static str {
    CLUSTER_BYTES
        .iter()
        .position(|bytes| *bytes == value)
        .map_or("Default", |index| CLUSTER_LABELS[index])
}

fn cluster_value(label: &str) -> Option<u32> {
    CLUSTER_LABELS
        .iter()
        .position(|candidate| *candidate == label)
        .and_then(|index| CLUSTER_BYTES[index])
}

fn passes_label(value: u8) -> &'static str {
    match value {
        2 => "2",
        3 => "3",
        4.. => "4",
        _ => "1",
    }
}

fn passes_value(label: &str) -> u8 {
    match label {
        "2" => 2,
        "3" => 3,
        "4" => 4,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Display helpers (presentation only).
// ---------------------------------------------------------------------------

fn human_size(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
}

fn device_label(device: &Device) -> String {
    let mut label = format!("{} ({})", device.dev_path, human_size(device.size_bytes));
    if let Some(model) = &device.model {
        label.push(' ');
        label.push_str(model);
    }
    if let Some(serial) = &device.serial {
        label.push_str(&format!(" [{serial}]"));
    }
    label
}

/// Read-only mount-state summary from `/proc/self/mounts` (display
/// facts only; reads of `/proc` are allowed for the GUI).
fn mount_summary(device: &Device) -> String {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return "mount state unknown".to_string();
    };
    for line in mounts.lines() {
        let Some((source, rest)) = line.split_once(' ') else {
            continue;
        };
        let same = source == device.dev_path
            || source
                .strip_prefix(&device.dev_path)
                .is_some_and(|tail| tail.chars().all(|c| c.is_ascii_digit()));
        if same {
            let target = rest.split(' ').next().unwrap_or("?");
            return format!("mounted at {target}");
        }
    }
    "not mounted".to_string()
}

fn step_name(step: &Step) -> &'static str {
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

/// Read-only description of a planned `Plan` for the status line: the
/// plan the GUI *reports* (START never writes anything).
fn describe_plan(plan: &Plan) -> String {
    let steps: Vec<&str> = plan.steps.iter().map(step_name).collect();
    format!(
        "steps: {} (scheme {:?}, target {:?}, fs {:?})",
        steps.join(" → "),
        plan.options.scheme,
        plan.options.target,
        plan.options.filesystem
    )
}

// ---------------------------------------------------------------------------
// S25 slice 5 presentation infrastructure. The rules stay in `run` and the
// transports in `ipc`; everything below is formatting or threading glue.
// ---------------------------------------------------------------------------

/// One-shot bridge from the UI thread to the worker's `CancelHandle`.
///
/// The `Run` owns a `CancelRequest` whose action is `bridge.request()`. The
/// handle only exists once the worker has started the transport, so an early
/// cancellation is latched and delivered at `install` instead of being lost.
#[derive(Clone, Default)]
struct CancelBridge {
    inner: Arc<Mutex<CancelBridgeInner>>,
}

#[derive(Default)]
struct CancelBridgeInner {
    requested: bool,
    fired: bool,
    sink: Option<Box<dyn Fn() + Send>>,
}

impl CancelBridge {
    fn request(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.fired {
            return;
        }
        inner.requested = true;
        if let Some(sink) = inner.sink.as_ref() {
            sink();
            inner.fired = true;
        }
    }

    /// Install the worker's cancellation action. A request made before the
    /// transport was ready is delivered exactly once here.
    fn install(&self, sink: impl Fn() + Send + 'static) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.sink = Some(Box::new(sink));
        if inner.requested && !inner.fired {
            inner.sink.as_ref().expect("sink was just installed")();
            inner.fired = true;
        }
    }
}

/// Every display value the window needs from the run machine, in one
/// snapshot so `render` never has to interpret a `RunState` itself.
struct RunView {
    progress: f32,
    detail: String,
    locked: bool,
    cancel_enabled: bool,
    start_enabled: bool,
    terminal: Option<String>,
}

/// Pure render-input helper: format progress, derive the lock flags and the
/// terminal status. No reference to Slint, a transport or a device.
fn run_view(run: &Run) -> RunView {
    let locked = run.configuration_locked();
    let mut progress = 0.0_f32;
    let mut detail = String::new();
    let mut cancel_enabled = false;
    let mut start_enabled = false;
    let mut terminal = None;
    match run.state() {
        RunState::Idle => start_enabled = true,
        RunState::Confirming => {}
        RunState::Running {
            step,
            percent,
            rate,
            eta,
        } => {
            cancel_enabled = true;
            progress = percent.map_or(0.0, |percent| f32::from(percent) / 100.0);
            let mut parts: Vec<String> = Vec::new();
            if let Some(step) = step {
                parts.push(format!("step {}", step.as_str()));
            }
            if let Some(percent) = percent {
                parts.push(format!("{percent}%"));
            }
            if let Some(rate) = rate {
                parts.push(rate.clone());
            }
            if let Some(eta) = eta {
                parts.push(format!("ETA {eta}"));
            }
            detail = parts.join(" · ");
        }
        RunState::Finished(outcome) => {
            progress = 1.0;
            start_enabled = true;
            terminal = Some(outcome_text(outcome));
        }
    }
    RunView {
        progress,
        detail,
        locked,
        cancel_enabled,
        start_enabled,
        terminal,
    }
}

fn outcome_text(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Ok => "Completed successfully.".to_string(),
        Outcome::Cancelled => "Cancelled.".to_string(),
        Outcome::Refused { code, message } => format!("Refused ({code}): {message}"),
        Outcome::Failed { code, message } => format!("Failed ({code}): {message}"),
    }
}

/// Facts shown in the destructive confirmation dialog: exactly the ones the
/// user saw on the form, plus an explicit irreversibility warning.
fn confirmation_facts(facts: &DeviceFacts) -> String {
    // The helper's fast validation will unmount an ordinary mount before
    // writing, so say so in the destructive confirmation. The other two
    // mount states are display facts only and stay untouched.
    let mounts = if facts.mount_summary.starts_with("mounted at ") {
        format!("{} (will be unmounted automatically)", facts.mount_summary)
    } else {
        facts.mount_summary.clone()
    };
    format!(
        "Model: {}\n\
         Path: {}\n\
         Serial: {}\n\
         Capacity: {} ({} bytes)\n\
         Existing mounts: {}\n\
         \n\
         WARNING: this will DESTROY all data on this device.\n\
         The operation cannot be undone.",
        facts.model.as_deref().unwrap_or("unknown model"),
        facts.path,
        facts.serial.as_deref().unwrap_or("no serial"),
        human_size(facts.size_bytes),
        facts.size_bytes,
        mounts,
    )
}

fn log_line(entry: &LogEntry) -> String {
    format!("[{}] {}", entry.level.as_str(), entry.message)
}

fn log_lines<'a>(entries: impl IntoIterator<Item = &'a LogEntry>) -> Vec<String> {
    entries.into_iter().map(log_line).collect()
}

// ---------------------------------------------------------------------------
// S25 slice 6 checksum modal display helpers (presentation only). The
// coordinator in `checksum.rs` owns every state decision; these only turn a
// `ChecksumResult` snapshot into the strings and fraction Slint renders.
// ---------------------------------------------------------------------------

/// Copyable hex strings in MD5 / SHA-1 / SHA-256 / SHA-512 order. Only a
/// finished result fills them, so a cancelled/failed run shows no partial
/// digests as if they were complete.
fn checksum_digests(result: Option<&ChecksumResult>) -> [String; 4] {
    match result {
        Some(result) if result.outcome == Some(ChecksumOutcome::Finished) => [
            result.digests.md5.clone().unwrap_or_default(),
            result.digests.sha1.clone().unwrap_or_default(),
            result.digests.sha256.clone().unwrap_or_default(),
            result.digests.sha512.clone().unwrap_or_default(),
        ],
        _ => std::array::from_fn(|_| String::new()),
    }
}

/// Status line for the modal: computing, finished, cancelled or the named
/// failure. No hashing or policy here — just text for what the worker sent.
fn checksum_status(result: Option<&ChecksumResult>) -> String {
    match result {
        None => "Computing digests…".to_string(),
        Some(result) => match &result.outcome {
            None => format!("Computing digests… {}%", result.progress),
            Some(ChecksumOutcome::Finished) => {
                let name = result.path.file_name().map_or_else(
                    || result.path.display().to_string(),
                    |n| n.to_string_lossy().into(),
                );
                format!("Finished — all four digests for {name}.")
            }
            Some(ChecksumOutcome::Cancelled) => {
                "Cancelled — no digests were completed.".to_string()
            }
            Some(ChecksumOutcome::Failed(message)) => format!("Failed: {message}"),
        },
    }
}

fn checksum_progress(result: Option<&ChecksumResult>) -> f32 {
    result.map_or(0.0, |result| f32::from(result.progress) / 100.0)
}

fn checksum_cancel_enabled(visible: bool, result: Option<&ChecksumResult>) -> bool {
    visible && result.is_none_or(|result| result.outcome.is_none())
}

/// A live system bus is addressable when its well-known socket exists or the
/// address was overridden. Construction never connects: the real probe is
/// only used by the worker, so tests stay offline. The live D-Bus path is
/// unverified in this environment (no system bus).
fn prefer_system_bus() -> bool {
    std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_some()
        || std::path::Path::new("/run/dbus/system_bus_socket").exists()
}

/// Messages the worker publishes to the UI thread. All `Run` mutations still
/// happen on the event loop; this channel only carries data.
enum RunMessage {
    Event(Result<Event, IpcError>),
    Failed(String),
    Stop,
}

fn finish_run_as_failed(session: &mut Session, code: &str, message: String) {
    session.run.apply(
        &Event::Done(Completion {
            session: String::new(),
            version: EVENT_STREAM_VERSION,
            outcome: Outcome::Failed {
                code: code.to_string(),
                message: message.clone(),
            },
        }),
        Duration::ZERO,
    );
}

/// Transport work runs here because `start` may block on polkit for the whole
/// authorization budget. No Slint API is touched from this thread.
fn run_worker(plan: Plan, bridge: CancelBridge, sender: mpsc::Sender<RunMessage>) {
    let mut transport = open_helper(prefer_system_bus);
    match start_with_fallback(&mut transport, &plan, || Box::new(PkexecTransport::new())) {
        Ok(started) => {
            bridge.install({
                let cancel = started.cancel.clone();
                move || {
                    let _ = cancel.cancel();
                }
            });
            for event in started.events {
                if sender.send(RunMessage::Event(event)).is_err() {
                    break;
                }
            }
        }
        Err(error) => {
            let _ = sender.send(RunMessage::Failed(error.to_string()));
        }
    }
}

enum AnalysisMessage {
    Result(Box<AnalysisResult>),
    Stop,
}

fn model<I, S>(labels: I) -> ModelRc<SharedString>
where
    I: IntoIterator<Item = S>,
    S: Into<SharedString>,
{
    ModelRc::from(Rc::new(VecModel::from(
        labels
            .into_iter()
            .map(Into::into)
            .collect::<Vec<SharedString>>(),
    )))
}

// ---------------------------------------------------------------------------
// Session: the GUI-side wiring state. All business state lives in
// `GuiState`; the session only remembers the discovered device list and
// display-only extras (progress fraction, transient notes).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SessionHandle(Arc<Mutex<Session>>);

impl SessionHandle {
    fn new(session: Session) -> Self {
        Self(Arc::new(Mutex::new(session)))
    }

    fn borrow(&self) -> MutexGuard<'_, Session> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn borrow_mut(&self) -> MutexGuard<'_, Session> {
        self.borrow()
    }
}

struct Session {
    state: GuiState,
    analyzer: AnalysisCoordinator,
    device_list: furus_gui::devices::DeviceListState,
    note: Option<String>,
    run: Run,
    cancel_bridge: CancelBridge,
    run_started: Option<Instant>,
    checksum: ChecksumCoordinator,
    checksum_visible: bool,
    checksum_result: Option<ChecksumResult>,
    /// START requested while the current selection's SHA-256 was pending.
    start_pending_digest: bool,
    /// Locale catalog and active tag: text/flags only, never a business rule.
    bridge: Arc<LocaleCatalog>,
    lang: String,
    /// Persisted GUI-only preferences (locale tag, hash toggles, advanced).
    prefs: GuiPrefs,
}

impl Session {
    /// Test constructor: embedded catalog and in-memory prefs, so a headless
    /// `Session` never reads or writes a config file. Production startup
    /// uses [`Session::with_prefs`] with the loaded bridge and prefs.
    #[cfg(test)]
    fn new(discovery: furus_gui::devices::Discovery) -> Self {
        Self::with_prefs(
            discovery,
            Arc::new(LocaleCatalog::embedded(None)),
            GuiPrefs::defaults(furus_core::paths::default_config_path()),
        )
    }

    /// Production/startup constructor: supply the loaded bridge and prefs.
    fn with_prefs(
        discovery: furus_gui::devices::Discovery,
        bridge: Arc<LocaleCatalog>,
        prefs: GuiPrefs,
    ) -> Self {
        let lang = prefs
            .locale()
            .map(str::to_string)
            .unwrap_or_else(|| bridge.lang().to_string());
        let mut device_list =
            furus_gui::devices::DeviceListState::new(discovery.devices, discovery.warning);
        let first = device_list.devices().first().cloned();
        if let Some(device) = &first {
            device_list.initialize_selection(Some(device.identity()));
        }
        let note = device_list.error().map(str::to_string);
        let mut session = Self {
            state: GuiState::default(),
            analyzer: AnalysisCoordinator::default(),
            device_list,
            note,
            run: Run::new(),
            cancel_bridge: CancelBridge::default(),
            run_started: None,
            checksum: ChecksumCoordinator::default(),
            checksum_visible: false,
            checksum_result: None,
            start_pending_digest: false,
            bridge,
            lang,
            prefs,
        };
        session.new_run();
        if let Some(first) = first {
            let summary = mount_summary(&first);
            session.state.select_device(&first, summary);
        }
        session
    }

    /// Give the next run a fresh one-shot cancel bridge. A new run is only
    /// created after a terminal outcome, so no old worker can still install
    /// a handle into it.
    fn new_run(&mut self) {
        let bridge = CancelBridge::default();
        self.run = Run::with_cancel(CancelRequest::new({
            let bridge = bridge.clone();
            move || bridge.request()
        }));
        self.cancel_bridge = bridge;
        self.run_started = None;
    }

    fn select_device(&mut self, label: &str) -> Option<u64> {
        let device = self
            .device_list
            .devices()
            .iter()
            .find(|device| device_label(device) == label)
            .cloned()?;
        let epoch = self.device_list.user_selected(Some(device.identity()));
        let summary = mount_summary(&device);
        self.state.select_device(&device, summary);
        self.note = None;
        Some(epoch)
    }

    fn apply_devices(&mut self, update: furus_gui::devices::DeviceUpdate) -> bool {
        if !self.device_list.apply(update) {
            return false;
        }
        let selected = self.device_list.selected_identity().map(str::to_string);
        match selected.and_then(|identity| {
            self.device_list
                .devices()
                .iter()
                .find(|device| device.identity() == identity)
        }) {
            Some(device) => self.state.select_device(device, mount_summary(device)),
            None if self.state.device.is_some() => self.state.clear_device(),
            None => {}
        }
        self.note = self.device_list.error().map(str::to_string);
        true
    }

    fn select_image(&mut self, path: PathBuf, sender: &AnalyzerSender) {
        self.start_pending_digest = false;
        self.note = None;
        let request_id = self.analyzer.begin(&mut self.state, &path);
        if let Err(error) = sender.submit(request_id, path.clone()) {
            let _ = self.analyzer.apply(
                &mut self.state,
                AnalysisResult {
                    request_id,
                    path,
                    result: Err(error),
                },
            );
        }
    }

    fn apply_analysis(&mut self, result: AnalysisResult) -> bool {
        let is_digest_ready = matches!(
            result.result,
            Ok(furus_gui::analyzer::AnalysisPhase::DigestReady { .. })
        );
        let applied = self.analyzer.apply(&mut self.state, result);
        if applied && is_digest_ready && self.start_pending_digest {
            self.start_pending_digest = false;
            self.start();
        } else if applied {
            self.note = self
                .state
                .clone()
                .build_plan()
                .err()
                .map(|error| format!("Refused to plan: {error}"));
        }
        applied
    }

    /// Open the modal at 0% with no digests and hand the selected image to
    /// the checksum worker. All request-id and stale decisions live in the
    /// coordinator; this method only starts the request and stores the view.
    fn begin_checksum(&mut self, sender: &ChecksumSender) {
        let Some(image) = self.state.image.as_ref() else {
            return;
        };
        let path = PathBuf::from(&image.image.path);
        let (request_id, token) = self.checksum.begin(&path);
        self.checksum_visible = true;
        self.checksum_result = None;
        if let Err(error) = sender.submit(request_id, path.clone(), token) {
            let failed = ChecksumResult::failed(request_id, path, error);
            self.apply_checksum_result(failed);
        }
    }

    /// Apply a worker publication through the coordinator's stale guard.
    /// False means the result belonged to a superseded request and no UI
    /// state was touched.
    fn apply_checksum_result(&mut self, result: ChecksumResult) -> bool {
        if !self.checksum.apply(result.clone()) {
            return false;
        }
        self.checksum_result = Some(result);
        true
    }

    fn request_checksum_cancel(&mut self) {
        self.checksum.cancel();
    }

    fn close_checksum(&mut self) {
        // Closing while a run is in flight still cancels it; after a terminal
        // result the token is already cleared, so this is a harmless no-op.
        self.checksum.cancel();
        self.checksum_visible = false;
    }

    /// START only plans and opens the confirmation gate. No transport is
    /// touched here, so this remains a no-write operation.
    fn start(&mut self) {
        if matches!(self.run.state(), RunState::Finished(_)) {
            self.new_run();
        }
        if self.state.image_digest_pending() {
            self.start_pending_digest = true;
            self.note = Some("START queued — computing image SHA-256…".to_string());
            return;
        }
        match self.run.start(&mut self.state) {
            Ok(()) => {
                let plan = self.run.plan().expect("START prepared a plan");
                self.note = Some(format!(
                    "Planned: {}. No device writes were performed.",
                    describe_plan(plan)
                ));
            }
            Err(error) => {
                self.note = Some(format!(
                    "Planning refused: {error}. No device writes were performed."
                ));
            }
        }
    }

    fn confirm(&mut self) -> Option<Plan> {
        let result = self.run.confirm().cloned();
        match result {
            Ok(plan) => {
                self.note = None;
                self.run_started = Some(Instant::now());
                Some(plan)
            }
            Err(error) => {
                self.note = Some(error.to_string());
                None
            }
        }
    }

    fn apply_run_message(&mut self, message: RunMessage) {
        match message {
            RunMessage::Event(Ok(event)) => {
                let elapsed = self
                    .run_started
                    .map_or(Duration::ZERO, |start| start.elapsed());
                self.run.apply(&event, elapsed);
            }
            RunMessage::Event(Err(error)) => {
                self.note = Some(format!("Helper error: {error}"));
                finish_run_as_failed(self, "ipc", error.to_string());
            }
            RunMessage::Failed(text) => {
                self.note = Some(format!("Could not start helper: {text}"));
                finish_run_as_failed(self, "ipc", text);
            }
            RunMessage::Stop => {}
        }
    }

    fn discard(&mut self) {
        self.new_run();
        self.start_pending_digest = false;
        self.note = None;
    }

    /// Persist GUI-only prefs and surface a save failure in the status line.
    /// A failure never rolls back the in-memory pref (the UI stays in sync
    /// with what the user just clicked) but it is reported honestly.
    fn save_prefs(&mut self) {
        if let Err(error) = self.prefs.save() {
            self.note = Some(format!("Could not save preferences: {error}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering: `GuiState` -> UI properties. One-way display; the only
// strings the window shows come from here.
// ---------------------------------------------------------------------------

/// Pure caption formatter: resolve one static caption id through the bridge.
///
/// The caption ids and their English literals live in the Rust i18n bridge;
/// `main.rs` only marshals the resolved text into a Slint property.
fn caption(bridge: &LocaleCatalog, lang: &str, msgid: &str) -> String {
    bridge.translate(lang, msgid)
}

fn status_with_device_warning(status: &str, note: Option<&str>, warning: Option<&str>) -> String {
    [Some(status), note, warning]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn render(session: &Session, ui: &MainWindow) {
    let state = &session.state;
    let run_view = run_view(&session.run);

    // Slice 7: locale, translated captions and GUI-only preferences. The
    // bridge decides all text; `render` only marshals it into properties.
    let lang = session.lang.as_str();
    let bridge = &session.bridge;
    ui.set_locale_model(model(
        bridge
            .locale_entries()
            .into_iter()
            .map(|(_, display)| display),
    ));
    ui.set_locale_current(SharedString::from(bridge.display_name(lang)));
    ui.set_rtl(bridge.rtl(lang));
    ui.set_caption_device(SharedString::from(caption(bridge, lang, "IDS_DEVICE_TXT")));
    ui.set_caption_boot(SharedString::from(caption(
        bridge,
        lang,
        "IDS_BOOT_SELECTION_TXT",
    )));
    ui.set_caption_partition(SharedString::from(caption(
        bridge,
        lang,
        "IDS_PARTITION_TYPE_TXT",
    )));
    ui.set_caption_target(SharedString::from(caption(
        bridge,
        lang,
        "IDS_TARGET_SYSTEM_TXT",
    )));
    ui.set_caption_fs(SharedString::from(caption(
        bridge,
        lang,
        "IDS_FILE_SYSTEM_TXT",
    )));
    ui.set_caption_cluster(SharedString::from(caption(
        bridge,
        lang,
        "IDS_CLUSTER_SIZE_TXT",
    )));
    ui.set_caption_format_options(SharedString::from(caption(
        bridge,
        lang,
        "IDS_FORMAT_OPTIONS_TXT",
    )));

    let prefs = &session.prefs;
    ui.set_advanced_visible(prefs.advanced_visible());
    ui.set_hash_md5_checked(prefs.hash_md5());
    ui.set_hash_sha1_checked(prefs.hash_sha1());
    ui.set_hash_sha256_checked(prefs.hash_sha256());
    ui.set_hash_sha512_checked(prefs.hash_sha512());

    ui.set_device_model(model(
        session.device_list.devices().iter().map(device_label),
    ));
    ui.set_device_current(SharedString::from(
        state
            .device
            .as_ref()
            .and_then(|selection| {
                session
                    .device_list
                    .devices()
                    .iter()
                    .find(|device| device.dev_path == selection.path)
            })
            .map_or_else(String::new, device_label),
    ));
    ui.set_device_info(SharedString::from(match &state.device {
        Some(selection) => format!(
            "{} — {} — {} — {} — {}",
            selection.path,
            human_size(selection.size_bytes),
            selection.model.as_deref().unwrap_or("unknown model"),
            selection.serial.as_deref().unwrap_or("no serial"),
            selection.mount_summary,
        ),
        None => "No removable device selected.".to_string(),
    }));

    ui.set_boot_model(model(BOOT_LABELS.iter().copied()));
    ui.set_boot_current(SharedString::from(boot_label(&state.bootloader)));

    ui.set_select_enabled(true);
    ui.set_checksum_enabled(state.image.is_some());

    ui.set_image_option_model(model(IMAGE_OPTION_LABELS.iter().copied()));
    ui.set_image_option_visible(state.image_option_enabled());
    ui.set_image_option_current(SharedString::from(image_option_label(&state.image_option)));

    ui.set_scheme_model(model(SCHEME_LABELS.iter().copied()));
    ui.set_scheme_current(SharedString::from(scheme_label(&state.scheme)));
    ui.set_target_model(model(TARGET_LABELS.iter().copied()));
    ui.set_target_current(SharedString::from(target_label(&state.target)));

    ui.set_fs_model(model(FS_LABELS.iter().copied()));
    ui.set_fs_enabled(state.filesystem_enabled());
    ui.set_fs_current(SharedString::from(fs_label(&state.filesystem)));

    ui.set_cluster_model(model(CLUSTER_LABELS.iter().copied()));
    ui.set_cluster_current(SharedString::from(cluster_label(state.cluster_bytes)));

    ui.set_volume_label(SharedString::from(
        state.volume_label.clone().unwrap_or_default(),
    ));
    ui.set_extended_label_checked(state.extended_label);
    ui.set_quick_format_checked(state.quick_format);

    let bad_blocks = state.bad_blocks_passes > 0;
    ui.set_bad_blocks_checked(bad_blocks);
    ui.set_passes_model(model(PASSES_LABELS.iter().copied()));
    ui.set_passes_enabled(bad_blocks);
    ui.set_passes_current(SharedString::from(passes_label(
        state.bad_blocks_passes.max(1),
    )));

    // The lock flag from `Run` gates every configuration control with one
    // binding; the per-control flags above still express weaker rules
    // (e.g. the checksum button needs an analysed image).
    ui.set_form_enabled(!run_view.locked);
    ui.set_cancel_enabled(run_view.cancel_enabled);
    ui.set_start_enabled(state.start_enabled() && run_view.start_enabled);

    let confirming = matches!(session.run.state(), RunState::Confirming);
    ui.set_confirm_visible(confirming);
    if confirming {
        ui.set_confirm_facts(SharedString::from(
            session
                .run
                .device()
                .map_or_else(String::new, confirmation_facts),
        ));
    }

    ui.set_progress_value(run_view.progress);
    ui.set_step_text(SharedString::from(run_view.detail.clone()));
    ui.set_log_text(SharedString::from(log_lines(session.run.logs()).join("\n")));

    let checksum_result = session.checksum_result.as_ref();
    ui.set_checksum_visible(session.checksum_visible);
    ui.set_checksum_progress(checksum_progress(checksum_result));
    ui.set_checksum_digests(model(checksum_digests(checksum_result)));
    ui.set_checksum_status(SharedString::from(checksum_status(checksum_result)));
    ui.set_checksum_cancel_enabled(checksum_cancel_enabled(
        session.checksum_visible,
        checksum_result,
    ));

    let mut status = state.status_text().to_string();
    if let Some(terminal) = &run_view.terminal {
        status.push('\n');
        status.push_str(terminal);
    }
    ui.set_status_text(SharedString::from(status_with_device_warning(
        &status,
        session.note.as_deref(),
        session.device_list.warning(),
    )));
}

// ---------------------------------------------------------------------------
// Window construction and callback wiring.
// ---------------------------------------------------------------------------

fn run_gui(startup_path: Option<PathBuf>) -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    let discovery = match sysfs::enumerate(&SysfsRoot::new("/sys")) {
        Ok(found) => furus_gui::devices::discover_candidates(found, false),
        Err(error) => furus_gui::devices::Discovery {
            devices: Vec::new(),
            warning: Some(format!("Device discovery failed: {error}")),
        },
    };
    // Startup: load one TOML config through the core-owned bridge, then
    // build the asset-or-embedded catalog for the saved locale. A load
    // failure is reported but never overwrites the user's config file.
    let config_path = furus_core::paths::default_config_path();
    let (prefs, warning) = match GuiPrefs::load(&config_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("furus-gui: could not load GUI preferences: {error}");
            (GuiPrefs::defaults(&config_path), None)
        }
    };
    let bridge = Arc::new(LocaleCatalog::load(prefs.locale()));
    let mut started = Session::with_prefs(discovery, bridge, prefs);
    if let Some(warning) = warning {
        started.note = Some(warning);
    }
    let session = SessionHandle::new(started);
    let epoch = Arc::new(AtomicU64::new(0));
    let (analysis_tx, analysis_rx) = mpsc::channel::<AnalysisMessage>();
    let analysis_shutdown_tx = analysis_tx.clone();
    let analysis_dispatch_session = session.clone();
    let analysis_dispatch_weak = ui.as_weak();
    let analysis_dispatcher = thread::spawn(move || {
        while let Ok(message) = analysis_rx.recv() {
            let AnalysisMessage::Result(result) = message else {
                break;
            };
            let result = *result;
            let session = analysis_dispatch_session.clone();
            let weak = analysis_dispatch_weak.clone();
            if slint::invoke_from_event_loop(move || {
                let mut session = session.borrow_mut();
                if session.apply_analysis(result)
                    && let Some(ui) = weak.upgrade()
                {
                    render(&session, &ui);
                }
            })
            .is_err()
            {
                break;
            }
        }
    });
    let analyzer = AnalyzerWorker::spawn_production(move |result| {
        analysis_tx
            .send(AnalysisMessage::Result(Box::new(result)))
            .is_ok()
    });
    let analyzer_sender = analyzer.sender();

    // Checksum worker: one long-lived thread publishing progress and the
    // terminal result into an mpsc channel. The dispatcher is the only place
    // that touches Session/Slint, matching the analysis and device paths.
    let (checksum_tx, checksum_rx) = mpsc::channel::<ChecksumResult>();
    let checksum_dispatch_session = session.clone();
    let checksum_dispatch_weak = ui.as_weak();
    let checksum_dispatcher = thread::spawn(move || {
        while let Ok(result) = checksum_rx.recv() {
            let session = checksum_dispatch_session.clone();
            let weak = checksum_dispatch_weak.clone();
            if slint::invoke_from_event_loop(move || {
                let mut session = session.borrow_mut();
                if session.apply_checksum_result(result)
                    && let Some(ui) = weak.upgrade()
                {
                    render(&session, &ui);
                }
            })
            .is_err()
            {
                break;
            }
        }
    });
    let checksum_worker = ChecksumWorker::spawn(move |result| checksum_tx.send(result).is_ok());
    let checksum_sender = checksum_worker.sender();

    let (updates_tx, updates_rx) = mpsc::channel();
    let dispatcher_session = session.clone();
    let dispatcher_weak = ui.as_weak();
    let dispatcher = thread::spawn(move || {
        while let Ok(update) = updates_rx.recv() {
            let session = dispatcher_session.clone();
            let weak = dispatcher_weak.clone();
            if slint::invoke_from_event_loop(move || {
                let mut session = session.borrow_mut();
                if session.apply_devices(update)
                    && let Some(ui) = weak.upgrade()
                {
                    render(&session, &ui);
                }
            })
            .is_err()
            {
                break;
            }
        }
    });
    let worker = match furus_gui::devices::start_live_watcher(false, Arc::clone(&epoch), {
        move |update| updates_tx.send(update).is_ok()
    }) {
        Ok((_initial, worker)) => Some(worker),
        Err(error) => {
            session.borrow_mut().note =
                Some(format!("Device hotplug watcher unavailable: {error}"));
            None
        }
    };

    // The helper worker only publishes data here; the event-loop dispatcher
    // is the sole place that mutates `Run` and the Slint properties.
    let (run_tx, run_rx) = mpsc::channel::<RunMessage>();
    let run_dispatch_session = session.clone();
    let run_dispatch_weak = ui.as_weak();
    let run_dispatcher = thread::spawn(move || {
        while let Ok(message) = run_rx.recv() {
            if matches!(message, RunMessage::Stop) {
                break;
            }
            let session = run_dispatch_session.clone();
            let weak = run_dispatch_weak.clone();
            if slint::invoke_from_event_loop(move || {
                let mut session = session.borrow_mut();
                session.apply_run_message(message);
                if let Some(ui) = weak.upgrade() {
                    render(&session, &ui);
                }
            })
            .is_err()
            {
                break;
            }
        }
    });
    let run_worker_handle: Arc<Mutex<Option<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    // Every callback: mutate `GuiState` through the session, then
    // re-render the whole form from `GuiState` (one-way display).
    {
        let session = session.clone();
        let epoch = Arc::clone(&epoch);
        let weak = ui.as_weak();
        ui.on_device_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut session = session.borrow_mut();
                if let Some(next_epoch) = session.select_device(&label) {
                    epoch.store(next_epoch, Ordering::Release);
                }
                render(&session, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_boot_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.bootloader = boot_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        // The picker dialog is synchronous and can block for as long as the
        // user takes, so it runs on a dedicated worker thread. The busy flag
        // (toggled on this UI thread) prevents a second dialog while one is
        // already open; every Session/Slint mutation is bounced back onto the
        // event loop, matching the other dispatchers in this file.
        let picker_busy = Arc::new(AtomicBool::new(false));
        let session = session.clone();
        let sender = analyzer_sender.clone();
        let weak = ui.as_weak();
        ui.on_select_clicked(move || {
            if picker_busy.swap(true, Ordering::AcqRel) {
                return;
            }
            let session = session.clone();
            let sender = sender.clone();
            let weak = weak.clone();
            let busy = Arc::clone(&picker_busy);
            if thread::Builder::new()
                .name("furus-file-picker".to_string())
                .spawn(move || {
                    let outcome = furus_gui::picker::pick_image_path();
                    let busy_for_loop = Arc::clone(&busy);
                    if slint::invoke_from_event_loop(move || {
                        {
                            let mut session = session.borrow_mut();
                            match outcome {
                                PickerOutcome::Selected(path) => {
                                    session.select_image(path, &sender);
                                }
                                PickerOutcome::Cancelled => {}
                                PickerOutcome::Unavailable(msg) => {
                                    session.note = Some(msg);
                                }
                            }
                        }
                        if let Some(ui) = weak.upgrade() {
                            render(&session.borrow(), &ui);
                        }
                        busy_for_loop.store(false, Ordering::Release);
                    })
                    .is_err()
                    {
                        busy.store(false, Ordering::Release);
                    }
                })
                .is_err()
            {
                picker_busy.store(false, Ordering::Release);
            }
        });
    }
    {
        let session = session.clone();
        let sender = checksum_sender.clone();
        let weak = ui.as_weak();
        ui.on_checksum_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().begin_checksum(&sender);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_checksum_cancel_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().request_checksum_cancel();
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_checksum_close_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().close_checksum();
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_image_option_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.set_image_option(image_option_value(&label));
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_scheme_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.scheme = scheme_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_target_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.target = target_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_fs_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.filesystem = fs_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_cluster_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.cluster_bytes = cluster_value(&label);
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_label_edited(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.volume_label = (!label.is_empty()).then(|| label.to_string());
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_extended_label_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.extended_label = ui.get_extended_label_checked();
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_quick_format_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.quick_format = ui.get_quick_format_checked();
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_bad_blocks_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.state.bad_blocks_passes = if ui.get_bad_blocks_checked() { 1 } else { 0 };
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_passes_selected(move |label| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                if guard.state.bad_blocks_passes > 0 {
                    guard.state.bad_blocks_passes = passes_value(&label);
                }
                guard.note = None;
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_start_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().start();
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        let run_tx = run_tx.clone();
        let handles = Arc::clone(&run_worker_handle);
        ui.on_confirm_clicked(move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let (plan, bridge) = {
                let mut guard = session.borrow_mut();
                let plan = guard.confirm();
                (plan, guard.cancel_bridge.clone())
            };
            let Some(plan) = plan else {
                render(&session.borrow(), &ui);
                return;
            };
            // Hide the dialog and lock the form before any process starts.
            render(&session.borrow(), &ui);
            let sender = run_tx.clone();
            let handle = thread::Builder::new()
                .name("furus-run-worker".to_string())
                .spawn(move || run_worker(plan, bridge, sender));
            if let Ok(handle) = handle {
                if let Ok(mut slot) = handles.lock() {
                    *slot = Some(handle);
                }
            } else {
                let _ = run_tx.send(RunMessage::Failed(
                    "could not start the helper worker thread".to_string(),
                ));
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_cancel_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                let _ = guard.run.cancel();
                guard.cancel_bridge.request();
                drop(guard);
                render(&session.borrow(), &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_discard_clicked(move || {
            if let Some(ui) = weak.upgrade() {
                session.borrow_mut().discard();
                render(&session.borrow(), &ui);
            }
        });
    }

    // Slice 7 callbacks: locale change, the four hash-display toggles and
    // advanced-options visibility. Each mutates only GUI prefs and saves
    // through the core config; none touches planning or run state.
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_locale_selected(move |display| {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                if let Some(tag) = guard.bridge.tag_for_display(&display) {
                    guard.lang = tag.clone();
                    guard.prefs.set_locale(Some(tag));
                    guard.save_prefs();
                }
                render(&guard, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_hash_md5_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.prefs.set_hash_md5(ui.get_hash_md5_checked());
                guard.save_prefs();
                render(&guard, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_hash_sha1_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.prefs.set_hash_sha1(ui.get_hash_sha1_checked());
                guard.save_prefs();
                render(&guard, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_hash_sha256_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.prefs.set_hash_sha256(ui.get_hash_sha256_checked());
                guard.save_prefs();
                render(&guard, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_hash_sha512_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.prefs.set_hash_sha512(ui.get_hash_sha512_checked());
                guard.save_prefs();
                render(&guard, &ui);
            }
        });
    }
    {
        let session = session.clone();
        let weak = ui.as_weak();
        ui.on_advanced_visible_toggled(move || {
            if let Some(ui) = weak.upgrade() {
                let mut guard = session.borrow_mut();
                guard.prefs.set_advanced_visible(ui.get_advanced_visible());
                guard.save_prefs();
                render(&guard, &ui);
            }
        });
    }
    ui.on_close_clicked(|| {
        let _ = slint::quit_event_loop();
    });

    if let Some(path) = startup_path {
        session.borrow_mut().select_image(path, &analyzer_sender);
    }

    render(&session.borrow(), &ui);
    let result = ui.run();
    // Cancel any checksum still in flight so its worker returns at the next
    // read chunk, then shut it down and join its dispatcher like the others.
    session.borrow().checksum.cancel();
    checksum_worker.shutdown();
    analyzer.shutdown();
    let _ = analysis_shutdown_tx.send(AnalysisMessage::Stop);
    drop(worker.map(|worker| worker.shutdown()));
    // Ask any in-flight helper to stop so its event stream ends and the
    // worker can be joined. A pkexec authorization budget bounds the wait.
    session.borrow().cancel_bridge.request();
    let _ = run_tx.send(RunMessage::Stop);
    if let Ok(mut slot) = run_worker_handle.lock()
        && let Some(handle) = slot.take()
    {
        let _ = handle.join();
    }
    let _ = run_dispatcher.join();
    let _ = dispatcher.join();
    let _ = analysis_dispatcher.join();
    let _ = checksum_dispatcher.join();
    result
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
