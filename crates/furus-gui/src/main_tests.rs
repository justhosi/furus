use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use furus_gui::checksum::{ChecksumOutcome, ChecksumResult, Digests};
use furus_gui::devices::{DeviceUpdate, Discovery};
use furus_gui::i18n_bridge::LocaleCatalog;
use furus_gui::run::{DeviceFacts, LogEntry, Run, RunState};
use furus_gui::state::{GuiError, GuiState};
use furus_linux::{Device, Partition, Transport};
use furus_proto::{Completion, EVENT_STREAM_VERSION, Event, LogLevel, Outcome, Progress};

use super::{
    CancelBridge, Session, caption, checksum_digests, checksum_progress, checksum_status,
    confirmation_facts, log_lines, run_view, startup_refusal, status_with_device_warning,
};

static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

/// A 4 KiB raw image with no container magic — enough for the planner
/// fixture, written and removed entirely in the temp directory.
struct ImageFile(PathBuf);

impl ImageFile {
    fn raw() -> Self {
        let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "furus-gui-slice5-{}-{serial}.img",
            std::process::id()
        ));
        fs::write(&path, [0xA5; 4096]).expect("write raw fixture");
        Self(path)
    }
}

impl Drop for ImageFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn planned_gui() -> (GuiState, ImageFile) {
    let image = ImageFile::raw();
    let mut device = fixture_device("sdz");
    device.size_bytes = 32_010_928_128;
    let mut gui = GuiState::default();
    gui.select_device(&device, "not mounted");
    gui.select_image(&image.0, false).expect("inspect fixture");
    (gui, image)
}

fn progress_event(step: usize, op: &str, done: u64, total: Option<u64>) -> Event {
    Event::Progress(Progress::new("s-1", step, op, done, total))
}

fn done_event(outcome: Outcome) -> Event {
    Event::Done(Completion {
        session: "s-1".to_string(),
        version: EVENT_STREAM_VERSION,
        outcome,
    })
}

fn fixture_device(name: &str) -> Device {
    Device {
        sysfs: format!("fixture/class/block/{name}"),
        name: name.to_string(),
        dev_path: format!("/dev/{name}"),
        size_bytes: 8 * 1024 * 1024,
        sector_size: 512,
        physical_sector_size: 512,
        removable: true,
        read_only: false,
        usb: true,
        vendor: Some("Test".to_string()),
        model: Some(format!("{name} test device")),
        serial: Some(format!("serial-{name}")),
        transport: Transport::Usb,
        partition_table: None,
        vid_pid: Some("1234:5678".to_string()),
        port_path: Some(format!("usb-{name}")),
        partitions: vec![Partition {
            name: format!("{name}1"),
            number: Some(1),
            size_bytes: 4096,
            fstype: Some("vfat".to_string()),
        }],
    }
}

/// The removal path end to end: `DeviceListState` clears its identity and
/// the session must clear the *planning* state too, so START cannot plan
/// against a stick that is no longer plugged in.
#[test]
fn unplugging_the_selected_device_clears_the_planning_state() {
    let stick = fixture_device("sdb");
    let mut session = Session::new(Discovery {
        devices: vec![stick],
        warning: None,
    });
    assert!(
        session.state.device.is_some(),
        "the first discovered device is auto-selected"
    );

    let applied = session.apply_devices(DeviceUpdate {
        epoch: 0,
        sequence: 1,
        devices: Vec::new(),
        warning: None,
        error: None,
    });

    assert!(applied, "the removal snapshot is the newest one");
    assert!(session.device_list.selected_identity().is_none());
    assert!(session.state.device.is_none());
    assert_eq!(
        session.state.status_text(),
        "Selected device was disconnected."
    );
    assert!(matches!(
        session.state.build_plan(),
        Err(GuiError::NoDevice)
    ));
}

/// The other direction: a snapshot that still carries the selected device
/// must not clear it.
#[test]
fn a_snapshot_that_still_carries_the_selected_device_keeps_it_selected() {
    let first = fixture_device("sdb");
    let second = fixture_device("sdc");
    let mut session = Session::new(Discovery {
        devices: vec![first.clone()],
        warning: None,
    });

    assert!(session.apply_devices(DeviceUpdate {
        epoch: 0,
        sequence: 1,
        devices: vec![first.clone(), second],
        warning: None,
        error: None,
    }));

    let selected = session
        .state
        .device
        .as_ref()
        .expect("device stays selected");
    assert_eq!(selected.path, first.dev_path);
    assert_eq!(
        session.device_list.selected_identity(),
        Some(first.identity().as_str())
    );
}

#[test]
fn start_reports_planner_refusal_without_attempting_any_write() {
    let mut session = Session::new(Discovery {
        devices: Vec::new(),
        warning: None,
    });

    session.start();

    assert!(
        session
            .note
            .as_deref()
            .is_some_and(|note| note.contains("Planning refused"))
    );
    assert!(
        session
            .note
            .as_deref()
            .is_some_and(|note| note.contains("Select a removable device"))
    );
    assert!(session.state.device.is_none());
}

/// The production seam end to end, minus the picker and the dispatcher
/// thread: a selection takes its request id *before* the worker can see
/// it, the worker analyses off-thread and publishes the real
/// `AnalysisResult`, and a result for a superseded selection is discarded
/// by the same `apply` the event loop uses.
#[test]
fn selected_image_is_analysed_off_thread_and_a_superseded_result_is_discarded() {
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use furus_core::image::{ImageInfo, ImageKind};
    use furus_core::report::ImageReport;
    use furus_gui::analyzer::{Analysis, AnalyzerWorker};

    let (publish_tx, publish_rx) = mpsc::channel();
    let worker = AnalyzerWorker::spawn(
        |path| {
            Ok(Analysis {
                info: ImageInfo {
                    path: path.display().to_string(),
                    size_bytes: 21,
                    sha256: "0".repeat(64),
                    kind: ImageKind::Raw,
                },
                report: ImageReport {
                    kind: "raw".to_string(),
                    ..ImageReport::default()
                },
            })
        },
        move |result| publish_tx.send(result).is_ok(),
    );
    let sender = worker.sender();
    let mut session = Session::new(Discovery {
        devices: Vec::new(),
        warning: None,
    });
    let image_a = PathBuf::from("/tmp/furus-gui-c4-analyzer-a.iso");
    let image_b = PathBuf::from("/tmp/furus-gui-c4-analyzer-b.iso");

    session.select_image(image_a, &sender);
    assert!(session.state.status_text().contains("Analyzing"));
    let first = publish_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker publishes first metadata");
    assert_eq!(
        session.analyzer.latest_pending_id(),
        Some(first.request_id),
        "the request id is assigned at selection, before the worker publishes"
    );
    let first_digest = publish_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker publishes first digest");

    session.select_image(image_b, &sender);
    assert!(
        !session.apply_analysis(first),
        "metadata for a superseded selection is discarded"
    );
    assert!(
        !session.apply_analysis(first_digest),
        "digest for a superseded selection is discarded"
    );
    assert!(session.state.image.is_none());
    assert!(session.state.status_text().contains("Analyzing"));

    let second = publish_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker publishes second metadata");
    assert!(session.apply_analysis(second));
    let second_digest = publish_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker publishes second digest");
    assert!(session.apply_analysis(second_digest));
    assert!(
        session
            .state
            .image
            .as_ref()
            .is_some_and(|image| { image.image.path.ends_with("-b.iso") })
    );
    worker.shutdown();
}

#[test]
fn show_all_warning_remains_in_rendered_status_without_a_transient_note() {
    let status = status_with_device_warning(
        "Select a device and boot image.",
        None,
        Some(furus_gui::devices::INTERNAL_DISK_WARNING),
    );
    assert!(status.contains("Select a device"));
    assert!(status.contains("WARNING: Show all exposes internal disks"));
    assert!(status.contains("destroy its data"));
}

#[test]
fn translated_captions_use_ids_and_keep_english_when_untranslated() {
    let embedded = LocaleCatalog::embedded(Some("en-US"));
    assert_eq!(caption(&embedded, "en-US", "IDS_DEVICE_TXT"), "Device");
    assert_eq!(
        caption(&embedded, "en-US", "IDS_FORMAT_OPTIONS_TXT"),
        "Format Options"
    );

    // A catalog that carries no caption entry keeps the English literal
    // instead of leaking a raw msgid into the UI; unknown ids stay as-is.
    let partial = b"l \"en-US\" \"English\"\nt IDS_DEVICE_TXT \"Device\"\n";
    let partial = LocaleCatalog::from_bytes(partial, Some("en-US"));
    assert_eq!(
        caption(&partial, "en-US", "IDS_BOOT_SELECTION_TXT"),
        "Boot selection"
    );
    assert_eq!(caption(&partial, "en-US", "NO_SUCH_ID"), "NO_SUCH_ID");

    // A real translation is used verbatim when the block has one.
    let translated = "l \"en-US\" \"English\"\n\
t IDS_DEVICE_TXT \"Device\"\n\
l \"de-DE\" \"German\"\n\
t IDS_DEVICE_TXT \"Gerät\"\n";
    let de = LocaleCatalog::from_bytes(translated.as_bytes(), Some("de-DE"));
    assert_eq!(caption(&de, "de-DE", "IDS_DEVICE_TXT"), "Gerät");
}

#[test]
fn root_is_refused_with_the_unprivileged_gui_privileged_helper_split() {
    let message = startup_refusal(0).expect("euid 0 must be refused");
    assert!(
        message.contains("unprivileged"),
        "the refusal names the unprivileged GUI half: {message}"
    );
    assert!(
        message.contains("furus-helper") && message.contains("helper"),
        "the refusal names the privileged helper half: {message}"
    );
    assert!(
        message.contains("no override flag"),
        "the refusal must state there is no override: {message}"
    );
}

#[test]
fn unprivileged_euids_start_normally() {
    for euid in [1_u32, 60_000, 65_534] {
        assert!(
            startup_refusal(euid).is_none(),
            "euid {euid} must not be refused"
        );
    }
}

#[test]
fn start_requires_confirmation_before_a_transport_can_start() {
    let (mut gui, _image) = planned_gui();
    let mut run = Run::new();

    run.start(&mut gui).expect("START builds a plan");
    assert_eq!(run.state(), &RunState::Confirming);
    assert_eq!(run.plan().expect("provisional plan").confirm, "");
    assert_eq!(
        run.confirmed_plan().err(),
        Some(furus_gui::run::RunError::ConfirmationRequired),
        "no transport may start after START alone"
    );

    let token = run
        .confirm()
        .expect("confirm attaches the token")
        .confirm
        .clone();
    assert!(token.starts_with("sha256:"));
    assert_eq!(run.confirmed_plan().expect("gate open").confirm, token);
    assert!(matches!(run.state(), RunState::Running { .. }));
}

#[test]
fn run_state_drives_progress_and_locked_controls() {
    let (mut gui, _image) = planned_gui();
    let mut run = Run::new();
    assert!(run_view(&run).start_enabled);
    assert!(!run_view(&run).locked);

    run.start(&mut gui).expect("START");
    let locked = run_view(&run);
    assert!(locked.locked, "Confirming locks the form");
    assert!(!locked.start_enabled);
    assert!(!locked.cancel_enabled);

    run.confirm().expect("confirm");
    // Two samples give a rate and an ETA for the same write step.
    run.apply(
        &progress_event(4, "write", 3 * 1024 * 1024, Some(6 * 1024 * 1024)),
        Duration::from_secs(1),
    );
    run.apply(
        &progress_event(4, "write", 3 * 1024 * 1024, Some(6 * 1024 * 1024)),
        Duration::from_secs(3),
    );
    let running = run_view(&run);
    assert!(running.locked, "Running locks the form");
    assert!(running.cancel_enabled);
    assert!(!running.start_enabled);
    assert!((running.progress - 0.5).abs() < f32::EPSILON);
    assert!(running.detail.contains("write"), "{}", running.detail);
    assert!(running.detail.contains("50%"), "{}", running.detail);
    assert!(running.detail.contains("1.50 MiB/s"), "{}", running.detail);
    assert!(running.detail.contains("ETA 0:02"), "{}", running.detail);

    run.apply(&done_event(Outcome::Ok), Duration::from_secs(4));
    let finished = run_view(&run);
    assert!(!finished.locked, "Finished unlocks the form");
    assert!(finished.start_enabled);
    assert!(!finished.cancel_enabled);
    assert_eq!(
        finished.terminal.as_deref(),
        Some("Completed successfully.")
    );
}

#[test]
fn cancel_bridge_is_one_shot_and_survives_early_cancel() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let bridge = CancelBridge::default();

    bridge.request();
    assert_eq!(calls.load(Ordering::Relaxed), 0, "no handle installed yet");

    bridge.install(move || {
        counter.fetch_add(1, Ordering::Relaxed);
    });
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "early cancel is delivered"
    );

    bridge.request();
    bridge.request();
    assert_eq!(calls.load(Ordering::Relaxed), 1, "still exactly once");
}

#[test]
fn confirmation_facts_include_every_destructive_warning() {
    let facts = DeviceFacts {
        model: Some("Test Stick".to_string()),
        path: "/dev/sdz".to_string(),
        serial: Some("ABC123".to_string()),
        size_bytes: 32_010_928_128,
        mount_summary: "mounted at /media/usb".to_string(),
    };
    let text = confirmation_facts(&facts);
    for needle in [
        "Test Stick",
        "/dev/sdz",
        "ABC123",
        "32.0 GB",
        "32010928128",
        "mounted at /media/usb (will be unmounted automatically)",
        "DESTROY",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
}

#[test]
fn confirmation_facts_note_only_actual_mounts() {
    for mount_summary in ["not mounted", "mount state unknown"] {
        let facts = DeviceFacts {
            model: None,
            path: "/dev/sdz".to_string(),
            serial: None,
            size_bytes: 32_010_928_128,
            mount_summary: mount_summary.to_string(),
        };
        let text = confirmation_facts(&facts);
        assert!(
            text.contains(&format!("Existing mounts: {mount_summary}\n")),
            "the state is printed unchanged: {text}"
        );
        assert!(
            !text.contains("will be unmounted automatically"),
            "no unmount promise for {mount_summary}: {text}"
        );
    }
}

#[test]
fn log_lines_keep_level_and_order() {
    let entries = vec![
        LogEntry {
            level: LogLevel::Error,
            message: "write failed".to_string(),
        },
        LogEntry {
            level: LogLevel::Info,
            message: "started".to_string(),
        },
        LogEntry {
            level: LogLevel::Warn,
            message: "retrying".to_string(),
        },
    ];
    assert_eq!(
        log_lines(&entries),
        vec!["[error] write failed", "[info] started", "[warn] retrying"]
    );
}

/// The formatter shows digests only for a finished result, in algorithm
/// order, and names the outcome for cancelled/failed runs instead.
#[test]
fn checksum_formatters_present_only_finished_digests_and_name_the_outcome() {
    let path = PathBuf::from("/tmp/image.iso");
    let finished = ChecksumResult {
        request_id: 1,
        path: path.clone(),
        progress: 100,
        digests: Digests {
            md5: Some("d".repeat(32)),
            sha1: Some("1".repeat(40)),
            sha256: Some("2".repeat(64)),
            sha512: Some("5".repeat(128)),
        },
        outcome: Some(ChecksumOutcome::Finished),
    };
    assert_eq!(checksum_digests(Some(&finished))[0], "d".repeat(32));
    assert_eq!(checksum_digests(Some(&finished))[3], "5".repeat(128));
    assert!((checksum_progress(Some(&finished)) - 1.0).abs() < f32::EPSILON);
    assert!(checksum_status(Some(&finished)).contains("image.iso"));

    let cancelled = ChecksumResult::failed(1, path.clone(), "stopped".to_string());
    assert_eq!(
        checksum_digests(Some(&cancelled)),
        [String::new(), String::new(), String::new(), String::new()]
    );
    assert!(checksum_status(Some(&cancelled)).contains("stopped"));

    let running = ChecksumResult {
        request_id: 1,
        path: path.clone(),
        progress: 25,
        digests: Digests::default(),
        outcome: None,
    };
    assert_eq!(checksum_digests(Some(&running))[0], String::new());
    assert!((checksum_progress(Some(&running)) - 0.25).abs() < f32::EPSILON);
    assert!(checksum_status(Some(&running)).contains("25%"));
    assert!(checksum_status(None).contains("Computing"));
}
