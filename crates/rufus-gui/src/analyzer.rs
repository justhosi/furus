//! Slint-free image-analysis worker and latest-request reducer.
//!
//! Tests inject a tiny fake analyzer; production uses the shared read-only
//! image inspector and report analyzer. No UI toolkit is referenced here.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rufus_core::image::{self, ImageInfo};
use rufus_core::report::{self, ImageReport};

use crate::state::GuiState;

/// Read-only facts needed to populate image selection and planning defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub info: ImageInfo,
    pub report: ImageReport,
}

/// Analysis result tagged with its originating user request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisResult {
    pub request_id: u64,
    pub path: PathBuf,
    pub result: Result<Analysis, String>,
}

type Analyze = Box<dyn Fn(&Path) -> Result<Analysis, String> + Send + 'static>;
type Publish = Box<dyn FnMut(AnalysisResult) -> bool + Send + 'static>;

enum WorkerCommand {
    Analyze { request_id: u64, path: PathBuf },
    Stop,
}

/// A single sequential analyzer worker with an injectable analysis seam.
pub struct AnalyzerWorker {
    sender: Sender<WorkerCommand>,
    thread: Option<JoinHandle<()>>,
    finished: Receiver<()>,
}

/// Cloneable, non-blocking submission handle for UI callbacks.
#[derive(Clone)]
pub struct AnalyzerSender(Sender<WorkerCommand>);

impl AnalyzerSender {
    pub fn submit(&self, request_id: u64, path: PathBuf) -> Result<(), String> {
        self.0
            .send(WorkerCommand::Analyze { request_id, path })
            .map_err(|_| "image analyzer worker is closed".to_string())
    }
}

impl AnalyzerWorker {
    /// Spawn a worker that receives work over std mpsc and publishes through
    /// the injected closure. Production should keep the closure limited to
    /// forwarding the result into a UI-dispatch channel.
    pub fn spawn<A, P>(analyze: A, publish: P) -> Self
    where
        A: Fn(&Path) -> Result<Analysis, String> + Send + 'static,
        P: FnMut(AnalysisResult) -> bool + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        let (finished_tx, finished) = mpsc::channel();
        let thread = thread::spawn(move || {
            worker_loop(receiver, Box::new(analyze), Box::new(publish));
            let _ = finished_tx.send(());
        });
        Self {
            sender,
            thread: Some(thread),
            finished,
        }
    }

    /// Spawn the production read-only inspector and report analyzer.
    pub fn spawn_production<P>(publish: P) -> Self
    where
        P: FnMut(AnalysisResult) -> bool + Send + 'static,
    {
        Self::spawn(
            |path| {
                let info = image::inspect(path).map_err(|error| error.to_string())?;
                let report = report::analyze_file(path).map_err(|error| error.to_string())?;
                Ok(Analysis { info, report })
            },
            publish,
        )
    }

    /// Queue a selection for analysis without blocking the caller.
    pub fn submit(&self, request_id: u64, path: PathBuf) -> Result<(), String> {
        self.sender().submit(request_id, path)
    }

    #[must_use]
    pub fn sender(&self) -> AnalyzerSender {
        AnalyzerSender(self.sender.clone())
    }

    /// Request stop and join only after a bounded completion wait.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        if self.thread.is_none() {
            return;
        }
        let _ = self.sender.send(WorkerCommand::Stop);
        if self.finished.recv_timeout(Duration::from_secs(2)).is_ok() {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        } else {
            // Do not turn a bounded shutdown into an unbounded Drop join.
            let _ = self.thread.take();
        }
    }
}

impl Drop for AnalyzerWorker {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn worker_loop(receiver: Receiver<WorkerCommand>, analyze: Analyze, mut publish: Publish) {
    while let Ok(WorkerCommand::Analyze { request_id, path }) = receiver.recv() {
        let mut current = (request_id, path);
        loop {
            match receiver.try_recv() {
                Ok(WorkerCommand::Analyze { request_id, path }) => {
                    current = (request_id, path);
                }
                Ok(WorkerCommand::Stop) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }
        let (request_id, path) = current;
        let result = analyze(&path);
        if !publish(AnalysisResult {
            request_id,
            path,
            result,
        }) {
            break;
        }
    }
}

/// State-side request id guard. IDs are assigned here at selection time and
/// only the latest pending request may alter image facts or status.
#[derive(Debug, Default)]
pub struct AnalysisCoordinator {
    next_id: u64,
    latest_pending: Option<(u64, PathBuf)>,
}

impl AnalysisCoordinator {
    /// Begin a selection request, invalidate previous results, and show
    /// progress without retaining an old plan.
    pub fn begin(&mut self, state: &mut GuiState, path: &Path) -> u64 {
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("analysis request id exhausted");
        self.latest_pending = Some((self.next_id, path.to_path_buf()));
        state.begin_image_analysis(path);
        self.next_id
    }

    /// Apply a result only if both monotonic id and path still identify the
    /// latest pending selection. False means it was discarded without mutation.
    pub fn apply(&mut self, state: &mut GuiState, result: AnalysisResult) -> bool {
        if self.latest_pending.as_ref() != Some(&(result.request_id, result.path.clone())) {
            return false;
        }
        self.latest_pending = None;
        match result.result {
            Ok(analysis) => state.apply_image_analysis(analysis.info, analysis.report),
            Err(error) => state.fail_image_analysis(&result.path, error),
        }
        true
    }

    #[must_use]
    pub fn latest_pending_id(&self) -> Option<u64> {
        self.latest_pending.as_ref().map(|(id, _)| *id)
    }
}

/// Present the already-computed image digest on demand. Hashing itself happens
/// during worker analysis, never in this UI action.
#[must_use]
pub fn checksum(state: &GuiState) -> Option<String> {
    state
        .image
        .as_ref()
        .map(|image| format!("SHA-256: {}", image.image.sha256))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::state::{GuiState, WindowsImageOption};
    use rufus_core::image::{ImageInfo, ImageKind};
    use rufus_core::report::ImageReport;
    use rufus_linux::{Device, Transport};
    use rufus_proto::{Filesystem, Scheme, Step, Target, WriteMode};

    use super::{Analysis, AnalysisCoordinator, AnalyzerWorker, checksum};

    static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Self {
            let id = NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rufus-gui-analyzer-{}-{id}-{name}",
                std::process::id()
            ));
            fs::write(&path, b"tiny analysis fixture").expect("write tiny fixture");
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn device() -> Device {
        Device {
            sysfs: "fixture/class/block/sdz".to_string(),
            name: "sdz".to_string(),
            dev_path: "/dev/rufus-analyzer-test".to_string(),
            size_bytes: 32_010_928_128,
            sector_size: 512,
            physical_sector_size: 4096,
            removable: true,
            read_only: false,
            usb: true,
            vendor: Some("Test".to_string()),
            model: Some("Fixture stick".to_string()),
            serial: Some("analyzer-fixture".to_string()),
            transport: Transport::Usb,
            partition_table: None,
            vid_pid: None,
            port_path: None,
            partitions: Vec::new(),
        }
    }

    fn analysis(path: &Path, kind: ImageKind, report: ImageReport) -> Analysis {
        Analysis {
            info: ImageInfo {
                path: path.display().to_string(),
                size_bytes: 21,
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                kind,
            },
            report,
        }
    }

    fn apply_fake_result(
        state: &mut GuiState,
        coordinator: &mut AnalysisCoordinator,
        path: &Path,
        value: Result<Analysis, String>,
    ) -> bool {
        let request_id = coordinator.begin(state, path);
        coordinator.apply(
            state,
            super::AnalysisResult {
                request_id,
                path: path.to_path_buf(),
                result: value,
            },
        )
    }

    fn bootloader_mode(plan: &rufus_proto::Plan) -> Option<&rufus_proto::BootloaderMode> {
        plan.steps.iter().find_map(|step| match step {
            Step::Bootloader { mode } => Some(mode),
            _ => None,
        })
    }

    fn write_mode(plan: &rufus_proto::Plan) -> Option<&WriteMode> {
        plan.steps.iter().find_map(|step| match step {
            Step::Write { mode } => Some(mode),
            _ => None,
        })
    }

    #[test]
    fn fake_windows_iso_analysis_applies_windows_defaults_and_builds_windows_plan() {
        let fixture = Fixture::new("windows.iso");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        let report = ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            is_windows: true,
            has_efi: true,
            has_bios: true,
            ..ImageReport::default()
        };
        let expected = analysis(&fixture.0, ImageKind::Iso, report);
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Ok(expected)
        ));

        assert!(state.image_option_enabled());
        assert_eq!(state.image_option, WindowsImageOption::Standard);
        assert_eq!(state.filesystem, Filesystem::Ntfs);
        assert_eq!(state.scheme, Scheme::Gpt);
        assert_eq!(state.target, Target::Uefi);
        assert!(state.status_text().contains("Analyzed"));
        assert!(state.status_text().contains("Windows"));
        assert!(state.status_text().contains("BIOS/UEFI"));
        assert!(state.set_image_option(WindowsImageOption::WindowsToGo));
        let plan = state.build_plan().expect("Windows installer plan");
        assert!(matches!(
            bootloader_mode(&plan),
            Some(rufus_proto::BootloaderMode::Windows)
        ));
    }

    #[test]
    fn fake_linux_hybrid_analysis_hides_windows_option_and_keeps_dd_and_copy_plans() {
        let fixture = Fixture::new("linux.iso");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        let report = ImageReport {
            kind: "iso".to_string(),
            is_iso: true,
            has_efi: true,
            has_bios: true,
            distro: Some("Test Linux".to_string()),
            ..ImageReport::default()
        };
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Ok(analysis(&fixture.0, ImageKind::Iso, report)),
        ));

        assert!(!state.image_option_enabled());
        assert_eq!(state.filesystem, Filesystem::Fat32);
        assert_eq!(state.scheme, Scheme::Gpt);
        assert_eq!(state.target, Target::Uefi);
        assert!(state.status_text().contains("Test Linux"));
        assert!(state.status_text().contains("BIOS/UEFI"));
        let dd = state.build_plan().expect("hybrid raw-write plan");
        assert_eq!(write_mode(&dd), Some(&WriteMode::Dd));
        state.iso_mode = true;
        let copy = state.build_plan().expect("hybrid ISO-copy plan");
        assert_eq!(write_mode(&copy), Some(&WriteMode::Copy));
    }

    #[test]
    fn fake_raw_analysis_keeps_choices_and_does_not_plan_bootloader_install() {
        let fixture = Fixture::new("raw.img");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Ok(analysis(
                &fixture.0,
                ImageKind::Raw,
                ImageReport {
                    kind: "raw".to_string(),
                    ..ImageReport::default()
                },
            )),
        ));

        state.scheme = Scheme::Mbr;
        state.filesystem = Filesystem::Ext4;
        let plan = state.build_plan().expect("raw image plan");
        assert_eq!(plan.options.scheme, Scheme::Mbr);
        assert_eq!(plan.options.filesystem, Filesystem::Ext4);
        assert_eq!(
            bootloader_mode(&plan),
            Some(&rufus_proto::BootloaderMode::None)
        );
    }

    #[test]
    fn analysis_failure_keeps_named_error_and_never_produces_a_plan() {
        let fixture = Fixture::new("missing-result.iso");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Err("named fixture read failure".to_string()),
        ));

        assert!(state.image.is_none());
        assert!(state.status_text().contains("named fixture read failure"));
        assert!(state.build_plan().is_err());
        assert!(!state.start_enabled());
    }

    #[test]
    fn newer_request_is_applied_and_older_result_is_discarded_in_both_orders() {
        let image_a = Fixture::new("a.img");
        let image_b = Fixture::new("b.img");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        let a_id = coordinator.begin(&mut state, &image_a.0);
        let b_id = coordinator.begin(&mut state, &image_b.0);
        assert!(b_id > a_id, "each selection gets a strictly increasing id");

        let b = analysis(
            &image_b.0,
            ImageKind::Raw,
            ImageReport {
                kind: "raw".to_string(),
                ..ImageReport::default()
            },
        );
        assert!(coordinator.apply(
            &mut state,
            super::AnalysisResult {
                request_id: b_id,
                path: image_b.0.clone(),
                result: Ok(b)
            },
        ));
        let state_after_b = state.clone();
        let a = analysis(
            &image_a.0,
            ImageKind::Iso,
            ImageReport {
                kind: "iso".to_string(),
                is_iso: true,
                is_windows: true,
                ..ImageReport::default()
            },
        );
        assert!(!coordinator.apply(
            &mut state,
            super::AnalysisResult {
                request_id: a_id,
                path: image_a.0.clone(),
                result: Ok(a)
            },
        ));
        assert_eq!(
            state, state_after_b,
            "stale results mutate no image or UI state"
        );

        let next = Fixture::new("next.img");
        let next_id = coordinator.begin(&mut state, &next.0);
        let stale = super::AnalysisResult {
            request_id: b_id,
            path: image_b.0.clone(),
            result: Err("late old failure".to_string()),
        };
        assert!(!coordinator.apply(&mut state, stale));
        assert!(state.status_text().contains("Analyzing"));
        assert!(coordinator.apply(
            &mut state,
            super::AnalysisResult {
                request_id: next_id,
                path: next.0.clone(),
                result: Ok(analysis(
                    &next.0,
                    ImageKind::Raw,
                    ImageReport {
                        kind: "raw".to_string(),
                        ..ImageReport::default()
                    },
                )),
            },
        ));
    }

    /// The stale guard must require *both* halves of the (id, path) pair. The
    /// re-selection case tells the two requests apart by id alone (identical
    /// path), the mis-routed case by path alone (identical id); a guard that
    /// compared only one of them would let one of these two overwrite state.
    #[test]
    fn stale_id_with_an_identical_path_and_current_id_with_a_wrong_path_are_both_discarded() {
        let fixture = Fixture::new("same-path.iso");
        let other = Fixture::new("other-path.iso");
        let mut state = GuiState::default();
        state.select_device(&device(), "not mounted");
        let mut coordinator = AnalysisCoordinator::default();
        let windows = || {
            analysis(
                &fixture.0,
                ImageKind::Iso,
                ImageReport {
                    kind: "iso".to_string(),
                    is_iso: true,
                    is_windows: true,
                    ..ImageReport::default()
                },
            )
        };

        let stale_id = coordinator.begin(&mut state, &fixture.0);
        let current_id = coordinator.begin(&mut state, &fixture.0);
        assert!(current_id > stale_id, "re-selecting a file gets a fresh id");
        let pending = state.clone();

        assert!(
            !coordinator.apply(
                &mut state,
                super::AnalysisResult {
                    request_id: stale_id,
                    path: fixture.0.clone(),
                    result: Ok(windows()),
                },
            ),
            "an older id for the identical path must be discarded",
        );
        assert_eq!(state, pending, "the stale id mutated no state");
        assert_eq!(coordinator.latest_pending_id(), Some(current_id));

        assert!(
            !coordinator.apply(
                &mut state,
                super::AnalysisResult {
                    request_id: current_id,
                    path: other.0.clone(),
                    result: Ok(windows()),
                },
            ),
            "the current id carrying a different path must be discarded",
        );
        assert_eq!(state, pending, "the wrong path mutated no state");
        assert_eq!(coordinator.latest_pending_id(), Some(current_id));

        assert!(coordinator.apply(
            &mut state,
            super::AnalysisResult {
                request_id: current_id,
                path: fixture.0.clone(),
                result: Ok(windows()),
            },
        ));
        assert_eq!(coordinator.latest_pending_id(), None);
        assert!(state.image_option_enabled());
    }

    #[test]
    fn injected_worker_analyzes_only_on_its_thread_and_closed_publish_is_safe() {
        let fixture = Fixture::new("thread.img");
        let (tx, rx) = mpsc::channel();
        let expected_path = fixture.0.clone();
        let submitted_path = fixture.0.clone();
        let worker = AnalyzerWorker::spawn(
            move |path| {
                assert_eq!(path, expected_path);
                Ok(analysis(
                    path,
                    ImageKind::Raw,
                    ImageReport {
                        kind: "raw".to_string(),
                        ..ImageReport::default()
                    },
                ))
            },
            move |result| tx.send(result).is_ok(),
        );
        worker.submit(7, submitted_path).expect("queue analysis");
        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker result");
        assert_eq!(result.request_id, 7);
        assert!(result.result.is_ok());
        worker.shutdown();

        let (closed_tx, closed_rx) = mpsc::channel();
        drop(closed_rx);
        let worker = AnalyzerWorker::spawn(
            |_| Err("not reached".to_string()),
            move |result| closed_tx.send(result).is_ok(),
        );
        worker
            .submit(8, PathBuf::from("closed.img"))
            .expect("queue closed publication");
        worker.shutdown();
    }

    #[test]
    fn checksum_displays_the_inspected_hash_without_reopening_or_rewriting_image() {
        let fixture = Fixture::new("checksum.img");
        let mut state = GuiState::default();
        let mut coordinator = AnalysisCoordinator::default();
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Ok(analysis(
                &fixture.0,
                ImageKind::Raw,
                ImageReport {
                    kind: "raw".to_string(),
                    ..ImageReport::default()
                },
            )),
        ));
        let before = fs::read(&fixture.0).expect("fixture bytes before checksum display");

        assert_eq!(
            checksum(&state).as_deref(),
            Some("SHA-256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            fs::read(&fixture.0).expect("fixture bytes after display"),
            before
        );
    }

    #[test]
    fn start_is_disabled_until_the_current_selection_has_a_plan() {
        let fixture = Fixture::new("start.img");
        let mut state = GuiState::default();
        assert!(!state.start_enabled());
        state.select_device(&device(), "not mounted");
        assert!(!state.start_enabled());
        let mut coordinator = AnalysisCoordinator::default();
        assert!(apply_fake_result(
            &mut state,
            &mut coordinator,
            &fixture.0,
            Ok(analysis(
                &fixture.0,
                ImageKind::Raw,
                ImageReport {
                    kind: "raw".to_string(),
                    ..ImageReport::default()
                },
            )),
        ));
        assert!(state.start_enabled());
    }
}
