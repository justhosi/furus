//! Slint-free checksum engine for the modal (S25 slice 6).
//!
//! This module is the headless owner of everything the checksum dialog
//! needs: the four streaming digests, incremental progress, one-shot
//! cancellation and the latest-request stale guard. It mirrors the proven
//! [`crate::analyzer`] shape — one sequential worker thread, std mpsc, an
//! injected publish closure and a monotonic `(request_id, path)` guard —
//! but adds a `Read` adapter that counts bytes and honours cancellation at
//! every chunk. No Slint API, device, pkexec or D-Bus is referenced here,
//! so the whole engine is testable headlessly.
//!
//! Hashing itself is delegated to [`furus_core::hash::hash_reader`]; this
//! module never formats hex or reimplements a digest.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use furus_core::hash::{Algo, hash_reader};

/// The four algorithms shown in the checksum modal, in display order.
pub const ALGORITHMS: [Algo; 4] = [Algo::Md5, Algo::Sha1, Algo::Sha256, Algo::Sha512];

/// A cloneable one-shot cancellation flag. The first `cancel` latches the
/// flag forever; further calls are harmless no-ops, so both the CANCEL
/// button and the modal-close path may call it without coordination.
#[derive(Clone, Default, Debug)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Latch the cancellation flag. Idempotent.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// True once [`CancelToken::cancel`] has been called (from any clone).
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Terminal outcome of a checksum run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumOutcome {
    /// All four passes completed; digests are present.
    Finished,
    /// The token was cancelled; no digests are published as complete.
    Cancelled,
    /// The source could not be read; the message names the cause.
    Failed(String),
}

/// The four optional lowercase hex digests. They are all `None` until a run
/// finishes, so a cancelled or failed run can never present a partial set as
/// if it were complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Digests {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
}

impl Digests {
    fn set(&mut self, algo: Algo, hex: String) {
        match algo {
            Algo::Md5 => self.md5 = Some(hex),
            Algo::Sha1 => self.sha1 = Some(hex),
            Algo::Sha256 => self.sha256 = Some(hex),
            Algo::Sha512 => self.sha512 = Some(hex),
        }
    }
}

/// One publication from the worker. Progress snapshots carry `outcome:
/// None` and no digests; the single terminal snapshot carries an `outcome`
/// and (only for [`ChecksumOutcome::Finished`]) all four digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumResult {
    pub request_id: u64,
    pub path: PathBuf,
    /// Whole percent, 0..=100, derived from bytes read across all four passes.
    pub progress: u8,
    pub digests: Digests,
    pub outcome: Option<ChecksumOutcome>,
}

impl ChecksumResult {
    fn progress(request_id: u64, path: &Path, percent: u8) -> Self {
        Self {
            request_id,
            path: path.to_path_buf(),
            progress: percent,
            digests: Digests::default(),
            outcome: None,
        }
    }

    fn terminal(
        request_id: u64,
        path: &Path,
        percent: u8,
        digests: Digests,
        outcome: ChecksumOutcome,
    ) -> Self {
        // Only a finished run may carry digests. A cancelled/failed run drops
        // whatever partial hex was computed so it cannot be read as complete.
        let digests = if outcome == ChecksumOutcome::Finished {
            digests
        } else {
            Digests::default()
        };
        Self {
            request_id,
            path: path.to_path_buf(),
            progress: percent,
            digests,
            outcome: Some(outcome),
        }
    }

    /// Build a failure result for a submission that never reached the worker.
    #[must_use]
    pub fn failed(request_id: u64, path: PathBuf, message: String) -> Self {
        Self {
            request_id,
            path,
            progress: 0,
            digests: Digests::default(),
            outcome: Some(ChecksumOutcome::Failed(message)),
        }
    }

    /// True for a terminal snapshot (no more publications for this request).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.outcome.is_some()
    }
}

type Publish = Box<dyn FnMut(ChecksumResult) -> bool + Send + 'static>;
type SharedPublish = Rc<RefCell<Publish>>;

fn interrupted(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, message)
}

fn emit(publish: &SharedPublish, result: ChecksumResult) -> bool {
    let mut guard = publish.borrow_mut();
    guard.as_mut()(result)
}

fn emit_final(
    publish: &SharedPublish,
    request_id: u64,
    path: &Path,
    percent: u8,
    outcome: ChecksumOutcome,
) -> bool {
    emit(
        publish,
        ChecksumResult::terminal(request_id, path, percent, Digests::default(), outcome),
    )
}

/// A `Read` adapter that counts bytes for progress and aborts on cancel.
/// `furus_core::hash::hash_reader` calls `read` once per 1 MiB chunk, which
/// gives us exactly the check granularity the slice requires.
struct CountingReader<'a> {
    inner: File,
    cancel: CancelToken,
    done: u64,
    total: u64,
    last_percent: u8,
    publish: &'a SharedPublish,
    request_id: u64,
    path: &'a Path,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(interrupted("checksum cancelled"));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.done += n as u64;
            let percent = if self.total == 0 {
                100
            } else {
                self.done.saturating_mul(100).div_ceil(self.total).min(100) as u8
            };
            if percent > self.last_percent {
                self.last_percent = percent;
                let mut guard = self.publish.borrow_mut();
                if !guard.as_mut()(ChecksumResult::progress(
                    self.request_id,
                    self.path,
                    percent,
                )) {
                    return Err(interrupted("checksum publisher closed"));
                }
            }
        }
        Ok(n)
    }
}

/// Compute all four digests on the calling (worker) thread. Returns whether
/// the publish channel is still open, so the worker loop can stop early.
fn run_checksum(
    request_id: u64,
    path: &Path,
    cancel: &CancelToken,
    publish: &SharedPublish,
) -> bool {
    let file_len = std::fs::metadata(path).map(|info| info.len()).unwrap_or(0);
    let total = file_len.saturating_mul(ALGORITHMS.len() as u64);
    let mut done = 0_u64;
    let mut last_percent = 0_u8;
    let mut digests = Digests::default();

    for algo in ALGORITHMS {
        if cancel.is_cancelled() {
            return emit_final(
                publish,
                request_id,
                path,
                last_percent,
                ChecksumOutcome::Cancelled,
            );
        }
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) => {
                return emit_final(
                    publish,
                    request_id,
                    path,
                    last_percent,
                    ChecksumOutcome::Failed(format!(
                        "cannot open '{}' for {}: {error}",
                        path.display(),
                        algo.as_str()
                    )),
                );
            }
        };
        let mut reader = CountingReader {
            inner: file,
            cancel: cancel.clone(),
            done,
            total,
            last_percent,
            publish,
            request_id,
            path,
        };
        let hashed = hash_reader(algo, &mut reader);
        done = reader.done;
        last_percent = reader.last_percent;
        match hashed {
            Ok(hex) => {
                if cancel.is_cancelled() {
                    return emit_final(
                        publish,
                        request_id,
                        path,
                        last_percent,
                        ChecksumOutcome::Cancelled,
                    );
                }
                digests.set(algo, hex);
            }
            Err(error) => {
                let outcome = if cancel.is_cancelled() {
                    ChecksumOutcome::Cancelled
                } else {
                    ChecksumOutcome::Failed(format!(
                        "{} reading '{}': {error}",
                        algo.as_str(),
                        path.display()
                    ))
                };
                return emit_final(publish, request_id, path, last_percent, outcome);
            }
        }
    }

    if cancel.is_cancelled() {
        emit_final(
            publish,
            request_id,
            path,
            last_percent,
            ChecksumOutcome::Cancelled,
        )
    } else {
        emit(
            publish,
            ChecksumResult::terminal(request_id, path, 100, digests, ChecksumOutcome::Finished),
        )
    }
}

enum WorkerCommand {
    Start {
        request_id: u64,
        path: PathBuf,
        cancel: CancelToken,
    },
    Stop,
}

/// A single sequential checksum worker with an injectable publish seam.
pub struct ChecksumWorker {
    sender: mpsc::Sender<WorkerCommand>,
    thread: Option<JoinHandle<()>>,
    finished: mpsc::Receiver<()>,
}

/// Cloneable, non-blocking submission handle for UI callbacks.
#[derive(Clone)]
pub struct ChecksumSender(mpsc::Sender<WorkerCommand>);

impl ChecksumSender {
    pub fn submit(
        &self,
        request_id: u64,
        path: PathBuf,
        cancel: CancelToken,
    ) -> Result<(), String> {
        self.0
            .send(WorkerCommand::Start {
                request_id,
                path,
                cancel,
            })
            .map_err(|_| "checksum worker is closed".to_string())
    }
}

impl ChecksumWorker {
    /// Spawn the worker. The closure publishes progress and terminal
    /// snapshots; production forwards them into the UI-dispatch channel.
    pub fn spawn<P>(publish: P) -> Self
    where
        P: FnMut(ChecksumResult) -> bool + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        let (finished_tx, finished) = mpsc::channel();
        let thread = thread::spawn(move || {
            worker_loop(receiver, Box::new(publish));
            let _ = finished_tx.send(());
        });
        Self {
            sender,
            thread: Some(thread),
            finished,
        }
    }

    pub fn submit(
        &self,
        request_id: u64,
        path: PathBuf,
        cancel: CancelToken,
    ) -> Result<(), String> {
        self.sender().submit(request_id, path, cancel)
    }

    #[must_use]
    pub fn sender(&self) -> ChecksumSender {
        ChecksumSender(self.sender.clone())
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

impl Drop for ChecksumWorker {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn worker_loop(receiver: mpsc::Receiver<WorkerCommand>, publish: Publish) {
    // The publish box stays on this one thread; Rc/RefCell let the counting
    // reader emit progress during a hash without any cross-thread locking.
    let shared = Rc::new(RefCell::new(publish));
    while let Ok(command) = receiver.recv() {
        let mut current = match command {
            WorkerCommand::Stop => return,
            WorkerCommand::Start {
                request_id,
                path,
                cancel,
            } => (request_id, path, cancel),
        };
        // Collapse a burst of requests to the newest one, as analyzer does.
        loop {
            match receiver.try_recv() {
                Ok(WorkerCommand::Start {
                    request_id,
                    path,
                    cancel,
                }) => {
                    current.2.cancel();
                    current = (request_id, path, cancel);
                }
                Ok(WorkerCommand::Stop) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => break,
            }
        }
        let (request_id, path, cancel) = current;
        if !run_checksum(request_id, &path, &cancel, &shared) {
            return;
        }
    }
}

/// Request-id guard. IDs are assigned at click time and only the latest
/// pending request may affect the modal; terminal results clear the guard.
#[derive(Debug, Default)]
pub struct ChecksumCoordinator {
    next_id: u64,
    latest_pending: Option<(u64, PathBuf)>,
    latest_cancel: Option<CancelToken>,
}

impl ChecksumCoordinator {
    /// Begin a request: invalidate the previous one, return a fresh id and
    /// cancellation token. Cancelling the old token stops stale work early.
    pub fn begin(&mut self, path: &Path) -> (u64, CancelToken) {
        if let Some(old) = &self.latest_cancel {
            old.cancel();
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("checksum request id exhausted");
        let token = CancelToken::default();
        self.latest_pending = Some((self.next_id, path.to_path_buf()));
        self.latest_cancel = Some(token.clone());
        (self.next_id, token)
    }

    /// Apply a result only if both the monotonic id and the path still
    /// identify the latest pending request. False means it was discarded.
    pub fn apply(&mut self, result: ChecksumResult) -> bool {
        if self.latest_pending.as_ref() != Some(&(result.request_id, result.path.clone())) {
            return false;
        }
        if result.is_terminal() {
            self.latest_pending = None;
            self.latest_cancel = None;
        }
        true
    }

    /// Cancel the latest pending request, if any. Idempotent.
    pub fn cancel(&self) {
        if let Some(token) = &self.latest_cancel {
            token.cancel();
        }
    }

    #[must_use]
    pub fn latest_pending_id(&self) -> Option<u64> {
        self.latest_pending.as_ref().map(|(id, _)| *id)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "furus-gui-checksum-{}-{id}-{name}",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("write fixture");
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    /// A directory can be opened but not read, exercising the error path.
    struct DirFixture(PathBuf);

    impl DirFixture {
        fn new(name: &str) -> Self {
            let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "furus-gui-checksum-dir-{}-{id}-{name}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create fixture dir");
            Self(path)
        }
    }

    impl Drop for DirFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir(&self.0);
        }
    }

    /// Drive the real worker to its terminal result, collecting every
    /// publication. When `cancel_on_progress`, the publish closure cancels
    /// the token *on the worker thread* at the first progress snapshot, so
    /// the mid-run cancellation test is fully deterministic.
    fn run(path: &Path, cancel: CancelToken, cancel_on_progress: bool) -> Vec<ChecksumResult> {
        let (tx, rx) = mpsc::channel();
        let hook_cancel = cancel.clone();
        let worker = ChecksumWorker::spawn(move |result| {
            if cancel_on_progress && result.outcome.is_none() && result.progress > 0 {
                hook_cancel.cancel();
            }
            tx.send(result).is_ok()
        });
        worker
            .submit(1, path.to_path_buf(), cancel)
            .expect("queue checksum");
        let mut results = Vec::new();
        loop {
            let result = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker publication");
            let terminal = result.is_terminal();
            results.push(result);
            if terminal {
                break;
            }
        }
        worker.shutdown();
        results
    }

    fn terminal(results: &[ChecksumResult]) -> &ChecksumResult {
        results.last().expect("terminal result")
    }

    #[test]
    fn all_four_digests_match_known_vectors() {
        let fixture = Fixture::new("abc.bin", b"abc");
        let results = run(&fixture.0, CancelToken::default(), false);
        let last = terminal(&results);
        assert_eq!(last.outcome, Some(ChecksumOutcome::Finished));
        assert_eq!(last.progress, 100);
        let d = &last.digests;
        assert_eq!(d.md5.as_deref(), Some("900150983cd24fb0d6963f7d28e17f72"));
        assert_eq!(
            d.sha1.as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            d.sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            d.sha512.as_deref(),
            Some(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn cancellation_stops_before_publishing_digests() {
        let data = vec![0x5A; 2 * 1024 * 1024 + 7];
        let fixture = Fixture::new("large.bin", &data);
        let cancel = CancelToken::default();
        let results = run(&fixture.0, cancel.clone(), true);
        let last = terminal(&results);
        assert_eq!(last.outcome, Some(ChecksumOutcome::Cancelled));
        assert_eq!(
            last.digests,
            Digests::default(),
            "no partial digests published"
        );
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn progress_is_monotonic_and_bounded() {
        let data = vec![0xA5; 3 * 1024 * 1024 + 13];
        let fixture = Fixture::new("progress.bin", &data);
        let results = run(&fixture.0, CancelToken::default(), false);
        let mut previous = 0_u8;
        for result in &results {
            assert!(
                result.progress >= previous,
                "progress went backwards: {previous} -> {}",
                result.progress
            );
            assert!(result.progress <= 100, "progress exceeded 100");
            previous = result.progress;
        }
        assert_eq!(terminal(&results).progress, 100);
        assert!(results.len() > 1, "incremental progress was published");
    }

    #[test]
    fn stale_request_result_is_discarded() {
        let a = Fixture::new("a.bin", b"a");
        let b = Fixture::new("b.bin", b"b");
        let mut coordinator = ChecksumCoordinator::default();
        let (a_id, _) = coordinator.begin(&a.0);
        let (b_id, _) = coordinator.begin(&b.0);
        assert!(b_id > a_id, "each request gets a strictly increasing id");

        let finished = |id, path: &Path| {
            ChecksumResult::terminal(id, path, 100, Digests::default(), ChecksumOutcome::Finished)
        };
        assert!(coordinator.apply(finished(b_id, &b.0)));
        assert_eq!(coordinator.latest_pending_id(), None);
        assert!(
            !coordinator.apply(finished(a_id, &a.0)),
            "an older result for a different path is discarded"
        );

        // Re-selecting the same file must distinguish the two requests by id.
        let (old_id, _) = coordinator.begin(&a.0);
        let (current_id, _) = coordinator.begin(&a.0);
        assert!(!coordinator.apply(finished(old_id, &a.0)));
        assert_eq!(coordinator.latest_pending_id(), Some(current_id));
        assert!(coordinator.apply(finished(current_id, &a.0)));
        assert_eq!(coordinator.latest_pending_id(), None);
    }

    #[test]
    fn repeated_cancel_is_harmless() {
        let token = CancelToken::default();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        let fixture = Fixture::new("pre-cancelled.bin", b"abc");
        let results = run(&fixture.0, token, false);
        let last = terminal(&results);
        assert_eq!(last.outcome, Some(ChecksumOutcome::Cancelled));
        assert_eq!(last.digests, Digests::default());
    }

    #[test]
    fn empty_file_yields_all_four_empty_string_digests() {
        let fixture = Fixture::new("empty.bin", b"");
        let results = run(&fixture.0, CancelToken::default(), false);
        let last = terminal(&results);
        assert_eq!(last.outcome, Some(ChecksumOutcome::Finished));
        assert_eq!(
            last.digests.md5.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(
            last.digests.sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn unreadable_source_is_a_named_failure_with_no_digests() {
        let dir = DirFixture::new("source");
        let results = run(&dir.0, CancelToken::default(), false);
        let last = terminal(&results);
        let message = match &last.outcome {
            Some(ChecksumOutcome::Failed(message)) => message,
            other => panic!("expected a named failure, got {other:?}"),
        };
        assert!(message.contains("md5"), "{message}");
        assert!(message.contains(&dir.0.display().to_string()), "{message}");
        assert_eq!(last.digests, Digests::default());
    }
}
