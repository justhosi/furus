//! One-shot `pkexec` transport for the helper's JSONL mode.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rufus_proto::{EVENT_STREAM_VERSION, Event, LineError, Outcome, Plan, from_jsonl_line};

use super::{CancelHandle, EventStream, HelperTransport, IpcError, Started};

const STDERR_LIMIT: usize = 8 * 1024;
const DEFAULT_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(120);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Starts `rufus-helper --plan … --progress jsonl` through `pkexec`.
///
/// `with_command` is a documented test seam for exercising the process
/// protocol without invoking pkexec or requiring root; production callers
/// should use the default transport.
pub struct PkexecTransport {
    program: PathBuf,
    args_prefix: Vec<std::ffi::OsString>,
    authorization_timeout: Duration,
}

impl PkexecTransport {
    /// Construct the production transport, which invokes `pkexec`.
    #[must_use]
    pub fn new() -> Self {
        sweep_stale_plan_files();
        Self {
            program: PathBuf::from("pkexec"),
            args_prefix: Vec::new(),
            authorization_timeout: DEFAULT_AUTHORIZATION_TIMEOUT,
        }
    }

    /// Construct a command-backed transport for tests.
    ///
    /// The prefix is followed by `rufus-helper --plan <FILE> --progress
    /// jsonl`. For example, `with_command("/bin/sh", ["-c", script])`
    /// runs the script with the helper arguments available as `$0` onward.
    #[must_use]
    pub fn with_command<I, S>(program: impl Into<PathBuf>, args_prefix: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        Self::with_command_and_authorization_timeout(
            program,
            args_prefix,
            DEFAULT_AUTHORIZATION_TIMEOUT,
        )
    }

    /// Construct a command-backed transport with an explicit authorization budget.
    #[must_use]
    pub fn with_command_and_authorization_timeout<I, S>(
        program: impl Into<PathBuf>,
        args_prefix: I,
        authorization_timeout: Duration,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        sweep_stale_plan_files();
        Self {
            program: program.into(),
            args_prefix: args_prefix.into_iter().map(Into::into).collect(),
            authorization_timeout,
        }
    }
}

impl Default for PkexecTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperTransport for PkexecTransport {
    /// Start blocks until the helper's first non-blank event. `pkexec` is
    /// silent while polkit authenticates, so this may legitimately take the
    /// entire authorization budget and returns an error when it expires.
    fn start(&mut self, plan: &Plan) -> Result<Started, IpcError> {
        let plan_file = PlanFile::create(plan)?;
        let mut command = Command::new(&self.program);
        command
            .args(&self.args_prefix)
            .arg("rufus-helper")
            .arg("--plan")
            .arg(&plan_file.path)
            .arg("--progress")
            .arg("jsonl")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| IpcError::Spawn(error.to_string()))?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = child.kill();
                return Err(IpcError::Spawn("helper stdout was not piped".to_string()));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                let _ = child.kill();
                return Err(IpcError::Spawn("helper stderr was not piped".to_string()));
            }
        };

        let child = Arc::new(Mutex::new(child));
        let cancelled = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel();
        let stderr_reader = match spawn_stderr_reader(stderr) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = cancel_child(&child, None);
                return Err(IpcError::Transport(format!(
                    "could not read helper stderr: {error}"
                )));
            }
        };
        let reader = match spawn_stdout_reader(stdout, Arc::clone(&child), stderr_reader, sender) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = cancel_child(&child, None);
                return Err(IpcError::Transport(format!(
                    "could not read helper stdout: {error}"
                )));
            }
        };

        let (session, first) = match first_message(&receiver, self.authorization_timeout) {
            Ok(message) => message,
            Err(()) => {
                let _ = cancel_child(&child, None);
                if let Ok(mut child) = child.lock() {
                    let _ = child.wait();
                }
                let _ = reader.join();
                drop(plan_file);
                return Err(IpcError::Transport(format!(
                    "no helper event within {}; authorization not completed",
                    format_duration(self.authorization_timeout)
                )));
            }
        };
        let lines = ProcessLines {
            receiver,
            first,
            session: session.clone(),
            plan_file: Some(plan_file),
            child: Arc::clone(&child),
            cancelled: Arc::clone(&cancelled),
            reader: Some(reader),
            ended: false,
        };
        let cancel_handle_child = Arc::clone(&child);
        let cancel_flag = Arc::clone(&cancelled);
        Ok(Started {
            session: session.clone(),
            events: EventStream::from_lines(session, lines),
            cancel: CancelHandle::new(move || {
                cancel_child(&cancel_handle_child, Some(&cancel_flag)).map(|_| ())
            }),
        })
    }
}

fn spawn_stderr_reader(
    stderr: impl Read + Send + 'static,
) -> io::Result<JoinHandle<io::Result<Vec<u8>>>> {
    thread::Builder::new()
        .name("rufus-helper-stderr".to_string())
        .spawn(move || read_bounded_stderr(stderr))
}

fn read_bounded_stderr(mut stderr: impl Read) -> io::Result<Vec<u8>> {
    let mut captured = Vec::with_capacity(STDERR_LIMIT);
    let mut buffer = [0u8; 1024];
    loop {
        let count = stderr.read(&mut buffer)?;
        if count == 0 {
            return Ok(captured);
        }
        if count >= STDERR_LIMIT {
            captured.clear();
            captured.extend_from_slice(&buffer[count - STDERR_LIMIT..count]);
        } else {
            let excess = captured
                .len()
                .saturating_add(count)
                .saturating_sub(STDERR_LIMIT);
            captured.drain(..excess);
            captured.extend_from_slice(&buffer[..count]);
        }
    }
}

fn spawn_stdout_reader(
    stdout: impl Read + Send + 'static,
    child: Arc<Mutex<Child>>,
    stderr_reader: JoinHandle<io::Result<Vec<u8>>>,
    sender: Sender<ReaderMessage>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("rufus-helper-stdout".to_string())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(ReaderMessage::Line(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(ReaderMessage::Error(IpcError::Transport(format!(
                            "could not read helper stdout: {error}"
                        ))));
                        break;
                    }
                }
            }
            let status = wait_for_child(&child);
            let stderr = match stderr_reader.join() {
                Ok(Ok(stderr)) => stderr,
                Ok(Err(error)) => {
                    let _ = sender.send(ReaderMessage::Error(IpcError::Transport(format!(
                        "could not read helper stderr: {error}"
                    ))));
                    Vec::new()
                }
                Err(_) => {
                    let _ = sender.send(ReaderMessage::Error(IpcError::Transport(
                        "helper stderr reader panicked".to_string(),
                    )));
                    Vec::new()
                }
            };
            match status {
                Ok(status) => {
                    let _ = sender.send(ReaderMessage::Exit { status, stderr });
                }
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(error));
                }
            }
        })
}

fn wait_for_child(child: &Arc<Mutex<Child>>) -> Result<ExitStatus, IpcError> {
    loop {
        let result = child
            .lock()
            .map_err(|_| IpcError::Transport("helper process lock poisoned".to_string()))?
            .try_wait()
            .map_err(|error| IpcError::Transport(format!("could not wait for helper: {error}")))?;
        if let Some(status) = result {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn cancel_child(
    child: &Arc<Mutex<Child>>,
    cancelled: Option<&AtomicBool>,
) -> Result<bool, IpcError> {
    let mut child = child
        .lock()
        .map_err(|_| IpcError::Transport("helper process lock poisoned".to_string()))?;
    if child
        .try_wait()
        .map_err(|error| IpcError::Transport(format!("could not inspect helper: {error}")))?
        .is_some()
    {
        return Ok(false);
    }
    match child.kill() {
        Ok(()) => {
            if let Some(cancelled) = cancelled {
                cancelled.store(true, Ordering::Release);
            }
            Ok(true)
        }
        Err(error) => match child.try_wait() {
            Ok(Some(_)) => Ok(false),
            Ok(None) => Err(IpcError::Transport(format!(
                "could not cancel helper: {error}"
            ))),
            Err(wait_error) => Err(IpcError::Transport(format!(
                "could not cancel helper: {error}; could not inspect it: {wait_error}"
            ))),
        },
    }
}

fn first_message(
    receiver: &Receiver<ReaderMessage>,
    timeout: Duration,
) -> Result<(String, Option<ReaderMessage>), ()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(ReaderMessage::Line(line)) if is_empty_line(&line) => continue,
            Ok(message @ ReaderMessage::Line(_)) => {
                let session = match &message {
                    ReaderMessage::Line(line) => session_from_line(line),
                    ReaderMessage::Error(_) | ReaderMessage::Exit { .. } => String::new(),
                };
                return Ok((session, Some(message)));
            }
            Ok(message) => return Ok((String::new(), Some(message))),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok((String::new(), None)),
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(()),
        }
    }
}

fn format_duration(duration: Duration) -> String {
    let mut formatted = format!("{:.3}", duration.as_secs_f64());
    while formatted.ends_with('0') {
        formatted.pop();
    }
    if formatted.ends_with('.') {
        formatted.pop();
    }
    format!("{formatted}s")
}

fn is_empty_line(line: &str) -> bool {
    matches!(from_jsonl_line(line), Err(LineError::Empty))
}

fn session_from_line(line: &str) -> String {
    match from_jsonl_line(line) {
        Ok(Event::Progress(progress)) => progress.session,
        Ok(Event::Log(log)) => log.session,
        Ok(Event::Done(completion)) => completion.session,
        Err(_) => String::new(),
    }
}

enum ReaderMessage {
    Line(String),
    Exit { status: ExitStatus, stderr: Vec<u8> },
    Error(IpcError),
}

struct PlanFile {
    path: PathBuf,
}

impl PlanFile {
    fn create(plan: &Plan) -> Result<Self, IpcError> {
        let json = plan
            .to_json()
            .map_err(|error| IpcError::Transport(format!("could not serialise plan: {error}")))?;
        let directory = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        loop {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                "rufus-plan-{}-{counter}-{nanos}.json",
                std::process::id()
            ));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(IpcError::Transport(format!(
                        "could not create temporary plan file: {error}"
                    )));
                }
            };
            let guard = Self { path };
            file.write_all(json.as_bytes()).map_err(|error| {
                IpcError::Transport(format!("could not write temporary plan file: {error}"))
            })?;
            return Ok(guard);
        }
    }
}

fn sweep_stale_plan_files() {
    let directory = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(pid) = plan_file_pid(name) else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(current_process) = fs::metadata("/proc/self") else {
            continue;
        };
        if metadata.uid() != current_process.uid() || metadata.mode() & 0o777 != 0o600 {
            continue;
        }
        match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let _ = fs::remove_file(path);
            }
            Ok(stat) if process_state(&stat) == Some('Z') => {
                let _ = fs::remove_file(path);
            }
            _ => {}
        }
    }
}

fn plan_file_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("rufus-plan-")?.strip_suffix(".json")?;
    let mut parts = rest.split('-');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let counter = parts.next()?.parse::<u64>().ok()?;
    let nanos = parts.next()?.parse::<u128>().ok()?;
    if pid == 0 || parts.next().is_some() || rest != format!("{pid}-{counter}-{nanos}") {
        return None;
    }
    Some(pid)
}

fn process_state(stat: &str) -> Option<char> {
    let close = stat.rfind(')')?;
    stat[close + 1..].split_whitespace().next()?.chars().next()
}

impl Drop for PlanFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct ProcessLines {
    receiver: Receiver<ReaderMessage>,
    first: Option<ReaderMessage>,
    session: String,
    plan_file: Option<PlanFile>,
    child: Arc<Mutex<Child>>,
    cancelled: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    ended: bool,
}

impl Iterator for ProcessLines {
    type Item = Result<String, IpcError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        loop {
            let message = match self.first.take() {
                Some(message) => message,
                None => match self.receiver.recv() {
                    Ok(message) => message,
                    Err(_) => {
                        self.ended = true;
                        self.plan_file.take();
                        return Some(Err(IpcError::Transport(
                            "helper event reader disconnected".to_string(),
                        )));
                    }
                },
            };
            match message {
                ReaderMessage::Line(line) if is_empty_line(&line) => continue,
                ReaderMessage::Line(line) => {
                    if let Ok(Event::Done(completion)) = from_jsonl_line(&line)
                        && completion.session == self.session
                    {
                        self.finish_after_done();
                    }
                    return Some(Ok(line));
                }
                ReaderMessage::Error(error) => {
                    let _ = cancel_child(&self.child, None);
                    self.ended = true;
                    self.plan_file.take();
                    self.join_reader();
                    return Some(Err(error));
                }
                ReaderMessage::Exit { status, stderr } => {
                    self.ended = true;
                    self.plan_file.take();
                    self.join_reader();
                    let outcome = synthesized_outcome(
                        status,
                        &stderr,
                        self.cancelled.load(Ordering::Acquire),
                    );
                    return Some(Ok(synthesized_done(&self.session, outcome)));
                }
            }
        }
    }
}

impl ProcessLines {
    fn finish_after_done(&mut self) {
        let _ = wait_for_child(&self.child);
        self.ended = true;
        self.plan_file.take();
        self.join_reader();
    }

    fn join_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for ProcessLines {
    fn drop(&mut self) {
        self.plan_file.take();
        if !self.ended {
            let _ = cancel_child(&self.child, None);
        }
        self.join_reader();
    }
}

fn synthesized_outcome(status: ExitStatus, stderr: &[u8], cancelled: bool) -> Outcome {
    if cancelled {
        return Outcome::Cancelled;
    }
    let code = status.code();
    let status_text = match code {
        Some(code) => format!("status {code}"),
        None => match status.signal() {
            Some(signal) => format!("signal {signal}"),
            None => "unknown status".to_string(),
        },
    };
    let message = format!("helper exited with {status_text}{}", stderr_suffix(stderr));
    match code {
        Some(0) => Outcome::Ok,
        Some(3) => Outcome::Refused {
            code: "exit".to_string(),
            message,
        },
        Some(4) => Outcome::Failed {
            code: "exit".to_string(),
            message,
        },
        Some(6) => Outcome::Cancelled,
        _ => Outcome::Failed {
            code: "exit".to_string(),
            message,
        },
    }
}

fn stderr_suffix(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let escaped = trimmed.escape_debug().to_string();
    let mut start = escaped.len().saturating_sub(STDERR_LIMIT);
    while !escaped.is_char_boundary(start) {
        start += 1;
    }
    format!("; stderr: {}", &escaped[start..])
}

fn synthesized_done(session: &str, outcome: Outcome) -> String {
    let outcome_json = match outcome {
        Outcome::Ok => r#"{"outcome":"ok"}"#.to_string(),
        Outcome::Refused { code, message } => format!(
            r#"{{"outcome":"refused","code":{},"message":{}}}"#,
            json_string(&code),
            json_string(&message)
        ),
        Outcome::Failed { code, message } => format!(
            r#"{{"outcome":"failed","code":{},"message":{}}}"#,
            json_string(&code),
            json_string(&message)
        ),
        Outcome::Cancelled => r#"{"outcome":"cancelled"}"#.to_string(),
    };
    format!(
        r#"{{"kind":"done","session":{},"version":{},"outcome":{outcome_json}}}"#,
        json_string(session),
        EVENT_STREAM_VERSION
    )
}

fn json_string(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use rufus_proto::{
        Completion, DeviceRef, EVENT_STREAM_VERSION, Event, Filesystem, ImageKind, ImageRef,
        Options, Outcome, PLAN_VERSION, Plan, Progress, Scheme, Step, Target,
    };

    use super::{PkexecTransport, STDERR_LIMIT};
    use crate::ipc::{HelperTransport, IpcError};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const SESSION: &str = "s-1";

    fn plan() -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "test".to_string(),
            device: DeviceRef {
                path: "/dev/sdz".to_string(),
                block_device: true,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: "x.iso".to_string(),
                size_bytes: 1,
                sha256: "0".to_string(),
                kind: ImageKind::Raw,
            },
            options: Options {
                scheme: Scheme::Mbr,
                target: Target::Uefi,
                filesystem: Filesystem::Fat32,
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
            steps: vec![Step::Wipe],
            confirm: String::new(),
        }
    }

    fn transport(script: &str) -> PkexecTransport {
        PkexecTransport::with_command("/bin/sh", ["-c", script])
    }

    fn transport_with_timeout(script: &str, timeout: Duration) -> PkexecTransport {
        PkexecTransport::with_command_and_authorization_timeout("/bin/sh", ["-c", script], timeout)
    }

    fn progress(done: u64) -> Event {
        Event::Progress(Progress::new(SESSION, 0, "wipe", done, Some(3)))
    }

    fn done(outcome: Outcome) -> Event {
        Event::Done(Completion {
            session: SESSION.to_string(),
            version: EVENT_STREAM_VERSION,
            outcome,
        })
    }

    fn prefixed_plan_files() -> Vec<PathBuf> {
        let prefix = format!("rufus-plan-{}-", std::process::id());
        fs::read_dir(std::env::temp_dir())
            .expect("temp directory is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .collect()
    }

    #[test]
    fn normal_run_surfaces_progress_in_order_and_only_one_done() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let script = concat!(
            "printf '%s\\n' ",
            "'",
            r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":1,"total":3,"percent":33}"#,
            "' ",
            "'",
            r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":2,"total":3,"percent":66}"#,
            "' ",
            "'",
            r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":3,"total":3,"percent":100}"#,
            "' ",
            "'",
            r#"{"kind":"done","session":"s-1","version":1,"outcome":{"outcome":"ok"}}"#,
            "'",
        );
        let mut started = transport(script).start(&plan()).expect("stub starts");
        assert_eq!(started.session, SESSION);
        assert_eq!(started.events.next(), Some(Ok(progress(1))));
        assert_eq!(started.events.next(), Some(Ok(progress(2))));
        assert_eq!(started.events.next(), Some(Ok(progress(3))));
        assert_eq!(started.events.next(), Some(Ok(done(Outcome::Ok))));
        assert_eq!(started.events.next(), None);
    }

    #[test]
    fn run_uses_the_helper_argv_and_plan_file_is_private_until_stream_end() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let script = concat!(
            "printf '{\"kind\":\"log\",\"session\":\"s-1\",\"level\":\"info\",\"message\":\"%s|%s|%s|%s|%s\"}\\n' ",
            "\"$0\" \"$1\" \"$2\" \"$3\" \"$4\"; ",
            "sleep 0.2; ",
            "printf '%s\\n' '",
            r#"{"kind":"done","session":"s-1","version":1,"outcome":{"outcome":"ok"}}"#,
            "'",
        );
        let mut started = transport(script).start(&plan()).expect("stub starts");
        let Some(Ok(Event::Log(log))) = started.events.next() else {
            panic!("stub should emit its argv log event");
        };
        let fields: Vec<_> = log.message.split('|').collect();
        assert_eq!(fields[0], "rufus-helper");
        assert_eq!(fields[1], "--plan");
        let plan_path = PathBuf::from(fields[2]);
        assert_eq!(fields[3], "--progress");
        assert_eq!(fields[4], "jsonl");
        assert!(
            plan_path.is_file(),
            "plan file must exist while the run is live"
        );
        assert_eq!(
            fs::metadata(&plan_path)
                .expect("plan metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(started.events.next(), Some(Ok(done(Outcome::Ok))));
        assert_eq!(started.events.next(), None);
        assert!(
            !plan_path.exists(),
            "plan file is removed after the stream ends"
        );
    }

    #[test]
    fn cancelling_a_live_run_kills_it_and_is_idempotent() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let script = concat!(
            "printf '%s\\n' '",
            r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":1,"total":3,"percent":33}"#,
            "'; exec sleep 30",
        );
        let mut started = transport(script).start(&plan()).expect("stub starts");
        assert_eq!(started.events.next(), Some(Ok(progress(1))));
        started.cancel.cancel().expect("cancel succeeds");
        assert_eq!(started.events.next(), Some(Ok(done(Outcome::Cancelled))));
        started
            .cancel
            .cancel()
            .expect("repeated cancel remains successful");
        assert_eq!(started.events.next(), None);
    }

    #[test]
    fn missing_program_is_a_spawn_error_and_leaves_no_temp_plan() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let before = prefixed_plan_files();
        let result = PkexecTransport::with_command(
            "/definitely/not/a/rufus-helper",
            std::iter::empty::<String>(),
        )
        .start(&plan());
        assert!(matches!(result, Err(IpcError::Spawn(_))));
        assert_eq!(prefixed_plan_files(), before);
    }

    #[test]
    fn exit_four_without_done_synthesizes_a_failed_completion() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let mut started = transport("printf 'stub failure\\n' >&2; exit 4")
            .start(&plan())
            .expect("stub starts");
        let Some(Ok(Event::Done(Completion {
            version, outcome, ..
        }))) = started.events.next()
        else {
            panic!("EOF should synthesize a terminal completion");
        };
        assert_eq!(version, EVENT_STREAM_VERSION);
        assert!(matches!(
            outcome,
            Outcome::Failed { code, message }
                if code == "exit" && message.contains('4') && message.contains("stub failure")
        ));
        assert_eq!(started.events.next(), None);
    }

    #[test]
    fn authorization_timeout_kills_and_reaps_silent_helper_and_removes_plan() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let marker = std::env::temp_dir().join(format!(
            "rufus-timeout-pid-{}-{}",
            std::process::id(),
            super::TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let before = prefixed_plan_files();
        let script = format!("echo $$ > '{}'; exec sleep 30", marker.display());
        let timeout = Duration::from_millis(500);
        let started_at = Instant::now();
        let result = transport_with_timeout(&script, timeout).start(&plan());
        assert!(matches!(
            result,
            Err(IpcError::Transport(message))
                if message == "no helper event within 0.5s; authorization not completed"
        ));
        assert!(started_at.elapsed() < Duration::from_secs(2));
        assert_eq!(prefixed_plan_files(), before, "timed-out plan is removed");
        let pid: u32 = fs::read_to_string(&marker)
            .expect("stub recorded its process id")
            .trim()
            .parse()
            .expect("stub process id parses");
        let process = PathBuf::from(format!("/proc/{pid}"));
        for _ in 0..100 {
            if !process.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!process.exists(), "timed-out helper is reaped");
        let _ = fs::remove_file(marker);
    }

    #[test]
    fn invalid_utf8_reader_error_ends_without_done_and_removes_plan() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let before = prefixed_plan_files();
        let mut started = transport("printf '\\377\\n'; exec sleep 30")
            .start(&plan())
            .expect("stub starts");
        assert!(matches!(
            started.events.next(),
            Some(Err(IpcError::Transport(_)))
        ));
        assert_eq!(started.events.next(), None, "reader error is terminal");
        assert_eq!(
            prefixed_plan_files(),
            before,
            "reader error removes the plan"
        );
    }

    #[test]
    fn exit_statuses_synthesize_expected_single_completion() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let cases = [
            (0, "ok"),
            (3, "refused"),
            (4, "failed"),
            (6, "cancelled"),
            (7, "failed"),
            (126, "failed"),
        ];
        for (status, expected) in cases {
            let mut started = transport(&format!("exit {status}"))
                .start(&plan())
                .expect("stub starts");
            let Some(Ok(Event::Done(completion))) = started.events.next() else {
                panic!("exit {status} should synthesize one completion");
            };
            assert_eq!(completion.version, EVENT_STREAM_VERSION);
            match (expected, completion.outcome) {
                ("ok", Outcome::Ok) | ("cancelled", Outcome::Cancelled) => {}
                ("refused", Outcome::Refused { code, .. })
                | ("failed", Outcome::Failed { code, .. }) => assert_eq!(code, "exit"),
                (expected, outcome) => {
                    panic!("exit {status}: expected {expected}, got {outcome:?}")
                }
            }
            assert_eq!(started.events.next(), None, "one Done for exit {status}");
        }
    }

    #[test]
    fn large_stderr_keeps_bounded_escaped_tail() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let mut started = transport(
            "head -c 65536 /dev/zero | tr '\\000' 'x' >&2; printf 'TAIL_MARKER\\n' >&2; exit 4",
        )
        .start(&plan())
        .expect("stub starts");
        let Some(Ok(Event::Done(Completion { outcome, .. }))) = started.events.next() else {
            panic!("EOF should synthesize a terminal completion");
        };
        let Outcome::Failed { message, .. } = outcome else {
            panic!("exit 4 should fail");
        };
        assert!(
            message.len() <= STDERR_LIMIT + 128,
            "{} bytes",
            message.len()
        );
        assert!(message.contains("TAIL_MARKER"), "stderr tail was retained");
        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn constructor_sweeps_only_stale_exact_scheme_plan_files() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let directory = std::env::temp_dir();
        let suffix = super::TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dead = directory.join(format!("rufus-plan-4294967295-{suffix}-1.json"));
        let live = directory.join(format!("rufus-plan-{}-{suffix}-2.json", std::process::id()));
        fs::write(&dead, "stale").expect("dead-pid fixture writes");
        fs::write(&live, "live").expect("live-pid fixture writes");
        fs::set_permissions(&dead, fs::Permissions::from_mode(0o600)).expect("dead mode set");
        fs::set_permissions(&live, fs::Permissions::from_mode(0o600)).expect("live mode set");

        let _transport = PkexecTransport::new();

        assert!(!dead.exists(), "dead-pid plan is swept");
        assert!(live.exists(), "live-pid plan is preserved");
        let _ = fs::remove_file(live);
    }

    #[test]
    fn blank_lines_between_events_are_skipped() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let script = concat!(
            "printf '%s\\n' '' '",
            r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":1,"total":3,"percent":33}"#,
            "' '' '",
            r#"{"kind":"done","session":"s-1","version":1,"outcome":{"outcome":"ok"}}"#,
            "'",
        );
        let mut started = transport(script).start(&plan()).expect("stub starts");
        assert_eq!(started.events.next(), Some(Ok(progress(1))));
        assert_eq!(started.events.next(), Some(Ok(done(Outcome::Ok))));
        assert_eq!(started.events.next(), None);
    }

    #[test]
    fn dropping_a_live_stream_removes_its_plan_file_and_kills_child() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let script = "printf '{\"kind\":\"log\",\"session\":\"s-1\",\"level\":\"info\",\"message\":\"%s\"}\\n' \"$2\"; exec sleep 30";
        let mut started = transport(script).start(&plan()).expect("stub starts");
        let Some(Ok(Event::Log(log))) = started.events.next() else {
            panic!("stub should emit its plan path");
        };
        let path = PathBuf::from(log.message);
        assert!(path.exists());
        drop(started.events);
        assert!(!path.exists(), "dropping the stream removes the temp plan");
        started
            .cancel
            .cancel()
            .expect("child cancellation succeeds");
    }

    #[test]
    fn stderr_control_characters_are_escaped_in_synthesized_failure_text() {
        let _serial = TEST_LOCK.lock().expect("test lock is available");
        let mut started = transport("printf 'bad\\033[2J\\nmessage\\n' >&2; exit 4")
            .start(&plan())
            .expect("stub starts");
        let Some(Ok(Event::Done(Completion { outcome, .. }))) = started.events.next() else {
            panic!("EOF should synthesize a terminal completion");
        };
        let Outcome::Failed { message, .. } = outcome else {
            panic!("exit 4 should fail");
        };
        assert!(!message.chars().any(char::is_control), "{message:?}");
        assert!(message.contains("\\u{1b}"), "{message:?}");
        assert!(message.contains("message"), "{message:?}");
    }
}
