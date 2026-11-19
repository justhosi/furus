//! Unprivileged client half of helper IPC. The privileged half is
//! `rufus-helper`; transports are swapped behind one trait so the UI and its
//! tests never care which is in use. The JSONL wire contract lives in
//! `rufus-proto` and is not re-implemented here.

use std::fmt;
use std::sync::{Arc, Mutex};

use rufus_proto::{Event, LineError, Plan, from_jsonl_line};

pub mod dbus;
pub mod pkexec;
pub use dbus::DbusTransport;
pub use pkexec::PkexecTransport;

/// Chosen implementation of the helper transport.
pub enum TransportChoice {
    /// Prefer the privileged system-bus service.
    Dbus(DbusTransport),
    /// One-shot fallback through pkexec.
    Pkexec(PkexecTransport),
}

impl HelperTransport for TransportChoice {
    fn start(&mut self, plan: &Plan) -> Result<Started, IpcError> {
        match self {
            Self::Dbus(transport) => transport.start(plan),
            Self::Pkexec(transport) => transport.start(plan),
        }
    }
}

/// Prefer the system-bus service; fall back to the one-shot pkexec path.
///
/// `prefer_dbus` is an injected probe so selection is testable without any
/// bus access. If the selected D-Bus transport later returns
/// [`IpcError::Unavailable`] from `start`, the caller should retry once with
/// pkexec via [`start_with_fallback`].
#[must_use]
pub fn open_helper(prefer_dbus: impl FnOnce() -> bool) -> TransportChoice {
    if prefer_dbus() {
        TransportChoice::Dbus(DbusTransport::new())
    } else {
        TransportChoice::Pkexec(PkexecTransport::new())
    }
}

/// Start the preferred transport, retrying through `fallback` only when its
/// error is [`IpcError::Unavailable`]. The fallback is constructed and
/// started at most once; its result is returned unchanged.
///
/// AccessDenied may mean either polkit denied the user or the helper's
/// authorization check is unavailable; fallback cannot distinguish
/// them and could re-prompt a user who already refused.
pub fn start_with_fallback(
    preferred: &mut dyn HelperTransport,
    plan: &Plan,
    fallback: impl FnOnce() -> Box<dyn HelperTransport>,
) -> Result<Started, IpcError> {
    match preferred.start(plan) {
        Err(IpcError::Unavailable(_)) => fallback().start(plan),
        result => result,
    }
}

/// Failure to start or communicate with the privileged helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    /// No supported helper transport is available on this system.
    Unavailable(String),
    /// The helper process could not be started.
    Spawn(String),
    /// The helper emitted an invalid or unsupported wire event.
    Protocol(LineError),
    /// The selected transport failed while delivering events.
    Transport(String),
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "helper unavailable: {message}"),
            Self::Spawn(message) => write!(formatter, "could not start helper: {message}"),
            Self::Protocol(error) => write!(formatter, "helper protocol error: {error}"),
            Self::Transport(message) => write!(formatter, "helper transport error: {message}"),
        }
    }
}

impl std::error::Error for IpcError {}

type CancelAction = Box<dyn FnOnce() -> Result<(), IpcError> + Send + 'static>;

/// Cloneable, one-shot request to cancel a helper run.
#[derive(Clone)]
pub struct CancelHandle {
    action: Arc<Mutex<Option<CancelAction>>>,
    result: Arc<Mutex<Option<Result<(), IpcError>>>>,
}

impl CancelHandle {
    /// Construct a handle around a one-shot transport cancellation action.
    pub(crate) fn new(action: impl FnOnce() -> Result<(), IpcError> + Send + 'static) -> Self {
        Self {
            action: Arc::new(Mutex::new(Some(Box::new(action)))),
            result: Arc::new(Mutex::new(None)),
        }
    }

    /// Cancel the run once; subsequent calls return the first result.
    pub fn cancel(&self) -> Result<(), IpcError> {
        let mut result = self
            .result
            .lock()
            .map_err(|_| IpcError::Transport("cancel handle lock poisoned".to_string()))?;
        if let Some(result) = result.as_ref() {
            return result.clone();
        }

        let action = self
            .action
            .lock()
            .map_err(|_| IpcError::Transport("cancel handle lock poisoned".to_string()))?
            .take();
        let first_result = action.map_or(Ok(()), |action| action());
        *result = Some(first_result.clone());
        first_result
    }
}

/// A started helper session, its event stream and its cancellation handle.
pub struct Started {
    /// Session identifier echoed by every event in this run.
    pub session: String,
    /// Events belonging to this session.
    pub events: EventStream,
    /// Request to cancel this session.
    pub cancel: CancelHandle,
}

/// Blocking iterator over one helper session's parsed events.
pub struct EventStream {
    session: String,
    lines: Box<dyn Iterator<Item = Result<String, IpcError>> + Send>,
    terminal: bool,
}

impl EventStream {
    pub(crate) fn from_lines<I>(session: impl Into<String>, lines: I) -> Self
    where
        I: Iterator<Item = Result<String, IpcError>> + Send + 'static,
    {
        Self {
            session: session.into(),
            lines: Box::new(lines),
            terminal: false,
        }
    }
}

impl Iterator for EventStream {
    type Item = Result<Event, IpcError>;

    /// Return the next matching event, or `None` after the stream ends or
    /// its terminal completion has been observed.
    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal {
            return None;
        }
        loop {
            let line = match self.lines.next()? {
                Ok(line) => line,
                Err(error) => return Some(Err(error)),
            };
            let event = match from_jsonl_line(&line) {
                Ok(event) => event,
                Err(error) => return Some(Err(IpcError::Protocol(error))),
            };
            let session = match &event {
                Event::Progress(progress) => &progress.session,
                Event::Log(log) => &log.session,
                Event::Done(completion) => &completion.session,
            };
            if session != &self.session {
                continue;
            }
            if matches!(event, Event::Done(_)) {
                self.terminal = true;
            }
            return Some(Ok(event));
        }
    }
}

/// A transport that starts one helper run for a plan.
pub trait HelperTransport {
    /// Start the plan and return its session-scoped event stream.
    ///
    /// This may block until the helper's first non-blank event. In particular,
    /// `pkexec` is silent while polkit authenticates, so this can legitimately
    /// take the entire authorization budget; it returns an error if that
    /// budget expires.
    fn start(&mut self, plan: &Plan) -> Result<Started, IpcError>;
}

/// In-memory transport for tests; replays JSONL through the production parser.
pub struct MockTransport {
    session: String,
    lines: Vec<String>,
}

impl MockTransport {
    /// Build a transport that replays these JSONL lines without spawning.
    #[must_use]
    pub fn new(session: impl Into<String>, lines: Vec<String>) -> Self {
        Self {
            session: session.into(),
            lines,
        }
    }
}

impl HelperTransport for MockTransport {
    fn start(&mut self, _plan: &Plan) -> Result<Started, IpcError> {
        let session = self.session.clone();
        let lines = self.lines.clone().into_iter().map(Ok);
        Ok(Started {
            session: session.clone(),
            events: EventStream::from_lines(session, lines),
            cancel: CancelHandle::new(|| Ok(())),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rufus_proto::{
        DeviceRef, Event, Filesystem, ImageKind, ImageRef, Options, PLAN_VERSION, Plan, Scheme,
        Step, Target,
    };

    use super::{
        CancelHandle, DbusTransport, EventStream, HelperTransport, IpcError, MockTransport,
        PkexecTransport, Started, TransportChoice, open_helper, start_with_fallback,
    };

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

    #[test]
    fn mock_transport_demultiplexes_and_stops_after_one_done() {
        let mut transport = MockTransport::new(
            "s-1",
            vec![
                r#"{"kind":"progress","session":"other","step":0,"op":"wipe","done":1,"total":2,"percent":50}"#.to_string(),
                r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":1,"total":2,"percent":50}"#.to_string(),
                r#"{"kind":"done","session":"s-1","version":1,"outcome":{"outcome":"ok"}}"#.to_string(),
                r#"{"kind":"progress","session":"s-1","step":0,"op":"wipe","done":2,"total":2,"percent":100}"#.to_string(),
            ],
        );

        let mut started = transport.start(&plan()).expect("mock transport starts");
        assert_eq!(started.session, "s-1");
        assert_eq!(
            started.events.next(),
            Some(Ok(Event::Progress(rufus_proto::Progress::new(
                "s-1",
                0,
                "wipe",
                1,
                Some(2),
            ))))
        );
        assert!(matches!(started.events.next(), Some(Ok(Event::Done(_)))));
        assert_eq!(started.events.next(), None, "Done is terminal");
        assert_eq!(started.events.next(), None, "Done is surfaced exactly once");
    }

    #[test]
    fn mock_transport_uses_the_proto_parser_and_surfaces_protocol_errors() {
        let mut transport = MockTransport::new("s-1", vec!["not JSON".to_string()]);
        let mut started = transport.start(&plan()).expect("mock transport starts");
        assert!(matches!(
            started.events.next(),
            Some(Err(IpcError::Protocol(rufus_proto::LineError::Json(_))))
        ));
    }

    #[test]
    fn cancel_runs_its_action_once_across_clones() {
        fn assert_send<T: Send>() {}
        assert_send::<CancelHandle>();
        assert_send::<EventStream>();

        let calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::clone(&calls);
        let cancel = CancelHandle::new(move || {
            cancel_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let clone = cancel.clone();

        cancel.cancel().expect("first cancellation succeeds");
        clone
            .cancel()
            .expect("repeat cancellation returns cached success");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cancel_repeats_the_first_error_across_clones() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::clone(&calls);
        let cancel = CancelHandle::new(move || {
            cancel_calls.fetch_add(1, Ordering::Relaxed);
            Err(IpcError::Transport("cancel failed".to_string()))
        });
        let clone = cancel.clone();
        let expected = Err(IpcError::Transport("cancel failed".to_string()));

        assert_eq!(cancel.cancel(), expected);
        assert_eq!(clone.cancel(), expected);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn event_stream_forwards_transport_errors_and_ignores_mismatched_sessions() {
        let lines = vec![
            Ok(r#"{"kind":"log","session":"other","level":"info","message":"skip"}"#.to_string()),
            Err(IpcError::Transport("reader closed".to_string())),
        ];
        let mut events = EventStream::from_lines("s-1", lines.into_iter());
        assert_eq!(
            events.next(),
            Some(Err(IpcError::Transport("reader closed".to_string())))
        );
        assert_eq!(events.next(), None);
    }

    struct FailingTransport {
        result: Option<IpcError>,
        calls: Arc<AtomicUsize>,
    }

    impl HelperTransport for FailingTransport {
        fn start(&mut self, _plan: &rufus_proto::Plan) -> Result<Started, IpcError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(self.result.take().expect("start called once"))
        }
    }

    #[test]
    fn open_helper_selects_transport_from_injected_probe() {
        assert!(matches!(open_helper(|| true), TransportChoice::Dbus(_)));
        assert!(matches!(open_helper(|| false), TransportChoice::Pkexec(_)));
        fn assert_transport<T: HelperTransport>() {}
        assert_transport::<DbusTransport>();
        assert_transport::<PkexecTransport>();
    }

    #[test]
    fn unavailable_preferred_transport_retries_fallback_once_and_returns_its_result() {
        let preferred_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let mut preferred = FailingTransport {
            result: Some(IpcError::Unavailable("bus absent".to_string())),
            calls: Arc::clone(&preferred_calls),
        };
        let fallback_counter = Arc::clone(&fallback_calls);
        let fallback = move || {
            Box::new(FailingTransport {
                result: Some(IpcError::Transport("fallback result".to_string())),
                calls: fallback_counter,
            }) as Box<dyn HelperTransport>
        };
        assert_eq!(
            start_with_fallback(&mut preferred, &plan(), fallback).err(),
            Some(IpcError::Transport("fallback result".to_string()))
        );
        assert_eq!(preferred_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn authorization_denial_from_dbus_does_not_construct_fallback() {
        let mapped = super::dbus::map_bus_error(
            zbus::fdo::Error::AccessDenied("polkit denied".to_string()).into(),
            super::dbus::BusPhase::AfterExecute,
        );
        assert!(matches!(mapped, IpcError::Transport(_)));

        let mut preferred = FailingTransport {
            result: Some(mapped),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let fallback_called = Arc::new(AtomicUsize::new(0));
        let fallback_counter = Arc::clone(&fallback_called);
        let result = start_with_fallback(&mut preferred, &plan(), move || {
            fallback_counter.fetch_add(1, Ordering::Relaxed);
            Box::new(FailingTransport {
                result: Some(IpcError::Transport("unexpected".to_string())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        });
        assert!(matches!(result, Err(IpcError::Transport(_))));
        assert_eq!(fallback_called.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn execute_io_error_does_not_construct_fallback() {
        let mapped = super::dbus::map_bus_error(
            zbus::Error::InputOutput(Arc::new(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "connection lost after Execute",
            ))),
            super::dbus::BusPhase::AfterExecute,
        );
        assert!(matches!(mapped, IpcError::Transport(_)));

        let mut preferred = FailingTransport {
            result: Some(mapped),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let fallback_called = Arc::new(AtomicUsize::new(0));
        let fallback_counter = Arc::clone(&fallback_called);
        let result = start_with_fallback(&mut preferred, &plan(), move || {
            fallback_counter.fetch_add(1, Ordering::Relaxed);
            Box::new(FailingTransport {
                result: Some(IpcError::Transport("unexpected".to_string())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        });
        assert!(matches!(result, Err(IpcError::Transport(_))));
        assert_eq!(fallback_called.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn non_unavailable_preferred_error_does_not_construct_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut preferred = FailingTransport {
            result: Some(IpcError::Transport("not fallback eligible".to_string())),
            calls: Arc::clone(&calls),
        };
        let fallback_called = Arc::new(AtomicUsize::new(0));
        let fallback_counter = Arc::clone(&fallback_called);
        let result = start_with_fallback(&mut preferred, &plan(), move || {
            fallback_counter.fetch_add(1, Ordering::Relaxed);
            Box::new(FailingTransport {
                result: Some(IpcError::Transport("unexpected".to_string())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        });
        assert_eq!(
            result.err(),
            Some(IpcError::Transport("not fallback eligible".to_string()))
        );
        assert_eq!(fallback_called.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ipc_errors_have_pinned_display_strings() {
        assert_eq!(
            IpcError::Unavailable("no helper".to_string()).to_string(),
            "helper unavailable: no helper"
        );
        assert_eq!(
            IpcError::Spawn("denied".to_string()).to_string(),
            "could not start helper: denied"
        );
        assert_eq!(
            IpcError::Protocol(rufus_proto::LineError::Empty).to_string(),
            "helper protocol error: empty JSONL event line"
        );
        assert_eq!(
            IpcError::Transport("reader closed".to_string()).to_string(),
            "helper transport error: reader closed"
        );
    }
}
