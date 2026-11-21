//! System-bus client for `org.furuslinux.Helper1`.
//!
//! zbus 6 has no blocking API. Each connection, method call, and signal
//! stream is driven with `zbus::block_on` only on this transport's own
//! `std::thread`, never on a thread driven by the connection runtime. The
//! helper measured that calling `block_on` from a runtime task panics rather
//! than hangs (`block_on called from a task this runtime is running`).
//!
//! The helper's `Progress` signal uses `done: u64`, `total: i64`, and
//! `percent: i16`; `-1` means unknown total. The conversion validates
//! negative `done` and negative totals other than that sentinel, ignores the
//! signal's potentially lossy `percent`, and delegates percent derivation to
//! `furus_proto::Progress::new` so zero-total and over-total rules have one
//! source of truth. `Execute(plan_json)` obtains caller identity from the
//! D-Bus message sender; `Cancel(session_id)` uses the same connection so the
//! helper can enforce that caller identity.
//!
//! If the helper exits mid-run without a `Done`, the bus connection and
//! signal stream can remain open, so the event iterator may wait indefinitely.
//! Slice 4/5 should decide whether to watch `NameOwnerChanged` or accept this
//! wait; this transport deliberately does not watch name ownership yet.

use std::sync::mpsc;
use std::thread;

use furus_proto::{
    BUS_NAME, Completion, ERROR_BUSY, ERROR_INVALID_PLAN, ERROR_NOT_AUTHORIZED,
    ERROR_UNKNOWN_SESSION, EVENT_STREAM_VERSION, Event, INTERFACE_NAME, LogLevel, LogLine,
    OBJECT_PATH, Outcome, Plan, Progress,
};
use zbus::export::futures_core::Stream;

use super::{CancelHandle, EventStream, HelperTransport, IpcError, Started};

// The D-Bus name, path, interface and error names are the single-sourced
// contract in `furus_proto` (shared with the helper and checked against the
// packaging files by `xtask contract --check`). Only the wire-level
// `UNKNOWN_TOTAL` sentinel stays local to this transport.
const UNKNOWN_TOTAL: i64 = -1;

#[derive(Clone, Copy)]
pub(super) enum BusPhase {
    BeforeExecute,
    AfterExecute,
}

/// Unprivileged system-bus client. Construction does not touch the bus;
/// failure to connect is reported as `Unavailable` from [`start`](Self::start).
#[derive(Debug, Default)]
pub struct DbusTransport;

impl DbusTransport {
    /// Construct a transport without probing or connecting to the bus.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl HelperTransport for DbusTransport {
    fn start(&mut self, plan: &Plan) -> Result<Started, IpcError> {
        let plan = plan
            .to_json()
            .map_err(|error| transport_error(format!("could not serialize plan: {error}")))?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (line_tx, line_rx) = mpsc::channel();

        thread::Builder::new()
            .name("furus-dbus-client".to_string())
            .spawn(move || run_session(plan, ready_tx, line_tx))
            .map_err(|error| IpcError::Spawn(safe_text(&error.to_string())))?;

        let (session, connection) = ready_rx.recv().map_err(|_| {
            IpcError::Transport("D-Bus client ended before opening a session".to_string())
        })??;
        let cancel_connection = connection.clone();
        let cancel_session = session.clone();
        Ok(Started {
            session: session.clone(),
            events: EventStream::from_lines(
                session,
                std::iter::from_fn(move || line_rx.recv().ok()),
            ),
            cancel: CancelHandle::new(move || {
                cancel_session_on_thread(cancel_connection, cancel_session)
            }),
        })
    }
}

fn run_session(
    plan_json: String,
    ready: mpsc::SyncSender<Result<(String, zbus::Connection), IpcError>>,
    lines: mpsc::Sender<Result<String, IpcError>>,
) {
    let opened = zbus::block_on(async move {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| map_bus_error(error, BusPhase::BeforeExecute))?;
        let proxy = zbus::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, INTERFACE_NAME)
            .await
            .map_err(|error| map_bus_error(error, BusPhase::BeforeExecute))?;
        // Install the subscription before Execute: a fast helper must not
        // emit its first event in the gap between method reply and subscribe.
        let signals = proxy
            .receive_all_signals()
            .await
            .map_err(|error| map_bus_error(error, BusPhase::BeforeExecute))?;
        let session: String = proxy
            .call("Execute", &(plan_json,))
            .await
            .map_err(|error| map_bus_error(error, BusPhase::AfterExecute))?;
        Ok::<_, IpcError>((session, connection, signals))
    });

    let (session, connection, mut signals) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok((session.clone(), connection))).is_err() {
        return;
    }

    loop {
        let message = zbus::block_on(std::future::poll_fn(|context| {
            Stream::poll_next(std::pin::Pin::new(&mut signals), context)
        }));
        let Some(message) = message else {
            let _ = lines.send(Err(IpcError::Transport(
                "D-Bus signal stream ended before Done".to_string(),
            )));
            return;
        };
        let event = match signal_event(&message) {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(error) => {
                let _ = lines.send(Err(error));
                return;
            }
        };
        let terminal = matches!(&event, Event::Done(done) if done.session == session);
        let line = match serde_json::to_string(&event) {
            Ok(line) => line,
            Err(error) => {
                let _ = lines.send(Err(transport_error(format!(
                    "could not serialize D-Bus event: {error}"
                ))));
                return;
            }
        };
        if lines.send(Ok(line)).is_err() || terminal {
            return;
        }
    }
}

fn signal_event(message: &zbus::Message) -> Result<Option<Event>, IpcError> {
    let header = message.header();
    let member = header
        .member()
        .map(|name| name.as_str())
        .unwrap_or_default();
    match member {
        "Progress" => {
            let (session, step, op, done, total, percent): (String, u32, String, u64, i64, i16) =
                message.body().deserialize().map_err(|error| {
                    transport_error(format!("invalid Progress signal: {error}"))
                })?;
            progress_event(&session, step, &op, i128::from(done), total, percent).map(Some)
        }
        "Log" => {
            let (session, level, message): (String, String, String) = message
                .body()
                .deserialize()
                .map_err(|error| transport_error(format!("invalid Log signal: {error}")))?;
            log_event(&session, &level, &message).map(Some)
        }
        "Done" => {
            let (session, outcome_json): (String, String) = message
                .body()
                .deserialize()
                .map_err(|error| transport_error(format!("invalid Done signal: {error}")))?;
            done_event(&session, &outcome_json).map(Some)
        }
        _ => Ok(None),
    }
}

fn progress_event(
    session: &str,
    step: u32,
    op: &str,
    done: i128,
    total: i64,
    _signal_percent: i16,
) -> Result<Event, IpcError> {
    // The D-Bus wire field is u64, so signal_event cannot pass a negative
    // value; retain this guard for internal callers of progress_event.
    let done =
        u64::try_from(done).map_err(|_| transport_error("protocol violation: negative done"))?;
    let total = match total {
        UNKNOWN_TOTAL => None,
        value if value < 0 => {
            return Err(transport_error(
                "protocol violation: negative total other than unknown sentinel",
            ));
        }
        value => Some(value as u64),
    };
    Ok(Event::Progress(Progress::new(
        session,
        usize::try_from(step).unwrap_or(usize::MAX),
        op,
        done,
        total,
    )))
}

fn log_event(session: &str, level: &str, message: &str) -> Result<Event, IpcError> {
    let level = LogLevel::parse(level)
        .ok_or_else(|| transport_error(format!("protocol violation: unknown log level {level}")))?;
    Ok(Event::Log(LogLine {
        session: session.to_string(),
        level,
        message: message.to_string(),
    }))
}

fn done_event(session: &str, outcome_json: &str) -> Result<Event, IpcError> {
    let outcome: Outcome = serde_json::from_str(outcome_json).map_err(|error| {
        transport_error(format!("protocol violation: invalid Done outcome: {error}"))
    })?;
    // Helper1.Done has no version argument; stamp the current event-stream
    // version because the shared EventStream parser requires a versioned Done.
    Ok(Event::Done(Completion {
        session: session.to_string(),
        version: EVENT_STREAM_VERSION,
        outcome,
    }))
}

fn cancel_session_on_thread(connection: zbus::Connection, session: String) -> Result<(), IpcError> {
    thread::Builder::new()
        .name("furus-dbus-cancel".to_string())
        .spawn(move || {
            zbus::block_on(async move {
                let proxy = zbus::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, INTERFACE_NAME)
                    .await
                    .map_err(|error| map_bus_error(error, BusPhase::BeforeExecute))?;
                map_cancel_result(proxy.call::<_, _, ()>("Cancel", &(session,)).await)
            })
        })
        .map_err(|error| transport_error(format!("could not start D-Bus cancel: {error}")))?
        .join()
        .map_err(|_| IpcError::Transport("D-Bus cancel thread panicked".to_string()))?
}

fn map_cancel_result(result: Result<(), zbus::Error>) -> Result<(), IpcError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if helper_error_name(&error).as_deref() == Some(ERROR_UNKNOWN_SESSION) => Ok(()),
        Err(error) => Err(map_bus_error(error, BusPhase::BeforeExecute)),
    }
}

fn map_helper_error(name: &str, message: &str) -> IpcError {
    transport_error(format!("{name}: {message}"))
}

fn helper_error_name(error: &zbus::Error) -> Option<String> {
    match error {
        zbus::Error::MethodError(name, _, _)
            if matches!(
                name.as_str(),
                ERROR_NOT_AUTHORIZED | ERROR_BUSY | ERROR_INVALID_PLAN | ERROR_UNKNOWN_SESSION
            ) =>
        {
            Some(name.as_str().to_string())
        }
        zbus::Error::FDO(error) => match error.as_ref() {
            // AccessDenied may mean either polkit denied the user or the helper's
            // authorization check is unavailable; fallback cannot distinguish
            // them and could re-prompt a user who already refused.
            zbus::fdo::Error::AccessDenied(_) => Some(ERROR_NOT_AUTHORIZED.to_string()),
            zbus::fdo::Error::Failed(message) => {
                let helper_name = if message.starts_with(&format!("{ERROR_BUSY}:")) {
                    Some(ERROR_BUSY)
                } else if message.starts_with(&format!("{ERROR_INVALID_PLAN}:")) {
                    Some(ERROR_INVALID_PLAN)
                } else if message.starts_with(&format!("{ERROR_UNKNOWN_SESSION}:")) {
                    Some(ERROR_UNKNOWN_SESSION)
                } else {
                    None
                };
                helper_name.map(str::to_string)
            }
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn map_bus_error(error: zbus::Error, phase: BusPhase) -> IpcError {
    if let Some(name) = helper_error_name(&error) {
        return map_helper_error(&name, &error.to_string());
    }
    let unavailable = match &error {
        zbus::Error::FDO(error) => matches!(
            error.as_ref(),
            zbus::fdo::Error::NameHasNoOwner(_) | zbus::fdo::Error::ServiceUnknown(_)
        ),
        zbus::Error::InputOutput(_) | zbus::Error::Connection(_, _) => {
            matches!(phase, BusPhase::BeforeExecute)
        }
        _ => false,
    };
    if unavailable {
        IpcError::Unavailable(safe_text(&error.to_string()))
    } else {
        transport_error(error.to_string())
    }
}

fn transport_error(message: impl AsRef<str>) -> IpcError {
    IpcError::Transport(safe_text(message.as_ref()))
}

fn safe_text(message: &str) -> String {
    message.escape_debug().to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use furus_proto::{Completion, EVENT_STREAM_VERSION, Event, LogLevel, Outcome, Progress};

    use super::{
        BusPhase, INTERFACE_NAME, OBJECT_PATH, log_event, map_bus_error, map_cancel_result,
        map_helper_error, progress_event, signal_event,
    };
    use crate::ipc::{EventStream, IpcError};

    #[test]
    fn transport_construction_does_not_probe_or_connect_to_a_bus() {
        let transport = super::DbusTransport::new();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn progress_signal_maps_to_the_shared_jsonl_parser_and_ignores_wire_percent() {
        let signal = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Progress")
            .build(&("s-1", 3u32, "write", 50u64, 200i64, 999i16))
            .expect("signal builds");
        let event = signal_event(&signal)
            .expect("signal converts")
            .expect("recognized signal");
        assert_eq!(
            event,
            Event::Progress(Progress::new("s-1", 3, "write", 50, Some(200)))
        );
        let Event::Progress(progress) = &event else {
            panic!("signal maps to progress");
        };
        assert_eq!(progress.percent, Some(25), "the signal's 999 is ignored");
        let line = serde_json::to_string(&event).expect("event serializes");
        let mut stream = EventStream::from_lines("s-1", [Ok(line)].into_iter());
        assert_eq!(stream.next(), Some(Ok(event)));
    }

    #[test]
    fn progress_total_none_zero_and_greater_done_follow_proto_rules() {
        assert_eq!(
            progress_event("s-1", 0, "wipe", 0, -1, -1),
            Ok(Event::Progress(Progress::new("s-1", 0, "wipe", 0, None)))
        );
        let zero =
            progress_event("s-1", 0, "finalize", 0, 0, 42).expect("zero-total progress converts");
        assert!(matches!(zero, Event::Progress(progress) if progress.percent == Some(100)));
        let excessive =
            progress_event("s-1", 0, "write", 9, 4, 0).expect("over-total progress converts");
        assert!(matches!(excessive, Event::Progress(progress) if progress.percent == Some(100)));
    }

    #[test]
    fn negative_done_and_total_end_the_stream_with_named_transport_errors() {
        for (result, field) in [
            (progress_event("s-1", 0, "write", -1, 4, 0), "done"),
            (progress_event("s-1", 0, "write", 1, -2, 0), "total"),
        ] {
            let error = result.expect_err("negative wire value is a protocol violation");
            let mut stream = EventStream::from_lines("s-1", [Err(error)].into_iter());
            assert!(matches!(
                stream.next(),
                Some(Err(IpcError::Transport(message))) if message.contains(field)
            ));
            assert_eq!(stream.next(), None, "a protocol violation ends the stream");
        }
    }

    #[test]
    fn log_signal_maps_every_wire_level_and_message() {
        for (wire, level) in [
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
        ] {
            let signal = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Log")
                .build(&("s-1", wire, "message"))
                .expect("signal builds");
            assert_eq!(
                signal_event(&signal).expect("signal converts"),
                Some(Event::Log(furus_proto::LogLine {
                    session: "s-1".to_string(),
                    level,
                    message: "message".to_string(),
                }))
            );
            assert_eq!(
                log_event("s-1", wire, "message"),
                Ok(Event::Log(furus_proto::LogLine {
                    session: "s-1".to_string(),
                    level,
                    message: "message".to_string(),
                }))
            );
        }

        let warning = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Log")
            .build(&("s-1", "warning", "message"))
            .expect("signal builds");
        assert!(matches!(
            signal_event(&warning),
            Ok(Some(Event::Log(furus_proto::LogLine {
                level: LogLevel::Warn,
                ..
            })))
        ));

        let bogus = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Log")
            .build(&("s-1", "verbose", "message"))
            .expect("signal builds");
        assert!(matches!(
            signal_event(&bogus),
            Err(IpcError::Transport(message)) if message.contains("verbose")
        ));
    }

    #[test]
    fn done_signal_synthesizes_event_stream_version_and_uses_shared_parser() {
        let signal = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Done")
            .build(&("s-1", r#"{"outcome":"cancelled"}"#))
            .expect("signal builds");
        let event = signal_event(&signal)
            .expect("signal converts")
            .expect("recognized signal");
        assert_eq!(
            event,
            Event::Done(Completion {
                session: "s-1".to_string(),
                version: EVENT_STREAM_VERSION,
                outcome: Outcome::Cancelled,
            })
        );
        let line = serde_json::to_string(&event).expect("event serializes");
        let mut stream = EventStream::from_lines("s-1", [Ok(line)].into_iter());
        assert_eq!(stream.next(), Some(Ok(event)));
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn malformed_done_signals_are_transport_errors_without_events() {
        for outcome_json in ["{not json", r#"{"outcome":"bogus"}"#] {
            let signal = zbus::Message::signal(OBJECT_PATH, INTERFACE_NAME, "Done")
                .build(&("s-1", outcome_json))
                .expect("signal builds");
            let result = signal_event(&signal);
            assert!(matches!(
                result,
                Err(IpcError::Transport(message))
                    if message.contains("protocol violation: invalid Done outcome")
            ));
        }
    }

    #[test]
    fn helper_error_mapping_names_each_helper_error_and_escapes_control_bytes() {
        for name in [
            "org.furuslinux.Error.NotAuthorized",
            "org.furuslinux.Error.Busy",
            "org.furuslinux.Error.InvalidPlan",
            "org.furuslinux.Error.UnknownSession",
        ] {
            let IpcError::Transport(message) = map_helper_error(name, "bad\u{1b}\nrequest") else {
                panic!("helper refusal must be a transport error");
            };
            assert!(message.contains(name), "{message:?}");
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
    }

    #[test]
    fn bus_unavailable_errors_map_to_unavailable_for_fallback() {
        assert!(matches!(
            map_bus_error(
                zbus::fdo::Error::NameHasNoOwner("no owner".to_string()).into(),
                BusPhase::BeforeExecute,
            ),
            IpcError::Unavailable(_)
        ));
        assert!(matches!(
            map_bus_error(
                zbus::fdo::Error::ServiceUnknown("no service".to_string()).into(),
                BusPhase::BeforeExecute,
            ),
            IpcError::Unavailable(_)
        ));
        assert!(matches!(
            map_bus_error(
                zbus::Error::InputOutput(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "bus down"
                ))),
                BusPhase::BeforeExecute,
            ),
            IpcError::Unavailable(_)
        ));
        let address = "unix:path=/tmp/no-real-bus"
            .parse()
            .expect("address parses");
        assert!(matches!(
            map_bus_error(
                zbus::Error::Connection(
                    Arc::new(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "absent"
                    )),
                    Box::new(address)
                ),
                BusPhase::BeforeExecute,
            ),
            IpcError::Unavailable(_)
        ));
    }

    #[test]
    fn helper_fdo_errors_map_to_named_transport_errors() {
        let cases = [
            (
                zbus::fdo::Error::AccessDenied("denied".to_string()),
                "org.furuslinux.Error.NotAuthorized",
            ),
            (
                zbus::fdo::Error::Failed(
                    "org.furuslinux.Error.Busy: another session is running".to_string(),
                ),
                "org.furuslinux.Error.Busy",
            ),
            (
                zbus::fdo::Error::Failed(
                    "org.furuslinux.Error.InvalidPlan: invalid JSON".to_string(),
                ),
                "org.furuslinux.Error.InvalidPlan",
            ),
            (
                zbus::fdo::Error::Failed(
                    "org.furuslinux.Error.UnknownSession: no running session".to_string(),
                ),
                "org.furuslinux.Error.UnknownSession",
            ),
        ];
        for (error, helper_name) in cases {
            let IpcError::Transport(message) = map_bus_error(error.into(), BusPhase::BeforeExecute)
            else {
                panic!("helper errors are transport errors");
            };
            assert!(message.contains(helper_name), "{message:?}");
        }
    }

    #[test]
    fn cancel_of_an_already_finished_session_is_successful() {
        let result = map_cancel_result(Err(zbus::fdo::Error::Failed(
            "org.furuslinux.Error.UnknownSession: done".to_string(),
        )
        .into()));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn bus_error_messages_escape_raw_control_bytes() {
        let error = map_bus_error(
            zbus::Error::Failure("bad\u{1b}\nreply".to_string()),
            BusPhase::BeforeExecute,
        );
        assert!(!error.to_string().chars().any(char::is_control));
    }
}
