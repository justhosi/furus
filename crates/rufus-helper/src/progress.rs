//! Progress sinks: where helper events go while a plan runs (S06).
//!
//! [`ProgressSink`] is the one seam between the executor loop
//! ([`crate::exec`] and, since S17, real step executors) and whatever
//! transports events: JSON lines on stdout, test buffers, later the
//! D-Bus signals of S06 part 4. Everything a sink receives has already
//! been sanitised by its producer (`rufus_core::text::device_text` at
//! every place a device-derived string is embedded), so sinks re-emit
//! verbatim — that wire contract is pinned by `rufus-proto::events`.
//!
//! [`JsonlSink`] implements the S06 transport for the `--progress jsonl`
//! mode: one compact JSON [`Event`](rufus_proto::Event) per line,
//! flushed immediately so a GUI reading the pipe is never behind. A
//! write error is *recorded* (`failed()`) instead of panicking — a
//! vanished GUI reader must not crash a helper that is mid-write;
//! `main` turns a failed sink into exit 4.

use std::io;

use rufus_proto::Event;

/// Where run-time events are delivered. Implemented for the JSONL
/// transport ([`JsonlSink`]), the test buffer ([`VecSink`]) and (since
/// S06 part 4) the D-Bus signalling bridge.
pub trait ProgressSink {
    /// Deliver one event. Implementations that cannot deliver (a dead
    /// reader behind a pipe) record that their own way
    /// ([`JsonlSink::failed()`]) but must never panic, block forever, or
    /// drop events without a record.
    fn event(&mut self, event: &Event);
}

/// The `--progress jsonl` sink: one compact JSON object per line.
///
/// Each event serialises into `writer` followed by `\n`, then flushes,
/// so a reader sees whole lines the moment they are produced. On the
/// first write error the sink *stops trying* (further events are
/// dropped without more failed writes) and reports the failure through
/// [`JsonlSink::failed`]; `main` maps the recorded failure to exit code
/// 4 (PLAN §2 fail closed: events that never reached their reader mean
/// the run's success was never actually reported).
pub struct JsonlSink<W: io::Write> {
    writer: W,
    failed: bool,
}

impl<W: io::Write> JsonlSink<W> {
    /// Wrap `writer`; a fresh sink has recorded no failure.
    #[must_use]
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            failed: false,
        }
    }

    /// `true` once any event could not be written (see the struct docs).
    #[must_use]
    pub fn failed(&self) -> bool {
        self.failed
    }
}

impl<W: io::Write> ProgressSink for JsonlSink<W> {
    fn event(&mut self, event: &Event) {
        if self.failed {
            return; // the writer is gone; stay quiet instead of choking
        }
        // One stepwise write, reported once: the serde error is folded
        // into the io error so the sequence reads straight through.
        let write = || -> io::Result<()> {
            serde_json::to_writer(&mut self.writer, event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            self.writer.write_all(b"\n")?;
            self.writer.flush()
        }();
        if write.is_err() {
            self.failed = true;
        }
    }
}

/// In-memory sink: collects every event it receives, in order.
///
/// Test-side companion (also used by `main` as the discard sink when the
/// caller passed no `--progress`): cheap, order-preserving, and usable
/// to *assert* on the event stream itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VecSink {
    events: Vec<Event>,
}

impl VecSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event received so far, in delivery order.
    #[allow(dead_code)] // the stream-inspection seam: tests, and the progress echo of S06 part 4
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

impl ProgressSink for VecSink {
    fn event(&mut self, event: &Event) {
        self.events.push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use rufus_proto::EVENT_STREAM_VERSION;
    use rufus_proto::Event;
    use rufus_proto::LogLevel;
    use rufus_proto::LogLine;
    use rufus_proto::Outcome;
    use rufus_proto::Progress;

    use super::JsonlSink;
    use super::ProgressSink;
    use super::VecSink;

    const SESSION: &str = "s-test";

    fn sample_log(message: &str) -> Event {
        Event::Log(LogLine {
            session: SESSION.to_string(),
            level: LogLevel::Info,
            message: message.to_string(),
        })
    }

    /// A writer that counts writes and fails them once past
    /// `succeed_for` calls; the counter lives in a shared `Cell` so the
    /// test can check it after the sink has been dropped.
    struct CountingWriter {
        succeed_for: usize,
        writes: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let writes = self.writes.get() + 1;
            self.writes.set(writes);
            if writes > self.succeed_for {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader gone"));
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn jsonl_lines_are_compact_newline_terminated_json() {
        let mut bytes = Vec::<u8>::new();
        {
            let mut sink = JsonlSink::new(&mut bytes);
            sink.event(&sample_log("hello"));
            sink.event(&Event::Progress(Progress::new(
                SESSION,
                0,
                "wipe",
                1,
                Some(2),
            )));
            assert!(!sink.failed(), "healthy writes record no failure");
        }
        let text = String::from_utf8(bytes).expect("the sink wrote UTF-8 JSON");

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per event: {text}");
        assert_eq!(
            lines[0], r#"{"kind":"log","session":"s-test","level":"info","message":"hello"}"#,
            "compact JSON in declaration field order: {text}"
        );
        assert_eq!(
            lines[1],
            concat!(
                r#"{"kind":"progress","session":"s-test","step":0,"op":"wipe","#,
                r#""done":1,"total":2,"percent":50}"#
            )
        );
    }

    #[test]
    fn write_errors_are_recorded_not_panicking_and_stop_further_writes() {
        let writes = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let mut sink = JsonlSink::new(CountingWriter {
            succeed_for: 0,
            writes: writes.clone(),
        });
        assert!(!sink.failed(), "a fresh sink has no recorded failure");

        for _ in 0..3 {
            sink.event(&sample_log("lost")); // the panic would be here
        }
        assert!(sink.failed(), "the write failure is recorded, not ignored");

        // Once failed, no further (failing) writes happen, so the
        // helper cannot stall on a dead reader.
        drop(sink);
        assert_eq!(writes.get(), 1, "exactly one broken write was attempted");

        // A new sink over a working writer reports no failure. (serde
        // streams one event as many small writes, so the budget must
        // cover the chunks, not the events.)
        let mut sink = JsonlSink::new(CountingWriter {
            succeed_for: 10_000,
            writes: std::rc::Rc::new(std::cell::Cell::new(0)),
        });
        sink.event(&Event::Done(rufus_proto::Completion {
            session: SESSION.to_string(),
            version: EVENT_STREAM_VERSION,
            outcome: Outcome::Ok,
        }));
        assert!(!sink.failed(), "an unreachable writer misreports nothing");
    }

    #[test]
    fn vec_sink_preserves_delivery_order() {
        let mut sink = VecSink::new();
        ProgressSink::event(
            &mut sink,
            &Event::Progress(Progress::new(SESSION, 0, "wipe", 0, None)),
        );
        ProgressSink::event(&mut sink, &sample_log("second"));
        ProgressSink::event(
            &mut sink,
            &Event::Done(rufus_proto::Completion {
                session: SESSION.to_string(),
                version: EVENT_STREAM_VERSION,
                outcome: Outcome::Cancelled,
            }),
        );

        let events = sink.events();
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], Event::Progress(_)));
        assert!(matches!(events[1], Event::Log(_)));
        assert!(matches!(events[2], Event::Done(_)));
        for event in events {
            let text = serde_json::to_string(event).expect("event serialises");
            assert!(text.contains(SESSION), "session echoed: {text}");
        }
    }
}
