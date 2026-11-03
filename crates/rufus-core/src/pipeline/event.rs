//! Progress and report surfaces: what a run tells its caller.
//!
//! [`Event`] is the JSON-friendly, stable contract a run emits: the
//! CLI's JSONL stream speaks these lines in slice 4 and the GUI channel
//! carries the same payload in S24, so variant and field names are
//! frozen once shipped — rename with a version bump, never silently.
//! The throughput fields (`bytes_per_second`, `eta_seconds`) are filled
//! by the write loop; zero/`None` only while no sample exists (a fast
//! run's single final event, a zero-byte image, the sub-second table
//! stamp). `total: None` means "unknown, indeterminate".
//!
//! [`Reporter`] is the only sink: [`NullReporter`] drops everything for
//! runs nobody watches, and tests collect with the test reporter. No
//! channels, no threads here — the caller owns the plumbing.

use serde::Serialize;

/// One run event. Serialised with an `"event"` tag and snake_case
/// variant names; see the module docs before renaming anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A step is starting: `index` is 0-based, `total` the step count.
    StepStarted {
        /// 0-based step index.
        index: usize,
        /// Total step count of the run.
        total: usize,
        /// Snake-case step identifier (see `step_name`).
        step: &'static str,
    },
    /// A step finished cleanly, with its wall time.
    StepFinished {
        /// 0-based step index.
        index: usize,
        /// Snake-case step identifier (see `step_name`).
        step: &'static str,
        /// Step wall time in milliseconds.
        millis: u64,
    },
    /// Throughput sample. The rate fields are filled by the write
    /// loop; zero/`None` only while no sample exists.
    Progress {
        /// Snake-case step identifier (see `step_name`): a plan step,
        /// or `"verify"` for the read-back pass, which is an
        /// event-level pseudo-step rather than a plan step. A
        /// `step: "verify"` sample reaching `done == total` means
        /// "bytes read", not "bytes matched": the run's `finished`
        /// event — absent on failure — is the only honest success
        /// signal for a consumer.
        step: &'static str,
        /// Bytes completed.
        done: u64,
        /// Total bytes, or `None` when unknown (indeterminate).
        total: Option<u64>,
        /// Bytes per second (zero only while no sample exists).
        bytes_per_second: u64,
        /// Seconds remaining: `None` only while no sample exists.
        eta_seconds: Option<u64>,
    },
    /// A log-grade line. The text is already sanitised ASCII when the
    /// caller emits it (mirrors the `Logger`, which owns no sanitising
    /// of its own either).
    Message {
        /// Severity as lowercase text (`"info"`, `"warn"`, `"error"`).
        level: &'static str,
        /// The sanitised line.
        text: String,
    },
    /// The whole run finished cleanly, with its wall time.
    Finished {
        /// Run wall time in milliseconds.
        millis: u64,
    },
}

/// The event sink a run reports to.
pub trait Reporter {
    /// Accept one [`Event`].
    fn event(&mut self, event: Event);
}

/// A [`Reporter`] that drops everything: runs nobody watches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NullReporter;

impl Reporter for NullReporter {
    fn event(&mut self, _event: Event) {}
}

/// A collecting [`Reporter`] for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct VecReporter {
    events: Vec<Event>,
}

#[cfg(test)]
impl VecReporter {
    /// A reporter collecting into a fresh log.
    pub(crate) fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Every event collected so far, in emission order.
    pub(crate) fn events(&self) -> &[Event] {
        &self.events
    }
}

#[cfg(test)]
impl Reporter for VecReporter {
    fn event(&mut self, event: Event) {
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporters_collect_and_drop() {
        let mut dropped = NullReporter;
        dropped.event(Event::Finished { millis: 3 });
        let mut kept = VecReporter::new();
        kept.event(Event::StepStarted {
            index: 0,
            total: 1,
            step: "finalize",
        });
        kept.event(Event::StepFinished {
            index: 0,
            step: "finalize",
            millis: 1,
        });
        kept.event(Event::Finished { millis: 2 });
        assert_eq!(kept.events().len(), 3);
        assert!(matches!(
            kept.events(),
            [
                Event::StepStarted {
                    index: 0,
                    total: 1,
                    ..
                },
                Event::StepFinished { index: 0, .. },
                Event::Finished { .. }
            ]
        ));
    }

    #[test]
    fn wire_tags_are_snake_case_event_names() {
        // The `toml` crate is the only serializer in this crate's
        // budget, so the tag spelling is pinned through it: `event =
        // "step_started"` must survive exactly.
        for (event, tag) in [
            (
                Event::StepStarted {
                    index: 1,
                    total: 7,
                    step: "mkfs",
                },
                "step_started",
            ),
            (
                Event::StepFinished {
                    index: 2,
                    step: "write",
                    millis: 9,
                },
                "step_finished",
            ),
            (
                Event::Message {
                    level: "info",
                    text: "finalized 8 byte target".to_string(),
                },
                "message",
            ),
            (Event::Finished { millis: 4 }, "finished"),
        ] {
            let text = toml::to_string(&event).expect("all-scalar events serialise to TOML");
            assert!(
                text.contains(&format!("event = \"{tag}\"")),
                "missing tag {tag}: {text}"
            );
        }
        // Progress carries `Option` totals the TOML shape cannot hold,
        // so it is pinned by construction only.
        let progress = Event::Progress {
            step: "write",
            done: 3,
            total: None,
            bytes_per_second: 0,
            eta_seconds: None,
        };
        assert!(matches!(
            progress,
            Event::Progress {
                done: 3,
                total: None,
                ..
            }
        ));
    }
}
