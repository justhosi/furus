//! Helper event stream: versioned progress, log and completion messages,
//! wrapped into one JSONL [`Event`] type (S06).
//!
//! # Wire contract (JSONL)
//!
//! The privileged helper streams its run of one plan as *one [`Event`] per
//! line* of JSON (`JSONL`) on its standard output: no framing bytes, no
//! length prefixes, no separators — only the newline that terminates each
//! line (JSON escaping keeps every message on its own line). Every event
//! is tagged by its `kind` field (`"progress"`, `"log"`, `"done"`) and
//! every payload echoes the run's `session` string — chosen by the caller
//! that started the plan — so the lines of concurrent runs can be
//! demultiplexed afterwards.
//!
//! The stream is versioned independently of [`crate::PLAN_VERSION`]
//! (which versions the plan schema only): every [`Completion`] carries
//! [`EVENT_STREAM_VERSION`], and a reader that meets a higher value must
//! stop early instead of guessing. Unknown `kind` values refuse to
//! deserialise (fail closed, PLAN §2), so adding an [`Event`] variant is
//! a schema change that bumps [`EVENT_STREAM_VERSION`].
//!
//! # Trust boundary
//!
//! This crate re-serialises strings verbatim; it does not sanitise
//! anything. Producers must run every device/kernel/image-derived string
//! through `rufus_core::text::device_text` before building a [`Progress`]
//! `op`/`session` or a [`LogLine`] `message`.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Schema version of the helper event stream ([`Event`] lines), written
/// into every [`Completion`]. Deliberately independent of
/// [`crate::PLAN_VERSION`].
pub const EVENT_STREAM_VERSION: u32 = 1;

/// Progress of the step currently being executed.
///
/// Emitted repeatedly while the step named by `step`/`op` moves bytes (or
/// units); `op` is the step's JSON op tag, so a reader can render progress
/// without a copy of the plan. Field order (`session`, `step`, `op`,
/// `done`, `total`, `percent`) is the canonical wire layout, like the
/// declaration order of the plan schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Run identifier echoed from the plan request; every event of one
    /// run carries the same value (see the module docs).
    pub session: String,
    /// 0-based index into the plan's `steps`.
    pub step: usize,
    /// The step's JSON op tag (`"wipe"`, `"write"`, …).
    pub op: String,
    /// Units completed so far (bytes for byte-moving steps).
    pub done: u64,
    /// Units to complete in total; `None` is indeterminate — the helper
    /// cannot size the remaining work of the step.
    pub total: Option<u64>,
    /// Derived percent `0..=100`; `None` exactly when `total` is `None`
    /// (see [`Progress::new`] for the deriving rule).
    pub percent: Option<u8>,
}

impl Progress {
    /// Build a `Progress`, deriving `percent` from `done`/`total`.
    ///
    /// The derived value is `floor(done * 100 / total)` clamped into
    /// `0..=100`, with the rules pinned here and tested:
    ///
    /// * `total: None` → `percent: None` (indeterminate).
    /// * `total: Some(0)` → `Some(100)`: a step with zero units of work
    ///   is vacuously complete. This covers `done == 0` (where the ratio
    ///   is 0/0 and a real percent does not exist) and an inconsistent
    ///   `done > 0` report alike — there is no unit of work left either
    ///   way.
    /// * `done > total` (progress outrunning its own total) clamps to
    ///   `Some(100)`.
    /// * The arithmetic is exact: `done * 100` is computed in `u128`, so
    ///   `u64::MAX` inputs neither overflow nor saturate, and nothing
    ///   ever panics.
    pub fn new(
        session: impl Into<String>,
        step: usize,
        op: impl Into<String>,
        done: u64,
        total: Option<u64>,
    ) -> Self {
        let percent = match total {
            None => None,
            // Zero work to do: vacuously complete (this is also the 0/0
            // case, which has no real percent).
            Some(0) => Some(100),
            Some(total) => {
                // Exact: `u64::MAX * 100` still fits a `u128`, so this
                // neither overflows nor saturates.
                let ratio = (u128::from(done) * 100) / u128::from(total);
                // `ratio` exceeds 100 only for an inconsistent `done >
                // total`; clamp it (the lossless-`u8` cast then holds).
                Some(ratio.min(100) as u8)
            }
        };
        Self {
            session: session.into(),
            step,
            op: op.into(),
            done,
            total,
            percent,
        }
    }
}

/// Severity of a [`LogLine`]; mirrors the naming of
/// `rufus_core::log::Level` without depending on `rufus-core` (proto must
/// stay standalone). Variant order and the snake-case tags (`"warn"` and
/// friends) are the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Failures.
    Error,
    /// Recoverable problems (JSON tag `"warn"`).
    Warn,
    /// Normal milestones.
    Info,
    /// Developer detail.
    Debug,
    /// Everything.
    Trace,
}

impl LogLevel {
    /// Lowercase snake-case JSON tag, e.g. `"warn"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parse `"error"`, `"warn"`/`"warning"`, `"info"`, `"debug"`,
    /// `"trace"` (ASCII case-insensitive; the JSON tags are all accepted,
    /// plus the `"warning"` spelling). Anything else returns `None`.
    pub fn parse(text: &str) -> Option<Self> {
        if text.eq_ignore_ascii_case("error") {
            Some(Self::Error)
        } else if text.eq_ignore_ascii_case("warn") || text.eq_ignore_ascii_case("warning") {
            Some(Self::Warn)
        } else if text.eq_ignore_ascii_case("info") {
            Some(Self::Info)
        } else if text.eq_ignore_ascii_case("debug") {
            Some(Self::Debug)
        } else if text.eq_ignore_ascii_case("trace") {
            Some(Self::Trace)
        } else {
            None
        }
    }
}

impl fmt::Display for LogLevel {
    /// Lowercase snake-case JSON tag (same as [`LogLevel::as_str`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One log line emitted by the helper while running a plan. Field order
/// (`session`, `level`, `message`) is the canonical wire layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// Run identifier echoed from the plan request.
    pub session: String,
    /// Severity.
    pub level: LogLevel,
    /// Message text (any UTF-8; pre-sanitised by the producer).
    pub message: String,
}

/// Terminal outcome of a plan run. Variant order and the `outcome` tag
/// values are the wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// The plan ran to its final milestone.
    Ok,
    /// Safety refusal before or during execution (PLAN §2 fail closed);
    /// `code` is the machine-readable `rufus_core::safety::Reason::code()`
    /// string of the refusing rule (e.g. `"mounted"`), short enough to
    /// key off in a GUI.
    Refused {
        /// Machine-readable reason, e.g. `"mounted"`.
        code: String,
        /// Human-readable explanation (pre-sanitised by the producer).
        message: String,
    },
    /// I/O or validation failure while executing.
    Failed {
        /// Machine-readable failure class, e.g. `"io"`.
        code: String,
        /// Human-readable explanation (pre-sanitised by the producer).
        message: String,
    },
    /// The user cancelled the run.
    Cancelled,
}

impl Outcome {
    /// Process exit code mirroring the CLI exit table
    /// (`Exit::Ok`/`Exit::Safety`/`Exit::Io`/`Exit::Cancelled` in
    /// `crates/rufus-cli/src/main.rs`): 0, 3, 4 and 6 respectively.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Ok => 0,
            // `Exit::Safety`.
            Self::Refused { .. } => 3,
            // `Exit::Io`.
            Self::Failed { .. } => 4,
            // `Exit::Cancelled`.
            Self::Cancelled => 6,
        }
    }
}

/// Terminal event of a run: the echoed stream version plus the final
/// [`Outcome`]. Field order (`session`, `version`, `outcome`) is the
/// canonical wire layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    /// Run identifier echoed from the plan request.
    pub session: String,
    /// Stream schema version at write time: [`EVENT_STREAM_VERSION`],
    /// not the plan version.
    pub version: u32,
    /// How the run ended.
    pub outcome: Outcome,
}

/// One JSONL event of the helper stream (see the module docs). Variant
/// order and the `kind` tags (`"progress"`, `"log"`, `"done"`) are the
/// wire contract; unknown `kind` values refuse to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Periodic progress of the current step.
    Progress(Progress),
    /// A log line for display.
    Log(LogLine),
    /// Terminal event: the run is over.
    Done(Completion),
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SESSION: &str = "s-1";

    #[test]
    fn progress_event_round_trips_and_pins_the_json_shape() {
        let event = Event::Progress(Progress::new(TEST_SESSION, 4, "write", 0, None));
        let line = serde_json::to_string(&event).expect("progress event serialises");

        let expected = concat!(
            r#"{"kind":"progress","session":"s-1","step":4,"op":"write","#,
            r#""done":0,"total":null,"percent":null}"#
        );
        // Declaration order is pinned by exact match.
        assert_eq!(line, expected);
        assert!(line.contains(r#""kind":"progress""#));
        assert!(line.contains(r#""total":null"#));
        assert!(line.contains(r#""percent":null"#));

        let back: Event = serde_json::from_str(&line).expect("progress event parses back");
        assert_eq!(back, event);
        assert_eq!(
            serde_json::from_str::<Progress>(
                r#"{ "session": "x", "step": 0,
                "op": "wipe", "done": 1, "total": 2, "percent": 50 }"#
            )
            .expect("payload parses on its own"),
            Progress::new("x", 0, "wipe", 1, Some(2))
        );
    }

    #[test]
    fn log_and_done_event_tags_are_pinned() {
        let log = Event::Log(LogLine {
            session: TEST_SESSION.to_string(),
            level: LogLevel::Warn,
            message: "label may not survive".to_string(),
        });
        let line = serde_json::to_string(&log).expect("log event serialises");
        assert_eq!(
            line,
            concat!(
                r#"{"kind":"log","session":"s-1","level":"warn","#,
                r#""message":"label may not survive"}"#
            )
        );
        assert_eq!(
            serde_json::from_str::<Event>(&line).expect("log event parses back"),
            log
        );

        let done = Event::Done(Completion {
            session: TEST_SESSION.to_string(),
            version: EVENT_STREAM_VERSION,
            outcome: Outcome::Cancelled,
        });
        let line = serde_json::to_string(&done).expect("done event serialises");
        assert!(line.starts_with(r#"{"kind":"done""#));
        assert!(line.contains(r#""version":1"#));
        assert_eq!(
            serde_json::from_str::<Event>(&line).expect("done event parses back"),
            done
        );

        // Unknown `kind`: fail closed, like unknown `Step` ops.
        assert!(serde_json::from_str::<Event>(r#"{"kind":"future"}"#).is_err());
    }

    #[test]
    fn outcome_tags_shapes_and_exit_codes_are_pinned() {
        let ok = serde_json::to_string(&Outcome::Ok).expect("ok serialises");
        assert_eq!(ok, r#"{"outcome":"ok"}"#);

        let refused = Outcome::Refused {
            code: "mounted".to_string(),
            message: "device is mounted".to_string(),
        };
        let refused_line = serde_json::to_string(&refused).expect("refused serialises");
        assert_eq!(
            refused_line,
            r#"{"outcome":"refused","code":"mounted","message":"device is mounted"}"#
        );

        let failed = serde_json::to_string(&Outcome::Failed {
            code: "write".to_string(),
            message: "lost".to_string(),
        })
        .expect("failed serialises");
        assert_eq!(
            failed,
            r#"{"outcome":"failed","code":"write","message":"lost"}"#
        );

        let cancelled = serde_json::to_string(&Outcome::Cancelled).expect("cancelled serialises");
        assert_eq!(cancelled, r#"{"outcome":"cancelled"}"#);

        // Tag shapes pick out the variant, payloads round-trip.
        assert!(
            refused_line.contains(r#""outcome":"refused""#)
                && refused_line.contains(r#""code":"mounted""#)
        );
        assert_eq!(
            serde_json::from_str::<Outcome>(&refused_line).expect("refused parses back"),
            refused
        );
        assert_eq!(
            serde_json::from_str::<Outcome>(&failed).expect("failed parses back"),
            Outcome::Failed {
                code: "write".to_string(),
                message: "lost".to_string()
            }
        );
        assert_eq!(
            serde_json::from_str::<Outcome>(&cancelled).expect("cancelled parses back"),
            Outcome::Cancelled
        );

        // The CLI exit table: `Exit::Ok`/`Safety`/`Io`/`Cancelled`.
        assert_eq!(Outcome::Ok.exit_code(), 0);
        assert_eq!(refused.exit_code(), 3);
        assert_eq!(
            Outcome::Failed {
                code: "write".to_string(),
                message: "lost".to_string()
            }
            .exit_code(),
            4
        );
        assert_eq!(Outcome::Cancelled.exit_code(), 6);
    }

    #[test]
    fn progress_percent_rules() {
        // The task table: half of 200 is 25.
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "wipe", 50, Some(200)).percent,
            Some(25)
        );
        // Indeterminate stays indeterminate (`percent` is `None` iff
        // `total` is).
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 1024, None).percent,
            None
        );
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 0, None).percent,
            None
        );
        // Zero-total step: vacuously complete (documented rule; the 0/0
        // case must not divide by zero).
        assert_eq!(
            Progress::new(TEST_SESSION, 6, "finalize", 0, Some(0)).percent,
            Some(100)
        );
        // Inconsistent producer (`done > total`) clamps to 100, two ways.
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 201, Some(200)).percent,
            Some(100)
        );
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 7, Some(0)).percent,
            Some(100)
        );
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", u64::MAX, Some(u64::MAX)).percent,
            Some(100)
        );
        // Exact scaling: saturating u64 math would wrongly yield 1 here.
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", u64::MAX / 2 + 1, Some(u64::MAX)).percent,
            Some(50)
        );
        // Bounds.
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 0, Some(1000)).percent,
            Some(0)
        );
        assert_eq!(
            Progress::new(TEST_SESSION, 0, "write", 1000, Some(1000)).percent,
            Some(100)
        );
    }

    #[test]
    fn log_level_parse_display_and_json_tag_agree() {
        for (level, tag) in [
            (LogLevel::Error, "error"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Info, "info"),
            (LogLevel::Debug, "debug"),
            (LogLevel::Trace, "trace"),
        ] {
            assert_eq!(level.to_string(), tag);
            assert_eq!(level.as_str(), tag);
            let wire = serde_json::to_string(&level).expect("level serialises");
            assert_eq!(wire, format!(r#""{tag}""#));
            assert_eq!(LogLevel::parse(tag), Some(level));
            assert_eq!(LogLevel::parse(&tag.to_ascii_uppercase()), Some(level));
        }
        // `warning` spelling, case-insensitively; anything else is None.
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("WARNing"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("bogus"), None);
        assert_eq!(LogLevel::parse(""), None);
        // The JSON wire only accepts the `"warn"` tag, not the spelling.
        assert_eq!(
            serde_json::from_str::<LogLevel>(r#""warn""#).expect("parsing works"),
            LogLevel::Warn
        );
        assert!(serde_json::from_str::<LogLevel>(r#""warning""#).is_err());
    }

    fn tiny_plan() -> crate::Plan {
        crate::Plan {
            version: crate::PLAN_VERSION,
            created_by: "test".to_string(),
            device: crate::DeviceRef {
                path: "/dev/sdz".to_string(),
                block_device: true,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: crate::ImageRef {
                path: "x.iso".to_string(),
                size_bytes: 1,
                sha256: "0".to_string(),
                kind: crate::ImageKind::Raw,
            },
            options: crate::Options {
                scheme: crate::Scheme::Mbr,
                target: crate::Target::Uefi,
                filesystem: crate::Filesystem::Fat32,
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
            steps: vec![crate::Step::Wipe],
            confirm: String::new(),
        }
    }

    #[test]
    fn plan_contract_is_untouched_by_the_event_module() {
        let plan = tiny_plan();
        let text = serde_json::to_string(&plan).expect("plan serialises");
        assert_eq!(
            serde_json::from_str::<crate::Plan>(&text).expect("plan parses"),
            plan
        );
        let obj: serde_json::Value = serde_json::from_str(&text).expect("plan is a JSON object");
        // The plan schema version and the stream schema version stay
        // distinct (plan schema at 6 since the windows mode bump,
        // stream at 1).
        assert_eq!(obj["version"], 6);
        assert_eq!(EVENT_STREAM_VERSION, 1);
        // No new top-level field may appear in the plan JSON.
        let mut keys: Vec<&str> = obj
            .as_object()
            .expect("plan is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "confirm",
                "created_by",
                "device",
                "image",
                "options",
                "steps",
                "version"
            ]
        );
    }

    #[test]
    fn completion_carries_the_stream_version_not_the_plan_version() {
        let done = Event::Done(Completion {
            session: TEST_SESSION.to_string(),
            version: EVENT_STREAM_VERSION,
            outcome: Outcome::Refused {
                code: "system_disk".to_string(),
                message: "refusing the system disk".to_string(),
            },
        });
        let line = serde_json::to_string(&done).expect("serialises");
        // The completion's `version` is the stream version, and the
        // nested outcome keeps its own `outcome` tag.
        assert_eq!(
            serde_json::from_str::<Event>(&line).expect("parses back"),
            done
        );
        assert!(
            !line.contains("PLAN"),
            "stream version must not be confused with the plan version"
        );
        assert!(line.contains(r#""version":1"#));
        assert!(line.contains(r#""outcome":{"outcome":"refused""#));
    }
}
