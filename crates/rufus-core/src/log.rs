//! [`Logger`]: a small in-memory log with an optional append-only file sink (S02).
//!
//! The GUI replays recent records via [`Logger::snapshot`] /
//! [`Logger::replay_from`]; the file sink receives one line per record:
//!
//! ```text
//! 2026-10-28T12:34:56Z [INFO ] target: message
//! ```
//!
//! Timestamps are formatted with an inline civil-from-days conversion — no
//! chrono/time dependency. Multi-line messages are preserved verbatim (the
//! continuation lines simply follow the header line).

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::error::CoreError;
use crate::error::Result;

/// Maximum records retained in memory; older records are evicted first.
pub const MAX_RECORDS: usize = 10_000;

/// Log severity, ordered from most to least severe.
///
/// A record is stored (and filed) when `record.level <= logger.level()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Failures.
    Error,
    /// Recoverable problems.
    Warn,
    /// Normal milestones.
    Info,
    /// Developer detail.
    Debug,
    /// Everything.
    Trace,
}

impl Level {
    /// Parse `"error"`, `"warn"`/`"warning"`, `"info"`, `"debug"`, `"trace"`
    /// (ASCII case-insensitive). Anything else returns `None`.
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

impl fmt::Display for Level {
    /// `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE` (matched with
    /// `{level:<5}` for the aligned file format).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        })
    }
}

/// One log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When the record was logged.
    pub timestamp: SystemTime,
    /// Severity at log time.
    pub level: Level,
    /// Component that logged (module or subsystem name).
    pub target: String,
    /// Message (may contain newlines; preserved verbatim).
    pub message: String,
}

#[derive(Debug)]
struct Inner {
    level: Level,
    records: VecDeque<Record>,
    file: Option<File>,
}

/// Shared log store. Create with [`Logger::new`], which returns an `Arc`.
#[derive(Debug)]
pub struct Logger {
    inner: Mutex<Inner>,
}

impl Logger {
    /// Create a logger recording records at or above `level`.
    pub fn new(level: Level) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                level,
                records: VecDeque::new(),
                file: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Current severity filter.
    pub fn level(&self) -> Level {
        self.lock().level
    }

    /// Change the severity filter. Records already stored are unaffected.
    pub fn set_level(&self, level: Level) {
        self.lock().level = level;
    }

    /// Record a message. Records above the current filter are dropped;
    /// failures of the optional file sink are ignored (logging must not
    /// fail the caller — use [`Logger::set_file`]'s `Result` for open
    /// errors).
    pub fn log(&self, level: Level, target: &str, message: &str) {
        let mut inner = self.lock();
        if level > inner.level {
            return;
        }
        let record = Record {
            timestamp: SystemTime::now(),
            level,
            target: target.to_string(),
            message: message.to_string(),
        };
        // The file line is only formatted when a sink exists; the in-memory
        // ring (the replay consumer) keeps the structured `Record`.
        let line = if inner.file.is_some() {
            Some(format_record(&record))
        } else {
            None
        };
        inner.records.push_back(record);
        if inner.records.len() > MAX_RECORDS {
            inner.records.pop_front();
        }
        if let (Some(file), Some(line)) = (inner.file.as_mut(), line) {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }

    /// Copy of every retained record, oldest first.
    pub fn snapshot(&self) -> Vec<Record> {
        self.lock().records.iter().cloned().collect()
    }

    /// Snapshot of records starting at `offset` (saturating: an offset past
    /// the end yields an empty vec). Offsets are positions in the current
    /// ring; callers tracking a cursor should rebase it with
    /// `snapshot().len()` after evictions.
    pub fn replay_from(&self, offset: usize) -> Vec<Record> {
        self.lock().records.iter().skip(offset).cloned().collect()
    }

    /// Drop all retained records. The file sink is unaffected.
    pub fn clear(&self) {
        self.lock().records.clear();
    }

    /// Attach (or replace) the append-only file sink, creating parents.
    /// The file is never truncated.
    pub fn set_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|err| CoreError::io(parent, err))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|err| CoreError::io(path, err))?;
        self.lock().file = Some(file);
        Ok(())
    }
}

/// Format `time` as `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds).
///
/// Implemented with Howard Hinnant's civil-from-days algorithm over
/// `days.div_euclid(86_400)` so pre-1970 timestamps wrap to the previous
/// day instead of panicking.
pub fn format_timestamp(time: SystemTime) -> String {
    let secs = match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        // Floor toward negative infinity: a sub-second part before the
        // epoch belongs to the previous whole second (`UNIX_EPOCH - 1ms`
        // is `1969-12-31T23:59:59Z`, not the epoch itself).
        Err(before) => {
            let ago = before.duration();
            match i64::try_from(ago.as_secs()) {
                Ok(whole) => {
                    if ago.subsec_nanos() == 0 {
                        whole.saturating_neg()
                    } else {
                        whole.saturating_neg().saturating_sub(1)
                    }
                }
                Err(_) => i64::MIN,
            }
        }
    };
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since 1970-01-01 → (year, month 1–12, day 1–31).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        (month_prime + 3) as u32
    } else {
        (month_prime - 9) as u32
    };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// One file-sink line for `record` (message preserved verbatim, including
/// any embedded newlines).
pub fn format_record(record: &Record) -> String {
    format!(
        "{} [{:<5}] {}: {}",
        format_timestamp(record.timestamp),
        record.level,
        record.target,
        record.message
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn epoch_formats_as_unix_origin() {
        assert_eq!(format_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamp_formats_exactly() {
        // 2026-10-28T12:34:56Z
        let time = UNIX_EPOCH + Duration::from_secs(1_793_190_896);
        assert_eq!(format_timestamp(time), "2026-10-28T12:34:56Z");
    }

    #[test]
    fn pre_epoch_does_not_panic_and_wraps() {
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_secs(1)),
            "1969-12-31T23:59:59Z"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_secs(86_400)),
            "1969-12-31T00:00:00Z"
        );
    }

    #[test]
    fn sub_second_before_epoch_floors_to_previous_second() {
        // Truncation would print the epoch itself; flooring prints the
        // previous second.
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_millis(1)),
            "1969-12-31T23:59:59Z"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_millis(1_000)),
            "1969-12-31T23:59:59Z"
        );
        assert_eq!(
            format_timestamp(UNIX_EPOCH - Duration::from_millis(1_500)),
            "1969-12-31T23:59:58Z"
        );
    }

    #[test]
    fn level_parse_and_display() {
        assert_eq!(Level::parse("error"), Some(Level::Error));
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("Info"), Some(Level::Info));
        assert_eq!(Level::parse("debug"), Some(Level::Debug));
        assert_eq!(Level::parse("TRACE"), Some(Level::Trace));
        assert_eq!(Level::parse("verbose"), None);
        assert_eq!(Level::parse(""), None);
        assert_eq!(format!("{}", Level::Info), "INFO");
        assert_eq!(format!("{:<5}", Level::Info), "INFO ");
        assert_eq!(format!("{:<5}", Level::Error), "ERROR");
    }

    #[test]
    fn level_filtering_drops_quiet_records() {
        let log = Logger::new(Level::Warn);
        log.log(Level::Info, "t", "dropped");
        log.log(Level::Warn, "t", "kept-warn");
        log.log(Level::Error, "t", "kept-error");
        let snapshot = log.snapshot();
        let messages: Vec<_> = snapshot.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(messages, ["kept-warn", "kept-error"]);

        log.set_level(Level::Info);
        log.log(Level::Info, "t", "kept-now");
        assert_eq!(log.snapshot().len(), 3);
        assert_eq!(log.level(), Level::Info);
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let log = Logger::new(Level::Trace);
        for index in 0..(MAX_RECORDS + 500) {
            log.log(Level::Info, "t", &format!("msg {index}"));
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), MAX_RECORDS);
        assert_eq!(snapshot.first().expect("non-empty").message, "msg 500");
        assert_eq!(
            snapshot.last().expect("non-empty").message,
            format!("msg {}", MAX_RECORDS + 499)
        );
        // Ordering is insertion order throughout.
        for pair in snapshot.windows(2) {
            let first: usize = pair[0].message["msg ".len()..].parse().expect("number");
            let second: usize = pair[1].message["msg ".len()..].parse().expect("number");
            assert_eq!(second, first + 1);
        }
    }

    #[test]
    fn replay_from_skips_prefix() {
        let log = Logger::new(Level::Trace);
        for index in 0..5 {
            log.log(Level::Info, "t", &format!("msg {index}"));
        }
        let replayed = log.replay_from(3);
        let messages: Vec<_> = replayed.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(messages, ["msg 3", "msg 4"]);
        assert!(log.replay_from(99).is_empty());

        log.clear();
        assert!(log.snapshot().is_empty());
    }

    #[test]
    fn file_sink_appends_formatted_lines() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.log");
        let log = Logger::new(Level::Trace);
        log.set_file(&path).expect("set file");
        log.log(Level::Info, "usb", "device arrived");
        log.log(Level::Error, "usb", "write failed");

        let content = std::fs::read_to_string(&path).expect("read log");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2, "{content}");
        assert!(
            lines[0].contains("[INFO ] usb: device arrived"),
            "{content}"
        );
        assert!(lines[1].contains("[ERROR] usb: write failed"), "{content}");

        // Appending continues in the same file.
        log.log(Level::Debug, "usb", "retrying");
        let content = std::fs::read_to_string(&path).expect("read log");
        assert_eq!(content.lines().count(), 3, "{content}");
    }

    #[test]
    fn multiline_messages_preserved() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.log");
        let log = Logger::new(Level::Trace);
        log.set_file(&path).expect("set file");
        log.log(Level::Info, "t", "first line\nsecond line");

        let stored = log.snapshot();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].message, "first line\nsecond line");

        let content = std::fs::read_to_string(&path).expect("read log");
        assert!(content.contains("first line\nsecond line"), "{content:?}");
    }

    #[test]
    fn record_line_matches_spec_format() {
        let record = Record {
            timestamp: UNIX_EPOCH + Duration::from_secs(1_793_190_896),
            level: Level::Info,
            target: "target".to_string(),
            message: "message".to_string(),
        };
        assert_eq!(
            format_record(&record),
            "2026-10-28T12:34:56Z [INFO ] target: message"
        );
    }
}
