//! [`CoreError`]: the single error type for `rufus-core` (S02).
//!
//! Every fallible `rufus-core` API returns [`Result`]. The variants carry the
//! context needed for a useful log line (which file, which catalog line,
//! which asset) and always keep the underlying source error via `#[source]`,
//! so a log message never loses an errno or a TOML span.

use std::io;
use std::path::Path;

use thiserror::Error;

/// Errors producible by `rufus-core`.
///
/// The `Display` strings are designed to be log-friendly: they name the
/// offending file, catalog line, or asset, and append the source error with
/// `: {source}` where one exists.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// Filesystem failure while reading or writing `path`.
    #[error("I/O error at '{path}': {source}")]
    Io {
        /// File the operation targeted.
        path: String,
        /// The underlying OS error (never discarded).
        #[source]
        source: io::Error,
    },
    /// A TOML config file failed to parse.
    #[error("failed to parse config '{path}': {source}")]
    ConfigParse {
        /// File that failed to parse.
        path: String,
        /// The TOML parser error (keeps line/column information).
        #[source]
        source: toml::de::Error,
    },
    /// A TOML config value failed to serialise.
    #[error("failed to serialise config '{path}': {source}")]
    ConfigWrite {
        /// File being written.
        path: String,
        /// The TOML serialiser error.
        #[source]
        source: toml::ser::Error,
    },
    /// A `.loc` locale catalog failed to parse.
    #[error("failed to parse locale catalog '{path}' at line {line}: {message}")]
    LocaleParse {
        /// Catalog file, or `"<memory>"` for
        /// [`Catalog::from_bytes`](crate::i18n::Catalog::from_bytes).
        path: String,
        /// 1-based line number of the offending input (`0` when the problem
        /// is not tied to a line, e.g. invalid UTF-8).
        line: u64,
        /// What was wrong.
        message: String,
    },
    /// A caller-supplied value is out of range or otherwise malformed.
    #[error("invalid input: {message}")]
    InvalidInput {
        /// What was wrong.
        message: String,
    },
    /// The run was cancelled, at a step boundary or inside a step. No
    /// source: cancellation carries no underlying failure, and the
    /// `Display` text names no step — [`run`](crate::pipeline::run)
    /// wraps it with the step that never ran or stopped early.
    #[error("the write was cancelled")]
    Cancelled,
    /// A planned step has no implementation yet. The `what` names it in
    /// plain words (it already names its own step, so unlike every
    /// other step error it is never wrapped in [`Step`](Self::Step)).
    #[error("not implemented yet: {what}")]
    NotImplemented {
        /// What is missing, e.g. `"bootloader installation (not wired yet)"`.
        what: &'static str,
    },
    /// Read-back verification failed: the bytes on the target do not
    /// match the plan digest. The message names the first differing
    /// byte offset when the loop could locate it cheaply, and always
    /// both digests. Like every in-run error except `NotImplemented`
    /// it is wrapped in [`Step`](Self::Step), so the step name still
    /// appears.
    #[error("image verification failed: {message}")]
    Verify {
        /// What differed: first differing offset plus expected and
        /// actual digests.
        message: String,
    },
    /// One pipeline step failed: the step name plus the underlying
    /// error, kept (not flattened) so exit mapping still sees an inner
    /// I/O failure through the wrapper.
    #[error("step '{step}': {source}")]
    Step {
        /// Snake-case step that failed.
        step: &'static str,
        /// The underlying step error (never discarded).
        #[source]
        source: Box<CoreError>,
    },
    /// No asset directory or asset file could be resolved.
    #[error("cannot resolve asset '{name}': {reason}")]
    AssetResolution {
        /// Asset that was looked up.
        name: String,
        /// Why resolution failed (searched locations, missing variable...).
        reason: String,
    },
}

/// `rufus-core` result type.
pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    /// Attach `path` context to an I/O error.
    ///
    /// There is deliberately no `From<io::Error>`: an I/O error without the
    /// file it belongs to is useless in a log.
    pub fn io(path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// Build an [`CoreError::InvalidInput`] from a message.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// Build an [`CoreError::AssetResolution`] from an asset name and reason.
    pub fn asset(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::AssetResolution {
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// Build an [`CoreError::LocaleParse`] for `path` at 1-based `line`.
    pub fn locale(path: impl AsRef<Path>, line: u64, message: impl Into<String>) -> Self {
        Self::LocaleParse {
            path: path.as_ref().display().to_string(),
            line,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn io_display_names_path_and_source() {
        let err = CoreError::io(
            "some/dir/rufus.toml",
            io::Error::new(io::ErrorKind::NotFound, "gone"),
        );
        let text = err.to_string();
        assert!(text.contains("some/dir/rufus.toml"), "{text}");
        assert!(text.contains("gone"), "{text}");
        assert!(err.source().is_some());
    }

    #[test]
    fn locale_display_names_path_line_and_message() {
        let err = CoreError::locale("r.loc", 12, "unterminated string");
        let text = err.to_string();
        assert!(text.contains("r.loc"), "{text}");
        assert!(text.contains("12"), "{text}");
        assert!(text.contains("unterminated string"), "{text}");
    }

    #[test]
    fn step_keeps_display_and_source() {
        let inner = CoreError::io("disk", io::Error::other("media error"));
        let err = CoreError::Step {
            step: "wipe",
            source: Box::new(inner),
        };
        let text = err.to_string();
        assert!(text.contains("step 'wipe'"), "{text}");
        assert!(text.contains("media error"), "{text}");
        assert!(err.source().is_some());
    }

    #[test]
    fn invalid_and_asset_have_no_source() {
        let invalid = CoreError::invalid("sector size is zero");
        assert!(invalid.to_string().contains("sector size is zero"));
        assert!(invalid.source().is_none());

        let asset = CoreError::asset("ldlinux.sys", "no assets dir");
        let text = asset.to_string();
        assert!(text.contains("ldlinux.sys"), "{text}");
        assert!(text.contains("no assets dir"), "{text}");
        assert!(asset.source().is_none());
    }

    #[test]
    fn config_errors_keep_source() {
        let bad: std::result::Result<toml::Value, _> = toml::from_str("[[[");
        let err = bad.expect_err("must fail");
        let wrapped = CoreError::ConfigParse {
            path: "c.toml".to_string(),
            source: err,
        };
        assert!(wrapped.to_string().contains("c.toml"));
        assert!(wrapped.source().is_some());
    }
}
