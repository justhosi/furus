//! [`WimlibError`]: the error type for the safe `wimlib-sys` facade.
//!
//! The raw FFI in [`crate::ffi`] reports failures as integer codes; this
//! type turns them into values Rust callers can match on. It exists in
//! both build configurations (linked and unlinked) so dependents compile
//! unchanged either way: when `libwim` is absent every operation fails
//! with [`WimlibError::NotLinked`] instead.
//!
//! Messages are plain ASCII by construction (the code path carries the
//! integer; the text comes from `wimlib_get_error_string` at construction
//! time, falling back to a fixed string when the library hands back null).

use std::fmt;

/// Failures of the safe wimlib facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WimlibError {
    /// `libwim` is not linked into this build: the `wimlib_present`
    /// gate is off, so there is no library to call. Every facade
    /// operation returns this without invoking any callback.
    NotLinked,
    /// A path could not be handed to wimlib: on Linux
    /// `wimlib_tchar` is `char` (UTF-8 bytes), so a path with an
    /// interior NUL byte has no C representation.
    InvalidPath {
        /// The offending path, lossy ASCII (`?` for anything outside
        /// printable ASCII, so the message stays log-safe).
        path: String,
    },
    /// wimlib reported an integer failure code. The message was read
    /// from `wimlib_get_error_string` when the error was built (or
    /// `"unknown wimlib error"` when the library returned null), so
    /// carrying the error across threads needs no library access.
    Code {
        /// The `wimlib_error_code` value (an `int` in C).
        code: i32,
        /// Human-readable description of `code`.
        message: String,
    },
}

impl WimlibError {
    /// The wimlib failure code, if this error carries one.
    pub fn code(&self) -> Option<i32> {
        match self {
            Self::Code { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl fmt::Display for WimlibError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => write!(formatter, "wimlib is not linked into this build"),
            Self::InvalidPath { path } => write!(
                formatter,
                "invalid wim path '{path}': paths with interior NUL bytes cannot reach wimlib"
            ),
            Self::Code { code, message } => {
                write!(formatter, "wimlib error {code}: {message}")
            }
        }
    }
}

impl std::error::Error for WimlibError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_texts_are_ascii_and_stable() {
        let texts = [
            WimlibError::NotLinked.to_string(),
            WimlibError::InvalidPath {
                path: "a.wim".to_string(),
            }
            .to_string(),
            WimlibError::Code {
                code: 76,
                message: "aborted".to_string(),
            }
            .to_string(),
        ];
        assert_eq!(
            texts[0], "wimlib is not linked into this build",
            "{texts:?}"
        );
        assert!(texts[1].contains("a.wim"), "{texts:?}");
        assert_eq!(texts[2], "wimlib error 76: aborted", "{texts:?}");
        for text in &texts {
            assert!(text.is_ascii(), "{text:?}");
        }
    }

    #[test]
    fn code_accessor_only_fires_on_code() {
        assert_eq!(WimlibError::NotLinked.code(), None);
        assert_eq!(
            WimlibError::InvalidPath {
                path: String::new(),
            }
            .code(),
            None
        );
        assert_eq!(
            WimlibError::Code {
                code: 43,
                message: String::new(),
            }
            .code(),
            Some(43)
        );
    }
}
