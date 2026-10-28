//! `rufus-core`: safe, non-privileged foundation of the rewrite.
//!
//! Slice S01 only: a version marker. Real modules (errors, log, config,
//! `i18n`, image readers, planner) arrive from S02 onwards.

#![forbid(unsafe_code)]

/// Crate version (workspace version, e.g. `"0.1.0"`).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pinned_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }
}
