//! [`version`], [`git_hash`] and [`user_agent`] (S02).
//!
//! `GIT_HASH` is baked in at compile time by `crates/rufus-core/build.rs`
//! (`git rev-parse --short HEAD`, `"unknown"` when git is unavailable).

/// Crate version (workspace version, e.g. `"0.1.0"`).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Short git hash of the build, or `"unknown"` when it could not be
/// determined (missing `.git`, git not installed, ...).
pub fn git_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// `rufus-linux/<version> (<hash>)`, e.g. for update-check HTTP requests.
pub fn user_agent() -> String {
    format!(
        "rufus-linux/{version} ({hash})",
        version = version(),
        hash = git_hash()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pinned_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }

    #[test]
    fn hash_and_agent_are_non_empty() {
        assert!(!git_hash().is_empty());
        let agent = user_agent();
        assert!(agent.starts_with("rufus-linux/0.1.0 ("), "{agent}");
        assert!(agent.ends_with(')'), "{agent}");
    }
}
