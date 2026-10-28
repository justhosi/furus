//! `rufus-core`: safe, non-privileged foundation of the rewrite.
//!
//! Slice S02 (core runtime) delivers the pieces every later slice builds
//! on — error handling, logging, configuration, paths, localisation,
//! checked arithmetic and version reporting:
//!
//! * [`error`] — [`CoreError`](error::CoreError), the single error type
//!   (I/O with path, config/serialise failures, `.loc` parse errors,
//!   invalid input, asset resolution). [`Result`](error::Result) is the
//!   crate-wide result alias.
//! * [`log`] — [`Logger`](log::Logger): an `Arc`-shared in-memory ring
//!   (10,000 records) with level filtering and an optional append-only
//!   file sink; UTC timestamps without a date/time dependency.
//! * [`config`] — [`Config`](config::Config): serde/TOML settings with
//!   forward-compatible parsing, atomic save, and corrupt-file recovery
//!   ([`LoadedConfig`](config::LoadedConfig)).
//! * [`paths`] — XDG directories without the `dirs` crate, asset-dir
//!   resolution (`$RUFUS_ASSETS`, AppImage `$APPDIR`, FHS install), and
//!   portable-mode (`./rufus.toml`) discovery.
//! * [`i18n`] — [`Catalog`](i18n::Catalog): the Rufus `.loc`
//!   (pollock-format) catalog, memory-mapped from disk, with locale
//!   normalisation, an English fallback chain and a [`Translator`](i18n::Translator).
//! * [`units`] — checked sector math, human-readable sizes, durations.
//! * [`version`] — crate version, compile-time git hash, user-agent string.
//!
//! The crate is dependency-light by design (serde, toml, thiserror,
//! memmap2, plus tempfile for tests): no async runtime, no logging
//! framework, no regex — see PLAN.md §5.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod i18n;
pub mod log;
pub mod paths;
pub mod units;
pub mod version;

pub use config::AdvancedConfig;
pub use config::Config;
pub use config::LoadedConfig;
pub use config::UpdateChannel;
pub use config::WindowConfig;
pub use error::CoreError;
pub use error::Result;
pub use i18n::Catalog;
pub use i18n::Translator;
pub use log::Level;
pub use log::Logger;
pub use log::Record;
pub use paths::asset_path;
pub use paths::assets_dir;
pub use paths::cache_dir;
pub use paths::config_dir;
pub use paths::default_config_path;
pub use paths::portable_config_path;
pub use paths::state_dir;
pub use units::bytes_to_sectors_ceil;
pub use units::format_duration;
pub use units::human_bytes;
pub use units::sectors_to_bytes;
pub use version::git_hash;
pub use version::user_agent;
pub use version::version;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pinned_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }
}
