//! `config_bridge`: GUI-owned preferences over one core-owned TOML config
//! (slice 7/7).
//!
//! This is a thin wrapper around [`rufus_core::config::Config`]. All parsing,
//! atomic save and corrupt-file recovery stay in `rufus-core`; this module
//! only exposes the GUI-owned fields and never parses TOML itself. Loading
//! never writes: a missing file stays missing and a corrupt file follows
//! core's backup policy (the original is moved aside, not overwritten).
//!
//! The active locale tag reuses `Config::locale`; the four hash-display
//! toggles and the advanced-section visibility live in `Config::gui` (the
//! `[gui]` table). No update-check or other network behaviour is touched.

use std::path::Path;
use std::path::PathBuf;

use rufus_core::config::Config;
use rufus_core::config::LoadedConfig;
use rufus_core::error::Result;

/// GUI preferences plus the path they were loaded from and saved to.
pub struct GuiPrefs {
    path: PathBuf,
    config: Config,
}

impl GuiPrefs {
    /// Build defaults tied to `path` without touching the filesystem.
    ///
    /// Used by headless tests and by a `Session` created before startup
    /// loading; production startup replaces it with [`GuiPrefs::load`].
    pub fn defaults(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            config: Config::default(),
        }
    }

    /// Load preferences from `path`, returning any warning from core's
    /// corrupt-file recovery. No file is created or modified on load.
    pub fn load(path: impl Into<PathBuf>) -> Result<(Self, Option<String>)> {
        let path = path.into();
        let LoadedConfig { config, warning } = Config::load(&path)?;
        Ok((Self { path, config }, warning))
    }

    /// Save atomically through `Config::save`, preserving every unrelated
    /// field that was loaded from the same file.
    pub fn save(&self) -> Result<()> {
        self.config.save(&self.path)
    }

    /// Config file this wrapper reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read-only view of the whole config (for tests asserting that
    /// unrelated fields survived a GUI-pref save).
    pub fn config(&self) -> &Config {
        &self.config
    }

    // ---- locale (single owner: top-level Config::locale) ----

    pub fn locale(&self) -> Option<&str> {
        self.config.locale.as_deref()
    }

    pub fn set_locale(&mut self, tag: Option<String>) {
        self.config.locale = tag;
    }

    // ---- hash-display toggles (Config::gui) ----

    pub fn hash_md5(&self) -> bool {
        self.config.gui.hash_md5
    }

    pub fn set_hash_md5(&mut self, value: bool) {
        self.config.gui.hash_md5 = value;
    }

    pub fn hash_sha1(&self) -> bool {
        self.config.gui.hash_sha1
    }

    pub fn set_hash_sha1(&mut self, value: bool) {
        self.config.gui.hash_sha1 = value;
    }

    pub fn hash_sha256(&self) -> bool {
        self.config.gui.hash_sha256
    }

    pub fn set_hash_sha256(&mut self, value: bool) {
        self.config.gui.hash_sha256 = value;
    }

    pub fn hash_sha512(&self) -> bool {
        self.config.gui.hash_sha512
    }

    pub fn set_hash_sha512(&mut self, value: bool) {
        self.config.gui.hash_sha512 = value;
    }

    // ---- advanced-options visibility (Config::gui) ----

    pub fn advanced_visible(&self) -> bool {
        self.config.gui.advanced_visible
    }

    pub fn set_advanced_visible(&mut self, value: bool) {
        self.config.gui.advanced_visible = value;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use rufus_core::config::AdvancedConfig;
    use rufus_core::config::GuiConfig;
    use rufus_core::config::UpdateChannel;
    use rufus_core::config::WindowConfig;

    use super::*;

    static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

    /// Unique temp directory with unconditional cleanup, so tests never
    /// leave config files (or `.bad-*` backups) behind.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let serial = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rufus-gui-prefs-{tag}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create scratch dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn gui_prefs_round_trip_atomically_and_preserve_unrelated_fields() {
        let scratch = Scratch::new("roundtrip");
        let path = scratch.path().join("rufus.toml");

        let seed = Config {
            locale: Some("de-DE".to_string()),
            show_all: true,
            update_channel: UpdateChannel::Beta,
            ignore_devices: vec!["/dev/sda".to_string()],
            window: WindowConfig {
                width: 1024,
                ..Default::default()
            },
            advanced: AdvancedConfig {
                verify: true,
                ..Default::default()
            },
            ..Default::default()
        };
        seed.save(&path).expect("seed config");

        let (mut prefs, warning) = GuiPrefs::load(&path).expect("load");
        assert_eq!(warning, None);
        assert_eq!(prefs.locale(), Some("de-DE"));
        assert_eq!(prefs.path(), path);

        // Mutate only GUI-owned prefs.
        prefs.set_locale(Some("fr-FR".to_string()));
        prefs.set_hash_md5(false);
        prefs.set_hash_sha512(false);
        prefs.set_advanced_visible(true);
        prefs.save().expect("save gui prefs");

        let reloaded = Config::load(&path).expect("reload").config;
        assert_eq!(reloaded.locale.as_deref(), Some("fr-FR"));
        assert!(!reloaded.gui.hash_md5);
        assert!(!reloaded.gui.hash_sha512);
        assert!(reloaded.gui.hash_sha256, "untouched toggle stays default");
        assert!(reloaded.gui.advanced_visible);

        // Unrelated fields survived the GUI-only save.
        assert!(reloaded.show_all);
        assert_eq!(reloaded.update_channel, UpdateChannel::Beta);
        assert_eq!(reloaded.ignore_devices, vec!["/dev/sda".to_string()]);
        assert_eq!(reloaded.window.width, 1024);
        assert!(reloaded.advanced.verify);

        // No atomic-save temp files leaked into the directory.
        let leftovers: Vec<_> = fs::read_dir(scratch.path())
            .expect("list dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn missing_or_corrupt_config_yields_defaults_without_destructive_write() {
        // Missing file: no file is created and defaults are returned.
        let missing = Scratch::new("missing");
        let path = missing.path().join("absent.toml");
        let (prefs, warning) = GuiPrefs::load(&path).expect("load missing");
        assert_eq!(warning, None);
        assert!(!path.exists(), "load must not create the config");
        assert_eq!(prefs.config(), &Config::default());
        assert_eq!(prefs.config().gui, GuiConfig::default());

        // Corrupt file: core moves it aside; GUI prefs are defaults and the
        // original path is never overwritten with a fresh config.
        let corrupt = Scratch::new("corrupt");
        let path = corrupt.path().join("rufus.toml");
        fs::write(&path, "[[[ not valid toml\n").expect("seed corrupt file");
        let (prefs, warning) = GuiPrefs::load(&path).expect("load corrupt");
        let warning = warning.expect("corrupt file warning");
        assert!(warning.contains("corrupt"), "{warning}");
        assert!(
            !path.exists(),
            "the corrupt file was moved aside, not overwritten"
        );
        assert_eq!(prefs.config(), &Config::default());
        assert_eq!(prefs.config().gui, GuiConfig::default());

        let backups: Vec<_> = fs::read_dir(corrupt.path())
            .expect("list dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with("rufus.toml.bad-"))
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
    }
}
