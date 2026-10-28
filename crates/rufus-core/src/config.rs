//! [`Config`]: TOML settings with atomic save and corrupt-file recovery (S02).
//!
//! Layout follows decision A10: the file lives at
//! [`default_config_path`](crate::paths::default_config_path), i.e. portable
//! `./rufus.toml` when present, otherwise
//! `<config_dir>/rufus-linux/rufus.toml`. Unknown TOML keys are ignored so
//! newer files stay readable (forward compatibility); unknown
//! [`UpdateChannel`] values fall back to the default instead of failing.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;

use crate::error::CoreError;
use crate::error::Result;

/// File name used for portable mode and inside the config directory.
pub const CONFIG_FILE_NAME: &str = "rufus.toml";

/// Counter distinguishing concurrent [`Config::save`] temp files.
static SAVE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Update channel: stable releases, or betas as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Stable releases only.
    #[default]
    Stable,
    /// Include beta releases.
    Beta,
}

impl<'de> Deserialize<'de> for UpdateChannel {
    /// Lenient parse: `"beta"` (any ASCII case) selects beta; anything else
    /// — unknown strings, wrong TOML types — falls back to [`UpdateChannel::Stable`]
    /// so a hand-edited or newer config can never fail to load.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = toml::Value::deserialize(deserializer)?;
        Ok(match &value {
            toml::Value::String(text) if text.eq_ignore_ascii_case("beta") => Self::Beta,
            _ => Self::Stable,
        })
    }
}

/// Window geometry persisted across runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowConfig {
    /// Window width in logical pixels.
    pub width: u32,
    /// Window height in logical pixels.
    pub height: u32,
    /// Window x position (platform dependent).
    pub x: i32,
    /// Window y position (platform dependent).
    pub y: i32,
    /// Whether the window was maximized.
    pub maximized: bool,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 480,
            x: 0,
            y: 0,
            maximized: false,
        }
    }
}

/// Advanced (format-time) toggles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedConfig {
    /// Verify blocks after writing.
    pub verify: bool,
    /// Check the device for bad blocks.
    pub badblocks: bool,
    /// Quick format (unchecked by default in Rufus terms: full format off).
    #[serde(default = "default_true")]
    pub quick_format: bool,
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            verify: false,
            badblocks: false,
            quick_format: true,
        }
    }
}

fn default_true() -> bool {
    true
}

/// User configuration (serde/TOML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Preferred locale tag (e.g. `"de-DE"`), `None` for system default.
    pub locale: Option<String>,
    /// List internal (non-removable) devices too.
    pub show_all: bool,
    /// Whether the update check may run (network only on explicit action).
    pub check_updates: bool,
    /// Stable or beta update channel.
    pub update_channel: UpdateChannel,
    /// Last successfully used device path (informational).
    pub last_device: Option<String>,
    /// Device paths the user hid from the device list.
    pub ignore_devices: Vec<String>,
    /// Persisted window geometry.
    pub window: WindowConfig,
    /// Format-time toggles.
    pub advanced: AdvancedConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            locale: None,
            show_all: false,
            check_updates: true,
            update_channel: UpdateChannel::Stable,
            last_device: None,
            ignore_devices: Vec::new(),
            window: WindowConfig::default(),
            advanced: AdvancedConfig::default(),
        }
    }
}

/// Result of [`Config::load`]: the effective config plus an optional warning
/// (set when a corrupt file was moved aside and defaults were used).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// Effective configuration (file content, or defaults).
    pub config: Config,
    /// Human-readable warning when defaults were substituted.
    pub warning: Option<String>,
}

/// Counter distinguishing concurrent corrupt-file backups.
static BACKUP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `<name>.bad-<unix_secs>-<pid>-<n>` next to `path`.
///
/// `unix_secs` uses `0` when the clock is before the epoch rather than
/// failing. The pid plus per-process counter keep two corrupt loads in the
/// same second from sharing a name; a final existence loop covers the
/// (near-impossible) case of a stale file with the same generated name, so
/// no backup is ever overwritten.
fn backup_path(path: &Path) -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| CONFIG_FILE_NAME.to_string());
    let pid = std::process::id();
    loop {
        let tag = BACKUP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let backup_name = format!("{file_name}.bad-{secs}-{pid}-{tag}");
        let candidate = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join(backup_name),
            _ => PathBuf::from(backup_name),
        };
        if !candidate.exists() {
            return candidate;
        }
    }
}

/// Wrap a temp-file I/O failure so the reported [`CoreError`] names the
/// config `path` while the temp path stays in the source chain.
fn tmp_io_error(tmp: &Path, err: std::io::Error) -> std::io::Error {
    let kind = err.kind();
    std::io::Error::new(kind, format!("temp file '{}': {err}", tmp.display()))
}

impl Config {
    /// Load the config file.
    ///
    /// * Missing file → defaults, no error, no warning.
    /// * Invalid TOML → the bad file is renamed to
    ///   `<name>.bad-<unix_secs>-<pid>-<n>` and defaults are returned with
    ///   [`LoadedConfig::warning`] set.
    pub fn load(path: &Path) -> Result<LoadedConfig> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedConfig {
                    config: Config::default(),
                    warning: None,
                });
            }
            Err(err) => return Err(CoreError::io(path, err)),
        };
        match toml::from_str::<Config>(&text) {
            Ok(config) => Ok(LoadedConfig {
                config,
                warning: None,
            }),
            Err(parse_err) => {
                let backup = backup_path(path);
                if let Err(rename_err) = fs::rename(path, &backup) {
                    return Err(CoreError::invalid(format!(
                        "config '{}' is corrupt ({parse_err}); backup to '{}' failed: {rename_err}",
                        path.display(),
                        backup.display()
                    )));
                }
                Ok(LoadedConfig {
                    config: Config::default(),
                    warning: Some(format!(
                        "ignored corrupt config '{}': {parse_err}; moved to '{}'",
                        path.display(),
                        backup.display()
                    )),
                })
            }
        }
    }

    /// Save atomically: create parents, write a temp file in the same
    /// directory, `fsync` it, then rename over the target. A crash can leave
    /// the temp file behind but never a partial config.
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
        if let Some(dir) = parent {
            fs::create_dir_all(dir).map_err(|err| CoreError::io(dir, err))?;
        }
        let text = toml::to_string_pretty(self).map_err(|err| CoreError::ConfigWrite {
            path: path.display().to_string(),
            source: err,
        })?;

        let dir = parent.map_or_else(|| Path::new("."), |dir| dir);
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| CONFIG_FILE_NAME.to_string());
        let tag = SAVE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{file_name}.tmp-{}-{tag}", std::process::id()));

        let write_result = (|| {
            let mut file = fs::File::create(&tmp)
                .map_err(|err| CoreError::io(path, tmp_io_error(&tmp, err)))?;
            file.write_all(text.as_bytes())
                .map_err(|err| CoreError::io(path, tmp_io_error(&tmp, err)))?;
            file.sync_all()
                .map_err(|err| CoreError::io(path, tmp_io_error(&tmp, err)))?;
            drop(file);
            fs::rename(&tmp, path).map_err(|err| CoreError::io(path, err))?;
            Ok::<(), CoreError>(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp);
        } else if let Ok(dir_file) = fs::File::open(dir) {
            // Best effort: make the rename itself durable.
            let _ = dir_file.sync_all();
        }
        write_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Config {
        Config {
            locale: Some("de-DE".to_string()),
            show_all: true,
            check_updates: false,
            update_channel: UpdateChannel::Beta,
            last_device: Some("/dev/sdb".to_string()),
            ignore_devices: vec!["/dev/sda".to_string()],
            window: WindowConfig {
                width: 800,
                height: 600,
                x: 10,
                y: 20,
                maximized: true,
            },
            advanced: AdvancedConfig {
                verify: true,
                badblocks: true,
                quick_format: false,
            },
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.toml");
        let want = example();
        want.save(&path).expect("save");
        let loaded = Config::load(&path).expect("load");
        assert_eq!(loaded.config, want);
        assert_eq!(loaded.warning, None);
    }

    #[test]
    fn missing_file_gives_defaults() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let loaded = Config::load(&scratch.path().join("nope.toml")).expect("load");
        assert_eq!(loaded.config, Config::default());
        assert_eq!(loaded.warning, None);
    }

    #[test]
    fn corrupt_file_is_moved_aside() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.toml");
        std::fs::write(&path, "[[[ this is not toml\n").expect("seed corrupt file");

        let loaded = Config::load(&path).expect("load");
        assert_eq!(loaded.config, Config::default());
        let warning = loaded.warning.expect("warning recorded");
        assert!(warning.contains("corrupt"), "{warning}");

        // Original is gone; exactly one `.bad-*` backup remains.
        assert!(!path.exists());
        let backups: Vec<_> = std::fs::read_dir(scratch.path())
            .expect("list dir")
            .map(|entry| entry.expect("dir entry").file_name())
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        let backup = backups.into_iter().next().expect("one backup");
        let backup = backup.to_string_lossy();
        assert!(backup.starts_with("rufus.toml.bad-"), "{backup}");
    }

    #[test]
    fn two_corrupt_loads_leave_two_distinct_backups() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.toml");
        for _ in 0..2 {
            std::fs::write(&path, "[[[ this is not toml\n").expect("seed corrupt file");
            let loaded = Config::load(&path).expect("load");
            assert!(loaded.warning.is_some());
        }

        // Original is gone; two distinct `.bad-*` backups remain.
        assert!(!path.exists());
        let mut backups: Vec<_> = std::fs::read_dir(scratch.path())
            .expect("list dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        backups.sort();
        assert_eq!(backups.len(), 2, "{backups:?}");
        assert_ne!(backups[0], backups[1], "{backups:?}");
        for backup in &backups {
            assert!(backup.starts_with("rufus.toml.bad-"), "{backup}");
        }
    }

    #[test]
    fn save_io_failure_names_config_path() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let dir = scratch.path().join("ro");
        std::fs::create_dir(&dir).expect("seed dir");
        set_read_only(&dir, true);

        let path = dir.join("rufus.toml");
        let err = example().save(&path).expect_err("save must fail");
        let text = err.to_string();
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(text.contains("temp file"), "{text}");

        // Restore write access so the scratch dir cleans up.
        set_read_only(&dir, false);
    }

    #[cfg(unix)]
    fn set_read_only(dir: &std::path::Path, read_only: bool) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if read_only { 0o555 } else { 0o755 };
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).expect("chmod dir");
    }

    #[cfg(not(unix))]
    fn set_read_only(dir: &std::path::Path, read_only: bool) {
        let mut perms = std::fs::metadata(dir).expect("stat dir").permissions();
        perms.set_readonly(read_only);
        std::fs::set_permissions(dir, perms).expect("chmod dir");
    }

    #[test]
    fn empty_file_loads_defaults() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.toml");
        std::fs::write(&path, "").expect("seed empty file");
        let loaded = Config::load(&path).expect("load");
        assert_eq!(loaded.config, Config::default());
        assert_eq!(loaded.warning, None);
        // Not treated as corrupt: no backup was created.
        assert!(path.is_file());
    }

    #[test]
    fn unknown_fields_and_channel_fall_back() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("rufus.toml");
        std::fs::write(
            &path,
            "show_all = true\nfuture_option = 42\nupdate_channel = \"nightly\"\n",
        )
        .expect("seed file");
        let loaded = Config::load(&path).expect("load");
        assert!(loaded.config.show_all);
        assert_eq!(loaded.config.update_channel, UpdateChannel::Stable);
        assert_eq!(loaded.warning, None);
    }

    #[test]
    fn beta_channel_survives_case_variants() {
        for channel in ["beta", "Beta", "BETA"] {
            let config: Config =
                toml::from_str(&format!("update_channel = \"{channel}\"\n")).expect("parse");
            assert_eq!(config.update_channel, UpdateChannel::Beta);
        }
        let config: Config = toml::from_str("update_channel = 7\n").expect("parse");
        assert_eq!(config.update_channel, UpdateChannel::Stable);
    }

    #[test]
    fn atomic_save_overwrites_cleanly() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("nested/dir/rufus.toml");
        example().save(&path).expect("first save");
        let mut second = example();
        second.show_all = false;
        second.save(&path).expect("second save");

        let loaded = Config::load(&path).expect("load");
        assert_eq!(loaded.config, second);

        // No temp files leak into the directory.
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(scratch.path().join("nested/dir")).expect("list") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy().into_owned();
            if name.starts_with('.') {
                leftovers.push(name);
            }
        }
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
