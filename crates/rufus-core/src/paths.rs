//! [`config_dir`], [`state_dir`], [`cache_dir`], [`assets_dir`] and portable-mode
//! discovery (S02).
//!
//! Directory layout follows decision A10: configuration lives under
//! `$XDG_CONFIG_HOME/rufus-linux` (portable mode: `./rufus.toml` next to the
//! current directory), runtime state under `$XDG_STATE_HOME/rufus-linux`
//! (the GUI log file goes there), and caches under
//! `$XDG_CACHE_HOME/rufus-linux`. No `dirs` crate is used; the three lookups
//! below are the whole implementation.
//!
//! [`assets_dir`] preference order:
//!
//! 1. `$RUFUS_ASSETS` (developer override / tests),
//! 2. `$APPDIR/usr/share/rufus-linux/assets` (AppImage),
//! 3. `<exe_dir>/../share/rufus-linux/assets` (FHS install: the binary lives
//!    in `<prefix>/bin`, assets in `<prefix>/share/rufus-linux/assets`).
//!
//! The returned directory is the *preferred* candidate; callers check for
//! existence (see [`asset_path`]) so unit tests stay filesystem-free.

use std::env;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use crate::error::CoreError;
use crate::error::Result;

/// Application directory name appended to each XDG base.
const APP_DIR: &str = "rufus-linux";
/// File name that enables portable mode when present in the cwd.
const PORTABLE_FILE_NAME: &str = "rufus.toml";
/// Asset tree inside an AppImage (`$APPDIR` is the AppImage mount root).
const APPDIR_ASSETS_SUFFIX: &str = "usr/share/rufus-linux/assets";
/// Asset tree relative to the executable directory (`<prefix>/bin`).
const EXE_RELATIVE_ASSETS_SUFFIX: &str = "../share/rufus-linux/assets";

/// Resolved process-environment inputs for directory lookup.
///
/// All direct `std::env` access in this module happens in [`Env::live`];
/// every public function below is a thin wrapper over a pure method on
/// `Env`, so unit tests can inject an [`Env::for_tests`] value and never
/// touch the real environment.
#[derive(Debug, Clone)]
struct Env {
    xdg_config_home: Option<String>,
    xdg_state_home: Option<String>,
    xdg_cache_home: Option<String>,
    home: Option<String>,
    rufus_assets: Option<String>,
    appdir: Option<String>,
    exe_dir: Option<PathBuf>,
    cwd: Option<PathBuf>,
}

impl Env {
    /// Read the live process environment.
    ///
    /// This is the only function in this module allowed to call
    /// `std::env`. Empty variables are treated as unset, per the XDG
    /// specification.
    fn live() -> Self {
        fn var(name: &str) -> Option<String> {
            env::var(name).ok().filter(|value| !value.is_empty())
        }

        Self {
            xdg_config_home: var("XDG_CONFIG_HOME"),
            xdg_state_home: var("XDG_STATE_HOME"),
            xdg_cache_home: var("XDG_CACHE_HOME"),
            home: var("HOME"),
            rufus_assets: var("RUFUS_ASSETS"),
            appdir: var("APPDIR"),
            exe_dir: env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(Path::to_path_buf)),
            cwd: env::current_dir().ok(),
        }
    }

    /// Fixed environment for unit tests.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn for_tests(
        xdg_config_home: Option<&str>,
        xdg_state_home: Option<&str>,
        xdg_cache_home: Option<&str>,
        home: Option<&str>,
        rufus_assets: Option<&str>,
        appdir: Option<&str>,
        exe_dir: Option<&Path>,
        cwd: Option<&Path>,
    ) -> Self {
        Self {
            xdg_config_home: xdg_config_home.map(str::to_string),
            xdg_state_home: xdg_state_home.map(str::to_string),
            xdg_cache_home: xdg_cache_home.map(str::to_string),
            home: home.map(str::to_string),
            rufus_assets: rufus_assets.map(str::to_string),
            appdir: appdir.map(str::to_string),
            exe_dir: exe_dir.map(Path::to_path_buf),
            cwd: cwd.map(Path::to_path_buf),
        }
    }

    /// `$HOME`, or — when `HOME` is unset (minimal containers) — the
    /// current directory rather than an invented `~` path.
    fn home_base(&self) -> PathBuf {
        if let Some(home) = &self.home {
            return PathBuf::from(home);
        }
        self.cwd.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    fn config_dir(&self) -> PathBuf {
        if let Some(base) = &self.xdg_config_home {
            return Path::new(base).join(APP_DIR);
        }
        self.home_base().join(".config").join(APP_DIR)
    }

    fn state_dir(&self) -> PathBuf {
        if let Some(base) = &self.xdg_state_home {
            return Path::new(base).join(APP_DIR);
        }
        self.home_base().join(".local").join("state").join(APP_DIR)
    }

    fn cache_dir(&self) -> PathBuf {
        if let Some(base) = &self.xdg_cache_home {
            return Path::new(base).join(APP_DIR);
        }
        self.home_base().join(".cache").join(APP_DIR)
    }

    /// Preferred asset directory, or `None` when no candidate is known.
    ///
    /// Pure preference order (no existence check): `$RUFUS_ASSETS`, then
    /// `$APPDIR/usr/share/rufus-linux/assets`, then
    /// `<exe_dir>/../share/rufus-linux/assets`.
    fn assets_dir(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.rufus_assets {
            return Some(PathBuf::from(dir));
        }
        if let Some(appdir) = &self.appdir {
            return Some(Path::new(appdir).join(APPDIR_ASSETS_SUFFIX));
        }
        self.exe_dir
            .as_ref()
            .map(|exe| exe.join(EXE_RELATIVE_ASSETS_SUFFIX))
    }

    /// `./rufus.toml` when it exists in the current directory.
    ///
    /// The existence check runs against the injected `cwd`, so tests point
    /// it at a `tempfile` scratch directory.
    fn portable_config_path(&self) -> Option<PathBuf> {
        let cwd = self.cwd.as_ref()?;
        let candidate = cwd.join(PORTABLE_FILE_NAME);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    }

    fn default_config_path(&self) -> PathBuf {
        if let Some(portable) = self.portable_config_path() {
            return portable;
        }
        self.config_dir().join(PORTABLE_FILE_NAME)
    }

    fn asset_path(&self, name: &str) -> Result<PathBuf> {
        validate_asset_name(name)?;
        let dir = self.assets_dir().ok_or_else(|| {
            CoreError::asset(
                name,
                "no asset directory candidate ($RUFUS_ASSETS, $APPDIR and executable path are all unset)",
            )
        })?;
        let candidate = dir.join(name);
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(CoreError::asset(
                name,
                format!("not found under '{}'", dir.display()),
            ))
        }
    }
}

/// Fail closed unless `name` is exactly one [`Component::Normal`].
///
/// String checks alone (`contains("..")` and friends) miss separator and
/// encoding edge cases, so the component walk is the authority. The extra
/// `/`/`\` scan additionally rejects trailing slashes (`"ok.bin/"` walks
/// as a single `Normal`) and Windows separators on Unix, where `\` would
/// otherwise be a legal (but never legitimate for assets) file character.
fn validate_asset_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::asset(
            name,
            "invalid asset name: must be a single file name",
        ));
    }
    if name.contains('\0') {
        return Err(CoreError::asset(
            name,
            "invalid asset name: must be a single file name",
        ));
    }
    let mut components = Path::new(name).components();
    let confined = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    );
    if !confined || name.contains('/') || name.contains('\\') {
        return Err(CoreError::asset(
            name,
            "invalid asset name: must be a single file name",
        ));
    }
    Ok(())
}

/// User configuration directory: `$XDG_CONFIG_HOME/rufus-linux`, else
/// `~/.config/rufus-linux`.
pub fn config_dir() -> PathBuf {
    Env::live().config_dir()
}

/// Runtime state directory (GUI log file): `$XDG_STATE_HOME/rufus-linux`,
/// else `~/.local/state/rufus-linux`.
pub fn state_dir() -> PathBuf {
    Env::live().state_dir()
}

/// Cache directory: `$XDG_CACHE_HOME/rufus-linux`, else
/// `~/.cache/rufus-linux`.
pub fn cache_dir() -> PathBuf {
    Env::live().cache_dir()
}

/// Preferred asset directory (see module docs for the order), or `None`
/// when no candidate is known. No existence check is performed.
pub fn assets_dir() -> Option<PathBuf> {
    Env::live().assets_dir()
}

/// `./rufus.toml` when that file exists in the current directory, else
/// `None`. Portable mode wins over the XDG config path.
pub fn portable_config_path() -> Option<PathBuf> {
    Env::live().portable_config_path()
}

/// Config file to use: portable `./rufus.toml` when present, otherwise
/// `<config_dir>/rufus.toml`.
pub fn default_config_path() -> PathBuf {
    Env::live().default_config_path()
}

/// Resolve `name` inside the preferred asset directory.
///
/// `name` must be exactly one normal path component (a bare file name).
/// Absolute paths, `..`, `.`, nested separators, empty names and embedded
/// NUL bytes are rejected fail-closed with [`CoreError::AssetResolution`]
/// before any filesystem access, so a hostile name can never escape the
/// asset directory (this primitive will be used by the root helper).
///
/// Returns [`CoreError::AssetResolution`] when the name is unsafe, when no
/// asset directory is known, or when the file does not exist there.
pub fn asset_path(name: &str) -> Result<PathBuf> {
    Env::live().asset_path(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(
        xdg_config_home: Option<&str>,
        xdg_state_home: Option<&str>,
        xdg_cache_home: Option<&str>,
        home: Option<&str>,
    ) -> Env {
        Env::for_tests(
            xdg_config_home,
            xdg_state_home,
            xdg_cache_home,
            home,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn xdg_bases_win_over_home() {
        let env = env(
            Some("/xdg/config"),
            Some("/xdg/state"),
            Some("/xdg/cache"),
            Some("/home/u"),
        );
        assert_eq!(env.config_dir(), PathBuf::from("/xdg/config/rufus-linux"));
        assert_eq!(env.state_dir(), PathBuf::from("/xdg/state/rufus-linux"));
        assert_eq!(env.cache_dir(), PathBuf::from("/xdg/cache/rufus-linux"));
    }

    #[test]
    fn home_fallbacks_match_xdg_defaults() {
        let env = env(None, None, None, Some("/home/u"));
        assert_eq!(
            env.config_dir(),
            PathBuf::from("/home/u/.config/rufus-linux")
        );
        assert_eq!(
            env.state_dir(),
            PathBuf::from("/home/u/.local/state/rufus-linux")
        );
        assert_eq!(env.cache_dir(), PathBuf::from("/home/u/.cache/rufus-linux"));
    }

    #[test]
    fn missing_home_falls_back_to_cwd() {
        let env = Env::for_tests(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(Path::new("/work")),
        );
        assert_eq!(env.config_dir(), PathBuf::from("/work/.config/rufus-linux"));
    }

    #[test]
    fn assets_preference_order() {
        let exe = Path::new("/opt/rufus-linux/bin");
        let direct = Env::for_tests(
            None,
            None,
            None,
            None,
            Some("/over/ride"),
            Some("/mnt/appimage"),
            Some(exe),
            None,
        );
        assert_eq!(direct.assets_dir(), Some(PathBuf::from("/over/ride")));

        let appimage = Env::for_tests(
            None,
            None,
            None,
            None,
            None,
            Some("/mnt/appimage"),
            Some(exe),
            None,
        );
        assert_eq!(
            appimage.assets_dir(),
            Some(PathBuf::from("/mnt/appimage/usr/share/rufus-linux/assets"))
        );

        let fhs = Env::for_tests(None, None, None, None, None, None, Some(exe), None);
        assert_eq!(
            fhs.assets_dir(),
            Some(PathBuf::from(
                "/opt/rufus-linux/bin/../share/rufus-linux/assets"
            ))
        );

        let none = Env::for_tests(None, None, None, None, None, None, None, None);
        assert_eq!(none.assets_dir(), None);
    }

    #[test]
    fn portable_config_detected_in_cwd() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        assert_eq!(
            Env::for_tests(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(scratch.path())
            )
            .portable_config_path(),
            None
        );

        std::fs::write(scratch.path().join("rufus.toml"), "show_all = true\n")
            .expect("write portable marker");
        assert_eq!(
            Env::for_tests(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(scratch.path())
            )
            .portable_config_path(),
            Some(scratch.path().join("rufus.toml"))
        );
    }

    #[test]
    fn default_config_prefers_portable() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        std::fs::write(scratch.path().join("rufus.toml"), "").expect("marker");
        let env = Env::for_tests(
            Some("/xdg/config"),
            None,
            None,
            Some("/home/u"),
            None,
            None,
            None,
            Some(scratch.path()),
        );
        assert_eq!(env.default_config_path(), scratch.path().join("rufus.toml"));

        let empty = tempfile::tempdir().expect("scratch dir");
        let env = Env::for_tests(
            Some("/xdg/config"),
            None,
            None,
            Some("/home/u"),
            None,
            None,
            None,
            Some(empty.path()),
        );
        assert_eq!(
            env.default_config_path(),
            PathBuf::from("/xdg/config/rufus-linux/rufus.toml")
        );
    }

    #[test]
    fn live_wrappers_agree_with_live_env() {
        // Only asserts internal consistency (never absolute values, so the
        // test is hermetic w.r.t. *values* while exercising the wrappers).
        let live = Env::live();
        assert_eq!(config_dir(), live.config_dir());
        assert_eq!(state_dir(), live.state_dir());
        assert_eq!(cache_dir(), live.cache_dir());
        assert_eq!(assets_dir(), live.assets_dir());
        assert_eq!(portable_config_path(), live.portable_config_path());
        assert_eq!(default_config_path(), live.default_config_path());
    }

    fn asset_env(scratch: &Path) -> Env {
        Env::for_tests(None, None, None, None, scratch.to_str(), None, None, None)
    }

    #[test]
    fn asset_path_resolves_plain_file_name() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        std::fs::write(scratch.path().join("RCDATA_500.bin"), b"payload").expect("seed asset");
        let env = asset_env(scratch.path());
        assert_eq!(
            env.asset_path("RCDATA_500.bin").expect("valid name"),
            scratch.path().join("RCDATA_500.bin")
        );
    }

    #[test]
    fn asset_path_rejects_traversal_absolute_and_nested() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let env = asset_env(scratch.path());
        for evil in [
            "../../../../etc/hostname",
            "../outside.bin",
            "/etc/hostname",
            "/abs/path.bin",
            "sub/dir.bin",
            "a/b",
            "..",
            ".",
            "",
            "trailing/",
            "back\\slash",
        ] {
            assert!(env.asset_path(evil).is_err(), "{evil:?} should be rejected");
        }
        // Embedded NUL can never be a real file name.
        assert!(env.asset_path("ok\0.bin").is_err());
    }

    #[test]
    fn public_asset_path_validates_before_filesystem() {
        // Validation runs before any asset-dir lookup, so these fail even
        // without `$RUFUS_ASSETS` set and without touching the filesystem.
        for evil in [
            "../../../../etc/hostname",
            "/etc/hostname",
            "..",
            ".",
            "",
            "a/b",
        ] {
            assert!(super::asset_path(evil).is_err(), "{evil:?}");
        }
    }
}
