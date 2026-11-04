//! The copy destination: one existing directory on a real filesystem.
//!
//! [`DestDir`] is deliberately thin — open, create a directory,
//! create a file, create a symlink — because Rufus copies into a
//! mounted filesystem and every placement decision (which names, which
//! order, what to skip) lives in [`walk`](super::walk), not here. Every I/O error
//! surfaces as [`CoreError::io`](crate::error::CoreError::io) naming
//! the path it hit, never anything vaguer.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::path::PathBuf;

use super::Entry;
use crate::error::CoreError;
use crate::error::Result;

/// One existing directory everything is copied under.
#[derive(Debug, Clone)]
pub struct DestDir {
    root: PathBuf,
}

impl DestDir {
    /// Open the existing directory at `root`: a missing path reports
    /// the I/O error, anything that is not a directory refuses naming
    /// the path.
    pub fn open(root: &Path) -> Result<Self> {
        match std::fs::metadata(root) {
            Ok(meta) if meta.is_dir() => Ok(Self {
                root: root.to_path_buf(),
            }),
            Ok(_) => Err(CoreError::invalid(format!(
                "copy destination '{}' is not a directory: refusing to copy into it",
                root.display()
            ))),
            Err(error) => Err(CoreError::io(root, error)),
        }
    }

    /// The opened root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the directory at `path`: reuse one that already exists
    /// as a real directory (the resumed-copy policy — re-running into
    /// a partial destination picks up where it stopped), refuse
    /// anything else in the way (a file, a symlink, anything but a
    /// directory: symlinks are never traversed). This check-then-act
    /// trusts the destination for the duration of the pass — a swap
    /// after the check is out of scope here; an `openat`-per-component
    /// walker is a later hardening item, not this slice. Parents
    /// already exist: the walk creates top-down, so `create_dir_all`
    /// would only mask a caller bug.
    pub fn create_dir(&self, path: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::invalid(format!(
                "copy destination '{}' is a symlink: refusing to copy through it",
                path.display()
            ))),
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(CoreError::invalid(format!(
                "copy destination '{}' exists and is not a directory: refusing to reuse it",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(path).map_err(|error| CoreError::io(path, error))
            }
            Err(error) => Err(CoreError::io(path, error)),
        }
    }

    /// Ensure owner write+execute on the directory at `path` while its
    /// children copy: when the existing mode lacks those bits (a reused
    /// `0555` directory from an earlier run, say), add them and return
    /// the prior bits so the caller can restore them with
    /// [`restore_mode`](DestDir::restore_mode) afterwards. Returns
    /// `None` when nothing needed changing. Only ever called on
    /// directories this walk just created or reused as a copy
    /// destination — never on the destination root, never elsewhere.
    pub fn enter_writable_dir(&self, path: &Path) -> Result<Option<u32>> {
        let mode = std::fs::metadata(path)
            .map_err(|error| CoreError::io(path, error))?
            .permissions()
            .mode()
            & 0o7777;
        if mode & 0o300 == 0o300 {
            return Ok(None);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o300))
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Some(mode))
    }

    /// Restore permission bits saved by
    /// [`enter_writable_dir`](DestDir::enter_writable_dir) once the
    /// directory's children are done.
    pub fn restore_mode(&self, path: &Path, mode: u32) -> Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| CoreError::io(path, error))
    }

    /// Create the file at `path`, refusing one that already exists:
    /// the first-creation half of the pair with [`replace_file`](DestDir::replace_file)
    /// (a second copy over the first would silently merge trees).
    pub fn create_file(&self, path: &Path) -> Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))
    }

    /// Open the file at `path` for a fresh copy: create it, or remove
    /// a regular file already there and recreate it. This is the
    /// resumed-copy policy beside [`create_dir`](DestDir::create_dir)'s
    /// directory reuse — an interrupted run leaves whole files behind,
    /// and re-running rewrites them — while [`create_file`](DestDir::create_file)
    /// keeps its refuse-existing contract for first creation (nothing
    /// is ever appended to or merged into). Anything but a regular
    /// file in the way refuses, symlinks loudest of all.
    pub fn replace_file(&self, path: &Path) -> Result<File> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::invalid(format!(
                "copy destination '{}' is a symlink: refusing to copy through it",
                path.display()
            ))),
            Ok(meta) if meta.is_file() => {
                std::fs::remove_file(path).map_err(|error| CoreError::io(path, error))?;
                self.create_file(path)
            }
            Ok(_) => Err(CoreError::invalid(format!(
                "copy destination '{}' exists and is not a regular file: refusing to replace it",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.create_file(path),
            Err(error) => Err(CoreError::io(path, error)),
        }
    }

    /// Create the symlink at `path` pointing at `target`: remove a
    /// regular file or symlink already there and recreate it (the
    /// resumed-copy policy, like [`replace_file`](DestDir::replace_file)
    /// for files); a directory or anything else in the way refuses.
    /// The caller guarantees `target` stays inside the copied tree —
    /// this never creates a link pointing outside the destination.
    pub fn replace_symlink(&self, path: &Path, target: &Path) -> Result<()> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
                std::fs::remove_file(path).map_err(|error| CoreError::io(path, error))?;
            }
            Ok(_) => {
                return Err(CoreError::invalid(format!(
                    "copy destination '{}' exists and is not a file: refusing to replace it",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CoreError::io(path, error)),
        }
        std::os::unix::fs::symlink(target, path).map_err(|error| CoreError::io(path, error))
    }

    /// Apply an entry's metadata to the already-written `path`:
    /// timestamps first, then the mode. The order matters — the mode
    /// goes last so a read-only mode cannot block the timestamp write
    /// (the file still carries its creation mode at that point, and
    /// the copier owns it either way). Masked to `0o7777`, never the
    /// file type bits; an absent stamp is skipped, not zeroed.
    /// Ownership (`uid`/`gid`) is deliberately never applied: it needs
    /// privileges the copy must not require.
    pub fn apply_metadata(&self, path: &Path, entry: &Entry) -> Result<()> {
        if entry.modified.is_some() || entry.accessed.is_some() {
            // Read-only handle suffices: the copier owns the file, so
            // setting explicit times is permitted.
            let file = File::open(path).map_err(|error| CoreError::io(path, error))?;
            let mut times = std::fs::FileTimes::new();
            if let Some(accessed) = entry.accessed {
                times = times.set_accessed(accessed);
            }
            if let Some(modified) = entry.modified {
                times = times.set_modified(modified);
            }
            file.set_times(times)
                .map_err(|error| CoreError::io(path, error))?;
        }
        if let Some(mode) = entry.mode {
            let permissions = std::fs::Permissions::from_mode(mode & 0o7777);
            std::fs::set_permissions(path, permissions)
                .map_err(|error| CoreError::io(path, error))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Permission bits of `path`, masked to the mode proper.
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .expect("entry stats")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn enter_widens_and_restore_returns_prior_bits() {
        // A `0555` directory widens to `0755` for the descent and
        // restores afterwards; an already-wide directory is a no-op.
        // Both halves are pure `DestDir` behaviour, independent of
        // any walk.
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let dir = scratch.path().join("sub");
        std::fs::create_dir(&dir).expect("subdir creates");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555))
            .expect("subdir chmods");
        let dest = DestDir::open(scratch.path()).expect("root opens");
        assert_eq!(dest.enter_writable_dir(&dir).expect("widens"), Some(0o555));
        assert_eq!(mode_of(&dir), 0o755);
        dest.restore_mode(&dir, 0o555).expect("restores");
        assert_eq!(mode_of(&dir), 0o555);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("subdir chmods");
        assert_eq!(dest.enter_writable_dir(&dir).expect("no-op"), None);
    }
}
