//! The copy destination: one existing directory on a real filesystem.
//!
//! [`DestDir`] is deliberately thin — open, create a directory,
//! create a file — because Rufus copies into a mounted filesystem
//! and every placement decision (which names, which order, what to
//! skip) lives in [`walk`](super::walk), not here. Every I/O error
//! surfaces as [`CoreError::io`](crate::error::CoreError::io) naming
//! the path it hit, never anything vaguer.

use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;

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
}
