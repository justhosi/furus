//! Unlinked implementation of the safe facade: [`Wim`] exists with an
//! identical signature to the linked side, but every operation fails
//! with [`WimlibError::NotLinked`] without touching any library.
//!
//! The `progress` callback of [`Wim::extract_image`] is never invoked:
//! there is no extraction to report on.

use std::path::Path;

use crate::error::WimlibError;

use super::ExtractFlags;
use super::ExtractProgress;
use super::OpenFlags;
use super::WimInfo;

/// Stand-in for the linked [`Wim`](super::Wim): unconstructible, and
/// every operation fails with [`WimlibError::NotLinked`].
pub struct Wim {
    /// Unconstructible outside this module (no fields to build).
    _private: (),
}

impl Wim {
    /// Always fails with [`WimlibError::NotLinked`]: there is no
    /// library to open the WIM with.
    pub fn open(_path: &Path, _flags: OpenFlags) -> Result<Wim, WimlibError> {
        Err(WimlibError::NotLinked)
    }

    /// Always fails with [`WimlibError::NotLinked`].
    pub fn info(&self) -> Result<WimInfo, WimlibError> {
        Err(WimlibError::NotLinked)
    }

    /// Always fails with [`WimlibError::NotLinked`].
    pub fn image_name(&self, _image: u32) -> Result<Option<String>, WimlibError> {
        Err(WimlibError::NotLinked)
    }

    /// Always fails with [`WimlibError::NotLinked`].
    pub fn image_description(&self, _image: u32) -> Result<Option<String>, WimlibError> {
        Err(WimlibError::NotLinked)
    }

    /// Always fails with [`WimlibError::NotLinked`]; the `progress`
    /// callback is never invoked.
    pub fn extract_image(
        &self,
        _image: u32,
        _target: &Path,
        _flags: ExtractFlags,
        _progress: &mut dyn FnMut(&ExtractProgress) -> bool,
    ) -> Result<(), WimlibError> {
        Err(WimlibError::NotLinked)
    }
}
