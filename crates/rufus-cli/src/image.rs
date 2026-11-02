//! Image file helpers for the CLI surface (S03 detectors, S15 core).
//!
//! Detection lives in [`rufus_core::image`]: size-guarded magic probes
//! over any volume, shared with every later reader. This module is the
//! thin CLI wrapper over it — file size, whole-file hash and the
//! [`Inspected`] preamble the `analyze` and `plan` subcommands share.
//! Container headers (VHD, VHDX, FFU, qcow2) validate inside
//! [`rufus_core::image::open_image`], which the readers (S16/S17) call;
//! the CLI reports the detected kind here and leaves the refusing to
//! them.

use std::path::Path;

use rufus_core::error::Result;
use rufus_core::fs::FileVolume;
use rufus_core::fs::Volume;
use rufus_proto::ImageKind;

/// File size of a *regular* file (it must be an image, not a directory or
/// device); other paths fail with a validation error naming the path.
pub fn image_size(path: &Path) -> Result<u64> {
    Ok(FileVolume::open(path)?.total_bytes())
}

/// Detect the image container kind by magic only (see
/// [`rufus_core::image::detect`]).
///
/// Never panics on short files: an empty file reports
/// [`ImageKind::Unknown`], never an error.
pub fn detect_kind(path: &Path, size: u64) -> Result<ImageKind> {
    if size == 0 {
        return Ok(ImageKind::Unknown);
    }
    let volume = FileVolume::open(path)?;
    rufus_core::image::detect(&volume)
}

/// Everything the CLI reports about an image for one `analyze`/`plan` run.
pub struct Inspected {
    /// Image path as presented on the command line.
    pub path: String,
    /// Regular-file length in bytes.
    pub size_bytes: u64,
    /// SHA-256 over the whole image, lowercase hex.
    pub sha256: String,
    /// Container kind (magic-only detection in this slice).
    pub kind: ImageKind,
}

/// Measure, hash and sniff `path` in one pass — the common preamble of the
/// `analyze` and `plan` subcommands.
///
/// Kept error-signature aligned with the CLI's exit codes via
/// [`CoreError`](rufus_core::error::CoreError): the dispatcher maps `Io`
/// to exit 4 and validation errors to exit 1.
pub fn inspect(path: &Path) -> Result<Inspected> {
    let size_bytes = image_size(path)?;
    let sha256 = rufus_core::hash_file(path)?;
    let kind = detect_kind(path, size_bytes)?;
    Ok(Inspected {
        path: path.display().to_string(),
        size_bytes,
        sha256,
        kind,
    })
}
