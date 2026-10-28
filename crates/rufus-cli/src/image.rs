//! Magic-based image detection and file helpers for the provisional CLI
//! surface (S03).
//!
//! This is intentionally the *same* first-pass classification Rufus does in
//! `img_report`: pick a container family by well-known magic bytes and
//! nothing else. Full readers (ISO9660, UDF, WIM metadata, VHD bodies)
//! arrive with S14–S16 and replace this outright; the plan JSON keeps the
//! [`ImageKind`] name, only the detection quality changes.
//!
//! Never panics on short files: every probe is guarded by a size check, and
//! a file whose probes were all short of their magic lengths reports
//! [`ImageKind::Unknown`] (an empty file too), never an error.

use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_proto::ImageKind;

/// `MSWIM\0\0\0` at offset 0 (a WIM or ESD).
const WIM_MAGIC: [u8; 8] = *b"MSWIM\0\0\0";
/// `vhdxfile` at offset 0.
const VHDX_MAGIC: [u8; 8] = *b"vhdxfile";
/// `ImageFlash` at offset 0 (full-flash update).
const FFU_MAGIC: [u8; 10] = *b"ImageFlash";
/// xz stream header at offset 0.
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
/// zstd frame magic at offset 0.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
/// bzip2 stream header at offset 0.
const BZIP2_MAGIC: [u8; 3] = *b"BZh";
/// gzip stream header at offset 0.
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
/// Windows PE image header at offset 0.
const PE_MAGIC: [u8; 2] = *b"MZ";
/// VHD footer magic at size-512.
const VHD_MAGIC: [u8; 8] = *b"conectix";
/// ISO9660 volume-descriptor magic at 0x8001.
const ISO_MAGIC: [u8; 5] = *b"CD001";

/// First `n` bytes at `offset`, or fewer when the file is shorter.
///
/// Read errors surface as [`CoreError::Io`] naming `path`.
fn read_up_to(file: &mut File, path: &Path, offset: u64, n: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| CoreError::io(path, source))?;
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        let read = file
            .read(&mut buf[filled..])
            .map_err(|source| CoreError::io(path, source))?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Bytes start with `magic` (length must be pre-checked); never panics.
fn matches(lead: &[u8], magic: &[u8]) -> bool {
    lead.len() >= magic.len() && &lead[..magic.len()] == magic
}

/// File size of a *regular* file (it must be an image, not a directory or
/// device); other paths fail with a validation error naming the path.
pub fn image_size(path: &Path) -> Result<u64> {
    let meta = std::fs::metadata(path).map_err(|source| CoreError::io(path, source))?;
    if !meta.is_file() {
        return Err(CoreError::invalid(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    Ok(meta.len())
}

/// Detect the image container kind by magic only (see module header).
pub fn detect_kind(path: &Path, size: u64) -> Result<ImageKind> {
    if size == 0 {
        return Ok(ImageKind::Unknown);
    }
    let mut file = File::open(path).map_err(|source| CoreError::io(path, source))?;

    // Leading magics, checked while ever the file is long enough.
    let mut any_probe = false;
    let lead = read_up_to(&mut file, path, 0, 16)?;
    for (magic, kind) in [
        (WIM_MAGIC.as_slice(), ImageKind::Wim),
        (VHDX_MAGIC.as_slice(), ImageKind::Vhdx),
        (FFU_MAGIC.as_slice(), ImageKind::Ffu),
        (XZ_MAGIC.as_slice(), ImageKind::Xz),
        (ZSTD_MAGIC.as_slice(), ImageKind::Zstd),
        (BZIP2_MAGIC.as_slice(), ImageKind::Bzip2),
        (GZIP_MAGIC.as_slice(), ImageKind::Gzip),
        (PE_MAGIC.as_slice(), ImageKind::Pe),
    ] {
        if lead.len() >= magic.len() {
            any_probe = true;
            if matches(&lead, magic) {
                return Ok(kind);
            }
        }
    }

    // VHD: footer at the very end.
    if size >= 512 {
        any_probe = true;
        let tail = read_up_to(&mut file, path, size - 512, 8)?;
        if matches(&tail, VHD_MAGIC.as_slice()) {
            return Ok(ImageKind::Vhd);
        }
    }

    // ISO9660: volume descriptor set sector 16 (`CD001` from 0x8001).
    if size >= 0x8001 + ISO_MAGIC.len() as u64 {
        any_probe = true;
        let sector = read_up_to(&mut file, path, 0x8001, ISO_MAGIC.len())?;
        if matches(&sector, ISO_MAGIC.as_slice()) {
            return Ok(ImageKind::Iso);
        }
    }

    // A non-empty file where at least one magic probe was possible but
    // nothing matched: raw content, e.g. a `.img` or an `.iso.gz` renamed.
    if any_probe {
        Ok(ImageKind::Raw)
    } else {
        // Too short to hold any magic byte sequence at all.
        Ok(ImageKind::Unknown)
    }
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
/// [`CoreError`]: the dispatcher maps `Io` to exit 4 and validation errors
/// to exit 1.
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
