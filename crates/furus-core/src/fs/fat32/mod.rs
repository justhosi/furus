//! The no-mount, no-external-tool FAT32 formatter and file API (S09).
//!
//! Six cooperating pieces, thin on top of the [`crate::fs::Volume`]
//! byte store:
//!
//! * [`geometry`] — the resolve step: cluster size, FAT size, cluster
//!   count and the refusal boundaries (65,525 clusters minimum, 2 TiB
//!   maximum, 512/4096 byte sectors only), including large FAT32 (64 KiB
//!   clusters) above 32 GiB;
//! * [`bpb`] — the byte images: the 512-byte boot sector (always, even
//!   on 4Kn media), the FSInfo structure and its backup copy, and the
//!   boot-sector parser [`Fat32::open`] drives;
//! * [`format`] — the write step: superblocks, both FAT copies and the
//!   root directory cluster, in the order the FAT32 spec explains (a
//!   mountable empty volume);
//! * [`dirent`] — directory entries: name validation, 8.3 rendering
//!   with `~n` collision tails, LFN runs and their reassembly, the
//!   32-byte entry images;
//! * [`fat`] — the cluster table: entry reads and writes, the chain
//!   classification, the write journal and the first-fit free-run scan;
//! * [`volume`] — the live type: [`Fat32::format`]/[`Fat32::open`] plus
//!   `mkdir`, `create_file`, `write_at`, `read_file`, `list_dir`,
//!   `allocate_contiguous`, `link_file`, `set_times`, `set_label`,
//!   `free_bytes` and `flush` (the file API of S09 part B).
//!
//! The field writes below share one rule: every byte goes into a
//! fixed-size stack buffer at a checked offset — there is no slice
//! indexing that can panic anywhere in the crate (#![forbid(unsafe_code)]
//! plus the repo-wide no-panic convention).

use crate::error::CoreError;
use crate::error::Result;

pub mod bpb;
pub mod dirent;
pub mod fat;
pub mod format;
pub mod geometry;
pub mod volume;

pub use dirent::FatTime;
pub use volume::DirEntryInfo;
pub use volume::Fat32;

/// Checked little-endian field write at a fixed offset inside a
/// byte-exact sector buffer. The offsets are compile-time constants of
/// the on-disk layouts, so a miss is impossible by construction — but a
/// total error return (never a panic, never an ignored call) keeps the
/// discipline from every reader in [`crate::part`].
pub(crate) fn put_bytes(target: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    let end = at
        .checked_add(bytes.len())
        .filter(|&end| end <= target.len())
        .ok_or_else(|| {
            let len = bytes.len();
            let total = target.len();
            CoreError::invalid(format!(
                "field at offset {at} ({len} bytes) does not fit a {total} byte buffer"
            ))
        })?;
    let Some(window) = target.get_mut(at..end) else {
        // Unreachable after the range check above; the explicit error
        // keeps the helper total instead of indexing into it.
        return Err(CoreError::invalid("field window vanished mid-copy"));
    };
    window.copy_from_slice(bytes);
    Ok(())
}

/// Checked little-endian `u16` field write ([`put_bytes`] specialised).
pub(crate) fn put_u16(target: &mut [u8], at: usize, value: u16) -> Result<()> {
    put_bytes(target, at, &value.to_le_bytes())
}

/// Checked little-endian `u32` field write ([`put_bytes`] specialised).
pub(crate) fn put_u32(target: &mut [u8], at: usize, value: u32) -> Result<()> {
    put_bytes(target, at, &value.to_le_bytes())
}
