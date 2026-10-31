//! The no-mount, no-external-tool exFAT formatter (S10).
//!
//! exFAT is the Windows default for removable media, and Rufus formats it
//! through `FormatEx`, which a Linux build cannot call. This module grows
//! the same bytes from first principles, on top of the
//! [`crate::fs::Volume`] byte store:
//!
//! * [`geometry`] — the resolve step: cluster size, FAT size, heap
//!   placement, cluster count and the refusal boundaries (4 KiB..=32 MiB
//!   clusters, 3 MiB..=2 TiB volumes, 512/4096 byte sectors);
//! * [`boot`] — the boot region images: the boot sector, the eight
//!   extended boot sectors, the OEM and reserved sectors, the boot
//!   checksum and the backup copy;
//! * [`upcase`] — the canonical up-case table the volume carries;
//! * [`format`] — the write step: boot region, FAT, allocation bitmap,
//!   up-case table and root directory (a mountable empty volume);
//! * [`dirent`] — the 0x85/0xC0/0xC1 entry sets a file or directory is
//!   made of: the images, the set checksum, the name hash and name
//!   rules, and the directory walker that reads them back;
//! * [`bitmap`] — the allocation bitmap in memory: bits, free count,
//!   contiguous first-fit, mark/clear and write-back;
//! * [`volume`] — the live volume type (`Exfat`): format/open on top
//!   of the writer, then `mkdir`, `create_file`, `list_dir`,
//!   `free_bytes` and `flush` over the byte store (part B1; `write_at`,
//!   `read_file`, `set_times` and `set_label` are part B2).
//!
//! The field writes below share the FAT32 side's rule: every byte goes
//! into a fixed-size buffer at a checked offset, there is no slice
//! indexing outside tests, and every failure is a [`CoreError`] naming
//! the value that did not fit.

use crate::error::CoreError;
use crate::error::Result;

pub mod bitmap;
pub mod boot;
pub mod dirent;
pub mod format;
pub mod geometry;
pub mod upcase;
pub mod volume;

pub use bitmap::Bitmap;
pub use boot::ParsedBoot;
pub use dirent::DirEntry;
pub use format::FormatOptions;
pub use format::format;
pub use geometry::Geometry;
pub use volume::DirInfo;
pub use volume::Exfat;

/// Checked byte copy at a fixed offset inside a byte-exact image.
///
/// The offsets below are compile-time constants of the on-disk layouts,
/// so a miss is impossible by construction - but a total error return
/// (never a panic, never an ignored call) keeps the discipline the
/// readers in [`crate::part`] follow.
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

/// Checked little-endian `u64` field write ([`put_bytes`] specialised).
pub(crate) fn put_u64(target: &mut [u8], at: usize, value: u64) -> Result<()> {
    put_bytes(target, at, &value.to_le_bytes())
}

/// Checked little-endian `u16` field read from a byte image.
pub(crate) fn get_u16(source: &[u8], at: usize) -> Option<u16> {
    let window = source.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(window).ok()?))
}

/// Checked little-endian `u32` field read from a byte image.
pub(crate) fn get_u32(source: &[u8], at: usize) -> Option<u32> {
    let window = source.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(<[u8; 4]>::try_from(window).ok()?))
}

/// Checked little-endian `u64` field read from a byte image.
pub(crate) fn get_u64(source: &[u8], at: usize) -> Option<u64> {
    let window = source.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(window).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_writers_refuse_a_window_that_does_not_fit() {
        let mut buffer = [0u8; 4];
        let error = put_u32(&mut buffer, 2, 1).expect_err("window runs past the end");
        assert!(error.to_string().contains("does not fit"), "{error}");
        assert!(put_u32(&mut buffer, 0, 0x1234_5678).is_ok());
        assert_eq!(buffer, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn field_readers_refuse_a_short_buffer() {
        let buffer = [1u8; 3];
        assert_eq!(get_u16(&buffer, 0), Some(0x0101));
        assert_eq!(get_u16(&buffer, 2), None);
        assert_eq!(get_u32(&buffer, 0), None);
        assert_eq!(get_u64(&buffer, 0), None);
    }
}
