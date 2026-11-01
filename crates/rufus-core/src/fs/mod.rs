//! The filesystem write side's storage abstraction plus the formatters
//! that drive it: FAT32 (S09), exFAT (S10), NTFS (S11, via the external
//! `mkntfs` tool), ext2/3/4 (S12, via the external `mke2fs` /
//! `mkfs.ext*` tool) and UDF (S13, slice 1 of 3, via the external
//! `mkudffs` / `mkfs.udf` tool).
//!
//! The crate layering puts privileged I/O in `rufus-linux` and the
//! formatter logic in `rufus-core`; the two meet here in [`Volume`], the
//! byte-store surface (total size, exact positional reads/writes, sector
//! size, flush) that is *all* the formatter ever needs. There is no
//! [`crate::paths`]-style exception in the other direction — `rufus-core`
//! never depends on `rufus-linux` — so a later slice has to wire an
//! adapter from `rufus_linux::Sink` (a device or scratch file) to
//! [`Volume`]; anyone could do the same for `std::fs::File`, which is
//! exactly what the integration tests of this slice do over sparse
//! images.
//!
//! This is the "no mount, no external tool" substrate the PLAN asks for
//! (S09: "a complete ... formatter and file writer, no mount, no
//! external tool"): the formatter below builds a complete FAT32 volume
//! against any [`Volume`], and the byte store promises nothing more than
//! bounds-checked exact I/O.
//!
//! Two contract rules for every [`Volume`] implementation, which the
//! formatter and its tests rely on:
//!
//! * reads past the store are an error, never zero-filled — a
//!   [`CoreError::io`] carrying [`std::io::ErrorKind::UnexpectedEof`] (the
//!   formatter only reads inside its own geometry, so a short store
//!   would otherwise dress a bogus volume up as formatted);
//! * every read/write is bounds-checked *before* the I/O happens
//!   (`offset + len <= total_bytes`, with checked arithmetic), and both
//!   numbers appear in the [`CoreError::invalid`] message. Nothing here
//!   ever panics: all byte addressing goes through the same checked
//!   helpers the byte-array and file implementations share.

use crate::error::CoreError;
use crate::error::Result;

pub mod exfat;
pub mod ext;
pub mod fat32;
pub mod ntfs;
pub mod udf;

mod tool;

/// The byte-store surface the write side of `rufus-core` drives.
///
/// Implementations promise:
///
/// * *exact* transfers — [`read_exact_at`] fills `buf` completely or
///   fails; [`write_all_at`] writes all of `buf` or fails; partial
///   transfers are retried inside the implementation, never reported as
///   silent truncation;
/// * immediate positioning — every call carries the absolute byte
///   `offset`, and a failed call has no lasting effect at that offset;
/// * bounds before I/O — a window running past [`Volume::total_bytes`]
///   is refused with [`CoreError::invalid`] naming both numbers, before
///   any byte moves;
/// * reads past the end of the store are an
///   [`std::io::ErrorKind::UnexpectedEof`] styled failure, so an
///   implementation maps its backend's short read up to that error
///   rather than padding with zeroes;
/// * [`flush`] makes buffered state durable where the backend has any.
///
/// [`read_exact_at`]: Volume::read_exact_at
/// [`write_all_at`]: Volume::write_all_at
/// [`flush`]: Volume::flush
pub trait Volume {
    /// Total extent in bytes the store exposes. Fixed for the store's
    /// lifetime: the formatter derives class geometry from a single
    /// reading and refuses a drift observed at write time.
    fn total_bytes(&self) -> u64;

    /// Fill `buf` completely from `offset`, or report why not.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Write all of `buf` at `offset`, or report why not.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Push buffered state down (`Ok(())` when nothing to do — the
    /// in-memory store has none).
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Sector size the store's backend reports, in bytes. Only 512 (the
    /// universal default) and 4096 (modern 4Kn media) are legal; the
    /// formatter refuses anything else with the offending value named.
    fn sector_size(&self) -> u32 {
        512
    }
}

/// Checked byte window of `len` bytes at `offset` in a store of
/// `total` bytes, shared by every [`Volume`] implementation here: the
/// lookup happens before any I/O and the violation message names the
/// direction, the length, the offset and the store's total extent.
fn checked_window(total: u64, offset: u64, len: usize, direction: &str) -> Result<(usize, usize)> {
    let end =
        offset
            .checked_add(u64::try_from(len).map_err(|_| {
                CoreError::invalid("byte window longer than u64 in a volume operation")
            })?)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "{direction} of {len} bytes at offset {offset} overflows a {total} byte volume"
                ))
            })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{direction} of {len} bytes at offset {offset} runs past the {total} byte volume end"
        )));
    }
    let start = usize::try_from(offset)
        .map_err(|_| CoreError::invalid("byte offset does not fit this machine's usize"))?;
    let end = usize::try_from(end)
        .map_err(|_| CoreError::invalid("byte window end does not fit this machine's usize"))?;
    Ok((start, end))
}

/// The in-memory [`Volume`]: one `Vec<u8>` sized exactly to
/// `total_bytes`, for unit tests and small volumes.
///
/// Sixty-four MiB formats comfortably live in RAM (a target-machine
/// phone call away from the format tests in
/// [`fat32::format`](fat32::format)); the multi-GiB and multi-TiB
/// acceptance tests of this slice deliberately never do this — they go
/// through sparse files, where the byte count is virtual.
#[derive(Debug, Clone)]
pub struct VecVolume {
    bytes: Vec<u8>,
    sector_size: u32,
}

impl VecVolume {
    /// Build a zero-filled volume of `len` bytes with `sector_size`
    /// byte sectors. The memory is bound to `len`: constructing a
    /// multi-GiB `VecVolume` is a caller's explicit (and unwise) request,
    /// which is why the acceptance tests never do it. The crate targets
    /// 64-bit Linux hosts only (`rust-toolchain.toml` pins a 64-bit
    /// triple), so the `usize` cast of `len` cannot truncate in practice;
    /// a volume that no allocation could ever back is refused here
    /// rather than when writing.
    pub fn new(len: u64, sector_size: u32) -> Result<Self> {
        if !matches!(sector_size, 512 | 4096) {
            return Err(CoreError::invalid(format!(
                "sector size {sector_size} is not supported: fat32 writes 512 and 4096 byte sectors only"
            )));
        }
        let bytes = usize::try_from(len)
            .ok()
            .map(|size| vec![0u8; size])
            .ok_or_else(|| CoreError::invalid("volume length does not fit this machine's usize"))?;
        Ok(Self { bytes, sector_size })
    }

    /// The whole backing bytes — for image comparisons and direct byte
    /// pins in tests.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Volume for VecVolume {
    fn total_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let (start, end) = checked_window(self.total_bytes(), offset, buf.len(), "read")?;
        buf.copy_from_slice(self.bytes.get(start..end).ok_or_else(|| {
            CoreError::invalid("read window vanished between the check and the copy")
        })?);
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let (start, end) = checked_window(self.total_bytes(), offset, buf.len(), "write")?;
        let Some(window) = self.bytes.get_mut(start..end) else {
            return Err(CoreError::invalid(
                "write window vanished between the check and the copy",
            ));
        };
        window.copy_from_slice(buf);
        Ok(())
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_volume_round_trips_byte_writes() {
        let mut volume = VecVolume::new(4096, 512).expect("4096 bytes of RAM");
        volume
            .write_all_at(0, b"RUFUS-boot")
            .expect("write at 0 fits");
        volume
            .write_all_at(4090, &[0x55, 0xAA, 0x11, 0x22, 0x33, 0xDE])
            .expect("write at the very end fits");
        let mut out = [0u8; 10];
        volume.read_exact_at(0, &mut out).expect("read back at 0");
        assert_eq!(&out, b"RUFUS-boot");
        let mut tail = [0u8; 6];
        volume
            .read_exact_at(4090, &mut tail)
            .expect("read back at the end");
        assert_eq!(tail, [0x55, 0xAA, 0x11, 0x22, 0x33, 0xDE]);
        assert_eq!(volume.total_bytes(), 4096);
        assert_eq!(volume.sector_size(), 512);
        assert_eq!(volume.bytes().len(), 4096);
    }

    #[test]
    fn vec_volume_bounds_violations_name_both_numbers() {
        let mut volume = VecVolume::new(1024, 512).expect("1 KiB of RAM");
        let error = volume.write_all_at(1020, &[0u8; 10]).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("10 bytes"), "{text}");
        assert!(text.contains("1020"), "{text}");
        assert!(text.contains("1024"), "{text}");

        let mut sink = [0xFFu8; 4];
        let error = volume.read_exact_at(1024, &mut sink).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("4 bytes"), "{text}");
        assert!(text.contains("1024"), "{text}");
        // an out-of-bounds operation changed nothing
        assert_eq!(sink, [0xFFu8; 4]);
        assert!(volume.bytes()[..1024].iter().all(|&b| b == 0));

        // the boundary itself is legal
        volume
            .read_exact_at(1020, &mut sink)
            .expect("window ending exactly on the volume end fits");
    }
}
