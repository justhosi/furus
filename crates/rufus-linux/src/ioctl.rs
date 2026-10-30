//! The single unsafe island of the tree: four kernel block ioctls with
//! no safe wrapper in rustix (S07).
//!
//! # Why this module exists
//!
//! The write pipeline needs the kernel's zero/discard/flush/rescan
//! primitives on an *opened* block device, and rustix deliberately ships
//! none of them (`BLKZEROOUT`, `BLKDISCARD`, `BLKRRPART`, `BLKFLSBUF`).
//! Rather than fork rustix or shell out to `blockdev`, this module makes
//! the four one-line `ioctl(2)` calls and nothing else.
//!
//! # What is allowed here
//!
//! Exactly the four requests below, each with the argument shape the
//! Linux UAPI header pins (numbers from `include/uapi/linux/fs.h`,
//! literal-checked in the test module):
//!
//! | shim | request | macro form | argument |
//! |------|---------|------------|----------|
//! | [`zero_out`] | `BLKZEROOUT` | `_IO(0x12, 127)` | `[u64; 2]` = offset, len |
//! | [`discard`] | `BLKDISCARD` | `_IO(0x12, 119)` | `[u64; 2]` = offset, len |
//! | [`reread_partitions`] | `BLKRRPART` | `_IO(0x12, 95)` | none |
//! | [`flush_buffers`] | `BLKFLSBUF` | `_IO(0x12, 97)` | none |
//!
//! Nothing else may be added without review: no other syscall, no
//! pointer arithmetic, no larger kernel struct shared across the call,
//! no second unsafe block — [`ioctl_raw`] is the one, and the callers
//! only ever lease it a stack array that outlives the call.
//!
//! Callers keep the failure discipline: `EOPNOTSUPP`/`EINVAL`/`ENOTTY`
//! mean "the driver does not provide this primitive" and are mapped to
//! documented fallback semantics in `crate::block`, not silently
//! swallowed here.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::ptr;

/// `BLKZEROOUT` — `_IO(0x12, 127)`: zero `[arg[0], arg[0] + arg[1])`
/// bytes of the device; out-of-range windows answer `EINVAL`.
const BLKZEROOUT: libc::c_ulong = 0x127F;
/// `BLKDISCARD` — `_IO(0x12, 119)`: let the device free
/// `[arg[0], arg[0] + arg[1])` (the caller treated as best effort).
const BLKDISCARD: libc::c_ulong = 0x1277;
/// `BLKRRPART` — `_IO(0x12, 95)`: re-read the partition table from the
/// media; `EINVAL` means the kernel could not rescan (the device is in
/// use, or it has no partition scanning enabled).
const BLKRRPART: libc::c_ulong = 0x125F;
/// `BLKFLSBUF` — `_IO(0x12, 97)`: flush the device's in-kernel buffers.
const BLKFLSBUF: libc::c_ulong = 0x1261;

/// The raw `ioctl(2)` shim and the only unsafe block in the workspace.
///
/// The single `#[allow(unsafe_code)]` of the tree lives *here* — on
/// this one function — and nowhere else: the workspace lint is
/// `deny`, every other module inherits it, and the module charter
/// above describes exactly what this body may do (one `ioctl` call,
/// four requests, caller-owned stack arguments).
#[allow(unsafe_code)]
fn ioctl_raw(fd: RawFd, request: libc::c_ulong, arg: *mut libc::c_void) -> io::Result<()> {
    // SAFETY: one variadic `ioctl(2)` call; the file descriptor is
    // owned by the caller, `request` is one of the four constants of
    // this module, and `arg` is either `null` (the no-argument
    // requests) or points at a two-element `u64` stack array the
    // caller keeps alive for the duration of the call (the kernel
    // reads it, never stores it, dereferences nothing else).
    let result = unsafe { libc::ioctl(fd, request, arg) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Zero `[offset, offset + len)` bytes of the device behind `file`
/// through `BLKZEROOUT`.
///
/// `EOPNOTSUPP`/`ENOTTY`/`EINVAL` mean "this driver has no zero
/// primitive"; `crate::block::Sink::zero_range` falls back to writing
/// zeroes on exactly those errors, so this signature only surfaces the
/// raw outcome.
pub fn zero_out(file: &impl AsRawFd, offset: u64, len: u64) -> io::Result<()> {
    let mut arg: [u64; 2] = [offset, len];
    // SAFETY: `BLKZEROOUT` reads exactly these two `u64`s behind the
    // pointer during the call; `arg` is a stack array that outlives it.
    ioctl_raw(
        file.as_raw_fd(),
        BLKZEROOUT,
        arg.as_mut_ptr().cast::<libc::c_void>(),
    )
}

/// Hand `[offset, offset + len)` back to the device through
/// `BLKDISCARD` (a wiped-block freespace hint, not a data guarantee).
///
/// Same failure discipline as [`zero_out`]: the caller decides whether
/// the absence of discard support is an error or a documented no-op.
pub fn discard(file: &impl AsRawFd, offset: u64, len: u64) -> io::Result<()> {
    let mut arg: [u64; 2] = [offset, len];
    // SAFETY: `BLKDISCARD` reads exactly these two `u64`s behind the
    // pointer during the call; `arg` is a stack array that outlives it.
    ioctl_raw(
        file.as_raw_fd(),
        BLKDISCARD,
        arg.as_mut_ptr().cast::<libc::c_void>(),
    )
}

/// Ask the kernel to re-read the partition table of the device behind
/// `file` (`BLKRRPART`).
///
/// The open fd must be the *whole disk*, not a partition. `EINVAL` is
/// the kernel's "cannot rescan while something uses the partitions"
/// answer and `crate::block` turns it into a plain-language error.
pub fn reread_partitions(file: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: `BLKRRPART` takes no argument; the variadic slot is
    // empty, so there is never a pointer to validate.
    ioctl_raw(file.as_raw_fd(), BLKRRPART, ptr::null_mut())
}

/// Flush the device's in-kernel buffers (`BLKFLSBUF`).
///
/// Paired with [`reread_partitions`] before the kernel sees a fresh
/// partition table; `crate::block` runs it first on every rescan.
pub fn flush_buffers(file: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: `BLKFLSBUF` takes no argument; the variadic slot is
    // empty, so there is never a pointer to validate.
    ioctl_raw(file.as_raw_fd(), BLKFLSBUF, ptr::null_mut())
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_numbers_are_pinned_to_the_uapi_header() {
        // `include/uapi/linux/fs.h`: BLKZEROOUT/BLKDISCARD/BLKRRPART/
        // BLKFLSBUF are `_IO(0x12, ...)` of the numbers below. Pin the
        // literals so a kernel header reshuffle cannot pass silently.
        assert_eq!(super::BLKZEROOUT, 0x127F, "_IO(0x12, 127)");
        assert_eq!(super::BLKDISCARD, 0x1277, "_IO(0x12, 119)");
        assert_eq!(super::BLKRRPART, 0x125F, "_IO(0x12, 95)");
        assert_eq!(super::BLKFLSBUF, 0x1261, "_IO(0x12, 97)");
    }

    #[test]
    fn range_ioctls_are_rejected_by_plain_files_without_panicking() {
        // A regular file is not a block device: both range ioctls must
        // answer with an OS error (typically ENOTTY) and never a panic.
        // No block device is needed or touched in this test.
        let scratch = tempfile::NamedTempFile::new().expect("scratch file");
        assert!(super::zero_out(&scratch, 0, 512).is_err(), "zero_out");
        assert!(super::discard(&scratch, 0, 512).is_err(), "discard");
    }
}
