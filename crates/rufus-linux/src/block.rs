//! Block-style I/O (S07 part A): the [`Sink`] surface the write pipeline
//! drives, three implementations and the shared loops underneath them.
//!
//! Three implementations share one correct body per behaviour:
//!
//! * [`BlockDevice`] — an opened device node (or, for tests, a stand-in
//!   regular file) with O_DIRECT probing (device nodes only: a plain
//!   file never gets the flag at all and opens buffered, see
//!   [`BlockDevice::open_with`]), [`ioctl`](crate::ioctl)-based
//!   zero/discard/rescan and the real kernel syscalls;
//! * [`MemorySink`] — the in-RAM test double: a `Vec<u8>` that simulates
//!   media;
//! * [`SparseFile`] — a real sparse file with the same file-backed
//!   bodies, for tests that need a genuine fd without a device.
//!
//! The loops (full-buffer positional read/write, cancellable chunked
//! writes, manual zero fallback) are free functions generic over a tiny
//! single-call positional I/O trait, implemented for both the file fd
//! and the RAM store — so the three sinks cannot drift apart on retry
//! or short-IO semantics.
//!
//! # Bounds and alignment contracts
//!
//! * Every window (`read`/`write`/`zero`/`discard`, including the
//!   cancellable writer) must lie inside [`Sink::size`]; the arithmetic
//!   is u64-overflow-checked and rejects with [`CoreError::invalid`],
//!   naming the offset and the size. `zero_range` additionally rejects
//!   a zero length as invalid, `write_all_at_cancellable` a zero chunk.
//! * Reads and writes are exact: the loops retry partial transfers and
//!   `EINTR`/`EAGAIN`, and map a surprise end of store to a plain
//!   `short read at offset N` error — never to a silently truncated
//!   success.
//! * On a direct sink (the kernel accepted `O_DIRECT`) every request
//!   must already be aligned end-to-end — offset and length multiples
//!   of [`AlignedBuf::ALIGN`], the slice drawn from an
//!   [`AlignedBuf`]. Misaligned calls are rejected with an
//!   `unaligned O_DIRECT ...` error instead of being silently copied
//!   around; there is no hidden bounce buffer.
//! * `discard` is best effort, matching the kernel's own definition: a
//!   device that cannot deallocate simply keeps the data while the
//!   call reports [`Ok`]. `zero_range` is not best effort — a missing
//!   zero primitive falls back to writing zeroes and reports real
//!   errors.

use std::fs;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;

use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::fs::fsync;
use rustix::fs::open;

use rufus_core::error::CoreError;
use rufus_core::error::Result;

use crate::ioctl;

/// Piece size of the manual zeroing fallback in bytes; equal to
/// [`AlignedBuf::DEFAULT_LEN`], restated as a `u64` for the byte loop
/// (the test module pins the two constants equal).
const FALLBACK_CHUNK: u64 = 4 * 1024 * 1024;

/// Logical-sector default for [`BlockDevice::open`], whose caller did
/// not bring sysfs geometry to the table.
const FALLBACK_LOGICAL_SECTOR: u32 = 512;
/// Physical-sector default for [`BlockDevice::open`] (see above).
const FALLBACK_PHYSICAL_SECTOR: u32 = 4096;

// ---------------------------------------------------------------------------
// AlignedBuf: the allocation shape O_DIRECT offsets need, built without
// unsafe (an over-allocated `Vec<u8>` plus an aligned window inside it).
// ---------------------------------------------------------------------------

/// One buffer whose data area starts at a [`AlignedBuf::ALIGN`]-byte
/// boundary — the shape direct I/O requires from its slices.
///
/// Everything is derived from an over-allocated [`Vec<u8>`]; there is no
/// `alloc::alloc`, no `posix_memalign` and no unsafe anywhere in this
/// type. The `Vec` owns and finally frees the real allocation, so the
/// aligned window is never responsible for memory.
///
/// The window is stored as a `Range` into `storage`, and [`AlignedBuf::len`]
/// reads `window.len()` — literally the length of the slice
/// [`AlignedBuf::as_slice`] hands out — so an arithmetic surprise can
/// never desync the reported length from the actual window.
#[derive(Debug)]
pub struct AlignedBuf {
    /// The raw, deliberately oversized backing allocation.
    storage: Vec<u8>,
    /// `storage[self.window.clone()]` is the aligned data window:
    /// built once, after the final allocation, entirely inside the
    /// allocation, so nothing can grow the vector under it and no
    /// accessor can skip past the end.
    window: Range<usize>,
}

impl AlignedBuf {
    /// Byte alignment of the data window — the unit direct I/O needs
    /// offsets/lengths/array addresses to line up on.
    pub const ALIGN: usize = 4096;
    /// Default capacity handed out by [`AlignedBuf::new`]; also the
    /// piece size of the manual zero fallback (`FALLBACK_CHUNK`).
    pub const DEFAULT_LEN: usize = 4 * 1024 * 1024;

    /// A [`AlignedBuf::DEFAULT_LEN`]-byte aligned buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::with_len(Self::DEFAULT_LEN)
    }

    /// A buffer with `len` bytes of room, rounded **up** to an
    /// [`AlignedBuf::ALIGN`] multiple so even awkward sizes produce
    /// legitimate aligned request geometry. `len == 0` stays legal and
    /// empty.
    ///
    /// Absurd lengths (`usize`-overflowing padding arithmetic) are
    /// computed with checked calls that saturate: the resulting
    /// unallocatable size then simply fails at the [`Vec`] allocation
    /// below. There is no code path that wraps around and hands back a
    /// small window pretending to be a huge one.
    #[must_use]
    pub fn with_len(len: usize) -> Self {
        // Checked on purpose: `len` near `usize::MAX` would otherwise
        // overflow the round-up (or the `+ ALIGN` padding) and wrap
        // into a small bogus request. Saturation routes every such
        // size into the `Vec` allocation, which fails for lengths
        // past the address space — the documented failure mode.
        let rounded = len
            .checked_next_multiple_of(Self::ALIGN)
            .unwrap_or(usize::MAX);
        // `rounded + ALIGN` bytes always contain an aligned window of
        // `rounded` bytes for any allocation address the allocator
        // hands out. The window is computed *after* the final
        // allocation: nothing ever grows this vector again, so the
        // data area cannot move under us.
        let storage = vec![0u8; rounded.saturating_add(Self::ALIGN)];
        let misaligned = storage.as_ptr() as usize % Self::ALIGN;
        let offset = (Self::ALIGN - misaligned) % Self::ALIGN;
        // By construction the allocation holds `rounded + ALIGN`
        // bytes, so `offset + rounded` can never exceed its length
        // and this plain end is in bounds; the saturating floor keeps
        // the range inside the slice even for a hypothetically
        // undersized allocation (never a panic).
        let end = storage.len().min(offset.saturating_add(rounded));
        Self {
            storage,
            window: offset..end,
        }
    }

    /// Room for data: the requested length rounded up to an
    /// [`AlignedBuf::ALIGN`] multiple — the length requests on a direct
    /// sink must be multiples of.
    ///
    /// Derived from the stored window on purpose: this is exactly what
    /// [`AlignedBuf::as_slice`] hands out, so a length that claims
    /// bytes the window does not contain is unrepresentable.
    #[must_use]
    pub fn len(&self) -> usize {
        self.window.len()
    }

    /// Whether the buffer carries no data window at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.window.start == self.window.end
    }

    /// The aligned window, shared view — the slice to hand to
    /// [`Sink::write_all_at`] on a direct sink.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // By construction the window lies completely inside `storage`
        // (an aligned offset plus a rounded length fits the
        // over-allocation), so the `get` result is always `Some`.
        // The fallback keeps the "no panic" rule even for a
        // hypothetical broken construction.
        self.storage.get(self.window.clone()).unwrap_or(&[])
    }

    /// The aligned window, mutable view — the slice to fill and then
    /// hand to [`Sink::write_all_at`] on a direct sink.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // Same construction guarantee as [`AlignedBuf::as_slice`].
        self.storage.get_mut(self.window.clone()).unwrap_or(&mut [])
    }

    /// Address of the aligned window. For direct I/O callers this is
    /// the pointer the kernel must see; the type guarantees its
    /// alignment.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}

impl Default for AlignedBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared plumbing: positional calls and the loops every sink drives.
// ---------------------------------------------------------------------------

/// The single-call positional I/O surface each backing store provides.
///
/// The loops below are written against this and nothing else, so the
/// file-backed sinks and the RAM sink drive exactly the same retry /
/// short-IO machinery.
trait Positional {
    /// One positional read: how many bytes landed, `0` only at end of
    /// store. Partial answers are expected; the loops drive them home.
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// One positional write: how many bytes left the caller, `0` only
    /// when nothing can go out (treated as end of store).
    fn write_once(&self, offset: u64, buf: &[u8]) -> io::Result<usize>;
}

impl Positional for File {
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        FileExt::read_at(self, buf, offset)
    }

    fn write_once(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        FileExt::write_at(self, buf, offset)
    }
}

impl Positional for Mutex<Vec<u8>> {
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let store = guard(self);
        let Ok(base) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(tail) = store.get(base..) else {
            return Ok(0);
        };
        let copied = buf.len().min(tail.len());
        buf[..copied].copy_from_slice(&tail[..copied]);
        Ok(copied)
    }

    fn write_once(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        let mut store = guard(self);
        let Ok(base) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(tail) = store.get_mut(base..) else {
            return Ok(0);
        };
        let copied = buf.len().min(tail.len());
        tail[..copied].copy_from_slice(&buf[..copied]);
        Ok(copied)
    }
}

/// A store guard that recovers from mutex poisoning instead of
/// propagating a panic storm: nothing in this module panics while
/// holding the guard, so poisoning means a non-module bug and the
/// recovery pattern `rufus-core::log` established still applies.
fn guard(store: &Mutex<Vec<u8>>) -> MutexGuard<'_, Vec<u8>> {
    store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Fill `buf` completely with positional reads from `store`, retrying
/// partial transfers and `EINTR`/`EAGAIN`; a surprise end of store is
/// its own error kind so the caller can produce the `short read`
/// message the S07 contract pins.
fn read_full<P: Positional + ?Sized>(store: &P, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        match store.read_once(offset + done as u64, &mut buf[done..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "positional read hit the end of the sink",
                ));
            }
            Ok(read) => done += read,
            Err(error) if is_retry(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Write `buf` completely with positional writes into `store`, same
/// retry rule as [`read_full`]; a write that makes no progress (the
/// sink went away or exactly zero room remains) fails like a read past
/// the end rather than looping forever. `Ok(0)` answers are retried a
/// bounded number of times (see [`WRITE_NO_PROGRESS_LIMIT`]) before
/// the failure verdict, so an implementation change that treats zero
/// progress as "retry" still terminates — and the review's
/// no-progress test cannot hang against the all-zero sink.
fn write_full<P: Positional + ?Sized>(store: &P, offset: u64, buf: &[u8]) -> io::Result<()> {
    let mut done = 0usize;
    // Consecutive zero-progress answers in a row; any real write
    // resets the count, so honest I/O never approaches the limit.
    let mut stalled = 0usize;
    while done < buf.len() {
        match store.write_once(offset + done as u64, &buf[done..]) {
            Ok(0) => {
                stalled += 1;
                if stalled > WRITE_NO_PROGRESS_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "positional write made no progress",
                    ));
                }
            }
            Ok(written) => {
                done += written;
                stalled = 0;
            }
            Err(error) if is_retry(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// How many consecutive no-progress (`Ok(0)`) positional writes the
/// write loop tolerates before [`write_full`] declares the write
/// stuck and fails. The S07 review's no-progress test relies on this
/// bound: without it, a sink that answers zero forever would spin the
/// loop indefinitely. Only *consecutive* zeros count, and a real write
/// resets the tally, so honest I/O never reaches the limit; sixty-four
/// rejects in a row are already past every transient 0-byte hiccup a
/// real device produces.
const WRITE_NO_PROGRESS_LIMIT: usize = 64;

/// `EINTR` and `EAGAIN` say "try that call again", nothing else does.
fn is_retry(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock)
}

/// Write `buf` in `chunk`-sized pieces through `piece`, asking
/// `cancelled()` before each piece. Cancelling stops *before* the
/// interrupted piece, so the counted progress is always a whole number
/// of pieces; completed runs count the full length.
///
/// The shared body of every [`Sink::write_all_at_cancellable`] — and,
/// with a never-cancelling closure and a maximum chunk, of
/// [`Sink::write_all_at`] too.
fn write_cancellable(
    offset: u64,
    buf: &[u8],
    chunk: usize,
    cancelled: &dyn Fn() -> bool,
    mut piece: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<u64> {
    if chunk == 0 {
        return Err(CoreError::invalid("write chunk size must be non-zero"));
    }
    let total = buf.len();
    let mut done = 0usize;
    while done < total {
        if cancelled() {
            return Ok(done as u64);
        }
        let piece_len = (total - done).min(chunk);
        piece(offset + done as u64, &buf[done..done + piece_len])?;
        done += piece_len;
    }
    Ok(total as u64)
}

/// Write zeroes over `[offset, offset + len)` in `FALLBACK_CHUNK`
/// pieces *reusing one aligned buffer* — the fallback for sinks whose
/// kernel does not offer the zero primitive. `len == 0` never reaches
/// it (the sinks treat that as invalid before calling).
fn fallback_zeroes(
    mut piece: impl FnMut(u64, &[u8]) -> Result<()>,
    offset: u64,
    len: u64,
) -> Result<()> {
    let mut zero = AlignedBuf::with_len(FALLBACK_CHUNK as usize);
    zero.as_mut_slice().fill(0);
    let mut pos = offset;
    let mut remaining = len;
    while remaining > 0 {
        let piece_len = remaining.min(FALLBACK_CHUNK);
        piece(pos, &zero.as_slice()[..piece_len as usize])?;
        pos += piece_len;
        remaining -= piece_len;
    }
    Ok(())
}

/// Shared bounds rule: `[offset, offset + len)` must lie inside `size`
/// with u64-safe arithmetic. The message names offset, length and size
/// so a log line can be read without further context.
fn check_window(offset: u64, len: u64, size: u64, verb: &str) -> Result<()> {
    match offset.checked_add(len) {
        Some(end) if end <= size => Ok(()),
        Some(end) => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, {end}) does not fit the sink size {size}"
        ))),
        None => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, ...) overflows past the sink size {size}"
        ))),
    }
}

/// Direct-sink rule: offsets, lengths and buffer addresses must line up
/// on [`AlignedBuf::ALIGN`], otherwise the kernel mis-executes — reject
/// instead of silently corrupting. `verb` labels the failing call (the
/// same rule guards reads; the failures just name what was asked).
fn check_direct(offset: u64, ptr: *const u8, len: usize, verb: &str) -> Result<()> {
    if !(ptr as usize).is_multiple_of(AlignedBuf::ALIGN)
        || !offset.is_multiple_of(AlignedBuf::ALIGN as u64)
        || !(len as u64).is_multiple_of(AlignedBuf::ALIGN as u64)
    {
        return Err(CoreError::invalid(format!(
            "unaligned O_DIRECT {verb}: offset {offset}, length {len}, buffer at {:#x}",
            ptr as usize
        )));
    }
    Ok(())
}

/// The syscalls whose errors mean "this driver does not provide the
/// zero/discard primitive": `EOPNOTSUPP`, `ENOTTY`, `EINVAL` — checked
/// by raw errno because `ENOTTY` has no dedicated [`io::ErrorKind`].
fn soft_ioctl_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOTTY | libc::EOPNOTSUPP)
    ) || matches!(
        error.kind(),
        ErrorKind::InvalidInput | ErrorKind::Unsupported
    )
}

/// Re-label a full-buffer read failure: a surprise end of store becomes
/// the S07 `short read` message (with the *requested* offset), any
/// other failure goes to `degrade` for the context the sink owns.
fn map_short_read(
    offset: u64,
    error: io::Error,
    degrade: impl FnOnce(io::Error) -> CoreError,
) -> CoreError {
    if error.kind() == ErrorKind::UnexpectedEof {
        return CoreError::invalid(format!("short read at offset {offset}"));
    }
    degrade(error)
}

/// Failures a RAM sink could raise are impossible in valid use (no
/// errno, no disk); a present one means a bug, so it is surfaced as a
/// plain description rather than a fabricated file path.
fn memory_error(error: io::Error) -> CoreError {
    CoreError::invalid(format!("memory sink failure: {error}"))
}

/// Map an open failure: `EBUSY` from the exclusive open is the
/// mounted-elsewhere verdict users must see verbatim; anything else
/// stays a plain I/O error with the node path attached.
fn open_stop(path: &Path, error: io::Error) -> CoreError {
    if error.kind() == ErrorKind::ResourceBusy {
        return CoreError::invalid(format!(
            "block device '{}' is busy: it is mounted or opened by another process \
             (O_EXCL refuses to share it) — unmount it or close the holder first",
            path.display()
        ));
    }
    CoreError::io(path, error)
}

/// Turn a `BLKRRPART` failure into a careful error: `EINVAL` is the
/// kernel's "cannot rescan this device" answer, and it has two
/// real-world causes — the device is mounted or otherwise in use, or
/// it was attached without partition scanning. Consumers need that
/// sentence, not an errno.
fn reread_error(path: &Path, error: io::Error) -> CoreError {
    if error.raw_os_error() == Some(libc::EINVAL) {
        return CoreError::invalid(format!(
            "the kernel cannot re-read the partition table on '{}': it is mounted or in use, \
             or the device has no partition scanning enabled",
            path.display()
        ));
    }
    CoreError::io(path, error)
}

// ---------------------------------------------------------------------------
// Sink: the contract, then the file-backed bodies, then the three sinks.
// ---------------------------------------------------------------------------

/// One opened sink the write pipeline drives (devices in part B, test
/// doubles everywhere else).
///
/// Shared contract for every implementation:
///
/// * windows must lie inside [`Sink::size`] — [`CoreError::invalid`]
///   with an offset-and-size message otherwise;
/// * reads and writes are exact — partial syscalls are retried
///   (`EINTR`/`EAGAIN` included) and short reads are reported, never
///   dressed up as success;
/// * [`write_all_at_cancellable`] stops on whole `chunk`-sized pieces,
///   returning the bytes written so far on cancellation and the full
///   length on completion;
/// * [`zero_range`] prefers the kernel primitive and falls back to
///   writing zeroes; `len == 0` is invalid;
/// * [`discard`] is best effort — the data of a non-supporting sink
///   simply stays and the call still reports [`Ok`];
/// * [`flush`] and [`reread_partitions`] work on every implementation.
pub trait Sink {
    /// Total writable extent in bytes.
    fn size(&self) -> u64;

    /// Whether the kernel accepted `O_DIRECT`: such sinks require
    /// [`AlignedBuf`]-shaped slices and aligned geometry and reject
    /// misaligned requests instead of hiding a copy.
    fn is_direct(&self) -> bool;

    /// Fill `buf` completely from `offset`, or report why not.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Write all of `buf` at `offset`, or report why not.
    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Write `buf` at `offset` in `chunk`-sized pieces, giving the
    /// caller the chance to abort between pieces: cancellation returns
    /// `Ok` with the bytes written so far — a whole number of pieces,
    /// nothing torn.
    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64>;

    /// Zero out `[offset, offset + len)` (`len == 0` invalid): kernel
    /// `BLKZEROOUT` when available, plain zero writes otherwise.
    fn zero_range(&self, offset: u64, len: u64) -> Result<()>;

    /// Suggest to the device that `[offset, offset + len)` be
    /// deallocated. Best effort by contract: no support means the data
    /// stays and the call reports [`Ok`] regardless.
    fn discard(&self, offset: u64, len: u64) -> Result<()>;

    /// Push any buffered bytes down (fsync on file-backed sinks).
    fn flush(&self) -> Result<()>;

    /// Ask the kernel for a fresh partition table view.
    fn reread_partitions(&self) -> Result<()>;
}

/// The file-backed half of [`BlockDevice`] and [`SparseFile`]: opened
/// descriptor, node path, extent and probe results, with one correct
/// body per [`Sink`] behaviour so the two sinks cannot drift apart.
#[derive(Debug)]
struct FileStore {
    /// The opened node (device or regular file).
    file: File,
    /// Where it was opened, for every error message.
    path: PathBuf,
    /// Extent in bytes, as the caller supplied it.
    size: u64,
    /// Whether the fd really runs with `O_DIRECT`: decided once at
    /// open time (yes for device nodes the kernel accepted the flag
    /// for, never for plain files), so the flag and the descriptor
    /// always agree.
    direct: bool,
}

impl FileStore {
    /// Total extent in bytes.
    fn size(&self) -> u64 {
        self.size
    }

    /// One validated piece write: reject misaligned direct geometry
    /// before touching the kernel, then loop the piece in.
    fn write_piece(&self, pos: u64, piece: &[u8]) -> Result<()> {
        if self.direct {
            check_direct(pos, piece.as_ptr(), piece.len(), "write")?;
        }
        write_full(&self.file, pos, piece).map_err(|error| CoreError::io(&self.path, error))
    }

    /// Exact positional read (see [`FileStore::write_piece`] for the
    /// alignment policy).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_window(offset, buf.len() as u64, self.size, "read")?;
        if self.direct {
            check_direct(offset, buf.as_ptr(), buf.len(), "read")?;
        }
        read_full(&self.file, offset, buf).map_err(|error| {
            map_short_read(offset, error, |error| CoreError::io(&self.path, error))
        })
    }

    /// Exact positional write over the whole buffer.
    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        check_window(offset, buf.len() as u64, self.size, "write")?;
        if self.direct {
            check_direct(offset, buf.as_ptr(), buf.len(), "write")?;
        }
        write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
            self.write_piece(pos, piece)
        })?;
        Ok(())
    }

    /// Chunked, cancellation-checked write over the same pieces; the
    /// whole-buffer checks ran here first so even an immediate
    /// cancellation reports validation errors, not a silent skip.
    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        check_window(offset, buf.len() as u64, self.size, "write")?;
        if self.direct {
            check_direct(offset, buf.as_ptr(), buf.len(), "write")?;
        }
        write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
            self.write_piece(pos, piece)
        })
    }

    /// `BLKZEROOUT` when the kernel offers it, aligned zero writes
    /// otherwise — the zero path every file-backed sink shares.
    fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
        check_window(offset, len, self.size, "zero")?;
        if len == 0 {
            return Err(CoreError::invalid("cannot zero a zero-length window"));
        }
        match ioctl::zero_out(&self.file, offset, len) {
            Ok(()) => Ok(()),
            Err(error) if soft_ioctl_error(&error) => {
                fallback_zeroes(|pos, piece| self.write_piece(pos, piece), offset, len)
            }
            Err(error) => Err(CoreError::io(&self.path, error)),
        }
    }

    /// `BLKDISCARD` where the kernel supports it; the documented
    /// best-effort rule turns every unsupported answer into `Ok`.
    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        check_window(offset, len, self.size, "discard")?;
        match ioctl::discard(&self.file, offset, len) {
            Ok(()) => Ok(()),
            // Best effort (Sink docs): without the primitive the kernel
            // simply keeps the old surface, so silence IS the contract.
            Err(error) if soft_ioctl_error(&error) => Ok(()),
            Err(error) => Err(CoreError::io(&self.path, error)),
        }
    }

    /// fsync the node.
    fn flush(&self) -> Result<()> {
        fsync(&self.file)
            .map_err(io::Error::from)
            .map_err(|error| CoreError::io(&self.path, error))
    }
}

/// An opened block-media sink: a kernel device node, or a regular file
/// standing in for one (tests, or `open` on plain files).
///
/// Geometry is *not* read from the fd (no extra ioctls here): the
/// caller who enumerated the device already carries
/// `size_bytes`/`sector_size`/`physical_sector_size` (S05
/// [`Device`](crate::model::Device)) and passes them through
/// [`BlockDevice::open_with`]. [`BlockDevice::open`] is the convenience
/// for regular-file and test use only.
///
/// `direct` means the kernel accepted `O_DIRECT` for the node: such a
/// sink demands [`AlignedBuf`]-shaped slices and
/// [`AlignedBuf::ALIGN`]-aligned offsets and lengths, rejecting
/// everything else with an `unaligned O_DIRECT ...` error instead of
/// corrupting quietly.
#[derive(Debug)]
pub struct BlockDevice {
    /// The opened node plus path/extent/probe facts.
    store: FileStore,
    /// Logical sector size, from the caller's sysfs read.
    logical: u32,
    /// Physical sector size, from the caller's sysfs read.
    physical: u32,
    /// Whether the node itself is a `b`-type device — partition
    /// rescanning only makes sense (and only works) on those.
    block: bool,
}

impl BlockDevice {
    /// Open `path` for positional write access with the sysfs geometry
    /// the enumeration step (`crate::sysfs`, `crate::inspect`) already
    /// holds: `size` in bytes plus logical/physical sector sizes (both
    /// must be non-zero).
    ///
    /// The open is `O_RDWR|O_EXCL|O_CLOEXEC|O_NOFOLLOW`: exclusive on
    /// purpose (nothing else should hold the device while it is about
    /// to be rewritten), with `EBUSY` mapped to a plain-language
    /// "mounted or held elsewhere" error. The node type is decided
    /// from metadata **before** opening: a regular file never gets
    /// `OFlags::DIRECT` at all — it opens buffered and [`Sink::is_direct`]
    /// reports `false`, because a kernel that accepted the flag on a
    /// plain file (ext4, xfs) would keep rejecting unaligned writes
    /// with `EINVAL` long after this sink claimed to be buffered.
    /// Device nodes are probed first: `O_DIRECT` tried, `EINVAL` from
    /// the kernel downgraded to a buffered descriptor and
    /// [`Sink::is_direct`] reports `false`.
    pub fn open_with(path: &Path, size: u64, logical: u32, physical: u32) -> Result<Self> {
        if logical == 0 || physical == 0 {
            return Err(CoreError::invalid(format!(
                "sector sizes must be non-zero: got logical {logical}, physical {physical}"
            )));
        }
        // What did the caller hand us? The node type comes from
        // metadata before any open flag is chosen, so the O_DIRECT
        // decision is made once and honestly — a regular file keeps
        // its buffered descriptor (the plain-file rule), while
        // everything else goes through the kernel probe below. The
        // stat fails first (and identically) for a missing node, so
        // the error text stays the one the opener produced before.
        let is_file = fs::metadata(path)
            .map(|meta| meta.is_file())
            .map_err(|error| CoreError::io(path, error))?;
        let oflags = OFlags::RDWR | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let (file, direct) = if is_file {
            // Regular file: buffered, unconditionally — O_DIRECT on a
            // plain file would silence nothing (no sector geometry)
            // and burden everything (alignment demands the kernel
            // keeps enforcing after this call).
            match open(path, oflags, Mode::empty()).map(File::from) {
                Ok(file) => (file, false),
                Err(error) => return Err(open_stop(path, io::Error::from(error))),
            }
        } else {
            match open(path, oflags | OFlags::DIRECT, Mode::empty()).map(File::from) {
                Ok(file) => (file, true),
                // EINVAL is the kernel's normal "this fs has no O_DIRECT"
                // answer; retry without the flag and record the downgrade.
                Err(error) if io::Error::from(error).kind() == ErrorKind::InvalidInput => {
                    match open(path, oflags, Mode::empty()).map(File::from) {
                        Ok(file) => (file, false),
                        Err(error) => return Err(open_stop(path, io::Error::from(error))),
                    }
                }
                Err(error) => return Err(open_stop(path, io::Error::from(error))),
            }
        };
        let meta = file
            .metadata()
            .map_err(|error| CoreError::io(path, error))?;
        let block = meta.file_type().is_block_device();
        Ok(Self {
            store: FileStore {
                file,
                path: path.to_path_buf(),
                size,
                direct,
            },
            logical,
            physical,
            block,
        })
    }

    /// Open `path` for tests and plain files: geometry comes from the
    /// file metadata (`len()`) and the 512/4096 sector defaults.
    ///
    /// **Regular-file and test use only** — a real block device must go
    /// through [`BlockDevice::open_with`] so the extent and sector
    /// sizes come from the sysfs facts, not from guesses.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path).map_err(|error| CoreError::io(path, error))?;
        Self::open_with(
            path,
            meta.len(),
            FALLBACK_LOGICAL_SECTOR,
            FALLBACK_PHYSICAL_SECTOR,
        )
    }

    /// Logical sector size the opener supplied (bytes, `> 0`).
    #[must_use]
    pub fn logical_sector_size(&self) -> u32 {
        self.logical
    }

    /// Physical sector size the opener supplied (bytes, `> 0`).
    #[must_use]
    pub fn physical_sector_size(&self) -> u32 {
        self.physical
    }
}

impl Sink for BlockDevice {
    fn size(&self) -> u64 {
        self.store.size()
    }

    fn is_direct(&self) -> bool {
        self.store.direct
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.store.read_at(offset, buf)
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.store.write_all_at(offset, buf)
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        self.store
            .write_all_at_cancellable(offset, buf, chunk, cancelled)
    }

    fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
        self.store.zero_range(offset, len)
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.store.discard(offset, len)
    }

    fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    fn reread_partitions(&self) -> Result<()> {
        if !self.block {
            // A stand-in file has no kernel partition table to rescan;
            // the no-op is the plain-file rule of the S07 contract.
            return Ok(());
        }
        ioctl::flush_buffers(&self.store.file)
            .map_err(|error| CoreError::io(&self.store.path, error))?;
        ioctl::reread_partitions(&self.store.file)
            .map_err(|error| reread_error(&self.store.path, error))
    }
}

/// A real, freshly created sparse file of `len` bytes — the file-backed
/// test double for paths that need a genuine fd (the write pipeline
/// exercises the same loops against the filesystem).
///
/// [`SparseFile::create`] opens with `create_new`: it never truncates
/// or reuses an existing file, so tests can hand it a fresh temp path
/// and know the content is zero-filled from `set_len` alone.
#[derive(Debug)]
pub struct SparseFile {
    /// The opened file plus path/extent facts (direct is always
    /// `false` there: created without O_DIRECT).
    store: FileStore,
}

impl SparseFile {
    /// Create a zero-filled sparse image of `len` bytes at `path`,
    /// failing when the path already exists (`create_new`).
    pub fn create(path: &Path, len: u64) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))?;
        file.set_len(len)
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Self {
            store: FileStore {
                file,
                path: path.to_path_buf(),
                size: len,
                direct: false,
            },
        })
    }
}

impl Sink for SparseFile {
    fn size(&self) -> u64 {
        self.store.size()
    }

    fn is_direct(&self) -> bool {
        self.store.direct
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.store.read_at(offset, buf)
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.store.write_all_at(offset, buf)
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        self.store
            .write_all_at_cancellable(offset, buf, chunk, cancelled)
    }

    fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
        self.store.zero_range(offset, len)
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.store.discard(offset, len)
    }

    fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    fn reread_partitions(&self) -> Result<()> {
        // A plain file has no kernel partition table; nothing to rescan.
        Ok(())
    }
}

/// A device image simulated in RAM — the zero-cost test double for
/// slices that must observe writes without a device, a file or a
/// kernel.
#[derive(Debug)]
pub struct MemorySink {
    /// The simulated media, zero-filled at [`MemorySink::new`].
    store: Mutex<Vec<u8>>,
    /// Always `false` from [`MemorySink::new`]; RAM needs no alignment
    /// story, the field only exists so `is_direct()` stays honest.
    direct: bool,
}

impl MemorySink {
    /// An empty, zero-filled image of `len` bytes.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            store: Mutex::new(vec![0u8; len]),
            direct: false,
        }
    }

    /// The image bytes as they stand right now (the "where did the
    /// write end up" mirror for assertions).
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        guard(&self.store).clone()
    }

    /// The one piece-write body the two write entry points share — the
    /// RAM twin of [`FileStore::write_piece`] but without an
    /// alignment gate (RAM never rejects geometry).
    fn write_piece(&self, pos: u64, piece: &[u8]) -> Result<()> {
        write_full(&self.store, pos, piece).map_err(memory_error)
    }
}

impl Sink for MemorySink {
    fn size(&self) -> u64 {
        guard(&self.store).len() as u64
    }

    fn is_direct(&self) -> bool {
        self.direct
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_window(offset, buf.len() as u64, self.size(), "read")?;
        read_full(&self.store, offset, buf)
            .map_err(|error| map_short_read(offset, error, memory_error))
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        check_window(offset, buf.len() as u64, self.size(), "write")?;
        write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
            self.write_piece(pos, piece)
        })?;
        Ok(())
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        check_window(offset, buf.len() as u64, self.size(), "write")?;
        write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
            self.write_piece(pos, piece)
        })
    }

    fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
        let mut store = guard(&self.store);
        check_window(offset, len, store.len() as u64, "zero")?;
        if len == 0 {
            return Err(CoreError::invalid("cannot zero a zero-length window"));
        }
        // The window was bounded against `store.len()` just above, so
        // both conversions are value-preserving on every supported
        // target; the guards keep the "no panic" rule regardless.
        let base = usize::try_from(offset)
            .map_err(|_| CoreError::invalid(format!("zero offset {offset} is out of range")))?;
        let length = usize::try_from(len).map_err(|_| {
            CoreError::invalid(format!("zero range of {len} bytes is out of range"))
        })?;
        let Some(tail) = store.get_mut(base..) else {
            return Err(CoreError::invalid(format!(
                "zero range at offset {offset} does not fit the sink size {}",
                store.len()
            )));
        };
        let Some(window) = tail.get_mut(..length) else {
            return Err(CoreError::invalid(format!(
                "zero range [{offset}, {}) does not fit the sink size {}",
                offset.saturating_add(len),
                store.len()
            )));
        };
        window.fill(0);
        Ok(())
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        // Best effort (Sink docs): RAM simulates a device without
        // deallocation support, so bounds are checked and the data
        // stays exactly where it is.
        check_window(offset, len, self.size(), "discard")?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        // Nothing between the RAM image and its readers; no-op.
        Ok(())
    }

    fn reread_partitions(&self) -> Result<()> {
        // RAM simulates a diskless device; no kernel table to rescan.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests: geometry, the shared loops through every sink, cancellation,
// the direct rule and the two real-fd doubles.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::io::ErrorKind;
    use std::sync::Mutex;

    use super::AlignedBuf;
    use super::BlockDevice;
    use super::CoreError;
    use super::FileStore;
    use super::MemorySink;
    use super::Result;
    use super::Sink;
    use super::SparseFile;
    use super::check_window;
    use super::fallback_zeroes;
    use super::read_full;
    use super::soft_ioctl_error;
    use super::write_cancellable;
    use super::write_full;

    /// Fill a fresh `Vec` with an easily recognized non-zero pattern.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251 + 1) as u8).collect()
    }

    /// A `BlockDevice` with its `direct` flag forced on for the
    /// alignment-rule tests, built by hand (the fields live in this
    /// module, so the construction needs no unsafe and no block
    /// device: the O_DIRECT rule is pure CPU-side validation ahead of
    /// the syscalls).
    fn direct_block_device(scratch: &tempfile::NamedTempFile) -> BlockDevice {
        BlockDevice {
            store: FileStore {
                file: scratch.reopen().expect("reopen scratch file"),
                path: scratch.path().to_path_buf(),
                size: 8192,
                direct: true,
            },
            logical: 512,
            physical: 4096,
            block: false,
        }
    }

    // ------------------------------------------------------------------
    // AlignedBuf
    // ------------------------------------------------------------------

    #[test]
    fn aligned_buffer_geometries_round_up_and_start_aligned() {
        let default = AlignedBuf::new();
        assert_eq!(default.len(), AlignedBuf::DEFAULT_LEN, "new() capacity");
        assert_eq!(
            default.as_ptr() as usize % AlignedBuf::ALIGN,
            0,
            "default window starts aligned"
        );
        assert!(!default.is_empty());

        assert_eq!(
            AlignedBuf::with_len(1).len(),
            AlignedBuf::ALIGN,
            "one byte rounds up to a full unit"
        );
        assert_eq!(
            AlignedBuf::with_len(AlignedBuf::ALIGN * 2 - 1).len(),
            AlignedBuf::ALIGN * 2,
            "odd sizes round up, never down"
        );
        assert_eq!(
            AlignedBuf::with_len(AlignedBuf::ALIGN * 3).len(),
            AlignedBuf::ALIGN * 3,
            "aligned sizes keep their length"
        );
    }

    #[test]
    fn aligned_mut_slice_covers_exactly_the_data_window() {
        let mut default = AlignedBuf::new();
        assert_eq!(default.as_mut_slice().len(), default.len());

        let mut one = AlignedBuf::with_len(1);
        one.as_mut_slice()[0] = 0x42;
        assert_eq!(
            one.as_slice()[0],
            0x42,
            "the rounded window itself is usable"
        );
        assert_eq!(one.as_mut_slice().len(), one.len());

        let mut empty = AlignedBuf::with_len(0);
        assert!(empty.is_empty());
        assert_eq!(empty.as_slice(), &[] as &[u8], "empty window");
        assert_eq!(
            empty.as_ptr() as usize % AlignedBuf::ALIGN,
            0,
            "even the empty buffer is aligned-safe"
        );
        assert_eq!(empty.as_mut_slice().len(), 0);
    }

    // ------------------------------------------------------------------
    // Shared plumbing (bounds rule, read/write loops)
    // ------------------------------------------------------------------

    #[test]
    fn window_rule_rejects_overflow_and_past_the_end() {
        assert!(check_window(0, 100, 100, "read").is_ok());
        assert!(check_window(100, 0, 100, "read").is_ok());
        let overflow = check_window(u64::MAX - 1, 2, 100, "read").expect_err("overflows");
        assert!(
            overflow
                .to_string()
                .contains("overflows past the sink size 100"),
            "{overflow}"
        );
        let beyond = check_window(90, 20, 100, "write").expect_err("past the end");
        assert!(
            beyond
                .to_string()
                .contains("[90, 110) does not fit the sink size 100"),
            "{beyond}"
        );
    }

    // ------------------------------------------------------------------
    // MemorySink
    // ------------------------------------------------------------------

    #[test]
    fn memory_sink_round_trip_at_a_nonzero_offset() {
        let sink = MemorySink::new(4096 + 257);
        let payload = pattern(257);
        sink.write_all_at(4096, &payload)
            .expect("in-bounds write at offset 4096");
        let mut back = vec![0u8; payload.len()];
        sink.read_at(4096, &mut back)
            .expect("in-bounds read at offset 4096");
        assert_eq!(back, payload, "the window survives both crossings");
        assert_eq!(sink.size(), 4096 + 257);
        assert!(!sink.is_direct(), "RAM never needs the alignment story");
    }

    #[test]
    fn memory_sink_zero_range_hits_only_the_requested_window() {
        let sink = MemorySink::new(100);
        sink.write_all_at(0, &[7u8; 100]).expect("seed");
        sink.zero_range(40, 20).expect("zero window");
        let image = sink.snapshot();
        assert!(image[..40].iter().all(|&byte| byte == 7), "before");
        assert!(image[40..60].iter().all(|&byte| byte == 0), "window");
        assert!(image[60..].iter().all(|&byte| byte == 7), "after");
    }

    #[test]
    fn memory_sink_rejects_windows_outside_the_size() {
        let sink = MemorySink::new(100);
        let lone = vec![0u8; 1];

        let read = sink
            .read_at(101, &mut lone.clone())
            .expect_err("read past end");
        assert!(read.to_string().contains("101"), "{read}");

        let write = sink.write_all_at(101, &lone).expect_err("write past end");
        assert!(write.to_string().contains("101"), "{write}");

        let zero = sink.zero_range(101, 1).expect_err("zero past end");
        assert!(zero.to_string().contains("101"), "{zero}");

        let zero_len = sink.zero_range(50, 0).expect_err("zero of nothing");
        assert!(zero_len.to_string().contains("zero-length"), "{zero_len}");

        let overflow = sink
            .read_at(u64::MAX, &mut lone.clone())
            .expect_err("u64 overflow");
        assert!(
            overflow.to_string().contains("18446744073709551615"),
            "{overflow}"
        );
    }

    #[test]
    fn memory_sink_discard_is_the_documented_best_effort_noop() {
        let sink = MemorySink::new(160);
        sink.write_all_at(0, &[9u8; 160]).expect("seed");
        sink.discard(0, 160).expect("discard never fails here");
        assert_eq!(
            sink.snapshot(),
            vec![9u8; 160],
            "the discarded data stays: documented best effort"
        );
        sink.flush().expect("RAM flush is a no-op");
        sink.reread_partitions().expect("no kernel table to rescan");
    }

    // ------------------------------------------------------------------
    // Shared loops through a throttled store (short writes)
    // ------------------------------------------------------------------

    /// A [`Sink`]-and-`Positional` double whose positional write
    /// refuses to take more than `quota` bytes per call: the shape the
    /// kernel can present through a slow USB endpoint, so
    /// `write_all_at` must prove it loops until everything landed.
    struct ShortSink {
        store: Mutex<Vec<u8>>,
        quota: usize,
    }

    impl ShortSink {
        fn new(len: usize, quota: usize) -> Self {
            assert!(quota > 0, "a zero quota would make no progress");
            Self {
                store: Mutex::new(vec![0u8; len]),
                quota,
            }
        }
    }

    impl super::Positional for ShortSink {
        fn read_once(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            // Reads behave normally; only the write side is throttled.
            <Mutex<Vec<u8>> as super::Positional>::read_once(&self.store, offset, buf)
        }

        fn write_once(&self, offset: u64, buf: &[u8]) -> std::io::Result<usize> {
            // At most `quota` bytes per call; the shared full-write
            // loop must drive the rest home.
            let piece = buf.len().min(self.quota);
            if piece == 0 {
                return Ok(0);
            }
            <Mutex<Vec<u8>> as super::Positional>::write_once(&self.store, offset, &buf[..piece])
        }
    }

    impl Sink for ShortSink {
        fn size(&self) -> u64 {
            super::guard(&self.store).len() as u64
        }

        fn is_direct(&self) -> bool {
            false
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "read")?;
            read_full(self, offset, buf).map_err(super::memory_error)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })?;
            Ok(())
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })
        }

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "zero")?;
            if len == 0 {
                return Err(CoreError::invalid("cannot zero a zero-length window"));
            }
            fallback_zeroes(
                |pos, piece| write_full(self, pos, piece).map_err(super::memory_error),
                offset,
                len,
            )
        }

        fn discard(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "discard")?;
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }

        fn reread_partitions(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_all_at_loops_past_slow_short_writes() {
        let sink = ShortSink::new(1024, 7);
        let payload = pattern(1024);
        sink.write_all_at(0, &payload)
            .expect("the short-write loop must complete");
        let mut back = vec![0u8; payload.len()];
        sink.read_at(0, &mut back).expect("read back");
        assert_eq!(back, payload, "every quota-limited piece landed");
    }

    // ------------------------------------------------------------------
    // Error paths the S07 review asked to pin (mutation-tested holes)
    // ------------------------------------------------------------------

    /// A [`Sink`]/[`Positional`] double whose positional write answers
    /// `Ok(0)` forever — the shape of a device that can accept no
    /// bytes at all (media gone, queue clogged). Only the bounded
    /// no-progress rule of [`super::WRITE_NO_PROGRESS_LIMIT`] lets
    /// this test terminate: `write_all_at` must come back with the
    /// no-progress error, neither spinning forever nor reporting
    /// success. Insurance against that bound ever disappearing: after
    /// [`STALL_ALARM`] zero-progress answers the double panics, so a
    /// regression fails loudly instead of hanging the test run.
    struct StalledSink {
        store: Mutex<Vec<u8>>,
        /// Zero-progress answers handed out so far; the alarm keeps a
        /// removed-bound regression loud (see the doc above).
        stalls: Cell<u64>,
    }

    /// Zero-progress answers [`StalledSink`] hands out before it
    /// panics. Deliberately far past the production bound
    /// ([`WRITE_NO_PROGRESS_LIMIT`](super::WRITE_NO_PROGRESS_LIMIT)): the
    /// bound is what must end the write, and this panic is only the
    /// loud fallback that turns a bound-removal regression into a
    /// failing test instead of a hang.
    const STALL_ALARM: u64 = 10_000;

    impl StalledSink {
        /// The image bytes as they stand (the "nothing was written"
        /// mirror for the assertion below).
        fn snapshot(&self) -> Vec<u8> {
            super::guard(&self.store).clone()
        }
    }

    impl super::Positional for StalledSink {
        fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            <Mutex<Vec<u8>> as super::Positional>::read_once(&self.store, offset, buf)
        }

        fn write_once(&self, _offset: u64, _buf: &[u8]) -> io::Result<usize> {
            let stalls = self.stalls.get() + 1;
            self.stalls.set(stalls);
            if stalls > STALL_ALARM {
                panic!(
                    "the writer never gave up on a stalled sink after {stalls} \
                     zero-progress answers"
                );
            }
            Ok(0)
        }
    }

    impl Sink for StalledSink {
        fn size(&self) -> u64 {
            super::guard(&self.store).len() as u64
        }

        fn is_direct(&self) -> bool {
            false
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "read")?;
            read_full(self, offset, buf).map_err(super::memory_error)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })?;
            Ok(())
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })
        }

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "zero")?;
            if len == 0 {
                return Err(CoreError::invalid("cannot zero a zero-length window"));
            }
            fallback_zeroes(
                |pos, piece| write_full(self, pos, piece).map_err(super::memory_error),
                offset,
                len,
            )
        }

        fn discard(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "discard")?;
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }

        fn reread_partitions(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_all_at_fails_when_the_sink_never_makes_progress() {
        let sink = StalledSink {
            store: Mutex::new(vec![0u8; 1024]),
            stalls: Cell::new(0),
        };
        let payload = pattern(64);
        let error = sink
            .write_all_at(0, &payload)
            .expect_err("a sink that accepts nothing cannot succeed");
        assert!(error.to_string().contains("no progress"), "{error}");
        let image = sink.snapshot();
        assert!(
            image.iter().all(|&byte| byte == 0),
            "nothing may be claimed as written into the stalled media"
        );
    }

    /// A [`Sink`] whose declared extent lies larger than its backing
    /// store — the shape `read_full`'s end-of-store branch was built
    /// for (the medium shrank under a mis-declared geometry). Every
    /// other sink reports itself at its true store length, so
    /// `check_window` rejects such windows before the loop could see
    /// the hole; only this lie reaches it.
    struct TruncatedStore {
        store: Mutex<Vec<u8>>,
        declared: u64,
    }

    impl super::Positional for TruncatedStore {
        fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            <Mutex<Vec<u8>> as super::Positional>::read_once(&self.store, offset, buf)
        }

        fn write_once(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
            <Mutex<Vec<u8>> as super::Positional>::write_once(&self.store, offset, buf)
        }
    }

    impl Sink for TruncatedStore {
        fn size(&self) -> u64 {
            self.declared
        }

        fn is_direct(&self) -> bool {
            false
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.declared, "read")?;
            read_full(self, offset, buf)
                .map_err(|error| super::map_short_read(offset, error, super::memory_error))
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.declared, "write")?;
            write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })?;
            Ok(())
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            check_window(offset, buf.len() as u64, self.declared, "write")?;
            write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })
        }

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.declared, "zero")?;
            if len == 0 {
                return Err(CoreError::invalid("cannot zero a zero-length window"));
            }
            fallback_zeroes(
                |pos, piece| write_full(self, pos, piece).map_err(super::memory_error),
                offset,
                len,
            )
        }

        fn discard(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.declared, "discard")?;
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }

        fn reread_partitions(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn read_full_reports_a_short_read_when_the_store_ends_early() {
        let sink = TruncatedStore {
            store: Mutex::new(vec![0u8; 100]),
            declared: 200,
        };
        // The window fits the *declared* extent but the backing store
        // ends at 100: the loop reads 10 bytes, then the next read
        // answers 0 — end of store — and the S07 contract demands the
        // short-read verdict, not a truncated success.
        let mut window = vec![0u8; 20];
        let error = sink
            .read_at(90, &mut window)
            .expect_err("the store ends at 100, not at the declared 200");
        assert!(
            error.to_string().contains("short read at offset 90"),
            "{error}"
        );
    }

    /// A [`Sink`]/[`Positional`] double whose write path throws
    /// `Interrupted`, then `WouldBlock`, and only then behaves like
    /// the store behind it: the retry loop must absorb both signals
    /// and land the write, and the test counts how many retries it
    /// burned.
    struct RetrySink {
        store: Mutex<Vec<u8>>,
        /// Scripted write answers popped front-first before the real
        /// store answers; empty script means plain store behaviour.
        script: Mutex<VecDeque<io::Error>>,
        /// How many `Err(retryable)` answers the double handed out.
        retries: Cell<usize>,
    }

    impl RetrySink {
        fn new(len: usize, script: VecDeque<io::Error>) -> Self {
            Self {
                store: Mutex::new(vec![0u8; len]),
                script: Mutex::new(script),
                retries: Cell::new(0),
            }
        }
    }

    impl super::Positional for RetrySink {
        fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            <Mutex<Vec<u8>> as super::Positional>::read_once(&self.store, offset, buf)
        }

        fn write_once(&self, offset: u64, buf: &[u8]) -> io::Result<usize> {
            // Same poisoning-recovery rule as `super::guard`: nothing
            // below panics while the script's guard is held.
            let mut script = self
                .script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(error) = script.pop_front() {
                if super::is_retry(&error) {
                    self.retries.set(self.retries.get() + 1);
                }
                drop(script);
                return Err(error);
            }
            drop(script);
            <Mutex<Vec<u8>> as super::Positional>::write_once(&self.store, offset, buf)
        }
    }

    impl Sink for RetrySink {
        fn size(&self) -> u64 {
            super::guard(&self.store).len() as u64
        }

        fn is_direct(&self) -> bool {
            false
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "read")?;
            read_full(self, offset, buf).map_err(super::memory_error)
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, usize::MAX, &|| false, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })?;
            Ok(())
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<u64> {
            check_window(offset, buf.len() as u64, self.size(), "write")?;
            write_cancellable(offset, buf, chunk, cancelled, |pos, piece| {
                write_full(self, pos, piece).map_err(super::memory_error)
            })
        }

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "zero")?;
            if len == 0 {
                return Err(CoreError::invalid("cannot zero a zero-length window"));
            }
            fallback_zeroes(
                |pos, piece| write_full(self, pos, piece).map_err(super::memory_error),
                offset,
                len,
            )
        }

        fn discard(&self, offset: u64, len: u64) -> Result<()> {
            check_window(offset, len, self.size(), "discard")?;
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }

        fn reread_partitions(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_all_at_retries_interrupted_and_would_block_then_completes() {
        let sink = RetrySink::new(
            1024,
            VecDeque::from([
                io::Error::from(ErrorKind::Interrupted),
                io::Error::from(ErrorKind::WouldBlock),
            ]),
        );
        let payload = pattern(512);
        sink.write_all_at(0, &payload)
            .expect("EINTR and EAGAIN are the try-again pair, not failures");
        assert_eq!(sink.retries.get(), 2, "both retry signals were absorbed");
        assert!(
            sink.script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty(),
            "the script was consumed to the end"
        );
        let mut back = vec![0u8; payload.len()];
        sink.read_at(0, &mut back).expect("read back");
        assert_eq!(back, payload, "the write completed after the retries");
    }

    #[test]
    fn soft_ioctl_error_accepts_only_the_unsupported_family() {
        // Behavioural note (S07 review): the EINVAL branch of
        // `zero_range`'s fallback cannot be injected without a real
        // block device — a regular-file fd answers `ENOTTY` to all
        // range ioctls, and `EINVAL` comes out of device drivers for
        // misaligned or out-of-range windows. The documented fallback
        // through a soft error is behaviourally covered by
        // `sparse_file_round_trip_with_zero_fallback` (ENOTTY), so
        // this decision function is the one pure unit that pins which
        // errnos — `EINVAL` included — fall through to that fallback
        // and which errors stay real failures.
        for raw in [libc::EINVAL, libc::ENOTTY, libc::EOPNOTSUPP] {
            let error = io::Error::from_raw_os_error(raw);
            assert!(
                soft_ioctl_error(&error),
                "{raw} is a documented soft-ioctl errno"
            );
        }
        for raw in [libc::EIO, libc::ENOSPC, libc::EBADF, libc::EACCES] {
            let error = io::Error::from_raw_os_error(raw);
            assert!(
                !soft_ioctl_error(&error),
                "{raw} is a real failure, not a missing primitive"
            );
        }
        // Kinds without an errno — the shape an injected error has.
        assert!(soft_ioctl_error(&io::Error::from(ErrorKind::InvalidInput)));
        assert!(soft_ioctl_error(&io::Error::from(ErrorKind::Unsupported)));
        assert!(
            !soft_ioctl_error(&io::Error::from(ErrorKind::Interrupted)),
            "Interrupted is a retry signal, not a missing primitive"
        );
        assert!(!soft_ioctl_error(&io::Error::from(ErrorKind::NotFound)));
    }

    // ------------------------------------------------------------------
    // Cancellable writes
    // ------------------------------------------------------------------

    #[test]
    fn cancellable_write_stops_after_whole_chunks_and_leaves_the_rest() {
        let sink = MemorySink::new(1024);
        let payload = pattern(1024);
        let checks = Cell::new(0u32);
        let written = sink
            .write_all_at_cancellable(0, &payload, 256, &|| {
                let seen = checks.get() + 1;
                checks.set(seen);
                seen > 2
            })
            .expect("cancellation reports progress, not failure");
        assert_eq!(written, 512, "stopped after two whole 256-byte chunks");
        let image = sink.snapshot();
        assert_eq!(&image[..512], &payload[..512], "the chunks landed");
        assert!(
            image[512..].iter().all(|&byte| byte == 0),
            "the rest stays untouched"
        );
    }

    #[test]
    fn cancellable_write_completes_when_never_cancelled() {
        let sink = MemorySink::new(1024);
        let payload = pattern(1024);
        let written = sink
            .write_all_at_cancellable(0, &payload, 256, &|| false)
            .expect("uncancelled run completes");
        assert_eq!(written, 1024, "the full length is the completion count");
        assert_eq!(sink.snapshot(), payload);
    }

    #[test]
    fn cancellable_write_rejects_a_zero_chunk() {
        let sink = MemorySink::new(1024);
        let payload = pattern(1024);
        let error = sink
            .write_all_at_cancellable(0, &payload, 0, &|| false)
            .expect_err("a zero chunk cannot make progress");
        assert!(error.to_string().contains("chunk"), "{error}");
    }

    // ------------------------------------------------------------------
    // The O_DIRECT alignment rule (hand-built device, no unsafe)
    // ------------------------------------------------------------------

    #[test]
    fn direct_device_rejects_misaligned_requests_and_accepts_aligned_ones() {
        let scratch = tempfile::NamedTempFile::new().expect("scratch file");
        let dev = direct_block_device(&scratch);

        let mut aligned = AlignedBuf::with_len(AlignedBuf::ALIGN);
        aligned.as_mut_slice().fill(0xA5);

        // Unaligned offset: 512 is a legitimate device offset on a
        // 512e disk, but the direct rule demands multiples of 4096.
        let offset_error = dev
            .write_all_at(512, aligned.as_slice())
            .expect_err("offset 512 is not a multiple of 4096");
        assert!(
            offset_error
                .to_string()
                .contains("unaligned O_DIRECT write"),
            "{offset_error}"
        );
        assert!(
            offset_error.to_string().contains("offset 512"),
            "{offset_error}"
        );

        // Unaligned length: aligned base pointer, length 512.
        let len_error = dev
            .write_all_at(0, &aligned.as_slice()[..512])
            .expect_err("length 512 is not a multiple of 4096");
        assert!(
            len_error.to_string().contains("unaligned O_DIRECT write"),
            "{len_error}"
        );

        // Unaligned buffer pointer: a *full-length* window shifted one
        // byte off the aligned base. The length stays a multiple of
        // `[AlignedBuf::ALIGN]` and the offset is aligned too, so the
        // pointer — not the length or the offset — is the rule under
        // test here. (A second buffer holds the extra byte the shift
        // needs; slicing the one-window buffer `[1..]` would produce
        // 4095 bytes and fail on the length rule first, which is the
        // rereview's vacuous-check trap.)
        let mut shifted = AlignedBuf::with_len(AlignedBuf::ALIGN * 2);
        shifted.as_mut_slice().fill(0x5A);
        let ptr_error = dev
            .write_all_at(4096, &shifted.as_slice()[1..4097])
            .expect_err("a shifted full-length window is not aligned");
        assert!(
            ptr_error.to_string().contains("unaligned O_DIRECT write"),
            "{ptr_error}"
        );

        // Reads obey the same rule.
        let mut window = AlignedBuf::with_len(AlignedBuf::ALIGN);
        let read_error = dev
            .read_at(512, window.as_mut_slice())
            .expect_err("reads use the same alignment rule");
        assert!(
            read_error.to_string().contains("unaligned O_DIRECT read"),
            "{read_error}"
        );

        // And the aligned happy path goes through unchanged.
        dev.write_all_at(0, aligned.as_slice())
            .expect("aligned write on the direct sink");
        let mut back = AlignedBuf::with_len(AlignedBuf::ALIGN);
        dev.read_at(0, back.as_mut_slice())
            .expect("aligned read on the direct sink");
        assert_eq!(
            back.as_slice(),
            vec![0xA5u8; AlignedBuf::ALIGN].as_slice(),
            "the aligned round trip kept the bytes"
        );
    }

    // ------------------------------------------------------------------
    // BlockDevice convenience constructor
    // ------------------------------------------------------------------

    #[test]
    fn block_device_open_defaults_to_plain_file_geometry() {
        let scratch = tempfile::NamedTempFile::new().expect("scratch file");
        fs::write(scratch.path(), vec![0u8; 4096]).expect("seed plain file");
        let dev = BlockDevice::open(scratch.path()).expect("plain file opens");
        assert_eq!(dev.size(), 4096, "extent comes from the file metadata");
        assert_eq!(dev.logical_sector_size(), 512);
        assert_eq!(dev.physical_sector_size(), 4096);
        assert!(!dev.is_direct(), "plain files always run buffered");

        let payload = pattern(64);
        dev.write_all_at(1024, &payload).expect("plain write");
        let mut back = vec![0u8; 64];
        dev.read_at(1024, &mut back).expect("plain read");
        assert_eq!(back, payload);
        dev.flush().expect("fsync on the scratch file");
    }

    #[test]
    fn open_with_rejects_zero_sector_sizes() {
        let scratch = tempfile::NamedTempFile::new().expect("scratch file");
        let logical = BlockDevice::open_with(scratch.path(), 4096, 0, 512)
            .expect_err("a zero logical sector size cannot be used");
        assert!(logical.to_string().contains("sector"), "{logical}");
        let physical = BlockDevice::open_with(scratch.path(), 4096, 512, 0)
            .expect_err("a zero physical sector size cannot be used");
        assert!(physical.to_string().contains("sector"), "{physical}");
    }

    // ------------------------------------------------------------------
    // Regression (S07 review blocker 1): a regular file must never be
    // *opened* with O_DIRECT. The pre-review code probed O_DIRECT
    // first and only masked the reported flag afterwards, so on a
    // filesystem that accepts the flag for files (ext4, xfs) the fd
    // stayed direct and unaligned writes failed with EINVAL while
    // `is_direct()` claimed "buffered".
    // ------------------------------------------------------------------

    #[test]
    fn plain_files_open_buffered_even_when_the_fs_offers_o_direct() {
        // The scratch dir honors TMPDIR, so under the reviewer's ext4
        // scratch this is the exact failing surface, not a tmpfs
        // accident.
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("plain.img");
        fs::write(&path, vec![0u8; 8192]).expect("seed plain file");

        let dev = BlockDevice::open_with(&path, 8192, 512, 4096)
            .expect("plain file opens with the caller's geometry");
        assert!(
            !dev.is_direct(),
            "regular files are buffered, period — O_DIRECT may never reach their fd"
        );

        // Deliberately unaligned end to end: offset and length both
        // miss `AlignedBuf::ALIGN`. With an O_DIRECT fd this write
        // answers EINVAL (the review repro); buffered, it is plain I/O.
        let payload = pattern(1024);
        dev.write_all_at(1000, &payload)
            .expect("unaligned writes on a plain file are ordinary I/O");
        let mut back = vec![0u8; 1024];
        dev.read_at(1000, &mut back).expect("read the write back");
        assert_eq!(back, payload, "the unaligned round trip kept the bytes");
        dev.flush().expect("fsync on the scratch file");

        // A second open of the same file must reach the same verdict:
        // the buffered plain-file rule is a property of the node, not
        // of one lucky open.
        let second = BlockDevice::open_with(&path, 8192, 512, 4096).expect("reopen the plain file");
        assert!(!second.is_direct(), "the second open reports buffered too");
        second
            .read_at(1000, &mut back)
            .expect("the reopened handle reads the same bytes");
        assert_eq!(back, payload);
    }

    // ------------------------------------------------------------------
    // SparseFile
    // ------------------------------------------------------------------

    #[test]
    fn sparse_file_round_trip_with_zero_fallback() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("image.bin");
        let sink = SparseFile::create(&path, 65536).expect("created");
        assert_eq!(sink.size(), 65536);
        assert!(!sink.is_direct(), "sparse files are created buffered");

        let payload = pattern(65536);
        sink.write_all_at(0, &payload).expect("full-image write");
        let mut back = vec![0u8; 65536];
        sink.read_at(0, &mut back).expect("full-image read");
        assert_eq!(back, payload);

        // The fd of a plain file answers BLKZEROOUT with ENOTTY, so the
        // zero request must ride the write fallback and hit exactly the
        // window.
        sink.zero_range(16384, 8192)
            .expect("zero through the write fallback");
        let mut window = vec![0u8; 8192];
        sink.read_at(16384, &mut window).expect("window read");
        assert_eq!(window, vec![0u8; 8192], "the window is zero");
        let mut before = vec![0u8; 16384];
        sink.read_at(0, &mut before).expect("before read");
        assert_eq!(before, payload[..16384], "data before the window stays");
        let mut after = vec![0u8; 65536 - 24576];
        sink.read_at(24576, &mut after).expect("after read");
        assert_eq!(after, payload[24576..], "data after the window stays");

        // Discard on a plain file is the documented best-effort no-op
        // (the ioctl answers ENOTTY and the sink keeps its data).
        sink.discard(4096, 1024)
            .expect("discard on a plain file never fails");
        let mut keep = vec![0u8; 1024];
        sink.read_at(4096, &mut keep).expect("post-discard read");
        assert_eq!(keep, payload[4096..5120], "the data stayed put");

        sink.flush().expect("fsync on a regular file");
        sink.reread_partitions()
            .expect("a plain file has no kernel table to rescan");
    }
}
