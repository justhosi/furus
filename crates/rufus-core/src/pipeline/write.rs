//! The write step: stream the image to the device.
//!
//! Layout choice: one file with an inline `mod raw` for the
//! straight-through path, an inline `mod compressed` for the host
//! decompressor path, and the [`Copy`](rufus_proto::WriteMode::Copy)
//! arm below (a source builder plus the mount/walk/release flow — no
//! submodule, it delegates the tree work to [`crate::copy`]).
//!
//! Evidence ported here (`0x140010a40` is the write thread: open the
//! image, allocate a write buffer — 256 KiB, `0x40000`, on the
//! compressed path — read a chunk, write it, advance the image
//! position): both paths read and write in [`CHUNK`]-sized pieces with
//! the Rufus error shapes (`Write error at
//! sector`, `Wrote %d bytes, expected %d bytes`, `Read error`, stale
//! layout, plus `Writing compressed image:` / `Could not write
//! compressed image: %lld` for the tool path) mapped onto [`CoreError`]
//! refusals that name their numbers.
//! `0x140010830` bounds a fill buffer at 64 KiB sectors and 1 GiB total;
//! sparse writing is slice 6, not this one.
//!
//! Trust boundary: the image path comes from the plan, and it names
//! whatever the planner was pointed at — a regular file, a FIFO, or a
//! device node. The CLI inspects (size, hash) the path before planning
//! and the loop re-checks the length at open, but a swapped or
//! streaming source between those checks is outside what this step can
//! see; the read-back verify pass is what catches it.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;
use rufus_proto::WriteMode;

use crate::copy::CopyOptions;
use crate::copy::IsoSource;
use crate::copy::Source as TreeSource;
use crate::copy::UdfSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::FileVolume;
use crate::iso::IsoReader;
use crate::pipeline::decompress::ToolStream;
use crate::pipeline::decompress::kind_name;
use crate::pipeline::decompress::tool_for;
use crate::pipeline::event::Event;
use crate::pipeline::event::Reporter;
use crate::pipeline::opener::MountedPartition;
use crate::pipeline::steps::RunContext;
use crate::udf::UdfReader;

/// Chunk size in bytes (256 KiB, the compressed path's `0x40000`
/// buffer): both loops below share it.
pub(crate) const CHUNK: usize = 256 * 1024;

/// Device slack past the image that triggers the large-drive warning
/// (4 GiB): beyond this the stick dwarfs the image, and the run says so
/// instead of silently leaving tens of gigabytes untouched.
pub(crate) const LARGE_DRIVE_SLACK: u64 = 4 * 1024 * 1024 * 1024;

/// Slowest progress cadence: a [`Progress`](Event::Progress) goes out at
/// most this often, plus always the final one at 100 %. Shared with
/// the bad-blocks scan, which keeps the same cadence.
pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Exponential moving average of write throughput in bytes per
/// second: `rate = alpha * sample + (1 - alpha) * rate` with
/// [`EMA_ALPHA`], the first sample setting the rate outright. The
/// average deliberately covers the read and the write of each chunk
/// (per-chunk wall time): on a real device the write dominates, and
/// smoothing both keeps one number for the event stream. Elapsed
/// time arrives as an explicit [`Duration`] so the arithmetic is
/// testable without sleeping. Shared with the bad-blocks scan, which
/// folds each scanned piece the same way.
pub(crate) struct RateEma {
    rate: f64,
}

/// Smoothing factor: each chunk moves the average a quarter of the
/// way to its sample — responsive within a few chunks, stable
/// across one slow outlier.
const EMA_ALPHA: f64 = 0.25;

impl RateEma {
    pub(crate) fn new() -> Self {
        Self { rate: 0.0 }
    }

    /// Fold one chunk's bytes and wall time into the average. A zero
    /// elapsed time carries no information (it would divide by
    /// zero), so the sample is dropped and the rate stands.
    pub(crate) fn observe(&mut self, bytes: u64, elapsed: Duration) {
        if elapsed.is_zero() {
            return;
        }
        let sample = bytes as f64 / elapsed.as_secs_f64();
        if self.rate == 0.0 {
            self.rate = sample;
        } else {
            self.rate = EMA_ALPHA * sample + (1.0 - EMA_ALPHA) * self.rate;
        }
    }

    /// Current rate, rounded down to whole bytes per second.
    pub(crate) fn bytes_per_second(&self) -> u64 {
        self.rate as u64
    }

    /// Seconds to drain `remaining` at the current rate, rounded up;
    /// `None` while the rate is still zero.
    pub(crate) fn eta_seconds(&self, remaining: u64) -> Option<u64> {
        if self.rate <= 0.0 {
            return None;
        }
        Some((remaining as f64 / self.rate).ceil() as u64)
    }
}

/// Warn when the device dwarfs the image: returns the warning text
/// when `device_size` exceeds `image_size` by more than
/// [`LARGE_DRIVE_SLACK`], so the exact boundary is unit-testable
/// without a 4 GiB fixture.
fn large_drive_warning(device_size: u64, image_size: u64) -> Option<String> {
    if device_size.saturating_sub(image_size) > LARGE_DRIVE_SLACK {
        Some(format!(
            "write: large device of {device_size} bytes for a {image_size} byte image, {} bytes left untouched",
            device_size.saturating_sub(image_size)
        ))
    } else {
        None
    }
}

/// The write loop's byte source: the raw image file or a host
/// decompressor's stdout pipe (see the `decompress` module).
enum Source {
    /// Straight-through reads with `read_exact` semantics.
    File { file: File, path: String },
    /// A pulled pipe; EOF arrives as a short read.
    Pipe(ToolStream),
}

impl Source {
    /// Fill `buf`: the file arm reads exactly (a short read before EOF
    /// is the Rufus `Read error` shape, naming the offset); the pipe
    /// arm pulls until full or EOF, returning what arrived (`0` only
    /// at EOF).
    fn fill(&mut self, buf: &mut [u8], offset: u64) -> Result<usize> {
        match self {
            Source::File { file, path } => {
                file.read_exact(buf).map_err(|error| {
                    CoreError::io(
                        &*path,
                        std::io::Error::new(
                            error.kind(),
                            format!("read error at image offset {offset}: {error}"),
                        ),
                    )
                })?;
                Ok(buf.len())
            }
            Source::Pipe(stream) => {
                let mut filled = 0;
                while filled < buf.len() {
                    let read = stream.read(&mut buf[filled..])?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                Ok(filled)
            }
        }
    }

    /// Reap the source: the pipe arm waits on the child and refuses on
    /// a non-zero exit (even after a clean EOF — EOF only closed the
    /// pipe, not the verdict); the file arm has nothing to reap.
    fn finish(&mut self) -> Result<()> {
        match self {
            Source::File { .. } => Ok(()),
            Source::Pipe(stream) => stream.finish(),
        }
    }

    /// Abandon the source: the pipe arm kills and reaps the child; the
    /// file arm has nothing running.
    fn cancel(&mut self) {
        match self {
            Source::File { .. } => {}
            Source::Pipe(stream) => stream.cancel(),
        }
    }
}

/// The shared open-time guards for both sources: the real file length
/// must match the plan's `size_bytes`, and a file already larger than
/// the target refuses before any step writes. For a piped image the
/// length is the archive (compressed) size, and the refusal says so:
/// an archive larger than the target can never decode onto it, while a
/// fitting archive may still overflow mid-stream — the streaming guard
/// in [`pump`] is authoritative, this check is the fast path. The
/// large-device warning fires on the file length too — for a piped
/// image the decoded size is unknowable upfront, so the compressed
/// size is the honest basis. Returns the file length the loops run
/// against.
fn check_image(
    ctx: &mut RunContext<'_>,
    image: &ImageRef,
    size: u64,
    compressed: bool,
) -> Result<u64> {
    let len = std::fs::metadata(&image.path)
        .map_err(|source| CoreError::io(&image.path, source))?
        .len();
    if len != image.size_bytes {
        return Err(CoreError::invalid(format!(
            "image file '{}' is {len} bytes but the plan describes {} bytes: refusing to write a different file",
            image.path, image.size_bytes
        )));
    }
    if len > size {
        if compressed {
            return Err(CoreError::invalid(format!(
                "archive of {len} bytes (compressed) does not fit the {size} byte device: refusing to start the write"
            )));
        }
        return Err(CoreError::invalid(format!(
            "image of {len} bytes does not fit the {size} byte device: refusing to start the write"
        )));
    }
    if let Some(warning) = large_drive_warning(size, len) {
        ctx.reporter.event(Event::Message {
            level: "warn",
            text: warning,
        });
    }
    Ok(len)
}

/// Linux `EIO` (5): the device reported a media error. A named
/// constant rather than `libc` (which `rufus-core` does not depend on,
/// and must not — see the crate's dependency discipline); Linux-only
/// by design, from the Linux UAPI, like the rest of this pipeline.
const EIO: i32 = 5;
/// Linux `ENOSPC` (28): no space left. Retryable: thin-provisioned and
/// quirky USB bridges report it transiently.
const ENOSPC: i32 = 28;

/// True only for I/O failures worth retrying: `EIO` or `ENOSPC` by raw
/// code. An `Io` error without a raw code (a portable failure with no
/// errno behind it) is not retryable — without a code there is nothing
/// to classify by. Cancellation, validation, impossible counts and
/// tool failures all fail fast.
fn retryable(error: &CoreError) -> bool {
    match error {
        CoreError::Io { source, .. } => {
            matches!(source.raw_os_error(), Some(EIO) | Some(ENOSPC))
        }
        _ => false,
    }
}

/// The per-attempt retry notice: 1-based attempt ordinal, attempt
/// budget, offset, error, and the coming delay. Emitted for every
/// failure a retry follows; the terminal failure returns its error
/// silently (the reset messages or the run report cover it). The
/// budget counts the initial attempt plus [`RunOptions::retries`]
/// retries — a USB reset may still buy one more attempt after it
/// (see [`write_chunk`](super::write_chunk)), so the total is worded
/// as what it is: the attempts before any USB reset. The shape
/// mirrors the reference (`0x140010a40` logs `Retrying in %d
/// seconds...` with 5 after each `Write error at sector %lld: %s`);
/// the offset here is a byte offset, not a sector number, because the
/// pipeline addresses the device in bytes.
fn retry_message(
    op: &str,
    offset: u64,
    attempt: u32,
    total: u32,
    error: &CoreError,
    delay: Duration,
) -> String {
    format!(
        "{op} error at offset {offset} (attempt {attempt} of {total} before any USB reset): {error}; retrying in {} seconds",
        delay.as_secs()
    )
}

/// Delay slices for [`sleep_cancellable`]: the cancel probe is
/// consulted this often while a retry delay elapses.
const SLEEP_SLICE: Duration = Duration::from_millis(100);

/// Sleep `delay` in [`SLEEP_SLICE`] slices, consulting `cancelled`
/// between slices: a Ctrl-C during a long retry delay returns
/// [`Cancelled`](CoreError::Cancelled) promptly instead of waiting
/// the full delay out. A set probe refuses even for a zero delay,
/// like the check-then-sleep this replaces.
fn sleep_cancellable(delay: Duration, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let mut remaining = delay;
    while !remaining.is_zero() {
        let slice = remaining.min(SLEEP_SLICE);
        std::thread::sleep(slice);
        if cancelled() {
            return Err(CoreError::Cancelled);
        }
        remaining = remaining.saturating_sub(slice);
    }
    Ok(())
}

/// Flush best effort before a retry: a flush failure is a warning, not
/// fatal — the flush is hygiene before the re-attempt, not the write
/// itself. The reference (`0x140010a40`) instead restores the stream
/// position before retrying (`SetFilePointerEx`, refused as `Write
/// error: Could not reset position - %s` after the `WARNING: Unable to
/// rewind image position - wrong data might be copied!` open-time
/// guard): this pipeline needs no repositioning because every attempt
/// addresses the same explicit offset, so the flush is the whole
/// between-attempt recovery.
fn flush_best_effort(ctx: &mut RunContext<'_>, offset: u64) {
    if let Err(error) = ctx.device().and_then(|target| target.flush()) {
        ctx.reporter.event(Event::Message {
            level: "warn",
            text: format!("write retry flush failed at offset {offset}: {error}; continuing"),
        });
    }
}

/// Re-read the device size after a failed attempt: if the device no
/// longer holds the chunk, retrying is pointless — refuse naming the
/// new size and the offset. The analogue of the reference's drive
/// layout refresh (`0x140010a40` ends the run with `Could not refresh
/// drive layout: %s` when the rescan fails): a device that vanished or
/// shrank under the write is observed here, before the next attempt,
/// rather than after the run. The re-read is genuinely live on
/// file-backed stores (the store re-stats on every `size` call); on
/// block devices the enumerated extent is stable, so the check is a
/// no-op safeguard there.
fn recheck_size(ctx: &mut RunContext<'_>, offset: u64, len: u64) -> Result<u64> {
    let size = ctx.device()?.size();
    if offset.checked_add(len).is_some_and(|end| end > size) {
        return Err(CoreError::invalid(format!(
            "device shrank to {size} bytes during write retries: refusing chunk at offset {offset} ({len} bytes); the device no longer holds it"
        )));
    }
    Ok(size)
}

/// Run the once-per-chunk USB reset after the retry budget is spent:
/// `true` means the device was reset and the chunk deserves one more
/// attempt; `false` means give up with the original error. Exactly one
/// `Message` names the outcome either way; a reset failure never
/// replaces the write error the run reports.
fn attempt_usb_reset(ctx: &mut RunContext<'_>) -> bool {
    match ctx.opener.reset_device() {
        Ok(true) => {
            ctx.reporter.event(Event::Message {
                level: "warn",
                text: "USB device was reset after write errors; retrying the failed chunk"
                    .to_string(),
            });
            true
        }
        Ok(false) => {
            ctx.reporter.event(Event::Message {
                level: "warn",
                text: "no USB reset was possible for this device; reporting the write error"
                    .to_string(),
            });
            false
        }
        Err(error) => {
            ctx.reporter.event(Event::Message {
                level: "warn",
                text: format!("USB reset failed: {error}; reporting the original write error"),
            });
            false
        }
    }
}

/// Write one `chunk` at `done` through the cancellable primitive,
/// folding the sample into `ema`: a short count reads as cancellation
/// (a target that reports full while swallowing bytes cannot be
/// detected here, which is why the read-back verify exists —
/// the honest form of Rufus's `Wrote %d bytes, expected %d bytes`
/// check), a count past the chunk as a faulty target refusing by name
/// with both numbers. Shared by the straight and sparse loops so the
/// rules cannot drift.
fn write_piece(
    ctx: &mut RunContext<'_>,
    chunk: &[u8],
    done: u64,
    cancelled: &dyn Fn() -> bool,
    ema: &mut RateEma,
) -> Result<u64> {
    let chunk_started = Instant::now();
    let written = ctx
        .device()?
        .write_all_at_cancellable(done, chunk, CHUNK, cancelled)?;
    let read = chunk.len() as u64;
    if written < read {
        return Err(CoreError::Cancelled);
    }
    if written > read {
        return Err(CoreError::invalid(format!(
            "target reported {written} bytes written for a {read} byte chunk at offset {done}: refusing an impossible count"
        )));
    }
    ema.observe(read, chunk_started.elapsed());
    Ok(written)
}

/// Zero one window with the reference retry policy, mirroring
/// [`write_chunk`]: one `zero_range` call per attempt (cancellable
/// between sub-chunks inside), the same warn/flush/size/sleep/reset
/// flow on a retryable failure. Shared policy, separate loop — the
/// success shapes differ (`()` vs bytes written) and the attempt
/// itself is one call either way.
fn zero_chunk(
    ctx: &mut RunContext<'_>,
    offset: u64,
    len: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let options = ctx.options;
    let total = options.retries.saturating_add(1);
    let mut performed: u32 = 0;
    let mut did_reset = false;
    loop {
        match ctx.device()?.zero_range(offset, len, cancelled) {
            Ok(()) => return Ok(()),
            Err(error) if !retryable(&error) => return Err(error),
            Err(error) => {
                let attempt = performed.saturating_add(1);
                if performed < options.retries {
                    ctx.reporter.event(Event::Message {
                        level: "warn",
                        text: retry_message(
                            "zero",
                            offset,
                            attempt,
                            total,
                            &error,
                            options.retry_delay,
                        ),
                    });
                    flush_best_effort(ctx, offset);
                    recheck_size(ctx, offset, len)?;
                    sleep_cancellable(options.retry_delay, cancelled)?;
                    performed += 1;
                    continue;
                }
                if options.reset_usb && !did_reset {
                    did_reset = true;
                    if attempt_usb_reset(ctx) {
                        if cancelled() {
                            return Err(CoreError::Cancelled);
                        }
                        continue;
                    }
                }
                return Err(error);
            }
        }
    }
}

/// Write one chunk with the reference retry policy (`0x140010a40`):
/// the initial attempt plus [`RunOptions::retries`] retries — the
/// reference gives up with `if (3 < uVar4)`, three retries, four tries
/// total (five when the post-reset attempt fires, which is why the
/// per-attempt notice counts its total "before any USB reset"). On a retryable failure the loop warns (attempt, offset,
/// error), flushes best effort, re-reads the device size (a vanished
/// device refuses at once), honours cancellation, sleeps
/// [`RunOptions::retry_delay`], and retries the same offset. The loop
/// retries only the failing chunk — never a chunk that already
/// succeeded — and there is no partial-chunk bookkeeping because
/// `write_all_at` is all-or-error. After the budget is spent (and only
/// then, and only with [`RunOptions::reset_usb` set) one USB reset
/// buys exactly one more attempt. The last error returns unwrapped:
/// [`run`](super::run) adds the single `Step` wrapper.
fn write_chunk(
    ctx: &mut RunContext<'_>,
    offset: u64,
    chunk: &[u8],
    cancelled: &dyn Fn() -> bool,
    ema: &mut RateEma,
) -> Result<u64> {
    let options = ctx.options;
    let total = options.retries.saturating_add(1);
    let mut performed: u32 = 0;
    let mut did_reset = false;
    loop {
        match write_piece(ctx, chunk, offset, cancelled, ema) {
            Ok(written) => return Ok(written),
            Err(error) if !retryable(&error) => return Err(error),
            Err(error) => {
                let attempt = performed.saturating_add(1);
                if performed < options.retries {
                    ctx.reporter.event(Event::Message {
                        level: "warn",
                        text: retry_message(
                            "write",
                            offset,
                            attempt,
                            total,
                            &error,
                            options.retry_delay,
                        ),
                    });
                    flush_best_effort(ctx, offset);
                    recheck_size(ctx, offset, chunk.len() as u64)?;
                    sleep_cancellable(options.retry_delay, cancelled)?;
                    performed += 1;
                    continue;
                }
                if options.reset_usb && !did_reset {
                    did_reset = true;
                    if attempt_usb_reset(ctx) {
                        if cancelled() {
                            return Err(CoreError::Cancelled);
                        }
                        continue;
                    }
                }
                return Err(error);
            }
        }
    }
}

/// Emit one [`Progress`](Event::Progress) for `step` unless
/// throttled: at most every [`PROGRESS_INTERVAL`], plus always when
/// `force` (the final sample of a loop). `total` rides along unchanged
/// — `Some` length for sized streams, `None` while a decoded size is
/// still unknown. `step` is usually `"write"`; the read-back verify
/// reports `"verify"` and the surface scan `"badblocks"`, event-level
/// pseudo-steps that are not plan steps (see
/// [`step_name`](super::step_name), which stays unchanged).
pub(crate) fn emit_progress(
    ctx: &mut RunContext<'_>,
    step: &'static str,
    done: u64,
    total: Option<u64>,
    ema: &RateEma,
    last_emit: &mut Instant,
    force: bool,
) {
    emit_progress_to(&mut *ctx.reporter, step, done, total, ema, last_emit, force);
}

/// The reporter half of [`emit_progress`]: the same cadence for
/// producers that own no [`RunContext`] (the copy walk's
/// [`CopyProgress`] bridge), so every producer throttles alike.
fn emit_progress_to(
    reporter: &mut dyn Reporter,
    step: &'static str,
    done: u64,
    total: Option<u64>,
    ema: &RateEma,
    last_emit: &mut Instant,
    force: bool,
) {
    if !force && last_emit.elapsed() < PROGRESS_INTERVAL {
        return;
    }
    *last_emit = Instant::now();
    reporter.event(Event::Progress {
        step,
        done,
        total,
        bytes_per_second: ema.bytes_per_second(),
        eta_seconds: match total {
            Some(len) => ema.eta_seconds(len.saturating_sub(done)),
            None => None,
        },
    });
}
/// Stream `source` to the device in [`CHUNK`]-sized pieces, returning
/// the bytes written with the loop's rate average. `total` is the raw
/// file length (every event carries it, the last at `done == total`)
/// or `None` for a piped stream (every intermediate carries `None` —
/// the decoded size is unknowable without decoding twice — and the
/// caller emits the one final `Some(done)` once EOF makes it known).
/// Cancellation kills the source first (reaping a piped child) and
/// refuses bare [`Cancelled`](CoreError::Cancelled); a chunk that
/// would cross the device end kills the source and refuses naming both
/// counts instead of writing past it.
fn pump(
    ctx: &mut RunContext<'_>,
    source: &mut Source,
    total: Option<u64>,
    size: u64,
) -> Result<(u64, RateEma)> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    let mut ema = RateEma::new();
    let mut last_emit = Instant::now();
    loop {
        if total.is_some_and(|len| done >= len) {
            break;
        }
        // Copy the probe out first: the device borrow below rules out
        // holding another `ctx` borrow across the call. A set flag
        // kills a piped child before refusing, so no decompressor
        // outlives its run; checking once per chunk is the whole
        // cancellation cadence — a source stalled inside `fill` (a
        // decompressor producing nothing) stalls cancellation with it
        // until it produces more or exits.
        let cancelled = ctx.cancelled;
        if cancelled() {
            source.cancel();
            return Err(CoreError::Cancelled);
        }
        let want = total
            .map(|len| (len - done).min(CHUNK as u64) as usize)
            .unwrap_or(CHUNK);
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| CoreError::invalid("write chunk window runs past its buffer"))?;
        let read = source.fill(chunk, done)?;
        if read == 0 {
            // EOF: only the unknown-total stream can end here (the
            // file arm reads exactly or errors), so the loop is over.
            break;
        }
        let end = done.checked_add(read as u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "write offset {done} plus a {read} byte chunk overflows"
            ))
        })?;
        if end > size {
            // The archive decodes past the target: kill the child and
            // refuse naming what the stream produced and what fits.
            // Nothing past `size` is ever written, so the tail logic
            // below cannot corrupt beyond the device.
            source.cancel();
            return Err(CoreError::invalid(format!(
                "decompressed image of at least {end} bytes does not fit the {size} byte device: refusing before the target overflows"
            )));
        }
        let chunk = chunk
            .get(..read)
            .ok_or_else(|| CoreError::invalid("write chunk window runs past its buffer"))?;
        let written = write_chunk(ctx, done, chunk, cancelled, &mut ema)?;
        done = done.saturating_add(written);
        emit_progress(
            ctx,
            "write",
            done,
            total,
            &ema,
            &mut last_emit,
            total.is_some_and(|len| done >= len),
        );
    }
    Ok((done, ema))
}

/// Zero the tail from `done` up to the next sector boundary — never
/// the whole remaining device, whose tail is the plan's business:
/// zeroing tens of gigabytes because of a small image would be data
/// loss twice over. Clamped to the device (an exactly device-sized but
/// unaligned image has no room past itself) and skipped for a zero
/// sector size — then flush and rescan: the run's epilogue for both
/// sources.
fn finish_write(
    ctx: &mut RunContext<'_>,
    done: u64,
    size: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let sector = u64::from(ctx.device()?.sector_size());
    if sector != 0 && !done.is_multiple_of(sector) {
        let end = (done / sector + 1).saturating_mul(sector).min(size);
        if end > done {
            ctx.device()?.zero_range(done, end - done, cancelled)?;
        }
    }
    ctx.device()?.flush()?;
    ctx.device()?.reread_partitions()?;
    Ok(())
}

/// Fill `buf` from `file` at `offset`: a short read before EOF is
/// the Rufus `Read error` shape, naming path and offset. Shared by
/// the sparse data runs and the verify mismatch locator.
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64, path: &str) -> Result<()> {
    use std::os::unix::fs::FileExt as _;

    let mut filled = 0usize;
    while filled < buf.len() {
        let window = buf
            .get_mut(filled..)
            .ok_or_else(|| CoreError::invalid("sparse read window runs past its buffer"))?;
        match file.read_at(window, offset + filled as u64) {
            Ok(0) => {
                return Err(CoreError::io(
                    path,
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("read error at image offset {offset}: unexpected end of file"),
                    ),
                ));
            }
            Ok(read) => filled += read,
            Err(error) => {
                return Err(CoreError::io(
                    path,
                    std::io::Error::new(
                        error.kind(),
                        format!("read error at image offset {offset}: {error}"),
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Run the write step for `mode` over `image`: `Dd` streams through
/// [`raw`] (every other [`ImageKind`] stays raw) or through
/// [`compressed`] when [`tool_for`] names a host decompressor, then —
/// for raw images only — reads the bytes back when `verify` is set;
/// [`Copy`](rufus_proto::WriteMode::Copy) copies the image's file
/// tree onto the freshly formatted data partition (see [`run_copy`]).
/// `filesystem` is the plan's filesystem: only the `Copy` arm reads
/// it (for the mount and the FAT32 pre-flight).
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &WriteMode,
    image: &ImageRef,
    filesystem: &Filesystem,
) -> Result<()> {
    match mode {
        WriteMode::Dd => {
            let verify = ctx.options.verify;
            // A plan with an empty digest refuses before any I/O: there
            // is nothing to compare against (`rufus plan` always fills
            // it, so this is a hand-written plan), and a hand-edited
            // plan wastes no write finding that out.
            if verify && image.sha256.is_empty() {
                return Err(CoreError::invalid(
                    "plan carries no digest to verify against: refusing to compare",
                ));
            }
            let size = ctx.device()?.size();
            let tool = tool_for(&image.kind);
            let len = check_image(ctx, image, size, tool.is_some())?;
            match tool {
                Some(tool) => {
                    if verify {
                        // The plan digest covers the archive, not the
                        // decoded stream, so there is nothing honest to
                        // compare: one warning, then the write as usual.
                        ctx.reporter.event(Event::Message {
                            level: "warn",
                            text: format!(
                                "verify of a {} image is skipped: the plan digest covers the compressed archive, not the decoded stream",
                                kind_name(&image.kind)
                            ),
                        });
                    }
                    compressed::run(ctx, image, tool, size)
                }
                None => {
                    raw::run(ctx, image, len, size)?;
                    if verify {
                        verify_target(ctx, image)?;
                    }
                    Ok(())
                }
            }
        }
        WriteMode::Copy => run_copy(ctx, image, filesystem),
    }
}

/// Refuse image kinds with no tree reader before the image file is
/// even opened: the WIM and disk-container kinds name the reader the
/// later slices still owe ([`NotImplemented`](CoreError::NotImplemented),
/// one static string each), while compressed archives and unknown
/// kinds refuse as invalid input naming the kind. `Iso` and `Raw`
/// pass through to the source builder in [`run_copy`].
fn refuse_unsupported_kind(kind: &ImageKind) -> Result<()> {
    match kind {
        ImageKind::Iso | ImageKind::Raw => Ok(()),
        ImageKind::Wim => Err(CoreError::NotImplemented {
            what: "copy of a wim image (the wim reader arrives in a later slice)",
        }),
        ImageKind::Vhd => Err(CoreError::NotImplemented {
            what: "copy of a vhd image (the vhd reader arrives in a later slice)",
        }),
        ImageKind::Vhdx => Err(CoreError::NotImplemented {
            what: "copy of a vhdx image (the vhdx reader arrives in a later slice)",
        }),
        ImageKind::Ffu => Err(CoreError::NotImplemented {
            what: "copy of an ffu image (the ffu reader arrives in a later slice)",
        }),
        ImageKind::Qcow2 => Err(CoreError::NotImplemented {
            what: "copy of a qcow2 image (the qcow2 reader arrives in a later slice)",
        }),
        ImageKind::Pe => Err(CoreError::NotImplemented {
            what: "copy of a pe image (the pe reader arrives in a later slice)",
        }),
        ImageKind::Gzip | ImageKind::Xz | ImageKind::Bzip2 | ImageKind::Zstd => {
            Err(CoreError::invalid(format!(
                "copy refuses a {} image: a compressed archive cannot be walked as a tree without decoding it first",
                kind_name(kind)
            )))
        }
        ImageKind::Unknown => Err(CoreError::invalid(
            "copy refuses an image of unknown kind: it names no readable file tree",
        )),
    }
}

/// The [`crate::copy::Progress`] bridge to the run's event stream:
/// every walk report becomes a step-`"write"` [`Event::Progress`]
/// rated by the shared [`RateEma`] (no second estimator), and every
/// walk warning becomes an unchanged `"warn"`
/// [`Message`](Event::Message). Reports throttle through
/// [`emit_progress_to`] at the pipeline's [`PROGRESS_INTERVAL`]
/// cadence (plus always the final one), so a large tree costs a
/// handful of lines, not one per 128 KiB chunk. `last_emit` is the
/// throttle clock alone: `last` stays the EMA sampler and must see
/// every report, throttled or not.
struct CopyProgress<'r> {
    reporter: &'r mut dyn Reporter,
    ema: RateEma,
    last: Instant,
    last_emit: Instant,
    done: u64,
}

impl<'r> CopyProgress<'r> {
    fn new(reporter: &'r mut dyn Reporter) -> Self {
        let now = Instant::now();
        Self {
            reporter,
            ema: RateEma::new(),
            last: now,
            last_emit: now,
            done: 0,
        }
    }
}

impl crate::copy::Progress for CopyProgress<'_> {
    fn report(&mut self, done_bytes: u64, total_bytes: u64) {
        let now = Instant::now();
        if done_bytes > self.done {
            self.ema
                .observe(done_bytes - self.done, now.duration_since(self.last));
        }
        self.last = now;
        self.done = done_bytes;
        emit_progress_to(
            self.reporter,
            "write",
            done_bytes,
            Some(total_bytes),
            &self.ema,
            &mut self.last_emit,
            done_bytes >= total_bytes,
        );
    }

    fn warn(&mut self, text: &str) {
        self.reporter.event(Event::Message {
            level: "warn",
            text: text.to_string(),
        });
    }
}

/// Release `mounted` after a failed pre-flight or walk: a release
/// failure warns naming both errors, while the run still reports the
/// error that matters (the earlier one, never the teardown's). The
/// warn path itself (a failure plus a failed release) is implemented
/// but not exercised by a test — no fake mount fails its release.
fn release_after_failure(
    ctx: &mut RunContext<'_>,
    mounted: &mut dyn MountedPartition,
    during: &str,
) {
    if let Err(error) = mounted.release() {
        ctx.reporter.event(Event::Message {
            level: "warn",
            text: format!(
                "mount release failed after {during}: {error}; reporting the earlier error"
            ),
        });
    }
}

/// Copy the image's file tree onto the freshly formatted data
/// partition. The order below is the contract, and it reads in
/// order: build the tree source first (a malformed image never
/// mounts anything), mount through the opener, read the free space,
/// walk the tree, then release the mount.
///
/// Source by [`ImageKind`]: `Iso` opens through [`IsoReader`] plus
/// [`IsoSource`]; `Raw` (a pure-UDF image carries no `CD001`, so it
/// detects as `Raw`) opens through [`UdfReader`] plus [`UdfSource`],
/// refusing — naming the kind and carrying the UDF reader's message
/// — when it is neither an ISO9660 nor a UDF tree. The `Raw` UDF
/// path is tested end to end on a synthetic UDF 2.01 volume built
/// in-tree (`copy_walks_a_udf_tree_onto_the_mount`), and the
/// neither-ISO-nor-UDF failure branch is tested too (a zeroed image,
/// and a UDF volume with a corrupt NSR sector). Still untested: UDF
/// volumes written by real tools (`mkudffs` or a Windows writer, see
/// the reader's own sample notes), the 2048-byte block size, multi-
/// extent or long-named entries, and the reserve-sequence fallback;
/// the copy tests only ever see the hand-encoded fixture. Every other kind refused earlier in
/// [`refuse_unsupported_kind`], before the image file was even
/// opened.
///
/// [`CopyOptions`]: `free_bytes` is the mount's own reading (the copy
/// refuses up front when the tree does not fit), `replacer` stays
/// `None` (the bootloader replacement table is the next slice's
/// work, so every file copies verbatim here), and `fat32_limit` is
/// set for `Fat32` targets. Cancellation passes `ctx.cancelled`
/// straight through to the walk. Release rule: the mount is always
/// released — a failed walk returns the walk error (a release failure
/// only warns), while a release failure after a good walk returns
/// the release error.
fn run_copy(ctx: &mut RunContext<'_>, image: &ImageRef, filesystem: &Filesystem) -> Result<()> {
    refuse_unsupported_kind(&image.kind)?;
    let volume = FileVolume::open(Path::new(&image.path))?;
    let source: Box<dyn TreeSource> = match &image.kind {
        ImageKind::Iso => Box::new(IsoSource::new(IsoReader::open(Box::new(volume))?)),
        ImageKind::Raw => match UdfReader::open(Box::new(volume)) {
            Ok(reader) => Box::new(UdfSource::new(reader)),
            Err(udf_error) => {
                return Err(CoreError::invalid(format!(
                    "copy refuses a raw image: it is neither an ISO9660 nor a UDF tree (UDF open failed: {udf_error})"
                )));
            }
        },
        // Every other kind refused above; this names the kind rather
        // than assuming the match is exhaustive forever.
        other => {
            return Err(CoreError::invalid(format!(
                "copy refuses an image of kind '{}': no tree reader takes it",
                kind_name(other)
            )));
        }
    };
    let mut mounted = ctx.opener.mount_partition(filesystem)?;
    run_copy_mounted(ctx, image, filesystem, &*source, mounted.as_mut())
}

/// The mounted half of [`run_copy`]: pre-flight the mount's free
/// space, walk the tree under [`CopyProgress`], then release the
/// mount on every path (see [`run_copy`] for the release rule). On
/// success the release lands before the completion line, so a failed
/// release returns without printing `copied ...`.
/// Factored out so tests can drive the mount and release flow with a
/// source no image builds (say one huge file for the FAT32
/// pre-flight) without a real image or a real mount.
fn run_copy_mounted(
    ctx: &mut RunContext<'_>,
    image: &ImageRef,
    filesystem: &Filesystem,
    source: &dyn TreeSource,
    mounted: &mut dyn MountedPartition,
) -> Result<()> {
    let free = match mounted.free_bytes() {
        Ok(free) => free,
        Err(error) => {
            release_after_failure(ctx, mounted, "the free-space check");
            return Err(error);
        }
    };
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!(
            "copying '{}' ({}) to the mounted data partition",
            image.path,
            kind_name(&image.kind)
        ),
    });
    let options = CopyOptions {
        free_bytes: Some(free),
        // No bootloader replacement table yet: the next slice wires
        // it in, so every file copies verbatim here.
        replacer: None,
        fat32_limit: matches!(filesystem, Filesystem::Fat32),
    };
    let cancelled = ctx.cancelled;
    let summary = {
        let mut progress = CopyProgress::new(&mut *ctx.reporter);
        crate::copy::walk(source, mounted.path(), &options, &mut progress, cancelled)
    };
    match summary {
        Ok(summary) => {
            mounted.release()?;
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!(
                    "copied {} files in {} directories ({} bytes), {} renamed",
                    summary.files, summary.directories, summary.bytes, summary.renamed
                ),
            });
            Ok(())
        }
        Err(error) => {
            release_after_failure(ctx, mounted, "the copy");
            Err(error)
        }
    }
}

/// Read the first `image.size_bytes` bytes back off the target in
/// [`CHUNK`]-sized pieces, hash them (SHA-256, lowercase hex, like the
/// plan digest), and compare case-insensitively. Sparse writes verify
/// the same way: the target holds the image's logical bytes (holes
/// zeroed), so the digest matches the file's own bytes. (An empty
/// digest refuses earlier, in [`run`], before any I/O.)
/// The mismatch locator never opens a path that is not a regular file
/// (see [`locate_mismatch`]). Progress runs
/// under the event-level `"verify"` pseudo-step — not a plan step (see
/// [`step_name`](super::step_name)) — at the usual cadence plus one
/// final event; a `Message` opens and closes the pass. Cancellation is
/// checked between chunks and honoured, never reporting success.
fn verify_target(ctx: &mut RunContext<'_>, image: &ImageRef) -> Result<()> {
    use sha2::Digest as _;

    let len = image.size_bytes;
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!("verifying {len} bytes against the plan digest"),
    });
    if len == 0 {
        // As in the write arms: one zero event, so "done instantly"
        // reads apart from "never reported".
        ctx.reporter.event(Event::Progress {
            step: "verify",
            done: 0,
            total: Some(0),
            bytes_per_second: 0,
            eta_seconds: None,
        });
    }
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut ema = RateEma::new();
    let mut last_emit = Instant::now();
    let mut done = 0u64;
    while done < len {
        let cancelled = ctx.cancelled;
        if cancelled() {
            return Err(CoreError::Cancelled);
        }
        let want = (len - done).min(CHUNK as u64) as usize;
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| CoreError::invalid("verify chunk window runs past its buffer"))?;
        let chunk_started = Instant::now();
        ctx.device()?.read_at(done, chunk)?;
        hasher.update(chunk);
        done += want as u64;
        ema.observe(want as u64, chunk_started.elapsed());
        emit_progress(
            ctx,
            "verify",
            done,
            Some(len),
            &ema,
            &mut last_emit,
            done >= len,
        );
    }
    let actual = crate::hash::hex(&hasher.finalize());
    if actual.eq_ignore_ascii_case(&image.sha256) {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: format!("verified {len} bytes"),
        });
        return Ok(());
    }
    // Digests differ: locate the first differing byte cheaply by
    // re-reading file and target side by side (the digest alone cannot
    // name an offset). Any trouble reading names the digests instead —
    // the refusal never lies about what it knows.
    let message = match locate_mismatch(ctx, image, len) {
        Some(offset) => format!(
            "first differing byte at offset {offset}: expected digest {}, read digest {actual}",
            image.sha256
        ),
        None => format!("expected digest {}, read digest {actual}", image.sha256),
    };
    Err(CoreError::Verify { message })
}

/// First offset where the target bytes differ from the image file, or
/// `None` when either side cannot be read (the caller then reports the
/// digests). Compares in [`CHUNK`] pieces without retaining them: on a
/// mismatch it re-reads up to the whole image and the whole target in
/// the worst case — two extra passes, but only on failure, so the cost
/// is predictable (an early difference costs one extra chunk,
/// measured). Never opens a path that is not a regular file (a FIFO
/// would block in `open` with no writer, the defect the hole query
/// already avoids).
fn locate_mismatch(ctx: &mut RunContext<'_>, image: &ImageRef, len: u64) -> Option<u64> {
    let meta = std::fs::metadata(&image.path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file = File::open(&image.path).ok()?;
    let mut expected = vec![0u8; CHUNK];
    let mut actual = vec![0u8; CHUNK];
    let mut done = 0u64;
    while done < len {
        let want = (len - done).min(CHUNK as u64) as usize;
        let want_buf = expected.get_mut(..want)?;
        read_exact_at(&file, want_buf, done, &image.path).ok()?;
        let got_buf = actual.get_mut(..want)?;
        ctx.device().ok()?.read_at(done, got_buf).ok()?;
        if let Some(position) = want_buf
            .iter()
            .zip(got_buf.iter())
            .position(|(want, got)| want != got)
        {
            return Some(done + position as u64);
        }
        done += want as u64;
    }
    None
}

/// Straight-through raw writing, sparse-aware: the opener's
/// [`data_ranges`](super::super::opener::Opener::data_ranges) answer
/// decides. `None` keeps the straight copy byte for byte; `Some`
/// streams only the data runs and zeroes the holes (see
/// [`pump_sparse`]).
mod raw {
    use std::path::Path;

    use super::*;

    /// Stream the image file to the device in [`CHUNK`](super::CHUNK)-sized
    /// pieces; `len` is the guarded file length from [`check_image`](super::check_image).
    pub(crate) fn run(
        ctx: &mut RunContext<'_>,
        image: &ImageRef,
        len: u64,
        size: u64,
    ) -> Result<()> {
        let file = File::open(&image.path).map_err(|source| CoreError::io(&image.path, source))?;
        // Compressed streams have no holes; only the raw arm asks.
        let ranges = ctx.opener.data_ranges(Path::new(&image.path))?;
        match ranges {
            None => {
                let mut source = super::Source::File {
                    file,
                    path: image.path.clone(),
                };
                if len == 0 {
                    // An empty image still reports itself: without this the run
                    // emits no Progress at all and a consumer cannot tell "done
                    // instantly" from "never reported".
                    ctx.reporter.event(Event::Progress {
                        step: "write",
                        done: 0,
                        total: Some(0),
                        bytes_per_second: 0,
                        eta_seconds: None,
                    });
                }
                let (done, _) = match super::pump(ctx, &mut source, Some(len), size) {
                    Ok(done) => done,
                    Err(error) => {
                        let _ = source.finish();
                        return Err(error);
                    }
                };
                source.finish()?;
                let cancelled = ctx.cancelled;
                super::finish_write(ctx, done, size, cancelled)?;
                Ok(())
            }
            Some(ranges) => run_sparse(ctx, image, &file, &ranges, len, size),
        }
    }

    /// Validate a `data_ranges` answer against the plan image size:
    /// ascending, non-overlapping, no empty entries, nothing past the
    /// image — a map contradicting `plan.image.size_bytes` is refused
    /// naming both, before any byte moves. The map itself is trusted:
    /// an under-reporting opener silently zeroes real data, and only
    /// this slice's read-back verify catches that afterwards.
    fn check_ranges(ranges: &[(u64, u64)], len: u64) -> Result<()> {
        let mut prev_end = 0u64;
        for (offset, rlen) in ranges {
            if *rlen == 0 {
                return Err(CoreError::invalid(format!(
                    "sparse range at offset {offset} is empty: refusing a map with zero-length entries"
                )));
            }
            if *offset < prev_end {
                return Err(CoreError::invalid(format!(
                    "sparse ranges overlap: range at offset {offset} starts before the previous range ends at {prev_end}"
                )));
            }
            let end = offset.checked_add(*rlen).ok_or_else(|| {
                CoreError::invalid(format!(
                    "sparse range at offset {offset} with length {rlen} overflows"
                ))
            })?;
            if end > len {
                return Err(CoreError::invalid(format!(
                    "sparse range [{offset}, {end}) runs past the {len} byte image: refusing a map that contradicts the plan size"
                )));
            }
            prev_end = end;
        }
        Ok(())
    }

    /// Stream only the data runs and zero the holes: gaps before the
    /// first, between, and after the last range go through
    /// [`zero_range`](super::super::Target::zero_range) (one call per
    /// window, cancellable between sub-chunks inside), data runs stream
    /// in [`CHUNK`](super::CHUNK) pieces under the same per-chunk
    /// cancellation and short/over-count rules as the straight loop.
    /// One `Progress` stream whose `total` is the image size and whose
    /// `done` counts every byte the target ends up holding, holes
    /// included, so the final event is `done == total == image size`.
    ///
    /// Holes are zeroed rather than skipped: the target holds whatever
    /// the previous image or a failed run left, so skipping a hole
    /// would leak stale bytes into the new filesystem's free space.
    /// Holes cost a `zero_range`, never a source read — and a target
    /// without a zero-out primitive pays the 4 MiB fallback writes.
    fn run_sparse(
        ctx: &mut RunContext<'_>,
        image: &ImageRef,
        file: &File,
        ranges: &[(u64, u64)],
        len: u64,
        size: u64,
    ) -> Result<()> {
        check_ranges(ranges, len)?;
        if len == 0 {
            // As in the straight arm: one zero event, so "done
            // instantly" reads apart from "never reported".
            ctx.reporter.event(Event::Progress {
                step: "write",
                done: 0,
                total: Some(0),
                bytes_per_second: 0,
                eta_seconds: None,
            });
        }
        let mut buf = vec![0u8; super::CHUNK];
        let mut ema = super::RateEma::new();
        let mut last_emit = Instant::now();
        let mut done = 0u64;
        let mut pos = 0u64;
        for (offset, rlen) in ranges {
            // The hole window before this data run.
            done = zero_gap(ctx, pos, *offset, len, &ema, &mut last_emit, done)?;
            // The data run itself, in chunk pieces.
            let mut rest = *rlen;
            let mut at = *offset;
            while rest > 0 {
                let cancelled = ctx.cancelled;
                if cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let want = rest.min(super::CHUNK as u64) as usize;
                let chunk = buf
                    .get_mut(..want)
                    .ok_or_else(|| CoreError::invalid("write chunk window runs past its buffer"))?;
                super::read_exact_at(file, chunk, at, &image.path)?;
                let written = super::write_chunk(ctx, at, chunk, cancelled, &mut ema)?;
                at += written;
                rest -= written;
                done += written;
                super::emit_progress(
                    ctx,
                    "write",
                    done,
                    Some(len),
                    &ema,
                    &mut last_emit,
                    done == len,
                );
            }
            pos = *offset + *rlen;
        }
        // The trailing hole window, if any.
        done = zero_gap(ctx, pos, len, len, &ema, &mut last_emit, done)?;
        let cancelled = ctx.cancelled;
        super::finish_write(ctx, done, size, cancelled)?;
        Ok(())
    }

    /// Zero the hole window `[from, to)`: one
    /// [`zero_range`](super::super::Target::zero_range) call per
    /// window (cancellable between sub-chunks inside), counted into
    /// `done` like every byte the target ends up holding. The running
    /// rate rides along unchanged — gaps add no sample. Empty windows
    /// are free. A retryable zero failure retries under the same
    /// policy as chunk writes (see [`write_chunk`](super::write_chunk)).
    fn zero_gap(
        ctx: &mut RunContext<'_>,
        from: u64,
        to: u64,
        len: u64,
        ema: &super::RateEma,
        last_emit: &mut Instant,
        done: u64,
    ) -> Result<u64> {
        if to <= from {
            return Ok(done);
        }
        let cancelled = ctx.cancelled;
        if cancelled() {
            return Err(CoreError::Cancelled);
        }
        super::zero_chunk(ctx, from, to - from, cancelled)?;
        let done = done + (to - from);
        super::emit_progress(ctx, "write", done, Some(len), ema, last_emit, done == len);
        Ok(done)
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use super::super::*; // hoisted RateEma, large_drive_warning

        #[test]
        fn rate_ema_and_eta_are_deterministic() {
            let mut ema = RateEma::new();
            assert_eq!(ema.bytes_per_second(), 0);
            assert_eq!(ema.eta_seconds(100), None);
            // The first sample sets the rate outright.
            ema.observe(1000, Duration::from_secs(1));
            assert_eq!(ema.bytes_per_second(), 1000);
            // Later samples move it by alpha (0.25): a quarter of the
            // way from 1000 to 2000.
            ema.observe(2000, Duration::from_secs(1));
            assert_eq!(ema.bytes_per_second(), 1250);
            // Zero elapsed carries no information: the rate stands.
            ema.observe(1_000_000, Duration::ZERO);
            assert_eq!(ema.bytes_per_second(), 1250);
            // ETA rounds up, and stays None at a zero rate.
            assert_eq!(ema.eta_seconds(2501), Some(3));
            assert_eq!(ema.eta_seconds(2000), Some(2));
            assert_eq!(RateEma::new().eta_seconds(10), None);
        }

        #[test]
        fn large_drive_warning_fires_only_above_the_slack() {
            let slack = super::super::LARGE_DRIVE_SLACK;
            assert_eq!(large_drive_warning(1024, 1024), None);
            assert_eq!(large_drive_warning(slack, 0), None);
            let warning = large_drive_warning(slack + 1, 0).expect("one byte over warns");
            assert!(warning.contains(&(slack + 1).to_string()), "{warning}");
            assert!(warning.contains("left untouched"), "{warning}");
        }
    }
}

/// Decompressed writing: the image file stays the compressed archive
/// on disk while a host tool streams the decoded bytes through the
/// same chunk loop the raw path uses.
mod compressed {
    use std::path::Path;

    use super::super::decompress::Tool;
    use super::super::decompress::kind_name;
    use super::*;

    /// Stream the decoded image to the device: spawn the tool over the
    /// archive, pump an unknown total (`Progress` carries `total: None`
    /// and no ETA while streaming), then reap the child. EOF only
    /// closed the pipe, so `finish` runs even after a clean drain: a
    /// tool that dies mid-archive must fail the run, never read as
    /// success.
    pub(crate) fn run(
        ctx: &mut RunContext<'_>,
        image: &ImageRef,
        tool: Tool,
        size: u64,
    ) -> Result<()> {
        let mut source = super::Source::Pipe(ToolStream::spawn(
            Path::new(&image.path),
            tool,
            kind_name(&image.kind),
        )?);
        let (done, ema) = match super::pump(ctx, &mut source, None, size) {
            Ok(done) => done,
            Err(error) => {
                // Reap on the error path too (a no-op after a
                // cancellation already reaped); the caller's error is
                // what propagates.
                let _ = source.finish();
                return Err(error);
            }
        };
        source.finish()?;
        // The decoded size is honest only now that the whole stream
        // arrived: one final event with the total known (every
        // intermediate carried `None`), so "done" stays
        // distinguishable from silence even for an empty payload. No
        // ETA: nothing remains to estimate.
        ctx.reporter.event(Event::Progress {
            step: "write",
            done,
            total: Some(done),
            bytes_per_second: ema.bytes_per_second(),
            eta_seconds: None,
        });
        let cancelled = ctx.cancelled;
        super::finish_write(ctx, done, size, cancelled)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::path::Path;
    use std::path::PathBuf;
    use std::rc::Rc;

    use super::*;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::log::Level;
    use crate::log::Logger;
    use crate::pipeline::event::VecReporter;
    use crate::pipeline::opener::Opener;
    use crate::pipeline::steps::RunContext;
    use crate::pipeline::target::Target;
    use crate::pipeline::target::VecTarget;
    use crate::udf::stamp_tag;

    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::WriteMode;

    /// Minimal [`Opener`] serving one [`VecTarget`]: the locator test
    /// below never touches partitions or hole maps.
    #[derive(Debug, Clone)]
    struct LocatorOpener {
        target: VecTarget,
    }

    impl Opener for LocatorOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Ok(Box::new(
                VecVolume::new(4096, 512).expect("fixture partition fits"),
            ))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn locate_mismatch_never_opens_a_non_regular_path() {
        // A FIFO image with a mismatching digest: the old code blocked
        // forever in `open` with no writer attached. The guard returns
        // `None` promptly instead — the test finishing at all is the
        // regression proof (no timing assertion; without the fix the
        // suite would stall here). `mkfifo(1)` is a host tool like the
        // `gzip` the pipeline tests already shell out to.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let fifo = scratch.path().join("image.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("the host mkfifo runs");
        assert!(status.success(), "mkfifo creates the node");
        let opener = LocatorOpener {
            target: VecTarget::new(4096, 512).expect("fixture target fits"),
        };
        let mut reporter = VecReporter::new();
        let never = || false;
        let mut ctx = RunContext {
            opener: &opener,
            target: None,
            table: None,
            partitioned: None,
            logger: Logger::new(Level::Info),
            reporter: &mut reporter,
            cancelled: &never,
            options: crate::pipeline::RunOptions {
                verify: false,
                badblocks: false,
                retries: 3,
                retry_delay: std::time::Duration::ZERO,
                reset_usb: false,
            },
        };
        let image = ImageRef {
            path: fifo.to_str().expect("scratch path is UTF-8").to_string(),
            size_bytes: 1024,
            sha256: "0".repeat(64),
            kind: ImageKind::Raw,
        };
        assert_eq!(locate_mismatch(&mut ctx, &image, 1024), None);
    }

    #[test]
    fn locate_mismatch_names_a_real_difference() {
        // A regular file vs a target holding other bytes: the first
        // differing offset comes back, proving the guard above did not
        // swallow the normal path — at offset 0 and, with a bigger
        // file, in a later chunk (300000 sits in the second 256 KiB
        // piece, so the locator must advance past the first).
        let scratch = tempfile::tempdir().expect("scratch fits");
        let path = scratch.path().join("image.bin");
        std::fs::write(&path, [0x11u8; 2048]).expect("fixture image writes");
        let opener = LocatorOpener {
            target: VecTarget::new(4096, 512).expect("fixture target fits"),
        };
        opener
            .target
            .write_all_at(0, &[0x22u8; 2048])
            .expect("target fills");
        let mut reporter = VecReporter::new();
        let never = || false;
        let mut ctx = RunContext {
            opener: &opener,
            target: None,
            table: None,
            partitioned: None,
            logger: Logger::new(Level::Info),
            reporter: &mut reporter,
            cancelled: &never,
            options: crate::pipeline::RunOptions {
                verify: false,
                badblocks: false,
                retries: 3,
                retry_delay: std::time::Duration::ZERO,
                reset_usb: false,
            },
        };
        let image = ImageRef {
            path: path.to_str().expect("scratch path is UTF-8").to_string(),
            size_bytes: 2048,
            sha256: "0".repeat(64),
            kind: ImageKind::Raw,
        };
        assert_eq!(locate_mismatch(&mut ctx, &image, 2048), Some(0));

        let big = scratch.path().join("big.bin");
        let body = vec![0x11u8; 300_001];
        std::fs::write(&big, &body).expect("fixture image writes");
        let big_target = VecTarget::new(512 * 1024, 512).expect("fixture target fits");
        big_target.write_all_at(0, &body).expect("target fills");
        big_target
            .write_all_at(300_000, &[0x22u8; 1])
            .expect("one byte differs");
        let big_opener = LocatorOpener { target: big_target };
        let mut reporter = VecReporter::new();
        let mut ctx = RunContext {
            opener: &big_opener,
            target: None,
            table: None,
            partitioned: None,
            logger: Logger::new(Level::Info),
            reporter: &mut reporter,
            cancelled: &never,
            options: crate::pipeline::RunOptions {
                verify: false,
                badblocks: false,
                retries: 3,
                retry_delay: std::time::Duration::ZERO,
                reset_usb: false,
            },
        };
        let image = ImageRef {
            path: big.to_str().expect("scratch path is UTF-8").to_string(),
            size_bytes: 300_001,
            sha256: "0".repeat(64),
            kind: ImageKind::Raw,
        };
        assert_eq!(locate_mismatch(&mut ctx, &image, 300_001), Some(300_000));
    }

    /// A test [`Opener`](super::super::Opener) whose `mount_partition`
    /// hands out its scratch directory as the mounted data partition:
    /// no privileges, no real mounts. Counts mounts and releases so
    /// the copy arm's ordering (mount, walk, release) is observable;
    /// `free` answers `free_bytes`; `fail_mount` refuses the mount
    /// itself.
    struct CopyOpener {
        scratch: tempfile::TempDir,
        mounts: Cell<usize>,
        releases: Rc<Cell<usize>>,
        free: u64,
        fail_mount: bool,
    }

    impl CopyOpener {
        fn new(free: u64) -> Self {
            Self {
                scratch: tempfile::tempdir().expect("scratch fits"),
                mounts: Cell::new(0),
                releases: Rc::new(Cell::new(0)),
                free,
                fail_mount: false,
            }
        }

        fn refusing() -> Self {
            Self {
                fail_mount: true,
                ..Self::new(0)
            }
        }

        fn mounts(&self) -> usize {
            self.mounts.get()
        }

        fn releases(&self) -> usize {
            self.releases.get()
        }
    }

    /// The directory guard [`CopyOpener`] hands out: the scratch
    /// directory as the mount point, a fixed `free_bytes` answer, and
    /// a counted `release`.
    struct CopyGuard {
        path: PathBuf,
        releases: Rc<Cell<usize>>,
        free: u64,
    }

    impl MountedPartition for CopyGuard {
        fn path(&self) -> &Path {
            &self.path
        }

        fn free_bytes(&self) -> Result<u64> {
            Ok(self.free)
        }

        fn release(&mut self) -> Result<()> {
            self.releases.set(self.releases.get() + 1);
            Ok(())
        }
    }

    impl Opener for CopyOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Err(CoreError::invalid("test opener has no device"))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Err(CoreError::invalid("test opener has no partition"))
        }

        fn partition_path(&self) -> Result<PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }

        fn mount_partition(&self, _filesystem: &Filesystem) -> Result<Box<dyn MountedPartition>> {
            self.mounts.set(self.mounts.get() + 1);
            if self.fail_mount {
                return Err(CoreError::NotImplemented {
                    what: "mounting the data partition",
                });
            }
            Ok(Box::new(CopyGuard {
                path: self.scratch.path().to_path_buf(),
                releases: Rc::clone(&self.releases),
                free: self.free,
            }))
        }
    }

    /// A [`RunContext`] over `opener`/`reporter`/`cancelled` for
    /// driving [`run`](super::run) directly: the copy arm never
    /// touches the device, so the opener only needs its mount seam.
    fn copy_context<'a>(
        opener: &'a CopyOpener,
        reporter: &'a mut VecReporter,
        cancelled: &'a dyn Fn() -> bool,
    ) -> RunContext<'a> {
        RunContext {
            opener,
            target: None,
            table: None,
            partitioned: None,
            logger: Logger::new(Level::Info),
            reporter,
            cancelled,
            options: crate::pipeline::RunOptions {
                verify: false,
                badblocks: false,
                retries: 3,
                retry_delay: Duration::ZERO,
                reset_usb: false,
            },
        }
    }

    /// An [`ImageRef`] over the file at `path` (`size` bytes) of
    /// container `kind`.
    fn copy_image(path: &Path, size: u64, kind: ImageKind) -> ImageRef {
        ImageRef {
            path: path.to_str().expect("scratch path is UTF-8").to_string(),
            size_bytes: size,
            sha256: "0".repeat(64),
            kind,
        }
    }

    /// The shared
    /// [`fixture_bytes`](crate::copy::source::fixture::fixture_bytes)
    /// ISO on disk: returns its path and length. The tree holds
    /// `TOP.TXT` (`top-txt`, 7 bytes), `A/NESTED.TXT` (`nested`, 6
    /// bytes) and an empty `B/`: 2 files in 2 directories, 13 bytes,
    /// nothing renamed.
    fn iso_fixture(scratch: &tempfile::TempDir) -> (PathBuf, u64) {
        let bytes = crate::copy::source::fixture::fixture_bytes();
        let path = scratch.path().join("fixture.iso");
        std::fs::write(&path, &bytes).expect("fixture image writes");
        (path, bytes.len() as u64)
    }

    /// The info-level [`Message`](Event::Message) texts in emission
    /// order.
    fn infos(reporter: &VecReporter) -> Vec<&str> {
        reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Message {
                    level: "info",
                    text,
                } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn copy_refuses_kinds_with_no_tree_reader_before_mounting() {
        // Every kind without a tree reader refuses — the WIM and
        // disk-container kinds as not-implemented naming the missing
        // reader, compressed archives and unknown kinds as invalid
        // input — and none of them mounts anything (zero mount calls
        // on the counting opener). The refusals land before the image
        // file is opened, so the path needs no fixture behind it.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let missing = scratch.path().join("absent.iso");
        for (kind, tag, fragment, not_implemented) in [
            (
                ImageKind::Wim,
                "wim",
                "reader arrives in a later slice",
                true,
            ),
            (
                ImageKind::Vhd,
                "vhd",
                "reader arrives in a later slice",
                true,
            ),
            (
                ImageKind::Vhdx,
                "vhdx",
                "reader arrives in a later slice",
                true,
            ),
            (
                ImageKind::Ffu,
                "ffu",
                "reader arrives in a later slice",
                true,
            ),
            (
                ImageKind::Qcow2,
                "qcow2",
                "reader arrives in a later slice",
                true,
            ),
            (ImageKind::Pe, "pe", "reader arrives in a later slice", true),
            (
                ImageKind::Gzip,
                "gzip",
                "cannot be walked as a tree without decoding it first",
                false,
            ),
            (
                ImageKind::Xz,
                "xz",
                "cannot be walked as a tree without decoding it first",
                false,
            ),
            (
                ImageKind::Bzip2,
                "bzip2",
                "cannot be walked as a tree without decoding it first",
                false,
            ),
            (
                ImageKind::Zstd,
                "zstd",
                "cannot be walked as a tree without decoding it first",
                false,
            ),
            (
                ImageKind::Unknown,
                "unknown",
                "names no readable file tree",
                false,
            ),
        ] {
            let opener = CopyOpener::new(u64::MAX);
            let mut reporter = VecReporter::new();
            let never = || false;
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&missing, 0, kind);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("a kind with no tree reader refuses");
            let text = error.to_string();
            assert!(text.contains(tag), "the refusal names the kind: {text}");
            assert!(text.contains(fragment), "{text}");
            assert!(text.is_ascii(), "{text}");
            assert_eq!(
                matches!(error, CoreError::NotImplemented { .. }),
                not_implemented,
                "the refusal variant names its shape: {error:?}"
            );
            assert_eq!(opener.mounts(), 0, "no mount for {tag}");
        }
    }

    #[test]
    fn copy_walks_an_iso_tree_onto_the_mount() {
        // End to end through `write::run`: the fixture ISO lands
        // byte-for-byte in the mounted directory, the completion line
        // reports the concrete counts, the opening line names the
        // image path and kind, at least one step-`write` progress
        // sample arrived, and the mount was released.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = iso_fixture(&scratch);
        let opener = CopyOpener::new(1024 * 1024);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, size, ImageKind::Iso);
            run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect("the iso tree copies");
        }
        let dest = opener.scratch.path();
        assert_eq!(
            std::fs::read(dest.join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert_eq!(
            std::fs::read(dest.join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
        assert_eq!(
            std::fs::read_dir(dest.join("B")).expect("B lists").count(),
            0
        );
        let found = infos(&reporter);
        assert!(
            found
                .iter()
                .any(|text| text.contains("fixture.iso") && text.contains("(iso)")),
            "the opening line names the image path and kind: {found:?}"
        );
        assert!(
            found
                .iter()
                .any(|text| text == &"copied 2 files in 2 directories (13 bytes), 0 renamed"),
            "the completion line reports the concrete result: {found:?}"
        );
        assert!(
            found.iter().all(|text| text.is_ascii()),
            "messages stay ASCII: {found:?}"
        );
        assert!(
            reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::Progress { step: "write", .. })),
            "a copy reports progress: {:?}",
            reporter.events()
        );
        assert_eq!(opener.mounts(), 1);
        assert_eq!(opener.releases(), 1, "the mount is released");
    }

    #[test]
    fn copy_reports_a_refused_mount_and_writes_nothing() {
        // The source builds (a real ISO fixture), then the mount
        // refuses: the step fails with the mount error and no file
        // lands in the would-be mount directory.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = iso_fixture(&scratch);
        let opener = CopyOpener::refusing();
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, size, ImageKind::Iso);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("a refused mount fails the step");
            assert!(
                matches!(error, CoreError::NotImplemented { .. }),
                "the mount refusal propagates: {error:?}"
            );
            assert!(error.to_string().contains("mounting"), "{error:?}");
        }
        assert_eq!(opener.mounts(), 1);
        assert_eq!(
            opener.releases(),
            0,
            "nothing mounted means nothing to release"
        );
        assert_eq!(
            std::fs::read_dir(opener.scratch.path())
                .expect("the dir lists")
                .count(),
            0
        );
    }

    #[test]
    fn copy_releases_the_mount_when_the_free_space_check_refuses() {
        // A mount reporting zero free bytes refuses the 13-byte tree
        // up front: the error surfaces, the mount is still released,
        // and nothing was written.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = iso_fixture(&scratch);
        let opener = CopyOpener::new(0);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, size, ImageKind::Iso);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("an empty destination refuses");
            let text = error.to_string();
            assert!(text.contains("13"), "{text}");
            assert!(text.contains("free"), "{text}");
        }
        assert_eq!(opener.mounts(), 1);
        assert_eq!(opener.releases(), 1, "a failed pre-flight still releases");
        assert_eq!(
            std::fs::read_dir(opener.scratch.path())
                .expect("the dir lists")
                .count(),
            0,
            "the refusal lands before any write"
        );
    }

    #[test]
    fn copy_cancels_mid_walk_releases_and_leaves_no_partial_file() {
        // The probe stays false for the walk entry and the first
        // sizing entry, then reads true: the walk stops with
        // `Cancelled`, the mount is released, and whatever landed is
        // whole (a cancelled file is removed like a write failure
        // removes it — a surviving file always reads back
        // byte-identical, never partial).
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, size) = iso_fixture(&scratch);
        let opener = CopyOpener::new(1024 * 1024);
        let mut reporter = VecReporter::new();
        let calls = Cell::new(0u32);
        let cancelled = || {
            let seen = calls.get();
            calls.set(seen + 1);
            seen >= 2
        };
        {
            let mut ctx = copy_context(&opener, &mut reporter, &cancelled);
            let image = copy_image(&path, size, ImageKind::Iso);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("a cancelled copy refuses");
            assert!(
                matches!(error, CoreError::Cancelled),
                "cancellation surfaces bare: {error:?}"
            );
        }
        assert_eq!(opener.mounts(), 1);
        assert_eq!(opener.releases(), 1, "a cancelled walk still releases");
        let dest = opener.scratch.path();
        for (name, bytes) in [
            ("TOP.TXT", b"top-txt".as_slice()),
            ("A/NESTED.TXT", b"nested".as_slice()),
        ] {
            let landed = dest.join(name);
            if landed.exists() {
                assert_eq!(
                    std::fs::read(&landed).expect("a surviving file reads"),
                    bytes,
                    "{name} is whole or absent, never partial"
                );
            }
        }
    }

    /// A [`Source`](crate::copy::Source) declaring one file above the
    /// FAT32 limit without holding any bytes: the limit check fires
    /// up front, so `read_bytes` never needs real data (it answers
    /// end-of-file, which the non-limited walk then reports as the
    /// short read it is).
    struct HugeSource;

    impl crate::copy::Source for HugeSource {
        fn root_entries(&self) -> Result<Vec<crate::copy::Entry>> {
            Ok(vec![crate::copy::Entry {
                name: b"big.bin".to_vec(),
                is_dir: false,
                size: u64::MAX,
                mode: None,
                modified: None,
                accessed: None,
                link: None,
            }])
        }

        fn child_entries(&self, _dir: &[Vec<u8>]) -> Result<Vec<crate::copy::Entry>> {
            Ok(Vec::new())
        }

        fn read_bytes(&self, _file: &[Vec<u8>], _offset: u64, _buf: &mut [u8]) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn copy_passes_the_fat32_limit_only_for_fat32_targets() {
        // The same huge-file source refuses on a `Fat32` plan (naming
        // the limit and the size) and walks past the limit on an
        // `Exfat` plan (failing later as the short read it is,
        // proving the limit flag was off); the mount is released in
        // both cases.
        for (filesystem, limited) in [(Filesystem::Fat32, true), (Filesystem::Exfat, false)] {
            let opener = CopyOpener::new(u64::MAX);
            let mut reporter = VecReporter::new();
            let never = || false;
            {
                let mut ctx = copy_context(&opener, &mut reporter, &never);
                let image = copy_image(Path::new("big.iso"), u64::MAX, ImageKind::Iso);
                let mut mounted = opener
                    .mount_partition(&filesystem)
                    .expect("the test mount opens");
                let error =
                    run_copy_mounted(&mut ctx, &image, &filesystem, &HugeSource, mounted.as_mut())
                        .expect_err("the huge file refuses or fails");
                let text = error.to_string();
                assert_eq!(
                    text.contains("FAT32"),
                    limited,
                    "{filesystem:?} carries the limit flag it was given: {text}"
                );
                if limited {
                    assert!(text.contains(&u64::MAX.to_string()), "{text}");
                }
            }
            assert_eq!(opener.mounts(), 1);
            assert_eq!(
                opener.releases(),
                1,
                "{filesystem:?} releases after the refusal"
            );
        }
    }

    #[test]
    fn copy_refuses_a_raw_image_that_is_neither_iso_nor_udf() {
        // Zeroed bytes are neither an ISO9660 nor a UDF tree: the arm
        // refuses naming the kind and carrying the UDF reader's
        // message (never swallowing it), before mounting anything.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let path = scratch.path().join("blank.bin");
        std::fs::write(&path, vec![0u8; 64 * 1024]).expect("blank image writes");
        let opener = CopyOpener::new(u64::MAX);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, 64 * 1024, ImageKind::Raw);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("a tree-less raw image refuses");
            assert!(
                matches!(error, CoreError::InvalidInput { .. }),
                "the refusal names its shape: {error:?}"
            );
            let text = error.to_string();
            assert!(text.contains("raw"), "{text}");
            assert!(text.contains("ISO9660"), "{text}");
            assert!(text.contains("UDF open failed"), "{text}");
            assert!(text.is_ascii(), "{text}");
        }
        assert_eq!(opener.mounts(), 0, "a malformed image never mounts");
    }

    /// Block size of the synthetic UDF volume. The anchor probe tries
    /// 2048 first; this volume is too short to hold the anchor at block
    /// 256 in 2048-byte units, so the probe falls through to 512 (the
    /// reader's own synthetic tests take the same path).
    const UDF_BLOCK: u32 = 512;
    /// Absolute block of the anchor volume descriptor pointer.
    const UDF_ANCHOR: u32 = 256;
    /// Absolute block where the main descriptor sequence starts (8 blocks).
    const UDF_MAIN: u32 = 96;
    /// Absolute block where partition 0 starts (900 blocks long).
    const UDF_PART: u32 = 257;
    /// Partition-relative block of the file set descriptor.
    const UDF_FSD: u32 = 8;
    /// Partition-relative block of the root directory file entry.
    const UDF_ROOT: u32 = 10;
    /// Blocks the synthetic volume occupies: the partition plus a tail.
    const UDF_BLOCKS: u32 = UDF_PART + 16;

    /// Stamp the ECMA-167 tag (`id`, CRC over `crc_len` bytes after the
    /// tag, claimed `location`) onto a whole block.
    fn udf_tagged(mut block: Vec<u8>, id: u16, crc_len: usize, location: u32) -> Vec<u8> {
        stamp_tag(&mut block, id, crc_len as u16, location);
        block
    }

    /// Write one whole block at absolute block `at` of `image`.
    fn udf_put(image: &mut [u8], at: u32, block: &[u8]) {
        let base = at as usize * UDF_BLOCK as usize;
        image[base..base + block.len()].copy_from_slice(block);
    }

    /// A file entry (tag 266, extended) with `data` embedded in the
    /// entry block itself: `ftype` 5 is a regular file, 4 a directory.
    /// The entry claims partition-relative block `rel`.
    fn udf_entry(rel: u32, ftype: u8, data: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; UDF_BLOCK as usize];
        block[27] = ftype;
        // Permission word (offset 44), mapped by `permissions_to_mode`:
        // 0x1CA5 reads 0o755 (the reader's own pinned word), 0x1884
        // reads 0o644. A zero word would copy as mode 0, unreadable.
        let perm: u32 = if ftype == 4 { 0x1CA5 } else { 0x1884 };
        block[44..48].copy_from_slice(&perm.to_le_bytes());
        // ICB flags: allocation type 3, data embedded in the entry.
        block[34..36].copy_from_slice(&3u16.to_le_bytes());
        block[56..64].copy_from_slice(&(data.len() as u64).to_le_bytes());
        block[212..216].copy_from_slice(&(data.len() as u32).to_le_bytes());
        block[216..216 + data.len()].copy_from_slice(data);
        udf_tagged(block, 266, UDF_BLOCK as usize - 16, rel)
    }

    /// One file identifier descriptor (tag 257) padded to 4 bytes:
    /// characteristics (`0x02` directory, `0x0A` parent), the ICB
    /// (one block at `lbn`), the compressed name, and the block
    /// `location` the record sits in.
    fn udf_fid(characteristics: u8, lbn: u32, name: &[u8], location: u32) -> Vec<u8> {
        let body = 38 + name.len();
        let total = body + (4 - body % 4) % 4;
        let mut record = vec![0u8; total];
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18] = characteristics;
        record[19] = name.len() as u8;
        record[20..24].copy_from_slice(&UDF_BLOCK.to_le_bytes());
        record[24..28].copy_from_slice(&lbn.to_le_bytes());
        record[38..38 + name.len()].copy_from_slice(name);
        udf_tagged(record, 257, total - 16, location)
    }

    /// OSTA compressed Unicode for `text` (compression id 8, one byte
    /// per character): the form every fixture name takes.
    fn udf_name(text: &str) -> Vec<u8> {
        let mut out = vec![8u8];
        out.extend_from_slice(text.as_bytes());
        out
    }

    /// A synthetic UDF 2.01 volume holding the same tree as the ISO
    /// fixture: `TOP.TXT` (`top-txt`), `A/NESTED.TXT` (`nested`) and an
    /// empty `B/`. Layout (512-byte blocks, partition 0 at block 257):
    /// recognition at byte 32768 (`BEA01`, `nsr`, `TEA01`), anchor at
    /// block 256 with the main sequence at block 96, the primary,
    /// logical volume (file set at relative block 8), partition,
    /// unallocated, implementation-use and terminator descriptors at
    /// 96..101, then the file set (8), the root entry (10), `TOP.TXT`
    /// (11), `A` (12), `B` (13) and `NESTED.TXT` (14). Every file and
    /// directory keeps its data inside its own entry block, so no
    /// extent maps are needed. `nsr` is `NSR03` for a valid volume.
    ///
    /// The offsets are the ones the reader's own synthetic volume pins
    /// (`udf/reader.rs`), which is the only source for them here: the
    /// fixture proves the copy arm consumes what the reader accepts,
    /// not that the reader matches a real `mkudffs` image byte for byte.
    fn udf_tree_bytes(nsr: &[u8; 5]) -> Vec<u8> {
        let mut image = vec![0u8; UDF_BLOCKS as usize * UDF_BLOCK as usize];
        for (index, id) in [*b"BEA01", *nsr, *b"TEA01"].iter().enumerate() {
            let base = 32768 + index * 2048;
            image[base + 1..base + 6].copy_from_slice(id);
            image[base + 6] = 0x01;
        }
        // Anchor: a main extent of 8 blocks at block 96, no reserve.
        let mut anchor = vec![0u8; UDF_BLOCK as usize];
        anchor[16..20].copy_from_slice(&(8 * UDF_BLOCK).to_le_bytes());
        anchor[20..24].copy_from_slice(&UDF_MAIN.to_le_bytes());
        udf_put(
            &mut image,
            UDF_ANCHOR,
            &udf_tagged(anchor, 2, UDF_BLOCK as usize - 16, UDF_ANCHOR),
        );
        // Primary volume descriptor (tag 1).
        let primary = vec![0u8; UDF_BLOCK as usize];
        udf_put(
            &mut image,
            UDF_MAIN,
            &udf_tagged(primary, 1, UDF_BLOCK as usize - 16, UDF_MAIN),
        );
        // Logical volume descriptor (tag 6): label `LABEL`, block size,
        // `*OSTA UDF Compliant` domain at revision 2.01, the file set's
        // long address and one type-1 partition map to partition 0.
        let mut logical = vec![0u8; UDF_BLOCK as usize];
        logical[84] = 8;
        logical[85..90].copy_from_slice(b"LABEL");
        logical[84 + 127] = 6;
        logical[212..216].copy_from_slice(&UDF_BLOCK.to_le_bytes());
        logical[217..236].copy_from_slice(b"*OSTA UDF Compliant");
        logical[240..242].copy_from_slice(&0x0201u16.to_le_bytes());
        logical[248..252].copy_from_slice(&UDF_BLOCK.to_le_bytes());
        logical[252..256].copy_from_slice(&UDF_FSD.to_le_bytes());
        logical[264..268].copy_from_slice(&6u32.to_le_bytes());
        logical[268..272].copy_from_slice(&1u32.to_le_bytes());
        logical[440..446].copy_from_slice(&[1, 6, 1, 0, 0, 0]);
        udf_put(
            &mut image,
            UDF_MAIN + 1,
            &udf_tagged(logical, 6, 446 - 16, UDF_MAIN + 1),
        );
        // Partition descriptor (tag 5): partition 0 at block 257, 900
        // blocks, contents identifier `+NSR03`.
        let mut partition = vec![0u8; UDF_BLOCK as usize];
        partition[25..31].copy_from_slice(b"+NSR03");
        partition[188..192].copy_from_slice(&UDF_PART.to_le_bytes());
        partition[192..196].copy_from_slice(&900u32.to_le_bytes());
        udf_put(
            &mut image,
            UDF_MAIN + 2,
            &udf_tagged(partition, 5, UDF_BLOCK as usize - 16, UDF_MAIN + 2),
        );
        // Unallocated space (7), implementation use (4) and the
        // terminator (8): skipped by the reader, required by the
        // measured six-descriptor shape.
        for (lbn, id) in [(UDF_MAIN + 3, 7u16), (UDF_MAIN + 4, 4), (UDF_MAIN + 5, 8)] {
            let block = vec![0u8; UDF_BLOCK as usize];
            udf_put(
                &mut image,
                lbn,
                &udf_tagged(block, id, UDF_BLOCK as usize - 16, lbn),
            );
        }
        // File set descriptor (tag 256) at partition-relative block 8:
        // the root ICB (one block, relative 10, partition 0).
        let mut fsd = vec![0u8; UDF_BLOCK as usize];
        fsd[400..404].copy_from_slice(&UDF_BLOCK.to_le_bytes());
        fsd[404..408].copy_from_slice(&UDF_ROOT.to_le_bytes());
        udf_put(
            &mut image,
            UDF_PART + UDF_FSD,
            &udf_tagged(fsd, 256, UDF_BLOCK as usize - 16, UDF_FSD),
        );
        // Root directory: the parent, TOP.TXT, A and B.
        let mut root = udf_fid(0x0A, UDF_ROOT, &[], UDF_ROOT);
        root.extend(udf_fid(0x00, 11, &udf_name("TOP.TXT"), UDF_ROOT));
        root.extend(udf_fid(0x02, 12, &udf_name("A"), UDF_ROOT));
        root.extend(udf_fid(0x02, 13, &udf_name("B"), UDF_ROOT));
        udf_put(
            &mut image,
            UDF_PART + UDF_ROOT,
            &udf_entry(UDF_ROOT, 4, &root),
        );
        // A holds NESTED.TXT; B stays empty (its parent entry only).
        let mut a = udf_fid(0x0A, 12, &[], 12);
        a.extend(udf_fid(0x00, 14, &udf_name("NESTED.TXT"), 12));
        udf_put(&mut image, UDF_PART + 12, &udf_entry(12, 4, &a));
        let b = udf_fid(0x0A, 13, &[], 13);
        udf_put(&mut image, UDF_PART + 13, &udf_entry(13, 4, &b));
        udf_put(&mut image, UDF_PART + 11, &udf_entry(11, 5, b"top-txt"));
        udf_put(&mut image, UDF_PART + 14, &udf_entry(14, 5, b"nested"));
        image
    }

    #[test]
    fn copy_walks_a_udf_tree_onto_the_mount() {
        // The synthetic UDF volume (no `CD001`, so `detect` says `Raw`)
        // runs through `write::run` with a `Raw` kind: the UDF arm
        // opens it, and the same tree the ISO test pins lands byte for
        // byte under the mount, with the same concrete counts.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let bytes = udf_tree_bytes(b"NSR03");
        let path = scratch.path().join("tree.udf");
        std::fs::write(&path, &bytes).expect("udf fixture writes");
        let size = bytes.len() as u64;
        let volume = FileVolume::open(&path).expect("udf fixture opens");
        assert_eq!(
            crate::image::detect(&volume).expect("detect reads the header"),
            ImageKind::Raw,
            "the fixture classifies as raw, so the UDF arm is the one under test"
        );
        let opener = CopyOpener::new(1024 * 1024);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, size, ImageKind::Raw);
            run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect("the udf tree copies");
        }
        let dest = opener.scratch.path();
        assert_eq!(
            std::fs::read(dest.join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert!(dest.join("A").is_dir(), "A is a directory on the mount");
        assert_eq!(
            std::fs::read(dest.join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
        assert!(dest.join("B").is_dir(), "B is an empty directory");
        assert_eq!(
            std::fs::read_dir(dest.join("B")).expect("B lists").count(),
            0
        );
        let found = infos(&reporter);
        assert!(
            found
                .iter()
                .any(|text| text.contains("tree.udf") && text.contains("(raw)")),
            "the opening line names the image path and kind: {found:?}"
        );
        assert!(
            found
                .iter()
                .any(|text| text == &"copied 2 files in 2 directories (13 bytes), 0 renamed"),
            "the completion line reports the concrete result: {found:?}"
        );
        assert!(
            found.iter().all(|text| text.is_ascii()),
            "messages stay ASCII: {found:?}"
        );
        assert!(
            reporter
                .events()
                .iter()
                .any(|event| matches!(event, Event::Progress { step: "write", .. })),
            "a copy reports progress: {:?}",
            reporter.events()
        );
        assert_eq!(opener.mounts(), 1);
        assert_eq!(opener.releases(), 1, "the mount is released");
    }

    #[test]
    fn copy_refuses_a_udf_volume_with_a_mismatched_structure() {
        // Same layout with the recognition sector's NSR identifier
        // corrupted: still `Raw` (no `CD001`), but the UDF reader
        // refuses it, so the arm names UDF and carries the reader's
        // refusal (the identifier it found). Nothing mounts.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let bytes = udf_tree_bytes(b"XXX01");
        let path = scratch.path().join("broken.udf");
        std::fs::write(&path, &bytes).expect("udf fixture writes");
        let size = bytes.len() as u64;
        let opener = CopyOpener::new(u64::MAX);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, size, ImageKind::Raw);
            let error = run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect_err("a UDF volume with a bad NSR refuses");
            assert!(
                matches!(error, CoreError::InvalidInput { .. }),
                "the refusal names its shape: {error:?}"
            );
            let text = error.to_string();
            assert!(text.contains("UDF open failed"), "{text}");
            assert!(text.contains("XXX01"), "{text}");
            assert!(text.is_ascii(), "{text}");
        }
        assert_eq!(opener.mounts(), 0, "a malformed UDF image never mounts");
    }

    /// A single-file ISO holding `size` patterned bytes under
    /// `BIG.BIN`, built from the shared
    /// [`fixture`](crate::copy::source::fixture) builders: several
    /// 128 KiB copy chunks, so the progress throttle has something
    /// to chew on. Returns its path and length.
    fn big_iso_fixture(scratch: &tempfile::TempDir, size: usize) -> (PathBuf, u64) {
        use crate::copy::source::fixture::boot_sector;
        use crate::copy::source::fixture::dir_sector;
        use crate::copy::source::fixture::encode_record;
        use crate::copy::source::fixture::primary_sector;
        use crate::copy::source::fixture::terminator_sector;
        use crate::iso::FLAG_DIRECTORY;
        use crate::iso::SECTOR_BYTES;

        const ROOT: u32 = 20;
        const CONTENT: u32 = 23;
        let content_sectors = (size as u32).div_ceil(SECTOR_BYTES as u32);
        let sectors = CONTENT + content_sectors;
        let mut image = vec![0u8; sectors as usize * SECTOR_BYTES];
        let put = |image: &mut Vec<u8>, sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(
            &mut image,
            16,
            &primary_sector("LABEL", ROOT, SECTOR_BYTES as u32),
        );
        put(&mut image, 17, &boot_sector());
        put(&mut image, 18, &terminator_sector());
        put(
            &mut image,
            ROOT,
            &dir_sector(&[
                encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
                encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
                encode_record(CONTENT, size as u32, 0, b"BIG.BIN;1"),
            ]),
        );
        let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        put(&mut image, CONTENT, &body);
        let path = scratch.path().join("big.iso");
        std::fs::write(&path, &image).expect("big fixture writes");
        (path, image.len() as u64)
    }

    #[test]
    fn copy_progress_is_throttled_to_a_handful_of_lines() {
        // A 300001-byte file streams as three 128 KiB chunks: without
        // the [`PROGRESS_INTERVAL`] throttle the walk would emit at
        // least 3 progress lines (initial, per-chunk, final), so the
        // cap below fails if the throttle is ever removed. With it,
        // only the forced final line is guaranteed — one line, two at
        // most if a 100 ms boundary slips mid-copy — and the last line
        // still reports `done == total`.
        let scratch = tempfile::tempdir().expect("scratch fits");
        let (path, len) = big_iso_fixture(&scratch, 300_001);
        let opener = CopyOpener::new(u64::MAX);
        let mut reporter = VecReporter::new();
        let never = || false;
        {
            let mut ctx = copy_context(&opener, &mut reporter, &never);
            let image = copy_image(&path, len, ImageKind::Iso);
            run(&mut ctx, &WriteMode::Copy, &image, &Filesystem::Fat32)
                .expect("the big tree copies");
        }
        let progress: Vec<(u64, Option<u64>)> = reporter
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Progress { done, total, .. } => Some((*done, *total)),
                _ => None,
            })
            .collect();
        assert!(
            !progress.is_empty() && progress.len() <= 2,
            "throttled to a forced final line plus at most one sample: {progress:?}"
        );
        assert_eq!(
            progress.last().copied(),
            Some((300_001, Some(300_001))),
            "the last line still reports done == total: {progress:?}"
        );
        let landed =
            std::fs::read(opener.scratch.path().join("BIG.BIN")).expect("the big file reads back");
        assert_eq!(landed.len(), 300_001);
        assert_eq!(
            landed,
            (0..300_001).map(|i| (i % 251) as u8).collect::<Vec<u8>>()
        );
    }
}
