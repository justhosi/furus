//! The write step: stream the image to the device.
//!
//! Layout choice: one file with an inline `mod raw` for the
//! straight-through path and an inline `mod compressed` for the host
//! decompressor path, so slice 6 (sparse) adds one more sibling
//! without renaming files or churning paths. Only
//! [`Dd`](rufus_proto::WriteMode::Dd) exists this slice; `Copy`
//! refuses by name (see [`run`]).
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
use std::time::Duration;
use std::time::Instant;

use rufus_proto::ImageRef;
use rufus_proto::WriteMode;

use crate::error::CoreError;
use crate::error::Result;
use crate::pipeline::decompress::ToolStream;
use crate::pipeline::decompress::tool_for;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;

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
    if !force && last_emit.elapsed() < PROGRESS_INTERVAL {
        return;
    }
    *last_emit = Instant::now();
    ctx.reporter.event(Event::Progress {
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
/// anything else refuses (see [`run`]).
pub(crate) fn run(ctx: &mut RunContext<'_>, mode: &WriteMode, image: &ImageRef) -> Result<()> {
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
                                super::decompress::kind_name(&image.kind)
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
        WriteMode::Copy => Err(CoreError::NotImplemented {
            what: "write mode 'copy' (file-tree copying arrives in slice 18)",
        }),
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

    use rufus_proto::ImageKind;

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
            partitioned: false,
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
            partitioned: false,
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
            partitioned: false,
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
}
