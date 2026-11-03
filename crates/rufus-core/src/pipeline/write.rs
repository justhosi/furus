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
//! see; the read-back verify pass (slice 7) is what catches it.

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
/// most this often, plus always the final one at 100 %.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Exponential moving average of write throughput in bytes per
/// second: `rate = alpha * sample + (1 - alpha) * rate` with
/// [`EMA_ALPHA`], the first sample setting the rate outright. The
/// average deliberately covers the read and the write of each chunk
/// (per-chunk wall time): on a real device the write dominates, and
/// smoothing both keeps one number for the event stream. Elapsed
/// time arrives as an explicit [`Duration`] so the arithmetic is
/// testable without sleeping.
struct RateEma {
    rate: f64,
}

/// Smoothing factor: each chunk moves the average a quarter of the
/// way to its sample — responsive within a few chunks, stable
/// across one slow outlier.
const EMA_ALPHA: f64 = 0.25;

impl RateEma {
    fn new() -> Self {
        Self { rate: 0.0 }
    }

    /// Fold one chunk's bytes and wall time into the average. A zero
    /// elapsed time carries no information (it would divide by
    /// zero), so the sample is dropped and the rate stands.
    fn observe(&mut self, bytes: u64, elapsed: Duration) {
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
    fn bytes_per_second(&self) -> u64 {
        self.rate as u64
    }

    /// Seconds to drain `remaining` at the current rate, rounded up;
    /// `None` while the rate is still zero.
    fn eta_seconds(&self, remaining: u64) -> Option<u64> {
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
        // cancellation cadence.
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
        let chunk_started = Instant::now();
        let written = ctx
            .device()?
            .write_all_at_cancellable(done, chunk, CHUNK, cancelled)?;
        if written < read as u64 {
            // The contract reads a short count as cancellation: a
            // target that reports full while swallowing bytes cannot
            // be detected here, which is why the verify pass
            // (slice 7) exists. This is the honest form of Rufus's
            // `Wrote %d bytes, expected %d bytes` check.
            return Err(CoreError::Cancelled);
        }
        if written > read as u64 {
            // Impossible by contract (no more than the chunk went
            // in): a target that claims otherwise is faulty, not
            // cancelled, so it refuses by name with both numbers.
            return Err(CoreError::invalid(format!(
                "target reported {written} bytes written for a {read} byte chunk at offset {done}: refusing an impossible count"
            )));
        }
        done = done.saturating_add(written);
        ema.observe(read as u64, chunk_started.elapsed());
        let finished = total.is_some_and(|len| done >= len);
        if last_emit.elapsed() >= PROGRESS_INTERVAL || finished {
            last_emit = Instant::now();
            ctx.reporter.event(Event::Progress {
                step: "write",
                done,
                total,
                bytes_per_second: ema.bytes_per_second(),
                eta_seconds: match total {
                    Some(len) => ema.eta_seconds(len.saturating_sub(done)),
                    None => None,
                },
            });
        }
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
fn finish_write(ctx: &mut RunContext<'_>, done: u64, size: u64) -> Result<()> {
    let sector = u64::from(ctx.device()?.sector_size());
    if sector != 0 && !done.is_multiple_of(sector) {
        let end = (done / sector + 1).saturating_mul(sector).min(size);
        if end > done {
            ctx.device()?.zero_range(done, end - done)?;
        }
    }
    ctx.device()?.flush()?;
    ctx.device()?.reread_partitions()?;
    Ok(())
}

/// Run the write step for `mode` over `image`: `Dd` streams through
/// [`raw`] (every other [`ImageKind`] stays raw) or through
/// [`compressed`] when [`tool_for`] names a host decompressor;
/// anything else refuses (see [`run`]).
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &WriteMode,
    image: &ImageRef,
    verify: bool,
) -> Result<()> {
    match mode {
        WriteMode::Dd => {
            if verify {
                // Slice 7 replaces this with the real read-back check; until
                // then the flag warns instead of vanishing silently. One
                // warning per run, whichever source the kind selects.
                ctx.reporter.event(Event::Message {
                    level: "warn",
                    text: "verify requested but verification is not implemented yet (slice 7): continuing without it"
                        .to_string(),
                });
            }
            let size = ctx.device()?.size();
            let tool = tool_for(&image.kind);
            let len = check_image(ctx, image, size, tool.is_some())?;
            match tool {
                Some(tool) => compressed::run(ctx, image, tool, size),
                None => raw::run(ctx, image, len, size),
            }
        }
        WriteMode::Copy => Err(CoreError::NotImplemented {
            what: "write mode 'copy' (file-tree copying arrives in slice 18)",
        }),
    }
}

/// Straight-through raw writing: no sparse skipping, no decompression
/// (slice 6).
mod raw {
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
        super::finish_write(ctx, done, size)?;
        Ok(())
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
        super::finish_write(ctx, done, size)?;
        Ok(())
    }
}
