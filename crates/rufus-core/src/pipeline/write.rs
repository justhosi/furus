//! The write step: stream the image to the device.
//!
//! Layout choice: one file with an inline `mod raw`, so slices 5
//! (sparse) and 6 (compressed) add sibling inline mods without renaming
//! files or churning paths. Only [`Dd`](rufus_proto::WriteMode::Dd)
//! exists this slice; `Copy` refuses by name (see [`run`]).
//!
//! Evidence ported here (`0x140010a40` is the write thread: open the
//! image, allocate a write buffer — 256 KiB, `0x40000`, on the
//! compressed path — read a chunk, write it, advance the image
//! position): the straight-through path below reads and writes in
//! [`CHUNK`]-sized pieces with the Rufus error shapes (`Write error at
//! sector`, `Wrote %d bytes, expected %d bytes`, `Read error`, stale
//! layout) mapped onto [`CoreError`] refusals that name their numbers.
//! `0x140010830` bounds a fill buffer at 64 KiB sectors and 1 GiB total;
//! sparse and compressed writing are slices 5 and 6, not this one.
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
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::check_cancelled;

/// Chunk size in bytes (256 KiB, the compressed path's `0x40000`
/// buffer): the straight-through loop shares it now, slice 5's sparse
/// and slice 6's compressed loops share it next.
pub(crate) const CHUNK: usize = 256 * 1024;

/// Device slack past the image that triggers the large-drive warning
/// (4 GiB): beyond this the stick dwarfs the image, and the run says so
/// instead of silently leaving tens of gigabytes untouched.
pub(crate) const LARGE_DRIVE_SLACK: u64 = 4 * 1024 * 1024 * 1024;

/// Slowest progress cadence: a [`Progress`](Event::Progress) goes out at
/// most this often, plus always the final one at 100 %.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Run the write step for `mode` over `image`: `Dd` streams through
/// [`raw`], anything else refuses (see [`run`]).
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &WriteMode,
    image: &ImageRef,
    verify: bool,
) -> Result<()> {
    match mode {
        WriteMode::Dd => raw::run(ctx, image, verify),
        WriteMode::Copy => Err(CoreError::NotImplemented {
            what: "write mode 'copy' (file-tree copying arrives in slice 18)",
        }),
    }
}

/// Straight-through raw writing: no sparse skipping, no decompression
/// (slices 5 and 6).
mod raw {
    use super::*;

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
        if device_size.saturating_sub(image_size) > super::LARGE_DRIVE_SLACK {
            Some(format!(
                "write: large device of {device_size} bytes for a {image_size} byte image, {} bytes left untouched",
                device_size.saturating_sub(image_size)
            ))
        } else {
            None
        }
    }

    /// Stream the image to the device in [`CHUNK`](super::CHUNK)-sized
    /// pieces.
    pub(crate) fn run(ctx: &mut RunContext<'_>, image: &ImageRef, verify: bool) -> Result<()> {
        if verify {
            // Slice 7 replaces this with the real read-back check; until
            // then the flag warns instead of vanishing silently.
            ctx.reporter.event(Event::Message {
                level: "warn",
                text: "verify requested but verification is not implemented yet (slice 7): continuing without it"
                    .to_string(),
            });
        }
        let mut file =
            File::open(&image.path).map_err(|source| CoreError::io(&image.path, source))?;
        let len = file
            .metadata()
            .map_err(|source| CoreError::io(&image.path, source))?
            .len();
        if len != image.size_bytes {
            return Err(CoreError::invalid(format!(
                "image file '{}' is {len} bytes but the plan describes {} bytes: refusing to write a different file",
                image.path, image.size_bytes
            )));
        }
        let size = ctx.device()?.size();
        if len > size {
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
        let mut buf = vec![0u8; super::CHUNK];
        let mut done = 0u64;
        let mut ema = RateEma::new();
        let mut last_emit = Instant::now();
        while done < len {
            check_cancelled(ctx)?;
            let want = (len - done).min(super::CHUNK as u64) as usize;
            let chunk = buf
                .get_mut(..want)
                .ok_or_else(|| CoreError::invalid("write chunk window runs past its buffer"))?;
            read_chunk(&mut file, &image.path, chunk, done)?;
            let chunk_started = Instant::now();
            // Copy the probe out first: the device borrow below rules
            // out holding another `ctx` borrow across the call.
            let cancelled = ctx.cancelled;
            let written =
                ctx.device()?
                    .write_all_at_cancellable(done, chunk, super::CHUNK, cancelled)?;
            if written < want as u64 {
                // The contract reads a short count as cancellation: a
                // target that reports full while swallowing bytes cannot
                // be detected here, which is why the verify pass
                // (slice 7) exists. This is the honest form of Rufus's
                // `Wrote %d bytes, expected %d bytes` check.
                return Err(CoreError::Cancelled);
            }
            if written > want as u64 {
                // Impossible by contract (no more than the chunk went
                // in): a target that claims otherwise is faulty, not
                // cancelled, so it refuses by name with both numbers.
                return Err(CoreError::invalid(format!(
                    "target reported {written} bytes written for a {want} byte chunk at offset {done}: refusing an impossible count"
                )));
            }
            done = done.saturating_add(written);
            ema.observe(want as u64, chunk_started.elapsed());
            let remaining = len.saturating_sub(done);
            if last_emit.elapsed() >= super::PROGRESS_INTERVAL || done == len {
                last_emit = Instant::now();
                ctx.reporter.event(Event::Progress {
                    step: "write",
                    done,
                    total: Some(len),
                    bytes_per_second: ema.bytes_per_second(),
                    eta_seconds: ema.eta_seconds(remaining),
                });
            }
        }
        // Zero the tail from the image end up to the next sector
        // boundary — never the whole remaining device, whose tail is
        // the plan's business: zeroing tens of gigabytes because of a
        // small image would be data loss twice over. Clamped to the
        // device (an exactly device-sized but unaligned image has no
        // room past itself) and skipped for a zero sector size.
        let sector = u64::from(ctx.device()?.sector_size());
        if sector != 0 && len % sector != 0 {
            let end = (len / sector + 1).saturating_mul(sector).min(size);
            if end > len {
                ctx.device()?.zero_range(len, end - len)?;
            }
        }
        ctx.device()?.flush()?;
        ctx.device()?.reread_partitions()?;
        Ok(())
    }

    /// Fill `chunk` from the image file: `read_exact` semantics, so a
    /// short read before EOF is an I/O error naming the offset (the
    /// Rufus `Read error` shape, with its class kept).
    fn read_chunk(file: &mut File, path: &String, chunk: &mut [u8], offset: u64) -> Result<()> {
        file.read_exact(chunk).map_err(|error| {
            CoreError::io(
                path,
                std::io::Error::new(
                    error.kind(),
                    format!("read error at image offset {offset}: {error}"),
                ),
            )
        })
    }

    #[cfg(test)]
    mod tests {
        use std::time::Duration;

        use super::*;

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
