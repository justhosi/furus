//! The wipe step: clear the device's edge megabytes like
//! `rufus-linux`'s `wipe_device`, without depending on it.
//!
//! Parity points: per-window `discard` hints best effort (errors
//! swallowed — an unsupported primitive must not fail the run), then
//! authoritative zeroing, then `reread_partitions`. Differences, both
//! deliberate: the discards go per window rather than whole-device
//! (a whole-device hint can address past the end on a tiny device),
//! cancellation is checked before each I/O phase — four in the
//! two-window shape, two in the small-device shape — one
//! `Message` names each phase's byte counts, and there is no trailing
//! flush here — `Finalize` owns the run's flush.
//!
//! A device smaller than two windows zeroes (and hints) its whole
//! extent instead: the front and rear windows would overlap otherwise,
//! and the rear offset would wrap. A zero-size device is a no-op, the
//! same correct sequence `wipe_device` runs.

use crate::error::Result;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::check_cancelled;

/// One wipe window in bytes (1 MiB, the `wipe_device` window).
const WINDOW: u64 = 1024 * 1024;

/// Clear the device's edge megabytes: discard hints best effort, then
/// zeroing, then a partition re-read.
pub(crate) fn run(ctx: &mut RunContext<'_>) -> Result<()> {
    let size = ctx.device()?.size();
    if size == 0 {
        return Ok(());
    }
    if size < WINDOW.saturating_mul(2) {
        // One pass over the whole (small) extent: no overlap, no
        // underflow on the rear offset.
        check_cancelled(ctx)?;
        let _ = ctx.device()?.discard(0, size);
        ctx.reporter.event(Event::Message {
            level: "info",
            text: format!("wipe: discard hint for bytes 0..{size}"),
        });
        check_cancelled(ctx)?;
        let cancelled = ctx.cancelled;
        ctx.device()?.zero_range(0, size, cancelled)?;
        ctx.reporter.event(Event::Message {
            level: "info",
            text: format!("wipe: zeroing bytes 0..{size}"),
        });
    } else {
        // The two-window shape: front and rear megabyte.
        let rear = size.saturating_sub(WINDOW);
        for offset in [0, rear] {
            check_cancelled(ctx)?;
            let _ = ctx.device()?.discard(offset, WINDOW);
            let end = offset.saturating_add(WINDOW);
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!("wipe: discard hint for bytes {offset}..{end}"),
            });
        }
        for offset in [0, rear] {
            check_cancelled(ctx)?;
            let cancelled = ctx.cancelled;
            ctx.device()?.zero_range(offset, WINDOW, cancelled)?;
            let end = offset.saturating_add(WINDOW);
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!("wipe: zeroing bytes {offset}..{end}"),
            });
        }
    }
    ctx.device()?.reread_partitions()?;
    Ok(())
}
