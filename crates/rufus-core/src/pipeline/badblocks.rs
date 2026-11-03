//! The bad-blocks surface scan: write test patterns over the whole
//! device and read them back, reporting the ranges that differ.
//!
//! A bounded port of the 1222-line `0x140011ac0` (the format thread,
//! which frames the check with `Rufus bad blocks check started on:`
//! and `Rufus bad blocks check ended on:` log lines plus the `Bad
//! Blocks: Check completed, %d bad block%s found. (%d/%d/%d errors)`
//! summary) and its `0x140001450` worker (one pass per pattern with `Writing
//! test pattern 0x%02X` then `Reading and comparing` phases over
//! `0x80000`-byte blocks, an in-memory bad-range list, and `Too many
//! bad blocks, aborting test` when the device fails badly). PLAN
//! §9-S17 fixes the shape ported here: patterns `00 FF AA 55`, block
//! size from the device, read-back compare, bad-range list, abort
//! threshold, report in the log (here: [`Event::Message` lines, since
//! this pipeline has no log file of its own).
//!
//! Placement: Rufus offers the check as part of preparing the device,
//! and the plan has no dedicated step for it, so the scan rides in
//! [`Wipe`](super::wipe::run) after the zeroing (and the rescan),
//! before any table, format or write step — and only when
//! [`RunOptions::badblocks`](super::RunOptions::badblocks) is set.
//! The scan is destructive by design (each pass overwrites the whole
//! device; the last pass leaves `0x55` behind): later steps overwrite
//! the surface anyway, which is why living in `Wipe` is safe.
//!
//! Differences from the reference, all deliberate: the block is the
//! reference's 512 KiB (`0x80000`), shortened for the last block —
//! the sector size stays the floor (a larger sector still scans
//! exactly); writes go through plain [`write_all_at`](super::Target::write_all_at)
//! rather than a cancellable loop — cancellation happens between
//! blocks, and mid-block cancellation is not claimed; the abort
//! threshold below is this project's policy (the reference aborts
//! too, but the decompiled evidence carries no constant, so none is
//! claimed here).

use std::time::Instant;

use super::write::CHUNK;
use super::write::RateEma;
use super::write::emit_progress;
use crate::error::CoreError;
use crate::error::Result;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::check_cancelled;

/// Test patterns in pass order (PLAN §9-S17; the reference worker
/// walks the same `00`/`FF`/`AA`/`55` family).
const PATTERNS: [u8; 4] = [0x00, 0xFF, 0xAA, 0x55];

/// Scan block in bytes: the reference's `0x80000`. Every pass
/// covers the device in these blocks (the last shortened to the
/// remaining bytes); a device reporting a larger sector still scans
/// exactly — the sector size is the floor, not the block.
const BLOCK: u64 = 512 * 1024;

/// Abort when the bad bytes exceed this percent of the device size.
/// Project policy, not reference behaviour (see the module docs): a
/// device failing that badly must not be written.
const ABORT_BAD_PERCENT: u64 = 1;

/// Cap on retained bad ranges: the summary can name the first range
/// however badly the device fails, without an unbounded list. Bytes
/// past the cap are still counted (see [`BadReport::record`]), only
/// their ranges are dropped, and the summary says so.
const MAX_RANGES: usize = 256;

/// Bounded bad-block report: merged ascending byte ranges plus the
/// exact bad-byte count, so the summary names the first offset and
/// the refusal names exact counts however many ranges a failing
/// device produces.
#[derive(Debug, Default)]
struct BadReport {
    /// Bad `(offset, len)` ranges, ascending, non-overlapping,
    /// merged on insert; at most [`MAX_RANGES`].
    ranges: Vec<(u64, u64)>,
    /// Bad bytes, including bytes whose ranges fell past the cap.
    bad_bytes: u64,
    /// True once a range was dropped for the cap.
    truncated: bool,
}

impl BadReport {
    /// Record a differing `[offset, offset + len)` window. Passes
    /// restart at offset 0, so records arrive out of order across
    /// passes: every stored range the window touches (overlap or
    /// adjacency — the list is sorted, so they sit together) folds
    /// into one span, and only bytes outside all stored ranges grow
    /// the count, keeping unique bad bytes exact. A touched run is
    /// replaced in place (the list never grows there); an untouched
    /// window appends in sorted order until the cap, past which bytes
    /// still count but ranges drop (setting
    /// [`truncated`](BadReport::truncated)).
    fn record(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let end = offset.saturating_add(len);
        let mut start = offset;
        let mut merged_end = end;
        let mut covered = 0u64;
        let mut begin = self.ranges.len();
        let mut past = begin;
        if let Some(found) = self
            .ranges
            .iter()
            .position(|range| range.0.saturating_add(range.1) >= offset)
        {
            begin = found;
            past = found;
            for range in self.ranges.iter().skip(found) {
                if range.0 > merged_end {
                    break;
                }
                let range_end = range.0.saturating_add(range.1);
                start = start.min(range.0);
                merged_end = merged_end.max(range_end);
                covered =
                    covered.saturating_add(end.min(range_end).saturating_sub(offset.max(range.0)));
                past += 1;
            }
        }
        if past == begin && self.ranges.len() >= MAX_RANGES {
            // Untouched window with a full list: the bytes still
            // count, the range drops.
            self.bad_bytes = self.bad_bytes.saturating_add(len);
            self.truncated = true;
            return;
        }
        self.bad_bytes = self.bad_bytes.saturating_add(len.saturating_sub(covered));
        self.ranges.drain(begin..past);
        self.ranges
            .insert(begin, (start, merged_end.saturating_sub(start)));
    }

    /// First bad offset, if any range was retained (the first record
    /// always is: the list starts empty, so truncation can never drop
    /// it).
    fn first_offset(&self) -> Option<u64> {
        self.ranges.first().map(|range| range.0)
    }
}

/// Fold one read-back piece into the report: every run of bytes
/// differing from the pattern becomes a [`BadReport::record`]. Runs
/// cannot straddle pieces — a differing run continues into the next
/// piece as a second record, and merging joins the fragments whatever
/// pass order produced them.
fn record_differences(report: &mut BadReport, expected: &[u8], actual: &[u8], base: u64) {
    let mut run: Option<u64> = None;
    let mut index = 0u64;
    for (want, got) in expected.iter().zip(actual.iter()) {
        if want != got {
            if run.is_none() {
                run = Some(base + index);
            }
        } else if let Some(start) = run.take() {
            report.record(start, base + index - start);
        }
        index += 1;
    }
    if let Some(start) = run {
        report.record(start, base + index - start);
    }
}

/// True once the bad bytes exceed [`ABORT_BAD_PERCENT`] percent of
/// the device size (strictly exceed: exactly 1% still scans).
/// Multiplication, never division, and saturating math keeps absurd
/// device sizes total instead of panicking.
fn over_threshold(report: &BadReport, size: u64) -> bool {
    report
        .bad_bytes
        .saturating_mul(100)
        .gt(&size.saturating_mul(ABORT_BAD_PERCENT))
}

/// The one summary [`Message`](Event::Message) every non-cancelled
/// ending reports, always in bytes: `no bad bytes found` on a clean
/// device, otherwise the bad-byte count with the first offset (plus a
/// truncation note when ranges fell past the cap). Cancellation
/// reports no summary — the scan never finished, so any count would
/// lie.
fn summarize(ctx: &mut RunContext<'_>, report: &BadReport) {
    let (level, mut text) = match report.first_offset() {
        None => ("info", "no bad bytes found".to_string()),
        Some(first) => (
            "warn",
            format!(
                "{bad} bad bytes (first at offset {first})",
                bad = report.bad_bytes
            ),
        ),
    };
    if report.truncated {
        text.push_str(&format!("; range list truncated past {MAX_RANGES} ranges"));
    }
    ctx.reporter.event(Event::Message { level, text });
}

/// Stop the scan for the abort threshold: the summary first (so the
/// log still carries the count), then the refusal naming the bad
/// count, the device size, the first offset and the threshold. Like
/// every in-run error except `NotImplemented`, [`run`](super::run)
/// wraps this as `step 'wipe'`.
fn abort(ctx: &mut RunContext<'_>, report: &BadReport, size: u64) -> Result<()> {
    summarize(ctx, report);
    let bad = report.bad_bytes;
    if let Some(first) = report.first_offset() {
        return Err(CoreError::invalid(format!(
            "bad-blocks scan aborted: {bad} bad bytes of {size} bytes (first at offset {first}) exceed the {ABORT_BAD_PERCENT}% abort threshold: refusing to write a failing device"
        )));
    }
    Err(CoreError::invalid(format!(
        "bad-blocks scan aborted: {bad} bad bytes of {size} bytes exceed the {ABORT_BAD_PERCENT}% abort threshold: refusing to write a failing device"
    )))
}

/// Run the scan over the whole device: four passes, one per
/// [`PATTERNS`] entry, each writing the pattern block by block and
/// reading it back for comparison. Progress runs under the
/// event-level `"badblocks"` pseudo-step — not a plan step (see
/// [`step_name`](super::step_name), which stays unchanged) — at the
/// shared [`PROGRESS_INTERVAL`](super::write::PROGRESS_INTERVAL)
/// cadence plus one final sample, with `done` counting the current
/// pass's bytes against the device size. Cancellation is checked
/// between blocks; a block already under I/O runs to completion
/// (mid-block cancellation is not claimed). A device whose read-back
/// differs anywhere refuses after its summary (see [`abort`] for the
/// early exit); I/O errors from the target propagate untouched — only
/// pattern mismatches become the `invalid` refusal below. That class
/// is deliberate: a mismatch is a verdict about the media, not an OS
/// error, and synthesising an errno for it would lie — so the refusal
/// routes where `Fail::from_core` already puts validation refusals,
/// and the CLI's exit mapping stays coherent.
pub(crate) fn run(ctx: &mut RunContext<'_>) -> Result<()> {
    let size = ctx.device()?.size();
    let sector = u64::from(ctx.device()?.sector_size());
    if sector == 0 {
        return Err(CoreError::invalid(
            "bad-blocks scan needs the device sector size: the target reports 0",
        ));
    }
    let block = sector.max(BLOCK);
    // A block is one compare unit; pieces split a block only to bound
    // the hoisted buffers at the write chunk size — a hostile sector
    // size must not dictate a gigabyte allocation either way.
    let piece_len = block.min(CHUNK as u64) as usize;
    let mut pattern_buf = vec![0u8; piece_len];
    let mut read_buf = vec![0u8; piece_len];
    let mut report = BadReport::default();
    let mut ema = RateEma::new();
    let mut last_emit = Instant::now();
    for (pass, pattern) in PATTERNS.iter().enumerate() {
        let pass_no = pass + 1;
        ctx.reporter.event(Event::Message {
            level: "info",
            text: format!(
                "badblocks pass {pass_no} of {} (pattern 0x{pattern:02X})",
                PATTERNS.len()
            ),
        });
        let mut offset = 0u64;
        let mut pass_done = 0u64;
        while offset < size {
            check_cancelled(ctx)?;
            let len = (size - offset).min(block);
            let mut pos = offset;
            while pos < offset + len {
                let n = (offset + len - pos).min(piece_len as u64) as usize;
                let window = pattern_buf.get_mut(..n).ok_or_else(|| {
                    CoreError::invalid("bad-blocks pattern window runs past its buffer")
                })?;
                window.fill(*pattern);
                let started = Instant::now();
                ctx.device()?.write_all_at(pos, window)?;
                let back = read_buf.get_mut(..n).ok_or_else(|| {
                    CoreError::invalid("bad-blocks read window runs past its buffer")
                })?;
                ctx.device()?.read_at(pos, back)?;
                ema.observe(n as u64, started.elapsed());
                record_differences(&mut report, window, back, pos);
                pos += n as u64;
                pass_done += n as u64;
                if over_threshold(&report, size) {
                    return abort(ctx, &report, size);
                }
            }
            offset += len;
            let final_sample = pass + 1 == PATTERNS.len() && offset >= size;
            emit_progress(
                ctx,
                "badblocks",
                pass_done,
                Some(size),
                &ema,
                &mut last_emit,
                final_sample,
            );
        }
    }
    summarize(ctx, &report);
    if let Some(first) = report.first_offset() {
        let bad = report.bad_bytes;
        let ranges = report.ranges.len();
        let noun = if ranges == 1 { "range" } else { "ranges" };
        let mut text = format!(
            "bad-blocks scan found {bad} bad bytes in {ranges} {noun} (first at offset {first}): refusing to write a failing device"
        );
        if report.truncated {
            text.push_str(&format!("; range list truncated past {MAX_RANGES} ranges"));
        }
        return Err(CoreError::invalid(text));
    }
    Ok(())
}
