//! Shared step machinery: the per-run context and the helpers every
//! step module uses.
//!
//! [`RunContext`] threads the run state through the steps so slices 3+
//! can add fields without re-plumbing every signature. One convention
//! the step modules follow: cancellation inside a step reports bare
//! [`Cancelled`](crate::error::CoreError::Cancelled) — [`run`](super::run)
//! wraps every step error with the step name, so naming it inside too
//! would stutter. (The boundary check in [`run`](super::run) keeps its
//! own wrapper for the same reason.) Step-name literals in messages and
//! [`Event`] payloads must match [`step_name`](super::step_name)
//! exactly. [`NotImplemented`](crate::error::CoreError::NotImplemented)
//! is the one exception to the wrapper: its `what` already names the
//! step, so wrapping it would stutter instead.

use std::sync::Arc;

use rufus_proto::Layout;
use rufus_proto::Scheme;

use super::RunOptions;
use crate::error::CoreError;
use crate::error::Result;
use crate::log::Level;
use crate::log::Logger;
use crate::part::TableKind;
use crate::part::plan::LayoutKind;
use crate::pipeline::event::Event;
use crate::pipeline::event::Reporter;
use crate::pipeline::opener::Opener;
use crate::pipeline::target::Target;

/// Private per-run state threaded through the steps: the supplier, the
/// opened whole-disk handle, what the table steps recorded, the shared
/// logger, and the run's reporter and cancellation probe.
pub(crate) struct RunContext<'a> {
    /// Who supplies the stores.
    pub(crate) opener: &'a dyn Opener,
    /// The whole-disk handle, opened lazily once on first use and reused
    /// by every step afterwards: a plan that never touches the device
    /// never opens it, and platform opens (exclusive on real devices)
    /// happen exactly once per run. See [`RunContext::device`].
    pub(crate) target: Option<Box<dyn Target>>,
    /// The table [`Mklabel`](rufus_proto::Step::Mklabel) recorded, if
    /// any.
    pub(crate) table: Option<TableKind>,
    /// Set once [`Mkpart`](rufus_proto::Step::Mkpart) stamped a table:
    /// the table and layout it stamped. [`Mkfs`](rufus_proto::Step::Mkfs)
    /// refuses while it is `None`, and reads the data window back from
    /// the same pair so the formatted partition is the one stamped.
    pub(crate) partitioned: Option<(TableKind, LayoutKind)>,
    /// The run's logger, kept for the whole run (path-based formatters
    /// borrow it; see [`mirror_log`]).
    pub(crate) logger: Arc<Logger>,
    /// Where step events go.
    pub(crate) reporter: &'a mut dyn Reporter,
    /// Cancellation probe, checked at step boundaries by [`run`](super::run)
    /// and inside the steps through [`check_cancelled`].
    pub(crate) cancelled: &'a dyn Fn() -> bool,
    /// Run-wide options (verify, retry policy): carried here so step
    /// signatures stay stable as slices add knobs.
    pub(crate) options: RunOptions,
}

impl<'a> RunContext<'a> {
    /// The run's whole-disk handle: opens it on first use, reuses it
    /// afterwards. Fallible and borrow-clean (no interior-mutability
    /// cell): callers copy out any sibling borrows, like the
    /// cancellation probe, before calling.
    pub(crate) fn device(&mut self) -> Result<&mut dyn Target> {
        if self.target.is_none() {
            self.target = Some(self.opener.device()?);
        }
        // Stored just above when missing, so present; the fallback keeps
        // this total without a panic.
        match self.target.as_mut() {
            Some(target) => Ok(target.as_mut()),
            None => Err(CoreError::invalid("pipeline device vanished after opening")),
        }
    }

    /// Release the whole-disk handle for the external formatters: flush
    /// what is buffered, drop the open handle, and tell the opener to
    /// forget its cached handle too, so the next [`device`](RunContext::device)
    /// reopens from scratch. The tool-based `Mkfs` arms (`mke2fs`,
    /// `mkntfs`, `mkudffs`) call this immediately before asking for the
    /// partition node path: those tools want their own exclusive claim
    /// on the node, which conflicts with the pipeline's open whole-disk
    /// handle on a real device. A flush failure still drops the handle
    /// (nothing is lost by closing) and reports the flush error.
    pub(crate) fn release_device(&mut self) -> Result<()> {
        let taken = self.target.take();
        if let Some(target) = taken {
            target.flush()?;
        }
        self.opener.release()
    }
}

/// Fail when the run is cancelled. The error names no step: [`run`]
/// (super::run) wraps every step error with its step already.
pub(crate) fn check_cancelled(ctx: &RunContext<'_>) -> Result<()> {
    if (ctx.cancelled)() {
        return Err(CoreError::Cancelled);
    }
    Ok(())
}

/// The [`TableKind`] a plan [`Scheme`] asks for.
pub(crate) fn table_kind_of(scheme: &Scheme) -> TableKind {
    match scheme {
        Scheme::Mbr => TableKind::Mbr,
        Scheme::Gpt => TableKind::Gpt,
    }
}

/// The [`LayoutKind`] a plan [`Layout`] asks for: the same mapping the
/// opener's partition window and node spelling run with, so the
/// stamped table, the formatted window and the node agree.
pub(crate) fn layout_kind_of(layout: &Layout) -> LayoutKind {
    match layout {
        Layout::Single => LayoutKind::Single,
        Layout::UefiNtfs => LayoutKind::UefiNtfs,
        Layout::WindowsToGo => LayoutKind::WindowsToGo,
        Layout::Persistence => LayoutKind::Persistence,
    }
}

/// The table name refusals and messages use (`mbr`/`gpt`, mirroring the
/// serde wire tags).
pub(crate) fn table_name(kind: TableKind) -> &'static str {
    match kind {
        TableKind::Mbr => "mbr",
        TableKind::Gpt => "gpt",
    }
}

/// Replay the logger records logged after `before` (a
/// `snapshot().len()` cursor taken before the call) into
/// [`Event::Message`] lines, so tool output surfaces in the event
/// stream.
pub(crate) fn mirror_log(ctx: &mut RunContext<'_>, before: usize) {
    for record in ctx.logger.replay_from(before) {
        let level = match record.level {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        };
        ctx.reporter.event(Event::Message {
            level,
            text: record.message,
        });
    }
}
