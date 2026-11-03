//! The mklabel step: validate the requested table, nothing more.
//!
//! A table and its partition entries are one on-disk structure
//! (`part::render` emits LBA0, the entry array and the backup header as
//! one consistent image), so writing a table with no entries would stamp
//! a momentarily invalid state. `Mklabel` therefore records the
//! requested [`TableKind`](crate::part::TableKind) in the run context
//! and [`Mkpart`](super::mkpart) performs the single atomic stamp.

use rufus_proto::Scheme;

use crate::error::Result;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::table_kind_of;
use crate::pipeline::steps::table_name;

/// Record the requested table kind for [`Mkpart`](super::mkpart): no
/// I/O, one message naming the scheme.
pub(crate) fn run(ctx: &mut RunContext<'_>, scheme: &Scheme) -> Result<()> {
    let kind = table_kind_of(scheme);
    ctx.table = Some(kind);
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!(
            "mklabel: recording {} table (written atomically by mkpart)",
            table_name(kind)
        ),
    });
    Ok(())
}
