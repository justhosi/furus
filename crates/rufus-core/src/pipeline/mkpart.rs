//! The mkpart step: stamp the recorded table with its partitions.
//!
//! The step refuses a scheme that disagrees with the table
//! [`Mklabel`](super::mklabel) recorded (naming both); a missing
//! recording is not a refusal — `Mklabel` is validation-only, and the
//! stamp carries its own scheme and layout. Geometry comes from the target: sector
//! size straight off it, `last_lba` as `floor(size / sector_size) - 1`
//! (the trailing partial sector is unused by construction — e.g. a
//! 64 MiB + 1234 byte target plans over full sectors only; a target
//! smaller than one sector refuses, naming the size). The data
//! type follows the plan's filesystem (see [`data_type_of`]): FAT32
//! stamps `0x0c` so DOS-family loaders can read the volume, the ext
//! family `0x83`, exFAT and NTFS `0x07`. The geometry does not depend
//! on the type, so the platform opener's window math is unchanged.
//! Every [`SectorWrite`](crate::part::plan::SectorWrite)
//! goes down through the cancellable path (chunk = the sector size)
//! with one [`Progress`](crate::pipeline::event::Event::Progress) per
//! write, then `flush()` and `reread_partitions()` close the step and
//! the partition counts as existing for
//! [`Mkfs`](rufus_proto::Step::Mkfs).

use rufus_proto::Filesystem;
use rufus_proto::Layout;
use rufus_proto::Scheme;

use crate::error::CoreError;
use crate::error::Result;
use crate::part::plan;
use crate::part::plan::PlanRequest;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::layout_kind_of;
use crate::pipeline::steps::table_kind_of;
use crate::pipeline::steps::table_name;

/// The `data` partition's type for the plan's filesystem.
///
/// Each filesystem maps to the type its readers expect, and the
/// planner derives both the MBR byte and the GPT GUID from it:
/// FAT32 is `0x0c` (FAT32 LBA), which FreeDOS and the other DOS-family
/// loaders need before they will read the volume at all. exFAT and
/// NTFS are `0x07`, the ext family is `0x83` (Linux), and UDF takes
/// the catch-all basic data type.
fn data_type_of(filesystem: &Filesystem) -> plan::DataType {
    match filesystem {
        Filesystem::Fat32 => plan::DataType::Fat32,
        Filesystem::Exfat => plan::DataType::Exfat,
        Filesystem::Ntfs => plan::DataType::Ntfs,
        Filesystem::Ext2 | Filesystem::Ext3 | Filesystem::Ext4 => plan::DataType::Linux,
        Filesystem::Udf => plan::DataType::MicrosoftBasicData,
    }
}

/// Stamp the table: plan the step's layout for the step's scheme,
/// render it against the real geometry and write every sector. The
/// `data` partition takes its type from `filesystem` (see
/// [`data_type_of`]).
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    scheme: &Scheme,
    layout: &Layout,
    filesystem: &Filesystem,
) -> Result<()> {
    let kind = table_kind_of(scheme);
    let layout_kind = layout_kind_of(layout);
    match ctx.table {
        Some(recorded) if recorded == kind => {}
        Some(recorded) => {
            return Err(CoreError::invalid(format!(
                "scheme {} disagrees with recorded mklabel scheme {}",
                table_name(kind),
                table_name(recorded)
            )));
        }
        None => {}
    }
    let size = ctx.device()?.size();
    let sector_size = ctx.device()?.sector_size();
    // The request the platform opener re-derives for its partition
    // window (see `data_window`): one constructor, so the
    // stamped table and the formatted window cannot disagree.
    let request: PlanRequest = plan::request(
        layout_kind,
        kind,
        sector_size,
        size,
        data_type_of(filesystem),
    )?;
    let table_plan = plan::plan(&request)?;
    let rendered = plan::render(&table_plan, sector_size, request.last_lba)?;
    let total = rendered.byte_len();
    let mut placed: u64 = 0;
    for write in rendered.writes.iter() {
        let offset = write
            .lba
            .checked_mul(u64::from(sector_size))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "lba {} times sector size {sector_size} overflows the byte arithmetic",
                    write.lba
                ))
            })?;
        // A short count means the write loop gave up to cancellation:
        // refuse before counting the bytes or emitting Progress, so a
        // cancelled stamp can never report success.
        let cancelled = ctx.cancelled;
        let written = ctx.device()?.write_all_at_cancellable(
            offset,
            &write.bytes,
            sector_size as usize,
            cancelled,
        )?;
        if written != write.bytes.len() as u64 {
            return Err(CoreError::Cancelled);
        }
        placed = placed.saturating_add(written);
        ctx.reporter.event(Event::Progress {
            step: "mkpart",
            done: placed,
            total: Some(total),
            bytes_per_second: 0,
            eta_seconds: None,
        });
    }
    ctx.device()?.flush()?;
    ctx.device()?.reread_partitions()?;
    ctx.partitioned = Some((kind, layout_kind));
    Ok(())
}
