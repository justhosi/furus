//! The mkfs step: format the stamped data partition.
//!
//! The partition must exist: without a prior `Mkpart` the step refuses
//! by name before opening anything. The open happens once through
//! [`Opener::partition`](crate::pipeline::opener::Opener::partition)
//! and the box is kept for the whole step.
//!
//! `quick == false` is a full surface format (the Rufus "quick format"
//! distinction): the partition zeroes first, in cancellable 1 MiB
//! pieces with a `Message` naming the bytes; `quick == true` writes
//! metadata only. Bad-block scanning during a full format arrives in
//! slice 9. Cancellation is checked before zeroing and before the
//! formatter call; a formatter in flight cannot be interrupted (one
//! external tool call or one tight metadata write) — honest, and slice
//! 9 owns the long scan.
//!
//! Engine mapping, exhaustive: FAT32 and exFAT format natively against
//! the partition volume (serial from a fresh v4 UUID, non-zero refused
//! rather than substituted); NTFS, ext2/3/4 and UDF drive their
//! external tools against the partition node path with a run logger
//! whose new records mirror into the event stream. Constructor
//! refusals (a non-power-of-two cluster size, a bad label) pass
//! through untouched.

use std::path::Path;

use rufus_proto::Filesystem;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::exfat;
use crate::fs::ext;
use crate::fs::fat32;
use crate::fs::ntfs;
use crate::fs::udf;
use crate::log::Logger;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::steps::check_cancelled;
use crate::pipeline::steps::mirror_log;

/// Zero piece for the full-surface pass (1 MiB, the wipe window).
const ZERO_PIECE: u64 = 1024 * 1024;

/// A fresh non-zero 32-bit volume serial from a v4 UUID.
fn fresh_serial(what: &str) -> Result<u32> {
    let serial = uuid::Uuid::new_v4().as_u128() as u32;
    if serial == 0 {
        return Err(CoreError::invalid(format!(
            "generated {what} volume id is zero: refusing to ship an unset serial rather than substituting one"
        )));
    }
    Ok(serial)
}

/// Zero the whole partition in [`ZERO_PIECE`] pieces, checking
/// cancellation between pieces.
fn zero_partition(ctx: &RunContext<'_>, partition: &mut dyn Volume) -> Result<()> {
    let total = partition.total_bytes();
    let zeros = vec![0u8; ZERO_PIECE as usize];
    let mut pos = 0u64;
    while pos < total {
        check_cancelled(ctx)?;
        let piece = total.saturating_sub(pos).min(ZERO_PIECE);
        let piece_len = usize::try_from(piece).map_err(|_| {
            CoreError::invalid(format!("zero window of {piece} bytes does not fit"))
        })?;
        let window = zeros
            .get(..piece_len)
            .ok_or_else(|| CoreError::invalid("zero window runs past its buffer".to_string()))?;
        partition.write_all_at(pos, window)?;
        pos = pos.saturating_add(piece);
    }
    Ok(())
}

/// Format through an external tool against the partition node path,
/// mirroring the run logger's new records into the event stream on both
/// paths: a failing tool's log lines are exactly what the caller needs
/// to diagnose the refusal, so they are mirrored before the error
/// returns. `format` drives `mke2fs`/`mkntfs`/`mkudffs` through `fs::tool`
/// and never touches the `Volume` box.
fn format_with_tool(
    ctx: &mut RunContext<'_>,
    run: &dyn Fn(&Path, &Logger) -> Result<()>,
) -> Result<()> {
    let path = ctx.opener.partition_path()?;
    let before = ctx.logger.snapshot().len();
    let result = run(&path, &ctx.logger);
    mirror_log(ctx, before);
    result
}

/// Format the data partition with the step's engine and label.
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    filesystem: &Filesystem,
    label: &Option<String>,
    cluster_bytes: &Option<u32>,
    quick: bool,
) -> Result<()> {
    if !ctx.partitioned {
        return Err(CoreError::invalid(
            "no partition was created to format (run mkpart first)",
        ));
    }
    check_cancelled(ctx)?;
    let mut partition = ctx.opener.partition()?;
    if !quick {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: format!(
                "mkfs: zeroing {} partition bytes for a full-surface format",
                partition.total_bytes()
            ),
        });
        zero_partition(ctx, partition.as_mut())?;
    }
    check_cancelled(ctx)?;
    match filesystem {
        Filesystem::Fat32 => {
            let options = fat32::format::FormatOptions {
                label: label.as_deref(),
                volume_id: fresh_serial("fat32")?,
                oem: fat32::bpb::DEFAULT_OEM,
            };
            fat32::format::format(partition.as_mut(), &options)?;
            Ok(())
        }
        Filesystem::Exfat => {
            let mut options = exfat::format::FormatOptions::new(fresh_serial("exfat")?);
            options.label = label.clone();
            options.cluster_bytes = *cluster_bytes;
            exfat::format::format(partition.as_mut(), &options)?;
            Ok(())
        }
        Filesystem::Ntfs => {
            let mut options = ntfs::Options::new(label.clone());
            if let Some(bytes) = cluster_bytes {
                options = options.with_cluster_bytes(*bytes)?;
            }
            format_with_tool(ctx, &|path, logger| {
                ntfs::format(path, &options, logger)?;
                Ok(())
            })
        }
        Filesystem::Ext2 => format_ext(ctx, ext::Flavour::Ext2, label),
        Filesystem::Ext3 => format_ext(ctx, ext::Flavour::Ext3, label),
        Filesystem::Ext4 => format_ext(ctx, ext::Flavour::Ext4, label),
        Filesystem::Udf => {
            let block = match ctx.device()?.sector_size() {
                512 => udf::BlockSize::Bytes512,
                // 2048-byte blocks are the tool's largest: 4Kn media
                // formats with them.
                2048 | 4096 => udf::BlockSize::Bytes2048,
                other => {
                    return Err(CoreError::invalid(format!(
                        "sector size {other} is not supported for udf: udf formats 512 and 2048 byte blocks"
                    )));
                }
            };
            let mut options = udf::Options::new(block);
            if let Some(name) = label {
                options = options.with_label(name.clone())?;
            }
            format_with_tool(ctx, &|path, logger| {
                udf::format(path, &options, logger)?;
                Ok(())
            })
        }
    }
}

/// Format through `mke2fs` with `flavour`, attaching the step label
/// when one is set.
fn format_ext(
    ctx: &mut RunContext<'_>,
    flavour: ext::Flavour,
    label: &Option<String>,
) -> Result<()> {
    let mut options = ext::Options::new(flavour);
    if let Some(name) = label {
        options = options.with_label(name.clone())?;
    }
    format_with_tool(ctx, &|path, logger| {
        ext::format(path, &options, logger)?;
        Ok(())
    })
}
