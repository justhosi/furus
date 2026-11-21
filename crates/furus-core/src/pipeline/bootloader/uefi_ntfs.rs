use furus_proto::Filesystem;

use crate::boot::Resource;
use crate::boot::uefi_ntfs;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::part::TableKind;
use crate::part::plan::LayoutKind;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;

use super::DiskView;
use super::Installed;
use super::filesystem_name;

/// UEFI:NTFS gates plus the ESP window: the filesystem gate mirrors
/// the reference (`furus.c:2032-2037`: NTFS or exFAT only, naming the
/// plan filesystem otherwise); the table gate mirrors [`gap_end`] (no
/// recorded table, no window); the window comes from
/// [`esp_window`](crate::part::plan::esp_window) over the `UefiNtfs`
/// layout the mode implies. Returns `(offset, end)` with `end`
/// overflow-checked. Shared by [`install_uefi_ntfs`] and
/// [`run_uefi_ntfs`] so a refused plan fails before any image read —
/// production's 1 MiB `load` runs only after these gates pass.
pub(super) fn uefi_ntfs_window(
    disk: &dyn Volume,
    table: Option<TableKind>,
    filesystem: &Filesystem,
) -> Result<(u64, u64)> {
    match filesystem {
        Filesystem::Ntfs | Filesystem::Exfat => {}
        _ => {
            return Err(CoreError::invalid(format!(
                "uefi-ntfs installation needs an NTFS or exFAT data partition, the plan carries {}: refusing",
                filesystem_name(filesystem)
            )));
        }
    }
    let table = table.ok_or_else(|| {
        CoreError::invalid(
            "uefi-ntfs install needs a recorded partition table to locate the ESP window: refusing"
                .to_string(),
        )
    })?;
    let (offset, len) = crate::part::plan::esp_window(
        LayoutKind::UefiNtfs,
        table,
        disk.sector_size(),
        disk.total_bytes(),
    )?;
    let end = offset.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "uefi-ntfs ESP window at offset {offset} plus {len} bytes overflows u64: refusing"
        ))
    })?;
    Ok((offset, end))
}

/// UEFI:NTFS arm: the shim `image` onto the whole disk at the ESP
/// offset, for `Ntfs`/`Exfat` plans only.
///
/// Disk-only, unlike every other arm: no image tree is opened and no
/// `Fat32` volume is touched — the copy step already placed the ISO
/// files on the data partition, and the shim lands in partition 1.
/// The gates and the window come from [`uefi_ntfs_window`], and the
/// write goes through
/// [`uefi_ntfs::install`](crate::boot::uefi_ntfs::install) —
/// pre-write bound check, whole image, nothing else. No flush here:
/// the caller owns it, like every other arm's disk side.
///
/// Production passes the embedded bytes (loaded through
/// [`crate::boot::load`]); tests pass explicit bytes, which is what
/// makes the oversized-image refusal testable without faking the
/// asset tree.
pub(super) fn install_uefi_ntfs(
    disk: &mut dyn Volume,
    table: Option<TableKind>,
    filesystem: &Filesystem,
    image: &[u8],
) -> Result<Installed> {
    let (offset, end) = uefi_ntfs_window(disk, table, filesystem)?;
    let installed = uefi_ntfs::install(disk, image, offset, end)?;
    Ok(Installed::UefiNtfs {
        bytes: installed.bytes(),
        offset: installed.offset(),
        messages: vec!["Writing UEFI:NTFS data...".to_string()],
    })
}

/// The UEFI:NTFS completion line: the image byte count and the ESP
/// offset, shared by [`run_uefi_ntfs`] and the tree-run summary match
/// so both agree.
pub(super) fn uefi_ntfs_summary(bytes: u64, offset: u64) -> String {
    format!("wrote UEFI:NTFS image ({bytes} bytes at offset {offset})")
}

/// Run the UEFI:NTFS arm: gate the plan and resolve the ESP window
/// first (a refused plan does no 1 MiB image read), then load the
/// embedded shim, install it through [`install_uefi_ntfs`], flush the
/// disk, and report the reference line plus the completion line.
pub(super) fn run_uefi_ntfs(ctx: &mut RunContext<'_>, filesystem: &Filesystem) -> Result<()> {
    let cancelled = ctx.cancelled;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let table = ctx.table;
    let mut disk = DiskView::new(ctx.device()?);
    uefi_ntfs_window(&disk, table, filesystem)?;
    let image = crate::boot::load(Resource::UefiNtfsImage)?;
    let installed = install_uefi_ntfs(&mut disk, table, filesystem, image.bytes())?;
    disk.flush()?;
    for message in installed.messages() {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: message.clone(),
        });
    }
    let Installed::UefiNtfs { bytes, offset, .. } = installed else {
        return Err(CoreError::invalid(
            "uefi-ntfs install reported no UEFI:NTFS facts: refusing".to_string(),
        ));
    };
    ctx.reporter.event(Event::Message {
        level: "info",
        text: uefi_ntfs_summary(bytes, offset),
    });
    Ok(())
}
