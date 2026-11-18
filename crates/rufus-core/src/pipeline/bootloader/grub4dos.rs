use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::grub4dos;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::Fat32;
use crate::part::TableKind;

use super::Installed;
use super::gap_end;

/// GRUB4DOS branch: the MBR+SBR over a root loader the volume already
/// carries.
///
/// Rufus does not bundle `grldr`: upstream downloads
/// `grub4dos-0.4.6a/grldr`, and resource 451 is GRUB2's `core.img`. So
/// the loader must reach the volume first, through the image tree (the
/// copy step) or the caller. The arm refuses, before any write, while
/// no root `/grldr` is present. Otherwise it keeps that file (the
/// loader refuses to overwrite) and writes the MBR+SBR after it (the
/// `install_boot` torn rule).
pub(super) fn install_grub4dos(
    fat: &mut Fat32,
    disk: &mut dyn Volume,
    table: Option<TableKind>,
    cancelled: &dyn Fn() -> bool,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let present = fat
        .list_dir("/")?
        .iter()
        .any(|entry| entry.short_name == "GRLDR");
    if !present {
        return Err(CoreError::invalid(
            "grub4dos needs a real grldr at the volume root: none is on the volume, and Rufus downloads it (grub4dos-0.4.6a/grldr) rather than bundling it: refusing",
        ));
    }
    let mbr = load(Resource::Grub4DosMbr)?;
    // The SBR must end inside the post-MBR gap like the GRUB2 core:
    // same Mkpart-planned bound, checked before any write even though
    // today's 7680 bytes clear a 1 MiB gap by two orders of magnitude.
    let sbr_len = u64::try_from(mbr.bytes().len().saturating_sub(512))
        .map_err(|_| CoreError::invalid("a grub4dos sbr longer than u64: refusing"))?;
    let gap = gap_end("grub4dos", table, disk.sector_size(), disk.total_bytes())?;
    let sbr_end = grub4dos::SBR_OFFSET
        .checked_add(sbr_len)
        .ok_or_else(|| CoreError::invalid("a grub4dos sbr end overflows u64: refusing"))?;
    if sbr_end > gap {
        return Err(CoreError::invalid(format!(
            "grub4dos sbr of {sbr_len} bytes at offset {} runs past the post-MBR gap ending at {gap}: refusing",
            grub4dos::SBR_OFFSET,
        )));
    }
    let mut messages: Vec<String> = vec!["root /grldr already present, keeping it".to_string()];
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let boot = grub4dos::install_boot(disk, mbr.bytes())?;
    let sbr_bytes = u64::try_from(boot.sbr_bytes())
        .map_err(|_| CoreError::invalid("a grub4dos sbr longer than u64: refusing"))?;
    messages.push(format!(
        "installed grub4dos boot record ({sbr_bytes} sbr bytes)",
    ));
    Ok(Installed::Grub4dos {
        sbr_bytes,
        messages,
    })
}
