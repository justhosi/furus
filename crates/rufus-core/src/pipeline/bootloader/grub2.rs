use crate::boot::grub2;
use crate::copy::Source as TreeSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::Fat32;
use crate::part::TableKind;

use super::Installed;
use super::gap_end;

/// GRUB2 BIOS branch: UEFI file placement first, then the core image,
/// then the MBR sector (boot code last, inside
/// [`grub2::install`](crate::boot::grub2::install) itself).
///
/// Unlike GRUB4DOS, GRUB2 ships no embedded fallback: `boot_img` and
/// `core_img` come only from the image's payload directories (see
/// [`grub2::payloads`](crate::boot::grub2::payloads)).
///
/// The core must end inside the post-MBR gap: `CORE_OFFSET + core
/// length` is checked against the Mkpart-planned first-partition
/// offset (see [`gap_end`]) before any write, so an oversized core
/// refuses instead of overwriting the partition's boot sector. The
/// payload lookup cannot cap this itself — the gap width depends on
/// the target geometry, unknowable there — so the clear refusal with
/// both numbers lives here.
pub(super) fn install_grub2(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    disk: &mut dyn Volume,
    payloads: &grub2::Payloads,
    table: Option<TableKind>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Installed> {
    let mut messages = vec![format!(
        "found grub2 bios payloads at '{}'",
        payloads.path()
    )];
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let core_len = u64::try_from(payloads.core_img().len())
        .map_err(|_| CoreError::invalid("a grub2 core longer than u64: refusing"))?;
    let gap = gap_end("grub2", table, disk.sector_size(), disk.total_bytes())?;
    let core_end = grub2::CORE_OFFSET
        .checked_add(core_len)
        .ok_or_else(|| CoreError::invalid("a grub2 core end overflows u64: refusing"))?;
    if core_end > gap {
        return Err(CoreError::invalid(format!(
            "grub2 core.img of {core_len} bytes at offset {} runs past the post-MBR gap ending at {gap}: refusing",
            grub2::CORE_OFFSET,
        )));
    }
    let mut uefi_placed = None;
    if let Some(efi) = grub2::efi_payload(source)? {
        // A genuine listing I/O error propagates (the volume may be
        // unreadable); any other listing refusal means the directory
        // is absent, so the file cannot be there either.
        let present = match fat.list_dir(grub2::EFI_BOOT_DIR) {
            Ok(entries) => entries
                .iter()
                .any(|entry| entry.short_name.eq_ignore_ascii_case("BOOTX64.EFI")),
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => false,
        };
        if present {
            messages.push(format!(
                "uefi image already present at '{}/{}', keeping it",
                grub2::EFI_BOOT_DIR,
                grub2::EFI_BOOT_NAME,
            ));
        } else {
            let placed = grub2::install_uefi(fat, efi.bytes())?;
            uefi_placed = Some(placed.path());
            messages.push(format!(
                "placed uefi image at '{}' ({} bytes)",
                placed.path(),
                placed.bytes(),
            ));
        }
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let report = grub2::install(disk, payloads.boot_img(), payloads.core_img())?;
    let core_bytes = u64::try_from(report.core_bytes())
        .map_err(|_| CoreError::invalid("a grub2 core longer than u64: refusing"))?;
    Ok(Installed::Grub2 {
        dir: payloads.path(),
        core_bytes,
        uefi_placed,
        messages,
    })
}
