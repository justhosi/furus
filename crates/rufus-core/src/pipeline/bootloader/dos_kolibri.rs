use std::path::Path;

use crate::boot::dos_locale;
use crate::boot::freedos;
use crate::boot::kolibri;
use crate::boot::msdos;
use crate::copy::Source as TreeSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;

use super::Installed;

/// FreeDOS branch: the embedded payloads, the locale files and the
/// boot record, through [`freedos::install`](crate::boot::freedos::install).
///
/// Does not read the image tree: the write step already copied it, and
/// the payloads are embedded (resources 300-326) plus the rendered
/// locale pair — so `source` is unused here, unlike the KolibriOS arm
/// whose loader comes from the image.
///
/// The locale is always [`Locale::us`](dos_locale::Locale::us()): the
/// reference takes the Windows UI language (`GetKeyboardLayoutNameA`
/// plus `GetOEMCP`), which this port has no equivalent for yet, so
/// US/437 is the honest default; the [`Locale`](dos_locale::Locale)
/// input exists precisely so a later UI can thread it through.
pub(super) fn install_freedos(fat: &mut Fat32, cancelled: &dyn Fn() -> bool) -> Result<Installed> {
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let locale = dos_locale::Locale::us();
    let planned = dos_locale::plan(dos_locale::DosFlavor::FreeDos, &locale);
    let installed = freedos::install(fat, &locale)?;
    let mut messages: Vec<String> = Vec::new();
    messages.extend(planned.messages().iter().cloned());
    for name in installed.kept() {
        messages.push(format!("  Kept existing '{name}'"));
    }
    let files_written = installed.written().len();
    let files_kept = installed.kept().len();
    let bytes = installed.bytes_written();
    Ok(Installed::Freedos {
        files_written,
        files_kept,
        bytes,
        messages,
    })
}

/// KolibriOS branch: the `MTLD_F32` loader from the image tree at the
/// volume root, then the KolibriOS boot record.
///
/// Reads the image tree — the loader comes from the image — unlike the
/// FreeDOS arm whose payloads are embedded. A tree without the exact
/// `HD_Load/USB_Boot/MTLD_F32` path refuses naming it, with the device
/// byte-identical: the copy step may already have placed the file, but
/// without the image copy there is nothing honest to write. The record
/// runs last, so a loader refusal leaves sector 0 untouched.
pub(super) fn install_kolibri(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    cancelled: &dyn Fn() -> bool,
) -> Result<Installed> {
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let Some(located) = kolibri::locate(source)? else {
        return Err(CoreError::invalid(
            "no kolibri loader found in the image: looked for HD_Load/USB_Boot/MTLD_F32; refusing",
        ));
    };
    let mut messages = vec![format!("found kolibri loader at '{}'", located.path())];
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let placed = kolibri::install_loader(fat, located.bytes())?;
    if placed.kept() {
        messages.push("kolibri loader already present at '/MTLD_F32', keeping it".to_string());
    } else {
        messages.push(format!(
            "placed kolibri loader at '/MTLD_F32' ({} bytes)",
            placed.bytes(),
        ));
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    kolibri::install_boot_record(fat)?;
    messages.push("installed kolibri boot record".to_string());
    Ok(Installed::Kolibri {
        bytes: placed.bytes(),
        kept: placed.kept(),
        messages,
    })
}

/// MS-DOS branch: the user-supplied `IO.SYS`, `MSDOS.SYS` and
/// `COMMAND.COM` from `dir` at the volume root, with the WinME
/// real-mode jump patch applied where the bytes match.
///
/// Reads no image tree: the files come from the user because MS-DOS
/// cannot be bundled (see [`msdos`]), so `source` is unused here —
/// like the FreeDOS arm, unlike the KolibriOS arm whose loader comes
/// from the image. A missing file, an unreadable directory, a
/// non-regular payload slot or an oversize file all surface with
/// [`msdos`](crate::boot::msdos)'s own messages, before any write.
/// The volume's real cluster size gates the install through
/// [`msdos::check_cluster_size`](crate::boot::msdos::check_cluster_size):
/// the `u64` geometry reading converts to `u32` with a refusal when
/// it cannot fit, never a truncating cast. Sector 0 is untouched:
/// MS-DOS uses the standard FAT record, so the formatter's stands
/// (`src/format.c` writes it; this arm writes files only).
pub(super) fn install_msdos(
    fat: &mut Fat32,
    dir: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Installed> {
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let files = msdos::MsDosFiles::load(dir)?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let cluster = fat.geometry().cluster_bytes();
    let cluster = u32::try_from(cluster).map_err(|_| {
        CoreError::invalid(format!(
            "msdos cluster size of {cluster} bytes does not fit u32: refusing"
        ))
    })?;
    msdos::check_cluster_size(cluster)?;
    let installed = msdos::install(fat, &files)?;
    // Reference order: the `Patching ...` line prints before its
    // file's write, with the skip note when the patch missed; the
    // kept-existing lines close, like the FreeDOS arm's.
    let mut messages = vec!["Patching IO.SYS...".to_string()];
    if let Some(note) = installed.io_sys_patch().note() {
        messages.push(note.to_string());
    }
    messages.push("Patching COMMAND.COM...".to_string());
    if let Some(note) = installed.command_com_patch().note() {
        messages.push(note.to_string());
    }
    for name in installed.kept() {
        messages.push(format!("  Kept existing '{name}'"));
    }
    let kept = installed.kept().len();
    let written = 3usize.saturating_sub(kept);
    let bytes = installed
        .io_sys()
        .saturating_add(installed.msdos_sys())
        .saturating_add(installed.command_com());
    Ok(Installed::MsDos {
        written,
        kept,
        bytes,
        patch_states: (installed.io_sys_patch(), installed.command_com_patch()),
        messages,
    })
}

/// The FreeDOS completion line: files written and kept counts,
/// bytes written and the record, shared by the tree-run summary match
/// so both agree.
pub(super) fn freedos_summary(files_written: usize, files_kept: usize, bytes: u64) -> String {
    format!(
        "installed freedos ({files_written} files written, {files_kept} kept, {bytes} bytes, boot record written)"
    )
}

/// The KolibriOS completion line: the loader byte count, its volume
/// path and whether it was kept or written, plus the boot record,
/// shared by the tree-run summary match so both agree.
pub(super) fn kolibri_summary(bytes: u64, kept: bool) -> String {
    let loader = if kept {
        "existing /MTLD_F32 kept"
    } else {
        "loader written"
    };
    format!("installed kolibri boot record ({bytes} loader bytes at '/MTLD_F32', {loader})")
}

/// The MS-DOS completion line: files written and kept counts plus
/// the bytes at the root, shared by the tree-run summary match so
/// both agree.
pub(super) fn msdos_summary(written: usize, kept: usize, bytes: u64) -> String {
    format!("installed msdos ({written} files written, {kept} kept, {bytes} bytes)")
}

/// Run the MS-DOS arm: the user-supplied files from `msdos_dir`
/// onto the freshly formatted FAT32 data partition, without ever
/// opening the image tree (an `msdos` plan carries no write step, so
/// the image is only the still-required CLI detection record — the
/// installer reads the directory, never the image).
///
/// The shared path above already ran the FAT32 gate; the
/// `msdos_dir` requirement mirrors the arm's own gate, so a refused
/// plan fails the same way through either entry: a non-FAT32
/// filesystem names itself first, then a missing directory names
/// `--msdos-dir`, both before any write. One flush of the partition
/// follows the install, then the reference lines plus the completion
/// line.
pub(super) fn run_msdos(ctx: &mut RunContext<'_>, msdos_dir: Option<&Path>) -> Result<()> {
    let cancelled = ctx.cancelled;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let Some(dir) = msdos_dir else {
        return Err(CoreError::invalid(
            "msdos install needs the user-supplied directory (--msdos-dir) holding IO.SYS, MSDOS.SYS and COMMAND.COM: refusing".to_string(),
        ));
    };
    let mut fat = Fat32::open(ctx.opener.partition()?)?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let installed = install_msdos(&mut fat, dir, cancelled)?;
    fat.flush()?;
    for message in installed.messages() {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: message.clone(),
        });
    }
    let Installed::MsDos {
        written,
        kept,
        bytes,
        ..
    } = installed
    else {
        return Err(CoreError::invalid(
            "msdos install reported no MS-DOS facts: refusing".to_string(),
        ));
    };
    ctx.reporter.event(Event::Message {
        level: "info",
        text: msdos_summary(written, kept, bytes),
    });
    Ok(())
}
