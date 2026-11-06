//! The bootloader step: Syslinux, GRUB2, GRUB4DOS, FreeDOS,
//! KolibriOS and MS-DOS installation from the image tree, UEFI GRUB placement,
//! and the UEFI:NTFS shim.
//!
//! What is wired today: explicit `Syslinux` mode installs one Syslinux
//! family; explicit `Grub2` installs the BIOS record and places a UEFI
//! image when the tree carries one; explicit `Grub4dos` writes the
//! embedded MBR/SBR and the root loader (all three read the image tree
//! and need a FAT32 volume); explicit `Freedos` installs the embedded
//! FreeDOS payloads plus the locale files and the FreeDOS record (it
//! does not read the image tree — the write step already copied it —
//! and needs a FAT32 volume); explicit `Kolibri` locates the
//! `HD_Load/USB_Boot/MTLD_F32` loader in the image tree, places it at
//! the volume root and writes the KolibriOS record (it does read the
//! image tree — the loader comes from the image — and needs a FAT32
//! volume); explicit `MsDos` installs the caller-supplied `IO.SYS`
//! (contiguous, first), `MSDOS.SYS` and `COMMAND.COM` from the plan's
//! `msdos_dir` with the WinME jump patch applied where the bytes
//! match (it reads no image tree — an `msdos` plan carries no write
//! step, and nothing is bundled for licensing reasons — and needs a
//! FAT32 volume); `Auto` takes the first match of syslinux,
//! grub2, grub4dos,
//! logging each probe. Explicit `UefiNtfs` is disk-only instead: it
//! writes the embedded 1 MiB shim image at the ESP offset of the
//! two-partition layout for NTFS or exFAT plans — no image tree, no
//! FAT32 volume (the copy step already placed the ISO files on the
//! data partition).
//!
//! The obsolete-module replacement ([`Obsolete`](crate::boot::syslinux::Obsolete))
//! is deliberately not applied here: no newer module bytes are
//! bundled, so there is nothing honest to substitute with — declared
//! gap, same as the copy wiring leaves it.
//!
//! Write order keeps slice 3's "boot code last" invariant per arm:
//! syslinux lays companions, config, then the boot record; grub2
//! places the UEFI file, then the core image, then the MBR sector;
//! grub4dos checks the root loader first (writing nothing), then
//! writes the SBR, then the MBR sector.
//! A refused step leaves no boot code behind. The BIOS payloads never
//! reach past the post-MBR gap: each arm bounds its core/SBR end
//! through the same helper Mkpart stamps with, before any write.
//!
//! Payload provenance is honest per arm: GRUB2 ships no embedded
//! fallback — `boot.img`, `core.img` and the UEFI image come only
//! from the image tree — while GRUB4DOS carries only its MBR/SBR record
//! (resource 450). Its root `grldr` is never embedded: Rufus downloads
//! the real GRUB4DOS loader, so the arm refuses unless the volume
//! already carries one (from the image tree or the caller). Resource
//! 451 is GRUB2's `core.img`, not a loader. FreeDOS carries its 27
//! payloads as embedded resources 300-326 (the locale
//! `CONFIG.SYS`/`AUTOEXEC.BAT`
//! pair is rendered, not embedded); KolibriOS carries only its boot
//! record as a transcription — the `MTLD_F32` loader comes from the
//! image tree; MS-DOS carries nothing at all — `IO.SYS`,
//! `MSDOS.SYS` and `COMMAND.COM` all come from the user's
//! `msdos_dir`, since MS-DOS cannot be bundled.

use std::path::Path;

use rufus_proto::BootloaderMode;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;

use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::dos_locale;
use crate::boot::freedos;
use crate::boot::grub2;
use crate::boot::grub4dos;
use crate::boot::kolibri;
use crate::boot::msdos;
use crate::boot::msdos::PatchState;
use crate::boot::syslinux;
use crate::boot::syslinux::Family;
use crate::boot::uefi_ntfs;
use crate::copy::IsoSource;
use crate::copy::Source as TreeSource;
use crate::copy::UdfSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::FileVolume;
use crate::fs::Volume;
use crate::fs::fat32::Fat32;
use crate::iso::IsoReader;
use crate::part::TableKind;
use crate::part::plan::LayoutKind;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::target::Target;
use crate::report::syslinux_banner;
use crate::udf::UdfReader;

/// Whole-disk [`Volume`] over a pipeline [`Target`]: bounds-checked
/// reads and writes delegating to `read_at`/`write_all_at`, `flush`
/// forwarding.
///
/// Exists only because the GRUB2/GRUB4DOS record writers predate the
/// pipeline: they speak [`Volume`] (sector images, exact windows)
/// while the pipeline speaks [`Target`] (whole-disk stores), so this
/// private adapter bridges the two for the BIOS arms. Test doubles
/// (`VecTarget`) flow through the same adapter, which is what makes
/// the GRUB arms unit-testable without a device.
struct DiskView<'a> {
    target: &'a mut dyn Target,
}

impl<'a> DiskView<'a> {
    fn new(target: &'a mut dyn Target) -> Self {
        Self { target }
    }
}

/// Checked byte window of `len` bytes at `offset` in a store of
/// `total` bytes, naming offset, length and total on refusal — the
/// same bounds-before-I/O rule every [`Volume`] keeps.
fn checked_window(total: u64, offset: u64, len: usize, direction: &str) -> Result<(usize, usize)> {
    let len_u64 = u64::try_from(len)
        .map_err(|_| CoreError::invalid("grub disk window longer than u64: refusing"))?;
    let end = offset.checked_add(len_u64).ok_or_else(|| {
        CoreError::invalid(format!(
            "grub disk {direction} of {len} bytes at offset {offset} overflows u64: refusing"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "grub disk {direction} of {len} bytes at offset {offset} runs past the {total} byte disk: refusing"
        )));
    }
    let start = usize::try_from(offset)
        .map_err(|_| CoreError::invalid("grub disk offset longer than usize: refusing"))?;
    let end = usize::try_from(end)
        .map_err(|_| CoreError::invalid("grub disk window end longer than usize: refusing"))?;
    Ok((start, end))
}

impl Volume for DiskView<'_> {
    fn total_bytes(&self) -> u64 {
        self.target.size()
    }

    fn sector_size(&self) -> u32 {
        self.target.sector_size()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let _ = checked_window(self.target.size(), offset, buf.len(), "read")?;
        self.target.read_at(offset, buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let _ = checked_window(self.target.size(), offset, buf.len(), "write")?;
        self.target.write_all_at(offset, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.target.flush()
    }
}

/// Refuse every [`BootloaderMode`] with no wired installer, naming
/// the mode: one table shared by [`install_tree`] and [`run`], so an
/// unwired mode never reaches the image or the device through either
/// entry point. `UefiNtfs` passes here — its disk-only arm lives in
/// [`run`], not [`install_tree`], which refuses it through its own
/// explicit arm. (The mode names S20's UEFI:NTFS partition, not the
/// UEFI GRUB file the GRUB arms place.) Every mode is wired today, so
/// this always passes; it stays as the shared gate so a future variant
/// fails closed in both entry points.
fn check_mode(mode: &BootloaderMode) -> Result<()> {
    match mode {
        BootloaderMode::None
        | BootloaderMode::Syslinux
        | BootloaderMode::Auto
        | BootloaderMode::Grub2
        | BootloaderMode::Grub4dos
        | BootloaderMode::UefiNtfs
        | BootloaderMode::Freedos
        | BootloaderMode::Kolibri
        | BootloaderMode::MsDos => Ok(()),
    }
}

/// Resolve the post-MBR gap end for `{owner}` through the same
/// helper Mkpart stamps with
/// ([`single_data_window`](crate::part::plan::single_data_window)):
/// the first data partition's start offset, so the numbers cannot
/// drift from the table on the disk. Refuses without a recorded
/// table — no table means no honest bound — and propagates the
/// planner's own refusals.
fn gap_end(owner: &str, table: Option<TableKind>, sector_size: u32, total: u64) -> Result<u64> {
    let table = table.ok_or_else(|| {
        CoreError::invalid(format!(
            "{owner} install needs a recorded partition table to bound the post-MBR gap: refusing"
        ))
    })?;
    let (offset, _) = crate::part::plan::single_data_window(table, sector_size, total)?;
    Ok(offset)
}

/// What [`install_tree`] installed: one variant per wired arm, each
/// carrying its own facts plus the log lines the run reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Installed {
    /// `None` mode: nothing written.
    Skipped,
    /// Syslinux family install: family and located directory, stage
    /// size, companions written and kept, config path, and log lines
    /// in reference order (located directory, selection, companion
    /// cautions, then kept-existing lines).
    Syslinux {
        family: Family,
        dir: String,
        stage_bytes: u64,
        companions: Vec<String>,
        kept_companions: Vec<String>,
        config_path: String,
        messages: Vec<String>,
    },
    /// GRUB2 BIOS install: payload directory, core byte count, the
    /// placed UEFI destination when one landed, and log lines (payload
    /// discovery, then UEFI placement or skip).
    Grub2 {
        dir: String,
        core_bytes: u64,
        uefi_placed: Option<String>,
        messages: Vec<String>,
    },
    /// GRUB4DOS install: SBR byte count and log lines. The root
    /// `grldr` is always one already on the volume (the arm refuses
    /// without it), so it is kept, never written.
    Grub4dos {
        sbr_bytes: u64,
        messages: Vec<String>,
    },
    /// FreeDOS install: files written and kept counts, bytes written,
    /// and log lines (the locale plan lines, then kept-existing
    /// lines). The boot record always lands on success, so the run
    /// summary names it without a separate flag.
    Freedos {
        files_written: usize,
        files_kept: usize,
        bytes: u64,
        messages: Vec<String>,
    },
    /// KolibriOS install: loader byte count, whether the loader was
    /// kept (`true`) or written (`false`), and log lines (loader
    /// discovery, then loader placement or skip, then the boot
    /// record).
    Kolibri {
        bytes: u64,
        kept: bool,
        messages: Vec<String>,
    },
    /// MS-DOS install: files written and kept counts, total bytes at
    /// the root, both patch states (`IO.SYS`, then `COMMAND.COM`),
    /// and log lines (the reference `Patching IO.SYS...` /
    /// `Patching COMMAND.COM...` lines with their skip notes, then
    /// kept-existing lines). Sector 0 is untouched: the formatter's
    /// standard record stands.
    MsDos {
        written: usize,
        kept: usize,
        bytes: u64,
        patch_states: (PatchState, PatchState),
        messages: Vec<String>,
    },
    /// UEFI:NTFS install: shim image byte count, the ESP offset it
    /// landed at, and log lines (the reference `Writing UEFI:NTFS
    /// data...` line). Only the disk-only [`run`] path builds this —
    /// [`install_tree`] refuses the mode through its own arm.
    UefiNtfs {
        bytes: u64,
        offset: u64,
        messages: Vec<String>,
    },
}

impl Installed {
    /// Log lines the run reports, in the order the arm produced them.
    #[must_use]
    pub fn messages(&self) -> &[String] {
        match self {
            Installed::Skipped => &[],
            Installed::Syslinux { messages, .. }
            | Installed::Grub2 { messages, .. }
            | Installed::Grub4dos { messages, .. }
            | Installed::Freedos { messages, .. }
            | Installed::Kolibri { messages, .. }
            | Installed::MsDos { messages, .. }
            | Installed::UefiNtfs { messages, .. } => messages,
        }
    }
}

/// Prepend probe lines ahead of a branch's own messages. A skip
/// carries no messages by construction, so there is nothing to
/// prefix (and `Auto` never returns a skip — every branch writes).
fn prepend_log(installed: &mut Installed, probes: Vec<String>) {
    if probes.is_empty() {
        return;
    }
    match installed {
        Installed::Skipped => {}
        Installed::Syslinux { messages, .. }
        | Installed::Grub2 { messages, .. }
        | Installed::Grub4dos { messages, .. }
        | Installed::Freedos { messages, .. }
        | Installed::Kolibri { messages, .. }
        | Installed::MsDos { messages, .. }
        | Installed::UefiNtfs { messages, .. } => {
            messages.splice(..0, probes);
        }
    }
}

/// Install the bootloader `mode` from the image `source` onto `fat`
/// (filesystem work) and `disk` (whole-disk record work, used by the
/// BIOS arms only).
///
/// Pure core over explicit inputs (no `RunContext`), so unit tests
/// drive it against an in-memory FAT32, a byte-backed disk view and a
/// fixture source. `load` resolves the embedded payloads (production
/// passes [`crate::boot::load`]; tests pass a `load_from` closure over
/// the asset tree, since `load` needs the runtime asset directory),
/// and `cancelled` is polled before the first write and before each
/// boot record.
///
/// `None` writes nothing and returns [`Installed::Skipped`] — the
/// correct mode for a `Dd` plan, whose image boot code already landed
/// verbatim. `Syslinux` runs the Syslinux branch; `Grub2` the GRUB2
/// BIOS branch plus UEFI placement; `Grub4dos` the embedded MBR/SBR
/// plus the root loader; `Freedos` the FreeDOS payloads plus the
/// locale files plus the boot record; `Kolibri` the image-tree loader
/// plus the boot record; `MsDos` the user-supplied files from
/// `msdos_dir` (no boot record — the formatter's standard record
/// stands — and no image tree: an `msdos` plan carries no write step,
/// so [`run`] short-circuits past the tree setup); `Auto` takes the
/// first match of syslinux,
/// grub2, grub4dos. `UefiNtfs` refuses here as invalid rather than not
/// implemented: the installer exists but is disk-only (no tree, no
/// FAT32 volume — see [`install_uefi_ntfs`]), so [`run`] wires it
/// directly and a tree install can never serve it. Any future variant
/// refuses through the shared [`check_mode`] table before reaching
/// here; the trailing `other` arm stays as fail-closed invalid,
/// unreachable today.
///
/// `table` is the recorded partition-table kind the BIOS arms bound
/// their post-MBR gap through (see [`gap_end`]); the Syslinux-only
/// paths ignore it.
///
/// `msdos_dir` is the user-supplied MS-DOS directory the `MsDos` arm
/// reads through [`install_msdos`]; every other arm ignores it. `None`
/// refuses the `MsDos` arm naming `--msdos-dir`, since the three
/// files cannot be bundled.
///
/// Eight parameters because the core needs the whole install context
/// at once; bundling them would only hide the same fields.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install_tree(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    disk: &mut dyn Volume,
    mode: &BootloaderMode,
    table: Option<TableKind>,
    msdos_dir: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    match mode {
        BootloaderMode::None => return Ok(Installed::Skipped),
        _ => check_mode(mode)?,
    }
    if *mode == BootloaderMode::Auto {
        // First match wins; one log line per probe, then the winning
        // branch's own messages (or the single refusal below).
        let mut probes: Vec<String> = Vec::new();
        probes.push("auto: probing syslinux".to_string());
        if let Some(located) = syslinux::locate(source)? {
            let mut installed = install_syslinux(source, fat, &located, cancelled, load)?;
            prepend_log(&mut installed, probes);
            return Ok(installed);
        }
        probes.push("auto: probing grub2".to_string());
        if let Some(payloads) = grub2::payloads(source)? {
            let mut installed = install_grub2(source, fat, disk, &payloads, table, cancelled)?;
            prepend_log(&mut installed, probes);
            return Ok(installed);
        }
        probes.push("auto: probing grub4dos".to_string());
        if syslinux::read(source, &[], "grldr")?.is_some() {
            let mut installed = install_grub4dos(fat, disk, table, cancelled, load)?;
            prepend_log(&mut installed, probes);
            return Ok(installed);
        }
        return Err(CoreError::invalid(
            "auto: no bootloader payloads found in the image: probed syslinux payload directories (isolinux.bin markers), grub2 directories /boot/grub/i386-pc and /boot/grub2/i386-pc (boot.img and core.img), and root /grldr (grub4dos); refusing",
        ));
    }
    match mode {
        BootloaderMode::Syslinux => {
            let Some(located) = syslinux::locate(source)? else {
                return Err(CoreError::invalid(
                    "no syslinux payloads found in the image: refusing a syslinux install",
                ));
            };
            install_syslinux(source, fat, &located, cancelled, load)
        }
        BootloaderMode::Grub2 => {
            let Some(payloads) = grub2::payloads(source)? else {
                return Err(CoreError::invalid(
                    "no grub2 payloads found in the image: looked in /boot/grub/i386-pc and /boot/grub2/i386-pc for boot.img and core.img; refusing",
                ));
            };
            install_grub2(source, fat, disk, &payloads, table, cancelled)
        }
        BootloaderMode::Grub4dos => install_grub4dos(fat, disk, table, cancelled, load),
        BootloaderMode::Freedos => install_freedos(fat, cancelled),
        BootloaderMode::Kolibri => install_kolibri(source, fat, cancelled),
        // User-supplied files by design (see `install_msdos`): the
        // directory rides in from the plan's `msdos_dir`, and no
        // directory means no honest install.
        BootloaderMode::MsDos => {
            let Some(dir) = msdos_dir else {
                return Err(CoreError::invalid(
                    "msdos install needs the user-supplied directory (--msdos-dir) holding IO.SYS, MSDOS.SYS and COMMAND.COM: refusing".to_string(),
                ));
            };
            install_msdos(fat, dir, cancelled)
        }
        // Disk-only by design (see `install_uefi_ntfs`): the shim
        // lands on the whole disk at the ESP offset with no tree and
        // no FAT32 volume, so the tree core refuses it and `run`
        // wires it directly.
        BootloaderMode::UefiNtfs => Err(CoreError::invalid(
            "uefi-ntfs installs the embedded image onto the whole disk at the ESP offset, not through the filesystem tree: refusing a tree install".to_string(),
        )),
        // `None` returned above; any future unwired variant would
        // refuse in `check_mode` above, so this arm is unreachable
        // today. This names the mode rather than assuming the match
        // is exhaustive forever.
        other => Err(CoreError::invalid(format!(
            "bootloader mode '{other:?}' has no wired installer: refusing"
        ))),
    }
}

/// Syslinux branch, shared by explicit `Syslinux` mode and `Auto`:
/// companions, generated config, then the boot record last.
fn install_syslinux(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    located: &syslinux::Located,
    cancelled: &dyn Fn() -> bool,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    // Banner scan over the well-known loader names in the located
    // directory, first hit with a parseable banner wins. Two explicit
    // reads is cheap (absent names return `None` without I/O past the
    // listing) and honest: nothing outside this directory is
    // consulted.
    let mut detected = None;
    for name in ["isolinux.bin", "syslinux.bin"] {
        let Some(bytes) = syslinux::read(source, located.dir(), name)? else {
            continue;
        };
        if let Some(version) = syslinux_banner(&bytes) {
            detected = Some(syslinux::Detected {
                version,
                source: format!("{}/{}", located.path(), name),
            });
            break;
        }
    }
    let inventory = syslinux::inventory(source, located.dir())?;
    let has_ldlinux_c32 = inventory.present().contains(&"ldlinux.c32");
    let selection = syslinux::select(detected, has_ldlinux_c32);
    let missing = inventory.required_missing(selection.family());
    if !missing.is_empty() {
        return Err(CoreError::invalid(format!(
            "syslinux {} install needs {} but the image lacks it: refusing before any write",
            selection.family().version(),
            missing.join(", "),
        )));
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let target = located.path();
    let placed = syslinux::install_companions(fat, source, located.dir(), &target)?;
    // The wrapper chains back to the image's own config: prefer the
    // config file the directory actually holds, defaulting to the
    // conventional name when neither is there.
    let cfg_name = if syslinux::read(source, located.dir(), "isolinux.cfg")?.is_some() {
        "isolinux.cfg"
    } else if syslinux::read(source, located.dir(), "syslinux.cfg")?.is_some() {
        "syslinux.cfg"
    } else {
        "isolinux.cfg"
    };
    let config_path = if target == "/" {
        format!("/{cfg_name}")
    } else {
        format!("{target}/{cfg_name}")
    };
    let text = syslinux::config_text(config_path.as_bytes())?;
    syslinux::write_config(fat, &text)?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let loader = syslinux::install_payloads_from(fat, selection.family(), load)?;
    // Reference order: the located line prints before the detection
    // (or forcing) line.
    let mut messages: Vec<String> = Vec::new();
    messages.extend(located.messages().iter().cloned());
    messages.extend(selection.messages().iter().cloned());
    messages.extend(placed.cautions.iter().cloned());
    for name in &placed.kept {
        messages.push(format!("  Kept existing '{name}'"));
    }
    Ok(Installed::Syslinux {
        family: selection.family(),
        dir: target,
        stage_bytes: loader.stage_bytes(),
        companions: placed.written,
        kept_companions: placed.kept,
        config_path: "/syslinux.cfg".to_string(),
        messages,
    })
}

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
fn install_grub2(
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
fn install_grub4dos(
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
fn install_freedos(fat: &mut Fat32, cancelled: &dyn Fn() -> bool) -> Result<Installed> {
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
fn install_kolibri(
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
fn install_msdos(fat: &mut Fat32, dir: &Path, cancelled: &dyn Fn() -> bool) -> Result<Installed> {
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

/// UEFI:NTFS gates plus the ESP window: the filesystem gate mirrors
/// the reference (`rufus.c:2032-2037`: NTFS or exFAT only, naming the
/// plan filesystem otherwise); the table gate mirrors [`gap_end`] (no
/// recorded table, no window); the window comes from
/// [`esp_window`](crate::part::plan::esp_window) over the `UefiNtfs`
/// layout the mode implies. Returns `(offset, end)` with `end`
/// overflow-checked. Shared by [`install_uefi_ntfs`] and
/// [`run_uefi_ntfs`] so a refused plan fails before any image read —
/// production's 1 MiB `load` runs only after these gates pass.
fn uefi_ntfs_window(
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
fn install_uefi_ntfs(
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
fn uefi_ntfs_summary(bytes: u64, offset: u64) -> String {
    format!("wrote UEFI:NTFS image ({bytes} bytes at offset {offset})")
}

/// The FreeDOS completion line: files written and kept counts,
/// bytes written and the record, shared by the tree-run summary match
/// so both agree.
fn freedos_summary(files_written: usize, files_kept: usize, bytes: u64) -> String {
    format!(
        "installed freedos ({files_written} files written, {files_kept} kept, {bytes} bytes, boot record written)"
    )
}

/// The KolibriOS completion line: the loader byte count, its volume
/// path and whether it was kept or written, plus the boot record,
/// shared by the tree-run summary match so both agree.
fn kolibri_summary(bytes: u64, kept: bool) -> String {
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
fn msdos_summary(written: usize, kept: usize, bytes: u64) -> String {
    format!("installed msdos ({written} files written, {kept} kept, {bytes} bytes)")
}

/// Run the UEFI:NTFS arm: gate the plan and resolve the ESP window
/// first (a refused plan does no 1 MiB image read), then load the
/// embedded shim, install it through [`install_uefi_ntfs`], flush the
/// disk, and report the reference line plus the completion line.
fn run_uefi_ntfs(ctx: &mut RunContext<'_>, filesystem: &Filesystem) -> Result<()> {
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
fn run_msdos(ctx: &mut RunContext<'_>, msdos_dir: Option<&Path>) -> Result<()> {
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

/// Filesystem name in plan vocabulary (`fat32`, `exfat`, ...).
fn filesystem_name(filesystem: &Filesystem) -> &'static str {
    match filesystem {
        Filesystem::Fat32 => "fat32",
        Filesystem::Exfat => "exfat",
        Filesystem::Ntfs => "ntfs",
        Filesystem::Ext2 => "ext2",
        Filesystem::Ext3 => "ext3",
        Filesystem::Ext4 => "ext4",
        Filesystem::Udf => "udf",
    }
}

/// Run the bootloader step: one wired arm onto the freshly
/// formatted data partition (and, for the BIOS arms, the whole disk
/// behind it), reading the image tree only where the arm needs it
/// (the disk-only and user-file arms never open it).
///
/// `None` reports one info line and writes nothing. `UefiNtfs` takes
/// the disk-only path ([`run_uefi_ntfs`]) before anything else below:
/// the shared [`check_mode`] table passes for every wired mode today
/// (it stays as the fail-closed gate for future variants), no
/// filesystem gate against FAT32, no image tree, no `Fat32` volume.
/// `MsDos` short-circuits past the image-tree setup below
/// ([`run_msdos`]): after the kind and FAT32 gates, the install goes
/// straight onto the partition under the `msdos_dir` requirement —
/// the image tree never opens, so the plan's image needs no readable
/// tree at all (the CLI still requires the `--image` argument as the
/// detection record). Every mode is wired today, so the run never
/// produces `NotImplemented` itself; a future variant would refuse
/// up front through the shared [`check_mode`]
/// table (never reaching the image or the device), then
/// non-FAT32 filesystems refuse naming the plan filesystem, then the
/// image tree opens exactly like `write::run_copy` does. The partition
/// and the whole-disk target open next; a cancellation check follows
/// before the first write (no partial-cleanup machinery is needed —
/// the directory tree can be reformatted, so a torn step reports and
/// the next run starts clean), then the install, one flush of the
/// partition, and the run message. The disk-side stores flush inside
/// their own install calls.
///
/// `msdos_dir` is the plan's user-supplied MS-DOS directory, read by
/// the `MsDos` arm only (see [`install_tree`]); every other arm
/// ignores it, so callers pass `None` there.
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &BootloaderMode,
    image: &ImageRef,
    filesystem: &Filesystem,
    msdos_dir: Option<&Path>,
) -> Result<()> {
    if *mode == BootloaderMode::None {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: "bootloader: none requested, leaving the image boot code untouched".to_string(),
        });
        return Ok(());
    }
    if *mode == BootloaderMode::UefiNtfs {
        // Disk-only arm, before the FAT32 gate and the image-tree
        // setup below: the copy step already placed the ISO files on
        // the data partition, and the shim lands in partition 1, so
        // neither the tree nor the FAT32 volume is opened here. Every
        // other mode keeps today's path byte-for-byte.
        return run_uefi_ntfs(ctx, filesystem);
    }
    // Unwired installers never reach the image or the device: same
    // table as `install_tree` (see `check_mode`).
    check_mode(mode)?;
    // `write::refuse_unsupported_kind` stays private to write.rs and
    // that module is out of scope here, so this arm carries its own
    // Iso/Raw-only table with this note: only tree images can hold
    // Syslinux payloads, and every other kind names itself on refusal.
    match image.kind {
        ImageKind::Iso | ImageKind::Raw => {}
        ref other => {
            return Err(CoreError::invalid(format!(
                "bootloader refuses an image of kind '{other}': no tree reader takes it"
            )));
        }
    }
    if *filesystem != Filesystem::Fat32 {
        return Err(CoreError::invalid(format!(
            "bootloader installation needs a FAT32 volume, the plan carries {}: only FAT32 is wired",
            filesystem_name(filesystem)
        )));
    }
    if *mode == BootloaderMode::MsDos {
        // User-supplied files by design (see `install_msdos`): the
        // arm never reads the image tree, so it short-circuits here
        // past the tree setup below — a plan whose image has no tree
        // still installs. The FAT32 gate above already ran.
        return run_msdos(ctx, msdos_dir);
    }
    let volume = FileVolume::open(Path::new(&image.path))?;
    let source: Box<dyn TreeSource> = match &image.kind {
        ImageKind::Iso => Box::new(IsoSource::new(IsoReader::open(Box::new(volume))?)),
        ImageKind::Raw => match UdfReader::open(Box::new(volume)) {
            Ok(reader) => Box::new(UdfSource::new(reader)),
            Err(udf_error) => {
                return Err(CoreError::invalid(format!(
                    "bootloader refuses a raw image: it is neither an ISO9660 nor a UDF tree (UDF open failed: {udf_error})"
                )));
            }
        },
        // Every other kind refused above; this names the kind rather
        // than assuming the match is exhaustive forever.
        other => {
            return Err(CoreError::invalid(format!(
                "bootloader refuses an image of kind '{other}': no tree reader takes it"
            )));
        }
    };
    let mut fat = Fat32::open(ctx.opener.partition()?)?;
    let cancelled = ctx.cancelled;
    let table = ctx.table;
    let mut disk = DiskView::new(ctx.device()?);
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let installed = install_tree(
        &*source,
        &mut fat,
        &mut disk,
        mode,
        table,
        msdos_dir,
        cancelled,
        &crate::boot::load,
    )?;
    fat.flush()?;
    for message in installed.messages() {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: message.clone(),
        });
    }
    match &installed {
        Installed::Skipped => {
            // Only `None` returns a skip, and `run` filtered that
            // above: unreachable, reported as success.
        }
        Installed::Syslinux {
            family,
            dir,
            stage_bytes,
            companions,
            kept_companions,
            config_path,
            ..
        } => {
            // Kept files log per file through the install messages
            // above; the summary counts every companion present.
            let total = companions.len() + kept_companions.len();
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!(
                    "installed {} Syslinux into '{dir}' ({total} companions, config {config_path}, {stage_bytes} stage bytes)",
                    family.version(),
                ),
            });
        }
        Installed::Grub2 {
            dir,
            core_bytes,
            uefi_placed,
            ..
        } => {
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!("installed grub2 BIOS loader from '{dir}' ({core_bytes} core bytes)"),
            });
            if let Some(dest) = uefi_placed {
                ctx.reporter.event(Event::Message {
                    level: "info",
                    text: format!("placed uefi image at '{dest}'"),
                });
            }
        }
        Installed::Grub4dos { sbr_bytes, .. } => {
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!(
                    "installed grub4dos boot record ({sbr_bytes} sbr bytes, existing /grldr kept)"
                ),
            });
        }
        Installed::Freedos {
            files_written,
            files_kept,
            bytes,
            ..
        } => {
            ctx.reporter.event(Event::Message {
                level: "info",
                text: freedos_summary(*files_written, *files_kept, *bytes),
            });
        }
        Installed::Kolibri { bytes, kept, .. } => {
            ctx.reporter.event(Event::Message {
                level: "info",
                text: kolibri_summary(*bytes, *kept),
            });
        }
        Installed::MsDos {
            written,
            kept,
            bytes,
            ..
        } => {
            ctx.reporter.event(Event::Message {
                level: "info",
                text: msdos_summary(*written, *kept, *bytes),
            });
        }
        Installed::UefiNtfs { bytes, offset, .. } => {
            // The tree core never builds this variant (its UefiNtfs
            // arm refuses); the disk-only path reports the same line
            // through `uefi_ntfs_summary`, kept here so both agree.
            ctx.reporter.event(Event::Message {
                level: "info",
                text: uefi_ntfs_summary(*bytes, *offset),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::Resource;
    use crate::boot::load_from;
    use crate::copy::Entry;
    use crate::copy::Source;
    use crate::error::Result as TestResult;
    use crate::fs::VecVolume;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use crate::pipeline::target::VecTarget;
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution: the loader seam every install
    /// below points at, so each one always executes.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// Asset-tree loader for [`install_tree`]: what production's
    /// [`crate::boot::load`] resolves to, without the runtime asset
    /// directory.
    fn asset_loader(resource: Resource) -> TestResult<Payload> {
        load_from(&resources_dir(), resource)
    }

    /// In-memory [`Source`] over explicit listings and file bytes, the
    /// same pattern the `copy` and `syslinux` tests use.
    struct MemSource {
        dirs: HashMap<Vec<Vec<u8>>, Vec<Entry>>,
        files: HashMap<Vec<Vec<u8>>, Vec<u8>>,
    }

    impl MemSource {
        fn new() -> Self {
            Self {
                dirs: HashMap::new(),
                files: HashMap::new(),
            }
        }

        fn with_dir(mut self, dir: &[&[u8]], entries: Vec<Entry>) -> Self {
            let key: Vec<Vec<u8>> = dir.iter().map(|part| part.to_vec()).collect();
            self.dirs.insert(key, entries);
            self
        }

        fn with_file(mut self, path: &[&[u8]], bytes: &[u8]) -> Self {
            let key: Vec<Vec<u8>> = path.iter().map(|part| part.to_vec()).collect();
            self.files.insert(key, bytes.to_vec());
            self
        }
    }

    fn file_entry(name: &[u8], bytes: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: false,
            size: bytes.len() as u64,
            mode: Some(0o644),
            modified: None,
            accessed: None,
            link: None,
        }
    }

    fn dir_entry(name: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: true,
            size: 0,
            mode: Some(0o755),
            modified: None,
            accessed: None,
            link: None,
        }
    }

    impl Source for MemSource {
        fn root_entries(&self) -> TestResult<Vec<Entry>> {
            self.child_entries(&[])
        }

        fn child_entries(&self, dir: &[Vec<u8>]) -> TestResult<Vec<Entry>> {
            self.dirs
                .get(dir)
                .cloned()
                .ok_or_else(|| CoreError::invalid("test source has no such directory".to_string()))
        }

        fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> TestResult<usize> {
            let bytes = self
                .files
                .get(file)
                .ok_or_else(|| CoreError::invalid("test source has no such file".to_string()))?;
            let at = usize::try_from(offset).expect("the test offset fits usize");
            if at > bytes.len() {
                return Err(CoreError::invalid(
                    "test read runs past its file".to_string(),
                ));
            }
            let rest = bytes.get(at..).expect("the test window fits");
            let take = rest.len().min(buf.len());
            let (head, _) = rest.split_at(take);
            let dest = buf.get_mut(..take).expect("the test buffer fits");
            dest.copy_from_slice(head);
            Ok(take)
        }
    }

    /// One `/isolinux` directory holding `isolinux.bin` with `banner`
    /// plus one file per name in `extra` (each holding its own name as
    /// bytes).
    fn payload_tree(banner: &[u8], extra: &[&str]) -> MemSource {
        let mut entries = vec![file_entry(b"isolinux.bin", banner)];
        let mut source = MemSource::new().with_dir(&[], vec![dir_entry(b"isolinux")]);
        for name in extra {
            entries.push(file_entry(name.as_bytes(), name.as_bytes()));
        }
        source = source.with_dir(&[b"isolinux"], entries);
        source = source.with_file(&[b"isolinux", b"isolinux.bin"], banner);
        for name in extra {
            source = source.with_file(&[b"isolinux", name.as_bytes()], name.as_bytes());
        }
        source
    }

    /// A 6.04 payload tree: banner, config, the core library and all
    /// three optional companions.
    fn syslinux_604_tree() -> MemSource {
        payload_tree(
            b"ISOLINUX 6.04 20140611 ETCD",
            &[
                "isolinux.cfg",
                "ldlinux.c32",
                "menu.c32",
                "vesamenu.c32",
                "libutil.c32",
            ],
        )
    }

    /// A 4.07 payload tree: banner and config only, no core library.
    fn syslinux_407_tree() -> MemSource {
        payload_tree(b"ISOLINUX 4.07 20130725 ETCD", &["isolinux.cfg"])
    }

    /// A [`Volume`] over shared bytes, the same shim the syslinux
    /// installer tests use: `Fat32` keeps its store private, so the
    /// tests watch the image through the shared handle.
    #[derive(Debug, Clone)]
    struct SharedVolume {
        bytes: Rc<RefCell<Vec<u8>>>,
    }

    impl SharedVolume {
        fn blank(len: u64) -> Self {
            let size = usize::try_from(len).expect("the ram size fits usize");
            Self {
                bytes: Rc::new(RefCell::new(vec![0u8; size])),
            }
        }

        /// A copy of the first 512 bytes (the boot sector under test).
        fn boot_sector(&self) -> [u8; 512] {
            let borrowed = self.bytes.borrow();
            let window = borrowed.get(..512).expect("the image holds a boot sector");
            let mut sector = [0u8; 512];
            sector.copy_from_slice(window);
            sector
        }
    }

    impl Volume for SharedVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.borrow().len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get(start..end).expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
            let mut borrowed = self.bytes.borrow_mut();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, Fat32) {
        let backing = SharedVolume::blank(64 * 1024 * 1024);
        let fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        (backing, fat)
    }

    /// Run [`install_tree`] with the asset loader and a whole-disk
    /// double the Syslinux path never touches (one sector is plenty):
    /// the Syslinux-shaped calls share this so the disk argument does
    /// not repeat in every test.
    fn tree_install(
        source: &MemSource,
        fat: &mut Fat32,
        mode: &BootloaderMode,
    ) -> Result<Installed> {
        tree_install_table(source, fat, mode, None)
    }

    /// [`tree_install`] with an explicit recorded table kind for the
    /// BIOS arms' gap bound; `None` exercises the no-table refusal.
    fn tree_install_table(
        source: &MemSource,
        fat: &mut Fat32,
        mode: &BootloaderMode,
        table: Option<TableKind>,
    ) -> Result<Installed> {
        let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
        install_tree(
            source,
            fat,
            &mut dummy,
            mode,
            table,
            None,
            &|| false,
            &asset_loader,
        )
    }

    #[test]
    fn syslinux_604_installs_stage_companions_and_config() {
        let (backing, mut fat) = formatted();
        let source = syslinux_604_tree();
        let installed =
            tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
        let Installed::Syslinux {
            family,
            dir,
            companions,
            config_path,
            messages,
            ..
        } = installed
        else {
            panic!("a syslinux install reports the Syslinux variant");
        };
        assert_eq!(family, Family::V604, "the 6.04 family wins");
        assert_eq!(dir, "/isolinux", "the located directory");
        assert_eq!(
            companions,
            [
                "ldlinux.c32".to_string(),
                "menu.c32".to_string(),
                "vesamenu.c32".to_string(),
                "libutil.c32".to_string(),
            ],
            "all four companions in order"
        );
        assert_eq!(config_path, "/syslinux.cfg", "the wrapper path");
        assert_eq!(
            messages[0], "  Will use '/isolinux' for Syslinux",
            "the located line prints first"
        );
        assert_eq!(
            messages[1], "  Detected Syslinux version: 6.04 (from '/isolinux/isolinux.bin')",
            "the detection line is verbatim"
        );
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        // The wrapper chains back to the image's own config.
        let expected =
            syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
        let back = fat
            .read_file("/syslinux.cfg")
            .expect("the wrapper reads back");
        assert_eq!(back, expected, "the wrapper is byte-identical");
        // The stage and the boot sector are the 6.04 payload's.
        let core = asset_loader(Resource::Syslinux604Core)
            .expect("the core loads")
            .bytes()
            .to_vec();
        let stage = fat.read_file("/ldlinux.sys").expect("the stage reads back");
        assert_eq!(
            stage.len(),
            core.len() + 1024,
            "the stage adds 1024 adv bytes"
        );
        let sector = backing.boot_sector();
        assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
        assert_eq!(
            2 + u16::from(sector[1]),
            0x5A,
            "the jump targets the code at 0x5A"
        );
        assert_eq!(
            &sector[3..11],
            b"SYSLINUX",
            "the payload OEM marks the volume"
        );
        for name in ["ldlinux.c32", "menu.c32", "vesamenu.c32", "libutil.c32"] {
            let path = format!("/isolinux/{name}");
            let back = fat.read_file(&path).expect("the companion reads back");
            assert_eq!(back, name.as_bytes(), "the companion is byte-identical");
        }
    }

    #[test]
    fn syslinux_407_logs_its_detection_and_needs_no_library() {
        let (_backing, mut fat) = formatted();
        let source = syslinux_407_tree();
        let installed =
            tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
        let Installed::Syslinux {
            family,
            companions,
            messages,
            ..
        } = installed
        else {
            panic!("a syslinux install reports the Syslinux variant");
        };
        assert_eq!(family, Family::V407, "the 4.07 family wins");
        assert_eq!(
            messages[0], "  Will use '/isolinux' for Syslinux",
            "the located line prints first"
        );
        assert_eq!(
            messages[1], "  Detected Syslinux version: 4.07 (from '/isolinux/isolinux.bin')",
            "the detection line is verbatim"
        );
        assert_eq!(
            companions,
            Vec::<String>::new(),
            "no companions ship with this tree"
        );
        // Only the wrapper config caution-free install ran: the one
        // companion present is the wrapper's own chain target.
        let back = fat
            .read_file("/syslinux.cfg")
            .expect("the wrapper reads back");
        assert_eq!(
            back,
            syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
            "the wrapper chains to the held config"
        );
    }

    #[test]
    fn bannerless_tree_forces_the_family_from_the_library() {
        // No banner anywhere but `ldlinux.c32` present: the family is
        // forced to 6.04 with the reference warning line.
        let source = payload_tree(b"no banner here", &["isolinux.cfg", "ldlinux.c32"]);
        let (_backing, mut fat) = formatted();
        let installed = tree_install(&source, &mut fat, &BootloaderMode::Auto)
            .expect("the forced install runs");
        let Installed::Syslinux {
            family, messages, ..
        } = installed
        else {
            panic!("a forced install reports the Syslinux variant");
        };
        assert_eq!(family, Family::V604, "the library forces 6.04");
        assert_eq!(messages[0], "auto: probing syslinux", "the probe is logged");
        assert_eq!(
            messages[1], "  Will use '/isolinux' for Syslinux",
            "the located line prints next"
        );
        assert_eq!(
            messages[2],
            "  Warning: Could not detect Isolinux version - Forcing to 6.04 (embedded)",
            "the forcing line is verbatim"
        );
    }

    #[test]
    fn syslinux_604_without_the_library_refuses_before_any_write() {
        // Banner says 6.04 but `ldlinux.c32` is absent: the required
        // module is missing, so the install refuses with the image
        // byte-identical.
        let source = payload_tree(b"ISOLINUX 6.04 20140611 ETCD", &["isolinux.cfg"]);
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
            .expect_err("a library-less 6.04 refuses");
        let text = error.to_string();
        assert!(text.contains("6.04"), "names the family: {text}");
        assert!(text.contains("ldlinux.c32"), "names the module: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no byte moved in 67108864 bytes of image"
        );
    }

    #[test]
    fn bare_tree_refuses_without_pretending_grub_support() {
        // Nothing Syslinux-like anywhere: the explicit mode refuses
        // naming what is missing instead of pretending GRUB support.
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (_backing, mut fat) = formatted();
        let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
            .expect_err("a bare tree refuses");
        let text = error.to_string();
        assert!(
            text.contains("no syslinux payloads"),
            "says what is missing: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn auto_bare_tree_lists_all_three_probes() {
        // Nothing bootloader-like anywhere: `Auto` walks the whole
        // chain and refuses once, naming every probe it ran.
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (_backing, mut fat) = formatted();
        let error = tree_install(&source, &mut fat, &BootloaderMode::Auto)
            .expect_err("a bare tree refuses");
        let text = error.to_string();
        assert!(text.contains("syslinux"), "names the first probe: {text}");
        assert!(text.contains("grub2"), "names the second probe: {text}");
        assert!(text.contains("grldr"), "names the third probe: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn none_mode_writes_nothing() {
        let source = syslinux_604_tree();
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let installed =
            tree_install(&source, &mut fat, &BootloaderMode::None).expect("none always runs");
        assert_eq!(
            installed,
            Installed::Skipped,
            "a skipped install reports Skipped"
        );
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no byte moved in 67108864 bytes of image"
        );
    }

    #[test]
    fn every_mode_passes_the_shared_gate() {
        // All modes are wired today: the shared table passes each one,
        // so a future variant fails closed here until it is named.
        // (`UefiNtfs` passes here too; its disk-only arm lives in
        // `run`, and the tree core refuses it as invalid — see the
        // next test.)
        for mode in [
            BootloaderMode::Auto,
            BootloaderMode::Syslinux,
            BootloaderMode::Grub2,
            BootloaderMode::Grub4dos,
            BootloaderMode::UefiNtfs,
            BootloaderMode::Freedos,
            BootloaderMode::Kolibri,
            BootloaderMode::MsDos,
            BootloaderMode::None,
        ] {
            check_mode(&mode).expect("a wired mode passes the gate");
        }
    }

    #[test]
    fn install_tree_refuses_uefi_ntfs_as_disk_only() {
        // The shim lands on the whole disk with no tree and no FAT32
        // volume, so the tree core refuses it — as invalid, not not
        // implemented (the installer exists, in `run`), naming the
        // whole-disk path.
        let source = syslinux_604_tree();
        let (_backing, mut fat) = formatted();
        let error = tree_install(&source, &mut fat, &BootloaderMode::UefiNtfs)
            .expect_err("a tree uefi-ntfs refuses");
        assert!(
            !matches!(error, CoreError::NotImplemented { .. }),
            "a wired mode is never NotImplemented: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("uefi-ntfs"), "names the mode: {text}");
        assert!(text.contains("whole disk"), "names the path: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn freedos_installs_payloads_locale_and_record() {
        // A fresh FAT32 image through the `Freedos` arm: the
        // `COMMAND.COM`/`KERNEL.SYS` pair, the `LOCALE` directory with
        // its 25 files, `AUTOEXEC.BAT` and the FreeDOS record. The
        // source tree is bare on purpose: the arm never reads it (the
        // write step already copied it), so a tree without any DOS
        // files still installs.
        use crate::boot::dos_locale::DosFlavor;
        use crate::boot::dos_locale::Locale;
        seed_exe_assets();
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let installed = tree_install(&source, &mut fat, &BootloaderMode::Freedos)
            .expect("the freedos install runs");
        let Installed::Freedos {
            files_written,
            files_kept,
            bytes,
            messages,
        } = installed
        else {
            panic!("a freedos install reports the Freedos variant");
        };
        // The US locale plans no `CONFIG.SYS`: 27 payloads plus the
        // echo-only `AUTOEXEC.BAT` write, nothing kept.
        assert_eq!(files_written, 28, "27 payloads plus AUTOEXEC.BAT");
        assert_eq!(files_kept, 0, "a fresh install keeps nothing");
        assert!(bytes > 0, "bytes count the written files");
        assert_eq!(
            messages[0], "Will use DOS keyboard 'us' [US-English]",
            "the locale keyboard line leads"
        );
        assert_eq!(
            messages[1], "Will use codepage 437 [US-English]",
            "the locale codepage line follows"
        );
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert!(!back.is_empty(), "COMMAND.COM landed");
        let back = fat.read_file("/KERNEL.SYS").expect("KERNEL.SYS reads back");
        assert!(!back.is_empty(), "KERNEL.SYS landed");
        let listed = fat.list_dir("/LOCALE").expect("the locale lists");
        assert_eq!(listed.len(), 25, "LOCALE holds the 25 locale files");
        let planned = crate::boot::dos_locale::plan(DosFlavor::FreeDos, &Locale::us());
        let back = fat
            .read_file("/AUTOEXEC.BAT")
            .expect("AUTOEXEC.BAT reads back");
        assert_eq!(
            back,
            planned.autoexec_bat(),
            "AUTOEXEC.BAT equals the locale plan bytes"
        );
        let sector = backing.boot_sector();
        assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
        assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        // The run summary names counts, bytes and the record.
        let summary = freedos_summary(files_written, files_kept, bytes);
        assert!(summary.contains("28"), "names the files: {summary}");
        assert!(
            summary.contains(&bytes.to_string()),
            "names the bytes: {summary}"
        );
        assert!(
            summary.contains("boot record"),
            "names the record: {summary}"
        );
        assert!(summary.is_ascii(), "stays ASCII: {summary}");
    }

    /// Synthetic KolibriOS loader bytes (1 KiB of distinct bytes): a
    /// stand-in with a realistic shape, not a KolibriOS payload.
    fn kolibri_loader_bytes() -> Vec<u8> {
        (0..1024)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect()
    }

    /// A source tree holding the exact `HD_Load/USB_Boot/MTLD_F32`
    /// path with `loader` bytes.
    fn kolibri_tree(loader: &[u8]) -> MemSource {
        MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_Load")])
            .with_dir(&[b"HD_Load"], vec![dir_entry(b"USB_Boot")])
            .with_dir(
                &[b"HD_Load", b"USB_Boot"],
                vec![file_entry(b"MTLD_F32", loader)],
            )
            .with_file(&[b"HD_Load", b"USB_Boot", b"MTLD_F32"], loader)
    }

    #[test]
    fn kolibri_installs_loader_and_record() {
        // A synthetic tree carrying `/HD_Load/USB_Boot/MTLD_F32`: the
        // arm places `/MTLD_F32` byte-identical and writes the Kolibri
        // record, reporting discovery, placement and the record.
        let loader = kolibri_loader_bytes();
        let source = kolibri_tree(&loader);
        let (backing, mut fat) = formatted();
        let installed = tree_install(&source, &mut fat, &BootloaderMode::Kolibri)
            .expect("the kolibri install runs");
        let Installed::Kolibri {
            bytes,
            kept,
            messages,
        } = installed
        else {
            panic!("a kolibri install reports the Kolibri variant");
        };
        assert_eq!(bytes, loader.len() as u64, "the loader bytes count");
        assert!(!kept, "a fresh write is not kept");
        assert_eq!(
            messages[0], "found kolibri loader at '/HD_Load/USB_Boot/MTLD_F32'",
            "discovery first"
        );
        assert!(
            messages[1].contains("placed kolibri loader at '/MTLD_F32'"),
            "placement next: {messages:?}"
        );
        assert!(
            messages[1].contains(&bytes.to_string()),
            "placement names the bytes: {messages:?}"
        );
        assert_eq!(
            messages[2], "installed kolibri boot record",
            "the record last"
        );
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        let back = fat.read_file("/MTLD_F32").expect("the loader reads back");
        assert_eq!(back, loader, "the loader is byte-identical");
        let sector = backing.boot_sector();
        assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
        assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        // The run summary names bytes, the path and the record.
        let summary = kolibri_summary(bytes, kept);
        assert!(
            summary.contains(&bytes.to_string()),
            "names the bytes: {summary}"
        );
        assert!(summary.contains("/MTLD_F32"), "names the path: {summary}");
        assert!(
            summary.contains("boot record"),
            "names the record: {summary}"
        );
        assert!(summary.is_ascii(), "stays ASCII: {summary}");
    }

    #[test]
    fn kolibri_keeps_an_identical_loader() {
        // A second install over identical bytes keeps them: the copy
        // step legitimately places the file first, so nothing writes —
        // but the record still lands and the skip is reported.
        let loader = kolibri_loader_bytes();
        let source = kolibri_tree(&loader);
        let (_backing, mut fat) = formatted();
        let first = tree_install(&source, &mut fat, &BootloaderMode::Kolibri)
            .expect("the first install runs");
        assert!(
            matches!(first, Installed::Kolibri { kept: false, .. }),
            "a fresh write is not kept"
        );
        let again = tree_install(&source, &mut fat, &BootloaderMode::Kolibri)
            .expect("identical bytes are kept");
        let Installed::Kolibri {
            bytes,
            kept,
            messages,
        } = again
        else {
            panic!("a kept install reports the Kolibri variant");
        };
        assert!(kept, "the second install reports kept");
        assert_eq!(
            bytes,
            loader.len() as u64,
            "the kept report counts the bytes"
        );
        assert!(
            messages.iter().any(|line| line.contains("keeping it")),
            "the skip is reported: {messages:?}"
        );
        let back = fat
            .read_file("/MTLD_F32")
            .expect("the kept file reads back");
        assert_eq!(back, loader, "kept bytes unchanged");
    }

    #[test]
    fn kolibri_without_a_loader_refuses_leaving_everything_identical() {
        // A tree without the loader path refuses naming it, with the
        // volume and the disk byte-identical (the record runs last, so
        // a loader refusal leaves sector 0 untouched).
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let mut target = VecTarget::new(512, 512).expect("one sector fits");
        let disk_before = target.bytes().expect("the disk reads back");
        let mut disk = DiskView::new(&mut target);
        let error = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Kolibri,
            None,
            None,
            &|| false,
            &asset_loader,
        )
        .expect_err("a loader-less kolibri refuses");
        let text = error.to_string();
        assert!(
            text.contains("HD_Load/USB_Boot/MTLD_F32"),
            "names the path: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no volume byte moved in 67108864 bytes of image"
        );
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            disk_before,
            "no disk byte moved"
        );
    }

    /// Synthetic `IO.SYS`-shaped bytes at the exact expected size
    /// with the reference signature planted: stand-in bytes for the
    /// arm tests — synthetic, not real DOS bytes.
    fn msdos_io_sys_input() -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..crate::boot::msdos::IO_SYS_BYTES)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let end = crate::boot::msdos::IO_SYS_SIGNATURE_OFFSET
            + crate::boot::msdos::IO_SYS_SIGNATURE.len();
        bytes[crate::boot::msdos::IO_SYS_SIGNATURE_OFFSET..end]
            .copy_from_slice(&crate::boot::msdos::IO_SYS_SIGNATURE);
        bytes
    }

    /// Synthetic `COMMAND.COM`-shaped bytes at the exact expected size
    /// with the reference signature planted: stand-in bytes for the
    /// arm tests — synthetic, not real DOS bytes.
    fn msdos_command_com_input() -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..crate::boot::msdos::COMMAND_COM_BYTES)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect();
        let end = crate::boot::msdos::COMMAND_COM_SIGNATURE_OFFSET
            + crate::boot::msdos::COMMAND_COM_SIGNATURE.len();
        bytes[crate::boot::msdos::COMMAND_COM_SIGNATURE_OFFSET..end]
            .copy_from_slice(&crate::boot::msdos::COMMAND_COM_SIGNATURE);
        bytes
    }

    /// A scratch directory holding the three user-supplied files: the
    /// caller passes the exact bytes, so the patch-miss test reuses
    /// the same seam with short inputs.
    fn msdos_scratch(io_sys: &[u8], msdos_sys: &[u8], command_com: &[u8]) -> tempfile::TempDir {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        std::fs::write(scratch.path().join("IO.SYS"), io_sys).expect("IO.SYS lands");
        std::fs::write(scratch.path().join("MSDOS.SYS"), msdos_sys).expect("MSDOS.SYS lands");
        std::fs::write(scratch.path().join("COMMAND.COM"), command_com).expect("COMMAND.COM lands");
        scratch
    }

    /// Run [`install_tree`] with `dir` as the plan's `msdos_dir`: the
    /// arm reads the directory, never the tree, so callers pass a
    /// bare source on purpose.
    fn msdos_install(source: &MemSource, fat: &mut Fat32, dir: &Path) -> Result<Installed> {
        let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
        install_tree(
            source,
            fat,
            &mut dummy,
            &BootloaderMode::MsDos,
            None,
            Some(dir),
            &|| false,
            &asset_loader,
        )
    }

    #[test]
    fn msdos_installs_user_files_with_io_sys_first_and_contiguous() {
        // A fresh FAT32 image through the `MsDos` arm: the three
        // user-supplied files land with both patches applied, `IO.SYS`
        // first, in one contiguous run, and sector 0 untouched (the
        // formatter's standard record stands — MS-DOS uses it).
        let io_sys = msdos_io_sys_input();
        let msdos_sys = vec![0xABu8; 2048];
        let command_com = msdos_command_com_input();
        let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let before = backing.boot_sector();
        let installed =
            msdos_install(&source, &mut fat, scratch.path()).expect("the msdos install runs");
        let Installed::MsDos {
            written,
            kept,
            bytes,
            patch_states,
            messages,
        } = installed
        else {
            panic!("an msdos install reports the MsDos variant");
        };
        assert_eq!(written, 3, "three files written");
        assert_eq!(kept, 0, "a fresh install keeps nothing");
        assert_eq!(
            bytes,
            (io_sys.len() + msdos_sys.len() + command_com.len()) as u64,
            "the bytes count the three files"
        );
        assert_eq!(
            patch_states,
            (
                crate::boot::msdos::PatchState::Applied,
                crate::boot::msdos::PatchState::Applied
            ),
            "both patches land"
        );
        assert_eq!(messages.len(), 2, "no skip notes: {messages:?}");
        assert_eq!(messages[0], "Patching IO.SYS...", "the bios line first");
        assert_eq!(
            messages[1], "Patching COMMAND.COM...",
            "the shell line next"
        );
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );

        // The root holds the three files, with IO.SYS first.
        let listed = fat.list_dir("/").expect("the root lists");
        let shorts: Vec<&str> = listed
            .iter()
            .map(|entry| entry.short_name.as_str())
            .collect();
        assert_eq!(
            shorts,
            vec!["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
            "the root lists the three files with IO.SYS first"
        );

        // The patched files carry 0xEB at the reference offsets and
        // are otherwise byte-identical to the supplied copies; the
        // kernel is verbatim.
        let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
        assert_eq!(back.len(), io_sys.len(), "the bios length holds");
        assert_eq!(
            back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
            0xEB,
            "the bios patch byte lands"
        );
        for (index, (&was, &is)) in io_sys.iter().zip(back.iter()).enumerate() {
            if index == crate::boot::msdos::IO_SYS_PATCH_OFFSET {
                continue;
            }
            assert_eq!(was, is, "only the patch byte differs at {index}");
        }
        let back = fat.read_file("/MSDOS.SYS").expect("MSDOS.SYS reads back");
        assert_eq!(back, msdos_sys, "the kernel is byte-correct");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert_eq!(back.len(), command_com.len(), "the shell length holds");
        assert_eq!(
            back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
            0xEB,
            "the shell patch byte lands"
        );

        // IO.SYS sits in one contiguous run ending in end-of-chain:
        // walk the first FAT copy straight from the raw image. The
        // allocator journals the chain and the arm never flushes, so
        // the caller-side flush below materializes it first.
        fat.flush().expect("the caller-side flush runs");
        let geometry = *fat.geometry();
        let io_entry = listed
            .iter()
            .find(|entry| entry.short_name == "IO.SYS")
            .expect("IO.SYS is listed");
        let cluster_bytes = geometry.cluster_bytes();
        let clusters = (crate::boot::msdos::IO_SYS_BYTES as u64).div_ceil(cluster_bytes);
        let count = u32::try_from(clusters).expect("the test run fits u32");
        let fat_start = u64::from(geometry.reserved_sectors) * u64::from(geometry.bytes_per_sector);
        let image = backing.bytes.borrow();
        for offset in 0..count {
            let cluster = io_entry
                .first_cluster
                .checked_add(offset)
                .expect("the test cluster fits");
            let at = usize::try_from(fat_start + u64::from(cluster) * 4)
                .expect("the fat window fits usize");
            let window = image.get(at..at + 4).expect("the fat entry fits");
            let raw = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            if offset + 1 < count {
                let next = cluster.checked_add(1).expect("the next cluster fits");
                assert_eq!(
                    raw, next,
                    "cluster {cluster} links to the next cluster, not {raw:#010x}"
                );
            } else {
                assert!(
                    raw >= 0x0FFF_FFF8,
                    "cluster {cluster} closes with end-of-chain, not {raw:#010x}"
                );
            }
        }

        // Sector 0 is untouched: MS-DOS uses the standard FAT record,
        // so the formatter's stands.
        assert_eq!(backing.boot_sector(), before, "no boot-sector byte moved");

        // The composed image is fsck clean (read-only check over a
        // dumped tempfile; the tool resolves through `PATH`).
        let dump = tempfile::tempdir().expect("a scratch directory");
        let dumped = dump.path().join("msdos.img");
        std::fs::write(&dumped, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg("-v")
            .arg(&dumped)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "fsck.fat -n -v exits 0 after the msdos install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );

        // The run summary names the files, the kept count and the bytes.
        let summary = msdos_summary(written, kept, bytes);
        assert!(summary.contains("3"), "names the files: {summary}");
        assert!(
            summary.contains(&bytes.to_string()),
            "names the bytes: {summary}"
        );
        assert!(summary.contains("msdos"), "names the mode: {summary}");
        assert!(summary.is_ascii(), "stays ASCII: {summary}");
    }

    #[test]
    fn msdos_second_install_keeps() {
        // A second install over identical bytes keeps all three: the
        // kept files report with the reference `Kept existing`
        // lines, and nothing writes.
        let io_sys = msdos_io_sys_input();
        let msdos_sys = vec![0xABu8; 2048];
        let command_com = msdos_command_com_input();
        let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (_backing, mut fat) = formatted();
        msdos_install(&source, &mut fat, scratch.path()).expect("the first install runs");
        let again =
            msdos_install(&source, &mut fat, scratch.path()).expect("identical bytes are kept");
        let Installed::MsDos {
            written,
            kept,
            messages,
            ..
        } = again
        else {
            panic!("a kept install reports the MsDos variant");
        };
        assert_eq!(written, 0, "nothing writes twice");
        assert_eq!(kept, 3, "all three files kept");
        for name in ["IO.SYS", "MSDOS.SYS", "COMMAND.COM"] {
            assert!(
                messages
                    .iter()
                    .any(|line| line == &format!("  Kept existing '{name}'")),
                "the kept line reports {name}: {messages:?}"
            );
        }
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        let back = fat.read_file("/IO.SYS").expect("the kept file reads back");
        assert_eq!(back.len(), io_sys.len(), "kept bytes unchanged");
        assert_eq!(
            back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
            0xEB,
            "the kept patch byte holds"
        );
    }

    #[test]
    fn msdos_patch_miss_is_noted_and_copied_verbatim() {
        // Short inputs miss the size check: the install still lands
        // every file verbatim and replays the reference skip notes
        // after each `Patching ...` line.
        let io_sys = vec![0x11u8; 1024];
        let msdos_sys = vec![0x22u8; 512];
        let command_com = vec![0x33u8; 1024];
        let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (_backing, mut fat) = formatted();
        let installed = msdos_install(&source, &mut fat, scratch.path())
            .expect("a size-missed install still lands");
        let Installed::MsDos {
            patch_states,
            messages,
            ..
        } = installed
        else {
            panic!("a missed install reports the MsDos variant");
        };
        assert_eq!(
            patch_states,
            (
                crate::boot::msdos::PatchState::UnexpectedSize { observed: 1024 },
                crate::boot::msdos::PatchState::UnexpectedSize { observed: 1024 }
            ),
            "both misses report their observed lengths"
        );
        assert_eq!(
            messages,
            vec![
                "Patching IO.SYS...".to_string(),
                "  unexpected file size".to_string(),
                "Patching COMMAND.COM...".to_string(),
                "  unexpected file size".to_string(),
            ],
            "each miss replays the reference note"
        );
        let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
        assert_eq!(back, io_sys, "a missed file copies verbatim");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert_eq!(back, command_com, "a missed shell copies verbatim");
    }

    #[test]
    fn msdos_without_a_directory_refuses_naming_the_flag() {
        // No directory means no honest install: the arm refuses
        // naming `--msdos-dir` before any write, with the volume
        // byte-identical.
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let error = tree_install(&source, &mut fat, &BootloaderMode::MsDos)
            .expect_err("a directory-less msdos refuses");
        let text = error.to_string();
        assert!(text.contains("--msdos-dir"), "names the flag: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no volume byte moved in 67108864 bytes of image"
        );
    }

    #[test]
    fn msdos_missing_directory_refuses_naming_it() {
        // A directory that does not exist is refused naming it, with
        // the volume byte-identical (the load runs before any write).
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let missing = scratch.path().join("no-such-dir");
        let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
        let error = install_tree(
            &source,
            &mut fat,
            &mut dummy,
            &BootloaderMode::MsDos,
            None,
            Some(&missing),
            &|| false,
            &asset_loader,
        )
        .expect_err("a missing directory refuses");
        let text = error.to_string();
        assert!(
            text.contains(&missing.display().to_string()),
            "names the directory: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no volume byte moved in 67108864 bytes of image"
        );
    }

    #[test]
    fn msdos_directory_slot_refuses() {
        // A directory sitting in a payload slot (`IO.SYS` as a
        // directory, not a file) refuses naming it instead of
        // failing on the read, with the volume byte-identical.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        std::fs::create_dir(scratch.path().join("IO.SYS")).expect("the directory lands");
        std::fs::write(scratch.path().join("MSDOS.SYS"), b"kernel-bytes")
            .expect("the kernel lands");
        std::fs::write(scratch.path().join("COMMAND.COM"), b"shell-bytes")
            .expect("the shell lands");
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let error =
            msdos_install(&source, &mut fat, scratch.path()).expect_err("a directory slot refuses");
        let text = error.to_string();
        assert!(text.contains("IO.SYS"), "names the slot: {text}");
        assert!(text.contains("regular file"), "names the problem: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no volume byte moved in 67108864 bytes of image"
        );
    }

    /// Sparse block size: one FAT32 cluster at most (64 KiB), so a
    /// block never straddles more than a couple of writes.
    const SPARSE_BLOCK: u64 = 64 * 1024;

    /// A sparse in-memory [`Volume`] reporting a large `total_bytes`
    /// while storing only the windows written (zero elsewhere): the
    /// stand-in for a multi-gigabyte device no test may allocate — a
    /// real 32 GiB file would blow the tmpfs under `/tmp`, and a
    /// 32 GiB `Vec` would blow the heap, while the format's few MiB
    /// of FAT writes cost MiB here. Cloned handles share the blocks
    /// (like [`SharedVolume`]), so the test still observes the
    /// formatter's bytes after [`Fat32::format`] returns.
    #[derive(Debug, Clone)]
    struct SparseVolume {
        blocks: Rc<RefCell<BTreeMap<u64, Vec<u8>>>>,
        total: u64,
    }

    impl SparseVolume {
        fn large(total: u64) -> Self {
            Self {
                blocks: Rc::new(RefCell::new(BTreeMap::new())),
                total,
            }
        }

        /// A copy of the stored blocks, for the unchanged comparisons.
        fn snapshot(&self) -> BTreeMap<u64, Vec<u8>> {
            self.blocks.borrow().clone()
        }

        /// Checked byte window of `len` bytes at `offset`, naming
        /// offset, length and total on refusal.
        fn window(&self, offset: u64, len: usize, direction: &str) -> Result<(u64, u64)> {
            let end = offset.checked_add(len as u64).ok_or_else(|| {
                CoreError::invalid(format!(
                    "sparse test {direction} overflows the byte arithmetic"
                ))
            })?;
            if end > self.total {
                return Err(CoreError::invalid(format!(
                    "sparse test {direction} of {len} bytes at offset {offset} runs past the {} byte volume",
                    self.total,
                )));
            }
            Ok((offset, end))
        }
    }

    impl Volume for SparseVolume {
        fn total_bytes(&self) -> u64 {
            self.total
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
            let (_, end) = self.window(offset, buf.len(), "read")?;
            buf.fill(0);
            if buf.is_empty() {
                return Ok(());
            }
            let stored = self.blocks.borrow();
            let mut cursor = offset;
            let mut done = 0usize;
            while cursor < end {
                let index = cursor / SPARSE_BLOCK;
                let base = index * SPARSE_BLOCK;
                let stop = (base + SPARSE_BLOCK).min(end);
                let take =
                    usize::try_from(stop - cursor).expect("a sparse block window fits usize");
                if let Some(block) = stored.get(&index) {
                    let from =
                        usize::try_from(cursor - base).expect("a sparse block offset fits usize");
                    buf[done..done + take].copy_from_slice(&block[from..from + take]);
                }
                done += take;
                cursor = stop;
            }
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
            let (_, end) = self.window(offset, buf.len(), "write")?;
            if buf.is_empty() {
                return Ok(());
            }
            let mut stored = self.blocks.borrow_mut();
            let mut cursor = offset;
            let mut done = 0usize;
            while cursor < end {
                let index = cursor / SPARSE_BLOCK;
                let base = index * SPARSE_BLOCK;
                let stop = (base + SPARSE_BLOCK).min(end);
                let take =
                    usize::try_from(stop - cursor).expect("a sparse block window fits usize");
                let block = stored
                    .entry(index)
                    .or_insert_with(|| vec![0u8; SPARSE_BLOCK as usize]);
                let from =
                    usize::try_from(cursor - base).expect("a sparse block offset fits usize");
                block[from..from + take].copy_from_slice(&buf[done..done + take]);
                done += take;
                cursor = stop;
            }
            Ok(())
        }
    }

    #[test]
    fn msdos_refuses_a_64kib_cluster_volume_before_any_write() {
        // 32 GiB is the first geometry tier with 64 KiB clusters (see
        // `CLUSTER_TIERS`/`LARGE_CLUSTER_BYTES`): MS-DOS cannot boot
        // from it, so the arm refuses with the reference MSG_110
        // sentence before any file lands. The volume is a sparse
        // double (see `SparseVolume`), so the format's few MiB of FAT
        // writes cost MiB, not GiB.
        let io_sys = msdos_io_sys_input();
        let msdos_sys = vec![0xABu8; 2048];
        let command_com = msdos_command_com_input();
        let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
        let backing = SparseVolume::large(32 * 1024 * 1024 * 1024);
        let mut fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the large volume formats");
        assert_eq!(
            fat.geometry().cluster_bytes(),
            65_536,
            "the tier premise holds: 32 GiB formats with 64 KiB clusters"
        );
        let before = backing.snapshot();
        let error = install_msdos(&mut fat, scratch.path(), &|| false)
            .expect_err("a 64 KiB cluster refuses");
        let text = error.to_string();
        assert!(
            text.contains("MS-DOS cannot boot from a drive using a 64 kilobytes Cluster size."),
            "the refusal carries the reference sentence verbatim: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.snapshot(),
            before,
            "no volume byte moved: the gate fires before any file write"
        );
    }

    /// 64 MiB whole-disk double for the UEFI:NTFS arm: big enough for
    /// the planner to lay the 1 MiB ESP window on, small enough to
    /// snapshot in RAM.
    const UEFI_DISK_BYTES: u64 = 64 * 1024 * 1024;

    /// A whole-disk double prefilled with a recognisable pattern, plus
    /// the pattern for the untouched comparisons.
    fn prefilled_uefi_disk() -> (VecTarget, Vec<u8>) {
        let target = VecTarget::new(UEFI_DISK_BYTES, 512).expect("the disk allocates");
        let before: Vec<u8> = (0..UEFI_DISK_BYTES as usize)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        target.write_all_at(0, &before).expect("the prefill lands");
        (target, before)
    }

    /// The pinned shim bytes through the asset-tree loader (what
    /// production's [`crate::boot::load`] resolves to, without the
    /// runtime asset directory).
    fn uefi_image_bytes() -> Vec<u8> {
        asset_loader(Resource::UefiNtfsImage)
            .expect("the shim loads")
            .bytes()
            .to_vec()
    }

    /// Run the disk-only arm over `target` with explicit `image`
    /// bytes: the helper-level seam every UEFI test below shares (a
    /// [`DiskView`] bridges the target into the [`Volume`] the arm
    /// speaks).
    fn uefi_install(
        target: &mut VecTarget,
        table: Option<TableKind>,
        filesystem: &Filesystem,
        image: &[u8],
    ) -> Result<Installed> {
        let mut disk = DiskView::new(target);
        install_uefi_ntfs(&mut disk, table, filesystem, image)
    }

    #[test]
    fn uefi_ntfs_installs_the_image_at_the_esp_window() {
        // The pinned 1 MiB lands whole at the 1 MiB ESP offset the
        // planner stamps for the `UefiNtfs` layout; the head and the
        // whole data window keep the prefill.
        let (mut target, before) = prefilled_uefi_disk();
        let image = uefi_image_bytes();
        let installed = uefi_install(&mut target, Some(TableKind::Mbr), &Filesystem::Ntfs, &image)
            .expect("the install runs");
        let Installed::UefiNtfs {
            bytes,
            offset,
            messages,
        } = installed
        else {
            panic!("a uefi-ntfs install reports the UefiNtfs variant");
        };
        assert_eq!(bytes, uefi_ntfs::IMAGE_BYTES, "the whole image counts");
        assert_eq!(offset, 1024 * 1024, "the planner's ESP offset");
        assert_eq!(
            messages,
            ["Writing UEFI:NTFS data...".to_string()],
            "the reference line reports"
        );
        assert!(
            messages.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        let after = target.bytes().expect("the disk reads back");
        assert_eq!(
            &after[offset as usize..(offset + bytes) as usize],
            &image[..],
            "the image lands whole at the ESP offset"
        );
        assert_eq!(
            &after[..offset as usize],
            &before[..offset as usize],
            "not one byte before the window moved"
        );
        let (data_offset, data_len) = crate::part::plan::data_window(
            LayoutKind::UefiNtfs,
            TableKind::Mbr,
            512,
            UEFI_DISK_BYTES,
        )
        .expect("the data window plans");
        assert_eq!(
            &after[data_offset as usize..(data_offset + data_len) as usize],
            &before[data_offset as usize..(data_offset + data_len) as usize],
            "the data window's bytes are untouched"
        );
    }

    #[test]
    fn uefi_ntfs_takes_ntfs_and_exfat_and_refuses_the_rest() {
        // The reference's filesystem rule (`rufus.c:2032-2037`): NTFS
        // and exFAT run, every other plan filesystem refuses naming
        // itself, before any write.
        for filesystem in [Filesystem::Ntfs, Filesystem::Exfat] {
            let (mut target, _before) = prefilled_uefi_disk();
            let image = uefi_image_bytes();
            let installed = uefi_install(&mut target, Some(TableKind::Mbr), &filesystem, &image)
                .expect("ntfs and exfat run");
            assert!(
                matches!(installed, Installed::UefiNtfs { .. }),
                "{filesystem:?} reports the UefiNtfs variant"
            );
        }
        for filesystem in [
            Filesystem::Fat32,
            Filesystem::Ext2,
            Filesystem::Ext3,
            Filesystem::Ext4,
            Filesystem::Udf,
        ] {
            let (mut target, before) = prefilled_uefi_disk();
            let image = uefi_image_bytes();
            let error = uefi_install(&mut target, Some(TableKind::Mbr), &filesystem, &image)
                .expect_err("other filesystems refuse");
            let text = error.to_string();
            assert!(
                text.contains(filesystem_name(&filesystem)),
                "names the filesystem: {text}"
            );
            assert!(text.contains("NTFS or exFAT"), "names the rule: {text}");
            assert!(text.is_ascii(), "stays ASCII: {text}");
            assert_eq!(
                target.bytes().expect("the disk reads back"),
                before,
                "no byte moved in 67108864 bytes of disk"
            );
        }
    }

    #[test]
    fn uefi_ntfs_without_a_recorded_table_refuses() {
        // No table, no window: the `gap_end`-style honesty gate fires
        // before any write.
        let (mut target, before) = prefilled_uefi_disk();
        let image = uefi_image_bytes();
        let error = uefi_install(&mut target, None, &Filesystem::Ntfs, &image)
            .expect_err("a table-less uefi-ntfs refuses");
        let text = error.to_string();
        assert!(
            text.contains("recorded partition table"),
            "names the missing bound: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            before,
            "no byte moved in 67108864 bytes of disk"
        );
    }

    #[test]
    fn uefi_ntfs_oversized_image_refuses_before_any_write() {
        // One byte past the ESP window: the pre-write bound check
        // fires naming the offset, the length and the limit, with the
        // device byte-identical.
        let (offset, len) = crate::part::plan::esp_window(
            LayoutKind::UefiNtfs,
            TableKind::Mbr,
            512,
            UEFI_DISK_BYTES,
        )
        .expect("the window plans");
        let oversized = vec![0xA5u8; (len + 1) as usize];
        let (mut target, before) = prefilled_uefi_disk();
        let error = uefi_install(
            &mut target,
            Some(TableKind::Mbr),
            &Filesystem::Ntfs,
            &oversized,
        )
        .expect_err("an overrunning image refuses");
        let text = error.to_string();
        assert!(
            text.contains(&offset.to_string()),
            "names the offset: {text}"
        );
        assert!(
            text.contains(&(len + 1).to_string()),
            "names the length: {text}"
        );
        assert!(
            text.contains(&(offset + len).to_string()),
            "names the limit: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            before,
            "no byte moved in 67108864 bytes of disk"
        );
    }

    /// An [`Opener`](crate::pipeline::opener::Opener) that counts
    /// `partition()` calls and refuses them: the non-FAT32 test
    /// proves the step never opens the partition.
    struct CountingOpener {
        partitions: Rc<Cell<usize>>,
    }

    impl crate::pipeline::opener::Opener for CountingOpener {
        fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
            Err(CoreError::invalid("test opener has no device".to_string()))
        }

        fn partition(&self) -> TestResult<Box<dyn Volume>> {
            self.partitions.set(self.partitions.get() + 1);
            Err(CoreError::invalid(
                "test opener has no partition".to_string(),
            ))
        }

        fn partition_path(&self) -> TestResult<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no node".to_string()))
        }
    }

    /// A test [`Opener`](crate::pipeline::opener::Opener) serving one
    /// shared [`VecTarget`](crate::pipeline::target::VecTarget) as the
    /// whole disk while counting `partition()` calls: the UEFI run
    /// path must never open the data partition.
    #[derive(Debug, Clone)]
    struct DiskOpener {
        target: VecTarget,
        partitions: Rc<Cell<usize>>,
    }

    impl crate::pipeline::opener::Opener for DiskOpener {
        fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
            Ok(Box::new(self.target.clone()))
        }

        fn partition(&self) -> TestResult<Box<dyn Volume>> {
            self.partitions.set(self.partitions.get() + 1);
            Err(CoreError::invalid(
                "test opener has no partition".to_string(),
            ))
        }

        fn partition_path(&self) -> TestResult<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no node".to_string()))
        }
    }

    /// A [`Reporter`](crate::pipeline::event::Reporter) that records
    /// every event in order.
    #[derive(Debug, Default)]
    struct Recorder {
        events: Vec<crate::pipeline::event::Event>,
    }

    impl crate::pipeline::event::Reporter for Recorder {
        fn event(&mut self, event: crate::pipeline::event::Event) {
            self.events.push(event);
        }
    }

    /// A [`RunContext`](crate::pipeline::steps::RunContext) over any
    /// test opener with an explicit recorded table, for the `run`
    /// tests below.
    fn run_context_table<'a>(
        opener: &'a dyn crate::pipeline::opener::Opener,
        reporter: &'a mut Recorder,
        table: Option<TableKind>,
    ) -> crate::pipeline::steps::RunContext<'a> {
        crate::pipeline::steps::RunContext {
            opener,
            target: None,
            table,
            partitioned: None,
            logger: crate::log::Logger::new(crate::log::Level::Info),
            reporter,
            cancelled: &|| false,
            options: crate::pipeline::RunOptions {
                verify: false,
                badblocks: false,
                retries: 3,
                retry_delay: std::time::Duration::ZERO,
                reset_usb: false,
            },
        }
    }

    /// [`run_context_table`] with no recorded table, over the counting
    /// opener.
    fn run_context<'a>(
        opener: &'a CountingOpener,
        reporter: &'a mut Recorder,
    ) -> crate::pipeline::steps::RunContext<'a> {
        run_context_table(opener, reporter, None)
    }

    /// The one shared asset seeder lives in [`super::end_to_end`]:
    /// every UEFI test below calls it there, so parallel threads stage
    /// through unique temp names plus an atomic `rename` and never race
    /// on the final asset bytes.
    use super::end_to_end::seed_exe_assets;

    fn image_ref(path: &str, kind: rufus_proto::ImageKind) -> rufus_proto::ImageRef {
        rufus_proto::ImageRef {
            path: path.to_string(),
            size_bytes: 0,
            sha256: String::new(),
            kind,
        }
    }

    #[test]
    fn run_refuses_a_non_fat32_filesystem_before_opening() {
        // exFAT with a bogus image path: the filesystem refusal lands
        // first, so `partition()` is never called.
        let partitions = Rc::new(Cell::new(0usize));
        let opener = CountingOpener {
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context(&opener, &mut reporter);
        let error = run(
            &mut ctx,
            &BootloaderMode::Syslinux,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Exfat,
            None,
        )
        .expect_err("a non-fat32 plan refuses");
        let text = error.to_string();
        assert!(text.contains("exfat"), "names the filesystem: {text}");
        assert!(text.contains("FAT32"), "names the wired one: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(partitions.get(), 0, "the partition never opens");
    }

    #[test]
    fn run_none_reports_and_writes_nothing() {
        let partitions = Rc::new(Cell::new(0usize));
        let opener = CountingOpener {
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context(&opener, &mut reporter);
        run(
            &mut ctx,
            &BootloaderMode::None,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Fat32,
            None,
        )
        .expect("none always runs");
        assert_eq!(partitions.get(), 0, "the partition never opens");
        assert_eq!(reporter.events.len(), 1, "one info event at most");
    }

    #[test]
    fn run_wired_modes_reach_the_image() {
        // `Freedos` and `Kolibri` are wired: with a bogus image path
        // the run gets past the shared gate to the image open (an I/O
        // refusal naming the path), never `NotImplemented` — and the
        // partition still never opens.
        for mode in [BootloaderMode::Freedos, BootloaderMode::Kolibri] {
            let partitions = Rc::new(Cell::new(0usize));
            let opener = CountingOpener {
                partitions: Rc::clone(&partitions),
            };
            let mut reporter = Recorder::default();
            let mut ctx = run_context(&opener, &mut reporter);
            let error = run(
                &mut ctx,
                &mode,
                &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
                &rufus_proto::Filesystem::Fat32,
                None,
            )
            .expect_err("a missing image refuses");
            assert!(
                !matches!(error, CoreError::NotImplemented { .. }),
                "a wired mode is never NotImplemented: {error:?}"
            );
            assert_eq!(partitions.get(), 0, "the partition never opens");
        }
    }

    #[test]
    fn run_uefi_ntfs_writes_the_image_and_reports_both_lines() {
        // Through the real `run` path with a bogus image path (proving
        // no image tree opens) on an NTFS plan: the image lands at the
        // 1 MiB ESP offset, the head and the data window keep the
        // prefill, the data partition never opens, the disk flushes
        // once, and both log lines report.
        seed_exe_assets();
        let (target, before) = prefilled_uefi_disk();
        let partitions = Rc::new(Cell::new(0usize));
        let opener = DiskOpener {
            target: target.clone(),
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Mbr));
        run(
            &mut ctx,
            &BootloaderMode::UefiNtfs,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Ntfs,
            None,
        )
        .expect("the run lands");
        assert_eq!(partitions.get(), 0, "the data partition never opens");
        let texts: Vec<&str> = reporter
            .events
            .iter()
            .filter_map(|event| match event {
                crate::pipeline::event::Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"Writing UEFI:NTFS data..."),
            "the reference line reports: {texts:?}"
        );
        assert!(
            texts.contains(&"wrote UEFI:NTFS image (1048576 bytes at offset 1048576)"),
            "the completion line names bytes and offset: {texts:?}"
        );
        let after = target.bytes().expect("the disk reads back");
        let image = uefi_image_bytes();
        assert_eq!(
            &after[1024 * 1024..2 * 1024 * 1024],
            &image[..],
            "the image lands whole at the ESP offset"
        );
        assert_eq!(
            &after[..1024 * 1024],
            &before[..1024 * 1024],
            "the head keeps the prefill"
        );
        let (data_offset, data_len) = crate::part::plan::data_window(
            LayoutKind::UefiNtfs,
            TableKind::Mbr,
            512,
            UEFI_DISK_BYTES,
        )
        .expect("the data window plans");
        assert_eq!(
            &after[data_offset as usize..(data_offset + data_len) as usize],
            &before[data_offset as usize..(data_offset + data_len) as usize],
            "the data window's bytes are untouched"
        );
        assert_eq!(target.flushes(), 1, "the run flushes the disk once");
    }

    #[test]
    fn run_uefi_ntfs_refuses_fat32_before_any_write() {
        // A FAT32 plan refuses naming the filesystem, with the device
        // byte-identical and the partition never opened.
        seed_exe_assets();
        let (target, before) = prefilled_uefi_disk();
        let partitions = Rc::new(Cell::new(0usize));
        let opener = DiskOpener {
            target: target.clone(),
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Mbr));
        let error = run(
            &mut ctx,
            &BootloaderMode::UefiNtfs,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Fat32,
            None,
        )
        .expect_err("a fat32 plan refuses");
        let text = error.to_string();
        assert!(text.contains("fat32"), "names the filesystem: {text}");
        assert!(text.contains("NTFS or exFAT"), "names the rule: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(partitions.get(), 0, "the data partition never opens");
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            before,
            "no byte moved in 67108864 bytes of disk"
        );
    }

    #[test]
    fn run_uefi_ntfs_without_a_table_refuses() {
        // No recorded table, no window: the run refuses before any
        // write, with the device byte-identical.
        seed_exe_assets();
        let (target, before) = prefilled_uefi_disk();
        let partitions = Rc::new(Cell::new(0usize));
        let opener = DiskOpener {
            target: target.clone(),
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context_table(&opener, &mut reporter, None);
        let error = run(
            &mut ctx,
            &BootloaderMode::UefiNtfs,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Ntfs,
            None,
        )
        .expect_err("a table-less run refuses");
        let text = error.to_string();
        assert!(
            text.contains("recorded partition table"),
            "names the missing bound: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(partitions.get(), 0, "the data partition never opens");
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            before,
            "no byte moved in 67108864 bytes of disk"
        );
    }

    /// A GRUB2 payload tree: `/boot/grub/i386-pc/boot.img` (600
    /// patterned bytes) and `core.img` (3000 patterned bytes), plus an
    /// EFI payload when asked.
    fn grub_tree(with_efi: bool) -> (MemSource, Vec<u8>, Vec<u8>) {
        let boot: Vec<u8> = (0..600)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let core: Vec<u8> = (0..3000)
            .map(|index| ((index * 13 + 5) % 251) as u8)
            .collect();
        let mut root = vec![dir_entry(b"boot")];
        if with_efi {
            root.push(dir_entry(b"efi"));
        }
        let mut source = MemSource::new()
            .with_dir(&[], root)
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![
                    file_entry(b"boot.img", &boot),
                    file_entry(b"core.img", &core),
                ],
            )
            .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], &boot)
            .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], &core);
        if with_efi {
            source = source
                .with_dir(&[b"efi"], vec![dir_entry(b"boot")])
                .with_dir(
                    &[b"efi", b"boot"],
                    vec![file_entry(b"grubx64.efi", b"efi-bytes")],
                )
                .with_file(&[b"efi", b"boot", b"grubx64.efi"], b"efi-bytes");
        }
        (source, boot, core)
    }

    /// A whole-disk double behind [`DiskView`], prefilled with a
    /// recognisable pattern. Two MiB: big enough for the planner to
    /// lay a first partition past the post-MBR gap the BIOS arms
    /// bound through.
    fn prefilled_disk() -> (VecTarget, Vec<u8>) {
        const SIZE: usize = 2 * 1024 * 1024;
        let target = VecTarget::new(SIZE as u64, 512).expect("the disk allocates");
        let before: Vec<u8> = (0..SIZE)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        target.write_all_at(0, &before).expect("the prefill lands");
        (target, before)
    }

    #[test]
    fn grub2_installs_bios_and_places_uefi() {
        let (source, boot, core) = grub_tree(true);
        let (backing, mut fat) = formatted();
        let (mut target, before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub2,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        let Installed::Grub2 {
            dir,
            core_bytes,
            uefi_placed,
            messages,
        } = installed
        else {
            panic!("a grub2 install reports the Grub2 variant");
        };
        assert_eq!(dir, "/boot/grub/i386-pc", "the payload directory");
        assert_eq!(core_bytes, 3000, "the core keeps its 3000 bytes");
        assert_eq!(
            uefi_placed.as_deref(),
            Some("/EFI/boot/bootx64.efi"),
            "the uefi image lands"
        );
        assert_eq!(
            messages[0], "found grub2 bios payloads at '/boot/grub/i386-pc'",
            "discovery first"
        );
        // MBR windows straight from the disk bytes.
        let mut sector = [0u8; 512];
        disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
        assert_eq!(&sector[..0x5c], &boot[..0x5c], "record head verbatim");
        assert_eq!(
            &sector[0x5c..0x64],
            &1u64.to_le_bytes(),
            "the kernel field names sector 1"
        );
        assert_eq!(&sector[0x64..432], &boot[0x64..432], "record tail verbatim");
        assert_eq!(
            &sector[432..510],
            &before[432..510],
            "signature window kept"
        );
        assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        let mut core_back = vec![0u8; 3000];
        disk.read_exact_at(512, &mut core_back)
            .expect("the core reads");
        assert_eq!(core_back, core, "the core lands whole at sector 1");
        // UEFI file on the partition, byte-identical.
        let back = fat
            .read_file("/EFI/boot/bootx64.efi")
            .expect("the efi image reads");
        assert_eq!(back, b"efi-bytes", "the efi payload lands whole");
        // The composed partition is fsck clean.
        fat.flush().expect("the partition flushes");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("grub2.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the grub2 install ({})",
            output.status
        );
    }

    #[test]
    fn grub2_core_overrunning_the_gap_refuses() {
        // A 2 MiB device whose first partition the planner starts at
        // `gap_end`: a core ending one byte inside that partition
        // refuses naming both numbers, with the device byte-identical.
        // The boundary comes from the same helper the installer uses,
        // so the test cannot drift from it.
        const SIZE: u64 = 2 * 1024 * 1024;
        let (gap_end, _) = crate::part::plan::single_data_window(TableKind::Mbr, 512, SIZE)
            .expect("the gap plans");
        let core_len = (gap_end - 512 + 1) as usize;
        let boot: Vec<u8> = (0..600)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let core: Vec<u8> = (0..core_len)
            .map(|index| ((index * 13 + 5) % 251) as u8)
            .collect();
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![
                    file_entry(b"boot.img", &boot),
                    file_entry(b"core.img", &core),
                ],
            )
            .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], &boot)
            .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], &core);
        let (_backing, mut fat) = formatted();
        let mut target = VecTarget::new(SIZE, 512).expect("the disk allocates");
        let before = {
            let mut snapshot = vec![0u8; SIZE as usize];
            target
                .read_at(0, &mut snapshot)
                .expect("the disk reads back");
            snapshot
        };
        let mut disk = DiskView::new(&mut target);
        let error = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub2,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect_err("an overrunning core refuses");
        let text = error.to_string();
        assert!(
            text.contains(&core_len.to_string()),
            "names the core length: {text}"
        );
        assert!(
            text.contains(&gap_end.to_string()),
            "names the gap end: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let mut after = vec![0u8; SIZE as usize];
        target.read_at(0, &mut after).expect("the disk reads back");
        assert_eq!(after, before, "no byte moved in 2097152 bytes of disk");
    }

    #[test]
    fn grub2_without_a_recorded_table_refuses() {
        let (source, _boot, _core) = grub_tree(false);
        let (_backing, mut fat) = formatted();
        let (mut target, _before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let error = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub2,
            None,
            None,
            &|| false,
            &asset_loader,
        )
        .expect_err("a table-less grub2 refuses");
        let text = error.to_string();
        assert!(
            text.contains("recorded partition table"),
            "names the missing bound: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    #[test]
    fn grub2_without_payloads_refuses_before_any_device_write() {
        let source = syslinux_407_tree();
        let (_backing, mut fat) = formatted();
        let (mut target, before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let error = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub2,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect_err("a payload-less grub2 refuses");
        let text = error.to_string();
        assert!(text.contains("/boot/grub/i386-pc"), "names the dir: {text}");
        assert!(text.contains("boot.img"), "names the record: {text}");
        assert!(text.contains("core.img"), "names the core: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let mut after = vec![0u8; before.len()];
        target.read_at(0, &mut after).expect("the disk reads back");
        assert_eq!(after, before, "no byte moved in 2097152 bytes of disk");
    }

    #[test]
    fn grub4dos_keeps_an_existing_grldr() {
        // The volume already carries `/grldr` (the copy step placed
        // the image's own): the embedded bytes stay out, the file is
        // untouched, but MBR+SBR still land.
        let (source, _boot, _core) = grub_tree(false);
        let (_backing, mut fat) = formatted();
        fat.create_file("/grldr", 11).expect("the copy lands first");
        fat.write_at("/grldr", 0, b"image-grldr")
            .expect("the copy writes");
        fat.flush().expect("the copy flushes");
        let (mut target, _before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub4dos,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        let Installed::Grub4dos {
            sbr_bytes,
            messages,
        } = installed
        else {
            panic!("a grub4dos install reports the Grub4dos variant");
        };
        assert!(
            messages.iter().any(|line| line.contains("keeping it")),
            "the skip is reported: {messages:?}"
        );
        let back = fat.read_file("/grldr").expect("the loader reads");
        assert_eq!(back, b"image-grldr", "the volume bytes are unchanged");
        let mbr = asset_loader(Resource::Grub4DosMbr)
            .expect("the mbr loads")
            .bytes()
            .to_vec();
        assert_eq!(
            sbr_bytes as usize,
            mbr.len() - 512,
            "the sbr spans the rest"
        );
        let mut sector = [0u8; 512];
        disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
        assert_eq!(&sector[..423], &mbr[..423], "the mbr window lands");
        assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
    }

    #[test]
    fn grub4dos_refuses_without_a_root_grldr() {
        // No root `/grldr` (neither the image tree nor a caller placed
        // one): the arm refuses before any write. It names the file
        // Rufus downloads, leaves the root empty and the disk byte for
        // byte unchanged, so no boot code lands without its loader.
        let (source, _boot, _core) = grub_tree(false);
        let (_backing, mut fat) = formatted();
        let (mut target, before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let error = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub4dos,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect_err("a grub4dos install without a loader refuses");
        let text = error.to_string();
        assert!(text.contains("real grldr"), "names the need: {text}");
        assert!(
            text.contains("grub4dos-0.4.6a/grldr"),
            "names the download: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(listed.is_empty(), "no loader lands at the root: {listed:?}");
        let mut after = vec![0u8; before.len()];
        disk.read_exact_at(0, &mut after)
            .expect("the disk reads back");
        assert_eq!(
            after, before,
            "no byte moves: the arm refuses before writing"
        );
    }

    #[test]
    fn uefi_skipped_when_already_present() {
        // Source and volume both carry the file: placement skips, the
        // partition stays byte-identical, the BIOS record still lands.
        let (source, boot, _core) = grub_tree(true);
        let (backing, mut fat) = formatted();
        fat.mkdir("/EFI").expect("the copy makes /EFI");
        fat.mkdir("/EFI/boot").expect("the copy makes boot");
        fat.create_file("/EFI/boot/bootx64.efi", 9)
            .expect("the copy lands first");
        fat.write_at("/EFI/boot/bootx64.efi", 0, b"copy-efi!")
            .expect("the copy writes");
        fat.flush().expect("the copy flushes");
        let before = backing.bytes.borrow().clone();
        let (mut target, _disk_before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub2,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        let Installed::Grub2 { uefi_placed, .. } = &installed else {
            panic!("a grub2 install reports the Grub2 variant");
        };
        assert_eq!(
            uefi_placed.as_deref(),
            None,
            "placement skips the present file"
        );
        assert!(
            installed
                .messages()
                .iter()
                .any(|line| line.contains("keeping it")),
            "the skip is reported"
        );
        let back = fat
            .read_file("/EFI/boot/bootx64.efi")
            .expect("the efi file reads");
        assert_eq!(back, b"copy-efi!", "the volume bytes are unchanged");
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no partition byte moved"
        );
        let mut sector = [0u8; 512];
        disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
        assert_eq!(
            &sector[..0x5c],
            &boot[..0x5c],
            "the bios record still lands"
        );
        assert_eq!(
            &sector[0x5c..0x64],
            &1u64.to_le_bytes(),
            "the kernel field still patches"
        );
    }

    #[test]
    fn auto_prefers_syslinux_when_both_are_present() {
        // Isolinux tree plus GRUB tree plus root grldr: Syslinux wins
        // the chain with no probe lines ahead of its own messages.
        let mut source = syslinux_604_tree();
        let (grub, _boot, _core) = grub_tree(false);
        for (dir, entries) in grub.dirs {
            source.dirs.entry(dir).or_default().extend(entries);
        }
        for (path, bytes) in grub.files {
            source.files.insert(path, bytes);
        }
        source
            .dirs
            .entry(Vec::new())
            .or_default()
            .push(file_entry(b"grldr", b"old"));
        source
            .files
            .insert(vec![b"grldr".to_vec()], b"old".to_vec());
        let (_backing, mut fat) = formatted();
        let (mut target, _before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Auto,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect("auto runs");
        let Installed::Syslinux { messages, .. } = installed else {
            panic!("syslinux wins the auto chain");
        };
        assert_eq!(
            messages[0], "auto: probing syslinux",
            "the winning probe is logged"
        );
        assert_eq!(
            messages[1], "  Will use '/isolinux' for Syslinux",
            "then the branch reports"
        );
    }

    #[test]
    fn auto_falls_through_to_grub2_over_grldr() {
        // GRUB tree plus root grldr, no isolinux: the syslinux probe
        // misses (logged), GRUB2 wins.
        let (mut source, _boot, _core) = grub_tree(false);
        source
            .dirs
            .entry(Vec::new())
            .or_default()
            .push(file_entry(b"grldr", b"old"));
        source
            .files
            .insert(vec![b"grldr".to_vec()], b"old".to_vec());
        let (_backing, mut fat) = formatted();
        let (mut target, _before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Auto,
            Some(TableKind::Mbr),
            None,
            &|| false,
            &asset_loader,
        )
        .expect("auto runs");
        let Installed::Grub2 { messages, .. } = installed else {
            panic!("grub2 wins over a bare grldr");
        };
        assert_eq!(
            messages[0], "auto: probing syslinux",
            "the first probe is logged"
        );
        assert_eq!(
            messages[1], "auto: probing grub2",
            "the second probe is logged"
        );
        assert_eq!(
            messages[2], "found grub2 bios payloads at '/boot/grub/i386-pc'",
            "the winner identifies itself"
        );
    }

    #[test]
    fn existing_syslinux_cfg_refuses_without_boot_code() {
        // The wrapper path already exists: companions land first, then
        // `write_config` refuses — leaving the formatter's boot sector
        // byte-identical and no `/ldlinux.sys` behind.
        let source = syslinux_604_tree();
        let (backing, mut fat) = formatted();
        let text = syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
        fat.create_file("/syslinux.cfg", text.len() as u64)
            .expect("the copy lands first");
        fat.write_at("/syslinux.cfg", 0, &text)
            .expect("the copy writes");
        let before_sector = backing.boot_sector();
        let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
            .expect_err("an existing wrapper refuses");
        let text = error.to_string();
        assert!(text.contains("syslinux.cfg"), "names the file: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            backing.boot_sector(),
            before_sector,
            "the boot sector is the formatter's still"
        );
        let listed = fat.list_dir("/isolinux").expect("the payload dir lists");
        assert!(
            listed.iter().all(|entry| entry.short_name != "LDLINUX.SYS"),
            "no stage file was linked"
        );
        let back = fat
            .read_file("/isolinux/menu.c32")
            .expect("the companion reads back");
        assert_eq!(back, b"menu.c32", "companions landed before the refusal");
    }

    #[test]
    fn installed_image_is_fsck_clean() {
        let (backing, mut fat) = formatted();
        let source = syslinux_604_tree();
        tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
        fat.flush().expect("the install flushes");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("bootloader.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
}

#[cfg(test)]
pub(crate) mod end_to_end {
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt as _;

    use crate::boot::Resource;
    use crate::boot::load_from;
    use crate::boot::syslinux;
    use crate::error::CoreError;
    use crate::error::Result as TestResult;
    use crate::fs::Volume;
    use crate::fs::fat32::Fat32;
    use crate::iso::FLAG_DIRECTORY;
    use crate::iso::SECTOR_BYTES;
    use crate::part::TableKind;
    use crate::part::plan::LayoutKind;
    use crate::part::plan::data_window;
    use crate::part::plan::esp_window;
    use crate::part::plan::single_data_window;
    use crate::pipeline::target::Target;
    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::PLAN_VERSION;
    use rufus_proto::Plan;

    /// 128 MiB stick image for the run.
    const DISK_BYTES: u64 = 128 * 1024 * 1024;

    /// Stand-in GRUB4DOS `grldr` bytes for the fixtures. No real loader
    /// is bundled (resource 451 is GRUB2's `core.img`), so the tests
    /// carry a patterned blob and check only the file plumbing.
    fn stand_in_grldr() -> Vec<u8> {
        (0..4096)
            .map(|index| ((index * 3 + 1) % 251) as u8)
            .collect()
    }

    /// Build the fixture ISO: primary + boot + terminator descriptors,
    /// a root holding `ISOLINUX/`, and six payload files under it, from
    /// the shared `copy::fixture` sector builders.
    fn syslinux_iso() -> Vec<u8> {
        syslinux_iso_with(None)
    }

    /// The Syslinux 6.04 fixture, optionally carrying a root `grldr`
    /// file (the image's own GRUB4DOS loader, which the GRUB4DOS arm
    /// needs on the volume). The loader starts at sector 32, past the
    /// 32-sector base image, and the descriptor's volume size follows
    /// the real image length.
    fn syslinux_iso_with(grldr: Option<&[u8]>) -> Vec<u8> {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const DIR: u32 = 21;
        const BIN: u32 = 22;
        const CFG: u32 = 23;
        const C32: u32 = 24;
        const MENU: u32 = 25;
        const VESA: u32 = 26;
        const LIB: u32 = 27;
        const LOADER: u32 = 32;
        let loader_sectors = grldr.map_or(0, |bytes| bytes.len().div_ceil(SECTOR_BYTES));
        let total_sectors = 32 + loader_sectors;
        let banner = b"ISOLINUX 6.04 20140611 test-image".to_vec();
        // Lowercase identifiers throughout: like the directory
        // above, the reader resolves file opens exactly, so only
        // lowercase names round-trip through locate and read.
        let files: Vec<(&[u8], u32, Vec<u8>)> = vec![
            (b"isolinux.bin;1", BIN, banner),
            (b"isolinux.cfg;1", CFG, b"DEFAULT linux\n".to_vec()),
            (b"ldlinux.c32;1", C32, b"ldlinux-c32-stub".to_vec()),
            (b"menu.c32;1", MENU, b"menu-stub".to_vec()),
            (b"vesamenu.c32;1", VESA, b"vesamenu-stub".to_vec()),
            (b"libutil.c32;1", LIB, b"libutil-stub".to_vec()),
        ];
        let mut image = vec![0u8; total_sectors * SECTOR_BYTES];
        let mut put = |sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        let mut primary = primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32);
        let total = total_sectors as u32;
        primary[80..84].copy_from_slice(&total.to_le_bytes());
        primary[84..88].copy_from_slice(&total.to_be_bytes());
        put(16, &primary);
        put(17, &boot_sector());
        put(18, &terminator_sector());
        let mut root = vec![
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            // Lowercase on purpose: the engine resolves payload
            // directory components exactly (only file names fold
            // case), so an upper-case directory is never located.
            encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"isolinux"),
        ];
        if let Some(bytes) = grldr {
            root.push(encode_record(LOADER, bytes.len() as u32, 0, b"grldr;1"));
            put(LOADER, bytes);
        }
        let mut dir = vec![
            encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        ];
        for (identifier, sector, bytes) in &files {
            dir.push(encode_record(*sector, bytes.len() as u32, 0, identifier));
        }
        put(ROOT, &dir_sector(&root));
        put(DIR, &dir_sector(&dir));
        for (_, sector, bytes) in &files {
            put(*sector, bytes);
        }
        image
    }

    /// Build the GRUB2 fixture ISO plus its payload bytes: primary +
    /// boot + terminator descriptors, `boot/grub/i386-pc/` holding
    /// `boot.img` (600 patterned bytes) and `core.img` (3000 patterned
    /// bytes). Lowercase identifiers with `;1` versions, like
    /// [`syslinux_iso`]: the reader resolves directory components
    /// exactly and strips the file versions.
    fn grub2_iso() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const BOOT: u32 = 21;
        const GRUB: u32 = 22;
        const PC: u32 = 23;
        const BOOTIMG: u32 = 24;
        const COREIMG: u32 = 25;
        let boot: Vec<u8> = (0..600)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let core: Vec<u8> = (0..3000)
            .map(|index| ((index * 13 + 5) % 251) as u8)
            .collect();
        let mut image = vec![0u8; 32 * SECTOR_BYTES];
        let mut put = |sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
        put(17, &boot_sector());
        put(18, &terminator_sector());
        let root = vec![
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"boot"),
        ];
        let boot_dir = vec![
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"grub"),
        ];
        let grub_dir = vec![
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"i386-pc"),
        ];
        let pc_dir = vec![
            encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(BOOTIMG, boot.len() as u32, 0, b"boot.img;1"),
            encode_record(COREIMG, core.len() as u32, 0, b"core.img;1"),
        ];
        put(ROOT, &dir_sector(&root));
        put(BOOT, &dir_sector(&boot_dir));
        put(GRUB, &dir_sector(&grub_dir));
        put(PC, &dir_sector(&pc_dir));
        put(BOOTIMG, &boot);
        put(COREIMG, &core);
        (image, boot, core)
    }

    /// Build the KolibriOS fixture ISO plus its loader bytes: the
    /// descriptors plus a 1 KiB loader file under the exact reference
    /// directories (`HD_Load`, then `USB_Boot`). The directory
    /// components keep their case: the locator resolves them exactly,
    /// unlike file names.
    fn kolibri_iso() -> (Vec<u8>, Vec<u8>) {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const HD: u32 = 21;
        const USB: u32 = 22;
        const LOADER: u32 = 23;
        let loader: Vec<u8> = (0..1024)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let mut image = vec![0u8; 32 * SECTOR_BYTES];
        let mut put = |sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
        put(17, &boot_sector());
        put(18, &terminator_sector());
        let root = vec![
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"HD_Load"),
        ];
        let hd_dir = vec![
            encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(USB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"USB_Boot"),
        ];
        let usb_dir = vec![
            encode_record(USB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(LOADER, loader.len() as u32, 0, b"MTLD_F32;1"),
        ];
        put(ROOT, &dir_sector(&root));
        put(HD, &dir_sector(&hd_dir));
        put(USB, &dir_sector(&usb_dir));
        put(LOADER, &loader);
        (image, loader)
    }

    /// A whole-disk [`Target`] over one open file with a declared
    /// extent: the tempdir-backed disk image the run drives. Opens a
    /// fresh handle per `device()` call (like the file-seam opener),
    /// so every handle sees the same bytes. Sparse-backed: the file is
    /// sized with `set_len`, and wipe/Mkfs pay only their real writes.
    #[derive(Debug)]
    struct FileTarget {
        file: std::fs::File,
        path: std::path::PathBuf,
        len: u64,
    }

    impl FileTarget {
        fn open(path: &std::path::Path, len: u64) -> TestResult<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|source| CoreError::io(path, source))?;
            Ok(Self {
                file,
                path: path.to_path_buf(),
                len,
            })
        }
    }

    impl Target for FileTarget {
        fn size(&self) -> u64 {
            self.len
        }

        fn sector_size(&self) -> u32 {
            512
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
            if offset
                .checked_add(buf.len() as u64)
                .is_some_and(|end| end > self.len)
            {
                return Err(CoreError::invalid(format!(
                    "test read of {} bytes at offset {offset} runs past the {} byte disk",
                    buf.len(),
                    self.len
                )));
            }
            self.file
                .read_exact_at(buf, offset)
                .map_err(|source| CoreError::io(&self.path, source))
        }

        fn write_all_at(&self, offset: u64, buf: &[u8]) -> TestResult<()> {
            self.write_all_at_cancellable(offset, buf, usize::MAX, &|| false)?;
            Ok(())
        }

        fn write_all_at_cancellable(
            &self,
            offset: u64,
            buf: &[u8],
            chunk: usize,
            cancelled: &dyn Fn() -> bool,
        ) -> TestResult<u64> {
            if chunk == 0 {
                return Err(CoreError::invalid("write chunk size must be non-zero"));
            }
            if offset
                .checked_add(buf.len() as u64)
                .is_some_and(|end| end > self.len)
            {
                return Err(CoreError::invalid(format!(
                    "test write of {} bytes at offset {offset} runs past the {} byte disk",
                    buf.len(),
                    self.len
                )));
            }
            let mut done = 0usize;
            while done < buf.len() {
                if cancelled() {
                    return Ok(done as u64);
                }
                let piece = (buf.len() - done).min(chunk);
                self.file
                    .write_all_at(&buf[done..done + piece], offset + done as u64)
                    .map_err(|source| CoreError::io(&self.path, source))?;
                done += piece;
            }
            Ok(done as u64)
        }

        fn flush(&self) -> TestResult<()> {
            self.file
                .sync_all()
                .map_err(|source| CoreError::io(&self.path, source))
        }
    }

    /// A [`Volume`] window over the disk file at `[base, base + len)`:
    /// the data partition the native formatters write, planned with the
    /// same [`single_data_window`] call the pipeline stamps with, so the
    /// formatted window is the stamped partition by construction.
    #[derive(Debug)]
    struct PartFile {
        file: std::fs::File,
        base: u64,
        len: u64,
    }

    impl PartFile {
        fn open(path: &std::path::Path, base: u64, len: u64) -> TestResult<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|source| CoreError::io(path, source))?;
            Ok(Self { file, base, len })
        }
    }

    impl Volume for PartFile {
        fn total_bytes(&self) -> u64 {
            self.len
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("test partition read overflows".to_string()))?;
            if end > self.len {
                return Err(CoreError::invalid(format!(
                    "test partition read of {} bytes at offset {offset} runs past the {} byte window at base {}",
                    buf.len(),
                    self.len,
                    self.base
                )));
            }
            self.file
                .read_exact_at(buf, self.base + offset)
                .map_err(|source| CoreError::io("<partition window>", source))
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| CoreError::invalid("test partition write overflows".to_string()))?;
            if end > self.len {
                return Err(CoreError::invalid(format!(
                    "test partition write of {} bytes at offset {offset} runs past the {} byte window at base {}",
                    buf.len(),
                    self.len,
                    self.base
                )));
            }
            self.file
                .write_all_at(buf, self.base + offset)
                .map_err(|source| CoreError::io("<partition window>", source))
        }

        fn flush(&mut self) -> TestResult<()> {
            self.file
                .sync_all()
                .map_err(|source| CoreError::io("<partition window>", source))
        }

        fn sector_size(&self) -> u32 {
            512
        }
    }

    /// The mount stand-in: a real temp directory standing in for the
    /// kernel mount. Before the copy, `partition.img` materialises the
    /// partition window bytes; on release, the temp tree's contents
    /// merge into the partition window through the real `Fat32` API
    /// and the volume flushes. That merge is what proves the copy's
    /// bytes round-trip into the partition window: a kernel mount
    /// would expose the live filesystem instead, which no unprivileged
    /// test can do, so the shim stands in for `mount(2)` without
    /// calling it.
    struct MountShim {
        dir: tempfile::TempDir,
        path: std::path::PathBuf,
        base: u64,
        len: u64,
    }

    impl MountShim {
        fn mount(path: &std::path::Path, base: u64, len: u64) -> TestResult<Self> {
            let dir = tempfile::tempdir().expect("the mount dir allocates");
            let file = OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|source| CoreError::io(path, source))?;
            let mut window = vec![0u8; usize::try_from(len).expect("the window fits usize")];
            file.read_exact_at(&mut window, base)
                .map_err(|source| CoreError::io(path, source))?;
            std::fs::write(dir.path().join("partition.img"), &window).expect("the window stages");
            Ok(Self {
                dir,
                path: path.to_path_buf(),
                base,
                len,
            })
        }
    }

    impl crate::pipeline::opener::MountedPartition for MountShim {
        fn path(&self) -> &std::path::Path {
            self.dir.path()
        }

        fn free_bytes(&self) -> TestResult<u64> {
            // Fixture scale only: plenty for a 60 KiB ISO tree. A
            // kernel mount would report statvfs here.
            Ok(1 << 40)
        }

        fn release(&mut self) -> TestResult<()> {
            let staged = std::fs::read(self.dir.path().join("partition.img"))
                .expect("the staged window reads back");
            let staged_len = u64::try_from(staged.len()).expect("the stage fits u64");
            if staged_len != self.len {
                return Err(CoreError::invalid(format!(
                    "test mount staged {staged_len} bytes for a {} byte window: refusing",
                    self.len
                )));
            }
            // Merge what the copy walk landed in the temp tree into
            // the live window, then flush: this is the assertion
            // surface that proves the copy's bytes reached the image.
            // (The staged window above only guards the size now — the
            // copy never touched the window, so there is nothing to
            // restore from it.)
            let mut fat = Fat32::open(Box::new(
                PartFile::open(&self.path, self.base, self.len).expect("the merge window opens"),
            ))
            .expect("the merge volume opens");
            merge_dir(&mut fat, self.dir.path(), "")?;
            fat.flush()?;
            Ok(())
        }
    }

    /// Copy one temp-tree level into the FAT32 volume: directories are
    /// created (when the listing misses them) before descending, files
    /// are created and written whole, and only the shim's own
    /// `partition.img` is skipped. Everything the walk produced lands —
    /// including the companions, which the bootloader step then keeps
    /// by byte comparison instead of refusing. Anything that is
    /// neither a file nor a directory refuses — the fixture tree holds
    /// no symlinks, and silently dropping one would hide a lost entry.
    fn merge_dir(fat: &mut Fat32, fs_dir: &std::path::Path, fat_dir: &str) -> TestResult<()> {
        let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(fs_dir)
            .map_err(|source| CoreError::io(fs_dir, source))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|source| CoreError::io(fs_dir, source))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in &entries {
            let name = entry.file_name();
            let name_str = name.to_str().ok_or_else(|| {
                CoreError::invalid(format!(
                    "test mount entry '{}' is not UTF-8: refusing",
                    name.to_string_lossy()
                ))
            })?;
            if name_str == "partition.img" {
                continue;
            }
            let dest = if fat_dir.is_empty() {
                format!("/{name_str}")
            } else {
                format!("{fat_dir}/{name_str}")
            };
            let file_type = entry
                .file_type()
                .map_err(|source| CoreError::io(entry.path(), source))?;
            if file_type.is_dir() {
                match fat.list_dir(&dest) {
                    Ok(_) => {}
                    Err(_) => {
                        fat.mkdir(&dest)?;
                    }
                }
                merge_dir(fat, &entry.path(), &dest)?;
            } else if file_type.is_file() {
                let bytes = std::fs::read(entry.path())
                    .map_err(|source| CoreError::io(entry.path(), source))?;
                fat.create_file(&dest, bytes.len() as u64)?;
                fat.write_at(&dest, 0, &bytes)?;
            } else {
                return Err(CoreError::invalid(format!(
                    "test mount entry '{dest}' is neither a file nor a directory: refusing"
                )));
            }
        }
        Ok(())
    }

    /// Fixture opener over one disk image file: the device is a fresh
    /// [`FileTarget`] per call, the partition a [`PartFile`] window at
    /// the Mkpart-planned offset, the mount the [`MountShim`] stand-in.
    #[derive(Debug, Clone)]
    struct EndToEndOpener {
        path: std::path::PathBuf,
        disk_len: u64,
        base: u64,
        len: u64,
    }

    impl crate::pipeline::opener::Opener for EndToEndOpener {
        fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
            Ok(Box::new(FileTarget::open(&self.path, self.disk_len)?))
        }

        fn partition(&self) -> TestResult<Box<dyn Volume>> {
            Ok(Box::new(PartFile::open(&self.path, self.base, self.len)?))
        }

        fn partition_path(&self) -> TestResult<std::path::PathBuf> {
            Err(CoreError::invalid(
                "test opener has no partition node".to_string(),
            ))
        }

        fn mount_partition(
            &self,
            _filesystem: &Filesystem,
        ) -> TestResult<Box<dyn crate::pipeline::opener::MountedPartition>> {
            Ok(Box::new(MountShim::mount(&self.path, self.base, self.len)?))
        }
    }

    /// A recording reporter: every event in run order.
    #[derive(Debug, Default)]
    struct Recorder {
        events: Vec<crate::pipeline::event::Event>,
    }

    impl crate::pipeline::event::Reporter for Recorder {
        fn event(&mut self, event: crate::pipeline::event::Event) {
            self.events.push(event);
        }
    }

    /// `assets/resources/` next to the workspace root, for the pinned
    /// core size below.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// Seed `<exe_dir>/../share/rufus-linux/assets` from the manifest
    /// tree so the production `load()` path resolves with no
    /// environment variables. This is the resolver's own third
    /// candidate (`Env::assets_dir` order); `load()` verifies exact
    /// size and SHA-256 on every load, so the seed cannot plant wrong
    /// bytes silently. Writes only under `target/` (gitignored),
    /// idempotent across reruns. The single seeder every lib test
    /// shares (unit and end-to-end alike): each payload stages to a
    /// unique temp name in the same directory and is `rename`d into
    /// place, and `rename` onto one filesystem is atomic — parallel
    /// test threads never observe a truncated asset, which a direct
    /// `write` of the final name allowed.
    pub(crate) fn seed_exe_assets() {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;
        static SEED_TICK: AtomicU64 = AtomicU64::new(0);
        let exe = std::env::current_exe().expect("the test exe resolves");
        let dir = exe
            .parent()
            .expect("the exe has a dir")
            .join("../share/rufus-linux/assets");
        std::fs::create_dir_all(&dir).expect("the asset dir creates");
        let mut names: Vec<String> = vec![
            // The Syslinux arm loads 400/401 for a 4.07 image and
            // 402/403 for a 6.04 one, chosen from the image banner.
            "RCDATA_400.bin".to_string(),
            "RCDATA_401.bin".to_string(),
            "RCDATA_402.bin".to_string(),
            "RCDATA_403.bin".to_string(),
            // The GRUB4DOS arm loads resource 450 through the
            // production path, so its tests seed it here too.
            "RCDATA_450.bin".to_string(),
            "RCDATA_502.bin".to_string(),
        ];
        for id in 300..=326u32 {
            // The FreeDOS arm loads resources 300-326 through the
            // production path, so its tests seed them here too.
            names.push(format!("RCDATA_{id}.bin"));
        }
        for name in &names {
            let bytes = std::fs::read(resources_dir().join(name)).expect("the pinned asset reads");
            let staged = dir.join(format!(
                ".{name}.seed-{}-{}.tmp",
                std::process::id(),
                SEED_TICK.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&staged, &bytes).expect("the asset stages");
            std::fs::rename(&staged, dir.join(name)).expect("the asset lands");
        }
    }

    #[test]
    fn full_plan_installs_syslinux_end_to_end() {
        // Seed the resolver first: the run below exercises the real
        // production `load()` path, which needs the asset directory.
        seed_exe_assets();
        // A real ISO file (the image tree opens from a path) and a
        // 128 MiB sparse disk image file, both under one scratch dir.
        // No `mount(2)`, no privileges: the opener below serves the
        // file, and the mount shim stands in with a temp directory.
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let iso_path = scratch.path().join("syslinux.iso");
        std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
        let disk_path = scratch.path().join("disk.img");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&disk_path)
            .expect("the disk creates")
            .set_len(DISK_BYTES)
            .expect("the disk sizes");
        let (base, len) =
            single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans");
        let opener = EndToEndOpener {
            path: disk_path.clone(),
            disk_len: DISK_BYTES,
            base,
            len,
        };
        let plan = Plan {
            version: PLAN_VERSION,
            created_by: "bootloader-e2e".to_string(),
            device: DeviceRef {
                path: "/dev/test".to_string(),
                block_device: false,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: iso_path.display().to_string(),
                size_bytes: 32 * SECTOR_BYTES as u64,
                sha256: String::new(),
                kind: ImageKind::Iso,
            },
            options: Options {
                scheme: rufus_proto::Scheme::Mbr,
                target: rufus_proto::Target::Dual,
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: None,
            },
            steps: vec![
                rufus_proto::Step::Wipe,
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Mkpart {
                    scheme: rufus_proto::Scheme::Mbr,
                    layout: rufus_proto::Layout::Single,
                },
                rufus_proto::Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: None,
                    cluster_bytes: None,
                    quick: true,
                },
                rufus_proto::Step::Write {
                    mode: rufus_proto::WriteMode::Copy,
                },
                rufus_proto::Step::Bootloader {
                    mode: rufus_proto::BootloaderMode::Auto,
                },
                rufus_proto::Step::Finalize,
            ],
            confirm: String::new(),
        };
        let options = crate::pipeline::RunOptions {
            verify: false,
            badblocks: false,
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        };
        let mut reporter = Recorder::default();
        let report = crate::pipeline::run(&plan, &opener, &options, &mut reporter, &|| false)
            .expect("the full plan runs");
        // All seven steps ran, in order, with no refusal anywhere.
        let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
        assert_eq!(
            names,
            [
                "wipe",
                "mklabel",
                "mkpart",
                "mkfs",
                "write",
                "bootloader",
                "finalize"
            ],
            "every step runs in order"
        );
        for event in &reporter.events {
            if let crate::pipeline::event::Event::Message { text, .. } = event {
                assert!(!text.contains("not implemented"), "no step refused: {text}");
            }
        }
        // The stamped MBR entry points at the same window the opener
        // serves: the table and the test agree on the offset.
        let disk = std::fs::OpenOptions::new()
            .read(true)
            .open(&disk_path)
            .expect("the disk reopens");
        let mut entry = [0u8; 16];
        disk.read_exact_at(&mut entry, 446)
            .expect("the mbr entry reads");
        let start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        assert_eq!(
            u64::from(start) * 512,
            base,
            "the table entry names the data window"
        );
        // The partition window is fsck clean.
        let mut window = vec![0u8; len as usize];
        disk.read_exact_at(&mut window, base)
            .expect("the window reads");
        let picture = scratch.path().join("part.img");
        std::fs::write(&picture, &window).expect("the window dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&picture)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 on the installed partition ({})",
            output.status
        );
        // Files and boot sector through a fresh handle over the same
        // window: the stage, the companions with the ISO's bytes, the
        // wrapper, and the grafted record.
        let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
        let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
        let core = load_from(&resources_dir(), Resource::Syslinux604Core)
            .expect("the core loads")
            .bytes()
            .to_vec();
        let stage = fat.read_file("/ldlinux.sys").expect("the stage reads");
        assert_eq!(
            stage.len(),
            core.len() + 1024,
            "the stage is core plus adv in 69145 bytes"
        );
        for (name, bytes) in [
            ("ldlinux.c32", b"ldlinux-c32-stub".as_slice()),
            ("menu.c32", b"menu-stub".as_slice()),
            ("vesamenu.c32", b"vesamenu-stub".as_slice()),
            ("libutil.c32", b"libutil-stub".as_slice()),
        ] {
            let path = format!("/isolinux/{name}");
            let back = fat.read_file(&path).expect("the companion reads back");
            assert_eq!(back, bytes, "{name} keeps the ISO bytes");
        }
        // The copy's own output, merged into the image on release:
        // this reads back out of the partition image, not the temp
        // dir, so it fails if the merge ever drops the walk's files.
        let back = fat
            .read_file("/isolinux/isolinux.cfg")
            .expect("the copied config reads back");
        assert_eq!(
            back, b"DEFAULT linux\n",
            "the copy output survived the merge into the image"
        );
        let back = fat
            .read_file("/syslinux.cfg")
            .expect("the wrapper reads back");
        assert_eq!(
            back,
            syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
            "the wrapper chains to the located config"
        );
        let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
        let mut sector = [0u8; 512];
        view.read_exact_at(0, &mut sector).expect("sector 0 reads");
        assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
        assert_eq!(
            &sector[3..11],
            b"SYSLINUX",
            "the payload OEM marks the volume"
        );
        assert_eq!(
            2 + u16::from(sector[1]),
            0x5A,
            "the jump targets the code at 0x5A"
        );
    }

    /// Synthetic user-supplied MS-DOS directory: exact-size `IO.SYS`
    /// and `COMMAND.COM` with the reference signatures planted plus a
    /// 2 KiB `MSDOS.SYS` — stand-in bytes (synthetic, not real DOS
    /// bytes), the same shape the arm-level tests use. The directory
    /// returns alongside so it outlives the run.
    fn msdos_user_dir() -> tempfile::TempDir {
        use crate::boot::msdos as dos;
        let mut io_sys: Vec<u8> = (0..dos::IO_SYS_BYTES)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect();
        let end = dos::IO_SYS_SIGNATURE_OFFSET + dos::IO_SYS_SIGNATURE.len();
        io_sys[dos::IO_SYS_SIGNATURE_OFFSET..end].copy_from_slice(&dos::IO_SYS_SIGNATURE);
        let mut command_com: Vec<u8> = (0..dos::COMMAND_COM_BYTES)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect();
        let end = dos::COMMAND_COM_SIGNATURE_OFFSET + dos::COMMAND_COM_SIGNATURE.len();
        command_com[dos::COMMAND_COM_SIGNATURE_OFFSET..end]
            .copy_from_slice(&dos::COMMAND_COM_SIGNATURE);
        let dir = tempfile::tempdir().expect("the dos dir allocates");
        std::fs::write(dir.path().join("IO.SYS"), &io_sys).expect("IO.SYS lands");
        std::fs::write(dir.path().join("MSDOS.SYS"), vec![0xABu8; 2048]).expect("MSDOS.SYS lands");
        std::fs::write(dir.path().join("COMMAND.COM"), &command_com).expect("COMMAND.COM lands");
        dir
    }

    /// The MS-DOS plan over `iso` with `dos` as its user-supplied
    /// directory (`None` for the refusal test): wipe, table,
    /// partition, format, bootloader, finalize — never a write step,
    /// since `IO.SYS` must be the first root entry of the fresh
    /// volume.
    fn msdos_plan(iso: &std::path::Path, dos: Option<&std::path::Path>) -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "bootloader-msdos-e2e".to_string(),
            device: DeviceRef {
                path: "/dev/test".to_string(),
                block_device: false,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: iso.display().to_string(),
                size_bytes: 32 * SECTOR_BYTES as u64,
                sha256: String::new(),
                kind: ImageKind::Iso,
            },
            options: Options {
                scheme: rufus_proto::Scheme::Mbr,
                target: rufus_proto::Target::Dual,
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: dos.map(|dir| dir.display().to_string()),
            },
            steps: vec![
                rufus_proto::Step::Wipe,
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Mkpart {
                    scheme: rufus_proto::Scheme::Mbr,
                    layout: rufus_proto::Layout::Single,
                },
                rufus_proto::Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: None,
                    cluster_bytes: None,
                    quick: true,
                },
                rufus_proto::Step::Bootloader {
                    mode: rufus_proto::BootloaderMode::MsDos,
                },
                rufus_proto::Step::Finalize,
            ],
            confirm: String::new(),
        }
    }

    /// A sparse 128 MiB disk image plus the opener serving it at the
    /// Mkpart-planned window: the shared rig both MS-DOS run tests
    /// drive (the refusal test snapshots the window between runs).
    fn msdos_rig(scratch: &tempfile::TempDir) -> (std::path::PathBuf, EndToEndOpener, u64, u64) {
        let disk_path = scratch.path().join("disk.img");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&disk_path)
            .expect("the disk creates")
            .set_len(DISK_BYTES)
            .expect("the disk sizes");
        let (base, len) =
            single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans");
        let opener = EndToEndOpener {
            path: disk_path.clone(),
            disk_len: DISK_BYTES,
            base,
            len,
        };
        (disk_path, opener, base, len)
    }

    /// The run options every MS-DOS run below shares: no read-back
    /// check, no surface scan, instant retries.
    fn msdos_run_options() -> crate::pipeline::RunOptions {
        crate::pipeline::RunOptions {
            verify: false,
            badblocks: false,
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        }
    }

    #[test]
    fn msdos_plan_installs_user_files_end_to_end() {
        // The full pipeline proves both wirings at once: `run_step`
        // threads `plan.options.msdos_dir` into `bootloader::run`,
        // which threads it into `install_tree`. Reverting either to
        // `None` refuses the run naming `--msdos-dir`, so this test
        // fails. The ISO is only the still-required detection record:
        // the arm never reads the tree (the plan carries no write
        // step), and `run` never even opens it (see
        // `msdos_plan_ignores_an_image_with_no_tree`).
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let iso_path = scratch.path().join("dos.iso");
        std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
        let (disk_path, opener, base, len) = msdos_rig(&scratch);
        let dos = msdos_user_dir();
        let mut reporter = Recorder::default();
        let plan = msdos_plan(&iso_path, Some(dos.path()));
        let report =
            crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
                false
            })
            .expect("the msdos plan runs");
        // All six steps ran, in order, with no transfer anywhere.
        let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
        assert_eq!(
            names,
            [
                "wipe",
                "mklabel",
                "mkpart",
                "mkfs",
                "bootloader",
                "finalize"
            ],
            "every step runs in order, with no write step"
        );
        // The three files land through a fresh handle over the same
        // window — which is what proves the run flushed — with both
        // patches applied and the kernel byte-correct.
        let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
        let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
        let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
        assert_eq!(
            back.len(),
            crate::boot::msdos::IO_SYS_BYTES,
            "the bios length holds"
        );
        assert_eq!(
            back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
            0xEB,
            "the bios patch byte lands"
        );
        let back = fat.read_file("/MSDOS.SYS").expect("MSDOS.SYS reads back");
        assert_eq!(back, vec![0xABu8; 2048], "the kernel is byte-correct");
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert_eq!(
            back.len(),
            crate::boot::msdos::COMMAND_COM_BYTES,
            "the shell length holds"
        );
        assert_eq!(
            back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
            0xEB,
            "the shell patch byte lands"
        );
        // The run reports the reference lines plus the summary.
        let texts: Vec<&str> = reporter
            .events
            .iter()
            .filter_map(|event| match event {
                crate::pipeline::event::Event::Message { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"Patching IO.SYS..."),
            "the bios line reports: {texts:?}"
        );
        assert!(
            texts.contains(&"Patching COMMAND.COM..."),
            "the shell line reports: {texts:?}"
        );
        let total = (crate::boot::msdos::IO_SYS_BYTES
            + 2048
            + crate::boot::msdos::COMMAND_COM_BYTES) as u64;
        let summary = format!("installed msdos (3 files written, 0 kept, {total} bytes)");
        assert!(
            texts.contains(&summary.as_str()),
            "the summary names the files: {texts:?}"
        );
        assert!(
            texts.iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
    }

    #[test]
    fn msdos_plan_ignores_an_image_with_no_tree() {
        // The arm never reads the image tree, and `run` short-circuits
        // past the tree setup: a plan whose image is not an ISO at all
        // (patterned bytes, no descriptors) still installs. The kind
        // stays `Iso` and the CLI still requires the `--image`
        // argument — only the readability requirement is gone.
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let iso_path = scratch.path().join("dos.iso");
        let garbage: Vec<u8> = (0..4096)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        std::fs::write(&iso_path, &garbage).expect("the non-image writes");
        let (disk_path, opener, base, len) = msdos_rig(&scratch);
        let dos = msdos_user_dir();
        let mut reporter = Recorder::default();
        let plan = msdos_plan(&iso_path, Some(dos.path()));
        let report =
            crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
                false
            })
            .expect("a tree-less image still installs msdos");
        let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
        assert_eq!(
            names,
            [
                "wipe",
                "mklabel",
                "mkpart",
                "mkfs",
                "bootloader",
                "finalize"
            ],
            "every step runs in order, with no write step"
        );
        let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
        let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
        let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
        assert_eq!(
            back.len(),
            crate::boot::msdos::IO_SYS_BYTES,
            "the bios lands without any image tree"
        );
        let back = fat
            .read_file("/COMMAND.COM")
            .expect("COMMAND.COM reads back");
        assert_eq!(
            back.len(),
            crate::boot::msdos::COMMAND_COM_BYTES,
            "the shell lands without any image tree"
        );
    }

    #[test]
    fn msdos_plan_without_its_directory_refuses_leaving_the_volume_identical() {
        // Same rig, two phases: format first, snapshot the partition
        // window, then run the bootloader step with `msdos_dir: None`
        // (as a hand-built plan without one would carry). The refusal
        // names `--msdos-dir` (step-wrapped as `bootloader`) and not
        // one window byte moves: the gate fires before any write, and
        // a failed step never flushes on its behalf.
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let iso_path = scratch.path().join("dos.iso");
        std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
        let (disk_path, opener, base, len) = msdos_rig(&scratch);
        let mut reporter = Recorder::default();
        let mut setup = msdos_plan(&iso_path, None);
        setup.steps.truncate(4);
        crate::pipeline::run(
            &setup,
            &opener,
            &msdos_run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe through mkfs runs");
        let disk = std::fs::OpenOptions::new()
            .read(true)
            .open(&disk_path)
            .expect("the disk reopens");
        let mut before = vec![0u8; len as usize];
        disk.read_exact_at(&mut before, base)
            .expect("the window snapshots");
        let mut reporter = Recorder::default();
        let mut plan = msdos_plan(&iso_path, None);
        plan.steps = vec![rufus_proto::Step::Bootloader {
            mode: rufus_proto::BootloaderMode::MsDos,
        }];
        let error =
            crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
                false
            })
            .expect_err("a directory-less msdos refuses");
        assert!(
            matches!(
                error,
                crate::error::CoreError::Step {
                    step: "bootloader",
                    ..
                }
            ),
            "the refusal is step-wrapped: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("--msdos-dir"), "names the flag: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let mut after = vec![0u8; len as usize];
        disk.read_exact_at(&mut after, base)
            .expect("the window reads back");
        assert_eq!(after, before, "no volume byte moved");
    }

    /// A real `pipeline::run` step plan for the acceptance table:
    /// wipe, table, partition, format, bootloader, finalize — never a
    /// transfer step, which no bootloader arm needs (every arm reads
    /// the image file itself, or nothing at all).
    fn acceptance_plan(
        iso: &std::path::Path,
        image_len: u64,
        filesystem: Filesystem,
        layout: rufus_proto::Layout,
        mode: rufus_proto::BootloaderMode,
        dos: Option<&std::path::Path>,
    ) -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "bootloader-acceptance".to_string(),
            device: DeviceRef {
                path: "/dev/test".to_string(),
                block_device: false,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: ImageRef {
                path: iso.display().to_string(),
                size_bytes: image_len,
                sha256: String::new(),
                kind: ImageKind::Iso,
            },
            options: Options {
                scheme: rufus_proto::Scheme::Mbr,
                target: rufus_proto::Target::Dual,
                filesystem: filesystem.clone(),
                label: None,
                cluster_bytes: None,
                quick_format: true,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: dos.map(|dir| dir.display().to_string()),
            },
            steps: vec![
                rufus_proto::Step::Wipe,
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Mkpart {
                    scheme: rufus_proto::Scheme::Mbr,
                    layout,
                },
                rufus_proto::Step::Mkfs {
                    filesystem: filesystem.clone(),
                    label: None,
                    cluster_bytes: None,
                    quick: true,
                },
                rufus_proto::Step::Bootloader { mode },
                rufus_proto::Step::Finalize,
            ],
            confirm: String::new(),
        }
    }

    /// One mode of the acceptance table on its own fresh file-backed
    /// disk, so modes cannot mask each other. The `UefiNtfs` and
    /// `None` modes run in two phases (set up, snapshot the data
    /// window, then the bootloader step) so the test pins that the
    /// arm itself leaves the data window alone; every other mode runs
    /// the whole six-step plan at once.
    fn acceptance_one(mode: rufus_proto::BootloaderMode) {
        use rufus_proto::BootloaderMode as Mode;
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        // Fixtures up front (a few hundred KiB total): the syslinux
        // image serves every arm that ignores the tree, the GRUB2 and
        // Kolibri images carry their payloads, and the MS-DOS image is
        // patterned garbage proving no tree is ever opened.
        let syslinux = syslinux_iso();
        let grub4dos = syslinux_iso_with(Some(&stand_in_grldr()));
        let (grub2_image, grub2_boot, grub2_core) = grub2_iso();
        let (kolibri_image, kolibri_loader) = kolibri_iso();
        let garbage: Vec<u8> = (0..4096)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        let (iso_bytes, image_len): (&[u8], u64) = match mode {
            Mode::Grub2 => (&grub2_image, 32 * SECTOR_BYTES as u64),
            Mode::Kolibri => (&kolibri_image, 32 * SECTOR_BYTES as u64),
            Mode::MsDos => (&garbage, garbage.len() as u64),
            // The GRUB4DOS arm refuses without a root loader on the
            // volume. The acceptance plan has no copy step, so the
            // stand-in loader is staged onto the volume directly (see
            // the two-phase branch below); the image only names it.
            Mode::Grub4dos => (&grub4dos, grub4dos.len() as u64),
            _ => (&syslinux, 32 * SECTOR_BYTES as u64),
        };
        let iso_path = scratch.path().join("acceptance.iso");
        std::fs::write(&iso_path, iso_bytes).expect("the iso writes");
        let dos = (mode == Mode::MsDos).then(msdos_user_dir);
        // The UEFI:NTFS data partition lives in the two-partition
        // window; every other mode formats the single data window.
        let uefi = mode == Mode::UefiNtfs;
        let disk_path = scratch.path().join("disk.img");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&disk_path)
            .expect("the disk creates")
            .set_len(DISK_BYTES)
            .expect("the disk sizes");
        let (base, len) = if uefi {
            data_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, DISK_BYTES)
                .expect("the uefi data window plans")
        } else {
            single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans")
        };
        let opener = EndToEndOpener {
            path: disk_path.clone(),
            disk_len: DISK_BYTES,
            base,
            len,
        };
        let filesystem = if uefi {
            Filesystem::Exfat
        } else {
            Filesystem::Fat32
        };
        let layout = if uefi {
            rufus_proto::Layout::UefiNtfs
        } else {
            rufus_proto::Layout::Single
        };
        let plan = acceptance_plan(
            &iso_path,
            image_len,
            filesystem,
            layout,
            mode.clone(),
            dos.as_ref().map(|dir| dir.path()),
        );
        // Step names in run order, asserted after every run below.
        let step_names = |report: &crate::pipeline::RunReport| {
            report
                .steps
                .iter()
                .map(|step| step.step)
                .collect::<Vec<_>>()
        };
        // Sector 0 of the data window through a fresh handle: the
        // record fingerprints below all read it this way, which is
        // what proves the run flushed.
        let boot_sector = || {
            let disk = std::fs::OpenOptions::new()
                .read(true)
                .open(&disk_path)
                .expect("the disk reopens");
            let mut sector = [0u8; 512];
            disk.read_exact_at(&mut sector, base)
                .expect("sector 0 reads");
            sector
        };
        // The data window through a fresh volume handle (flush proof
        // for the file fingerprints).
        let open_volume = || {
            let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
            Fat32::open(Box::new(view)).expect("the volume opens")
        };
        // The GRUB4DOS fingerprint: the staged root loader is kept
        // byte-identical and the MBR+SBR land over it. Both paths
        // below reach it (the two-phase one returns early).
        let grub4dos_fingerprint = || {
            let expected = stand_in_grldr();
            let mut fat = open_volume();
            let back = fat.read_file("/GRLDR").expect("the loader reads back");
            assert_eq!(back, expected, "the staged loader is kept byte-identical");
            let mbr = load_from(&resources_dir(), Resource::Grub4DosMbr)
                .expect("the mbr loads")
                .bytes()
                .to_vec();
            let disk = std::fs::OpenOptions::new()
                .read(true)
                .open(&disk_path)
                .expect("the disk reopens");
            let mut sector = [0u8; 512];
            disk.read_exact_at(&mut sector, 0).expect("sector 0 reads");
            assert_eq!(&sector[..423], &mbr[..423], "the mbr window lands");
            assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
            let sbr = &mbr[512..];
            let mut sbr_back = vec![0u8; sbr.len()];
            disk.read_exact_at(&mut sbr_back, 512)
                .expect("the sbr reads");
            assert_eq!(sbr_back, sbr, "the sbr lands whole at sector 1");
        };
        if uefi || mode == Mode::None || mode == Mode::Grub4dos {
            // Two phases: format first, snapshot the window, then the
            // bootloader step alone. A single plan could not isolate
            // the arm's own writes from the formatter's.
            let mut setup = plan.clone();
            setup.steps.truncate(4);
            let mut reporter = Recorder::default();
            crate::pipeline::run(
                &setup,
                &opener,
                &msdos_run_options(),
                &mut reporter,
                &|| false,
            )
            .expect("wipe through mkfs runs");
            if mode == Mode::Grub4dos {
                // The copy step would place the image's root loader
                // here; the plan has none, so stage the stand-in with
                // the same byte-taking core the arm's loader uses.
                let mut fat = open_volume();
                crate::boot::grub4dos::install_loader(&mut fat, &stand_in_grldr())
                    .expect("the staged loader lands");
            }
            let disk = std::fs::OpenOptions::new()
                .read(true)
                .open(&disk_path)
                .expect("the disk reopens");
            let mut before = vec![0u8; len as usize];
            disk.read_exact_at(&mut before, base)
                .expect("the window snapshots");
            let mut phase = plan.clone();
            phase.steps = if uefi {
                // `Mklabel` re-records the table: every `run` starts
                // context-free, so the second phase must stamp it again
                // before the arm resolves its ESP window.
                vec![
                    rufus_proto::Step::Mklabel {
                        scheme: rufus_proto::Scheme::Mbr,
                    },
                    rufus_proto::Step::Bootloader {
                        mode: Mode::UefiNtfs,
                    },
                    rufus_proto::Step::Finalize,
                ]
            } else if mode == Mode::Grub4dos {
                // The GRUB4DOS arm bounds its record by the recorded
                // table, so this phase stamps the record first too.
                vec![
                    rufus_proto::Step::Mklabel {
                        scheme: rufus_proto::Scheme::Mbr,
                    },
                    rufus_proto::Step::Bootloader {
                        mode: Mode::Grub4dos,
                    },
                ]
            } else {
                vec![rufus_proto::Step::Bootloader { mode: mode.clone() }]
            };
            let mut reporter = Recorder::default();
            let report = crate::pipeline::run(
                &phase,
                &opener,
                &msdos_run_options(),
                &mut reporter,
                &|| false,
            )
            .expect("the bootloader phase runs");
            if uefi {
                assert_eq!(
                    step_names(&report),
                    ["mklabel", "bootloader", "finalize"],
                    "the uefi phase runs in order"
                );
                let (offset, esp_len) =
                    esp_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, DISK_BYTES)
                        .expect("the esp window plans");
                assert_eq!(
                    esp_len,
                    crate::boot::uefi_ntfs::IMAGE_BYTES,
                    "the esp window holds the whole shim"
                );
                let shim = load_from(&resources_dir(), Resource::UefiNtfsImage)
                    .expect("the shim loads")
                    .bytes()
                    .to_vec();
                let mut window = vec![0u8; esp_len as usize];
                disk.read_exact_at(&mut window, offset)
                    .expect("the esp window reads");
                assert_eq!(window, shim, "the shim lands whole at the esp offset");
            } else if mode == Mode::Grub4dos {
                assert_eq!(
                    step_names(&report),
                    ["mklabel", "bootloader"],
                    "the grub4dos phase runs in order"
                );
            } else {
                assert_eq!(
                    step_names(&report),
                    ["bootloader"],
                    "the bootloader phase runs its one step"
                );
            }
            let mut after = vec![0u8; len as usize];
            disk.read_exact_at(&mut after, base)
                .expect("the window reads back");
            assert_eq!(
                after, before,
                "the {mode:?} arm leaves the data window alone"
            );
            if mode == Mode::Grub4dos {
                grub4dos_fingerprint();
            }
            return;
        }
        let mut reporter = Recorder::default();
        let report =
            crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
                false
            })
            .expect("the acceptance plan runs");
        assert_eq!(
            step_names(&report),
            [
                "wipe",
                "mklabel",
                "mkpart",
                "mkfs",
                "bootloader",
                "finalize"
            ],
            "every step runs in order, with no write step"
        );
        match mode {
            Mode::Syslinux => {
                // The stage lands and the payload record grafts:
                // companions and the wrapper are the arm tests'
                // province (`syslinux_604_installs_stage_companions_and_config`).
                let mut fat = open_volume();
                let stage = fat.read_file("/LDLINUX.SYS").expect("the stage reads back");
                assert!(!stage.is_empty(), "the stage lands");
                let sector = boot_sector();
                assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
                assert_eq!(
                    &sector[3..11],
                    b"SYSLINUX",
                    "the payload oem marks the volume"
                );
                assert_eq!(
                    2 + u16::from(sector[1]),
                    0x5A,
                    "the jump targets the code at 0x5A"
                );
            }
            Mode::Grub2 => {
                // The BIOS record plus the whole core image on the
                // disk itself (sectors 0 and 1, not the partition
                // window); the UEFI placement has no payload in this
                // image, so nothing is placed (see
                // `grub2_installs_bios_and_places_uefi` for the placed
                // case).
                let disk = std::fs::OpenOptions::new()
                    .read(true)
                    .open(&disk_path)
                    .expect("the disk reopens");
                let mut sector = [0u8; 512];
                disk.read_exact_at(&mut sector, 0).expect("sector 0 reads");
                assert_eq!(&sector[..0x5c], &grub2_boot[..0x5c], "record head verbatim");
                assert_eq!(
                    &sector[0x5c..0x64],
                    &1u64.to_le_bytes(),
                    "the kernel field names sector 1"
                );
                assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
                let mut core_back = vec![0u8; grub2_core.len()];
                disk.read_exact_at(&mut core_back, 512)
                    .expect("the core reads");
                assert_eq!(core_back, grub2_core, "the core lands whole at sector 1");
            }
            Mode::Grub4dos => {
                // Every GRUB4DOS run takes the two-phase branch above,
                // which runs this same fingerprint; the refusal without
                // a loader is `grub4dos_refuses_without_a_root_grldr`.
                grub4dos_fingerprint();
            }
            Mode::Freedos => {
                // The pair, the 25 locale files and the rendered
                // `AUTOEXEC.BAT`: 28 files, plus the record (the locale
                // plan lines are the arm tests' province,
                // `install_us_builds_the_full_volume`).
                let mut fat = open_volume();
                for name in ["/COMMAND.COM", "/KERNEL.SYS", "/AUTOEXEC.BAT"] {
                    let back = fat.read_file(name).expect("the file reads back");
                    assert!(!back.is_empty(), "{name} lands");
                }
                let listed = fat.list_dir("/LOCALE").expect("the locale lists");
                assert_eq!(listed.len(), 25, "LOCALE holds the 25 locale files");
                let entries = fat.list_dir("/").expect("the root lists");
                let mut root: Vec<&str> = entries
                    .iter()
                    .map(|entry| entry.short_name.as_str())
                    .collect();
                root.sort_unstable();
                assert_eq!(
                    root,
                    vec!["AUTOEXEC.BAT", "COMMAND.COM", "KERNEL.SYS", "LOCALE"],
                    "the root holds the pair plus AUTOEXEC.BAT beside LOCALE"
                );
                let sector = boot_sector();
                assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
                assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
            }
            Mode::Kolibri => {
                // The image-tree loader byte-identical at the root,
                // plus the record (the keep path is the arm tests'
                // province).
                let mut fat = open_volume();
                let back = fat.read_file("/MTLD_F32").expect("the loader reads back");
                assert_eq!(back, kolibri_loader, "the loader is byte-identical");
                let sector = boot_sector();
                assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
                assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
            }
            Mode::MsDos => {
                // The three user files with `IO.SYS` first and both
                // patches applied (the keep and miss paths are the arm
                // tests' province).
                let mut fat = open_volume();
                let listed = fat.list_dir("/").expect("the root lists");
                let shorts: Vec<&str> = listed
                    .iter()
                    .map(|entry| entry.short_name.as_str())
                    .collect();
                assert_eq!(
                    shorts,
                    vec!["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
                    "IO.SYS lands first"
                );
                let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
                assert_eq!(
                    back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
                    0xEB,
                    "the bios patch byte lands"
                );
                let back = fat
                    .read_file("/COMMAND.COM")
                    .expect("COMMAND.COM reads back");
                assert_eq!(
                    back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
                    0xEB,
                    "the shell patch byte lands"
                );
            }
            Mode::UefiNtfs | Mode::Auto | Mode::None => {
                panic!("the two-phase arms above return early; auto is never accepted here");
            }
        }
    }

    /// Acceptance across every wired bootloader mode: each mode runs a
    /// real `pipeline::run` step plan on its own fresh file-backed
    /// disk and leaves its fingerprint behind. The `UefiNtfs` and
    /// `None` arms run in two phases so the data-window comparison
    /// isolates the arm from the formatter; the exFAT data partition
    /// for `UefiNtfs` formats natively (NTFS would need the host
    /// tool). Every fingerprint reads through a fresh handle, which
    /// is what proves each run flushed.
    #[test]
    fn every_wired_mode_installs_its_fingerprint_end_to_end() {
        // One asset seeding for the arms that load production
        // payloads (FreeDOS, GRUB4DOS, UEFI:NTFS); the rest read the
        // image tree or the user directory only.
        seed_exe_assets();
        use rufus_proto::BootloaderMode as Mode;
        for mode in [
            Mode::Syslinux,
            Mode::Grub2,
            Mode::Grub4dos,
            Mode::UefiNtfs,
            Mode::Freedos,
            Mode::Kolibri,
            Mode::MsDos,
            Mode::None,
        ] {
            acceptance_one(mode);
        }
    }

    /// QEMU VGA-text boot capture for the BIOS bootloader modes
    /// (test-only): each boot test below drives its disk file through
    /// this instead of transcribing expectations from sources.
    ///
    /// Technique: the `isa-debugcon` / `-chardev file` path yields an
    /// empty log on the QEMU + SeaBIOS builds this suite runs under,
    /// so the harness boots with `-display none -monitor
    /// unix:<sock>,server,nowait`, waits out the load, then sends
    /// `pmemsave 0xb8000 4000 "<file>"` (double-quoted path) over the
    /// monitor socket and decodes the dump as 25 rows of 80
    /// character/attribute pairs. Boot media always come from
    /// [`boot_disk`] (full plans with a partition table): bare FAT32
    /// volumes cannot boot FreeDOS (its kernel assigns drive letters
    /// from partition tables only) and GRUB4DOS likewise needs a
    /// real partition entry.
    ///
    /// Every capture kills and reaps its child and drops its scratch
    /// directory (socket and dump vanish with it) on every path, so
    /// no machine and no file survives a failed assertion; every
    /// monitor read carries a timeout, so a silent QEMU fails the
    /// test instead of hanging it.
    mod qemu {
        use std::io::Read as _;
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        use crate::error::CoreError;
        use crate::error::Result as TestResult;

        /// VGA text buffer shape: 25 rows of 80
        /// character/attribute pairs.
        const VGA_ROWS: usize = 25;
        const VGA_COLS: usize = 80;
        const VGA_BYTES: usize = VGA_ROWS * VGA_COLS * 2;

        /// Whether `qemu-system-x86_64` answers `--version`: the one
        /// probe every boot test gates on (the same smoke shape as
        /// the `fsck.fat` acceptances elsewhere in this file).
        pub(crate) fn have_qemu() -> bool {
            std::process::Command::new("qemu-system-x86_64")
                .arg("--version")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }

        /// A spawned QEMU that is killed and reaped on drop, so no
        /// machine survives a failed assertion or an early return.
        struct Guard {
            child: Option<std::process::Child>,
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(child) = self.child.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        /// Send one monitor line (the reply is drained by the
        /// caller after it has had time to arrive).
        fn send(stream: &mut UnixStream, line: &str) -> TestResult<()> {
            stream
                .write_all(line.as_bytes())
                .map_err(|source| CoreError::io("qemu monitor", source))
        }

        /// Read and discard one monitor reply (greeting, command
        /// reply, prompt): bounded by the stream timeout, so a
        /// silent monitor fails instead of hanging.
        fn drain(stream: &mut UnixStream) -> TestResult<()> {
            let mut buf = [0u8; 65536];
            stream
                .read(&mut buf)
                .map_err(|source| CoreError::io("qemu monitor", source))?;
            Ok(())
        }

        /// Connect to the monitor socket, retrying while QEMU binds
        /// it; a socket that never answers refuses naming it.
        fn connect(sock: &std::path::Path) -> TestResult<UnixStream> {
            let mut last = String::new();
            for _ in 0..50 {
                match UnixStream::connect(sock) {
                    Ok(stream) => return Ok(stream),
                    Err(error) => {
                        last = error.to_string();
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            Err(CoreError::invalid(format!(
                "qemu monitor at {} never answered ({last}): refusing",
                sock.display()
            )))
        }

        /// Decode a VGA dump into 25 right-trimmed rows: every second
        /// byte is the character cell (the attribute byte interleaves
        /// it), non-printable cells read as a space.
        fn decode(dump: &[u8]) -> TestResult<Vec<String>> {
            if dump.len() < VGA_BYTES {
                return Err(CoreError::invalid(format!(
                    "qemu vga dump holds {} bytes, the text buffer needs {VGA_BYTES}: refusing",
                    dump.len()
                )));
            }
            let mut lines = Vec::with_capacity(VGA_ROWS);
            for row in 0..VGA_ROWS {
                let mut text = String::with_capacity(VGA_COLS);
                for col in 0..VGA_COLS {
                    let byte = dump
                        .get(row * VGA_COLS * 2 + col * 2)
                        .expect("the vga window fits the length check above");
                    text.push(if (0x20..0x7F).contains(byte) {
                        *byte as char
                    } else {
                        ' '
                    });
                }
                lines.push(text.trim_end().to_string());
            }
            Ok(lines)
        }

        /// Boot `disk` in QEMU, wait `wait`, capture the VGA text
        /// buffer and quit the machine.
        pub(crate) fn capture(disk: &std::path::Path, wait: Duration) -> TestResult<Vec<String>> {
            capture_keys(disk, wait, &[])
        }

        /// [`capture`] plus one `sendkey` line per entry of `keys`
        /// after the wait (then a settle wait before the dump): the
        /// GRUB2 config test drives the loader shell this way.
        pub(crate) fn capture_keys(
            disk: &std::path::Path,
            wait: Duration,
            keys: &[&str],
        ) -> TestResult<Vec<String>> {
            let scratch = tempfile::tempdir().expect("a qemu scratch directory");
            let sock = scratch.path().join("mon.sock");
            let dump = scratch.path().join("vga.bin");
            let child = std::process::Command::new("qemu-system-x86_64")
                .arg("-m")
                .arg("128")
                .arg("-drive")
                .arg(format!("file={},format=raw,if=ide", disk.display()))
                .arg("-display")
                .arg("none")
                .arg("-no-reboot")
                .arg("-monitor")
                .arg(format!("unix:{},server,nowait", sock.display()))
                .spawn()
                .map_err(|source| CoreError::io("qemu-system-x86_64", source))?;
            let guard = Guard { child: Some(child) };
            std::thread::sleep(wait);
            let mut stream = connect(&sock)?;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|source| CoreError::io("qemu monitor", source))?;
            drain(&mut stream)?;
            for key in keys {
                send(&mut stream, &format!("sendkey {key}\n"))?;
                std::thread::sleep(Duration::from_millis(150));
            }
            if !keys.is_empty() {
                std::thread::sleep(Duration::from_secs(3));
            }
            // The dump path is double-quoted: the monitor splits
            // unquoted paths on whitespace.
            send(
                &mut stream,
                &format!("pmemsave 0xb8000 4000 \"{}\"\n", dump.display()),
            )?;
            std::thread::sleep(Duration::from_secs(1));
            drain(&mut stream)?;
            send(&mut stream, "quit\n")?;
            std::thread::sleep(Duration::from_millis(300));
            drop(guard);
            let bytes = std::fs::read(&dump).map_err(|source| CoreError::io(&dump, source))?;
            decode(&bytes)
        }

        /// Print the non-empty rows for the test log: every boot test
        /// reports what it saw, so a failure quotes the screen.
        pub(crate) fn log(lines: &[String]) {
            eprintln!("qemu vga screen (non-empty rows only):");
            for line in lines.iter().filter(|line| !line.is_empty()) {
                eprintln!("  |{line}|");
            }
        }
    }

    /// Build the Syslinux 4.07 fixture ISO: the same descriptor and
    /// directory shape as [`syslinux_iso`], but a 4.07 banner and no
    /// `.c32` files. 4.07 needs no core library, which is what makes
    /// it the bootable fixture: 6.04 needs real `.c32` modules no
    /// test can provide, so a 6.04 stick can never get past its
    /// loader.
    fn syslinux_407_iso() -> Vec<u8> {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const DIR: u32 = 21;
        const BIN: u32 = 22;
        const CFG: u32 = 23;
        let banner = b"ISOLINUX 4.07 20130725 test-image".to_vec();
        // Lowercase identifiers with `;1` versions, like
        // [`syslinux_iso`]: the reader resolves file opens exactly.
        let files: Vec<(&[u8], u32, Vec<u8>)> = vec![
            (b"isolinux.bin;1", BIN, banner),
            (b"isolinux.cfg;1", CFG, b"DEFAULT linux\n".to_vec()),
        ];
        let mut image = vec![0u8; 32 * SECTOR_BYTES];
        let mut put = |sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
        put(17, &boot_sector());
        put(18, &terminator_sector());
        let root = vec![
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"isolinux"),
        ];
        let mut dir = vec![
            encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        ];
        for (identifier, sector, bytes) in &files {
            dir.push(encode_record(*sector, bytes.len() as u32, 0, identifier));
        }
        put(ROOT, &dir_sector(&root));
        put(DIR, &dir_sector(&dir));
        for (_, sector, bytes) in &files {
            put(*sector, bytes);
        }
        image
    }

    /// Build the GRUB2 boot fixture ISO from test-time bytes: real
    /// `boot.img` and `core.img` under `boot/grub/i386-pc/` (what the
    /// GRUB2 arm installs) plus the `grub.cfg` the Write step copies
    /// to the partition (what the booted core reads). File data
    /// starts at sector 24 and packs contiguously; the image sizes
    /// itself around the three payloads.
    fn grub2_boot_iso(boot: &[u8], core: &[u8], cfg: &[u8]) -> Vec<u8> {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const BOOT: u32 = 21;
        const GRUB: u32 = 22;
        const PC: u32 = 23;
        let boot_at = 24u32;
        let core_at = boot_at + boot.len().div_ceil(SECTOR_BYTES) as u32;
        let cfg_at = core_at + core.len().div_ceil(SECTOR_BYTES) as u32;
        let total = (cfg_at as usize + cfg.len().div_ceil(SECTOR_BYTES) + 1) * SECTOR_BYTES;
        let mut image = vec![0u8; total];
        let mut put = |sector: u32, bytes: &[u8]| {
            let base = sector as usize * SECTOR_BYTES;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        };
        put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
        put(17, &boot_sector());
        put(18, &terminator_sector());
        let root = vec![
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"boot"),
        ];
        let boot_dir = vec![
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"grub"),
        ];
        let grub_dir = vec![
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"i386-pc"),
            encode_record(cfg_at, cfg.len() as u32, 0, b"grub.cfg;1"),
        ];
        let pc_dir = vec![
            encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
            encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
            encode_record(boot_at, boot.len() as u32, 0, b"boot.img;1"),
            encode_record(core_at, core.len() as u32, 0, b"core.img;1"),
        ];
        put(ROOT, &dir_sector(&root));
        put(BOOT, &dir_sector(&boot_dir));
        put(GRUB, &dir_sector(&grub_dir));
        put(PC, &dir_sector(&pc_dir));
        put(boot_at, boot);
        put(core_at, core);
        put(cfg_at, cfg);
        image
    }

    /// Run the acceptance plan over a fresh file-backed disk and hand
    /// back the scratch directory (it owns the disk file, so it must
    /// outlive the QEMU boot) plus the disk path to boot. `write_copy`
    /// inserts a `Write { mode: Copy }` step between `Mkfs` and
    /// `Bootloader` for the GRUB2 arm, whose `grub.cfg` must reach
    /// the partition; every other arm reads the image tree straight
    /// from the file, like [`acceptance_one`].
    fn boot_disk(
        iso_bytes: &[u8],
        image_len: u64,
        mode: rufus_proto::BootloaderMode,
        write_copy: bool,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let iso_path = scratch.path().join("boot.iso");
        std::fs::write(&iso_path, iso_bytes).expect("the iso writes");
        let disk_path = scratch.path().join("disk.img");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&disk_path)
            .expect("the disk creates")
            .set_len(DISK_BYTES)
            .expect("the disk sizes");
        let (base, len) =
            single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans");
        let opener = EndToEndOpener {
            path: disk_path.clone(),
            disk_len: DISK_BYTES,
            base,
            len,
        };
        let mut plan = acceptance_plan(
            &iso_path,
            image_len,
            Filesystem::Fat32,
            rufus_proto::Layout::Single,
            mode,
            None,
        );
        if write_copy {
            // The copy must land before the bootloader step; look the
            // step up rather than assume its index in the plan.
            let bootloader = plan
                .steps
                .iter()
                .position(|step| matches!(step, rufus_proto::Step::Bootloader { .. }))
                .expect("the acceptance plan carries a bootloader step");
            plan.steps.insert(
                bootloader,
                rufus_proto::Step::Write {
                    mode: rufus_proto::WriteMode::Copy,
                },
            );
        }
        let mut reporter = Recorder::default();
        crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
            false
        })
        .expect("the boot plan runs");
        (scratch, disk_path)
    }

    /// Whether `grub-mkimage` answers `--version`: the GRUB2 boot
    /// test builds its `core.img` at test time, so it gates on this
    /// alongside [`qemu::have_qemu`].
    fn have_grub_mkimage() -> bool {
        std::process::Command::new("grub-mkimage")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn syslinux_407_boots_to_its_prompt_in_qemu() {
        // Through the full six-step plan (partition table included)
        // with the 4.07 fixture: the installed VBR and stage are the
        // real embedded 4.07 payloads, so the stick boots for real.
        if !qemu::have_qemu() {
            eprintln!("skip: qemu-system-x86_64 is not on PATH");
            return;
        }
        seed_exe_assets();
        let iso = syslinux_407_iso();
        let (_scratch, disk) = boot_disk(
            &iso,
            32 * SECTOR_BYTES as u64,
            rufus_proto::BootloaderMode::Syslinux,
            false,
        );
        let screen = qemu::capture(&disk, std::time::Duration::from_secs(10))
            .expect("qemu captures the screen");
        qemu::log(&screen);
        assert!(
            screen.iter().any(|line| line.contains("SYSLINUX 4.07")),
            "the loader banner shows: {screen:?}"
        );
        assert!(
            screen.iter().any(|line| line == "boot:"),
            "the loader prompt shows: {screen:?}"
        );
    }

    #[test]
    #[ignore = "needs a caller-supplied grldr: resource 451 is GRUB2 core.img and Rufus downloads the loader"]
    fn grub4dos_boots_to_its_prompt_in_qemu() {
        // Only a real GRUB4DOS `grldr` can produce this prompt, and no
        // loader is bundled. The test therefore reads one from the path
        // in `RUFUS_TEST_GRLDR` (run it with `--ignored`) and skips
        // without it, rather than assert a prompt it cannot produce.
        // The image carries that loader at its root, the record is the
        // embedded MBR/SBR (resource 450), and the boot runs for real.
        let Some(grldr_path) = std::env::var_os("RUFUS_TEST_GRLDR") else {
            eprintln!("skip: set RUFUS_TEST_GRLDR to a real grldr to run this boot test");
            return;
        };
        if !qemu::have_qemu() {
            eprintln!("skip: qemu-system-x86_64 is not on PATH");
            return;
        }
        seed_exe_assets();
        let grldr = std::fs::read(&grldr_path).expect("the caller's grldr reads");
        let iso = syslinux_iso_with(Some(&grldr));
        let (_scratch, disk) = boot_disk(
            &iso,
            iso.len() as u64,
            rufus_proto::BootloaderMode::Grub4dos,
            true,
        );
        let screen = qemu::capture(&disk, std::time::Duration::from_secs(10))
            .expect("qemu captures the screen");
        qemu::log(&screen);
        assert!(
            screen.iter().any(|line| line.contains("grub>")),
            "the loader prompt shows: {screen:?}"
        );
    }

    #[test]
    fn freedos_boots_to_its_shell_in_qemu() {
        // Through the full six-step plan (partition table included:
        // the kernel assigns drive letters from partition tables
        // only). The payloads and the record are the embedded ones,
        // so the stick boots for real into the kernel and its shell.
        if !qemu::have_qemu() {
            eprintln!("skip: qemu-system-x86_64 is not on PATH");
            return;
        }
        seed_exe_assets();
        let iso = syslinux_iso();
        let (_scratch, disk) = boot_disk(
            &iso,
            32 * SECTOR_BYTES as u64,
            rufus_proto::BootloaderMode::Freedos,
            false,
        );
        let screen = qemu::capture(&disk, std::time::Duration::from_secs(12))
            .expect("qemu captures the screen");
        qemu::log(&screen);
        assert!(
            screen
                .iter()
                .any(|line| line.contains("FreeDOS kernel 2043")),
            "the kernel banner shows: {screen:?}"
        );
        // The kernel's own `C: HD1, Pri[ 1], ...` line also contains
        // "C:", so the shell is pinned by its FreeCom prompt instead.
        assert!(
            screen.iter().any(|line| line.ends_with("C:\\>")),
            "the FreeCom prompt shows: {screen:?}"
        );
        assert!(
            screen.iter().any(|line| line.contains("FreeCom version")),
            "the FreeCom banner shows: {screen:?}"
        );
    }

    #[test]
    fn grub2_bios_boots_its_shell_and_reads_its_config_in_qemu() {
        // Genuine GRUB2 binaries only: `core.img` is built at test
        // time with the host `grub-mkimage` (prefix `/boot/grub`, an
        // early config that roots the boot partition, and every
        // module the boot needs embedded — no module loads from
        // disk), and the record is the host `boot.img`. Both reach
        // the stick through the image tree, exactly like a real
        // image's payloads; the Write step copies the tree
        // (including `grub.cfg`) to the partition first.
        if !qemu::have_qemu() {
            eprintln!("skip: qemu-system-x86_64 is not on PATH");
            return;
        }
        if !have_grub_mkimage() {
            eprintln!("skip: grub-mkimage is not on PATH");
            return;
        }
        let boot_img = match std::fs::read("/usr/lib/grub/i386-pc/boot.img") {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("skip: the grub2 boot record is not present ({error})");
                return;
            }
        };
        seed_exe_assets();
        let build = tempfile::tempdir().expect("a grub scratch directory");
        std::fs::write(
            build.path().join("early.cfg"),
            b"search --set=root --file /boot/grub/grub.cfg\nset prefix=($root)/boot/grub\n",
        )
        .expect("the early config writes");
        let core_path = build.path().join("core.img");
        let built = std::process::Command::new("grub-mkimage")
            .arg("-O")
            .arg("i386-pc")
            .arg("-o")
            .arg(&core_path)
            .arg("-p")
            .arg("/boot/grub")
            .arg("-c")
            .arg(build.path().join("early.cfg"))
            .args([
                "biosdisk",
                "part_msdos",
                "fat",
                "normal",
                "configfile",
                "search",
                "search_fs_file",
                "echo",
            ])
            .output();
        let output = match built {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: grub-mkimage did not run ({error})");
                return;
            }
        };
        if !output.status.success() {
            eprintln!(
                "skip: grub-mkimage could not build the test core.img ({})",
                output.status
            );
            return;
        }
        let core_img = std::fs::read(&core_path).expect("the test core reads back");
        let cfg = b"set timeout=0\necho GRUB2-OK\n";
        let iso = grub2_boot_iso(&boot_img, &core_img, cfg);
        let iso_len = iso.len() as u64;
        let (_scratch, disk) = boot_disk(&iso, iso_len, rufus_proto::BootloaderMode::Grub2, true);
        // Fresh boot: the banner and the shell prove the record
        // handed off to the core and the core reached `normal`.
        let screen = qemu::capture(&disk, std::time::Duration::from_secs(10))
            .expect("qemu captures the screen");
        qemu::log(&screen);
        assert!(
            screen.iter().any(|line| line.contains("GNU GRUB")),
            "the grub banner shows: {screen:?}"
        );
        assert!(
            screen.iter().any(|line| line.contains("grub>")),
            "the grub shell shows: {screen:?}"
        );
        // Driven shell: `configfile` loads the `grub.cfg` the Write
        // step copied, proving the booted core reads the partition.
        // (Boot-time `echo` output does not survive to the captured
        // screen — the line below is what a driven load shows.)
        let keys = [
            "c", "o", "n", "f", "i", "g", "f", "i", "l", "e", "spc", "slash", "b", "o", "o", "t",
            "slash", "g", "r", "u", "b", "slash", "g", "r", "u", "b", "dot", "c", "f", "g", "ret",
        ];
        let screen = qemu::capture_keys(&disk, std::time::Duration::from_secs(9), &keys)
            .expect("qemu drives the shell");
        qemu::log(&screen);
        assert!(
            screen.iter().any(|line| line.contains("GRUB2-OK")),
            "the copied config runs: {screen:?}"
        );
    }
}
