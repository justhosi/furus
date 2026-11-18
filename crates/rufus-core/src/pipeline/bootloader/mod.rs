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
//! data partition). Explicit `Windows` is mount-based instead: it
//! formats the ESP as FAT32, applies the WIM image onto the mounted
//! NTFS data partition, builds both BCD stores, places the boot files
//! and sets the offline SAN policy — no image tree, no FAT32 data
//! volume (the WIM itself is the image).
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
//!
//! S23 splits the installers into focused submodules so each arm stays
//! reviewable: [`syslinux`], [`grub2`], [`grub4dos`], [`dos_kolibri`]
//! (FreeDOS, KolibriOS and MS-DOS), [`uefi_ntfs`] and [`windows`]. This
//! module keeps the shared dispatch ([`install_tree`], [`run`]), the
//! [`Installed`] report vocabulary and the post-MBR-gap bound the BIOS
//! arms share. No on-disk behaviour or public item changed in the split:
//! the submodules stay private, [`run`] and [`install_tree`] keep their
//! signatures, and callers still use `bootloader::…`.

use std::path::Path;

use rufus_proto::BootloaderMode;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;

use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::grub2 as boot_grub2;
use crate::boot::msdos::PatchState;
use crate::boot::syslinux as boot_syslinux;
use crate::boot::syslinux::Family;
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
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::pipeline::target::Target;
use crate::udf::UdfReader;

mod dos_kolibri;
mod grub2;
mod grub4dos;
mod syslinux;
mod uefi_ntfs;
mod windows;

use dos_kolibri::install_freedos;
use dos_kolibri::install_kolibri;
use dos_kolibri::install_msdos;
use dos_kolibri::run_msdos;
use grub2::install_grub2;
use grub4dos::install_grub4dos;
use syslinux::install_syslinux;
use uefi_ntfs::run_uefi_ntfs;
use windows::run_windows;

use dos_kolibri::freedos_summary;
use dos_kolibri::kolibri_summary;
use dos_kolibri::msdos_summary;
use uefi_ntfs::uefi_ntfs_summary;

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
pub(super) struct DiskView<'a> {
    target: &'a mut dyn Target,
}

impl<'a> DiskView<'a> {
    pub(super) fn new(target: &'a mut dyn Target) -> Self {
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
/// UEFI GRUB file the GRUB arms place.) `Windows` passes here too —
/// its mount-based arm lives in [`run`], not [`install_tree`], which
/// refuses it through its own explicit arm. Every other mode is wired
/// today, so this always passes for them; it stays as the shared gate
/// so a future variant fails closed in both entry points.
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
        | BootloaderMode::MsDos
        | BootloaderMode::Windows => Ok(()),
    }
}

/// Resolve the post-MBR gap end for `{owner}` through the same
/// helper Mkpart stamps with
/// ([`single_data_window`](crate::part::plan::single_data_window)):
/// the first data partition's start offset, so the numbers cannot
/// drift from the table on the disk. Refuses without a recorded
/// table — no table means no honest bound — and propagates the
/// planner's own refusals.
pub(super) fn gap_end(
    owner: &str,
    table: Option<TableKind>,
    sector_size: u32,
    total: u64,
) -> Result<u64> {
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
/// directly and a tree install can never serve it. `Windows` refuses
/// here as invalid: the installer exists but is mount-based (the WIM
/// applies onto the mounted data and ESP partitions — see
/// [`run_windows`]), so [`run`] wires it directly and no tree install
/// can serve it either. Any future variant refuses through the shared [`check_mode`]
/// table before reaching here; the trailing `other` arm stays as
/// fail-closed invalid, unreachable today.
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
        if let Some(located) = boot_syslinux::locate(source)? {
            let mut installed = install_syslinux(source, fat, &located, cancelled, load)?;
            prepend_log(&mut installed, probes);
            return Ok(installed);
        }
        probes.push("auto: probing grub2".to_string());
        if let Some(payloads) = boot_grub2::payloads(source)? {
            let mut installed = install_grub2(source, fat, disk, &payloads, table, cancelled)?;
            prepend_log(&mut installed, probes);
            return Ok(installed);
        }
        probes.push("auto: probing grub4dos".to_string());
        if boot_syslinux::read(source, &[], "grldr")?.is_some() {
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
            let Some(located) = boot_syslinux::locate(source)? else {
                return Err(CoreError::invalid(
                    "no syslinux payloads found in the image: refusing a syslinux install",
                ));
            };
            install_syslinux(source, fat, &located, cancelled, load)
        }
        BootloaderMode::Grub2 => {
            let Some(payloads) = boot_grub2::payloads(source)? else {
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
        // Mount-based by design (see `run_windows`): the WIM
        // applies onto the mounted data and ESP partitions with no
        // tree and no FAT32 data volume, so the tree core refuses it
        // and `run` wires it directly.
        BootloaderMode::Windows => Err(CoreError::invalid(
            "windows installs the WIM image onto the mounted data and ESP partitions, not through the filesystem tree: refusing a tree install".to_string(),
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

/// Filesystem name in plan vocabulary (`fat32`, `exfat`, ...).
pub(super) fn filesystem_name(filesystem: &Filesystem) -> &'static str {
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
/// detection record). `Windows` takes the mount-based path
/// ([`run_windows`]) before the gates below: it formats the ESP,
/// applies the WIM onto the mounted partitions and reports one
/// summary line — no FAT32 data volume, no image tree. A future
/// variant would refuse up front through the shared [`check_mode`]
/// table, never reaching the image or the device, then
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
    if *mode == BootloaderMode::Windows {
        // Mount-based arm, before the FAT32 gate and the image-tree
        // setup below: the WIM applies onto the mounted data and ESP
        // partitions, so neither the tree nor the FAT32 data volume is
        // opened here. Every other mode keeps today's path
        // byte-for-byte.
        return run_windows(ctx, image);
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
mod tests;

#[cfg(test)]
pub(crate) mod end_to_end;
