//! The bootloader step: Syslinux, GRUB2 and GRUB4DOS installation
//! from the image tree, plus UEFI GRUB placement.
//!
//! What is wired today (FAT32 volumes only): explicit `Syslinux` mode
//! installs one Syslinux family; explicit `Grub2` installs the BIOS
//! record and places a UEFI image when the tree carries one; explicit
//! `Grub4dos` writes the embedded MBR/SBR and the root loader; `Auto`
//! takes the first match of syslinux, grub2, grub4dos, logging each
//! probe. `UefiNtfs` stays not implemented: it names S20's UEFI:NTFS
//! partition, not the UEFI GRUB file this step places. `Freedos`
//! refuses the same way.
//!
//! The obsolete-module replacement ([`Obsolete`](crate::boot::syslinux::Obsolete))
//! is deliberately not applied here: no newer module bytes are
//! bundled, so there is nothing honest to substitute with — declared
//! gap, same as the copy wiring leaves it.
//!
//! Write order keeps slice 3's "boot code last" invariant per arm:
//! syslinux lays companions, config, then the boot record; grub2
//! places the UEFI file, then the core image, then the MBR sector;
//! grub4dos writes the root loader, then the SBR, then the MBR sector.
//! A refused step leaves no boot code behind. The BIOS payloads never
//! reach past the post-MBR gap: each arm bounds its core/SBR end
//! through the same helper Mkpart stamps with, before any write.
//!
//! Payload provenance is honest per arm: GRUB2 ships no embedded
//! fallback — `boot.img`, `core.img` and the UEFI image come only
//! from the image tree — while GRUB4DOS carries its record and loader
//! as embedded resources 450/451.

use std::path::Path;

use rufus_proto::BootloaderMode;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;

use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::grub2;
use crate::boot::grub4dos;
use crate::boot::syslinux;
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
/// entry point. (`UefiNtfs` names S20's UEFI:NTFS partition, not the
/// UEFI GRUB file the GRUB arms place.)
fn check_mode(mode: &BootloaderMode) -> Result<()> {
    match mode {
        BootloaderMode::None
        | BootloaderMode::Syslinux
        | BootloaderMode::Auto
        | BootloaderMode::Grub2
        | BootloaderMode::Grub4dos => Ok(()),
        BootloaderMode::UefiNtfs => Err(CoreError::NotImplemented {
            what: "uefi_ntfs bootloader installation (wired in a later slice)",
        }),
        BootloaderMode::Freedos => Err(CoreError::NotImplemented {
            what: "freedos bootloader installation (wired in a later slice)",
        }),
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
    /// GRUB4DOS install: SBR byte count, whether the embedded loader
    /// was written (`true`) or an existing root loader was kept
    /// (`false`), and log lines.
    Grub4dos {
        sbr_bytes: u64,
        embedded_grldr: bool,
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
            | Installed::Grub4dos { messages, .. } => messages,
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
        | Installed::Grub4dos { messages, .. } => {
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
/// plus the root loader; `Auto` takes the first match of syslinux,
/// grub2, grub4dos. Every other mode refuses as not implemented,
/// naming itself.
///
/// `table` is the recorded partition-table kind the BIOS arms bound
/// their post-MBR gap through (see [`gap_end`]); the Syslinux-only
/// paths ignore it.
pub(crate) fn install_tree(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    disk: &mut dyn Volume,
    mode: &BootloaderMode,
    table: Option<TableKind>,
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
                    "no syslinux payloads found in the image: refusing a syslinux install (grub, grub4dos and uefi auto-detection arrive in a later slice)",
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
        // `None` returned above; unwired modes refused in
        // `check_mode`. This names the mode rather than assuming the
        // match is exhaustive forever.
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

/// GRUB4DOS branch: the root loader first, then the MBR+SBR (loader
/// before boot code, the `install_boot` torn rule). The loader bytes
/// are embedded (resource 451) unless the volume already carries a
/// root loader — however it got there, including the copy step
/// placing the image's own `/grldr` — in which case the existing file
/// is kept, since the loader refuses to overwrite.
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
    let embedded = !fat
        .list_dir("/")?
        .iter()
        .any(|entry| entry.short_name == "GRLDR");
    let mut messages: Vec<String> = Vec::new();
    if embedded {
        let grldr = load(Resource::Grub4DosCore)?;
        grub4dos::install_loader(fat, grldr.bytes())?;
        messages.push(format!(
            "writing embedded grldr ({} bytes)",
            grldr.bytes().len(),
        ));
    } else {
        messages.push("root /grldr already present, keeping it".to_string());
    }
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
        embedded_grldr: embedded,
        messages,
    })
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

/// Run the bootloader step: one wired arm from the image tree onto
/// the freshly formatted data partition (and, for the BIOS arms, the
/// whole disk behind it).
///
/// `None` reports one info line and writes nothing. Unwired modes
/// refuse up front through the shared [`check_mode`] table (they never
/// reach the image or the device), then non-FAT32 filesystems refuse
/// naming the plan filesystem, then the image tree opens exactly like
/// `write::run_copy` does. The partition and the whole-disk target
/// open next; a cancellation check follows before the first write (no
/// partial-cleanup machinery is needed — the directory tree can be
/// reformatted, so a torn step reports and the next run starts
/// clean), then the install, one flush of the partition, and the run
/// message. The disk-side stores flush inside their own install
/// calls.
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &BootloaderMode,
    image: &ImageRef,
    filesystem: &Filesystem,
) -> Result<()> {
    if *mode == BootloaderMode::None {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: "bootloader: none requested, leaving the image boot code untouched".to_string(),
        });
        return Ok(());
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
        Installed::Grub4dos {
            sbr_bytes,
            embedded_grldr,
            ..
        } => {
            let grldr = if *embedded_grldr {
                "embedded grldr written"
            } else {
                "existing /grldr kept"
            };
            ctx.reporter.event(Event::Message {
                level: "info",
                text: format!("installed grub4dos boot record ({sbr_bytes} sbr bytes, {grldr})"),
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
    fn bare_tree_refuses_with_the_later_slice_note() {
        // Nothing Syslinux-like anywhere: the explicit mode refuses
        // naming the gap instead of pretending GRUB support.
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
        assert!(text.contains("later slice"), "names the gap: {text}");
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
    fn unimplemented_modes_name_themselves() {
        let source = syslinux_604_tree();
        for (mode, name) in [
            (BootloaderMode::UefiNtfs, "uefi_ntfs"),
            (BootloaderMode::Freedos, "freedos"),
        ] {
            let (_backing, mut fat) = formatted();
            let error =
                tree_install(&source, &mut fat, &mode).expect_err("an unwired mode refuses");
            assert!(
                matches!(error, CoreError::NotImplemented { .. }),
                "a mode refusal is NotImplemented: {error:?}"
            );
            let text = error.to_string();
            assert!(text.contains(name), "names the mode: {text}");
            assert!(text.contains("later slice"), "names the gap: {text}");
        }
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

    /// A [`RunContext`](crate::pipeline::steps::RunContext) over the
    /// counting opener, for the `run` tests below.
    fn run_context<'a>(
        opener: &'a CountingOpener,
        reporter: &'a mut Recorder,
    ) -> crate::pipeline::steps::RunContext<'a> {
        crate::pipeline::steps::RunContext {
            opener,
            target: None,
            table: None,
            partitioned: false,
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
        )
        .expect("none always runs");
        assert_eq!(partitions.get(), 0, "the partition never opens");
        assert_eq!(reporter.events.len(), 1, "one info event at most");
    }

    #[test]
    fn run_unimplemented_mode_never_reaches_the_image() {
        let partitions = Rc::new(Cell::new(0usize));
        let opener = CountingOpener {
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context(&opener, &mut reporter);
        let error = run(
            &mut ctx,
            &BootloaderMode::Freedos,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Fat32,
        )
        .expect_err("freedos is not wired");
        assert!(
            matches!(error, CoreError::NotImplemented { .. }),
            "a mode refusal is NotImplemented: {error:?}"
        );
        assert_eq!(partitions.get(), 0, "the partition never opens");
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
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        let Installed::Grub4dos {
            sbr_bytes,
            embedded_grldr,
            messages,
        } = installed
        else {
            panic!("a grub4dos install reports the Grub4dos variant");
        };
        assert!(!embedded_grldr, "the existing loader wins");
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
    fn grub4dos_writes_the_embedded_grldr() {
        let (source, _boot, _core) = grub_tree(false);
        let (backing, mut fat) = formatted();
        let (mut target, _before) = prefilled_disk();
        let mut disk = DiskView::new(&mut target);
        let installed = install_tree(
            &source,
            &mut fat,
            &mut disk,
            &BootloaderMode::Grub4dos,
            Some(TableKind::Mbr),
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        let Installed::Grub4dos { embedded_grldr, .. } = installed else {
            panic!("a grub4dos install reports the Grub4dos variant");
        };
        assert!(embedded_grldr, "the embedded loader lands");
        let expected = asset_loader(Resource::Grub4DosCore)
            .expect("the loader loads")
            .bytes()
            .to_vec();
        let back = fat.read_file("/grldr").expect("the loader reads");
        assert_eq!(back, expected, "resource 451 lands byte-identical");
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(
            listed.iter().any(|entry| entry.short_name == "GRLDR"),
            "the root lists GRLDR"
        );
        fat.flush().expect("the partition flushes");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("grub4dos.img");
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
            "fsck.fat -n exits 0 after the grub4dos install ({})",
            output.status
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
mod end_to_end {
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

    /// Build the fixture ISO: primary + boot + terminator descriptors,
    /// a root holding `ISOLINUX/`, and six payload files under it, from
    /// the shared `copy::fixture` sector builders.
    fn syslinux_iso() -> Vec<u8> {
        use crate::copy::source::fixture::*;
        const ROOT: u32 = 20;
        const DIR: u32 = 21;
        const BIN: u32 = 22;
        const CFG: u32 = 23;
        const C32: u32 = 24;
        const MENU: u32 = 25;
        const VESA: u32 = 26;
        const LIB: u32 = 27;
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
            // Lowercase on purpose: the engine resolves payload
            // directory components exactly (only file names fold
            // case), so an upper-case directory is never located.
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
    /// idempotent across reruns.
    fn seed_exe_assets() {
        let exe = std::env::current_exe().expect("the test exe resolves");
        let dir = exe
            .parent()
            .expect("the exe has a dir")
            .join("../share/rufus-linux/assets");
        std::fs::create_dir_all(&dir).expect("the asset dir creates");
        for name in ["RCDATA_402.bin", "RCDATA_403.bin"] {
            let bytes = std::fs::read(resources_dir().join(name)).expect("the pinned asset reads");
            std::fs::write(dir.join(name), &bytes).expect("the asset seeds");
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
            },
            steps: vec![
                rufus_proto::Step::Wipe,
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Mkpart {
                    scheme: rufus_proto::Scheme::Mbr,
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
}
