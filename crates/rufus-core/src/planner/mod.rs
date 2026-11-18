//! Shared provisional plan construction (S23).
//!
//! The steps describe *what* happens in order — wipe, table, partition,
//! format, write, bootloader, finalise — against the options the user
//! picked. They are deliberately high-level: exact LBA placement,
//! alignment, gaps, engine arguments and progress mapping are computed by
//! the S17 executor against the real device geometry. Nothing here touches
//! a device; this module only *constructs* a plan object.
//!
//! The builder lives in `rufus-core` so the CLI and the S24 GUI call the
//! exact same partition/filesystem/bootloader selection rules. Platform
//! probing stays outside: callers supply a [`DeviceProbe`] (filled by
//! `rufus-linux` from sysfs, or by the CLI from the command line) and an
//! already-inspected [`rufus_proto::ImageRef`], so this crate never
//! depends on `rufus-linux` and never touches `/sys`.
//!
//! Device grading rules (PLAN §6 preview semantics):
//!
//! * `--dry-run` — a missing or non-block device is allowed, reported in
//!   the plan with `block_device: false`, so plans can be produced
//!   anywhere. Never a reason to fail.
//! * otherwise — a missing device is a device error (CLI exit 2) and an
//!   existing non-block device is refused outright (CLI exit 3, safety).
//!
//! After grading, the mapper fields are filled from the discovery facts
//! when the target was found on the given sysfs root: `size_bytes`,
//! `serial`, `model`, `sysfs`, and `block_device`. The enrichment is
//! deliberately non-fatal — a missing root, a vanished class directory or
//! an unmatched path (e.g. `/dev/null`, which is what the plan golden
//! uses) keeps the fields `None`, exactly the S03 plan shape.

use std::fmt;
use std::path::Path;

use rufus_proto::BootloaderMode;
use rufus_proto::DeviceRef;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;
use rufus_proto::Layout;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Step;
use rufus_proto::WriteMode;

/// The `--bootloader` selector: which installer the plan's bootloader
/// step carries. `Auto` keeps the write-mode pairing (a `Dd` write
/// already laid the image's own boot code, so no installer; a `Copy`
/// write needs one); any explicit mode is emitted verbatim, except
/// that `Windows` additionally selects the Windows To Go layout with
/// an NTFS data partition and plans no write step (the bootloader
/// step applies the WIM onto the mounted data partition).
/// `UefiNtfs` additionally selects the two-partition UEFI:NTFS layout
/// and forces `Copy` (the shim boots an NTFS or exFAT data partition
/// the image tree populates); every other mode stays on the single layout.
///
/// This is the platform-agnostic selector. The CLI wraps it in a
/// `clap::ValueEnum` of the same shape and converts at the boundary, so
/// no UI dependency leaks into core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootloaderOpt {
    /// Pair with the write mode (`Dd` → none, `Copy` → auto).
    Auto,
    /// Syslinux 4.x/6.x.
    Syslinux,
    /// GNU GRUB 2.
    Grub2,
    /// GRUB4DOS.
    Grub4dos,
    /// UEFI:NTFS helper partition (NTFS or exFAT data partition, copy mode).
    UefiNtfs,
    /// FreeDOS.
    Freedos,
    /// KolibriOS.
    Kolibri,
    /// MS-DOS from the user's own system files (`--msdos-dir`): no
    /// write step is planned, since `IO.SYS` must be the first root
    /// entry of the fresh volume.
    MsDos,
    /// Windows To Go: the GPT `WindowsToGo` layout and an NTFS data
    /// partition with no write step (`--filesystem` is overridden; a
    /// `--scheme mbr` plan is refused later by the layout, which is
    /// GPT-only). The bootloader step applies the WIM itself.
    Windows,
    /// No bootloader (plain data media).
    None,
}

impl BootloaderOpt {
    /// The bootloader mode the plan's bootloader step carries.
    #[must_use]
    pub fn mode(self) -> BootloaderMode {
        match self {
            BootloaderOpt::Auto => BootloaderMode::Auto,
            BootloaderOpt::Syslinux => BootloaderMode::Syslinux,
            BootloaderOpt::Grub2 => BootloaderMode::Grub2,
            BootloaderOpt::Grub4dos => BootloaderMode::Grub4dos,
            BootloaderOpt::UefiNtfs => BootloaderMode::UefiNtfs,
            BootloaderOpt::Freedos => BootloaderMode::Freedos,
            BootloaderOpt::Kolibri => BootloaderMode::Kolibri,
            BootloaderOpt::MsDos => BootloaderMode::MsDos,
            BootloaderOpt::Windows => BootloaderMode::Windows,
            BootloaderOpt::None => BootloaderMode::None,
        }
    }

    /// The partition layout the plan's mkpart step stamps.
    #[must_use]
    pub fn layout(self) -> Layout {
        match self {
            BootloaderOpt::UefiNtfs => Layout::UefiNtfs,
            BootloaderOpt::Windows => Layout::WindowsToGo,
            _ => Layout::Single,
        }
    }
}

/// Options as accepted from a front end (the CLI flags or the GUI form).
#[derive(Debug)]
pub struct Options {
    /// Partition table scheme.
    pub scheme: rufus_proto::Scheme,
    /// Firmware target.
    pub target: rufus_proto::Target,
    /// Data filesystem.
    pub filesystem: rufus_proto::Filesystem,
    /// Volume label (`None` = executor-chosen default later).
    pub label: Option<String>,
    /// Cluster size in bytes (`None` = executor-chosen default later).
    pub cluster_bytes: Option<u32>,
    /// Quick (metadata-only) format; the surface case is documented in the
    /// `--help` text.
    pub quick_format: bool,
    /// Copy an ISO/UDF image's file tree instead of writing the image
    /// byte-for-byte (`--iso-mode`): the recommended mode for bootable
    /// sticks, whose bootloader step then installs from the tree.
    pub iso_mode: bool,
    /// Bootloader selector (`--bootloader`): `auto` pairs with the
    /// write mode, an explicit mode is emitted verbatim, and
    /// `uefi-ntfs` additionally selects the UEFI:NTFS layout and
    /// forces copy mode (refused without an NTFS or exFAT filesystem
    /// in [`build`]; `freedos` and `kolibri` are refused without a
    /// FAT32 filesystem there). `windows` selects the Windows To Go
    /// layout with an NTFS data partition and plans no write step:
    /// the `--filesystem` flag is overridden (the plan records NTFS)
    /// and a `--scheme mbr` plan is refused later by the layout,
    /// which is GPT-only. `msdos` plans no write step at all
    /// (see [`steps`]) and is refused without a FAT32 filesystem and
    /// without a non-empty [`Options::msdos_dir`] there.
    pub bootloader: BootloaderOpt,
    /// Directory holding the user-supplied MS-DOS system files
    /// (`--msdos-dir`); only meaningful with the `msdos` bootloader,
    /// refused with any other mode in [`build`]. An empty string
    /// counts as absent, so only a non-empty path rides into the
    /// plan's `msdos_dir`.
    pub msdos_dir: Option<String>,
    /// Bad-block scan.
    pub bad_blocks: bool,
    /// Read-back verification.
    pub verify: bool,
    /// Persistence partition.
    pub persistence: bool,
    /// "Show all devices" was on.
    pub show_all: bool,
    /// Serial the user typed to confirm a non-removable device (`None` =
    /// no confirmation); accepted only together with `show_all` and
    /// trimmed once at CLI acceptance. Rides into the plan JSON so the
    /// S06 helper can tell show-all with a typed serial apart from
    /// show-all alone (PLAN §6 rule 4).
    pub confirmed_serial: Option<String>,
}

/// The platform-supplied facts about the selected target path.
///
/// `rufus-linux` fills this from `std::fs::metadata` plus sysfs discovery;
/// the GUI can fill it straight from a selected [`Device`] model and the
/// CLI from the command line. `rufus-core` only grades the facts, so the
/// crate keeps its platform boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProbe {
    /// Device path as presented, e.g. `/dev/sdb`.
    pub path: String,
    /// Whether the path exists at all (`metadata` succeeded).
    pub exists: bool,
    /// Whether an existing path is a block device.
    pub block_device: bool,
    /// `metadata`'s error text when [`DeviceProbe::exists`] is false.
    pub error: Option<String>,
    /// Discovery facts when the path matched a discovered device.
    pub facts: Option<DeviceFacts>,
}

/// The mapper fields discovery can honestly fill for a target device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceFacts {
    /// Device capacity in bytes.
    pub size_bytes: u64,
    /// Stable serial, when the device reports one.
    pub serial: Option<String>,
    /// Human-readable model, when the device reports one.
    pub model: Option<String>,
    /// `/sys/class/block/<name>` path.
    pub sysfs: String,
}

impl DeviceProbe {
    /// Probe facts for a path the front end has only just resolved: no
    /// metadata check and no discovery, exactly the dry-run fixture shape.
    #[must_use]
    pub fn unknown(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            exists: false,
            block_device: false,
            error: None,
            facts: None,
        }
    }
}

/// A plan-construction refusal, classified for a front end's exit table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The target device is missing or unusable (CLI exit 2).
    Device(String),
    /// The target exists but is not a block device (CLI exit 3, safety).
    Safety(String),
    /// The options or bootloader/filesystem pairing are unusable
    /// (CLI exit 1).
    Usage(String),
    /// The confirm hash could not be recomputed (CLI exit 4, I/O class;
    /// practically unreachable for this JSON-native schema).
    Confirm(String),
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::Device(message)
            | PlanError::Safety(message)
            | PlanError::Usage(message)
            | PlanError::Confirm(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PlanError {}

/// Grade the target device path into a [`DeviceRef`], enriched with the
/// discovery facts the probe carries.
///
/// `dry_run` relaxes the existence and block-device checks (PLAN §6): a
/// missing or non-block path is planned with `block_device: false`.
/// Without it a missing path is a [`PlanError::Device`] and an existing
/// non-block path a [`PlanError::Safety`] refusal.
pub fn device_ref(probe: &DeviceProbe, dry_run: bool) -> Result<DeviceRef, PlanError> {
    if !probe.exists && !dry_run {
        let detail = probe.error.as_deref().unwrap_or("the path does not exist");
        return Err(PlanError::Device(format!(
            "device '{}': {detail} (does the path exist? use --dry-run to plan anyway)",
            probe.path
        )));
    }
    if probe.exists && !probe.block_device && !dry_run {
        return Err(PlanError::Safety(format!(
            "'{}' is not a block device; refusing (safety). Use --dry-run to build a plan for it without touching anything.",
            probe.path
        )));
    }
    let mut device = DeviceRef {
        path: probe.path.clone(),
        block_device: probe.exists && probe.block_device,
        size_bytes: None,
        serial: None,
        model: None,
        sysfs: None,
    };

    // Discovery is best-effort. An unmatched path keeps the all-`None`
    // mapper fields and the CLI/golden tests stay deterministic.
    if let Some(found) = &probe.facts {
        // A discoverable device *is* a block device on its root, so the
        // fact rides into the plan (S06's helper re-checks it anyway).
        device.block_device = true;
        device.size_bytes = Some(found.size_bytes);
        device.serial = found.serial.clone();
        device.model = found.model.clone();
        device.sysfs = Some(found.sysfs.clone());
    }
    Ok(device)
}

/// How the image transfers: sniffed ISO, raw and compressed streams go
/// by dd (the pipeline streams the compressed kinds through their host
/// tool), structured containers by copy. Detection is authoritative: a
/// sniffed ISO or raw stream is dd-ed whatever the name, and a sniffed
/// container (WIM, ...) is *copied* even when named `.iso` — a Windows
/// `.iso` whose bytes sniff as WIM must not go to the raw writer. The
/// extension is only a tiebreaker when the content could not be
/// identified at all ([`ImageKind::Unknown`]): `iso`/`img`/`raw` names
/// conventionally mean sector images worth dd-ing, anything else is a
/// job for a later-slice reader (WIM: wimlib in S21). The plan's mode
/// is final: the executor runs whatever mode lands here.
/// `iso_mode` (the `--iso-mode` flag) flips tree-walkable images to
/// copy: `Iso`/`Raw` kinds, and `Unknown` kinds with a ddable
/// extension, become `Copy` so the file tree (and the bootloader step
/// after it) serves the stick. Compressed and container kinds are
/// unchanged by the flag — a compressed ISO cannot be walked without
/// decoding, and the write arm refuses that combination with a clear
/// message.
#[must_use]
pub fn write_mode(image: &Path, kind: &ImageKind, iso_mode: bool) -> WriteMode {
    if iso_mode {
        match kind {
            ImageKind::Iso | ImageKind::Raw => return WriteMode::Copy,
            ImageKind::Unknown => {
                let ddable = image
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("iso")
                            || ext.eq_ignore_ascii_case("img")
                            || ext.eq_ignore_ascii_case("raw")
                    });
                if ddable {
                    return WriteMode::Copy;
                }
            }
            _ => {}
        }
    }
    match kind {
        // Content is authoritative for the streamable kinds: sector
        // images raw, archives through the pipeline's host-tool
        // streaming (S17 slice 5).
        ImageKind::Iso
        | ImageKind::Raw
        | ImageKind::Gzip
        | ImageKind::Xz
        | ImageKind::Bzip2
        | ImageKind::Zstd => WriteMode::Dd,
        // Unidentified content: fall back to the extension as the
        // user-declared hint about the byte layout.
        ImageKind::Unknown => {
            let ddable = image
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("iso")
                        || ext.eq_ignore_ascii_case("img")
                        || ext.eq_ignore_ascii_case("raw")
                });
            if ddable {
                WriteMode::Dd
            } else {
                WriteMode::Copy
            }
        }
        // Every other sniffed container needs its reader/copier (WIM
        // through wimlib in S21, VHD/VHDX/FFU through their parsers, qcow2
        // through its reader in S15, PE files as
        // payload parts).
        ImageKind::Wim
        | ImageKind::Vhd
        | ImageKind::Vhdx
        | ImageKind::Ffu
        | ImageKind::Qcow2
        | ImageKind::Pe => WriteMode::Copy,
    }
}

/// The ordered provisional steps for one image/device combination.
///
/// With `Auto` the bootloader step follows the write mode: a `Dd`
/// write already laid the image's own boot code, so the plan emits
/// [`BootloaderMode::None`]; a `Copy` write needs the installer, so it
/// emits [`BootloaderMode::Auto`]. An explicit selector is emitted
/// verbatim instead, except that `UefiNtfs` forces [`WriteMode::Copy`]
/// (the shim boots a populated NTFS or exFAT data partition).
/// `Windows` plans no `Write` step: the bootloader step applies the
/// WIM onto the mounted NTFS data partition itself, and no tree
/// reader takes a WIM (so a copy step could only refuse).
/// The mkpart step carries the selector's layout (`UefiNtfs` for
/// `uefi-ntfs`, `WindowsToGo` for `windows`, `Single` otherwise),
/// and a `windows` plan formats the data partition NTFS whatever
/// `--filesystem` says: the `--filesystem` flag is overridden for
/// this mode (the ESP is separate and is not this step). A `windows`
/// plan with `--scheme mbr` still plans here and is refused later by
/// the layout, which is GPT-only.
///
/// `MsDos` plans no `Write` step: MS-DOS reads `IO.SYS` from the
/// front of the root directory over one contiguous cluster chain, so
/// the installer must place it as the first root entry of the fresh
/// volume — a byte-for-byte image write would own the volume instead
/// and leave no honest first slot. The `--image` reference stays
/// required (detection still runs) but is unused by such a plan; the
/// installer reads the user's `--msdos-dir` files, never the image.
#[must_use]
pub fn steps(image: &Path, kind: &ImageKind, options: &Options) -> Vec<Step> {
    let (write, bootloader) = match options.bootloader {
        BootloaderOpt::MsDos => (None, BootloaderMode::MsDos),
        // A Windows To Go plan carries no write step: the bootloader
        // step applies the WIM onto the mounted NTFS data partition,
        // and no tree reader takes a WIM (so a copy step could only refuse).
        BootloaderOpt::Windows => (None, BootloaderMode::Windows),
        BootloaderOpt::Auto => {
            let write = write_mode(image, kind, options.iso_mode);
            let needs_installer = write == WriteMode::Copy;
            (
                Some(write),
                if needs_installer {
                    BootloaderMode::Auto
                } else {
                    BootloaderMode::None
                },
            )
        }
        selected => {
            let write = if selected == BootloaderOpt::UefiNtfs {
                WriteMode::Copy
            } else {
                write_mode(image, kind, options.iso_mode)
            };
            (Some(write), selected.mode())
        }
    };
    // A Windows To Go plan formats the data partition NTFS whatever
    // `--filesystem` says (the flag is overridden for this mode; the
    // ESP is separate and is not this step).
    let filesystem = if options.bootloader == BootloaderOpt::Windows {
        Filesystem::Ntfs
    } else {
        options.filesystem.clone()
    };
    let mut planned = vec![
        Step::Wipe,
        Step::Mklabel {
            scheme: options.scheme.clone(),
        },
        Step::Mkpart {
            scheme: options.scheme.clone(),
            layout: options.bootloader.layout(),
        },
        Step::Mkfs {
            filesystem,
            label: options.label.clone(),
            cluster_bytes: options.cluster_bytes,
            quick: options.quick_format,
        },
    ];
    // Only the MS-DOS and Windows To Go plans skip the transfer: the
    // former must place IO.SYS first on the fresh volume, the latter
    // applies the WIM in the bootloader step (see above).
    if let Some(mode) = write {
        planned.push(Step::Write { mode });
    }
    planned.push(Step::Bootloader { mode: bootloader });
    planned.push(Step::Finalize);
    planned
}

/// Build and seal the provisional [`Plan`] for `image`/`device`.
///
/// The device must already have been graded with [`device_ref`]. The plan
/// carries no write instructions beyond the step list and is approved
/// neither by the user nor by the helper; safety decisions per PLAN §6
/// happen in S05/S06. The confirm hash is recomputed here and a
/// serialisation failure (practically impossible for this JSON-native
/// schema) is surfaced as [`PlanError::Confirm`], fail closed (PLAN §2).
/// A `uefi-ntfs` bootloader without an NTFS or exFAT data filesystem
/// is refused here, before any step is built: the shim boots an NTFS
/// or exFAT partition the image tree populates, so any other
/// filesystem is a usage error. A `windows` bootloader overrides the
/// `--filesystem` flag instead: the plan records NTFS in both the
/// options and the mkfs step, whatever was asked. A `windows` plan
/// with `--scheme mbr` still seals here and is refused later by the
/// layout, which is GPT-only. A `freedos` or `kolibri` bootloader
/// without a FAT32 data filesystem is refused the same way: both
/// installers write a FAT32 volume, so any other filesystem is a
/// usage error naming the mode and the filesystem. An `msdos`
/// bootloader is refused without a FAT32 data filesystem the same
/// way, and without a non-empty `msdos_dir` (the user's `IO.SYS`,
/// `MSDOS.SYS` and `COMMAND.COM`, which licensing keeps out of the
/// bundle); an `msdos_dir` with any other bootloader mode is
/// refused, since no other installer reads it.
pub fn build(device: DeviceRef, image: ImageRef, options: &Options) -> Result<Plan, PlanError> {
    if options.bootloader == BootloaderOpt::UefiNtfs
        && options.filesystem != Filesystem::Ntfs
        && options.filesystem != Filesystem::Exfat
    {
        return Err(PlanError::Usage(
            "UEFI:NTFS needs an NTFS or exFAT data partition; choose --filesystem ntfs or exfat"
                .to_owned(),
        ));
    }
    if options.bootloader == BootloaderOpt::Freedos && options.filesystem != Filesystem::Fat32 {
        return Err(PlanError::Usage(
            "FreeDOS needs a FAT32 data partition; choose --filesystem fat32".to_owned(),
        ));
    }
    if options.bootloader == BootloaderOpt::Kolibri && options.filesystem != Filesystem::Fat32 {
        return Err(PlanError::Usage(
            "KolibriOS needs a FAT32 data partition; choose --filesystem fat32".to_owned(),
        ));
    }
    if options.bootloader == BootloaderOpt::MsDos && options.filesystem != Filesystem::Fat32 {
        return Err(PlanError::Usage(
            "MS-DOS needs a FAT32 data partition; choose --filesystem fat32".to_owned(),
        ));
    }
    // An empty directory string counts as absent (see
    // `Options::msdos_dir`), so only a non-empty path rides into the
    // plan.
    let msdos_dir = options.msdos_dir.clone().filter(|dir| !dir.is_empty());
    if options.bootloader == BootloaderOpt::MsDos && msdos_dir.is_none() {
        return Err(PlanError::Usage(
            "MS-DOS needs --msdos-dir with the user's IO.SYS, MSDOS.SYS and COMMAND.COM".to_owned(),
        ));
    }
    if options.bootloader != BootloaderOpt::MsDos && msdos_dir.is_some() {
        return Err(PlanError::Usage(
            "--msdos-dir only applies to --bootloader msdos".to_owned(),
        ));
    }
    let steps = steps(Path::new(&image.path), &image.kind, options);
    // A Windows To Go plan records NTFS whatever `--filesystem` said
    // (see `steps`): options and the mkfs step agree.
    let filesystem = if options.bootloader == BootloaderOpt::Windows {
        Filesystem::Ntfs
    } else {
        options.filesystem.clone()
    };
    let mut plan = Plan {
        version: PLAN_VERSION,
        created_by: crate::user_agent(),
        device,
        image,
        options: rufus_proto::Options {
            scheme: options.scheme.clone(),
            target: options.target.clone(),
            filesystem,
            label: options.label.clone(),
            cluster_bytes: options.cluster_bytes,
            quick_format: options.quick_format,
            bad_blocks: options.bad_blocks,
            verify: options.verify,
            persistence: options.persistence,
            show_all: options.show_all,
            confirmed_serial: options.confirmed_serial.clone(),
            msdos_dir,
        },
        steps,
        confirm: String::new(),
    };
    plan.confirm = plan
        .confirm()
        .map_err(|err| PlanError::Confirm(format!("failed to compute plan confirm hash: {err}")))?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rufus_proto::BootloaderMode;
    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Layout;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target;
    use rufus_proto::WriteMode;

    use super::BootloaderOpt;
    use super::Options;
    use super::build;
    use super::device_ref;
    use super::steps;
    use super::write_mode;

    #[test]
    fn write_mode_lets_content_win_with_extension_as_tiebreaker() {
        for (name, kind, want) in [
            // Content wins regardless of the name…
            ("image.iso", ImageKind::Iso, WriteMode::Dd),
            ("image", ImageKind::Iso, WriteMode::Dd),
            ("image.bin", ImageKind::Raw, WriteMode::Dd),
            // …even when a .iso name would have said dd.
            ("image.iso", ImageKind::Wim, WriteMode::Copy),
            ("image.iso", ImageKind::Pe, WriteMode::Copy),
            ("image.iso", ImageKind::Xz, WriteMode::Dd),
            ("archive.gz", ImageKind::Gzip, WriteMode::Dd),
            ("disk.vhd", ImageKind::Vhd, WriteMode::Copy),
            ("disk.qcow2", ImageKind::Qcow2, WriteMode::Copy),
            // Unknown content: the extension is the only hint.
            ("FIXED.ISO", ImageKind::Unknown, WriteMode::Dd),
            ("image.img", ImageKind::Unknown, WriteMode::Dd),
            ("image.raw", ImageKind::Unknown, WriteMode::Dd),
            ("image.bin", ImageKind::Unknown, WriteMode::Copy),
            ("image", ImageKind::Unknown, WriteMode::Copy),
        ] {
            let got = write_mode(Path::new(name), &kind, false);
            assert_eq!(
                got, want,
                "'{name}' sniffed as {kind:?} must transfer with {want:?}"
            );
        }
    }

    #[test]
    fn write_mode_iso_flag_flips_walkable_images_to_copy() {
        // With the flag set, tree-walkable images copy whatever the
        // sniff said; compressed and container kinds do not move.
        for (name, kind, want) in [
            ("image.iso", ImageKind::Iso, WriteMode::Copy),
            ("image.bin", ImageKind::Raw, WriteMode::Copy),
            ("image.img", ImageKind::Unknown, WriteMode::Copy),
            ("image.bin", ImageKind::Unknown, WriteMode::Copy),
            ("archive.gz", ImageKind::Gzip, WriteMode::Dd),
            ("image.iso", ImageKind::Wim, WriteMode::Copy),
            ("disk.vhd", ImageKind::Vhd, WriteMode::Copy),
        ] {
            let got = write_mode(Path::new(name), &kind, true);
            assert_eq!(
                got, want,
                "'{name}' sniffed as {kind:?} with --iso-mode must transfer with {want:?}"
            );
        }
    }

    fn test_options(iso_mode: bool) -> Options {
        Options {
            scheme: Scheme::Mbr,
            target: Target::Dual,
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
            iso_mode,
            bootloader: BootloaderOpt::Auto,
        }
    }

    /// The `Write` and `Bootloader` modes of one planned step list.
    fn planned_modes(image: &str, kind: &ImageKind, iso_mode: bool) -> (WriteMode, BootloaderMode) {
        let mut write = None;
        let mut bootloader = None;
        for step in steps(Path::new(image), kind, &test_options(iso_mode)) {
            match step {
                Step::Write { mode } => write = Some(mode),
                Step::Bootloader { mode } => bootloader = Some(mode),
                _ => {}
            }
        }
        (
            write.expect("the plan carries a write step"),
            bootloader.expect("the plan carries a bootloader step"),
        )
    }

    #[test]
    fn steps_pairs_bootloader_with_write_mode() {
        // A dd write already laid the image's boot code: no installer.
        assert_eq!(
            planned_modes("image.iso", &ImageKind::Iso, false),
            (WriteMode::Dd, BootloaderMode::None),
            "a plain iso plans dd plus no bootloader"
        );
        // An iso-mode write needs the installer from the tree.
        assert_eq!(
            planned_modes("image.iso", &ImageKind::Iso, true),
            (WriteMode::Copy, BootloaderMode::Auto),
            "an iso-mode iso plans copy plus auto bootloader"
        );
        // Copy stays paired however it was reached.
        assert_eq!(
            planned_modes("image.iso", &ImageKind::Wim, false),
            (WriteMode::Copy, BootloaderMode::Auto),
            "a wim plans copy plus auto bootloader"
        );
    }

    /// The `Layout` of one planned step list.
    fn planned_layout(image: &str, kind: &ImageKind, bootloader: BootloaderOpt) -> Layout {
        let mut options = test_options(false);
        options.bootloader = bootloader;
        for step in steps(Path::new(image), kind, &options) {
            if let Step::Mkpart { layout, .. } = step {
                return layout;
            }
        }
        panic!("the plan carries an mkpart step");
    }

    #[test]
    fn explicit_bootloader_modes_are_emitted_verbatim_on_single() {
        // Any explicit selector but `uefi-ntfs` is emitted as-is and
        // stays on the single layout; the write mode still follows the
        // image (a dd image stays dd).
        for (selected, want) in [
            (BootloaderOpt::Syslinux, BootloaderMode::Syslinux),
            (BootloaderOpt::Grub2, BootloaderMode::Grub2),
            (BootloaderOpt::Grub4dos, BootloaderMode::Grub4dos),
            (BootloaderOpt::Freedos, BootloaderMode::Freedos),
            (BootloaderOpt::Kolibri, BootloaderMode::Kolibri),
            (BootloaderOpt::None, BootloaderMode::None),
        ] {
            let mut options = test_options(false);
            options.bootloader = selected;
            let mut write = None;
            let mut bootloader = None;
            for step in steps(Path::new("image.iso"), &ImageKind::Iso, &options) {
                match step {
                    Step::Write { mode } => write = Some(mode),
                    Step::Bootloader { mode } => bootloader = Some(mode),
                    _ => {}
                }
            }
            assert_eq!(
                bootloader.expect("the plan carries a bootloader step"),
                want,
                "{selected:?} is emitted verbatim"
            );
            assert_eq!(
                write.expect("the plan carries a write step"),
                WriteMode::Dd,
                "{selected:?} keeps the image write mode"
            );
            assert_eq!(
                planned_layout("image.iso", &ImageKind::Iso, selected),
                Layout::Single,
                "{selected:?} stays on the single layout"
            );
        }
    }

    #[test]
    fn uefi_ntfs_selects_two_partition_layout_and_forces_copy() {
        // The shim boots a populated NTFS data partition: even a dd
        // image is forced to copy, and the mkpart step stamps the
        // two-partition layout.
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::UefiNtfs;
        options.filesystem = Filesystem::Ntfs;
        let mut write = None;
        let mut bootloader = None;
        for step in steps(Path::new("image.iso"), &ImageKind::Iso, &options) {
            match step {
                Step::Write { mode } => write = Some(mode),
                Step::Bootloader { mode } => bootloader = Some(mode),
                _ => {}
            }
        }
        assert_eq!(
            write.expect("the plan carries a write step"),
            WriteMode::Copy,
            "uefi-ntfs forces copy even for a dd image"
        );
        assert_eq!(
            bootloader.expect("the plan carries a bootloader step"),
            BootloaderMode::UefiNtfs,
            "uefi-ntfs is emitted verbatim"
        );
        assert_eq!(
            planned_layout("image.iso", &ImageKind::Iso, BootloaderOpt::UefiNtfs),
            Layout::UefiNtfs,
            "uefi-ntfs stamps the two-partition layout"
        );
    }

    fn test_device() -> DeviceRef {
        DeviceRef {
            path: "/dev/null".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        }
    }

    fn test_image(kind: ImageKind) -> ImageRef {
        ImageRef {
            path: "image.iso".to_string(),
            size_bytes: 32_780,
            sha256: "0".repeat(64),
            kind,
        }
    }

    #[test]
    fn build_refuses_uefi_ntfs_without_ntfs_or_exfat() {
        // The shim boots an NTFS or exFAT data partition: any other
        // filesystem is a usage refusal with the exact message, before
        // any hash is sealed.
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::UefiNtfs;
        options.filesystem = Filesystem::Fat32;
        let refused =
            build(test_device(), test_image(ImageKind::Iso), &options).expect_err("fat32 refuses");
        assert_eq!(
            refused.to_string(),
            "UEFI:NTFS needs an NTFS or exFAT data partition; choose --filesystem ntfs or exfat",
            "the refusal carries the exact message"
        );
        // The NTFS and exFAT siblings seal fine and stamp the
        // uefi-ntfs layout.
        for filesystem in [Filesystem::Ntfs, Filesystem::Exfat] {
            options.filesystem = filesystem.clone();
            let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
                Ok(plan) => plan,
                Err(fail) => panic!("{filesystem:?} seals: {fail}"),
            };
            let layout = plan
                .steps
                .iter()
                .find_map(|step| match step {
                    Step::Mkpart { layout, .. } => Some(layout.clone()),
                    _ => None,
                })
                .expect("the plan carries an mkpart step");
            assert_eq!(layout, Layout::UefiNtfs);
        }
    }

    #[test]
    fn build_refuses_freedos_without_fat32() {
        // The FreeDOS installer writes a FAT32 volume: any other
        // filesystem is a usage refusal with the exact message, before
        // any hash is sealed, so a plan cannot be built that is
        // guaranteed to stop at the last step.
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::Freedos;
        for (filesystem, accepted) in [
            (Filesystem::Fat32, true),
            (Filesystem::Exfat, false),
            (Filesystem::Ntfs, false),
            (Filesystem::Ext4, false),
        ] {
            options.filesystem = filesystem.clone();
            if accepted {
                let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
                    Ok(plan) => plan,
                    Err(fail) => panic!("{filesystem:?} seals: {fail}"),
                };
                let mode = plan
                    .steps
                    .iter()
                    .find_map(|step| match step {
                        Step::Bootloader { mode } => Some(mode.clone()),
                        _ => None,
                    })
                    .expect("the plan carries a bootloader step");
                assert_eq!(mode, BootloaderMode::Freedos);
            } else {
                let refused = build(test_device(), test_image(ImageKind::Iso), &options)
                    .expect_err("non-fat32 refuses");
                assert_eq!(
                    refused.to_string(),
                    "FreeDOS needs a FAT32 data partition; choose --filesystem fat32",
                    "the refusal carries the exact message"
                );
                assert!(refused.to_string().is_ascii(), "the refusal stays ASCII");
            }
        }
    }

    #[test]
    fn build_refuses_kolibri_without_fat32() {
        // The KolibriOS installer writes a FAT32 volume: any other
        // filesystem is a usage refusal with the exact message, before
        // any hash is sealed, so a plan cannot be built that is
        // guaranteed to stop at the last step.
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::Kolibri;
        for (filesystem, accepted) in [
            (Filesystem::Fat32, true),
            (Filesystem::Exfat, false),
            (Filesystem::Ntfs, false),
            (Filesystem::Ext4, false),
        ] {
            options.filesystem = filesystem.clone();
            if accepted {
                let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
                    Ok(plan) => plan,
                    Err(fail) => panic!("{filesystem:?} seals: {fail}"),
                };
                let mode = plan
                    .steps
                    .iter()
                    .find_map(|step| match step {
                        Step::Bootloader { mode } => Some(mode.clone()),
                        _ => None,
                    })
                    .expect("the plan carries a bootloader step");
                assert_eq!(mode, BootloaderMode::Kolibri);
            } else {
                let refused = build(test_device(), test_image(ImageKind::Iso), &options)
                    .expect_err("non-fat32 refuses");
                assert_eq!(
                    refused.to_string(),
                    "KolibriOS needs a FAT32 data partition; choose --filesystem fat32",
                    "the refusal carries the exact message"
                );
                assert!(refused.to_string().is_ascii(), "the refusal stays ASCII");
            }
        }
    }

    #[test]
    fn windows_plans_the_to_go_layout_without_a_write_step() {
        // A Windows To Go plan carries no write step: the bootloader
        // step applies the WIM onto the mounted NTFS data partition,
        // and no tree reader takes a WIM — a copy step would only
        // refuse with "copy of a wim image". The mkfs filesystem and
        // the layout ignore the image kind and the `--filesystem`
        // flag alike (a `--scheme mbr` plan still seals here and is
        // refused later by the layout).
        for (name, kind) in [("image.iso", ImageKind::Iso), ("image.iso", ImageKind::Wim)] {
            let mut options = test_options(false);
            options.bootloader = BootloaderOpt::Windows;
            options.filesystem = Filesystem::Fat32;
            let planned = steps(Path::new(name), &kind, &options);
            assert!(
                planned
                    .iter()
                    .all(|step| !matches!(step, Step::Write { .. })),
                "no write step in {planned:?}"
            );
            let mut bootloader = None;
            let mut mkfs = None;
            for step in &planned {
                match step {
                    Step::Bootloader { mode } => bootloader = Some(mode.clone()),
                    Step::Mkfs { filesystem, .. } => mkfs = Some(filesystem.clone()),
                    _ => {}
                }
            }
            assert_eq!(
                bootloader.expect("the plan carries a bootloader step"),
                BootloaderMode::Windows,
                "windows is emitted verbatim"
            );
            assert_eq!(
                mkfs.expect("the plan carries a mkfs step"),
                Filesystem::Ntfs,
                "the data partition is NTFS whatever --filesystem says"
            );
            assert_eq!(
                planned_layout(name, &kind, BootloaderOpt::Windows),
                Layout::WindowsToGo,
                "windows stamps the Windows To Go layout"
            );
        }
        // The sealed plan records the overridden NTFS in its options
        // too, so options and the mkfs step agree — while an mbr
        // scheme still seals here (the layout refuses it later).
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::Windows;
        options.filesystem = Filesystem::Fat32;
        let plan = match build(test_device(), test_image(ImageKind::Wim), &options) {
            Ok(plan) => plan,
            Err(fail) => panic!("the windows plan seals: {fail}"),
        };
        assert_eq!(plan.options.filesystem, Filesystem::Ntfs);
        assert!(
            plan.steps
                .iter()
                .all(|step| !matches!(step, Step::Write { .. })),
            "no write step in {:?}",
            plan.steps
        );
        let mkfs = plan
            .steps
            .iter()
            .find_map(|step| match step {
                Step::Mkfs { filesystem, .. } => Some(filesystem.clone()),
                _ => None,
            })
            .expect("the plan carries a mkfs step");
        assert_eq!(mkfs, Filesystem::Ntfs);
    }

    #[test]
    fn build_refuses_msdos_without_fat32() {
        // The MS-DOS installer writes a FAT32 volume: any other
        // filesystem is a usage refusal with the exact message, before
        // any hash is sealed, so a plan cannot be built that is
        // guaranteed to stop at the last step.
        for (filesystem, accepted) in [
            (Filesystem::Fat32, true),
            (Filesystem::Exfat, false),
            (Filesystem::Ntfs, false),
            (Filesystem::Ext4, false),
        ] {
            let mut options = test_options(false);
            options.bootloader = BootloaderOpt::MsDos;
            options.msdos_dir = Some("/tmp/dos".to_string());
            options.filesystem = filesystem.clone();
            if accepted {
                let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
                    Ok(plan) => plan,
                    Err(fail) => panic!("{filesystem:?} seals: {fail}"),
                };
                let mode = plan
                    .steps
                    .iter()
                    .find_map(|step| match step {
                        Step::Bootloader { mode } => Some(mode.clone()),
                        _ => None,
                    })
                    .expect("the plan carries a bootloader step");
                assert_eq!(mode, BootloaderMode::MsDos);
            } else {
                let refused = build(test_device(), test_image(ImageKind::Iso), &options)
                    .expect_err("non-fat32 refuses");
                assert_eq!(
                    refused.to_string(),
                    "MS-DOS needs a FAT32 data partition; choose --filesystem fat32",
                    "the refusal carries the exact message"
                );
                assert!(refused.to_string().is_ascii(), "the refusal stays ASCII");
            }
        }
    }

    #[test]
    fn build_refuses_msdos_without_its_directory() {
        // The three system files are user-supplied for licensing
        // reasons: without `--msdos-dir` the plan refuses with the
        // exact message, before any hash is sealed. An empty string
        // counts as absent, so it refuses the same way.
        for dir in [None, Some(String::new())] {
            let mut options = test_options(false);
            options.bootloader = BootloaderOpt::MsDos;
            options.msdos_dir = dir;
            let refused = build(test_device(), test_image(ImageKind::Iso), &options)
                .expect_err("no dir refuses");
            assert_eq!(
                refused.to_string(),
                "MS-DOS needs --msdos-dir with the user's IO.SYS, MSDOS.SYS and COMMAND.COM",
                "the refusal carries the exact message"
            );
            assert!(refused.to_string().is_ascii(), "the refusal stays ASCII");
        }
    }

    #[test]
    fn build_refuses_msdos_dir_with_other_modes() {
        // No other installer reads the directory: pairing it with any
        // other bootloader mode refuses with the exact message, before
        // any hash is sealed.
        for bootloader in [
            BootloaderOpt::Auto,
            BootloaderOpt::Syslinux,
            BootloaderOpt::Windows,
            BootloaderOpt::Freedos,
            BootloaderOpt::None,
        ] {
            let mut options = test_options(false);
            options.bootloader = bootloader;
            options.msdos_dir = Some("/tmp/dos".to_string());
            let refused = build(test_device(), test_image(ImageKind::Iso), &options)
                .expect_err("a misplaced dir refuses");
            assert_eq!(
                refused.to_string(),
                "--msdos-dir only applies to --bootloader msdos",
                "the refusal carries the exact message for {bootloader:?}"
            );
            assert!(refused.to_string().is_ascii(), "the refusal stays ASCII");
        }
    }

    #[test]
    fn msdos_plans_no_write_step_but_keeps_bootloader_msdos() {
        // MS-DOS needs `IO.SYS` as the first root entry of the fresh
        // volume, so the plan carries no transfer step: wipe, table,
        // partition, format, bootloader, finalize. The directory rides
        // into the sealed options for the installer.
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::MsDos;
        options.msdos_dir = Some("/tmp/dos".to_string());
        let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
            Ok(plan) => plan,
            Err(fail) => panic!("the msdos plan seals: {fail}"),
        };
        assert!(
            plan.steps
                .iter()
                .all(|step| !matches!(step, Step::Write { .. })),
            "no write step in {:?}",
            plan.steps
        );
        let bootloader = plan
            .steps
            .iter()
            .find_map(|step| match step {
                Step::Bootloader { mode } => Some(mode.clone()),
                _ => None,
            })
            .expect("the plan carries a bootloader step");
        assert_eq!(bootloader, BootloaderMode::MsDos);
        assert_eq!(
            plan.steps.len(),
            6,
            "wipe, mklabel, mkpart, mkfs, bootloader, finalize"
        );
        assert_eq!(plan.options.msdos_dir.as_deref(), Some("/tmp/dos"));
        // `freedos` still plans its transfer step; `windows`
        // plans none either (its bootloader step applies the WIM).
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::Freedos;
        let plan = match build(test_device(), test_image(ImageKind::Iso), &options) {
            Ok(plan) => plan,
            Err(fail) => panic!("the freedos plan seals: {fail}"),
        };
        assert!(
            plan.steps
                .iter()
                .any(|step| matches!(step, Step::Write { .. })),
            "other modes keep their write step"
        );
    }

    #[test]
    fn device_ref_grades_missing_and_non_block_paths() {
        // Dry-run relaxes both checks and keeps the mapper fields empty.
        let probe = super::DeviceProbe::unknown("/dev/null");
        let device = device_ref(&probe, true).expect("dry-run grades");
        assert!(!device.block_device);
        assert_eq!(device.size_bytes, None);

        // Without dry-run a missing path is a device refusal…
        let missing = super::DeviceProbe {
            path: "/no/such/device".to_string(),
            exists: false,
            block_device: false,
            error: Some("No such file or directory (os error 2)".to_string()),
            facts: None,
        };
        let error = device_ref(&missing, false).expect_err("missing refuses");
        assert!(matches!(error, super::PlanError::Device(_)));
        assert!(error.to_string().contains("--dry-run"));

        // …and an existing non-block path is a safety refusal.
        let char_device = super::DeviceProbe {
            path: "/dev/null".to_string(),
            exists: true,
            block_device: false,
            error: None,
            facts: None,
        };
        let error = device_ref(&char_device, false).expect_err("non-block refuses");
        assert!(matches!(error, super::PlanError::Safety(_)));
    }

    #[test]
    fn device_ref_enriches_from_discovery_facts() {
        let probe = super::DeviceProbe {
            path: "/dev/sdb".to_string(),
            exists: true,
            block_device: true,
            error: None,
            facts: Some(super::DeviceFacts {
                size_bytes: 32_010_928_128,
                serial: Some("ABC123".to_string()),
                model: Some("Rufus Test Stick".to_string()),
                sysfs: "/sys/class/block/sdb".to_string(),
            }),
        };
        let device = device_ref(&probe, false).expect("the device grades");
        assert!(device.block_device);
        assert_eq!(device.size_bytes, Some(32_010_928_128));
        assert_eq!(device.serial.as_deref(), Some("ABC123"));
        assert_eq!(device.model.as_deref(), Some("Rufus Test Stick"));
        assert_eq!(device.sysfs.as_deref(), Some("/sys/class/block/sdb"));
    }
}
