//! Provisional plan construction for `rufus plan` (S03).
//!
//! The steps describe *what* happens in order — wipe, table, partition,
//! format, write, bootloader, finalise — against the options the user
//! picked. They are deliberately high-level: exact LBA placement,
//! alignment, gaps, engine arguments and progress mapping are computed by
//! the S17 executor against the real device geometry. Nothing here touches
//! a device; the CLI only *constructs* a plan object.
//!
//! Device grading rules (PLAN §6 preview semantics):
//!
//! * `--dry-run` — a missing or non-block device is allowed, reported in
//!   the plan with `block_device: false`, so plans can be produced
//!   anywhere. Never a reason to fail.
//! * otherwise — a missing device is a device error (exit 2) and an
//!   existing non-block device is refused outright (exit 3, safety).
//!
//! After grading, the mapper fields are filled from S04 discovery when
//! the target resolves on the given sysfs root (a `dev_path` match):
//! `size_bytes`, `serial`, `model`, `sysfs`, and `block_device`. The
//! enrichment is deliberately non-fatal — a missing root, a vanished
//! class directory or an unmatched path (e.g. `/dev/null`, which is what
//! the plan golden uses) keeps the fields `None`, exactly the S03 plan
//! shape.

use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use rufus_linux::SysfsRoot;
use rufus_proto::BootloaderMode;
use rufus_proto::DeviceRef;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::Layout;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Step;
use rufus_proto::WriteMode;

use crate::Fail;
use crate::image::Inspected;

/// The `--bootloader` selector: which installer the plan's bootloader
/// step carries. `Auto` keeps the write-mode pairing (a `Dd` write
/// already laid the image's own boot code, so no installer; a `Copy`
/// write needs one); any explicit mode is emitted verbatim.
/// `UefiNtfs` additionally selects the two-partition UEFI:NTFS layout
/// and forces `Copy` (the shim boots an NTFS or exFAT data partition
/// the image tree populates); every other mode stays on the single layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
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
    /// No bootloader (plain data media).
    None,
}

impl BootloaderOpt {
    /// The bootloader mode the plan's bootloader step carries.
    fn mode(self) -> BootloaderMode {
        match self {
            BootloaderOpt::Auto => BootloaderMode::Auto,
            BootloaderOpt::Syslinux => BootloaderMode::Syslinux,
            BootloaderOpt::Grub2 => BootloaderMode::Grub2,
            BootloaderOpt::Grub4dos => BootloaderMode::Grub4dos,
            BootloaderOpt::UefiNtfs => BootloaderMode::UefiNtfs,
            BootloaderOpt::Freedos => BootloaderMode::Freedos,
            BootloaderOpt::None => BootloaderMode::None,
        }
    }

    /// The partition layout the plan's mkpart step stamps.
    fn layout(self) -> Layout {
        match self {
            BootloaderOpt::UefiNtfs => Layout::UefiNtfs,
            _ => Layout::Single,
        }
    }
}

/// Options as parsed from the `plan` subcommand flags.
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
    /// in [`build`]).
    pub bootloader: BootloaderOpt,
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

/// Grade the target device path into a [`DeviceRef`], enriched from S04
/// discovery where possible.
pub fn device_ref(path: &Path, dry_run: bool, sysfs: &SysfsRoot) -> Result<DeviceRef, Fail> {
    let block_device = match std::fs::metadata(path) {
        Ok(meta) => {
            // unix only: the workspace targets Linux (PLAN §1 A3).
            meta.file_type().is_block_device()
        }
        Err(source) => {
            if !dry_run {
                return Err(Fail {
                    exit: crate::Exit::Device,
                    kind: "device",
                    message: format!(
                        "device '{}': {} (does the path exist? use --dry-run to plan anyway)",
                        path.display(),
                        source
                    ),
                });
            }
            false
        }
    };
    if !block_device && !dry_run {
        return Err(Fail {
            exit: crate::Exit::Safety,
            kind: "safety",
            message: format!(
                "'{}' is not a block device; refusing (safety). Use --dry-run to build a plan for it without touching anything.",
                path.display()
            ),
        });
    }
    let mut device = DeviceRef {
        path: path.display().to_string(),
        block_device,
        size_bytes: None,
        serial: None,
        model: None,
        sysfs: None,
    };

    // S04 enrichment: discovery is best-effort. A sysfs root that cannot
    // be enumerated (missing on a dry-run box, unreadable in a fixture)
    // is simply ignored — the plan keeps the all-`None` mapper fields
    // and the CLI/golden tests stay deterministic.
    let discovered = rufus_linux::enumerate(sysfs).ok().and_then(|devices| {
        devices
            .into_iter()
            .find(|known| known.dev_path == device.path)
    });
    if let Some(found) = discovered {
        // A discoverable device *is* a block device on its root, so the
        // fact rides into the plan (S06's helper re-checks it anyway).
        device.block_device = true;
        device.size_bytes = Some(found.size_bytes);
        device.serial = found.serial;
        device.model = found.model;
        device.sysfs = Some(found.sysfs);
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
fn write_mode(image: &Path, kind: &ImageKind, iso_mode: bool) -> WriteMode {
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
/// (the shim boots a populated NTFS or exFAT data partition). The mkpart step
/// carries the selector's layout (`UefiNtfs` for `uefi-ntfs`, `Single`
/// otherwise).
pub fn steps(image: &Path, kind: &ImageKind, options: &Options) -> Vec<Step> {
    let (write, bootloader) = match options.bootloader {
        BootloaderOpt::Auto => {
            let write = write_mode(image, kind, options.iso_mode);
            let needs_installer = write == WriteMode::Copy;
            (
                write,
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
            (write, selected.mode())
        }
    };
    vec![
        Step::Wipe,
        Step::Mklabel {
            scheme: options.scheme.clone(),
        },
        Step::Mkpart {
            scheme: options.scheme.clone(),
            layout: options.bootloader.layout(),
        },
        Step::Mkfs {
            filesystem: options.filesystem.clone(),
            label: options.label.clone(),
            cluster_bytes: options.cluster_bytes,
            quick: options.quick_format,
        },
        Step::Write { mode: write },
        Step::Bootloader { mode: bootloader },
        Step::Finalize,
    ]
}

/// Build and seal the provisional [`Plan`] for `image`/`device`.
///
/// The device must already have been graded with [`device_ref`]. The plan
/// carries no write instructions beyond the step list and is approved
/// neither by the user nor by the helper; safety decisions per PLAN §6
/// happen in S05/S06. The confirm hash is recomputed here and a
/// serialisation failure (practically impossible for this JSON-native
/// schema) is surfaced as an I/O-class [`Fail`], fail closed (PLAN §2).
/// A `uefi-ntfs` bootloader without an NTFS or exFAT data filesystem
/// is refused here, before any step is built: the shim boots an NTFS
/// or exFAT partition the image tree populates, so any other
/// filesystem is a usage error.
pub fn build(device: DeviceRef, inspected: Inspected, options: &Options) -> Result<Plan, Fail> {
    if options.bootloader == BootloaderOpt::UefiNtfs
        && options.filesystem != Filesystem::Ntfs
        && options.filesystem != Filesystem::Exfat
    {
        return Err(Fail {
            exit: crate::Exit::Usage,
            kind: "usage",
            message:
                "UEFI:NTFS needs an NTFS or exFAT data partition; choose --filesystem ntfs or exfat"
                    .to_owned(),
        });
    }
    let steps = steps(Path::new(&inspected.path), &inspected.kind, options);
    let mut plan = Plan {
        version: PLAN_VERSION,
        created_by: rufus_core::user_agent(),
        device,
        image: rufus_proto::ImageRef {
            path: inspected.path,
            size_bytes: inspected.size_bytes,
            sha256: inspected.sha256,
            kind: inspected.kind,
        },
        options: rufus_proto::Options {
            scheme: options.scheme.clone(),
            target: options.target.clone(),
            filesystem: options.filesystem.clone(),
            label: options.label.clone(),
            cluster_bytes: options.cluster_bytes,
            quick_format: options.quick_format,
            bad_blocks: options.bad_blocks,
            verify: options.verify,
            persistence: options.persistence,
            show_all: options.show_all,
            confirmed_serial: options.confirmed_serial.clone(),
        },
        steps,
        confirm: String::new(),
    };
    plan.confirm = plan
        .confirm()
        .map_err(|err| Fail::json(format!("failed to compute plan confirm hash: {err}",)))?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rufus_proto::BootloaderMode;
    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::Layout;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target;
    use rufus_proto::WriteMode;

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

    use super::BootloaderOpt;
    use super::Options;
    use super::build;
    use super::steps;

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

    #[test]
    fn build_refuses_uefi_ntfs_without_ntfs_or_exfat() {
        // The shim boots an NTFS or exFAT data partition: any other
        // filesystem is a usage refusal with the exact message, before
        // any hash is sealed.
        let device = DeviceRef {
            path: "/dev/null".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        };
        let inspected = crate::image::Inspected {
            path: "image.iso".to_string(),
            size_bytes: 32_780,
            sha256: "0".repeat(64),
            kind: ImageKind::Iso,
        };
        let mut options = test_options(false);
        options.bootloader = BootloaderOpt::UefiNtfs;
        options.filesystem = Filesystem::Fat32;
        let refused = build(device.clone(), inspected, &options).expect_err("fat32 refuses");
        assert_eq!(
            refused.message,
            "UEFI:NTFS needs an NTFS or exFAT data partition; choose --filesystem ntfs or exfat",
            "the refusal carries the exact message"
        );
        // The NTFS and exFAT siblings seal fine and stamp the
        // uefi-ntfs layout.
        for filesystem in [Filesystem::Ntfs, Filesystem::Exfat] {
            let inspected = crate::image::Inspected {
                path: "image.iso".to_string(),
                size_bytes: 32_780,
                sha256: "0".repeat(64),
                kind: ImageKind::Iso,
            };
            options.filesystem = filesystem.clone();
            let plan = match build(device.clone(), inspected, &options) {
                Ok(plan) => plan,
                Err(fail) => panic!("{filesystem:?} seals: {}", fail.message),
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
}
