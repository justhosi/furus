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
use rufus_proto::ImageKind;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Step;
use rufus_proto::WriteMode;

use crate::Fail;
use crate::image::Inspected;

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

/// How the image transfers: raw streams by dd, structured containers by
/// copy. Detection is authoritative: a sniffed ISO or raw stream is
/// dd-ed whatever the name, and a sniffed container (WIM, gzip, ...) is
/// *copied* even when named `.iso` — a Windows `.iso` whose bytes sniff
/// as WIM must not go to the raw writer. The extension is only a
/// tiebreaker when the content could not be identified at all
/// ([`ImageKind::Unknown`]): `iso`/`img`/`raw` names conventionally mean
/// sector images worth dd-ing, anything else is a job for a later-slice
/// reader (WIM: wimlib in S21, compressed raws: S15). Provisional for
/// this schema generation: the executor decides finally.
fn write_mode(image: &Path, kind: &ImageKind) -> WriteMode {
    match kind {
        // Content is authoritative for the streamable kinds.
        ImageKind::Iso | ImageKind::Raw => WriteMode::Dd,
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
        // through wimlib in S21, VHD/VHDX/FFU through their parsers, a
        // gzip/xz/bzip2 stream decompressed first in S15, PE files as
        // payload parts).
        ImageKind::Wim
        | ImageKind::Vhd
        | ImageKind::Vhdx
        | ImageKind::Ffu
        | ImageKind::Gzip
        | ImageKind::Xz
        | ImageKind::Bzip2
        | ImageKind::Zstd
        | ImageKind::Pe => WriteMode::Copy,
    }
}

/// The ordered provisional steps for one image/device combination.
pub fn steps(image: &Path, kind: &ImageKind, options: &Options) -> Vec<Step> {
    vec![
        Step::Wipe,
        Step::Mklabel {
            scheme: options.scheme.clone(),
        },
        Step::Mkpart {
            scheme: options.scheme.clone(),
        },
        Step::Mkfs {
            filesystem: options.filesystem.clone(),
            label: options.label.clone(),
            cluster_bytes: options.cluster_bytes,
            quick: options.quick_format,
        },
        Step::Write {
            mode: write_mode(image, kind),
        },
        Step::Bootloader {
            mode: BootloaderMode::Auto,
        },
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
pub fn build(device: DeviceRef, inspected: Inspected, options: &Options) -> Result<Plan, Fail> {
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

    use rufus_proto::ImageKind;
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
            ("image.iso", ImageKind::Xz, WriteMode::Copy),
            ("archive.gz", ImageKind::Gzip, WriteMode::Copy),
            ("disk.vhd", ImageKind::Vhd, WriteMode::Copy),
            // Unknown content: the extension is the only hint.
            ("FIXED.ISO", ImageKind::Unknown, WriteMode::Dd),
            ("image.img", ImageKind::Unknown, WriteMode::Dd),
            ("image.raw", ImageKind::Unknown, WriteMode::Dd),
            ("image.bin", ImageKind::Unknown, WriteMode::Copy),
            ("image", ImageKind::Unknown, WriteMode::Copy),
        ] {
            let got = write_mode(Path::new(name), &kind);
            assert_eq!(
                got, want,
                "'{name}' sniffed as {kind:?} must transfer with {want:?}"
            );
        }
    }
}
