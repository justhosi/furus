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

use std::os::unix::fs::FileTypeExt;
use std::path::Path;

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
}

/// Grade the target device path into a [`DeviceRef`].
///
/// All mapper fields (`size_bytes`, `serial`, `model`, `sysfs`) stay `None`
/// in S03 — device identity comes from S04/S05; S06's helper will refuse
/// plans that lack it.
pub fn device_ref(path: &Path, dry_run: bool) -> Result<DeviceRef, Fail> {
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
    Ok(DeviceRef {
        path: path.display().to_string(),
        block_device,
        // DELIBERATE (see module header): no BLKGETSIZE64 in this slice.
        size_bytes: None,
        serial: None,
        model: None,
        sysfs: None,
    })
}

/// How the image transfers: raw streams by dd, structured containers by
/// copy. `*.iso` files and magic-`raw`/`iso` content are dd-ed; everything
/// else copies (WIMs through wimlib in S21, trees through the S18 copier).
/// Provisional for this schema generation: the executor decides finally.
fn write_mode(image: &Path, kind: &ImageKind) -> WriteMode {
    let iso_by_name = image
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("iso"))
        .unwrap_or(false);
    if iso_by_name || matches!(kind, ImageKind::Iso | ImageKind::Raw) {
        WriteMode::Dd
    } else {
        WriteMode::Copy
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
        },
        steps,
        confirm: String::new(),
    };
    plan.confirm = plan
        .confirm()
        .map_err(|err| Fail::json(format!("failed to compute plan confirm hash: {err}",)))?;
    Ok(plan)
}
