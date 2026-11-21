//! Subcommand implementations for `furus`.
//!
//! Each `cmd_*` entry point is called by `crate::dispatch`; the output
//! structs and human renderers come from `crate::output`, the image
//! preamble from `crate::image`, and the crate-root failure mapping
//! (`Exit`/`Fail`/`to_pretty`/`fail_from_plan`/`HostPaths`) stays private
//! to the crate root and is reached through `crate::`.

use std::path::Path;

use furus_core::error::CoreError;
use furus_core::hash::Algo;
use furus_core::part::plan::LayoutKind;
use furus_core::partition::TableKind;
use furus_core::planner;
use furus_core::safety::SafetyVerdict;
use furus_core::text::device_text;
use furus_linux::SysfsRoot;
use furus_proto::Layout;
use furus_proto::PLAN_VERSION;
use furus_proto::Plan;
use furus_proto::Scheme;
use furus_proto::Step;

use crate::Exit;
use crate::Fail;
use crate::HostPaths;
use crate::fail_from_plan;
use crate::image;
use crate::output::AnalyzeDevice;
use crate::output::AnalyzeMount;
use crate::output::AnalyzeOutput;
use crate::output::AnalyzePartitionFs;
use crate::output::HumanReporter;
use crate::output::JsonReporter;
use crate::output::ListOutput;
use crate::output::human_layout;
use crate::output::human_lead;
use crate::output::human_scheme;
use crate::output::human_table;
use crate::output::print_human_plan;
use crate::output::report_summary;
use crate::output::verdict_json;
use crate::to_pretty;

pub(crate) fn cmd_version(json: bool) -> Result<Exit, Fail> {
    if json {
        let object = serde_json::json!({
            "version": furus_core::version(),
            "git_hash": furus_core::git_hash(),
            "plan_version": PLAN_VERSION,
        });
        println!("{}", to_pretty(&object)?);
    } else {
        println!(
            "furus {} ({})",
            furus_core::version(),
            furus_core::git_hash()
        );
    }
    Ok(Exit::Ok)
}

pub(crate) fn cmd_checksum(json: bool, path: &Path, algo: Algo) -> Result<Exit, Fail> {
    // Regular-file check first so a directory gives a validation error, not
    // a read error from inside the stream digest.
    let size = image::image_size(path).map_err(Fail::from_core)?;
    let digest = furus_core::hash_file_with(algo, path).map_err(Fail::from_core)?;
    if json {
        let object = serde_json::json!({
            "algo": algo.as_str(),
            "hash": digest,
            "path": path.display().to_string(),
            "bytes": size,
        });
        println!("{}", to_pretty(&object)?);
    } else {
        // sha256sum-compatible line: "<digest>  <path>".
        println!("{digest}  {}", path.display());
    }
    Ok(Exit::Ok)
}

/// S03 image analysis, with the S05 PLAN §6 device report on top when
/// `--device` is given.
///
/// `analyze` is a *reporting* command: it samples the device honestly,
/// prints the verdict — and exits 0 even when the verdict refuses.
/// Enforcing a refusal is the S06 preview/helper's job (PLAN §6 wants
/// two enforcement points over one judging implementation, and a report
/// must be readable by scripts in both states).
///
/// Device-fact failures (a discovery root that cannot be enumerated, a
/// mount/swap table that cannot be read, no device matching the
/// requested path, a partition path) are device-class errors: exit 2,
/// kind "device", with the `{"error","message"}` object in `--json`
/// mode. A partition path names its whole disk in the refusal.
/// Select the graded device from an enumeration: first match in the
/// name-sorted enumeration order, by the discovered node path, the
/// sysfs path, one shared canonical path (both sides must exist — two
/// failed lookups never mean "the same path") or the bare kernel name.
/// Shared by `analyze --device` and `write` so the two cannot disagree
/// on what a path names; nothing infers a device from a file's name.
///
/// Refusals are device class (exit 2): a partition path names its whole
/// disk (tables are read from the whole disk), unknown paths keep the
/// plain message.
fn find_device(
    devices: &[furus_linux::Device],
    requested: &Path,
) -> Result<furus_linux::Device, Fail> {
    let selected = devices.iter().find(|candidate| {
        Path::new(&candidate.dev_path) == requested
            || Path::new(&candidate.sysfs) == requested
            || Path::new(&candidate.name) == requested
            || {
                match (
                    std::fs::canonicalize(Path::new(&candidate.dev_path)),
                    std::fs::canonicalize(requested),
                ) {
                    (Ok(real), Ok(given)) => real == given,
                    _ => false,
                }
            }
    });
    let Some(selected) = selected else {
        // A partition path is the common miss worth naming: tables are
        // read from the whole disk, so say which disk owns the name.
        // Unknown paths keep the plain message.
        let base = requested.file_name();
        let owner = base.and_then(|base| {
            devices.iter().find(|disk| {
                disk.partitions
                    .iter()
                    .any(|part| std::ffi::OsStr::new(&part.name) == base)
            })
        });
        return Err(match owner {
            Some(disk) => Fail {
                exit: Exit::Device,
                kind: "device",
                message: format!(
                    "{} is a partition of {} - select the whole disk",
                    requested.display(),
                    disk.dev_path
                ),
            },
            None => Fail {
                exit: Exit::Device,
                kind: "device",
                message: format!("no block device found for {}", requested.display()),
            },
        });
    };
    Ok(selected.clone())
}

pub(crate) fn cmd_analyze(
    json: bool,
    image_path: &Path,
    device: Option<&Path>,
    confirm_serial: Option<&str>,
    extra_devs: bool,
    paths: &HostPaths,
) -> Result<Exit, Fail> {
    let inspected = image::inspect(image_path).map_err(Fail::from_core)?;
    // The S16 image report, filled on every path (image and `--device`
    // alike) from the same image file, so `null` always means the report
    // could not be produced — never "not asked".
    let image_report = furus_core::report::analyze_file(image_path).ok();
    let Some(requested) = device else {
        // The pre-S05 surface, unchanged in every byte: four image facts
        // in both output modes and no `device` key in JSON.
        if json {
            let output = AnalyzeOutput {
                path: inspected.path,
                size_bytes: inspected.size_bytes,
                sha256: inspected.sha256,
                kind: inspected.kind.to_string(),
                device: None,
                report: image_report,
            };
            println!("{}", to_pretty(&output)?);
        } else {
            println!("image:  {}", inspected.path);
            println!(
                "size:   {} ({})",
                inspected.size_bytes,
                furus_core::human_bytes(inspected.size_bytes)
            );
            println!("kind:   {}", inspected.kind);
            println!("sha256: {}", inspected.sha256);
            match &image_report {
                Some(report) => println!("report: {}", report_summary(report)),
                None => println!("report: analysis refused"),
            }
        }
        return Ok(Exit::Ok);
    };

    // Discovery is deliberately unfiltered: PLAN §6 wants the fixed disk
    // the user named to be analyzable — its refusal comes from the
    // verdict, not from hiding the disk.
    let sysfs = paths.sysfs();
    let devices = furus_linux::enumerate(&sysfs).map_err(|core| Fail {
        // Not bad input and not ordinary I/O: the device tree the CLI
        // was pointed at cannot be listed. Device class, exit 2 (same
        // mapping as `list`).
        exit: Exit::Device,
        kind: "device",
        message: core.to_string(),
    })?;

    // Selection: first match in the name-sorted enumeration order (see
    // `find_device`). The graded device is always the discovered one,
    // and the node that gets sampled is always its own `/dev/<name>`
    // (fixture tests redirect that with `--device-file`); nothing
    // infers a device from a file's name.
    let selected = find_device(&devices, requested)?;
    // S05 test hook: `--device-file` redirects only the file the
    // sampling half opens. The graded device (name, size, serial,
    // mounts, holders — every verdict fact) stays the discovered one,
    // and without the flag the discovered `/dev/<name>` node is
    // sampled, so the graded device and the read bytes never diverge.
    let mut selected = selected;
    if let Some(file) = paths.device_file.as_deref() {
        selected.dev_path = file.display().to_string();
    }

    // The tables the inspection half matches device numbers against:
    // fixture files in tests, the live /proc files on a real run. Host
    // state failing here is device class (exit 2).
    let mounts = paths.mount_table()?;
    let swaps = paths.swaps()?;
    let furus_linux::inspect::Inspected { report, target } = furus_linux::inspect(
        &sysfs,
        &selected,
        &furus_linux::inspect::Options {
            mount_table: &mounts,
            swaps: &swaps,
            image_bytes: Some(inspected.size_bytes),
            allow_fixed: extra_devs,
            confirmed_serial: confirm_serial,
        },
    );
    let verdict = furus_core::safety::judge(&target);

    if json {
        let mounts_output: Vec<AnalyzeMount> = report
            .mounts
            .iter()
            .map(|entry| AnalyzeMount {
                dev: format!("{}:{}", entry.major, entry.minor),
                mountpoint: entry.mountpoint.clone(),
                fstype: entry.fstype.clone(),
                source: entry.source.clone(),
            })
            .collect();
        let partition_filesystems: Vec<AnalyzePartitionFs> = report
            .partition_filesystems
            .iter()
            .map(|(name, kind)| AnalyzePartitionFs {
                partition: name.clone(),
                filesystem: kind.as_str(),
            })
            .collect();
        let device_output = AnalyzeDevice {
            path: device_text(&report.device.dev_path),
            name: device_text(&report.device.name),
            size_bytes: report.device.size_bytes,
            serial: report.device.serial.clone(),
            model: report.device.model.clone(),
            removable: report.device.removable,
            read_only: report.device.read_only,
            transport: report.device.transport.as_str(),
            table: report.layout,
            filesystem: report.filesystem.map(|fs| fs.as_str()),
            partition_filesystems,
            mounts: mounts_output,
            swaps: report
                .swaps
                .iter()
                .map(|entry| entry.filename.clone())
                .collect(),
            holders: report.holders,
            warnings: report.warnings,
            verdict: verdict_json(&verdict),
        };
        let output = AnalyzeOutput {
            path: inspected.path,
            size_bytes: inspected.size_bytes,
            sha256: inspected.sha256,
            kind: inspected.kind.to_string(),
            device: Some(device_output),
            report: image_report,
        };
        println!("{}", to_pretty(&output)?);
    } else {
        println!("image:  {}", inspected.path);
        println!(
            "size:   {} ({})",
            inspected.size_bytes,
            furus_core::human_bytes(inspected.size_bytes)
        );
        println!("kind:   {}", inspected.kind);
        println!("sha256: {}", inspected.sha256);
        match &image_report {
            Some(report) => println!("report: {}", report_summary(report)),
            None => println!("report: analysis refused"),
        }

        // The device half (S05). Every device/kernel-supplied string
        // reaches these lines through its sanitiser — `device_text` at
        // this boundary here, at the parse boundary for the fields the
        // inspection half gathered — so the whole report stays ASCII by
        // construction.
        println!(
            "device:   {} ({})  {}  {}",
            device_text(&report.device.dev_path),
            device_text(&report.device.name),
            furus_core::human_bytes(report.device.size_bytes),
            report.device.transport.as_str(),
        );
        if let Some(serial) = &report.device.serial {
            println!("serial:   {serial}");
        }
        // An unreadable device must not read as a blank disk: the
        // table line says so explicitly, and the refuse verdict below
        // carries the reason. Layout `None` (no readable table rule
        // matched) keeps the plain "none" for the blank-stick case.
        if report.unreadable.is_some() {
            println!("table:    unreadable");
        } else {
            match &report.layout {
                Some(layout) => {
                    println!(
                        "table:    {}, {} partition(s), backup gpt: {}",
                        human_table(&layout.kind),
                        layout.partitions.len(),
                        human_lead(layout.backup_gpt),
                    );
                    for part in &layout.partitions {
                        println!(
                            "  #{}  start {}  sectors {}  {}  {}",
                            part.index,
                            part.start_lba,
                            part.sectors,
                            furus_core::human_bytes(part.size_bytes),
                            part.kind,
                        );
                    }
                }
                None => println!("table:    none"),
            }
        }
        if let Some(fs) = &report.filesystem {
            println!("filesystem: {}", fs.as_str());
        }
        for (name, fs) in &report.partition_filesystems {
            println!("partition {name}: {}", fs.as_str());
        }
        for mount in &report.mounts {
            println!("mounted:  {} ({})", mount.mountpoint, mount.fstype);
        }
        for swap in &report.swaps {
            println!("swap:     {}", swap.filename);
        }
        for holder in &report.holders {
            println!("holder:   {holder}");
        }
        for warning in &report.warnings {
            println!("warning:  {warning}");
        }
        match &verdict {
            SafetyVerdict::Safe => println!("verdict:  safe"),
            SafetyVerdict::Refuse(reason) => println!("verdict:  refuse: {reason}"),
        }
    }
    Ok(Exit::Ok)
}

/// S04 discovery: enumerate candidates through sysfs + udev data and
/// print the filtered list.
///
/// Mirrors Furus's removable-only default; `--all`/`-x` reveal internal
/// fixed disks. The destruction warning is the one canonical statement
/// in this module's surface: **whenever show-all mode is on, the PLAN
/// §6 rule-4 line prints to stderr exactly once per run — even if that
/// run lists only removable devices.** Discovery failure (a missing or
/// unreadable class directory) is a device-class error: exit 2, and the
/// `--json` error object keeps the standard `{"error","message"}` shape.
pub(crate) fn cmd_list(
    json: bool,
    all: bool,
    legacy_extra_devs: bool,
    sysfs: &SysfsRoot,
) -> Result<Exit, Fail> {
    let show_all = all || legacy_extra_devs;
    let filter = furus_linux::Filter { show_all };
    let devices = furus_linux::enumerate(sysfs)
        .map(|enumerated| furus_linux::filter(enumerated, filter))
        .map_err(|core| Fail {
            // Not bad input and not ordinary I/O: the device tree the CLI
            // was pointed at cannot be listed. Device class, exit 2.
            exit: Exit::Device,
            kind: "device",
            message: core.to_string(),
        })?;

    // PLAN §6 rule 4: exactly one warning per run whenever show-all is
    // on (the canonical rule is documented on `cmd_list`).
    if show_all {
        eprintln!("show all: internal disks are listed; writing to them can destroy the system");
    }

    if json {
        let output = ListOutput {
            devices: &devices,
            show_all,
        };
        println!("{}", to_pretty(&output)?);
    } else {
        println!(
            "devices from {} ({} shown, show all: {})",
            sysfs.root.join("class").join("block").display(),
            devices.len(),
            human_lead(show_all),
        );
        for device in &devices {
            let mut markers: Vec<&'static str> = Vec::new();
            if device.removable {
                markers.push("removable");
            }
            if device.read_only {
                markers.push("read-only");
            }
            let markers = if markers.is_empty() {
                "-".to_string()
            } else {
                markers.join(",")
            };
            let names = match (&device.vendor, &device.model) {
                (Some(vendor), Some(model)) => format!("{vendor} {model}"),
                (Some(vendor), None) => vendor.clone(),
                (None, Some(model)) => model.clone(),
                (None, None) => "-".to_string(),
            };
            let serial = match &device.serial {
                Some(serial) => format!("serial={serial}"),
                None => "<no serial>".to_string(),
            };
            println!(
                "{}  {}  {}  {}  {}  {}  {} partition(s)",
                device.dev_path,
                furus_core::human_bytes(device.size_bytes),
                device.transport.as_str(),
                markers,
                names,
                serial,
                device.partitions.len(),
            );
        }
    }
    Ok(Exit::Ok)
}

pub(crate) fn cmd_plan(
    json: bool,
    dry_run: bool,
    image_path: &Path,
    device_path: &Path,
    sysfs: &SysfsRoot,
    options: &planner::Options,
) -> Result<Exit, Fail> {
    // Safety first: grade the device (exit 2/3 without --dry-run), then the
    // image (exit 4/1), then assemble and seal the plan. The S04 facts
    // (size/serial/model/sysfs) ride along when the device is discoverable
    // on `sysfs`, and stay `None` otherwise.
    let probe = furus_linux::probe_device(device_path, sysfs);
    let device = planner::device_ref(&probe, dry_run).map_err(fail_from_plan)?;
    let inspected = image::inspect(image_path).map_err(Fail::from_core)?;
    let image = furus_proto::ImageRef {
        path: inspected.path,
        size_bytes: inspected.size_bytes,
        sha256: inspected.sha256,
        kind: inspected.kind,
    };
    let built = planner::build(device, image, options).map_err(fail_from_plan)?;
    if json {
        // `println!` keeps `plan --json` output line-oriented: scripts
        // and `jq` always see one complete line, never a cut-off value.
        println!("{}", to_pretty(&built)?);
    } else {
        print_human_plan(&built);
    }
    Ok(Exit::Ok)
}

pub(crate) fn cmd_write(
    json: bool,
    plan_path: &Path,
    paths: &HostPaths,
    reset_usb: bool,
) -> Result<Exit, Fail> {
    let text = std::fs::read_to_string(plan_path)
        .map_err(|source| Fail::from_core(CoreError::io(plan_path, source)))?;
    let parsed: Plan = serde_json::from_str(&text).map_err(|err| Fail {
        exit: Exit::Usage,
        kind: "invalid_plan",
        message: format!("failed to parse plan '{}': {err}", plan_path.display()),
    })?;
    if parsed.version != PLAN_VERSION {
        return Err(Fail {
            exit: Exit::Usage,
            kind: "unsupported_version",
            message: format!(
                "plan '{}' carries version {}, but this build supports {}",
                plan_path.display(),
                parsed.version,
                PLAN_VERSION
            ),
        });
    }
    // Fail closed: a confirm hash that cannot be recomputed means the plan
    // must not be accepted (PLAN §2, even though it is practically
    // impossible for this JSON-native schema).
    let recomputed = parsed
        .confirm()
        .map_err(|err| Fail::json(format!("failed to recompute confirm hash: {err}")))?;
    if recomputed != parsed.confirm {
        return Err(Fail {
            exit: Exit::Usage,
            kind: "confirm_mismatch",
            message: format!(
                "plan '{}' confirm hash mismatch (file says {}, recomputed {}); modified after signing?",
                plan_path.display(),
                parsed.confirm,
                recomputed
            ),
        });
    }
    // The plan verifies; run it through the S17 pipeline.
    // The opener's partition window and node spelling are derived from
    // the plan steps, not from `options.scheme`: `Mklabel`/`Mkpart` are
    // what `Mkpart` stamps, so a plan whose options disagree with its
    // steps still formats the stamped partition (see `opener_table_kind`).
    let (table, layout) = opener_table_kind(&parsed)?;
    let cancel = furus_linux::Cancel::new();
    cancel.install().map_err(Fail::from_core)?;
    if let Some(file) = paths.device_file.as_deref() {
        // Test seam: the plan's device path is never opened in this
        // mode, so a graded device cannot be written by accident — only
        // the seam file is touched.
        let opener = furus_linux::FileOpener::open(file, table, layout).map_err(Fail::from_core)?;
        run_plan(&parsed, &opener, &cancel, json, reset_usb)
    } else {
        let sysfs = paths.sysfs();
        let devices = furus_linux::enumerate(&sysfs).map_err(|core| Fail {
            exit: Exit::Device,
            kind: "device",
            message: core.to_string(),
        })?;
        let device = find_device(&devices, Path::new(&parsed.device.path))?;
        let opener = furus_linux::DeviceOpener::new(&device, table, layout, sysfs)
            .map_err(Fail::from_core)?;
        run_plan(&parsed, &opener, &cancel, json, reset_usb)
    }
}

/// The (`TableKind`, `LayoutKind`) pair the opener plans its partition
/// window and node spelling for: read off the plan's `Mklabel`/`Mkpart`
/// steps — the authority for what
/// [`Mkpart`](furus_proto::Step::Mkpart) stamps — never off
/// `options.scheme`, which is the planner's intent, not the stamped
/// table. The layout rides on the `Mkpart` step alone (`Mklabel` only
/// records the table); a plan whose options disagree with its steps
/// still runs against the stamped partition, while a plan whose steps
/// disagree with each other refuses here, before touching the device,
/// with the same exit class the in-run refusal would map to.
pub(crate) fn opener_table_kind(plan: &Plan) -> Result<(TableKind, LayoutKind), Fail> {
    let mut label: Option<Scheme> = None;
    let mut part: Option<Scheme> = None;
    let mut layout: Option<Layout> = None;
    for step in &plan.steps {
        match step {
            Step::Mklabel { scheme } => label = Some(scheme.clone()),
            Step::Mkpart {
                scheme,
                layout: step_layout,
            } => {
                part = Some(scheme.clone());
                if let Some(seen) = &layout {
                    if seen != step_layout {
                        return Err(Fail {
                            exit: Exit::Usage,
                            kind: "invalid_plan",
                            message: format!(
                                "plan steps disagree: mkpart asks for '{}' but also for '{}': refusing before touching the device",
                                human_layout(seen),
                                human_layout(step_layout),
                            ),
                        });
                    }
                } else {
                    layout = Some(step_layout.clone());
                }
            }
            _ => {}
        }
    }
    let table = match (label, part) {
        (Some(label), Some(part)) if label != part => {
            return Err(Fail {
                exit: Exit::Usage,
                kind: "invalid_plan",
                message: format!(
                    "plan steps disagree: mklabel asks for '{}' but mkpart asks for '{}': refusing before touching the device",
                    human_scheme(&label),
                    human_scheme(&part),
                ),
            });
        }
        (Some(scheme), _) | (None, Some(scheme)) => table_kind(&scheme),
        (None, None) => table_kind(&plan.options.scheme),
    };
    // Every planned run stamps an `Mkpart` step; a hand-built plan
    // without one keeps the single layout, the planner's default.
    let layout = match layout {
        Some(step_layout) => layout_kind(&step_layout),
        None => LayoutKind::Single,
    };
    Ok((table, layout))
}

/// The [`TableKind`] a plan [`Scheme`] asks for: the same mapping the
/// pipeline's `Mklabel`/`Mkpart` run with, so the opener's partition
/// window is planned for the table the steps stamp.
fn table_kind(scheme: &Scheme) -> TableKind {
    match scheme {
        Scheme::Mbr => TableKind::Mbr,
        Scheme::Gpt => TableKind::Gpt,
    }
}

/// The [`LayoutKind`] a plan [`Layout`] asks for: the same mapping the
/// pipeline's `Mkpart` runs with, so the opener's partition window and
/// node spelling cover the layout the steps stamp.
fn layout_kind(layout: &Layout) -> LayoutKind {
    match layout {
        Layout::Single => LayoutKind::Single,
        Layout::UefiNtfs => LayoutKind::UefiNtfs,
        Layout::WindowsToGo => LayoutKind::WindowsToGo,
        Layout::Persistence => LayoutKind::Persistence,
    }
}

/// Run `plan` against `opener` under the SIGINT `cancel` flag,
/// reporting per `json`. A clean run exits 0; every pipeline refusal
/// maps through [`Fail::from_core`] (I/O and verification → 4,
/// cancelled → 6, unimplemented → 7, anything else → 1).
fn run_plan(
    plan: &Plan,
    opener: &dyn furus_core::pipeline::Opener,
    cancel: &furus_linux::Cancel,
    json: bool,
    reset_usb: bool,
) -> Result<Exit, Fail> {
    let options = write_options(plan.options.verify, plan.options.bad_blocks, reset_usb);
    let probe = cancel.as_fn();
    if json {
        let mut reporter = JsonReporter;
        furus_core::pipeline::run(plan, opener, &options, &mut reporter, &probe)
            .map_err(Fail::from_core)?;
    } else {
        let mut reporter = HumanReporter::new();
        match furus_core::pipeline::run(plan, opener, &options, &mut reporter, &probe) {
            Ok(_) => {}
            Err(error) => {
                // Close the carriage-return progress line so the error
                // below starts on its own line.
                eprintln!();
                return Err(Fail::from_core(error));
            }
        }
    }
    Ok(Exit::Ok)
}

/// The [`RunOptions`](furus_core::pipeline::RunOptions) a `write` run
/// executes with: verify and surface-scan intent from the plan, the
/// `--reset-usb` flag verbatim, and the reference retry policy
/// (`0x140010a40`): three retries, five seconds apart. A pure
/// constructor so the flag plumbing is unit-testable without running a
/// plan.
pub(crate) fn write_options(
    verify: bool,
    bad_blocks: bool,
    reset_usb: bool,
) -> furus_core::pipeline::RunOptions {
    furus_core::pipeline::RunOptions {
        verify,
        badblocks: bad_blocks,
        retries: 3,
        retry_delay: std::time::Duration::from_secs(5),
        reset_usb,
    }
}

pub(crate) fn cmd_log(json: bool, lines: usize) -> Result<Exit, Fail> {
    let path = furus_core::paths::state_dir().join("furus.log");
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => Some(content),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => return Err(Fail::from_core(CoreError::io(&path, source))),
    };

    // A missing log is normal before the first run — say so, exit 0.
    let Some(content) = content else {
        if json {
            let object = serde_json::json!({
                "path": path.display().to_string(),
                "exists": false,
                "lines": [],
            });
            println!("{}", to_pretty(&object)?);
        } else {
            println!("no log file at {} (nothing logged yet)", path.display());
        }
        return Ok(Exit::Ok);
    };

    let all: Vec<&str> = content.lines().collect();
    let start = all.len().saturating_sub(lines);
    let shown = &all[start..];
    if json {
        let object = serde_json::json!({
            "path": path.display().to_string(),
            "exists": true,
            "lines": shown,
        });
        println!("{}", to_pretty(&object)?);
    } else {
        println!("log file: {}", path.display());
        println!("showing {} of {} lines", shown.len(), all.len());
        for line in shown {
            println!("{line}");
        }
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
