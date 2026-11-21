//! `furus`: command-line front end (S03–S05).
//!
//! Full command surface per PLAN §9-S03, driving the building blocks:
//!
//! * `version` — version, git hash, plan schema version;
//! * `checksum` — MD5/SHA-1/SHA-256/SHA-512 via `furus_core::hash`;
//! * `analyze` — size, SHA-256, magic-only container detection (S03),
//!   with the S05 `--device` report: partition table, probed
//!   filesystems, mounts, swap, holders and the PLAN §6 safety verdict
//!   — *reported*, exit 0 even when the verdict refuses (enforcement
//!   is the S06 helper's job, see [`commands::cmd_analyze`]; the sampling test
//!   hook is `--device-file`);
//! * `plan` — provisional plan JSON (the S06 helper contract), with
//!   `--dry-run` device-check relaxation and S04 device enrichment;
//! * `list` — S04 device discovery (sysfs + udev data), with the
//!   `--sysfs-root`/`--mountinfo` test hooks of PLAN §9-S04;
//! * `write` — validates the plan file (schema version + confirm
//!   hash) and runs it through the S17 pipeline against the planned
//!   device, or against the `--device-file` seam in tests; exit 7 only
//!   for image kinds with no tree reader (wim, vhd, vhdx, ffu, qcow2,
//!   pe) and `Copy` plans run over the `--device-file` seam (no
//!   partition node to mount).
//!   `write`
//!   is the one command whose failure goes to stderr in both modes:
//!   `--json` streams one `Event` object per stdout line, so the
//!   failure object (one compact JSON line, same `{"error","message"}`)
//!   goes to stderr to keep stdout pure JSONL.
//!
//! Exit codes: 0 ok, 1 usage, 2 device, 3 safety, 4 I/O, 5 unsupported
//! image, 6 cancelled, 7 not implemented — see [`Exit`]. clap errors are
//! mapped to 1 deliberately (clap's own default is 2).

#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use furus_core::error::CoreError;
use furus_core::planner;
use furus_linux::MountTable;
use furus_linux::SwapEntry;
use furus_linux::SysfsRoot;
use furus_linux::mounts::read_swaps;
use serde::Serialize;

use crate::cli::Cli;
use crate::cli::Command;
use crate::cli::validate_cluster;
use crate::commands::cmd_analyze;
use crate::commands::cmd_checksum;
use crate::commands::cmd_list;
use crate::commands::cmd_log;
use crate::commands::cmd_plan;
use crate::commands::cmd_version;
use crate::commands::cmd_write;

mod cli;
mod commands;
mod image;
mod output;
mod plan;

// ---------------------------------------------------------------------------
// Exit codes and failure reporting
// ---------------------------------------------------------------------------

/// Exit codes (PLAN §9-S03 table, plus `NotImplemented` for image
/// kinds with no tree reader and mounts no seam provides).
/// `UnsupportedImage`
/// has no producer yet (images the executor cannot serve arrive with a
/// later slice); the contract above is authoritative for callers, hence
/// the `dead_code` allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // UnsupportedImage returns with its slice
pub enum Exit {
    /// Success.
    Ok = 0,
    /// Usage or validation failure (clap errors map here too, not to 2).
    Usage = 1,
    /// Target device unusable or missing.
    Device = 2,
    /// Safety refusal (PLAN §2 fail closed).
    Safety = 3,
    /// I/O failure.
    Io = 4,
    /// Image kind that cannot be served by the (future) executor.
    UnsupportedImage = 5,
    /// User cancelled a long operation.
    Cancelled = 6,
    /// A planned step or mount the run cannot serve yet (image kinds
    /// with no tree reader, mounts with no node).
    NotImplemented = 7,
}

impl Exit {
    fn code(self) -> i32 {
        self as i32
    }
}

/// A command failure already mapped to an exit class and an error kind for
/// the `--json` error object.
pub struct Fail {
    /// Exit class of this failure.
    pub exit: Exit,
    /// Short machine name for the `--json` error object.
    pub kind: &'static str,
    /// One-line human description (no trailing newline).
    pub message: String,
}

impl Fail {
    /// Map a [`CoreError`] onto the exit table: I/O and verification
    /// failures → 4, cancellation → 6, unimplemented steps → 7,
    /// anything else is a validation failure → 1; the error `Display`
    /// names the path. Verification is a device-integrity failure
    /// (the bytes did not survive the round trip), not a usage error.
    /// Pipeline step wrappers are transparent: classification recurses
    /// into the wrapped error, so a device I/O failure inside a step
    /// still exits 4 while the message keeps its step prefix.
    fn from_core(err: CoreError) -> Self {
        fn exit_of(err: &CoreError) -> (Exit, &'static str) {
            match err {
                CoreError::Io { .. } => (Exit::Io, "io"),
                CoreError::Verify { .. } => (Exit::Io, "verify"),
                CoreError::Cancelled => (Exit::Cancelled, "cancelled"),
                CoreError::NotImplemented { .. } => (Exit::NotImplemented, "not_implemented"),
                CoreError::Step { source, .. } => exit_of(source),
                _ => (Exit::Usage, "invalid_input"),
            }
        }
        let (exit, kind) = exit_of(&err);
        Self {
            exit,
            kind,
            message: err.to_string(),
        }
    }

    /// Map a `serde_json` failure (confirm recompute or output format).
    ///
    /// Practically unreachable — every value this CLI serialises is
    /// JSON-native — but mapping instead of panicking keeps the whole CLI
    /// panic-free: a formatting failure is an I/O-class error (exit 4).
    fn json(message: String) -> Self {
        Self {
            exit: Exit::Io,
            kind: "json",
            message,
        }
    }
}

/// Map a shared-planner refusal onto the CLI's exit table, keeping the
/// pre-extraction class and `--json` kind for every case: a graded device
/// error is exit 2 (`device`), an existing non-block target is exit 3
/// (`safety`), option/pairing refusals are exit 1 (`usage`), and a failed
/// confirm recompute stays the I/O-class `json` failure.
fn fail_from_plan(err: planner::PlanError) -> Fail {
    match err {
        planner::PlanError::Device(message) => Fail {
            exit: Exit::Device,
            kind: "device",
            message,
        },
        planner::PlanError::Safety(message) => Fail {
            exit: Exit::Safety,
            kind: "safety",
            message,
        },
        planner::PlanError::Usage(message) => Fail {
            exit: Exit::Usage,
            kind: "usage",
            message,
        },
        planner::PlanError::Confirm(message) => Fail {
            exit: Exit::Io,
            kind: "json",
            message,
        },
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Pretty JSON for any CLI-produced value ([`furus_proto::Plan`], hand-built
/// `serde_json::Value` objects): every field is JSON-native, so
/// serialisation cannot fail in practice, but the error is propagated as a
/// [`Fail`] instead of being turned into a panic.
fn to_pretty<T: Serialize>(value: &T) -> Result<String, Fail> {
    serde_json::to_string_pretty(value)
        .map_err(|err| Fail::json(format!("failed to serialise JSON output: {err}")))
}

/// Machine-readable error object for `--json` runs.
fn json_error(kind: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "error": kind, "message": message })
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Filesystem paths the CLI should read host data from (PLAN §9-S04
/// test hooks). The defaults are the live system: `/sys` with
/// `/run/udev/data` records for discovery, the current-process
/// `/proc/self/mountinfo` for the mount table and `/proc/swaps` for
/// swap state. Discovery reads sysfs for every command; the two table
/// files are parsed by `analyze --device` (S05), which also honours
/// `--device-file`, with `--sysfs-root`, `--mountinfo`, `--swaps` and
/// `--device-file` pointing at fixture files instead.
struct HostPaths {
    /// sysfs root override from `--sysfs-root` (`None` = live `/sys`).
    sysfs_root: Option<PathBuf>,
    /// mountinfo file override from `--mountinfo` (`None` = current
    /// process). Parsed by `analyze --device`.
    mountinfo: Option<PathBuf>,
    /// swaps file override from `--swaps` (`None` = live `/proc/swaps`).
    /// Parsed by `analyze --device`.
    swaps: Option<PathBuf>,
    /// Device file override from `--device-file` (`None` = sample the
    /// discovered device node). The `analyze --device` sampling test
    /// hook: it replaces only the file the inspection half opens; the
    /// graded device stays the discovered one.
    device_file: Option<PathBuf>,
}

impl HostPaths {
    /// The discovery root/records pair to read from.
    ///
    /// An override root is self-contained: `SysfsRoot::new` keeps its
    /// udev record directory inside the tree (`<root>/run/udev/data`).
    fn sysfs(&self) -> SysfsRoot {
        SysfsRoot::new(self.sysfs_root.clone().unwrap_or(PathBuf::from("/sys")))
    }

    /// The mount table the S05 inspection matches device numbers
    /// against: the `--mountinfo` fixture file or the live `/proc`.
    ///
    /// A failure here is host state, not bad input: the file cannot be
    /// read or is rot. Device class, exit 2, never [`Fail::from_core`].
    fn mount_table(&self) -> Result<MountTable, Fail> {
        MountTable::read(self.mountinfo.as_deref()).map_err(|err| Fail {
            exit: Exit::Device,
            kind: "device",
            message: err.to_string(),
        })
    }

    /// The parsed `/proc/swaps` rows: the `--swaps` fixture file or the
    /// live one. Same failure etiquette as [`HostPaths::mount_table`].
    fn swaps(&self) -> Result<Vec<SwapEntry>, Fail> {
        read_swaps(self.swaps.as_deref()).map_err(|err| Fail {
            exit: Exit::Device,
            kind: "device",
            message: err.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(cli: &Cli, paths: &HostPaths) -> Result<Exit, Fail> {
    let json = cli.json;
    match &cli.command {
        Command::Version => cmd_version(json),
        Command::Checksum { image, algo } => cmd_checksum(json, image, *algo),
        Command::Analyze {
            image,
            device,
            confirm_serial,
        } => {
            // PLAN §6 rule 4 needs a *typed* serial comparable to the
            // device's own: trim once, here at acceptance, so the
            // non-empty check below and the exact comparison inside
            // `judge` see the same value. Refused before any inspection
            // work, in both output modes.
            let confirm_serial = confirm_serial.as_deref().map(str::trim);
            if confirm_serial.is_some_and(|serial| serial.is_empty()) {
                return Err(Fail {
                    exit: Exit::Usage,
                    kind: "usage",
                    message: "confirmation serial must not be empty".to_owned(),
                });
            }
            cmd_analyze(
                json,
                image,
                device.as_deref(),
                confirm_serial,
                cli.extra_devs,
                paths,
            )
        }
        // S04 hook note: `-x/--extra-devs` is the Furus-legacy spelling
        // of `--all`; `list` picks up whichever is set.
        Command::List { all } => cmd_list(json, *all, cli.extra_devs, &paths.sysfs()),
        Command::Plan {
            image,
            device,
            scheme,
            target,
            filesystem,
            iso_mode,
            bootloader,
            label,
            cluster,
            quick,
            badblocks,
            verify,
            persistence,
            show_all,
            confirm_serial,
            msdos_dir,
        } => {
            // Gate first, before grading or image inspection: in every
            // mode (JSON or human) an invalid cluster must exit 1 and
            // write nothing — the plan path builds objects only, but the
            // ask comes before any work regardless.
            let cluster_bytes = cluster
                .map(validate_cluster)
                .transpose()
                .map_err(|message| Fail {
                    exit: Exit::Usage,
                    kind: "usage",
                    message,
                })?;
            // PLAN §6 rule 4 needs the typed serial alongside --show-all,
            // and a blank-typed serial confirms nothing. Trimmed once,
            // here at acceptance, exactly like `analyze --confirm-serial`;
            // both refusals fire before any device/image work in both
            // output modes.
            let confirm_serial = confirm_serial.as_deref().map(str::trim);
            if confirm_serial.is_some_and(|serial| serial.is_empty()) {
                return Err(Fail {
                    exit: Exit::Usage,
                    kind: "usage",
                    message: "confirmation serial must not be empty".to_owned(),
                });
            }
            if confirm_serial.is_some() && !*show_all {
                return Err(Fail {
                    exit: Exit::Usage,
                    kind: "usage",
                    message: "confirmation serial requires --show-all".to_owned(),
                });
            }
            cmd_plan(
                json,
                cli.dry_run,
                image,
                device,
                &paths.sysfs(),
                &planner::Options {
                    scheme: scheme.clone(),
                    target: target.clone(),
                    filesystem: filesystem.clone(),
                    iso_mode: *iso_mode,
                    bootloader: (*bootloader).into(),
                    msdos_dir: msdos_dir.clone(),
                    label: label.clone(),
                    cluster_bytes,
                    quick_format: *quick,
                    bad_blocks: *badblocks,
                    verify: *verify,
                    persistence: *persistence,
                    show_all: *show_all,
                    confirmed_serial: confirm_serial.map(str::to_owned),
                },
            )
        }
        Command::Write { plan, reset_usb } => cmd_write(json, plan, paths, *reset_usb),
        Command::Log { lines } => cmd_log(json, *lines),
    }
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // clap prints the help/error itself; its default exit code is 2
            // for parse errors (0 for --help/--version), while this CLI's
            // contract maps every parse failure to exit 1.
            let _ = err.print();
            let exit = if err.use_stderr() {
                Exit::Usage
            } else {
                Exit::Ok
            };
            std::process::exit(exit.code());
        }
    };

    // Flags inert in this slice are accepted (their wiring lands with S06
    // wait/yes/progress verbosity, S24 locale/GUI). They are consumed here
    // so the inertness is visible in code — and so the unused-field lint
    // stays quiet. `extra_devs` left the list: `list` consumes it since
    // S04, and `analyze --device` uses it as the PLAN §6 rule-4 gate
    // since S05.
    let _ = (cli.verbose, cli.quiet, cli.yes, cli.gui, cli.iso, cli.wait);
    let _ = cli.locale.as_deref();

    let paths = HostPaths {
        sysfs_root: cli.sysfs_root.clone(),
        mountinfo: cli.mountinfo.clone(),
        swaps: cli.swaps.clone(),
        device_file: cli.device_file.clone(),
    };

    match dispatch(&cli, &paths) {
        Ok(exit) => std::process::exit(exit.code()),
        Err(fail) => {
            // `write` failures go to stderr in both modes: `--json`
            // streams one `Event` object per stdout line, and a
            // pretty-printed error object on stdout would break that
            // stream (see the module docs). Every other command keeps
            // the `--json` error object on stdout. A failure to render
            // the object itself (practically impossible) restores the
            // human line on stderr so the failure is never dropped.
            let is_write = matches!(cli.command, Command::Write { .. });
            if is_write {
                if cli.json {
                    match serde_json::to_string(&json_error(fail.kind, &fail.message)) {
                        Ok(line) => eprintln!("{line}"),
                        Err(_) => eprintln!("furus: {}", fail.message),
                    }
                } else {
                    eprintln!("furus: {}", fail.message);
                }
            } else {
                let json_line = if cli.json {
                    to_pretty(&json_error(fail.kind, &fail.message)).ok()
                } else {
                    None
                };
                match json_line {
                    Some(text) => println!("{text}"),
                    None => eprintln!("furus: {}", fail.message),
                }
            }
            std::process::exit(fail.exit.code());
        }
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
