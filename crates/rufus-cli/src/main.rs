//! `rufus`: command-line front end (S03).
//!
//! Full command surface per PLAN §9-S03, driving the S03 building blocks:
//!
//! * `version` — version, git hash, plan schema version;
//! * `checksum` — MD5/SHA-1/SHA-256/SHA-512 via `rufus-core::hash`;
//! * `analyze` — size, SHA-256, magic-only container detection;
//! * `plan` — provisional plan JSON (the S06 helper contract), with
//!   `--dry-run` device-check relaxation;
//! * `write` / `list` — arguments validated, then honestly *not
//!   implemented* (exit 7) until S06/S17 and S04 respectively.
//!
//! Exit codes: 0 ok, 1 usage, 2 device, 3 safety, 4 I/O, 5 unsupported
//! image, 6 cancelled, 7 not implemented — see [`Exit`]. clap errors are
//! mapped to 1 deliberately (clap's own default is 2).

use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use rufus_core::error::CoreError;
use rufus_core::hash::Algo;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Scheme;
use rufus_proto::Step;
use rufus_proto::Target;
use serde::Serialize;

mod image;
mod plan;

// ---------------------------------------------------------------------------
// Exit codes and failure reporting
// ---------------------------------------------------------------------------

/// Exit codes (PLAN §9-S03 table, plus `NotImplemented` for the stubs this
/// slice ships). Not every class is reachable yet; the contract above is
/// authoritative for callers, hence the `dead_code` allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Cancelled/UnsupportedImage return with their slices
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
    /// Subcommand exists but ships with a later slice.
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
    /// Map a [`CoreError`] onto the exit table: I/O → 4, anything else is
    /// a validation failure → 1; the error `Display` names the path.
    fn from_core(err: CoreError) -> Self {
        let (exit, kind) = match &err {
            CoreError::Io { .. } => (Exit::Io, "io"),
            _ => (Exit::Usage, "invalid_input"),
        };
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

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Pretty JSON for any CLI-produced value ([`Plan`], hand-built
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

/// Native Linux USB/ISO writer — command line (slice S03).
#[derive(Debug, Parser)]
#[command(
    name = "rufus",
    version,
    about = "Native Linux USB/ISO writer — command line rewrite (slice S03)"
)]
struct Cli {
    /// Emit machine-readable JSON for results and errors.
    #[arg(long, global = true)]
    json: bool,

    // Accepted now, wired later, so scripts written against the final
    // surface keep running: progress verbosity lands with S06/S24.
    /// Verbose output (wiring arrives with S06 progress and S24).
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    /// Quiet output (wiring arrives with S06/S24).
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    /// Locale tag, e.g. `de_DE` (accepted; wiring arrives in S24).
    #[arg(short = 'l', long = "locale", value_name = "TAG", global = true)]
    locale: Option<String>,
    /// Assume "yes" for confirmation prompts (wired with the S06 chooser).
    #[arg(long, global = true)]
    yes: bool,
    /// Build the plan without touching the device; relaxes device checks
    /// (missing or non-block devices are allowed, reported as
    /// `block_device: false`).
    #[arg(long, global = true)]
    dry_run: bool,

    // Rufus legacy parity switches — parsed, documented, inert in S03.
    /// Show all devices, including fixed disks (no effect yet: arrives
    /// with S04 device discovery).
    #[arg(short = 'x', long = "extra-devs", global = true)]
    extra_devs: bool,
    /// Launch the graphical front end instead of the CLI (no effect yet:
    /// arrives with S24).
    #[arg(short = 'g', long, global = true)]
    gui: bool,
    /// Select an ISO image for the legacy invocation style (no effect in
    /// S03; `plan --image` is the live image switch).
    #[arg(short = 'i', long, global = true)]
    iso: bool,
    /// Wait for outstanding writes before exiting (no effect yet: S06).
    #[arg(short = 'w', long, global = true)]
    wait: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print version, git hash and plan schema version.
    Version,

    /// Compute a checksum of IMAGE like `md5sum` or `sha256sum`.
    Checksum {
        /// Image file to hash (a regular file).
        image: PathBuf,
        /// Digest algorithm; defaults to SHA-256 like the plan contract.
        #[arg(long, value_name = "ALGO", default_value = "sha256")]
        algo: Algo,
    },

    /// Report size, SHA-256 and detected container kind of IMAGE.
    ///
    /// Detection is by magic bytes only in this slice; full container
    /// readers (ISO9660, WIM, VHD, ...) arrive with S14–S16.
    Analyze {
        /// Image file to inspect (a regular file).
        image: PathBuf,
    },

    /// List candidate USB devices.
    ///
    /// Device discovery ships with S04 (sysfs + udev data); this stub
    /// prints a not-implemented notice to stderr and exits 7.
    List {
        /// Reveal fixed disks too ("show all devices" parity).
        #[arg(long)]
        all: bool,
    },

    /// Build the provisional write plan for IMAGE to DEVICE and print it.
    ///
    /// The steps describe what happens, in order — wipe, mklabel, mkpart,
    /// mkfs, write, bootloader, finalize — deliberately without
    /// offset-level detail: exact LBA placement, alignment and engine
    /// arguments are computed by the S17 executor against the device
    /// geometry. Nothing here writes to the device.
    Plan {
        /// Image file to write.
        #[arg(long, value_name = "FILE")]
        image: PathBuf,
        /// Target device path, e.g. /dev/sdb (must be a real block device
        /// unless --dry-run is given).
        #[arg(long, value_name = "DEVICE")]
        device: PathBuf,
        /// Partition table scheme (default: mbr; S16 classification will
        /// recommend per-image defaults later).
        #[arg(long, value_parser = parse_scheme, default_value = "mbr")]
        scheme: Scheme,
        /// Firmwares the media must boot (default: dual).
        #[arg(long, value_parser = parse_target, default_value = "dual")]
        target: Target,
        /// Data-partition filesystem (default: fat32).
        #[arg(
            short = 'f',
            long = "filesystem",
            value_parser = parse_filesystem,
            default_value = "fat32"
        )]
        filesystem: rufus_proto::Filesystem,
        /// Volume label (default: executor derives it from the image).
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
        /// Cluster size for the data filesystem, in bytes.
        #[arg(long, value_name = "BYTES")]
        cluster: Option<u32>,
        /// Quick format (metadata only) instead of a full surface format.
        #[arg(long)]
        quick: bool,
        /// Scan for bad blocks while formatting.
        #[arg(long)]
        badblocks: bool,
        /// Read the written image back for verification.
        #[arg(long)]
        verify: bool,
        /// Add a persistence partition for Linux live media.
        #[arg(long)]
        persistence: bool,
        /// Record that "show all devices" was enabled.
        #[arg(long)]
        show_all: bool,
    },

    /// Execute a previously saved plan file.
    ///
    /// With --plan the file is checked (schema version + confirm hash);
    /// mismatches exit 1. Executing the plan arrives with S06 (helper) and
    /// S17 (pipeline), so a valid plan today ends with exit 7.
    Write {
        /// Plan JSON file produced by `rufus plan`.
        #[arg(long, value_name = "FILE")]
        plan: PathBuf,
    },

    /// Print the log file location and the last N log lines.
    ///
    /// The GUI/helper write `$XDG_STATE_HOME/rufus-linux/rufus.log` from
    /// S06 on; an absent file is reported calmly and is not an error here.
    Log {
        /// How many trailing lines to show.
        #[arg(long, value_name = "N", default_value = "50")]
        lines: usize,
    },
}

/// `mbr`/`gpt` (ASCII, case-insensitive) → [`Scheme`].
fn parse_scheme(text: &str) -> Result<Scheme, String> {
    match text.to_ascii_lowercase().as_str() {
        "mbr" => Ok(Scheme::Mbr),
        "gpt" => Ok(Scheme::Gpt),
        other => Err(format!("invalid scheme '{other}' (expected mbr or gpt)")),
    }
}

/// `bios`/`uefi`/`dual` (ASCII, case-insensitive) → [`Target`].
fn parse_target(text: &str) -> Result<Target, String> {
    match text.to_ascii_lowercase().as_str() {
        "bios" => Ok(Target::Bios),
        "uefi" => Ok(Target::Uefi),
        "dual" => Ok(Target::Dual),
        other => Err(format!(
            "invalid target '{other}' (expected bios, uefi or dual)"
        )),
    }
}

/// `fat32|exfat|ntfs|ext2|ext3|ext4|udf` (ASCII, case-insensitive) →
/// [`rufus_proto::Filesystem`].
fn parse_filesystem(text: &str) -> Result<rufus_proto::Filesystem, String> {
    use rufus_proto::Filesystem;
    match text.to_ascii_lowercase().as_str() {
        "fat32" => Ok(Filesystem::Fat32),
        "exfat" => Ok(Filesystem::Exfat),
        "ntfs" => Ok(Filesystem::Ntfs),
        "ext2" => Ok(Filesystem::Ext2),
        "ext3" => Ok(Filesystem::Ext3),
        "ext4" => Ok(Filesystem::Ext4),
        "udf" => Ok(Filesystem::Udf),
        other => Err(format!(
            "invalid filesystem '{other}' (expected fat32, exfat, ntfs, ext2, ext3, ext4 or udf)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

fn cmd_version(json: bool) -> Result<Exit, Fail> {
    if json {
        let object = serde_json::json!({
            "version": rufus_core::version(),
            "git_hash": rufus_core::git_hash(),
            "plan_version": PLAN_VERSION,
        });
        println!("{}", to_pretty(&object)?);
    } else {
        println!(
            "rufus {} ({})",
            rufus_core::version(),
            rufus_core::git_hash()
        );
    }
    Ok(Exit::Ok)
}

fn cmd_checksum(json: bool, path: &Path, algo: Algo) -> Result<Exit, Fail> {
    // Regular-file check first so a directory gives a validation error, not
    // a read error from inside the stream digest.
    let size = image::image_size(path).map_err(Fail::from_core)?;
    let digest = rufus_core::hash_file_with(algo, path).map_err(Fail::from_core)?;
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

fn cmd_analyze(json: bool, path: &Path) -> Result<Exit, Fail> {
    let inspected = image::inspect(path).map_err(Fail::from_core)?;
    if json {
        let object = serde_json::json!({
            "path": inspected.path,
            "size_bytes": inspected.size_bytes,
            "sha256": inspected.sha256,
            "kind": inspected.kind.to_string(),
        });
        println!("{}", to_pretty(&object)?);
    } else {
        println!("image:  {}", inspected.path);
        println!(
            "size:   {} ({})",
            inspected.size_bytes,
            rufus_core::human_bytes(inspected.size_bytes)
        );
        println!("kind:   {}", inspected.kind);
        println!("sha256: {}", inspected.sha256);
    }
    Ok(Exit::Ok)
}

fn cmd_list(json: bool) -> Result<Exit, Fail> {
    // Honest stub: device enumeration (sysfs + udev data) ships in S04.
    // The stderr notice prints in both modes; JSON keeps the exact
    // {"error","slice"} contract shape.
    eprintln!("list: not implemented yet — device discovery ships in slice S04");
    if json {
        let object = serde_json::json!({ "error": "not_implemented", "slice": "S04" });
        println!("{}", to_pretty(&object)?);
    }
    Ok(Exit::NotImplemented)
}

fn cmd_plan(
    json: bool,
    dry_run: bool,
    image_path: &Path,
    device_path: &Path,
    options: &plan::Options,
) -> Result<Exit, Fail> {
    // Safety first: grade the device (exit 2/3 without --dry-run), then the
    // image (exit 4/1), then assemble and seal the plan.
    let device = plan::device_ref(device_path, dry_run)?;
    let inspected = image::inspect(image_path).map_err(Fail::from_core)?;
    let built = plan::build(device, inspected, options)?;
    if json {
        print!("{}", to_pretty(&built)?);
    } else {
        print_human_plan(&built);
    }
    Ok(Exit::Ok)
}

fn cmd_write(json: bool, plan_path: &Path) -> Result<Exit, Fail> {
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
    // The plan verifies; dispatch is S06, the pipeline is S17.
    eprintln!(
        "write: plan verifies (device {}, image {}); writing is not implemented yet (S06/S17)",
        parsed.device.path, parsed.image.path
    );
    if json {
        let object = serde_json::json!({ "error": "not_implemented", "slice": "S06/S17" });
        println!("{}", to_pretty(&object)?);
    }
    Ok(Exit::NotImplemented)
}

fn cmd_log(json: bool, lines: usize) -> Result<Exit, Fail> {
    let path = rufus_core::paths::state_dir().join("rufus.log");
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

// ---------------------------------------------------------------------------
// Human plan rendering
// ---------------------------------------------------------------------------

/// Human summary for `plan` (same data as the `--json` object).
fn print_human_plan(built: &Plan) {
    println!("plan (version {})", built.version);
    println!(
        "image:  {} ({} B, {})",
        built.image.path, built.image.size_bytes, built.image.kind
    );
    println!(
        "device: {} (block device: {})",
        built.device.path, built.device.block_device
    );
    println!(
        "options: scheme {} target {} filesystem {} label {} cluster {} quick {} badblocks {} verify {} persistence {} show-all {}",
        human_scheme(&built.options.scheme),
        human_target(&built.options.target),
        human_filesystem(&built.options.filesystem),
        human_optional(&built.options.label),
        match built.options.cluster_bytes {
            Some(bytes) => bytes.to_string(),
            None => "<auto>".to_string(),
        },
        human_lead(built.options.quick_format),
        human_lead(built.options.bad_blocks),
        human_lead(built.options.verify),
        human_lead(built.options.persistence),
        human_lead(built.options.show_all),
    );
    println!("steps:");
    for (index, step) in built.steps.iter().enumerate() {
        println!("  {:>2}. {}", index + 1, describe_step(step));
    }
    println!("confirm: {}", built.confirm);
}

fn human_lead(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn human_optional(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<none>".to_string())
}

/// Human-friendly scheme tag (matches the plan JSON values).
fn human_scheme(scheme: &rufus_proto::Scheme) -> &'static str {
    match scheme {
        rufus_proto::Scheme::Mbr => "mbr",
        rufus_proto::Scheme::Gpt => "gpt",
    }
}

fn human_target(target: &Target) -> &'static str {
    match target {
        Target::Bios => "bios",
        Target::Uefi => "uefi",
        Target::Dual => "dual",
    }
}

fn human_filesystem(filesystem: &rufus_proto::Filesystem) -> &'static str {
    use rufus_proto::Filesystem;
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

/// One line per step; tags mirror the JSON `op` values.
fn describe_step(step: &Step) -> String {
    match step {
        Step::Wipe => "wipe (clear first/last MiB, rescan)".to_string(),
        Step::Mklabel { scheme } => format!("mklabel (scheme {})", human_scheme(scheme)),
        Step::Mkpart { scheme } => format!("mkpart (scheme {})", human_scheme(scheme)),
        Step::Mkfs {
            filesystem,
            label,
            cluster_bytes,
            quick,
        } => format!(
            "mkfs (fs {}, label {}, cluster {}, quick {})",
            human_filesystem(filesystem),
            human_optional(label),
            match cluster_bytes {
                Some(bytes) => bytes.to_string(),
                None => "<auto>".to_string(),
            },
            human_lead(*quick)
        ),
        Step::Write { mode } => format!(
            "write (mode {})",
            match mode {
                rufus_proto::WriteMode::Dd => "dd",
                rufus_proto::WriteMode::Copy => "copy",
            }
        ),
        Step::Bootloader { mode } => format!(
            "bootloader (mode {})",
            match mode {
                rufus_proto::BootloaderMode::Auto => "auto",
                rufus_proto::BootloaderMode::Syslinux => "syslinux",
                rufus_proto::BootloaderMode::Grub2 => "grub2",
                rufus_proto::BootloaderMode::Grub4dos => "grub4dos",
                rufus_proto::BootloaderMode::UefiNtfs => "uefi_ntfs",
                rufus_proto::BootloaderMode::Freedos => "freedos",
                rufus_proto::BootloaderMode::None => "none",
            }
        ),
        Step::Finalize => "finalize (flush, checks, rescan)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(cli: &Cli) -> Result<Exit, Fail> {
    let json = cli.json;
    match &cli.command {
        Command::Version => cmd_version(json),
        Command::Checksum { image, algo } => cmd_checksum(json, image, *algo),
        Command::Analyze { image } => cmd_analyze(json, image),
        Command::List { .. } => cmd_list(json),
        Command::Plan {
            image,
            device,
            scheme,
            target,
            filesystem,
            label,
            cluster,
            quick,
            badblocks,
            verify,
            persistence,
            show_all,
        } => cmd_plan(
            json,
            cli.dry_run,
            image,
            device,
            &plan::Options {
                scheme: scheme.clone(),
                target: target.clone(),
                filesystem: filesystem.clone(),
                label: label.clone(),
                cluster_bytes: *cluster,
                quick_format: *quick,
                bad_blocks: *badblocks,
                verify: *verify,
                persistence: *persistence,
                show_all: *show_all,
            },
        ),
        Command::Write { plan } => cmd_write(json, plan),
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

    // Flags inert in this slice are accepted (their wiring lands with S04
    // extra-devs, S06 wait/yes/progress verbosity, S24 locale/GUI). They
    // are consumed here so the inertness is visible in code — and so the
    // unused-field lint stays quiet.
    let _ = (
        cli.verbose,
        cli.quiet,
        cli.yes,
        cli.extra_devs,
        cli.gui,
        cli.iso,
        cli.wait,
    );
    let _ = cli.locale.as_deref();

    match dispatch(&cli) {
        Ok(exit) => std::process::exit(exit.code()),
        Err(fail) => {
            // `--json` error objects go to stdout; if even that formatting
            // fails (practically impossible), restore the human line on
            // stderr so the failure is never silently dropped.
            let json_line = if cli.json {
                to_pretty(&json_error(fail.kind, &fail.message)).ok()
            } else {
                None
            };
            match json_line {
                Some(text) => println!("{text}"),
                None => eprintln!("rufus: {}", fail.message),
            }
            std::process::exit(fail.exit.code());
        }
    }
}
