//! `rufus`: command-line front end (S03/S04).
//!
//! Full command surface per PLAN §9-S03, driving the building blocks:
//!
//! * `version` — version, git hash, plan schema version;
//! * `checksum` — MD5/SHA-1/SHA-256/SHA-512 via `rufus-core::hash`;
//! * `analyze` — size, SHA-256, magic-only container detection;
//! * `plan` — provisional plan JSON (the S06 helper contract), with
//!   `--dry-run` device-check relaxation and S04 device enrichment;
//! * `list` — S04 device discovery (sysfs + udev data), with the
//!   `--sysfs-root`/`--mountinfo` test hooks of PLAN §9-S04;
//! * `write` — arguments validated, then honestly *not implemented*
//!   (exit 7) until S06/S17.
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
use rufus_linux::SysfsRoot;
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

/// `list --json` output: the filtered device list plus the show-all echo.
///
/// One struct instead of a hand-built `json!` value, so serialisation
/// cannot fail between fields and the key order stays declaration-stable
/// (the CLI must be panic-free).
#[derive(Serialize)]
struct ListOutput<'a> {
    /// Candidate devices, name-sorted by discovery.
    devices: &'a [rufus_linux::Device],
    /// Whether internal fixed disks were included in `devices`.
    show_all: bool,
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Filesystem paths the CLI should read host data from (PLAN §9-S04 test
/// hooks). The defaults are the live system: `/sys` with `/run/udev/data`
/// records for discovery and the current-process `mountinfo` for the S05
/// mount checks.
struct HostPaths {
    /// sysfs root override from `--sysfs-root` (`None` = live `/sys`).
    sysfs_root: Option<PathBuf>,
    /// mountinfo file override from `--mountinfo` (`None` = current
    /// process). Parsed by S05.
    mountinfo: Option<PathBuf>,
}

impl HostPaths {
    /// The discovery root/records pair to read from.
    ///
    /// An override root is self-contained: `SysfsRoot::new` keeps its
    /// udev record directory inside the tree (`<root>/run/udev/data`).
    fn sysfs(&self) -> SysfsRoot {
        SysfsRoot::new(self.sysfs_root.clone().unwrap_or(PathBuf::from("/sys")))
    }
}

/// Native Linux USB/ISO writer — command line (slice S03 by the schema,
/// with the S04 device surface wired on top).
#[derive(Debug, Parser)]
#[command(
    name = "rufus",
    version,
    about = "Native Linux USB/ISO writer — command line rewrite (slice S04)"
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

    // S04/S05 test hooks (PLAN §9-S04): the defaults are the live system
    // (`/sys` with `/run/udev/data` records, current-process mountinfo);
    // the flags point at small fixture trees so tests and containers
    // never touch real state.
    /// Root of a (possibly synthetic) sysfs tree for device discovery
    /// (S04 test hook; default: the live `/sys`).
    #[arg(long, value_name = "DIR", global = true)]
    sysfs_root: Option<PathBuf>,
    /// Path to a `/proc/self/mountinfo`-shaped file (S05 test hook; the
    /// mount-detection slices parse it, accepted now so the CLI surface
    /// is final).
    #[arg(long, value_name = "FILE", global = true)]
    mountinfo: Option<PathBuf>,

    // Rufus legacy parity switches — parsed and documented; the S04
    // discovery switch is live in `list`, the rest land with S06/S24.
    /// Show all devices, including fixed disks (S04: `list` honours it
    /// and turns on the destruction warning; the exact rule is stated
    /// once on the `cmd_list` function).
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

    /// List candidate USB devices from sysfs + udev data (S04).
    ///
    /// Mirrors Rufus's default: USB-or-removable only, built-in and
    /// zero-size entries dropped; `--all` (together with the global
    /// `-x/--extra-devs`) reveals internal fixed disks. The destruction
    /// warning rule is stated once, on the `cmd_list` implementation.
    List {
        /// Reveal fixed disks too ("show all devices" parity; the
        /// warning rule lives on the `cmd_list` implementation).
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
        /// Cluster size for the data filesystem, in bytes (power of two
        /// between 512 and 1048576; per-filesystem limits land with the
        /// S09–S13 writers).
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

/// Cluster size gate for `plan --cluster` (S03 review): a power of two,
/// 512..=1_048_576 bytes. Per-filesystem maxima (FAT's cluster count and
/// friends) are the writers' business in S09–S13, checked against the
/// real device geometry; this check only refuses sizes no filesystem of
/// the plan shape can want, keeping the plan schema engine-independent.
fn validate_cluster(bytes: u32) -> std::result::Result<u32, String> {
    const MIN: u32 = 512;
    const MAX: u32 = 1_048_576;
    if bytes.is_power_of_two() && (MIN..=MAX).contains(&bytes) {
        Ok(bytes)
    } else {
        Err(format!(
            "invalid cluster size '{bytes}' (expected a power of two between 512 and 1048576 bytes)"
        ))
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

/// S04 discovery: enumerate candidates through sysfs + udev data and
/// print the filtered list.
///
/// Mirrors Rufus's removable-only default; `--all`/`-x` reveal internal
/// fixed disks. The destruction warning is the one canonical statement
/// in this module's surface: **whenever show-all mode is on, the PLAN
/// §6 rule-4 line prints to stderr exactly once per run — even if that
/// run lists only removable devices.** Discovery failure (a missing or
/// unreadable class directory) is a device-class error: exit 2, and the
/// `--json` error object keeps the standard `{"error","message"}` shape.
fn cmd_list(
    json: bool,
    all: bool,
    legacy_extra_devs: bool,
    sysfs: &SysfsRoot,
) -> Result<Exit, Fail> {
    let show_all = all || legacy_extra_devs;
    let filter = rufus_linux::Filter { show_all };
    let devices = rufus_linux::enumerate(sysfs)
        .map(|enumerated| rufus_linux::filter(enumerated, filter))
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
                rufus_core::human_bytes(device.size_bytes),
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

fn cmd_plan(
    json: bool,
    dry_run: bool,
    image_path: &Path,
    device_path: &Path,
    sysfs: &SysfsRoot,
    options: &plan::Options,
) -> Result<Exit, Fail> {
    // Safety first: grade the device (exit 2/3 without --dry-run), then the
    // image (exit 4/1), then assemble and seal the plan. The S04 facts
    // (size/serial/model/sysfs) ride along when the device is discoverable
    // on `sysfs`, and stay `None` otherwise.
    let device = plan::device_ref(device_path, dry_run, sysfs)?;
    let inspected = image::inspect(image_path).map_err(Fail::from_core)?;
    let built = plan::build(device, inspected, options)?;
    if json {
        // `println!` keeps `plan --json` output line-oriented: scripts
        // and `jq` always see one complete line, never a cut-off value.
        println!("{}", to_pretty(&built)?);
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

fn dispatch(cli: &Cli, paths: &HostPaths) -> Result<Exit, Fail> {
    let json = cli.json;
    match &cli.command {
        Command::Version => cmd_version(json),
        Command::Checksum { image, algo } => cmd_checksum(json, image, *algo),
        Command::Analyze { image } => cmd_analyze(json, image),
        // S04 hook note: `-x/--extra-devs` is the Rufus-legacy spelling
        // of `--all`; `list` picks up whichever is set.
        Command::List { all } => cmd_list(json, *all, cli.extra_devs, &paths.sysfs()),
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
            cmd_plan(
                json,
                cli.dry_run,
                image,
                device,
                &paths.sysfs(),
                &plan::Options {
                    scheme: scheme.clone(),
                    target: target.clone(),
                    filesystem: filesystem.clone(),
                    label: label.clone(),
                    cluster_bytes,
                    quick_format: *quick,
                    bad_blocks: *badblocks,
                    verify: *verify,
                    persistence: *persistence,
                    show_all: *show_all,
                },
            )
        }
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

    // Flags inert in this slice are accepted (their wiring lands with S06
    // wait/yes/progress verbosity, S24 locale/GUI). They are consumed here
    // so the inertness is visible in code — and so the unused-field lint
    // stays quiet. `extra_devs` left the list: `list` consumes it now.
    let _ = (cli.verbose, cli.quiet, cli.yes, cli.gui, cli.iso, cli.wait);
    let _ = cli.locale.as_deref();

    let paths = HostPaths {
        sysfs_root: cli.sysfs_root.clone(),
        mountinfo: cli.mountinfo.clone(),
    };
    // Accepted now, wired later: S05 parses this mountinfo file (the flag
    // is its PLAN §9-S04 test hook). Binding it keeps the surface final
    // without pretending the file was read.
    let _ = &paths.mountinfo;

    match dispatch(&cli, &paths) {
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
