//! `rufus`: command-line front end (S03–S05).
//!
//! Full command surface per PLAN §9-S03, driving the building blocks:
//!
//! * `version` — version, git hash, plan schema version;
//! * `checksum` — MD5/SHA-1/SHA-256/SHA-512 via `rufus-core::hash`;
//! * `analyze` — size, SHA-256, magic-only container detection (S03),
//!   with the S05 `--device` report: partition table, probed
//!   filesystems, mounts, swap, holders and the PLAN §6 safety verdict
//!   — *reported*, exit 0 even when the verdict refuses (enforcement
//!   is the S06 helper's job, see [`cmd_analyze`]; the sampling test
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

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use clap::Subcommand;
use rufus_core::error::CoreError;
use rufus_core::hash::Algo;
use rufus_core::part::plan::LayoutKind;
use rufus_core::partition::TableKind;
use rufus_core::pipeline::Event;
use rufus_core::safety::SafetyVerdict;
use rufus_core::text::device_text;
use rufus_linux::MountTable;
use rufus_linux::SwapEntry;
use rufus_linux::SysfsRoot;
use rufus_linux::mounts::read_swaps;
use rufus_proto::Layout;
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

/// `analyze --json` output: owned-field structs instead of a hand-built
/// `json!` value (the same panic-free, declaration-stable spelling as
/// [`ListOutput`]). The image part keeps the pre-S05 four-key shape
/// byte for byte — `path`, `size_bytes`, `sha256`, `kind` keep their
/// names, order and values; `report` is additive, always present. The
/// `device` member only serialises with `--device`. The human form
/// prints a one-line `report:` summary after `sha256:` instead — `--json`
/// carries the whole report.
#[derive(Serialize)]
struct AnalyzeOutput {
    /// Image path as given on the command line.
    path: String,
    /// Regular-file length in bytes.
    size_bytes: u64,
    /// SHA-256 over the whole image, lowercase hex.
    sha256: String,
    /// Container kind (magic-only detection in this slice).
    kind: String,
    /// The S05 device report; skipped without `--device` so the
    /// pre-S05 JSON contract stays exactly four keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<AnalyzeDevice>,
    /// The S16 image report, always serialized; `null` when the report
    /// could not be produced — the volume probed positive but the
    /// reader refused it (a corrupt or truncated image), or reading the
    /// image failed — so a broken ISO never turns `analyze` into an
    /// error.
    report: Option<rufus_core::report::ImageReport>,
}

/// One-line `report:` summary for human `analyze` output: the kind
/// first, then the non-empty highlights in a fixed order (label, the
/// Windows version/build, distro, boot family), comma-separated. Empty
/// parts are omitted and no placeholder is ever printed for a missing
/// part — `--json` carries the whole report, this line is a summary
/// only.
fn report_summary(report: &rufus_core::report::ImageReport) -> String {
    let mut parts = vec![report.kind.clone()];
    if let Some(label) = report.labels.best() {
        parts.push(format!("label {}", device_text(label)));
    }
    if report.is_windows {
        let mut windows = String::from("windows");
        if let Some(version) = &report.windows_version {
            windows.push_str(&format!(" {}", device_text(version)));
        }
        if let Some(build) = report.build {
            windows.push_str(&format!(" ({build})"));
        }
        parts.push(windows);
    }
    if let Some(distro) = &report.distro {
        parts.push(format!("distro {}", device_text(distro)));
    }
    let boot = match report.boot_mode() {
        rufus_core::report::BootMode::Bios => Some("bios"),
        rufus_core::report::BootMode::Uefi => Some("uefi"),
        rufus_core::report::BootMode::Both => Some("bios+uefi"),
        rufus_core::report::BootMode::None => None,
    };
    if let Some(mode) = boot {
        parts.push(format!("boot {mode}"));
    }
    parts.join(", ")
}

/// One probed partition filesystem of the table-order list.
#[derive(Serialize)]
struct AnalyzePartitionFs {
    /// Kernel name of the partition (`sdb1`), derived from the table.
    partition: String,
    /// Recognised filesystem kind tag (`fat32`, ...).
    filesystem: &'static str,
}

/// One mount of the device or of one of its partitions.
#[derive(Serialize)]
struct AnalyzeMount {
    /// Device number as the kernel spells it (`8:17`).
    dev: String,
    /// Mountpoint (octal-unescaped, sanitised).
    mountpoint: String,
    /// Filesystem of the mount.
    fstype: String,
    /// Kernel-reported mount source.
    source: String,
}

/// The PLAN §6 verdict as one flat JSON object. A refusal carries the
/// reason tag plus the one-sentence `Display` text; the all-clear is
/// only `{ "safe": true }`, so scripts can truth-test on the presence
/// of a `reason` key.
#[derive(Serialize)]
struct AnalyzeVerdict {
    /// Whether the device may be written.
    safe: bool,
    /// The [`rufus_core::safety::Reason`] tag (`"mounted"`, `"swap"`,
    /// ...), absent when safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// The human refusal sentence, absent when safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// The device half of `analyze --device` (S05). Field order is the
/// publish-facing JSON order — keep it when adding fields.
#[derive(Serialize)]
struct AnalyzeDevice {
    /// Device node that was sampled: the discovered `/dev/<name>` node,
    /// or the `--device-file` fixture when the S05 test hook redirects
    /// the sampling.
    path: String,
    /// Kernel name (`sdb`).
    name: String,
    /// Capacity in bytes.
    size_bytes: u64,
    /// Stable serial, when the device states one.
    serial: Option<String>,
    /// Model, when the device states one.
    model: Option<String>,
    /// sysfs card-removable flag.
    removable: bool,
    /// sysfs write-protect flag.
    read_only: bool,
    /// Transport tag (`usb`, `sata`, ...).
    transport: &'static str,
    /// The partition table as read from the device; `null` when LBA0
    /// holds no readable table (normal for a blank stick).
    table: Option<rufus_core::partition::Layout>,
    /// Recognised whole-device filesystem, `null` when none matches.
    filesystem: Option<&'static str>,
    /// `(kernel partition name, kind)` per probed partition.
    partition_filesystems: Vec<AnalyzePartitionFs>,
    /// Mounts of the disk or of its partitions.
    mounts: Vec<AnalyzeMount>,
    /// Active swap sources covering the device.
    swaps: Vec<String>,
    /// Kernel names of everything stacked on top.
    holders: Vec<String>,
    /// ASCII notes about rot and skipped work; never aborting.
    warnings: Vec<String>,
    /// The PLAN §6 verdict (see [`AnalyzeVerdict`]).
    verdict: AnalyzeVerdict,
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

/// Native Linux USB/ISO writer — command line (slice S03 by the schema,
/// with the S04 device surface wired on top).
#[derive(Debug, Parser)]
#[command(
    name = "rufus",
    version,
    about = "Native Linux USB/ISO writer — command line (slice S05)"
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
    // (`/sys` with `/run/udev/data` records, the current-process
    // `/proc/self/mountinfo` and `/proc/swaps`); the flags point at small
    // fixture files so tests and containers never touch real state.
    // Discovery reads sysfs for every command; the two table files and
    // the sampled node (`--device-file`) are `analyze --device` hooks.
    /// Root of a (possibly synthetic) sysfs tree for device discovery
    /// (S04 test hook; default: the live `/sys`).
    #[arg(long, value_name = "DIR", global = true)]
    sysfs_root: Option<PathBuf>,
    /// Path to a `/proc/self/mountinfo`-shaped file (S05 test hook;
    /// default: the live `/proc/self/mountinfo`, parsed by `analyze
    /// --device`).
    #[arg(long, value_name = "FILE", global = true)]
    mountinfo: Option<PathBuf>,
    /// Path to a `/proc/swaps`-shaped file (S05 test hook; default: the
    /// live `/proc/swaps`, parsed by `analyze --device`).
    #[arg(long, value_name = "FILE", global = true)]
    swaps: Option<PathBuf>,
    /// Regular file to sample instead of the discovered device node
    /// (S05 test hook for `analyze --device`; default: the discovered
    /// `/dev/<name>` node). Only meaningful once `--device` resolved to
    /// an enumerated device; tests point it at their sparse fixture
    /// bytes, while on a real run it stays unset so the graded device
    /// and the sampled bytes are one and the same.
    #[arg(long, value_name = "FILE", global = true)]
    device_file: Option<PathBuf>,

    // Rufus legacy parity switches — parsed and documented; the S04
    // discovery switch is live in `list` (and `analyze --device`
    // show-all confirmation since S05), the rest land with S06/S24.
    /// Show all devices, including fixed disks (the destruction-warning
    /// rule lives on the `cmd_list` implementation; with `analyze
    /// --device` it flips PLAN §6 rule 4's serial gate).
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
    ///
    /// With `--device`, the named block device is inspected alongside
    /// the image (S05): partition table, probed filesystems, mounts,
    /// swap, holders — and the PLAN §6 verdict is *reported*. `analyze`
    /// never enforces: it exits 0 even when the verdict refuses the
    /// device, so scripts can read the report; enforcement of a refusal
    /// is the S06 preview/helper's job. The graded device is always the
    /// discovered one and its own node is sampled; tests redirect the
    /// reading with the `--device-file` hook.
    Analyze {
        /// Image file to inspect (a regular file).
        image: PathBuf,
        /// Block device to inspect alongside the image (S05): partition
        /// table, filesystem and the PLAN §6 safety verdict.
        ///
        /// The discovered node path (`/dev/sdb`), the sysfs path, or the
        /// bare kernel name (`sdb`) is accepted; a partition path is
        /// refused with a pointer at its whole disk. Tests redirect the
        /// sampling to fixture bytes with `--device-file` (S05 test
        /// hook).
        #[arg(long, value_name = "DEVICE")]
        device: Option<PathBuf>,
        /// Serial the user typed to confirm a fixed disk (PLAN §6 rule 4;
        /// only meaningful together with `-x/--extra-devs`). Compared
        /// trimmed: surrounding whitespace does not hide a match.
        ///
        /// Unlike `plan --confirm-serial`, this accepts the flag without
        /// `-x`: `analyze` only reports, and the verdict then refuses a
        /// fixed disk as not removable, which is the honest answer.
        #[arg(long, value_name = "SERIAL")]
        confirm_serial: Option<String>,
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
    /// geometry. Nothing here writes to the device. An `msdos` plan
    /// carries no write step (IO.SYS must be the first root entry of
    /// the fresh volume); its `--image` reference is still required
    /// but unused.
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
        /// Copy an ISO/UDF image's file tree instead of writing the
        /// image byte-for-byte (the recommended mode for bootable
        /// sticks).
        #[arg(long = "iso-mode")]
        iso_mode: bool,
        /// Bootloader installer for the copy step (default: auto, paired
        /// with the write mode: auto|syslinux|grub2|grub4dos|uefi-ntfs|freedos|kolibri|msdos|windows|none;
        /// uefi-ntfs selects the two-partition UEFI:NTFS layout and
        /// forces copy mode, refused without --filesystem ntfs or
        /// exfat; windows selects the Windows To Go layout and forces
        /// copy mode with an NTFS data partition (--filesystem is
        /// overridden; --scheme mbr is refused later by the layout);
        /// freedos, kolibri and msdos need --filesystem fat32;
        /// msdos plans no write step — IO.SYS must be the first root
        /// entry — and needs --msdos-dir).
        #[arg(long, value_enum, default_value_t = plan::BootloaderOpt::Auto)]
        bootloader: plan::BootloaderOpt,
        /// Directory holding the user's own MS-DOS system files
        /// (IO.SYS, MSDOS.SYS, COMMAND.COM) for --bootloader msdos:
        /// MS-DOS cannot be bundled for licensing reasons, so the
        /// files must be legal copies the user supplies. Refused with
        /// any other bootloader mode.
        #[arg(long, value_name = "DIR")]
        msdos_dir: Option<String>,
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
        /// Scan for bad blocks in the wipe step, before the table and
        /// format.
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
        /// Device serial typed by the user to confirm writing a
        /// non-removable device; requires --show-all.
        #[arg(long, value_name = "SERIAL")]
        confirm_serial: Option<String>,
    },

    /// Execute a previously saved plan file.
    ///
    /// With --plan the file is checked (schema version + confirm hash)
    /// and then run through the S17 pipeline: wipe, table, partition,
    /// format, write, bootloader, finalize. Mismatches exit 1; image
    /// kinds with no tree reader, and `Copy` plans over `--device-file`
    /// (no partition node to mount), exit 7.
    /// `--device-file` runs
    /// the same plan against a regular file instead of the planned
    /// device (a test seam; the planned device is never opened then).
    /// Failures report on stderr in both modes, so `--json` stdout
    /// stays one parseable `Event` object per line.
    Write {
        /// Plan JSON file produced by `rufus plan`.
        #[arg(long, value_name = "FILE")]
        plan: PathBuf,
        /// Reset the USB device once the write retry budget is spent,
        /// then retry the failed chunk once more. Best effort: when no
        /// reset happens the run reports "no USB reset was possible for
        /// this device; reporting the write error" and the original
        /// write error stands.
        #[arg(long)]
        reset_usb: bool,
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
    devices: &[rufus_linux::Device],
    requested: &Path,
) -> Result<rufus_linux::Device, Fail> {
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

fn cmd_analyze(
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
    let image_report = rufus_core::report::analyze_file(image_path).ok();
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
                rufus_core::human_bytes(inspected.size_bytes)
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
    let devices = rufus_linux::enumerate(&sysfs).map_err(|core| Fail {
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
    let rufus_linux::inspect::Inspected { report, target } = rufus_linux::inspect(
        &sysfs,
        &selected,
        &rufus_linux::inspect::Options {
            mount_table: &mounts,
            swaps: &swaps,
            image_bytes: Some(inspected.size_bytes),
            allow_fixed: extra_devs,
            confirmed_serial: confirm_serial,
        },
    );
    let verdict = rufus_core::safety::judge(&target);

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
            rufus_core::human_bytes(inspected.size_bytes)
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
            rufus_core::human_bytes(report.device.size_bytes),
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
                            rufus_core::human_bytes(part.size_bytes),
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

/// The verdict half of the `analyze --json` device object: the reason
/// slug and the Display sentence are refusal payloads, omitted when the
/// verdict is [`SafetyVerdict::Safe`].
fn verdict_json(verdict: &SafetyVerdict) -> AnalyzeVerdict {
    match verdict {
        SafetyVerdict::Safe => AnalyzeVerdict {
            safe: true,
            reason: None,
            message: None,
        },
        SafetyVerdict::Refuse(reason) => AnalyzeVerdict {
            safe: false,
            reason: Some(reason.code().to_owned()),
            message: Some(reason.to_string()),
        },
    }
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

fn cmd_write(
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
    let cancel = rufus_linux::Cancel::new();
    cancel.install().map_err(Fail::from_core)?;
    if let Some(file) = paths.device_file.as_deref() {
        // Test seam: the plan's device path is never opened in this
        // mode, so a graded device cannot be written by accident — only
        // the seam file is touched.
        let opener = rufus_linux::FileOpener::open(file, table, layout).map_err(Fail::from_core)?;
        run_plan(&parsed, &opener, &cancel, json, reset_usb)
    } else {
        let sysfs = paths.sysfs();
        let devices = rufus_linux::enumerate(&sysfs).map_err(|core| Fail {
            exit: Exit::Device,
            kind: "device",
            message: core.to_string(),
        })?;
        let device = find_device(&devices, Path::new(&parsed.device.path))?;
        let opener = rufus_linux::DeviceOpener::new(&device, table, layout, sysfs)
            .map_err(Fail::from_core)?;
        run_plan(&parsed, &opener, &cancel, json, reset_usb)
    }
}

/// The (`TableKind`, `LayoutKind`) pair the opener plans its partition
/// window and node spelling for: read off the plan's `Mklabel`/`Mkpart`
/// steps — the authority for what
/// [`Mkpart`](rufus_proto::Step::Mkpart) stamps — never off
/// `options.scheme`, which is the planner's intent, not the stamped
/// table. The layout rides on the `Mkpart` step alone (`Mklabel` only
/// records the table); a plan whose options disagree with its steps
/// still runs against the stamped partition, while a plan whose steps
/// disagree with each other refuses here, before touching the device,
/// with the same exit class the in-run refusal would map to.
fn opener_table_kind(plan: &Plan) -> Result<(TableKind, LayoutKind), Fail> {
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
    opener: &dyn rufus_core::pipeline::Opener,
    cancel: &rufus_linux::Cancel,
    json: bool,
    reset_usb: bool,
) -> Result<Exit, Fail> {
    let options = write_options(plan.options.verify, plan.options.bad_blocks, reset_usb);
    let probe = cancel.as_fn();
    if json {
        let mut reporter = JsonReporter;
        rufus_core::pipeline::run(plan, opener, &options, &mut reporter, &probe)
            .map_err(Fail::from_core)?;
    } else {
        let mut reporter = HumanReporter::new();
        match rufus_core::pipeline::run(plan, opener, &options, &mut reporter, &probe) {
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

/// The [`RunOptions`](rufus_core::pipeline::RunOptions) a `write` run
/// executes with: verify and surface-scan intent from the plan, the
/// `--reset-usb` flag verbatim, and the reference retry policy
/// (`0x140010a40`): three retries, five seconds apart. A pure
/// constructor so the flag plumbing is unit-testable without running a
/// plan.
fn write_options(
    verify: bool,
    bad_blocks: bool,
    reset_usb: bool,
) -> rufus_core::pipeline::RunOptions {
    rufus_core::pipeline::RunOptions {
        verify,
        badblocks: bad_blocks,
        retries: 3,
        retry_delay: std::time::Duration::from_secs(5),
        reset_usb,
    }
}

/// Streams every pipeline [`Event`] as one JSON line on stdout, flushed
/// per line, with no wrapper object: the wire shape is exactly
/// [`Event`]'s serde shape. Serialisation of an event is infallible in
/// practice (all fields are JSON-native); a failure drops that one line
/// rather than aborting the run mid-stream.
struct JsonReporter;

impl rufus_core::pipeline::Reporter for JsonReporter {
    fn event(&mut self, event: Event) {
        if let Ok(line) = serde_json::to_string(&event) {
            println!("{line}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }
}

/// Human progress on stderr: one carriage-return line throttled to
/// about 1 Hz, one line per `Message`, and a final newline on
/// `Finished`. All ASCII, all whole numbers — totals, rates and ETAs
/// render by hand (absent when unknown), never with `{:?}`, so no
/// `Some`/`None` can leak.
struct HumanReporter {
    last_emit: Instant,
}

impl HumanReporter {
    /// A reporter whose first sample always prints: `last_emit` starts
    /// an hour back, so even a sub-second run shows its 100 %.
    fn new() -> Self {
        Self {
            last_emit: Instant::now() - Duration::from_secs(3600),
        }
    }

    /// Render one throughput sample. The final sample always prints;
    /// the rest at most once a second.
    fn progress(&mut self, step: &str, done: u64, total: Option<u64>, rate: u64, eta: Option<u64>) {
        let now = Instant::now();
        let final_sample = total.is_some_and(|total| done >= total);
        if !final_sample && now.duration_since(self.last_emit) < Duration::from_secs(1) {
            return;
        }
        self.last_emit = now;
        let mut line = match total {
            Some(total) if total > 0 => {
                let pct = (done.saturating_mul(100) / total).min(100);
                format!("{step}: {pct}% {done}/{total} bytes")
            }
            _ => format!("{step}: {done} bytes"),
        };
        if rate > 0 {
            line.push_str(&format!(", {}/s", rufus_core::human_bytes(rate)));
        }
        if let Some(eta) = eta {
            line.push_str(&format!(", ETA {eta}s"));
        }
        eprint!("{line}\r");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

impl rufus_core::pipeline::Reporter for HumanReporter {
    fn event(&mut self, event: Event) {
        match event {
            Event::Progress {
                step,
                done,
                total,
                bytes_per_second,
                eta_seconds,
            } => self.progress(step, done, total, bytes_per_second, eta_seconds),
            Event::Message { level, text } => {
                // The progress line has no trailing newline, so a bare
                // `eprintln!` would glue the message onto it: clear the
                // line first (carriage return, spaces, carriage return).
                eprint!("\r{:width$}\r", "", width = CLEAR_WIDTH);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                eprintln!("{level}: {text}");
            }
            Event::Finished { .. } => {
                eprintln!();
            }
            Event::StepStarted { .. } | Event::StepFinished { .. } => {}
        }
    }
}

/// Spaces the [`HumanReporter`] clears before a `Message`: wider than
/// any progress line it prints (step name plus numbers, rate and ETA),
/// so no stale characters survive.
const CLEAR_WIDTH: usize = 80;

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

/// Human tag of a partition-table kind, mirroring the JSON tags of
/// [`rufus_core::partition::TableKind`] (`"mbr"`/`"gpt"`).
fn human_table(kind: &TableKind) -> &'static str {
    match kind {
        TableKind::Mbr => "mbr",
        TableKind::Gpt => "gpt",
    }
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

/// Human-friendly layout tag (matches the plan JSON values).
fn human_layout(layout: &rufus_proto::Layout) -> &'static str {
    match layout {
        rufus_proto::Layout::Single => "single",
        rufus_proto::Layout::UefiNtfs => "uefi_ntfs",
        rufus_proto::Layout::WindowsToGo => "windows_to_go",
        rufus_proto::Layout::Persistence => "persistence",
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
        Step::Mkpart { scheme, layout } => format!(
            "mkpart (scheme {} layout {})",
            human_scheme(scheme),
            human_layout(layout)
        ),
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
                rufus_proto::BootloaderMode::Kolibri => "kolibri",
                rufus_proto::BootloaderMode::MsDos => "msdos",
                rufus_proto::BootloaderMode::Windows => "windows",
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
        // S04 hook note: `-x/--extra-devs` is the Rufus-legacy spelling
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
                &plan::Options {
                    scheme: scheme.clone(),
                    target: target.clone(),
                    filesystem: filesystem.clone(),
                    iso_mode: *iso_mode,
                    bootloader: *bootloader,
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
                        Err(_) => eprintln!("rufus: {}", fail.message),
                    }
                } else {
                    eprintln!("rufus: {}", fail.message);
                }
            } else {
                let json_line = if cli.json {
                    to_pretty(&json_error(fail.kind, &fail.message)).ok()
                } else {
                    None
                };
                match json_line {
                    Some(text) => println!("{text}"),
                    None => eprintln!("rufus: {}", fail.message),
                }
            }
            std::process::exit(fail.exit.code());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cancellation maps to exit 6 with kind `cancelled`, bare and
    /// through the step wrapper. No message text is matched: the
    /// contract is the code plus the kind.
    #[test]
    fn from_core_maps_cancellation_to_exit_6() {
        let fail = Fail::from_core(CoreError::Cancelled);
        assert_eq!(fail.exit, Exit::Cancelled);
        assert_eq!(fail.exit.code(), 6);
        assert_eq!(fail.kind, "cancelled");
        let fail = Fail::from_core(CoreError::Step {
            step: "write",
            source: Box::new(CoreError::Cancelled),
        });
        assert_eq!(fail.exit, Exit::Cancelled);
        assert_eq!(fail.exit.code(), 6);
        assert_eq!(fail.kind, "cancelled");
    }

    /// Unimplemented steps map to exit 7 with kind `not_implemented`,
    /// bare (the pipeline never wraps this variant). Same terms: code
    /// plus kind, no message text.
    #[test]
    fn from_core_maps_unimplemented_to_exit_7() {
        let fail = Fail::from_core(CoreError::NotImplemented {
            what: "copy of a wim image (the wim reader arrives in a later slice)",
        });
        assert_eq!(fail.exit, Exit::NotImplemented);
        assert_eq!(fail.exit.code(), 7);
        assert_eq!(fail.kind, "not_implemented");
    }

    /// Verification failures map to exit 4 with kind `verify`, bare
    /// and through the step wrapper — a device-integrity failure, not
    /// a usage error. Same terms: code plus kind, no message text.
    #[test]
    fn from_core_maps_verify_to_exit_4() {
        let fail = Fail::from_core(CoreError::Verify {
            message: "first differing byte at offset 3".to_string(),
        });
        assert_eq!(fail.exit, Exit::Io);
        assert_eq!(fail.exit.code(), 4);
        assert_eq!(fail.kind, "verify");
        let fail = Fail::from_core(CoreError::Step {
            step: "write",
            source: Box::new(CoreError::Verify {
                message: "first differing byte at offset 3".to_string(),
            }),
        });
        assert_eq!(fail.exit, Exit::Io);
        assert_eq!(fail.exit.code(), 4);
        assert_eq!(fail.kind, "verify");
    }

    /// The pre-existing classes are unchanged by the new arms: I/O
    /// (bare and step-wrapped) stays exit 4, validation stays exit 1.
    #[test]
    fn from_core_keeps_io_and_usage_classes() {
        let fail = Fail::from_core(CoreError::io("disk", std::io::Error::other("media error")));
        assert_eq!(fail.exit, Exit::Io);
        assert_eq!(fail.exit.code(), 4);
        assert_eq!(fail.kind, "io");
        let fail = Fail::from_core(CoreError::Step {
            step: "wipe",
            source: Box::new(CoreError::io("disk", std::io::Error::other("media error"))),
        });
        assert_eq!(fail.exit, Exit::Io);
        assert_eq!(fail.kind, "io");
        let fail = Fail::from_core(CoreError::invalid("bad value"));
        assert_eq!(fail.exit, Exit::Usage);
        assert_eq!(fail.exit.code(), 1);
        assert_eq!(fail.kind, "invalid_input");
    }

    /// `--reset-usb` parses on `write` (absent by default) and reaches
    /// [`RunOptions`](rufus_core::pipeline::RunOptions) verbatim, with
    /// the reference retry policy alongside: the parse half and the
    /// plumbing half of the flag, without running a plan.
    #[test]
    fn write_reset_usb_parses_and_plumbs_to_run_options() {
        let cli = Cli::try_parse_from(["rufus", "write", "--plan", "plan.json"])
            .expect("write parses without the flag");
        let Command::Write { plan, reset_usb } = &cli.command else {
            panic!("expected the write subcommand");
        };
        assert_eq!(plan, &PathBuf::from("plan.json"));
        assert!(!*reset_usb);
        assert!(!write_options(false, false, *reset_usb).reset_usb);

        let cli = Cli::try_parse_from(["rufus", "write", "--plan", "plan.json", "--reset-usb"])
            .expect("write parses with the flag");
        let Command::Write { reset_usb, .. } = &cli.command else {
            panic!("expected the write subcommand");
        };
        assert!(*reset_usb);
        let options = write_options(true, true, *reset_usb);
        assert!(options.reset_usb);
        assert!(options.verify);
        assert!(options.badblocks);
        // The reference policy (`0x140010a40`) rides along unchanged.
        assert_eq!(options.retries, 3);
        assert_eq!(options.retry_delay, std::time::Duration::from_secs(5));
    }

    /// A minimal plan carrying `steps`: the opener derivation only reads
    /// steps and `options.scheme`, so device/image facts stay empty.
    fn derivation_plan(steps: Vec<Step>) -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "test".to_string(),
            device: rufus_proto::DeviceRef {
                path: "/dev/null".to_string(),
                block_device: false,
                size_bytes: None,
                serial: None,
                model: None,
                sysfs: None,
            },
            image: rufus_proto::ImageRef {
                path: "image.iso".to_string(),
                size_bytes: 32_780,
                sha256: "0".repeat(64),
                kind: rufus_proto::ImageKind::Iso,
            },
            options: rufus_proto::Options {
                scheme: Scheme::Mbr,
                target: Target::Dual,
                filesystem: rufus_proto::Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick_format: false,
                bad_blocks: false,
                verify: false,
                persistence: false,
                show_all: false,
                confirmed_serial: None,
                msdos_dir: None,
            },
            steps,
            confirm: String::new(),
        }
    }

    /// The opener derivation follows the steps, not the options: the
    /// layout rides on the `Mkpart` step, defaulting to single when no
    /// `Mkpart` step is present.
    #[test]
    fn opener_derivation_reads_table_and_layout_off_the_steps() {
        let plan = derivation_plan(vec![
            Step::Mklabel {
                scheme: Scheme::Mbr,
            },
            Step::Mkpart {
                scheme: Scheme::Mbr,
                layout: Layout::UefiNtfs,
            },
        ]);
        let (table, layout) = match opener_table_kind(&plan) {
            Ok(pair) => pair,
            Err(fail) => panic!("agreeing steps derive: {}", fail.message),
        };
        assert_eq!(table, TableKind::Mbr);
        assert_eq!(layout, LayoutKind::UefiNtfs);

        // No mkpart step at all: the table falls back to the options
        // scheme and the layout to the single default.
        let plan = derivation_plan(vec![Step::Wipe]);
        let (table, layout) = match opener_table_kind(&plan) {
            Ok(pair) => pair,
            Err(fail) => panic!("fallbacks hold: {}", fail.message),
        };
        assert_eq!(table, TableKind::Mbr);
        assert_eq!(layout, LayoutKind::Single);
    }

    /// Two `Mkpart` steps with different layouts refuse before touching
    /// the device, naming both layouts like the scheme refusal names
    /// both schemes.
    #[test]
    fn opener_derivation_refuses_mkpart_layout_disagreement() {
        let plan = derivation_plan(vec![
            Step::Mkpart {
                scheme: Scheme::Mbr,
                layout: Layout::Single,
            },
            Step::Mkpart {
                scheme: Scheme::Mbr,
                layout: Layout::UefiNtfs,
            },
        ]);
        let refused = match opener_table_kind(&plan) {
            Ok(_) => panic!("disagreeing layouts must refuse"),
            Err(fail) => fail,
        };
        assert_eq!(refused.exit, Exit::Usage);
        assert_eq!(refused.kind, "invalid_plan");
        assert!(
            refused.message.contains("single"),
            "names the first layout: {}",
            refused.message
        );
        assert!(
            refused.message.contains("uefi_ntfs"),
            "names the second layout: {}",
            refused.message
        );
    }

    /// The human mkpart line prints scheme and layout in their JSON
    /// spellings.
    #[test]
    fn describe_step_prints_mkpart_scheme_and_layout() {
        let line = describe_step(&Step::Mkpart {
            scheme: Scheme::Gpt,
            layout: Layout::UefiNtfs,
        });
        assert_eq!(line, "mkpart (scheme gpt layout uefi_ntfs)");
        let line = describe_step(&Step::Mkpart {
            scheme: Scheme::Mbr,
            layout: Layout::Single,
        });
        assert_eq!(line, "mkpart (scheme mbr layout single)");
    }
}
