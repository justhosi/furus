//! CLI argument surface (`clap`) for `furus`.
//!
//! The command tree and the value parsers live here so the flag spelling
//! (part of the CLI contract) stays in one place; `crate::dispatch` matches
//! the parsed [`Command`] and routes it to `crate::commands`.

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use furus_core::hash::Algo;
use furus_proto::Scheme;
use furus_proto::Target;

use crate::plan;

/// Native Linux USB/ISO writer — command line (slice S03 by the schema,
/// with the S04 device surface wired on top).
#[derive(Debug, Parser)]
#[command(
    name = "furus",
    version,
    about = "Native Linux USB/ISO writer — command line (slice S05)"
)]
pub(crate) struct Cli {
    /// Emit machine-readable JSON for results and errors.
    #[arg(long, global = true)]
    pub(crate) json: bool,

    // Accepted now, wired later, so scripts written against the final
    // surface keep running: progress verbosity lands with S06/S24.
    /// Verbose output (wiring arrives with S06 progress and S24).
    #[arg(short = 'v', long, global = true)]
    pub(crate) verbose: bool,
    /// Quiet output (wiring arrives with S06/S24).
    #[arg(short = 'q', long, global = true)]
    pub(crate) quiet: bool,
    /// Locale tag, e.g. `de_DE` (accepted; wiring arrives in S24).
    #[arg(short = 'l', long = "locale", value_name = "TAG", global = true)]
    pub(crate) locale: Option<String>,
    /// Assume "yes" for confirmation prompts (wired with the S06 chooser).
    #[arg(long, global = true)]
    pub(crate) yes: bool,
    /// Build the plan without touching the device; relaxes device checks
    /// (missing or non-block devices are allowed, reported as
    /// `block_device: false`).
    #[arg(long, global = true)]
    pub(crate) dry_run: bool,

    // S04/S05 test hooks (PLAN §9-S04): the defaults are the live system
    // (`/sys` with `/run/udev/data` records, the current-process
    // `/proc/self/mountinfo` and `/proc/swaps`); the flags point at small
    // fixture files so tests and containers never touch real state.
    // Discovery reads sysfs for every command; the two table files and
    // the sampled node (`--device-file`) are `analyze --device` hooks.
    /// Root of a (possibly synthetic) sysfs tree for device discovery
    /// (S04 test hook; default: the live `/sys`).
    #[arg(long, value_name = "DIR", global = true)]
    pub(crate) sysfs_root: Option<PathBuf>,
    /// Path to a `/proc/self/mountinfo`-shaped file (S05 test hook;
    /// default: the live `/proc/self/mountinfo`, parsed by `analyze
    /// --device`).
    #[arg(long, value_name = "FILE", global = true)]
    pub(crate) mountinfo: Option<PathBuf>,
    /// Path to a `/proc/swaps`-shaped file (S05 test hook; default: the
    /// live `/proc/swaps`, parsed by `analyze --device`).
    #[arg(long, value_name = "FILE", global = true)]
    pub(crate) swaps: Option<PathBuf>,
    /// Regular file to sample instead of the discovered device node
    /// (S05 test hook for `analyze --device`; default: the discovered
    /// `/dev/<name>` node). Only meaningful once `--device` resolved to
    /// an enumerated device; tests point it at their sparse fixture
    /// bytes, while on a real run it stays unset so the graded device
    /// and the sampled bytes are one and the same.
    #[arg(long, value_name = "FILE", global = true)]
    pub(crate) device_file: Option<PathBuf>,

    // Furus legacy parity switches — parsed and documented; the S04
    // discovery switch is live in `list` (and `analyze --device`
    // show-all confirmation since S05), the rest land with S06/S24.
    /// Show all devices, including fixed disks (the destruction-warning
    /// rule lives on the `cmd_list` implementation; with `analyze
    /// --device` it flips PLAN §6 rule 4's serial gate).
    #[arg(short = 'x', long = "extra-devs", global = true)]
    pub(crate) extra_devs: bool,
    /// Launch the graphical front end instead of the CLI (no effect yet:
    /// arrives with S24).
    #[arg(short = 'g', long, global = true)]
    pub(crate) gui: bool,
    /// Select an ISO image for the legacy invocation style (no effect in
    /// S03; `plan --image` is the live image switch).
    #[arg(short = 'i', long, global = true)]
    pub(crate) iso: bool,
    /// Wait for outstanding writes before exiting (no effect yet: S06).
    #[arg(short = 'w', long, global = true)]
    pub(crate) wait: bool,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
    /// Mirrors Furus's default: USB-or-removable only, built-in and
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
        filesystem: furus_proto::Filesystem,
        /// Copy an ISO/UDF image's file tree instead of writing the
        /// image byte-for-byte (the recommended mode for bootable
        /// sticks).
        #[arg(long = "iso-mode")]
        iso_mode: bool,
        /// Bootloader installer for the copy step (default: auto, paired
        /// with the write mode: auto|syslinux|grub2|grub4dos|uefi-ntfs|freedos|kolibri|msdos|windows|none;
        /// uefi-ntfs selects the two-partition UEFI:NTFS layout and
        /// forces copy mode, refused without --filesystem ntfs or
        /// exfat; windows selects the Windows To Go layout with an NTFS
        /// data partition and no write step (--filesystem is
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
        /// Plan JSON file produced by `furus plan`.
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
    /// The GUI/helper write `$XDG_STATE_HOME/furus-linux/furus.log` from
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
/// [`furus_proto::Filesystem`].
fn parse_filesystem(text: &str) -> Result<furus_proto::Filesystem, String> {
    use furus_proto::Filesystem;
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
pub(crate) fn validate_cluster(bytes: u32) -> std::result::Result<u32, String> {
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

#[cfg(test)]
#[path = "cli/tests.rs"]
mod tests;
