//! Output shapes and renderers for `furus`.
//!
//! The JSON structs keep their field declaration order (that order is the
//! publish-facing key order) and the human helpers keep the exact wording;
//! `crate::commands` builds the structs and calls the `pub(crate)` entry
//! points while the private helpers stay local to this module.

use std::time::Duration;
use std::time::Instant;

use furus_core::partition::TableKind;
use furus_core::pipeline::Event;
use furus_core::safety::SafetyVerdict;
use furus_core::text::device_text;
use furus_proto::Plan;
use furus_proto::Step;
use furus_proto::Target;
use serde::Serialize;

/// `list --json` output: the filtered device list plus the show-all echo.
///
/// One struct instead of a hand-built `json!` value, so serialisation
/// cannot fail between fields and the key order stays declaration-stable
/// (the CLI must be panic-free).
#[derive(Serialize)]
pub(crate) struct ListOutput<'a> {
    /// Candidate devices, name-sorted by discovery.
    pub(crate) devices: &'a [furus_linux::Device],
    /// Whether internal fixed disks were included in `devices`.
    pub(crate) show_all: bool,
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
pub(crate) struct AnalyzeOutput {
    /// Image path as given on the command line.
    pub(crate) path: String,
    /// Regular-file length in bytes.
    pub(crate) size_bytes: u64,
    /// SHA-256 over the whole image, lowercase hex.
    pub(crate) sha256: String,
    /// Container kind (magic-only detection in this slice).
    pub(crate) kind: String,
    /// The S05 device report; skipped without `--device` so the
    /// pre-S05 JSON contract stays exactly four keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device: Option<AnalyzeDevice>,
    /// The S16 image report, always serialized; `null` when the report
    /// could not be produced — the volume probed positive but the
    /// reader refused it (a corrupt or truncated image), or reading the
    /// image failed — so a broken ISO never turns `analyze` into an
    /// error.
    pub(crate) report: Option<furus_core::report::ImageReport>,
}

/// One-line `report:` summary for human `analyze` output: the kind
/// first, then the non-empty highlights in a fixed order (label, the
/// Windows version/build, distro, boot family), comma-separated. Empty
/// parts are omitted and no placeholder is ever printed for a missing
/// part — `--json` carries the whole report, this line is a summary
/// only.
pub(crate) fn report_summary(report: &furus_core::report::ImageReport) -> String {
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
        furus_core::report::BootMode::Bios => Some("bios"),
        furus_core::report::BootMode::Uefi => Some("uefi"),
        furus_core::report::BootMode::Both => Some("bios+uefi"),
        furus_core::report::BootMode::None => None,
    };
    if let Some(mode) = boot {
        parts.push(format!("boot {mode}"));
    }
    parts.join(", ")
}

/// One probed partition filesystem of the table-order list.
#[derive(Serialize)]
pub(crate) struct AnalyzePartitionFs {
    /// Kernel name of the partition (`sdb1`), derived from the table.
    pub(crate) partition: String,
    /// Recognised filesystem kind tag (`fat32`, ...).
    pub(crate) filesystem: &'static str,
}

/// One mount of the device or of one of its partitions.
#[derive(Serialize)]
pub(crate) struct AnalyzeMount {
    /// Device number as the kernel spells it (`8:17`).
    pub(crate) dev: String,
    /// Mountpoint (octal-unescaped, sanitised).
    pub(crate) mountpoint: String,
    /// Filesystem of the mount.
    pub(crate) fstype: String,
    /// Kernel-reported mount source.
    pub(crate) source: String,
}

/// The PLAN §6 verdict as one flat JSON object. A refusal carries the
/// reason tag plus the one-sentence `Display` text; the all-clear is
/// only `{ "safe": true }`, so scripts can truth-test on the presence
/// of a `reason` key.
#[derive(Serialize)]
pub(crate) struct AnalyzeVerdict {
    /// Whether the device may be written.
    safe: bool,
    /// The [`furus_core::safety::Reason`] tag (`"mounted"`, `"swap"`,
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
pub(crate) struct AnalyzeDevice {
    /// Device node that was sampled: the discovered `/dev/<name>` node,
    /// or the `--device-file` fixture when the S05 test hook redirects
    /// the sampling.
    pub(crate) path: String,
    /// Kernel name (`sdb`).
    pub(crate) name: String,
    /// Capacity in bytes.
    pub(crate) size_bytes: u64,
    /// Stable serial, when the device states one.
    pub(crate) serial: Option<String>,
    /// Model, when the device states one.
    pub(crate) model: Option<String>,
    /// sysfs card-removable flag.
    pub(crate) removable: bool,
    /// sysfs write-protect flag.
    pub(crate) read_only: bool,
    /// Transport tag (`usb`, `sata`, ...).
    pub(crate) transport: &'static str,
    /// The partition table as read from the device; `null` when LBA0
    /// holds no readable table (normal for a blank stick).
    pub(crate) table: Option<furus_core::partition::Layout>,
    /// Recognised whole-device filesystem, `null` when none matches.
    pub(crate) filesystem: Option<&'static str>,
    /// `(kernel partition name, kind)` per probed partition.
    pub(crate) partition_filesystems: Vec<AnalyzePartitionFs>,
    /// Mounts of the disk or of its partitions.
    pub(crate) mounts: Vec<AnalyzeMount>,
    /// Active swap sources covering the device.
    pub(crate) swaps: Vec<String>,
    /// Kernel names of everything stacked on top.
    pub(crate) holders: Vec<String>,
    /// ASCII notes about rot and skipped work; never aborting.
    pub(crate) warnings: Vec<String>,
    /// The PLAN §6 verdict (see [`AnalyzeVerdict`]).
    pub(crate) verdict: AnalyzeVerdict,
}

/// The verdict half of the `analyze --json` device object: the reason
/// slug and the Display sentence are refusal payloads, omitted when the
/// verdict is [`SafetyVerdict::Safe`].
pub(crate) fn verdict_json(verdict: &SafetyVerdict) -> AnalyzeVerdict {
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

/// Streams every pipeline [`Event`] as one JSON line on stdout, flushed
/// per line, with no wrapper object: the wire shape is exactly
/// [`Event`]'s serde shape. Serialisation of an event is infallible in
/// practice (all fields are JSON-native); a failure drops that one line
/// rather than aborting the run mid-stream.
pub(crate) struct JsonReporter;

impl furus_core::pipeline::Reporter for JsonReporter {
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
pub(crate) struct HumanReporter {
    last_emit: Instant,
}

impl HumanReporter {
    /// A reporter whose first sample always prints: `last_emit` starts
    /// an hour back, so even a sub-second run shows its 100 %.
    pub(crate) fn new() -> Self {
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
            line.push_str(&format!(", {}/s", furus_core::human_bytes(rate)));
        }
        if let Some(eta) = eta {
            line.push_str(&format!(", ETA {eta}s"));
        }
        eprint!("{line}\r");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

impl furus_core::pipeline::Reporter for HumanReporter {
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

/// Human summary for `plan` (same data as the `--json` object).
pub(crate) fn print_human_plan(built: &Plan) {
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

pub(crate) fn human_lead(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Human tag of a partition-table kind, mirroring the JSON tags of
/// [`furus_core::partition::TableKind`] (`"mbr"`/`"gpt"`).
pub(crate) fn human_table(kind: &TableKind) -> &'static str {
    match kind {
        TableKind::Mbr => "mbr",
        TableKind::Gpt => "gpt",
    }
}

fn human_optional(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "<none>".to_string())
}

/// Human-friendly scheme tag (matches the plan JSON values).
pub(crate) fn human_scheme(scheme: &furus_proto::Scheme) -> &'static str {
    match scheme {
        furus_proto::Scheme::Mbr => "mbr",
        furus_proto::Scheme::Gpt => "gpt",
    }
}

/// Human-friendly layout tag (matches the plan JSON values).
pub(crate) fn human_layout(layout: &furus_proto::Layout) -> &'static str {
    match layout {
        furus_proto::Layout::Single => "single",
        furus_proto::Layout::UefiNtfs => "uefi_ntfs",
        furus_proto::Layout::WindowsToGo => "windows_to_go",
        furus_proto::Layout::Persistence => "persistence",
    }
}

fn human_target(target: &Target) -> &'static str {
    match target {
        Target::Bios => "bios",
        Target::Uefi => "uefi",
        Target::Dual => "dual",
    }
}

fn human_filesystem(filesystem: &furus_proto::Filesystem) -> &'static str {
    use furus_proto::Filesystem;
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
                furus_proto::WriteMode::Dd => "dd",
                furus_proto::WriteMode::Copy => "copy",
            }
        ),
        Step::Bootloader { mode } => format!(
            "bootloader (mode {})",
            match mode {
                furus_proto::BootloaderMode::Auto => "auto",
                furus_proto::BootloaderMode::Syslinux => "syslinux",
                furus_proto::BootloaderMode::Grub2 => "grub2",
                furus_proto::BootloaderMode::Grub4dos => "grub4dos",
                furus_proto::BootloaderMode::UefiNtfs => "uefi_ntfs",
                furus_proto::BootloaderMode::Freedos => "freedos",
                furus_proto::BootloaderMode::Kolibri => "kolibri",
                furus_proto::BootloaderMode::MsDos => "msdos",
                furus_proto::BootloaderMode::Windows => "windows",
                furus_proto::BootloaderMode::None => "none",
            }
        ),
        Step::Finalize => "finalize (flush, checks, rescan)".to_string(),
    }
}

#[cfg(test)]
#[path = "output/tests.rs"]
mod tests;
