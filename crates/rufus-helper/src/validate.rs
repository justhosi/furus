//! Plan loading and validation — the helper's fail-closed gate (S06).
//!
//! Everything between "a plan file exists" and "run_plan may touch a
//! device" lives here, and it is deliberately read-only: nothing in
//! this module writes anywhere (only `inspect` samples the target with
//! plain reads). The rules follow PLAN §6 in the order the helper
//! reports them — cheap schema facts first, node/discovery TOCTOU
//! checks next, step semantics, and finally the **independent safety
//! re-check**: the helper re-assembles the *same* inspection + verdict
//! the unprivileged preview showed, from its own privileges, and
//! refuses on any [`rufus_core::safety::Reason`] (PLAN §6 "enforced
//! twice").
//!
//! # Test hooks live in `Env`, never in argv
//!
//! The helper binary accepts **no** `--sysfs-root`/`--mountinfo`/
//! `--swaps`/`--device-file` flags; those exist only in the
//! unprivileged CLI. A root helper must look at the real system, so
//! `main` always builds [`Env::live`]. The `Env` fields exist only so
//! unit tests can inject the same fixtures the CLI tests point at (a
//! synthetic sysfs tree, a mountinfo/`/proc/swaps` fixture file, and —
//! mirroring the CLI's `--device-file` — a regular file the inspection
//! half samples *instead of* the device node, so verdict facts stay
//! fixture-determined without real media).
//!
//! # Reject codes
//!
//! Every refusal carries a stable snake_case code ([`Reject`]); codes
//! are `Reason::code()` strings from the safety layer wherever an
//! enforcement point already exists, otherwise this module's own — all
//! pinned by tests. Front ends key off these, never off messages,
//! which are human sentences.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use rufus_core::hash::hash_file;
use rufus_core::safety::SafetyVerdict;
use rufus_core::safety::Target;
use rufus_core::safety::judge;
use rufus_core::text::device_text;
use rufus_core::units::human_bytes;
use rufus_linux::Device;
use rufus_linux::MountTable;
use rufus_linux::SysfsRoot;
use rufus_linux::mounts::read_swaps;
use rufus_linux::sysfs::Filter;
use rufus_linux::sysfs::enumerate as enumerate_devices;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::Layout;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Scheme;
use rufus_proto::Step;
use rufus_proto::WriteMode;

/// One refusal of one rule: a stable code for the machines, one ASCII
/// sentence for the human. Codes are pinned in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    /// Machine-readable rule id, e.g. `"size_mismatch"`.
    pub code: String,
    /// ASCII-only, user-facing sentence (no jargon, no debug output).
    pub message: String,
}

/// Reject constructor: codes and messages are written once, here, as
/// literal ASCII — [`device_text`] runs as the belt over the suspenders
/// so a future interpolated fragment cannot smuggle bytes in.
fn reject(code: &str, message: impl Into<String>) -> Reject {
    Reject {
        code: device_text(code),
        message: device_text(message.into().as_str()),
    }
}

/// Where the validation's facts come from: a sysfs root for discovery,
/// optional fixture paths for the mount/swap tables, and the
/// CLI-mirroring `--device-file` stand-in (see the module docs).
#[derive(Debug, Clone)]
pub struct Env {
    /// sysfs root plus its udev data directory (`SysfsRoot::new` keeps
    /// a fixture's udev records inside the tree, `"/sys"` keeps
    /// `/run/udev/data`).
    pub sysfs: SysfsRoot,
    /// A `/proc/self/mountinfo`-shaped file, or `None` for the live
    /// one.
    pub mountinfo: Option<PathBuf>,
    /// A `/proc/swaps`-shaped file, or `None` for the live one.
    pub swaps: Option<PathBuf>,
    /// Test-only stand-in for the device node; **the binary never sets
    /// it** — production is always [`Env::live`], whose field is `None`,
    /// so every path-shape rule (`/dev/` prefix, no symlink, block
    /// device mode) is applied to `plan.device.path` itself, and the
    /// safety re-check samples exactly that node (PLAN §6).
    ///
    /// When a unit test sets this field, the check behind it runs
    /// against this file instead of the plan's path: the stand-in plays
    /// the node's role (a regular file, since only the kernel can mint
    /// a block device node in CI) while the graded device (path, name,
    /// size, serial) still comes from the plan and discovery. The seam
    /// therefore only chooses *which file is examined*: it cannot erode
    /// a production rule, because production never takes this branch.
    pub device_file: Option<PathBuf>,
}

impl Env {
    /// The real system — what `main` always uses.
    #[must_use]
    pub fn live() -> Env {
        Env {
            sysfs: SysfsRoot::new("/sys"),
            mountinfo: None,
            swaps: None,
            device_file: None,
        }
    }
}

/// A plan that passed every rule: the plan itself, the discovered
/// device it was judged against, and the [`Target`] the verdict used.
///
/// S06 part 3 wires `plan` and `device` into the run; `target` carries
/// the judged facts for the writing executor (S17) and for the tests,
/// so the S06 build marks it dead until then like the CLI's stubbed
/// exit classes.
#[derive(Debug, Clone)]
pub struct Validated {
    /// The plan, confirm intact, byte-identical to what was loaded.
    pub plan: Plan,
    /// The device the discovery half resolved the plan's path to.
    pub device: Device,
    /// The verdict input the safety re-check judged `Safe`.
    #[allow(dead_code)] // consumed by the S17 writing executor; tests assert on it
    pub target: Target,
}

/// The plan-file read cap (bytes): the plan schema is a small document
/// (one device reference, one image reference, a step list), so
/// anything past 1 MiB is hostile input or the wrong file, and a root
/// process must never buffer it (`--plan /dev/zero` would otherwise
/// grow without bound). The cap is enforced *during* the read, not
/// after it — `fs::read` alone would still OOM on a cap check.
pub const MAX_PLAN_BYTES: usize = 1_048_576; // 1 MiB

/// Load a plan file from disk, refusing anything that is not one.
///
/// I/O and parse failures refuse with separate codes
/// (`"unreadable_plan"` vs `"malformed_plan"`) so a front end can say
/// "path wrong / no permissions" vs "file is rot"; a read hitting the
/// [`MAX_PLAN_BYTES`] ceiling refuses as `"plan_too_large"`. Both
/// messages carry the sanitised path (the plan file path is user
/// input) and stay one ASCII line.
pub fn load(path: &Path) -> Result<Plan, Reject> {
    // The read itself is capped: read (up to) the cap, then probe one
    // more byte — any probe read means the file has content beyond the
    // cap, so it is not a plan.
    let mut file = fs::File::open(path).map_err(|source| {
        reject(
            "unreadable_plan",
            format!("cannot read the plan file {}: {source}", path.display()),
        )
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PLAN_BYTES as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            reject(
                "unreadable_plan",
                format!("cannot read the plan file {}: {source}", path.display()),
            )
        })?;
    let mut probe = [0u8; 1];
    let overrun = file.read(&mut probe).map_err(|source| {
        reject(
            "unreadable_plan",
            format!("cannot read the plan file {}: {source}", path.display()),
        )
    })? > 0;
    if overrun {
        return Err(reject(
            "plan_too_large",
            format!(
                "the plan file {} is larger than {} - a plan is a small \
                 document; rebuild the plan",
                path.display(),
                human_bytes(MAX_PLAN_BYTES as u64)
            ),
        ));
    }
    serde_json::from_slice::<Plan>(&bytes).map_err(|source| {
        reject(
            "malformed_plan",
            format!(
                "the plan file {} is not a valid plan: {source}",
                path.display()
            ),
        )
    })
}

/// Run every PLAN §6 helper rule against `plan`, in their documented
/// order, returning the validated bundle or the first refusal.
pub fn validate(plan: &Plan, env: &Env) -> Result<Validated, Reject> {
    // 1. Schema version: the whole-schema check; refuse anything this
    //    build does not speak (fail closed, PLAN §2).
    if plan.version != PLAN_VERSION {
        return Err(reject(
            "unsupported_version",
            format!(
                "the plan carries version {}, this build supports version \
                 {PLAN_VERSION} - rebuild the plan",
                plan.version
            ),
        ));
    }

    // 2. Integrity: the confirm hash must be reproducible from the plan
    //    contents. A recompute *error* is a hard failure, never an
    //    acceptance (PLAN §2).
    let recomputed = plan.confirm().map_err(|source| {
        reject(
            "confirm_error",
            format!("the plan integrity hash cannot be recomputed: {source}"),
        )
    })?;
    if recomputed != plan.confirm {
        return Err(reject(
            "confirm_mismatch",
            "the plan failed its integrity check (the confirm hash does not \
             match its contents) - rebuild the plan",
        ));
    }

    // 3. Travel shape: at least one step, and exactly one Finalize, at
    //    the end (the executor treats it as the flushing milestone).
    if plan.steps.is_empty() {
        return Err(reject("invalid_step", "the plan has no steps"));
    }
    if !matches!(plan.steps.last(), Some(Step::Finalize)) {
        return Err(reject(
            "invalid_step",
            "the last step of the plan must be finalize",
        ));
    }
    let finalize_count = plan
        .steps
        .iter()
        .filter(|step| matches!(step, Step::Finalize))
        .count();
    if finalize_count != 1 {
        return Err(reject(
            "invalid_step",
            "the plan must hold exactly one finalize step, moreover at the end",
        ));
    }

    // 4. The device: a real block device node under /dev, resolved on
    //    this system's device list (node facts first: the pre-open
    //    shape check on every path the helper would touch, before any
    //    content is read).
    device_node_checks(&plan.device.path, env.device_file.as_deref())?;
    let devices = collect_candidates(env)?;
    let Some(device) = resolve_device(&devices, &plan.device.path) else {
        return Err(reject(
            "unknown_device",
            format!(
                "device {} is no longer on this system's device list \
                 - replug it and rebuild the plan",
                plan.device.path
            ),
        ));
    };

    // 5. Size: the plan's recorded capacity within one sector of what
    //    discovery reports (the same stick, not another one).
    check_size(plan, &device)?;

    // 6. The image: a regular, non-world-writable file whose size and
    //    SHA-256 are exactly what the plan recorded (the contents
    //    re-read — see `check_image` for the narrow guarantee it
    //    provides and the S17 obligations it leaves).
    check_image(plan)?;

    // 7. Step semantics: table/format arguments legal for this plan.
    check_steps(plan)?;

    // 8. The independent safety re-check (PLAN §6 enforced twice): the
    //    helper re-assembles the verdict from its own view of the host
    //    and refuses on any reason, fail closed.
    let target = judge_target(plan, env, &device)?;

    Ok(Validated {
        plan: plan.clone(),
        device,
        target,
    })
}

/// Rule 4a: the node the helper would touch must exist as a real block
/// device — never a symlink (which a hostile plan uses to redirect a
/// write), not a regular file, not a character device.
///
/// The `/dev/` prefix is a plan-shape rule and always applies to the
/// plan's own path. The file-type rules apply to the node that would be
/// opened: `plan.device.path` in production (the binary never sets
/// [`Env::device_file`]), or the test stand-in behind the seam — where a
/// regular file stands for the node, because only the kernel can mint a
/// block device node, and the check must stay runnable on CI.
fn device_node_checks(plan_path: &str, stand_in: Option<&Path>) -> Result<(), Reject> {
    if !plan_path.starts_with("/dev/") {
        return Err(reject(
            "not_a_block_device",
            format!("the device path must be under /dev (it says {plan_path})"),
        ));
    }
    let Some(name) = Path::new(plan_path).file_name() else {
        return Err(reject(
            "not_a_block_device",
            format!("the device path {plan_path} does not name a device"),
        ));
    };
    let name = device_text(&name.to_string_lossy());
    let node = stand_in.unwrap_or(Path::new(plan_path));
    let meta = fs::symlink_metadata(node).map_err(|source| {
        reject(
            "not_a_block_device",
            format!("device {name} is not a block device (it cannot be found: {source})"),
        )
    })?;
    // lstat on purpose: a symlink standing in as the device is exactly
    // what this check refuses (PLAN §6 canonicalised node requirement).
    if meta.file_type().is_symlink() {
        return Err(reject(
            "symlink",
            format!("device {name} is a symlink - this helper opens only real device nodes"),
        ));
    }
    if stand_in.is_some() {
        // The stand-in must be a plain file (the role it plays); a
        // directory or anything else would not sample either, so this
        // is fail-closed, not a licence.
        if !meta.is_file() {
            return Err(reject(
                "not_a_block_device",
                format!("device {name} is not a block device"),
            ));
        }
    } else if !meta.file_type().is_block_device() {
        // Production: the write target is opened by path at run time
        // (S17), so the node must genuinely be a block device.
        return Err(reject(
            "not_a_block_device",
            format!("device {name} is not a block device"),
        ));
    }
    Ok(())
}

/// Rule 4b: enumerate the sysfs and keep every candidate. An
/// unreadable `class/block` refuses (`"unreadable"`) — the helper has
/// no business guessing at a device list it cannot honestly read.
fn collect_candidates(env: &Env) -> Result<Vec<Device>, Reject> {
    let devices = enumerate_devices(&env.sysfs).map_err(|source| {
        reject(
            "unreadable",
            format!(
                "cannot read the device list from {}: {source}",
                env.sysfs.root.display()
            ),
        )
    })?;
    // show_all reveals fixed disks as candidates: the *serial gate*
    // (rule 8) still refuses them unless the plan carries the typed
    // confirmation, so nothing here is a write unlock (PLAN §6 rule 4).
    Ok(rufus_linux::filter(devices, Filter { show_all: true }))
}

/// Rule 4c: find the enumerated device the plan names — the kernel
/// name and the `/dev/<name>` node path must both match.
fn resolve_device(devices: &[Device], path: &str) -> Option<Device> {
    let name = Path::new(path).file_name()?.to_str()?;
    devices
        .iter()
        .find(|device| device.name == name && device.dev_path == path)
        .cloned()
}

/// Rule 5: the plan's recorded capacity must sit within one sector of
/// the discovered size — the same stick, not a different one swapped
/// in between plan time and run time.
fn check_size(plan: &Plan, device: &Device) -> Result<(), Reject> {
    let Some(plan_size) = plan.device.size_bytes else {
        return Err(reject(
            "size_mismatch",
            "the plan does not record the device size - rebuild the plan",
        ));
    };
    // `sector_size` is never zero (a bogus 0 attribute is rejected when
    // sysfs facts are parsed, defaulting to 512), so the slack test
    // compares against a real number.
    let sector = u64::from(device.sector_size);
    if plan_size.abs_diff(device.size_bytes) > sector {
        return Err(reject(
            "size_mismatch",
            format!(
                "device {} is {} now but the plan expects {} - the stick \
                 changed? rebuild the plan",
                device_text(&plan.device.path),
                human_bytes(device.size_bytes),
                human_bytes(plan_size)
            ),
        ));
    }
    Ok(())
}

/// Rule 6: image regularity, permissions, size and digest — the helper
/// re-reads the whole image once here so the bytes S17 will stream have
/// just been seen (the digest cost is the point).
///
/// # What this narrows, and what it does not
///
/// The re-read confirms the image contents against the plan's hash at
/// *check* time; it cannot make the file immutable. [`fs::metadata`]
/// follows symlinks (rule 6 is about the file the path resolves to),
/// and the device node is equally re-checked by `lstat` rather than
/// held. Both the image and the node are re-opened **by path** when
/// S17 streams, so the bytes may still change between this check and
/// the write (PLAN §6's "image passed as an open fd" is not
/// implemented). The S17 obligations close that gap: open with
/// `O_NOFOLLOW`, re-verify the size (and ideally the digest) against
/// the plan after the open, or take the image fd from the front end so
/// the path is never resolved a second time. Until then the truth is:
/// this rule narrows the window, it does not close it.
fn check_image(plan: &Plan) -> Result<(), Reject> {
    let path = Path::new(&plan.image.path);
    let displayed = device_text(&plan.image.path);
    let meta = fs::metadata(path).map_err(|source| {
        reject(
            "image_unreadable",
            format!("image {displayed} cannot be read ({source}) - rebuild the plan"),
        )
    })?;
    if !meta.is_file() {
        return Err(reject(
            "image_not_regular",
            format!("image {displayed} is not a regular file"),
        ));
    }
    if (meta.permissions().mode() & 0o002) != 0 {
        return Err(reject(
            "image_world_writable",
            format!(
                "image {displayed} is writable by everyone - tighten its \
                 permissions and rebuild the plan"
            ),
        ));
    }
    if meta.len() != plan.image.size_bytes {
        return Err(reject(
            "image_changed",
            format!(
                "image {displayed} changed size since the plan was built \
                 ({} now, {} recorded) - rebuild the plan",
                human_bytes(meta.len()),
                human_bytes(plan.image.size_bytes)
            ),
        ));
    }
    let sha256 = hash_file(path).map_err(|source| {
        reject(
            "image_unreadable",
            format!("image {displayed} cannot be read ({source}) - rebuild the plan"),
        )
    })?;
    if sha256 != plan.image.sha256 {
        return Err(reject(
            "image_changed",
            format!(
                "image {displayed} changed since the plan was built (its \
                 SHA-256 no longer matches) - rebuild the plan"
            ),
        ));
    }
    Ok(())
}

/// Rule 7: step arguments must be legal for this plan's options and
/// image kind; one readable message per rule, step numbers 1-based.
fn check_steps(plan: &Plan) -> Result<(), Reject> {
    for (index, step) in plan.steps.iter().enumerate() {
        let number = index + 1;
        match step {
            Step::Mkpart { layout, .. }
                if *layout == Layout::UefiNtfs && plan.options.filesystem != Filesystem::Ntfs =>
            {
                // The shim boots an NTFS data partition the image tree
                // populates: any other filesystem is refused with the
                // planner's own wording, so a hand-built plan cannot
                // slip past the CLI gate.
                return Err(reject(
                    "invalid_step",
                    "UEFI:NTFS needs an NTFS data partition; choose --filesystem ntfs",
                ));
            }
            Step::Mklabel { scheme } | Step::Mkpart { scheme, .. } => {
                if *scheme != plan.options.scheme {
                    return Err(reject(
                        "invalid_step",
                        format!(
                            "step {number} builds a {} table but the plan \
                             selected {} - rebuild the plan",
                            scheme_tag(scheme),
                            scheme_tag(&plan.options.scheme)
                        ),
                    ));
                }
            }
            Step::Mkfs {
                label,
                cluster_bytes,
                ..
            } => {
                if label.as_deref().is_some_and(|label| !label_ok(label)) {
                    return Err(reject(
                        "invalid_step",
                        format!(
                            "step {number} has a volume label the filesystem \
                             rules refuse (at most 32 printable ASCII \
                             characters) - rebuild the plan"
                        ),
                    ));
                }
                if let Some(cluster) = cluster_bytes
                    && !cluster_ok(*cluster)
                {
                    return Err(reject(
                        "invalid_step",
                        format!(
                            "step {number} has a cluster size of {cluster} \
                             bytes (only power-of-two sizes from 512 bytes \
                             to 1 MiB) - rebuild the plan"
                        ),
                    ));
                }
            }
            Step::Write { mode } => {
                // `dd` streams sector images; a structured container
                // reaches the device through a copier instead, so an
                // impossible pairing is refused before any byte moves.
                let dd = *mode == WriteMode::Dd;
                let streamable = matches!(plan.image.kind, ImageKind::Iso | ImageKind::Raw);
                if dd && !streamable {
                    return Err(reject(
                        "invalid_step",
                        format!(
                            "step {number} streams a {} image directly, but \
                             that kind is written by copying - rebuild the \
                             plan",
                            plan.image.kind
                        ),
                    ));
                }
            }
            Step::Bootloader { .. } | Step::Wipe | Step::Finalize => {}
        }
    }
    Ok(())
}

/// Rule 8: the independent safety re-check. Mount/swap tables come from
/// the `Env` fixture paths or their live `/proc` paths; a read or parse
/// failure refuses with `"unreadable"` — the helper never passes a
/// device silently on rot it can see.
fn judge_target(plan: &Plan, env: &Env, device: &Device) -> Result<Target, Reject> {
    let mount_table = MountTable::read(env.mountinfo.as_deref()).map_err(|source| {
        reject(
            "unreadable",
            format!("the mount table cannot be read: {source}"),
        )
    })?;
    let swaps = read_swaps(env.swaps.as_deref()).map_err(|source| {
        reject(
            "unreadable",
            format!("the swap table cannot be read: {source}"),
        )
    })?;
    // The CLI hook mirror: sample a stand-in *file* when `Env` says so
    // (unit fixtures); the graded device facts themselves stay put.
    let sampled = match &env.device_file {
        Some(file) => {
            let mut sampled = device.clone();
            sampled.dev_path = file.display().to_string();
            sampled
        }
        None => device.clone(),
    };
    let inspected = rufus_linux::inspect(
        &env.sysfs,
        &sampled,
        &rufus_linux::inspect::Options {
            mount_table: &mount_table,
            swaps: &swaps,
            image_bytes: Some(plan.image.size_bytes),
            allow_fixed: plan.options.show_all,
            confirmed_serial: plan.options.confirmed_serial.as_deref(),
        },
    );
    match judge(&inspected.target) {
        SafetyVerdict::Safe => Ok(inspected.target),
        SafetyVerdict::Refuse(reason) => Err(reject(reason.code(), reason.to_string())),
    }
}

/// The displays of a [`Scheme`], equal to its serde JSON tags (pinned
/// by tests so a `rename_all` change cannot drift the messages).
fn scheme_tag(scheme: &Scheme) -> &'static str {
    match scheme {
        Scheme::Mbr => "mbr",
        Scheme::Gpt => "gpt",
    }
}

/// Volume label rule (PLAN §6 rule 7): at most 32 characters, all
/// printable ASCII (`0x20..=0x7E`).
fn label_ok(label: &str) -> bool {
    label.chars().count() <= 32 && label.chars().all(|c| (' '..='~').contains(&c))
}

/// Cluster size rule: a power of two in `512..=1048576` bytes.
fn cluster_ok(cluster: u32) -> bool {
    cluster.is_power_of_two() && (512..=1_048_576).contains(&cluster)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::path::PathBuf;

    use rufus_core::hash::hash_file;
    use rufus_core::partition::MBR_SIGNATURE;
    use rufus_linux::SysfsRoot;
    use rufus_proto::BootloaderMode;
    use rufus_proto::DeviceRef;
    use rufus_proto::Filesystem;
    use rufus_proto::ImageKind;
    use rufus_proto::ImageRef;
    use rufus_proto::Options;
    use rufus_proto::PLAN_VERSION;
    use rufus_proto::Plan;
    use rufus_proto::Scheme;
    use rufus_proto::Step;
    use rufus_proto::Target as Firmware;
    use rufus_proto::WriteMode;

    use super::Env;
    use super::MAX_PLAN_BYTES;
    use super::Validated;
    use super::load;
    use super::scheme_tag;
    use super::validate;

    // ----------------------------------------------------------------------
    // Fixtures: synthetic sysfs tree + sparse scratch images, mirroring
    // the style of rufus-linux/src/inspect.rs tests byte-for-byte where
    // the same facts are seeded (`class/block/<name>` sibling links,
    // `partition` attributes, `size` in 512-byte units). No test scans
    // `/dev` or touches live state: the device node role is played by
    // `Env.device_file` (the documented test-only stand-in).
    // ----------------------------------------------------------------------

    /// The device-tree chain every seeded stick links in at.
    const STICK_CHAIN: &str = "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0";
    /// The whole disk's kernel name (and the plan's `/dev/<name>`).
    const NAME: &str = "sdb";
    const DISK_DEVNUM: &str = "8:16";
    const PART_DEVNUM: &str = "8:17";
    /// sysfs `size` is in 512-byte units regardless of media geometry.
    const SECTOR: u64 = 512;
    const STICK_UNITS: u64 = 8192; // 4 MiB of synthetic stick
    const STICK_BYTES: u64 = STICK_UNITS * SECTOR;
    /// The image the samples describe: 1.5 MiB, well inside the stick.
    const IMAGE_LEN: u64 = 1_572_864;
    /// The stick fixture's serial (rides into show-all tests).
    const SERIAL: &str = "SER123";

    struct Fixture {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Self {
                _scratch: scratch,
                root,
            }
        }

        fn write_text(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent directories");
            }
            fs::write(&path, content).unwrap_or_else(|err| panic!("seed {rel}: {err}"));
            path
        }

        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.root.join(rel))
                .unwrap_or_else(|err| panic!("mkdir {rel}: {err}"));
        }

        fn symlink(&self, target: &Path, link: &str) {
            if let Some(parent) = self.root.join(link).parent() {
                fs::create_dir_all(parent).unwrap_or_else(|err| panic!("link dirs: {err}"));
            }
            let link_path = self.root.join(link);
            // Re-seeding is legal in loops: a previous link of the same
            // name is replaced, a real file is never clobbered.
            if let Ok(meta) = std::fs::symlink_metadata(&link_path) {
                assert!(
                    meta.file_type().is_symlink(),
                    "refusing to overwrite a real file at {link}"
                );
                std::fs::remove_file(&link_path)
                    .unwrap_or_else(|err| panic!("drop stale link {link}: {err}"));
            }
            std::os::unix::fs::symlink(target, &link_path)
                .unwrap_or_else(|err| panic!("link {link}: {err}"));
        }

        /// A sparse stand-in or image file: `len` zero bytes on disk.
        fn sparse(&self, rel: &str, len: u64) -> PathBuf {
            let path = self.root.join(rel);
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("sparse {rel}: {err}"));
            file.set_len(len)
                .unwrap_or_else(|err| panic!("length {rel}: {err}"));
            path
        }

        /// Stamp `bytes` at `offset` of a sparse file.
        fn patch(&self, path: &Path, offset: u64, bytes: &[u8]) {
            use std::io::Seek as _;
            use std::io::SeekFrom;
            use std::io::Write as _;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap_or_else(|err| panic!("open {:?}: {err}", path));
            file.seek(SeekFrom::Start(offset))
                .expect("seek within the scratch file");
            file.write_all(bytes)
                .unwrap_or_else(|err| panic!("patch {:?}: {err}", path));
        }

        /// Seed the synthetic stick exactly like live sysfs: the S04
        /// chain (`devices/<chain>/block/<name>`), device identity on
        /// the four-up USB node, and class/block sibling links whose
        /// partitions carry the `partition` attribute.
        fn seed_stick(&self, removable: bool) {
            let real = format!("{STICK_CHAIN}/block/{NAME}");
            self.write_text(&format!("{real}/size"), &STICK_UNITS.to_string());
            self.write_text(
                &format!("{real}/removable"),
                if removable { "1" } else { "0" },
            );
            self.write_text(&format!("{real}/ro"), "0");
            self.write_text(&format!("{real}/dev"), DISK_DEVNUM);
            self.write_text(&format!("{STICK_CHAIN}/vendor"), "SanDisk");
            self.write_text(&format!("{STICK_CHAIN}/model"), "Test Stick");
            self.write_text(&format!("{STICK_CHAIN}/serial"), SERIAL);
            let part = format!("{real}/{NAME}1");
            self.write_text(&format!("{part}/size"), "6144");
            self.write_text(&format!("{part}/dev"), PART_DEVNUM);
            self.write_text(&format!("{part}/partition"), "1");

            self.symlink(&self.root.join(STICK_CHAIN), &format!("{real}/device"));
            self.symlink(&self.root.join(&real), &format!("class/block/{NAME}"));
            self.symlink(&self.root.join(&part), &format!("class/block/{NAME}1"));
        }

        /// A mountinfo file carrying one extra foreign line (never the
        /// fixture's own devnums, so the seeded stick is unmounted).
        fn foreign_mountinfo(&self) -> PathBuf {
            self.write_text(
                "mountinfo.tsv",
                "1 0 252:0 / / rw,relatime - ext4 /dev/simroot rw\n",
            )
        }

        /// One mountinfo line in the kernel's own five-part shape.
        fn mount_line(majmin: &str, mountpoint: &str) -> String {
            format!("2 1 {majmin} / {mountpoint} rw,relatime - vfat /dev/{majmin} rw")
        }

        /// A `/proc/swaps` file with the header row and nothing on it.
        fn empty_swaps(&self) -> PathBuf {
            self.write_text("swaps.tsv", "Filename Type Size Used Priority\n")
        }

        fn swaps(&self, rows: &str) -> PathBuf {
            self.write_text("swaps.tsv", rows)
        }

        /// The full test window for `validate`: fixture sysfs, fixture
        /// tables and (unless explicitly production-mode) the regular
        /// file stand-in that plays the device node.
        fn env(&self, stand_in: Option<&Path>) -> Env {
            Env {
                sysfs: SysfsRoot::new(self.root.clone()),
                mountinfo: Some(self.foreign_mountinfo()),
                swaps: Some(self.empty_swaps()),
                device_file: stand_in.map(Path::to_path_buf),
            }
        }

        /// A plan-shaped file (the canonical happy-path steps of the
        /// provisional CLI plan) for the seeded stick.
        fn plan_for(&self, image: &Path, image_len: u64, sha: &str) -> Plan {
            Plan {
                version: PLAN_VERSION,
                created_by: "rufus-helper tests".to_string(),
                device: DeviceRef {
                    path: format!("/dev/{NAME}"),
                    block_device: true,
                    size_bytes: Some(STICK_BYTES),
                    serial: Some(SERIAL.to_string()),
                    model: Some("Test Stick".to_string()),
                    sysfs: Some(format!("/sys/class/block/{NAME}")),
                },
                image: ImageRef {
                    path: image.display().to_string(),
                    size_bytes: image_len,
                    sha256: sha.to_string(),
                    kind: ImageKind::Raw,
                },
                options: Options {
                    scheme: Scheme::Mbr,
                    target: Firmware::Uefi,
                    filesystem: Filesystem::Fat32,
                    label: Some("RUFUS".to_string()),
                    cluster_bytes: Some(32768),
                    quick_format: true,
                    bad_blocks: false,
                    verify: false,
                    persistence: false,
                    show_all: false,
                    confirmed_serial: None,
                },
                steps: vec![
                    Step::Wipe,
                    Step::Mklabel {
                        scheme: Scheme::Mbr,
                    },
                    Step::Mkpart {
                        scheme: Scheme::Mbr,
                        layout: rufus_proto::Layout::Single,
                    },
                    Step::Mkfs {
                        filesystem: Filesystem::Fat32,
                        label: Some("RUFUS".to_string()),
                        cluster_bytes: Some(32768),
                        quick: true,
                    },
                    Step::Write {
                        mode: WriteMode::Dd,
                    },
                    Step::Bootloader {
                        mode: BootloaderMode::Auto,
                    },
                    Step::Finalize,
                ],
                confirm: String::new(),
            }
        }

        /// Sparse image of `len` zero bytes plus its SHA-256.
        fn image(&self, rel: &str, len: u64) -> (PathBuf, String) {
            let path = self.sparse(rel, len);
            let sha = hash_file(&path).expect("image hashes");
            (path, sha)
        }

        /// The canonical good case: clean removable stick, blank device
        /// bytes, an image the plan describes exactly.
        fn good(&self, removable: bool) -> (Plan, Env, PathBuf) {
            self.seed_stick(removable);
            let device = self.sparse("device.img", STICK_BYTES);
            let (image, sha) = self.image("image.img", IMAGE_LEN);
            let plan = signed(self.plan_for(&image, IMAGE_LEN, &sha));
            let env = self.env(Some(&device));
            (plan, env, device)
        }
    }

    /// A plan whose confirm hash is freshly recomputed from its own
    /// contents (the CLI's contract).
    fn signed(mut plan: Plan) -> Plan {
        plan.confirm = plan
            .confirm()
            .expect("tests build JSON-native plans that always serialise");
        plan
    }

    //"#[must_use]"-style: every refusal test asserts through this.
    fn refused_code(tested: Result<Validated, super::Reject>) -> String {
        match tested {
            Ok(_) => panic!("expected a refusal, got acceptance"),
            Err(reject) => reject.code,
        }
    }

    fn refused_message(tested: Result<Validated, super::Reject>) -> String {
        match tested {
            Ok(_) => panic!("expected a refusal, got acceptance"),
            Err(reject) => reject.message,
        }
    }

    // ----------------------------------------------------------------------
    // The good path
    // ----------------------------------------------------------------------

    #[test]
    fn good_plan_is_accepted() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        let validated = validate(&plan, &env).expect("a good plan is accepted");

        assert_eq!(validated.plan, plan, "the plan rides unmodified");
        assert_eq!(validated.device.name, NAME);
        assert_eq!(validated.device.size_bytes, STICK_BYTES);
        assert_eq!(validated.device.serial.as_deref(), Some(SERIAL));
        assert_eq!(validated.target.name, NAME);
        assert_eq!(validated.target.size_bytes, STICK_BYTES);
        // The stand-in redirected only the sampling: the graded device
        // keeps the plan's /dev path while the target records the file
        // that was actually read.
        assert_eq!(validated.target.dev_path, _device.display().to_string());
        assert!(validated.target.mounted_at.is_none());
        assert!(validated.target.holders.is_empty());
    }

    #[test]
    fn validate_is_deterministic() {
        // Running the rules twice over the same fixtures must agree
        // (no hidden state, no tidy order dependence).
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        let first = validate(&plan, &env).expect("accepted");
        let second = validate(&plan, &env).expect("accepted");
        assert_eq!(first.device, second.device);
        assert_eq!(first.target.serial, second.target.serial);
    }

    // ----------------------------------------------------------------------
    // Schema and integrity (rules 1–2)
    // ----------------------------------------------------------------------

    #[test]
    fn wrong_version_is_refused_naming_both_numbers() {
        let fixture = Fixture::new();
        for (version, label) in [(1u32, "v1 plan"), (PLAN_VERSION + 1, "future plan")] {
            let (mut plan, env, _device) = fixture.good(true);
            plan.version = version;
            plan = signed(plan);
            let code = refused_code(validate(&plan, &env));
            assert_eq!(code, "unsupported_version", "{label}");
            let message = refused_message(validate(&plan, &env));
            assert!(
                message.contains(&format!("version {version}"))
                    && message.contains("supports version"),
                "the message names both numbers: {message}"
            );
        }
    }

    #[test]
    fn tampered_confirm_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.confirm = format!("sha256:{}", "0".repeat(64));
        assert_eq!(refused_code(validate(&plan, &env)), "confirm_mismatch");
    }

    #[test]
    fn descriptive_confirm_without_the_hash_shape_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.confirm = String::new(); // not recomputed from plan content
        assert_eq!(refused_code(validate(&plan, &env)), "confirm_mismatch");
    }

    // ----------------------------------------------------------------------
    // Step shape (rule 3)
    // ----------------------------------------------------------------------

    #[test]
    fn a_plan_without_steps_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.steps = Vec::new();
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
        assert!(
            refused_message(validate(&plan, &env)).contains("no steps"),
            "the message says what is wrong"
        );
    }

    #[test]
    fn a_plan_without_a_final_step_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.steps.pop();
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    #[test]
    fn duplicate_finalize_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        // Finalize twice: the last-step shape is intact, the count rules
        // separately refuse it.
        plan.steps.insert(3, Step::Finalize);
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    // ----------------------------------------------------------------------
    // Device node rules (rule 4)
    // ----------------------------------------------------------------------

    #[test]
    fn device_path_must_say_dev() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.device.path = "/home/user/usb.img".to_string();
        plan = signed(plan); // every mutation re-signs: confirm gates first
        assert_eq!(refused_code(validate(&plan, &env)), "not_a_block_device");
        // A relative name equally fails the prefix rule.
        plan.device.path = "sdb".to_string();
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "not_a_block_device");
    }

    /// The production shape forces regular nodes to refuse: with
    /// `device_file: None` the path-shape rules examine
    /// `plan.device.path` itself, exactly as the helper binary does.
    #[test]
    fn production_mode_refuses_a_regular_file_as_the_device() {
        let fixture = Fixture::new();
        let plain = fixture.write_text("plain-device", "not a block device");
        // `/dev/../<scratch>` keeps the `/dev/` prefix on the literal
        // plan path while pointing at a scratch regular file the test
        // controls (what the kernel path walk resolves to), so the
        // file-type rule can be exercised hermetically.
        let plan_path = format!("/dev/../{}", plain.display());
        let (mut plan, mut env, _device) = fixture.good(true);
        // Production mode: no stand-in, the plan path itself is checked.
        env.device_file = None;
        plan.device.path = plan_path.clone();
        plan = signed(plan);
        let tested = validate(&plan, &env);
        assert_eq!(refused_code(tested), "not_a_block_device");
        assert!(
            refused_message(validate(&plan, &env)).contains(
                Path::new(plan_path.as_str())
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .expect("plain file name")
            ),
            "the message names the device"
        );
    }

    #[test]
    fn production_mode_refuses_a_missing_node() {
        let fixture = Fixture::new();
        let absent = format!(
            "/dev/../{}",
            fixture.root.join("definitely-not-there").display()
        );
        let (mut plan, mut env, _device) = fixture.good(true);
        env.device_file = None;
        plan.device.path = absent;
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "not_a_block_device");
    }

    #[test]
    fn symlink_device_is_refused() {
        let fixture = Fixture::new();
        let target = fixture.write_text("real-target", "content");
        fixture.symlink(&target, "linked-device");
        let absent = format!("/dev/../{}", fixture.root.join("linked-device").display());
        let (mut plan, mut env, _device) = fixture.good(true);
        env.device_file = None;
        plan.device.path = absent;
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "symlink");
    }

    #[test]
    fn unknown_device_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.device.path = "/dev/no_such_helper_device".to_string();
        plan = signed(plan);
        // The node check passes (it examines the stand-in), discovery
        // cannot find the name: the device is gone from this system.
        assert_eq!(refused_code(validate(&plan, &env)), "unknown_device");
    }

    #[test]
    fn unreadable_sysfs_refuses_instead_of_passing() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        let bare = tempfile::tempdir().expect("bare root");
        env.sysfs = SysfsRoot::new(bare.path().to_path_buf());
        assert_eq!(refused_code(validate(&plan, &env)), "unreadable");
    }

    // The documented seam: `device_file` only redirects WHICH file the
    // node check and the safety re-check examine. Pinned by the pair
    // below: the same plan, the same plan path, two stand-ins — one
    // carrying LVM2 magic (refused as `refused_filesystem`), one with
    // clean blank bytes (accepted). Only the stand-in content decides,
    // so the plan's own `/dev/<name>` path is never even opened.

    #[test]
    fn device_file_redirects_which_file_is_examined() {
        let fixture = Fixture::new();
        fixture.seed_stick(true);

        let hostile = fixture.sparse("hostile.img", STICK_BYTES);
        fixture.patch(&hostile, 512, b"LABELONE");
        fixture.patch(&hostile, 536, b"LVM2 001");
        let (image, sha) = fixture.image("image.img", IMAGE_LEN);
        let plan = signed(fixture.plan_for(&image, IMAGE_LEN, &sha));

        let code = refused_code(validate(&plan, &fixture.env(Some(&hostile))));
        assert_eq!(code, "refused_filesystem", "the stand-in was examined");
        assert!(
            refused_message(validate(&plan, &fixture.env(Some(&hostile)))).contains("lvm2"),
            "the probed kind is named"
        );
    }

    #[test]
    fn device_file_clean_stand_in_runs_verdict_clean() {
        // The exact twin of the hostile test: clean stand-in bytes over
        // the same plan accept, proving the sampled file is the seam.
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        validate(&plan, &env).expect("a clean stand-in plays the device");
        // And, equally, the stand-in is what judged NOT the host's own
        // node: the plan path stays a string reference throughout.
        assert_eq!(plan.device.path, format!("/dev/{NAME}"));
    }

    // ----------------------------------------------------------------------
    // Size rule (rule 5)
    // ----------------------------------------------------------------------

    #[test]
    fn size_within_one_sector_is_accepted_both_ways() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.device.size_bytes = Some(STICK_BYTES + SECTOR);
        plan = signed(plan);
        validate(&plan, &env).expect("exactly one sector more is planned correctly");

        let (mut plan, env, _device) = fixture.good(true);
        plan.device.size_bytes = Some(STICK_BYTES - SECTOR);
        plan = signed(plan);
        validate(&plan, &env).expect("exactly one sector less is planned correctly");
    }

    #[test]
    fn size_beyond_one_sector_is_refused_both_ways() {
        let fixture = Fixture::new();
        for (size, label) in [
            (STICK_BYTES + 2 * SECTOR, "more than a sector"),
            (STICK_BYTES - 2 * SECTOR, "less than a sector"),
        ] {
            let (mut plan, env, _device) = fixture.good(true);
            plan.device.size_bytes = Some(size);
            plan = signed(plan);
            assert_eq!(
                refused_code(validate(&plan, &env)),
                "size_mismatch",
                "{label}"
            );
            let message = refused_message(validate(&plan, &env));
            assert!(
                message.contains("device"),
                "the message names the device and both numbers: {message}"
            );
        }
    }

    #[test]
    fn a_plan_without_recorded_size_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.device.size_bytes = None;
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "size_mismatch");
    }

    // ----------------------------------------------------------------------
    // Image rules (rule 6)
    // ----------------------------------------------------------------------

    #[test]
    fn image_missing_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.image.path = fixture.root.join("gone.iso").display().to_string();
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "image_unreadable");
    }

    #[test]
    fn image_not_a_regular_file_is_refused() {
        let fixture = Fixture::new();
        let dir = fixture.root.join("image-dir");
        fixture.mkdir("image-dir");
        let (mut plan, env, _device) = fixture.good(true);
        plan.image.path = dir.display().to_string();
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "image_not_regular");
    }

    #[test]
    fn world_writable_image_is_refused() {
        let fixture = Fixture::new();
        let (image, sha) = fixture.image("ww.img", IMAGE_LEN);
        fs::set_permissions(&image, fs::Permissions::from_mode(0o666)).expect("fixture chmod");
        let plan = signed(fixture.plan_for(&image, IMAGE_LEN, &sha));
        let (_p2, env, _d2) = fixture.good(true);
        assert_eq!(refused_code(validate(&plan, &env)), "image_world_writable");
    }

    #[test]
    fn world_writable_flag_is_not_limited_to_the_owner_bits() {
        // 0o600 (owner write, group/other none) must pass; the rule is
        // only about the world-write bit.
        let fixture = Fixture::new();
        let (image, sha) = fixture.image("600.img", IMAGE_LEN);
        fs::set_permissions(&image, fs::Permissions::from_mode(0o600)).expect("fixture chmod");
        let plan = signed(fixture.plan_for(&image, IMAGE_LEN, &sha));
        let (_p2, env, _d2) = fixture.good(true);
        validate(&plan, &env).expect("owner-only writable image is fine");
    }

    #[test]
    fn shrunken_image_is_refused_talking_about_the_change() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        fs::OpenOptions::new()
            .write(true)
            .open(Path::new(&plan.image.path))
            .and_then(|file| file.set_len(plan.image.size_bytes - 1))
            .expect("shrink the image behind the plan");
        assert_eq!(refused_code(validate(&plan, &env)), "image_changed");
        assert!(
            refused_message(validate(&plan, &env)).contains("changed size"),
            "the message says what changed: {}",
            refused_message(validate(&plan, &env))
        );
    }

    #[test]
    fn patched_image_bytes_are_refused_as_changed() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        // Same length, different bytes: the digest guard catches it
        // (this is the TOCTOU re-read the whole rule exists for).
        fixture.patch(Path::new(&plan.image.path), 4096, b"vanished");
        assert_eq!(refused_code(validate(&plan, &env)), "image_changed");
    }

    #[test]
    fn an_absolute_zero_grew_image_bytes_are_read_back() {
        // A plan that LIES about the image size (records more than
        // exists) refuses as changed.
        let fixture = Fixture::new();
        let (image, sha) = fixture.image("img.img", IMAGE_LEN);
        let mut plan = fixture.plan_for(&image, IMAGE_LEN + 1, &sha);
        plan = signed(plan);
        let (_p2, env, _d2) = fixture.good(true);
        assert_eq!(refused_code(validate(&plan, &env)), "image_changed");
    }

    // ----------------------------------------------------------------------
    // Step semantics (rule 7)
    // ----------------------------------------------------------------------

    #[test]
    fn mklabel_scheme_mismatch_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mklabel { scheme } = &mut plan.steps[1] {
            *scheme = Scheme::Gpt; // the plan selected Mbr
        }
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    #[test]
    fn mkpart_scheme_mismatch_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mkpart { scheme, .. } = &mut plan.steps[2] {
            *scheme = Scheme::Gpt;
        }
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    #[test]
    fn uefi_ntfs_layout_without_ntfs_is_refused() {
        // The shim boots an NTFS data partition: a hand-built plan
        // pairing the two-partition layout with the default FAT32
        // filesystem is refused with the planner's own wording.
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mkpart { layout, .. } = &mut plan.steps[2] {
            *layout = rufus_proto::Layout::UefiNtfs;
        }
        plan = signed(plan);
        let refused = validate(&plan, &env).expect_err("fat32 data refuses");
        assert_eq!(refused.code, "invalid_step");
        assert_eq!(
            refused.message,
            "UEFI:NTFS needs an NTFS data partition; choose --filesystem ntfs"
        );
    }

    #[test]
    fn uefi_ntfs_layout_with_ntfs_is_accepted() {
        // The same layout over the NTFS filesystem it boots passes:
        // the rule only fires on the mismatched pairing.
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mkpart { layout, .. } = &mut plan.steps[2] {
            *layout = rufus_proto::Layout::UefiNtfs;
        }
        plan.options.filesystem = Filesystem::Ntfs;
        plan = signed(plan);
        validate(&plan, &env).expect("the ntfs pairing passes");
    }

    #[test]
    fn label_too_long_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mkfs { label, .. } = &mut plan.steps[3] {
            *label = Some("x".repeat(33));
        }
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    #[test]
    fn label_with_control_characters_is_refused() {
        let fixture = Fixture::new();
        for hostiled in ["bad\u{0007}label", "bad\u{00e9}label"] {
            let (mut plan, env, _device) = fixture.good(true);
            if let Step::Mkfs { label, .. } = &mut plan.steps[3] {
                *label = Some(hostiled.to_string());
            }
            plan = signed(plan);
            assert_eq!(
                refused_code(validate(&plan, &env)),
                "invalid_step",
                "label {hostiled:?}"
            );
        }
    }

    #[test]
    fn label_of_32_chars_is_accepted() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        if let Step::Mkfs { label, .. } = &mut plan.steps[3] {
            *label = Some("R".repeat(32));
        }
        plan.options.label = Some("R".repeat(32));
        plan = signed(plan);
        validate(&plan, &env).expect("32 printable chars stay valid");
    }

    #[test]
    fn cluster_size_rules_are_enforced() {
        let fixture = Fixture::new();
        for (cluster, accepted, why) in [
            (300u32, false, "no power of two"),
            (0, false, "not a size at all"),
            (256, false, "below the floor"),
            (2_097_152, false, "above the ceiling"),
            (1024, true, "smallest common upward size"),
            (1_048_576, true, "the 1 MiB ceiling"),
        ] {
            let (mut plan, env, _device) = fixture.good(true);
            if let Step::Mkfs { cluster_bytes, .. } = &mut plan.steps[3] {
                *cluster_bytes = Some(cluster);
            }
            plan = signed(plan);
            let tested = validate(&plan, &env);
            assert_eq!(tested.is_ok(), accepted, "cluster {cluster}: {why}");
        }
    }

    #[test]
    fn dd_write_of_a_wim_image_is_refused() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.image.kind = ImageKind::Wim; // steps still say Write{Dd}
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "invalid_step");
    }

    #[test]
    fn copy_write_of_a_wim_image_is_accepted() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.image.kind = ImageKind::Wim;
        if let Step::Write { mode } = &mut plan.steps[4] {
            *mode = WriteMode::Copy;
        }
        plan = signed(plan);
        validate(&plan, &env).expect("copy mode fits structured images");
    }

    #[test]
    fn iso_images_stay_ddable() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(true);
        plan.image.kind = ImageKind::Iso;
        plan = signed(plan);
        validate(&plan, &env).expect("iso is a streamable kind");
    }

    // ----------------------------------------------------------------------
    // The independent safety re-check (rule 8)
    // ----------------------------------------------------------------------

    #[test]
    fn mounted_device_is_refused_naming_the_mountpoint() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        env.mountinfo = Some(fixture.write_text(
            "mountinfo.tsv",
            &format!(
                "{}\n",
                Fixture::mount_line(DISK_DEVNUM, "/media/user/STICK")
            ),
        ));
        assert_eq!(refused_code(validate(&plan, &env)), "mounted");
        assert!(
            refused_message(validate(&plan, &env)).contains("mounted at /media/user/STICK"),
            "the mountpoint is named: {}",
            refused_message(validate(&plan, &env))
        );
    }

    #[test]
    fn mounted_partition_is_enough_to_refuse() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        env.mountinfo = Some(fixture.write_text(
            "mountinfo.tsv",
            &format!("{}\n", Fixture::mount_line(PART_DEVNUM, "/run/media/usb")),
        ));
        assert_eq!(refused_code(validate(&plan, &env)), "mounted");
    }

    #[test]
    fn active_swap_is_refused() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        env.swaps = Some(fixture.swaps(
            "Filename Type Size Used Priority\n\
             /dev/sdb1 partition 3000 0 -2\n",
        ));
        assert_eq!(refused_code(validate(&plan, &env)), "swap");
    }

    #[test]
    fn held_device_is_refused() {
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        fixture.mkdir(&format!("{STICK_CHAIN}/block/{NAME}/holders/dm-0"));
        assert_eq!(refused_code(validate(&plan, &env)), "holder");
        assert!(
            refused_message(validate(&plan, &env)).contains("dm-0"),
            "the holder is named: {}",
            refused_message(validate(&plan, &env))
        );
    }

    #[test]
    fn system_disk_is_refused_before_mount_state() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        // The fixture partition mounted at / backs the running system.
        env.mountinfo = Some(fixture.write_text(
            "mountinfo.tsv",
            &format!("{}\n", Fixture::mount_line(PART_DEVNUM, "/")),
        ));
        assert_eq!(refused_code(validate(&plan, &env)), "system_disk");
    }

    #[test]
    fn lvm_partition_is_refused_by_kind() {
        let fixture = Fixture::new();
        fixture.seed_stick(true);
        // An MBR table plus an LVM2 label inside the partition window.
        let mut lba0 = [0u8; 512];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        lba0[446 + 4] = 0x0b;
        lba0[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        lba0[446 + 12..446 + 16].copy_from_slice(&6144u32.to_le_bytes());
        let stand_in = fixture.sparse("device.img", STICK_BYTES);
        fixture.patch(&stand_in, 0, &lba0);
        fixture.patch(&stand_in, 2048 * SECTOR + 512, b"LABELONE");
        fixture.patch(&stand_in, 2048 * SECTOR + 536, b"LVM2 001");
        let (image, sha) = fixture.image("image.img", IMAGE_LEN);
        let plan = signed(fixture.plan_for(&image, IMAGE_LEN, &sha));
        let env = fixture.env(Some(&stand_in));

        assert_eq!(refused_code(validate(&plan, &env)), "refused_filesystem");
        assert!(
            refused_message(validate(&plan, &env)).contains("lvm2")
                && refused_message(validate(&plan, &env)).contains(&format!("{NAME}1")),
            "the probed kind and partition are named"
        );
    }

    // The show-all serial gate (PLAN §6 rule 4): a non-removable target
    // is refused until the plan carries show-all *and* a typed serial
    // identical to the device's own.

    #[test]
    fn fixed_disk_without_a_serial_is_refused() {
        let fixture = Fixture::new();
        // Show-all turned on but nothing typed: still not removable.
        let (mut plan, env, _device) = fixture.good(false);
        plan.options.show_all = true;
        plan.options.confirmed_serial = None;
        plan = signed(plan);
        let tested = validate(&plan, &env);
        assert!(tested.is_err(), "an unconfirmed fixed disk got through");
        assert_eq!(refused_code(tested), "not_removable");

        // The gate is the serial, not show-all alone: show-all off (a
        // serial typed nobody asked for) is refused the same way.
        let (mut plan, env, _device2) = fixture.good(false);
        plan.options.show_all = false;
        plan.options.confirmed_serial = Some(SERIAL.to_string());
        plan = signed(plan);
        assert_eq!(refused_code(validate(&plan, &env)), "not_removable");
    }

    #[test]
    fn fixed_disk_with_the_wrong_serial_is_refused() {
        let fixture = Fixture::new();
        for (typed, label) in [
            ("WRONG".to_string(), "different serial"),
            (String::new(), "empty serial"),
            ("ser123\u{2000}".to_string(), "padded serial"),
        ] {
            let (mut plan, env, _device) = fixture.good(false);
            plan.options.show_all = true;
            plan.options.confirmed_serial = Some(typed.trim_end().to_string());
            plan = signed(plan);
            assert_eq!(
                refused_code(validate(&plan, &env)),
                "not_removable",
                "{label}"
            );
        }
    }

    #[test]
    fn fixed_disk_with_the_exact_serial_is_accepted() {
        let fixture = Fixture::new();
        let (mut plan, env, _device) = fixture.good(false);
        plan.options.show_all = true;
        plan.options.confirmed_serial = Some(SERIAL.to_string());
        plan = signed(plan);
        validate(&plan, &env).expect("typed serial unblocks the fixed disk");
    }

    #[test]
    fn removable_disk_stays_ungated() {
        // No show-all, no serial: a plain removable stick runs.
        let fixture = Fixture::new();
        let (plan, env, _device) = fixture.good(true);
        validate(&plan, &env).expect("removable media is the normal case");
    }

    // ----------------------------------------------------------------------
    // Environment rot refuses (never passes silently)
    // ----------------------------------------------------------------------

    #[test]
    fn a_rotten_mount_table_refuses_as_unreadable() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        env.mountinfo = Some(fixture.write_text(
            "mountinfo.tsv",
            "this line is not a kernel mountinfo record\n",
        ));
        assert_eq!(
            refused_code(validate(&plan, &env)),
            "unreadable",
            "table rot must never read as \"not mounted\""
        );
    }

    #[test]
    fn a_rotten_swap_table_refuses_as_unreadable() {
        let fixture = Fixture::new();
        let (plan, mut env, _device) = fixture.good(true);
        env.swaps = Some(fixture.swaps("only one field here\n"));
        assert_eq!(refused_code(validate(&plan, &env)), "unreadable");
    }

    // ----------------------------------------------------------------------
    // load()
    // ----------------------------------------------------------------------

    #[test]
    fn load_round_trips_a_saved_plan() {
        let fixture = Fixture::new();
        let (plan, _env, _device) = fixture.good(true);
        let path = fixture.write_text(
            "plan.json",
            &serde_json::to_string(&plan).expect("plan serialises"),
        );
        let loaded = load(&path).expect("the saved plan loads");
        assert_eq!(loaded, plan);
    }

    #[test]
    fn load_refuses_a_missing_file() {
        let fixture = Fixture::new();
        let err = load(&fixture.root.join("absent.json")).expect_err("a missing plan file refuses");
        assert_eq!(err.code, "unreadable_plan");
        assert!(err.message.contains("cannot read the plan file"));
    }

    #[test]
    fn load_refuses_a_plan_file_beyond_the_size_cap() {
        let fixture = Fixture::new();
        // One byte past the cap is enough; the reader never parses it.
        let oversized = " ".repeat(MAX_PLAN_BYTES + 1);
        let path = fixture.write_text("huge.json", &oversized);
        let err = load(&path).expect_err("a plan larger than the cap refuses");
        assert_eq!(err.code, "plan_too_large");
        assert!(err.message.contains("plan file"), "{}", err.message);
    }

    #[test]
    fn an_image_larger_than_the_device_is_refused_as_too_small() {
        let fixture = Fixture::new();
        fixture.seed_stick(true);
        let device = fixture.sparse("device.img", STICK_BYTES);
        // Two sectors past the device, which is beyond the plan's own
        // size slack and therefore a `TooSmall` refusal, not a mismatch.
        let oversize = STICK_BYTES + 2 * SECTOR;
        let (image, sha) = fixture.image("image.img", oversize);
        let plan = signed(fixture.plan_for(&image, oversize, &sha));
        let env = fixture.env(Some(&device));

        let reject = validate(&plan, &env).expect_err("an image bigger than the device refuses");
        assert_eq!(reject.code, "too_small", "{}", reject.message);
    }

    #[test]
    fn load_refuses_rot() {
        let fixture = Fixture::new();
        let path = fixture.write_text("plan.json", "{");
        let err = load(&path).expect_err("rot refuses");
        assert_eq!(err.code, "malformed_plan");
        let path = fixture.write_text("plan.json", "{\"version\": 2}");
        let err = load(&path).expect_err("an incomplete plan refuses");
        assert_eq!(err.code, "malformed_plan");
    }

    // ----------------------------------------------------------------------
    // Pinned machine-facing strings
    // ----------------------------------------------------------------------

    #[test]
    fn scheme_tags_match_the_serde_wire_tags() {
        for (scheme, tag) in [(Scheme::Mbr, "mbr"), (Scheme::Gpt, "gpt")] {
            assert_eq!(scheme_tag(&scheme), tag, "scheme human tag");
            let wire = serde_json::to_value(&scheme).expect("scheme serialises");
            assert_eq!(
                wire, tag,
                "the human message cannot drift from the wire tag"
            );
        }
    }
}
