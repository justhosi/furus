//! Root-gated integration tests for the copy-step mount seam
//! (`rufus_linux::mount::partition`) against the real kernel.
//!
//! Until this file existed, every test of the seam ran against a fake
//! `MountOps`, so no filesystem had ever been mounted for real, and the
//! NTFS mapping (`Filesystem::Ntfs` to the kernel's `ntfs3`) had no
//! real-kernel coverage at all.
//!
//! Each test attaches a fresh sparse image to a loop device, formats the
//! loop node with the real external tool for one filesystem, and drives
//! the production [`mount`] through its public API only:
//!
//! * the guard's `path()` is an existing directory listed in mountinfo;
//! * a 1 MiB payload written through the mount shrinks `free_bytes()`
//!   (asserted as `after <= before`, since cluster rounding applies);
//! * `release()` removes the mount point and drops it from mountinfo,
//!   and a second `release()` is a no-op;
//! * re-mounting the same loop device returns the payload byte-exact
//!   (the durability proof);
//! * the loop device is detached again before the test returns.
//!
//! Every test is `#[ignore]`d: a plain `cargo test --workspace` compiles
//! this file and skips every test here. Run them as root, after a first
//! unprivileged build so nothing is compiled under sudo:
//!
//! ```text
//! sudo -E $(which cargo) test --offline -p rufus-linux --test mount_seam -- --ignored --nocapture
//! ```
//!
//! Tools (a missing one prints one `skip:` line naming its package and
//! the test returns without asserting anything):
//!
//! * `losetup` - util-linux
//! * `mkfs.fat` - dosfstools (FAT32)
//! * `mkfs.exfat` - exfatprogs (exFAT)
//! * `mkntfs` - ntfsprogs (NTFS, mounted by the kernel's `ntfs3` driver,
//!   so the running kernel needs `ntfs3` built in or as a module)
//!
//! A non-root run skips every test. A root run that cannot attach a
//! loop device, or whose formatter or mount fails, is a real failure.

use std::fs;
use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::process::Output;
use std::thread;
use std::time::Duration;

use rufus_core::pipeline::MountedPartition;
use rufus_linux::mount::partition::mount;
use rufus_linux::mounts::MountTable;
use rufus_proto::Filesystem;

/// One MiB in bytes.
const MIB: u64 = 1024 * 1024;

/// Size of the sparse backing image. Big enough for every formatter's
/// minimum (`mkfs.fat -F 32` wants well over 65525 clusters), and cheap
/// because the file is sparse.
const IMAGE_BYTES: u64 = 128 * MIB;

/// The payload written through each mount: one MiB, far above any
/// cluster rounding in the free-space comparison.
const PAYLOAD_BYTES: usize = MIB as usize;

/// File name the payload is written under, at the mount root.
const PAYLOAD_NAME: &str = "rufus-payload.bin";

/// The kernel's mount table for this process, the file
/// [`MountTable::read`] reads by default.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// How often, and how many times, to look for a loop device that is
/// still attached after `losetup -d`. udev or blkid can hold the node
/// open for a moment after the last write, and the kernel then
/// auto-clears it on the last close instead of at once, so one look is
/// not enough. Five seconds is the bound; a device still attached after
/// that is a real failure.
const DETACH_POLLS: u32 = 50;
const DETACH_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A formatter run on the loop node: the program, the flags before the
/// device path, and the package that ships it (named in the skip line).
struct Formatter {
    program: &'static str,
    flags: &'static [&'static str],
    package: &'static str,
}

/// Whether this process is root (effective user id 0). The root gate
/// decides between a documented skip and a real run.
fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

/// Whether `program` can be spawned at all. Presence only, never a
/// status verdict (the same convention as the core format suites): a
/// spawn error means the binary is missing.
fn tool_present(program: &str) -> bool {
    Command::new(program).arg("--version").output().is_ok()
}

/// Skip gate for one tool: prints the single `skip:` line naming the
/// tool and its package, and reports `false` when the tool is absent.
fn have_tool(program: &str, package: &str) -> bool {
    if tool_present(program) {
        return true;
    }
    eprintln!("skip: {program} is not installed; install the {package} package and re-run");
    false
}

/// Skip gate for the root requirement.
fn root_or_skip() -> bool {
    if is_root() {
        return true;
    }
    eprintln!("skip: the mount seam tests need root and loop devices; run as root with --ignored");
    false
}

/// stdout and stderr of a finished tool run, trimmed, for failure
/// messages.
fn captured(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_string()
}

/// A loop device attached to the test's image. `Drop` detaches it, so
/// every exit path, including a panic, releases the node.
struct LoopGuard {
    /// The device node losetup picked, e.g. `/dev/loop7`.
    device: String,
}

impl LoopGuard {
    /// Attach `image` to a free loop device with `losetup --find --show`.
    /// Root asked for a device, so a failure panics with losetup's own
    /// output.
    fn attach(image: &Path) -> Self {
        let output = Command::new("losetup")
            .arg("--find")
            .arg("--show")
            .arg(image)
            .output()
            .expect("losetup spawns (its presence was checked)");
        assert!(
            output.status.success(),
            "losetup could not attach {}: {}",
            image.display(),
            captured(&output)
        );
        let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            device.starts_with("/dev/loop"),
            "losetup printed an unexpected device name: {device:?}"
        );
        Self { device }
    }

    /// The device node.
    fn path(&self) -> &Path {
        Path::new(&self.device)
    }
}

impl Drop for LoopGuard {
    /// Best-effort detach for every exit path. A failure is only
    /// reported here; the explicit check in [`round_trip`] is the one
    /// that fails the test.
    fn drop(&mut self) {
        match Command::new("losetup").arg("-d").arg(&self.device).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "warning: losetup -d {} failed: {}",
                self.device,
                captured(&output)
            ),
            Err(error) => eprintln!("warning: losetup -d {} could not run: {error}", self.device),
        }
    }
}

/// Whether `device` still shows in `losetup -a` (one line per attached
/// device, starting with the node name and a colon).
fn loop_attached(device: &Path) -> bool {
    let output = Command::new("losetup")
        .arg("-a")
        .output()
        .expect("losetup -a spawns (its presence was checked)");
    let prefix = format!("{}:", device.display());
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.starts_with(&prefix))
}

/// Poll until `device` is gone from `losetup -a`, up to the bound in
/// [`DETACH_POLLS`]. Returns whether it is detached at the end.
fn wait_until_detached(device: &Path) -> bool {
    for _ in 0..DETACH_POLLS {
        if !loop_attached(device) {
            return true;
        }
        thread::sleep(DETACH_POLL_INTERVAL);
    }
    !loop_attached(device)
}

/// Whether `mount_point` is listed in this process's mount table. The
/// comparison is on the exact text, which holds for the ASCII temp paths
/// this suite creates.
fn mounted_at(mount_point: &Path) -> bool {
    let table = MountTable::read(Some(Path::new(MOUNTINFO)))
        .expect("the mount table (/proc/self/mountinfo) parses");
    let wanted = mount_point.display().to_string();
    table
        .entries()
        .iter()
        .any(|entry| entry.mountpoint == wanted)
}

/// Deterministic payload: the same cycle the loop suites use, so any
/// misplaced byte shows up as a mismatch.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251 + 1) as u8).collect()
}

/// Run the formatter on the loop node. A failing formatter is a real
/// failure in a root run, with its own output in the message.
fn format_node(formatter: &Formatter, device: &Path) {
    let output = Command::new(formatter.program)
        .args(formatter.flags)
        .arg(device)
        .output()
        .expect("the formatter spawns (its presence was checked)");
    assert!(
        output.status.success(),
        "{} failed on {}: {}",
        formatter.program,
        device.display(),
        captured(&output)
    );
}

/// The whole round trip for one filesystem. `name` labels every stage
/// line and assertion message.
fn round_trip(name: &str, filesystem: &Filesystem, formatter: &Formatter) {
    if !root_or_skip() {
        return;
    }
    if !have_tool("losetup", "util-linux") || !have_tool(formatter.program, formatter.package) {
        return;
    }

    let dir = tempfile::tempdir().expect("a scratch directory");
    let image = dir.path().join("partition.img");
    File::create(&image)
        .and_then(|file| file.set_len(IMAGE_BYTES))
        .expect("the sparse backing image is created");
    // Declared before any mount so that, on unwind, every mount is
    // released first and the device is detached last.
    let loop_guard = LoopGuard::attach(&image);
    let device = loop_guard.path().to_path_buf();
    eprintln!(
        "stage: {name}: attached {} over {}",
        device.display(),
        image.display()
    );

    format_node(formatter, &device);
    eprintln!(
        "stage: {name}: formatted {} with {}",
        device.display(),
        formatter.program
    );

    // First mount through the production seam.
    let mut first = mount(&device, filesystem).unwrap_or_else(|error| {
        panic!(
            "{name}: mount of {} through the seam failed: {error}",
            device.display()
        )
    });
    let mount_point = first.path().to_path_buf();
    eprintln!("stage: {name}: mounted at {}", mount_point.display());
    assert!(
        mount_point.is_dir(),
        "{name}: the mount point {} is not a directory",
        mount_point.display()
    );
    assert!(
        mounted_at(&mount_point),
        "{name}: {} is not listed in the mount table while mounted",
        mount_point.display()
    );

    let before = first
        .free_bytes()
        .unwrap_or_else(|error| panic!("{name}: free_bytes failed before the write: {error}"));
    assert!(
        before > 0,
        "{name}: free bytes before the write must be positive, got {before} on {}",
        mount_point.display()
    );

    let payload = pattern(PAYLOAD_BYTES);
    let written = mount_point.join(PAYLOAD_NAME);
    fs::write(&written, &payload).unwrap_or_else(|error| {
        panic!(
            "{name}: writing {} through the mount failed: {error}",
            written.display()
        )
    });
    File::open(&written)
        .and_then(|file| file.sync_all())
        .unwrap_or_else(|error| panic!("{name}: syncing the payload failed: {error}"));

    let after = first
        .free_bytes()
        .unwrap_or_else(|error| panic!("{name}: free_bytes failed after the write: {error}"));
    eprintln!("stage: {name}: free bytes before {before}, after {after}");
    assert!(
        after > 0 && after <= before,
        "{name}: free bytes must stay positive and not grow after a {PAYLOAD_BYTES} byte write: \
         before {before}, after {after}, mount point {}",
        mount_point.display()
    );

    // Explicit release: the mount point is gone, mountinfo no longer
    // lists it, and a second release is a no-op.
    first.release().unwrap_or_else(|error| {
        panic!(
            "{name}: release of {} failed: {error}",
            mount_point.display()
        )
    });
    assert!(
        !mount_point.exists(),
        "{name}: release must remove the mount point {}",
        mount_point.display()
    );
    assert!(
        !mounted_at(&mount_point),
        "{name}: {} is still listed in the mount table after release",
        mount_point.display()
    );
    first
        .release()
        .unwrap_or_else(|error| panic!("{name}: a second release must be Ok: {error}"));
    assert!(
        !mounted_at(&mount_point),
        "{name}: a second release must leave {} unmounted",
        mount_point.display()
    );
    eprintln!("stage: {name}: released {}", mount_point.display());

    // Durability: mount the same loop device again and read the payload
    // back byte-exact.
    let mut second = mount(&device, filesystem).unwrap_or_else(|error| {
        panic!(
            "{name}: the re-mount of {} through the seam failed: {error}",
            device.display()
        )
    });
    let remount_point = second.path().to_path_buf();
    assert!(
        mounted_at(&remount_point),
        "{name}: the re-mount {} is not listed in the mount table",
        remount_point.display()
    );
    let read_back = fs::read(remount_point.join(PAYLOAD_NAME)).unwrap_or_else(|error| {
        panic!(
            "{name}: reading the payload back from {} failed: {error}",
            remount_point.display()
        )
    });
    assert_eq!(
        read_back.len(),
        payload.len(),
        "{name}: the payload length changed across the remount on {}",
        remount_point.display()
    );
    assert!(
        read_back == payload,
        "{name}: the payload bytes differ after the remount on {}",
        remount_point.display()
    );
    second
        .release()
        .unwrap_or_else(|error| panic!("{name}: releasing the re-mount failed: {error}"));
    assert!(
        !mounted_at(&remount_point),
        "{name}: the re-mount {} is still listed after release",
        remount_point.display()
    );
    eprintln!("stage: {name}: payload read back byte-exact after the remount");

    // Detach, then prove it: the node must leave `losetup -a`.
    drop(loop_guard);
    assert!(
        wait_until_detached(&device),
        "{name}: {} is still listed by losetup -a after the detach wait",
        device.display()
    );
    eprintln!("stage: {name}: {} detached", device.display());
}

#[ignore = "needs root and loop devices: run as root with --ignored"]
#[test]
fn fat32_mounts_through_the_real_kernel() {
    round_trip(
        "FAT32",
        &Filesystem::Fat32,
        &Formatter {
            program: "mkfs.fat",
            flags: &["-F", "32"],
            package: "dosfstools",
        },
    );
}

#[ignore = "needs root and loop devices: run as root with --ignored"]
#[test]
fn exfat_mounts_through_the_real_kernel() {
    round_trip(
        "exFAT",
        &Filesystem::Exfat,
        &Formatter {
            program: "mkfs.exfat",
            flags: &[],
            package: "exfatprogs",
        },
    );
}

#[ignore = "needs root and loop devices: run as root with --ignored"]
#[test]
fn ntfs_mounts_through_the_real_kernel_ntfs3() {
    round_trip(
        "NTFS",
        &Filesystem::Ntfs,
        &Formatter {
            program: "mkntfs",
            flags: &["-F", "-q"],
            package: "ntfsprogs",
        },
    );
}
