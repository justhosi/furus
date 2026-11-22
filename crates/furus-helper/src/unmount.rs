//! Safe host unmount of removable media before namespace isolation (S35.2b).
//!
//! Fast validation ([`crate::validate::validate`]) deliberately tolerates an
//! ordinary mount on removable media because *this* module owns the unmount
//! step. It runs in the **host** mount namespace, before the worker enters
//! the private namespace: a mount the host made must be released on the
//! host, where the kernel still knows it. Only after every matching
//! mountpoint is gone does the strict re-check
//! ([`crate::validate::recheck_strict`]) re-read mountinfo and refuse if
//! anything is still mounted.
//!
//! # Two seams
//!
//! * [`Unmounter`] is the injectable step used by both entry points. The
//!   argv path and the D-Bus service use [`LiveUnmounter`]; the D-Bus unit
//!   fixtures use a stub that performs no syscalls (the plan env carries
//!   no real mounts).
//! * [`MountOps`](furus_linux::mount::MountOps) stays the syscall boundary.
//!   [`unmount_device_mounts`] owns the *policy* — devnum matching,
//!   deepest-first ordering, fail-closed protection check, `detach = false`
//!   and the per-unmount log — against any `&mut dyn MountOps`, so all of
//!   it is testable without root or a real block device.
//!
//! Nothing here touches the device: this is mount-table work only. The
//! streamed digest verification that must precede any device write is a
//! later slice (S35.3); this step only releases mounts.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use furus_core::safety::is_protected_mountpoint;
use furus_core::text::device_text;
use furus_linux::Device;
use furus_linux::MountTable;
use furus_linux::SysfsRoot;
use furus_linux::mount::LiveOps;
use furus_linux::mount::MountOps;
use furus_linux::mounts::DevNum;
use furus_linux::mounts::dev_number;
use furus_proto::Event;
use furus_proto::LogLevel;
use furus_proto::LogLine;

use crate::progress::ProgressSink;
use crate::validate::Env;

/// How the host-unmount step ended. `protected_path` marks the single
/// fail-closed case that is a *safety refusal* (`Outcome::Refused`); every
/// other failure is an I/O/environment failure (`Outcome::Failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmountRefusal {
    /// Stable machine-readable class (`"protected_mount"`, `"busy"`,
    /// `"unmount_io"`, `"unreadable"`).
    pub code: String,
    /// One ASCII sentence for the human.
    pub message: String,
    /// `true` only for the protected-system-path refusal.
    pub protected_path: bool,
}

/// The injectable host-unmount seam. `Send + Sync` because the D-Bus
/// worker owns one on its own thread through an `Arc`, exactly like its
/// `PlanRunner`.
pub trait Unmounter: Send + Sync {
    /// Release every mount of `device` in the host namespace, emitting one
    /// Info log per successful unmount. `session` is the run id echoed in
    /// those log lines.
    fn unmount(
        &self,
        device: &Device,
        env: &Env,
        sink: &mut dyn ProgressSink,
        session: &str,
    ) -> Result<(), UnmountRefusal>;
}

/// The production [`Unmounter`]: reads the host mount table (`env.mountinfo`
/// is `None` in production, so the real `/proc/self/mountinfo`) and
/// unmounts through [`LiveOps`] with `detach = false` — never a lazy
/// detach: a busy mount is a hard failure the caller must resolve.
pub struct LiveUnmounter;

impl Unmounter for LiveUnmounter {
    fn unmount(
        &self,
        device: &Device,
        env: &Env,
        sink: &mut dyn ProgressSink,
        session: &str,
    ) -> Result<(), UnmountRefusal> {
        let table =
            MountTable::read(env.mountinfo.as_deref()).map_err(|source| UnmountRefusal {
                code: "unreadable".to_string(),
                message: device_text(&format!("the mount table cannot be read: {source}")),
                protected_path: false,
            })?;
        let mut ops = LiveOps;
        unmount_device_mounts(&mut ops, device, &env.sysfs, &table, sink, session)
    }
}

/// Device numbers of the whole disk and every one of its partitions.
///
/// A missing or unparseable sysfs `dev` attribute degrades to "no device
/// number" (mirroring `inspect::devnum_or_warning`): cheap readers and
/// fixtures omit it freely. A real I/O error is different — it would read
/// as "nothing is mounted" and fail open — so it is a clean rejection.
fn collect_devnums(sysfs: &SysfsRoot, device: &Device) -> Result<Vec<DevNum>, UnmountRefusal> {
    let mut devnums = Vec::with_capacity(1 + device.partitions.len());
    let mut names = vec![device.name.clone()];
    names.extend(device.partitions.iter().map(|part| part.name.clone()));
    for name in names {
        match dev_number(sysfs, &name) {
            Ok(Some(devnum)) => devnums.push(devnum),
            Ok(None) => {}
            Err(err) => {
                return Err(UnmountRefusal {
                    code: "unreadable".to_string(),
                    message: device_text(&format!(
                        "cannot read the device number of {name}: {err}"
                    )),
                    protected_path: false,
                });
            }
        }
    }
    Ok(devnums)
}

/// Boundary-aware component count of a mountpoint. `/media/usb` is 2 deep,
/// `/media/usb/stick` is 3: a nested mount must come off before its parent.
fn path_depth(path: &str) -> usize {
    path.split('/').filter(|part| !part.is_empty()).count()
}

/// Every mountpoint in `table` whose device number belongs to the disk or
/// one of its partitions, deduplicated and sorted **deepest first**.
///
/// All entries are scanned (not just the first per devnum — `mount_of`
/// would hide a second mount), so a device mounted twice is fully swept.
/// The sort is deterministic: depth descending, then length descending,
/// then lexicographic (the `BTreeSet` order) for ties.
fn collect_mountpoints(table: &MountTable, devnums: &[DevNum]) -> Vec<String> {
    let mut unique = BTreeSet::new();
    for entry in table.entries() {
        if devnums.contains(&entry.devnum()) {
            unique.insert(entry.mountpoint.clone());
        }
    }
    let mut paths: Vec<String> = unique.into_iter().collect();
    paths.sort_by(|a, b| {
        path_depth(b)
            .cmp(&path_depth(a))
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| a.cmp(b))
    });
    paths
}

/// `EBUSY` is `io::ErrorKind::ResourceBusy` through std, but a stub (or a
/// different syscall wrapper) may surface the raw errno instead, so check
/// both against rustix's pinned constant.
fn is_busy(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::ResourceBusy
        || err.raw_os_error() == Some(rustix::io::Errno::BUSY.raw_os_error())
}

/// The host-unmount policy against any syscall backend. See the module
/// header for the two seams this sits between.
pub fn unmount_device_mounts(
    ops: &mut dyn MountOps,
    device: &Device,
    sysfs: &SysfsRoot,
    table: &MountTable,
    sink: &mut dyn ProgressSink,
    session: &str,
) -> Result<(), UnmountRefusal> {
    let devnums = collect_devnums(sysfs, device)?;
    let mountpoints = collect_mountpoints(table, &devnums);

    // Fail closed BEFORE touching anything. The fast-validation policy
    // already protects the *first* mount, but a device can be mounted
    // twice with the protected one second — check every path here, and
    // refuse the whole step if any of them is a system path.
    for path in &mountpoints {
        if is_protected_mountpoint(path) {
            return Err(UnmountRefusal {
                code: "protected_mount".to_string(),
                message: device_text(&format!(
                    "refusing to unmount {path}: it is a protected system path - unmount it manually and rebuild the plan"
                )),
                protected_path: true,
            });
        }
    }

    for path in &mountpoints {
        let target = Path::new(path);
        match ops.unmount(target, false) {
            Ok(()) => sink.event(&Event::Log(LogLine {
                session: session.to_string(),
                level: LogLevel::Info,
                message: device_text(&format!("Unmounted {path}")),
            })),
            Err(err) => {
                let busy = is_busy(&err);
                let message = if busy {
                    format!(
                        "cannot unmount {path}: device is busy - close open files or terminals using this drive and try again"
                    )
                } else {
                    format!("cannot unmount {path}: {err}")
                };
                return Err(UnmountRefusal {
                    code: if busy { "busy" } else { "unmount_io" }.to_string(),
                    message: device_text(&message),
                    protected_path: false,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::path::PathBuf;

    use furus_linux::Device;
    use furus_linux::MountTable;
    use furus_linux::Partition;
    use furus_linux::SysfsRoot;
    use furus_linux::Transport;
    use furus_linux::mount::MountOps;
    use furus_proto::Event;
    use furus_proto::LogLevel;

    use crate::progress::VecSink;

    use super::UnmountRefusal;
    use super::path_depth;
    use super::unmount_device_mounts;

    /// The stub syscall boundary: records every call and can be told to
    /// fail specific targets with `EBUSY` (by kind or raw errno), a hard
    /// I/O error, or to refuse a devnum sysfs read.
    #[derive(Default)]
    struct FakeOps {
        calls: Vec<(String, bool)>,
        busy_kind: Vec<String>,
        busy_errno: Vec<String>,
        hard_fail: Vec<String>,
    }

    impl MountOps for FakeOps {
        fn mount(
            &mut self,
            _source: &Path,
            _target: &Path,
            _fstype: Option<&str>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn unmount(&mut self, target: &Path, detach: bool) -> io::Result<()> {
            let name = target.display().to_string();
            self.calls.push((name.clone(), detach));
            if self.hard_fail.contains(&name) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
            }
            if self.busy_kind.contains(&name) {
                return Err(io::Error::from(io::ErrorKind::ResourceBusy));
            }
            if self.busy_errno.contains(&name) {
                return Err(io::Error::from_raw_os_error(
                    rustix::io::Errno::BUSY.raw_os_error(),
                ));
            }
            Ok(())
        }
    }

    /// A synthetic sysfs tree with just the `class/block/<name>/dev`
    /// attributes the devnum lookup needs.
    struct SysfsFixture {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl SysfsFixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Self {
                _scratch: scratch,
                root,
            }
        }

        fn seed(&self, name: &str, dev: &str) {
            let dir = self.root.join("class").join("block").join(name);
            fs::create_dir_all(&dir).expect("sysfs class dir");
            fs::write(dir.join("dev"), dev).expect("sysfs dev attribute");
        }

        fn sysfs(&self) -> SysfsRoot {
            SysfsRoot::new(self.root.clone())
        }
    }

    /// A stick with one partition, matching the repo's other fixtures.
    fn device() -> Device {
        Device {
            sysfs: "/sys/class/block/sdb".to_string(),
            name: "sdb".to_string(),
            dev_path: "/dev/sdb".to_string(),
            size_bytes: 4 * 1024 * 1024,
            sector_size: 512,
            physical_sector_size: 512,
            removable: true,
            read_only: false,
            usb: true,
            vendor: None,
            model: None,
            serial: None,
            transport: Transport::Usb,
            partition_table: None,
            vid_pid: None,
            port_path: None,
            partitions: vec![Partition {
                name: "sdb1".to_string(),
                number: Some(1),
                size_bytes: 3 * 1024 * 1024,
                fstype: Some("vfat".to_string()),
            }],
        }
    }

    fn table(lines: &str) -> MountTable {
        MountTable::parse(lines).expect("fixture mountinfo parses")
    }

    fn line(mountpoint: &str, majmin: &str) -> String {
        format!("30 1 {majmin} / {mountpoint} rw,relatime - vfat /dev/src rw")
    }

    fn seeded_sysfs() -> SysfsFixture {
        let fixture = SysfsFixture::new();
        fixture.seed("sdb", "8:16");
        fixture.seed("sdb1", "8:17");
        fixture
    }

    // -- selection and ordering -----------------------------------------

    #[test]
    fn path_depth_counts_boundary_aware_components() {
        assert_eq!(path_depth("/"), 0);
        assert_eq!(path_depth("/media"), 1);
        assert_eq!(path_depth("/media/usb"), 2);
        assert_eq!(path_depth("/media/usb/stick"), 3);
    }

    #[test]
    fn selects_all_mounts_of_disk_and_partitions_not_just_the_first() {
        let sysfs = seeded_sysfs();
        // The disk has two mounts and the partition one; all three must
        // be collected (mount_of would only see the first per devnum).
        let table = table(&format!(
            "{}\n{}\n{}\n{}\n",
            line("/media/disk-one", "8:16"),
            line("/media/foreign", "252:0"),
            line("/media/disk-two", "8:16"),
            line("/run/media/part", "8:17"),
        ));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect("ordinary mounts unmount cleanly");

        assert_eq!(
            ops.calls
                .iter()
                .map(|(path, detach)| (path.as_str(), *detach))
                .collect::<Vec<_>>(),
            vec![
                // Deepest-first: /run/media/part (3 components) precedes
                // the two /media/disk-* mounts (2 components each).
                ("/run/media/part", false),
                ("/media/disk-one", false),
                ("/media/disk-two", false),
            ],
            "both disk mounts and the partition mount, never the foreign one"
        );
    }

    #[test]
    fn unmounts_deepest_path_first_and_deduplicates() {
        let sysfs = seeded_sysfs();
        let table = table(&format!(
            "{}\n{}\n{}\n{}\n",
            line("/media/usb", "8:16"),
            line("/media/usb/stick", "8:17"),
            line("/media/usb/stick", "8:16"), // duplicate path, other devnum
            line("/media/usb/stick/deep", "8:17"),
        ));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect("ordinary mounts unmount cleanly");

        assert_eq!(
            ops.calls
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            vec!["/media/usb/stick/deep", "/media/usb/stick", "/media/usb",],
            "nested first, duplicate removed, no detach"
        );
        assert!(
            ops.calls.iter().all(|(_, detach)| !*detach),
            "host unmount never uses MNT_DETACH"
        );
    }

    #[test]
    fn absent_dev_attribute_degrades_to_no_mounts() {
        // A partition without a `dev` attribute is simply skipped; a
        // disk mount still unmounts.
        let sysfs = SysfsFixture::new();
        sysfs.seed("sdb", "8:16");
        sysfs.seed("sdb1", "not-a-devnum");
        let table = table(&format!(
            "{}\n{}\n",
            line("/media/disk", "8:16"),
            line("/media/part", "8:17"),
        ));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect("an unparseable sysfs dev degrades quietly");
        assert_eq!(
            ops.calls
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            vec!["/media/disk"],
            "the partition's mount is not matched without a devnum"
        );
    }

    // -- fail closed -----------------------------------------------------

    #[test]
    fn a_protected_mount_refuses_before_any_unmount() {
        let sysfs = seeded_sysfs();
        // First mount is ordinary (fast validation would accept it), the
        // second is protected: the unmount step must still catch it and
        // touch nothing.
        let table = table(&format!(
            "{}\n{}\n",
            line("/media/usb", "8:16"),
            line("/home", "8:17"),
        ));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        let refusal = unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect_err("a protected system path is refused");

        assert_eq!(
            refusal,
            UnmountRefusal {
                code: "protected_mount".to_string(),
                message: refusal.message.clone(),
                protected_path: true,
            }
        );
        assert!(refusal.message.contains("/home"));
        assert!(refusal.message.is_ascii(), "{:?}", refusal.message);
        assert!(ops.calls.is_empty(), "nothing was unmounted on refusal");
        assert!(sink.events().is_empty(), "no success log on refusal");
    }

    #[test]
    fn unreadable_sysfs_dev_is_a_clean_rejection() {
        // A sysfs entry whose `dev` is a directory cannot be read as a
        // file: that is a real I/O error, not an absent attribute.
        let sysfs = SysfsFixture::new();
        sysfs.seed("sdb", "8:16");
        let dev_dir = sysfs.root.join("class/block/sdb1/dev");
        fs::create_dir_all(&dev_dir).expect("a directory where `dev` should be a file");
        let table = table(&line("/media/disk", "8:16"));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        let refusal = unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect_err("an unreadable dev attribute refuses");
        assert_eq!(refusal.code, "unreadable");
        assert!(!refusal.protected_path);
        assert!(ops.calls.is_empty());
    }

    // -- busy / I/O errors ----------------------------------------------

    #[test]
    fn a_busy_mount_gives_the_guided_ascii_message_and_stops() {
        for (label, busy_kind, busy_errno) in [
            ("by kind", vec!["/media/a".to_string()], vec![]),
            ("by raw errno", vec![], vec!["/media/a".to_string()]),
        ] {
            let sysfs = seeded_sysfs();
            let table = table(&format!(
                "{}\n{}\n",
                line("/media/a", "8:16"),
                line("/media/b", "8:17"),
            ));
            let mut ops = FakeOps {
                busy_kind,
                busy_errno,
                ..FakeOps::default()
            };
            let mut sink = VecSink::new();
            let refusal = unmount_device_mounts(
                &mut ops,
                &device(),
                &sysfs.sysfs(),
                &table,
                &mut sink,
                "sess",
            )
            .expect_err("a busy mount refuses");
            assert_eq!(refusal.code, "busy", "{label}");
            assert_eq!(
                refusal.message,
                "cannot unmount /media/a: device is busy - close open files or terminals using this drive and try again",
                "{label}"
            );
            assert!(refusal.message.is_ascii(), "{label}");
            assert_eq!(
                ops.calls
                    .iter()
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>(),
                vec!["/media/a"],
                "the sweep stops at the busy mount: {label}"
            );
        }
    }

    #[test]
    fn a_hard_io_error_gives_a_sanitized_message() {
        let sysfs = seeded_sysfs();
        let table = table(&line("/media/a", "8:16"));
        let mut ops = FakeOps {
            hard_fail: vec!["/media/a".to_string()],
            ..FakeOps::default()
        };
        let mut sink = VecSink::new();
        let refusal = unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "sess",
        )
        .expect_err("a hard I/O failure refuses");
        assert_eq!(refusal.code, "unmount_io");
        assert!(
            refusal.message.contains("cannot unmount /media/a"),
            "{}",
            refusal.message
        );
        assert!(refusal.message.is_ascii());
        assert!(!refusal.protected_path);
    }

    // -- logging ---------------------------------------------------------

    #[test]
    fn each_success_emits_one_sanitized_info_log() {
        let sysfs = seeded_sysfs();
        let table = table(&format!(
            "{}\n{}\n",
            line("/media/usb/stick", "8:17"),
            line("/media/usb", "8:16"),
        ));
        let mut ops = FakeOps::default();
        let mut sink = VecSink::new();
        unmount_device_mounts(
            &mut ops,
            &device(),
            &sysfs.sysfs(),
            &table,
            &mut sink,
            "my-session",
        )
        .expect("ordinary mounts unmount cleanly");

        let logs: Vec<(String, String)> = sink
            .events()
            .iter()
            .filter_map(|event| match event {
                Event::Log(line) => Some((line.level.as_str().to_string(), line.message.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            logs,
            vec![
                (
                    LogLevel::Info.as_str().to_string(),
                    "Unmounted /media/usb/stick".to_string()
                ),
                (
                    LogLevel::Info.as_str().to_string(),
                    "Unmounted /media/usb".to_string()
                ),
            ],
            "one info log per successful unmount, in unmount order"
        );
    }
}
