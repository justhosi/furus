//! Device discovery from sysfs and the udev data records (S04).
//!
//! Rufus on Windows builds its removable-media device list from the
//! setup API; the Linux rewrite reads the same facts from
//! `<sysfs-root>/class/block` plus the matching udev data records. This
//! module owns the discovery half: where to read ([`SysfsRoot`]), what
//! the disks look like ([`enumerate`]) and which ones are write
//! candidates ([`filter`]).
//!
//! Two invariants make every later slice testable without hardware:
//!
//! * a fixture tree is self-contained — [`SysfsRoot::new`] points at
//!   `/run/udev/data` only when the root *is* the live `/sys`; every
//!   other root keeps its udev records under `<root>/run/udev/data`, so
//!   no test ever reads the host's real state;
//! * a missing attribute is normal, not an error — real devices
//!   frequently omit `device/serial` and cheap readers omit whole
//!   `device/` subtrees, so absent facts map to `None`/defaults. Only an
//!   unreadable `class/block` itself is an error (the caller cannot know
//!   what world it is looking at).
//!
//! # Size units
//!
//! The sysfs `size` attribute counts **512-byte units regardless of the
//! logical block size** (long-standing kernel contract); every byte size
//! this module produces is therefore `units * 512`.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::text::device_text;

use crate::model::Device;
use crate::model::Partition;
use crate::model::Transport;
use crate::udev_db;

/// Sysfs `size` unit — one attribute unit is exactly this many bytes,
/// whatever the disk's logical block size is (see the module header).
const SIZE_UNIT: u64 = 512;
/// Sector size fallback when `queue/logical_block_size` is unreadable
/// (the kernel default for rotational media).
const DEFAULT_SECTOR: u32 = 512;

/// Where discovery reads from: a sysfs root plus the udev data directory
/// that belongs to it.
///
/// The pairing exists so a fixture tree `/tmp/.../sys` can carry its own
/// record directory instead of racing the host's live `/run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysfsRoot {
    /// sysfs root, normally `/sys`.
    pub root: PathBuf,
    /// Directory holding `b<major>:<minor>` records. `/run/udev/data`
    /// under the live `/sys`, `<root>/run/udev/data` otherwise so a
    /// fixture is self-contained.
    pub udev_data: PathBuf,
}

impl SysfsRoot {
    /// Build the root/records pair for `root`.
    ///
    /// `root == /sys` keeps the live record directory `/run/udev/data`
    /// (the real layout); any other root keeps the records inside
    /// `<root>/run/udev/data`, so tests and containers stay
    /// self-contained.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let udev_data = if root == Path::new("/sys") {
            PathBuf::from("/run/udev/data")
        } else {
            root.join("run").join("udev").join("data")
        };
        Self { root, udev_data }
    }

    /// Build the pair with an explicit record directory (tests override
    /// the default layout).
    #[must_use]
    pub fn with_udev(root: impl Into<PathBuf>, udev_data: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            udev_data: udev_data.into(),
        }
    }

    /// The block-class directory this root serves. `pub(crate)` because
    /// [`crate::watch`] watches the very same directory.
    pub(crate) fn class_block(&self) -> PathBuf {
        self.root.join("class").join("block")
    }
}

/// Enumerate every whole disk beneath `<root>/class/block`.
///
/// Only directories are devices (symlinks count — `fs::metadata`
/// follows them — while attribute files and vanished entries are
/// skipped). Partition siblings (`<name>` with a `partition` attribute,
/// e.g. `sdb1` next to `sdb` on a live kernel) are skipped here — they
/// surface through [`partitions_of`] inside their whole disk instead.
/// The result is sorted by kernel name so the CLI, the GUI and
/// the golden diffs never depend on readdir order.
///
/// An unreadable `class/block` is the one fatal outcome here (see the
/// module header); every per-device reading degrades to defaults.
pub fn enumerate(sysfs: &SysfsRoot) -> Result<Vec<Device>> {
    let class_block = sysfs.class_block();
    let names = list_directories(&class_block)?;
    let devices = names
        .iter()
        .filter_map(|name| {
            let dir = class_block.join(name);
            // The walker lands on the class-side path (a symlink on a
            // live sysfs); `is_file` follows it to the real target, so a
            // partition sibling's `partition` attribute is visible here
            // while a whole disk has none.
            if dir.join("partition").is_file() {
                return None;
            }
            Some(device_from_dir(sysfs, name, &dir))
        })
        .collect();
    Ok(devices)
}

/// Sorted kernel names of `dir`'s directory children.
///
/// Children count as devices through [`fs::metadata`], which follows
/// symlinks — `class/block/<name>` is a symlink on a live system — while
/// attribute files are skipped. Undecipherable entries are skipped too:
/// a device tree that races a hotplug must not fail the whole list.
fn list_directories(dir: &Path) -> Result<Vec<String>> {
    let entries = fs::read_dir(dir).map_err(|err| CoreError::io(dir, err))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            // A child that cannot even be stated: skip, never fatal.
            Err(_) => continue,
        };
        match fs::metadata(entry.path()) {
            Ok(meta) if meta.is_dir() => {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            // A file, a dangling link, or an entry that vanished on the
            // way out: none of them is a device.
            _ => {}
        }
    }
    names.sort();
    Ok(names)
}

/// Read an attribute file as trimmed, sanitised text (`None` when
/// missing, empty or unreadable — a real `device/serial` may hold odd
/// bytes, hence lossy; the trim + neutralisation rule lives in
/// [`rufus_core::text::device_text`], the one sanitiser every module
/// shares). Device strings are untrusted from *both* sources, so the
/// sanitiser applied here is the same one the udev merge applies below.
fn attr_text(path: &Path) -> Option<String> {
    let raw = fs::read(path).ok()?;
    let clean = device_text(&String::from_utf8_lossy(&raw));
    if clean.is_empty() { None } else { Some(clean) }
}

/// Parse a whole-number attribute such as `size` (512-byte units).
fn attr_u64(path: &Path) -> Option<u64> {
    attr_text(path)?.parse().ok()
}

/// Parse a block-size attribute, rejecting `0` so a bogus value cannot
/// poison the offset arithmetic downstream.
fn attr_block_size(path: &Path) -> Option<u32> {
    attr_u64(path)?.try_into().ok().filter(|size| *size > 0)
}

/// `KEY` from a record as an owned string; see [`udev_db::read_record`].
///
/// Record values are as untrusted as sysfs attribute bytes and go
/// through the same sanitiser, [`rufus_core::text::device_text`]: the
/// merge *overwrites* the cleaned sysfs facts, so a raw record value here
/// would bypass the rule that the attribute path already applied.
fn lookup(record: &Option<udev_db::UdevRecord>, key: &str) -> Option<String> {
    record
        .as_ref()
        .and_then(|known| known.get(key))
        .map(device_text)
}

/// The partition suffix of `child` under the disk named `base`.
///
/// `sdb1`-style suffixes (plain digits) yield the partition number;
/// `nvme0n1p1`/`mmcblk0p2`-style suffixes (`p` + digits) are listed with
/// number `None`, because the base/partition split is genuinely
/// ambiguous — S05 reads the real table anyway, so a missing number is
/// fine while silently inventing one would not be. Anything else
/// (`sdbextra`, the disk itself, `queue`, `holders`, ...) is not a
/// partition.
fn partition_number(child: &str, base: &str) -> Option<Option<u32>> {
    let suffix = child.strip_prefix(base)?;
    if suffix.is_empty() {
        return None;
    }
    if suffix.bytes().all(|b| b.is_ascii_digit()) {
        // A suffix that parse-fails (more than u32 digits) is treated
        // like any other junk entry: not a partition.
        return suffix.parse::<u32>().ok().map(Some);
    }
    match suffix.strip_prefix('p') {
        Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
            Some(None)
        }
        _ => None,
    }
}

/// Partition subdirectories of the disk directory `dir` (named `name`),
/// unordered; [`device_from_dir`] sorts the finished list per device.
fn partitions_of(sysfs: &SysfsRoot, dir: &Path, name: &str) -> Vec<Partition> {
    // The directory was successfully listed a moment ago, so a failure
    // here is a lost hotplug race: an empty list is the honest degraded
    // answer, and a fatal error would kill the whole enumeration over
    // one vanishing disk.
    let children = list_directories(dir).unwrap_or_default();
    children
        .into_iter()
        .filter_map(|child| {
            let number = partition_number(&child, name)?;
            let directory = dir.join(&child);
            let size_bytes = attr_u64(&directory.join("size"))
                .map(|units| units.saturating_mul(SIZE_UNIT))
                .unwrap_or(0);
            let fstype = attr_text(&directory.join("dev"))
                .and_then(|major_minor| udev_db::read_record(&sysfs.udev_data, &major_minor))
                .and_then(|record| record.get("ID_FS_TYPE").map(device_text));
            Some(Partition {
                name: child,
                number,
                size_bytes,
                fstype,
            })
        })
        .collect()
}

/// Transport classification from the resolved device path (see
/// [`Transport`]: best-effort, never probed).
fn transport_of(resolved: &Path, device_link: &Path) -> Transport {
    // The canonical device path is the kernel's transport chain, e.g.
    // /sys/devices/.../usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0/block/sdb
    let chain = resolved.to_string_lossy();
    if chain.contains("usb") {
        Transport::Usb
    } else if chain.contains("nvme") {
        Transport::Nvme
    } else if chain.contains("mmc") {
        Transport::Mmc
    } else if chain.contains("ata") || chain.contains("host") {
        // ATA (and its SCSI host shim) is what SATA/AHCI controllers
        // publish on every distro kernel of the last decade.
        Transport::Sata
    } else if chain.contains("virtio") || chain.contains("/vd") {
        Transport::Virtual
    } else if device_link.exists() {
        // A real bus we do not recognise; still a physical device.
        Transport::Other
    } else {
        // No device link at all: nothing to classify from.
        Transport::Unknown
    }
}

/// The USB `vid:pid` (e.g. `"0781:5583"`) from the resolved `device`
/// symlink target plus up to four of its ancestors — on USB storage the
/// node carrying `idVendor`/`idProduct` sits four levels above the SCSI
/// device the block device's link points at. `None` when neither the
/// target nor any ancestor carries both files.
fn vid_pid_of(resolved_device: &Path) -> Option<String> {
    let mut current = Some(resolved_device);
    for _ in 0..=4 {
        if let Some(dir) = current {
            if let (Some(vid), Some(pid)) = (
                attr_text(&dir.join("idVendor")),
                attr_text(&dir.join("idProduct")),
            ) {
                return Some(format!("{vid}:{pid}"));
            }
            current = dir.parent();
        }
    }
    None
}

/// Build one [`Device`] from its sysfs directory.
///
/// All attribute reads are best-effort (see the module header); only the
/// `class/block` listing is allowed to fail upstream.
fn device_from_dir(sysfs: &SysfsRoot, name: &str, dir: &Path) -> Device {
    // The canonicalised path is the transport chain on a live system
    // (`/sys/class/block/sdb` is a symlink into `/sys/devices/...`).
    let resolved = fs::canonicalize(dir).unwrap_or_else(|_gone| dir.to_path_buf());
    // Same for the link to the physical `device` node (the vid:pid walk
    // needs its real location, not the class-side shortcut).
    let resolved_device =
        fs::canonicalize(dir.join("device")).unwrap_or_else(|_gone| dir.join("device"));

    let major_minor = attr_text(&dir.join("dev"));
    // The `dev` attribute feeds the `b<major>:<minor>` record filename:
    // reject anything but `digits:digits` before the lookup (the record
    // reader re-checks, this keeps the intent local to the interpolation).
    let record = major_minor
        .as_deref()
        .filter(|dev| udev_db::is_valid_major_minor(dev))
        .and_then(|dev| udev_db::read_record(&sysfs.udev_data, dev));

    let mut device = Device {
        sysfs: dir.display().to_string(),
        name: name.to_string(),
        dev_path: format!("/dev/{name}"),
        // Kernel contract: `size` is in 512-byte units regardless of the
        // logical block size (see the module header). `saturating` keeps
        // a surreal attribute from panicking the arithmetic downstream.
        size_bytes: attr_u64(&dir.join("size"))
            .map(|units| units.saturating_mul(SIZE_UNIT))
            .unwrap_or(0),
        sector_size: attr_block_size(&dir.join("queue").join("logical_block_size"))
            .unwrap_or(DEFAULT_SECTOR),
        // Overwritten below from the (possibly missing) attribute.
        physical_sector_size: DEFAULT_SECTOR,
        removable: attr_u64(&dir.join("removable")) == Some(1),
        read_only: attr_u64(&dir.join("ro")) == Some(1),
        usb: false,
        vendor: attr_text(&dir.join("device").join("vendor")),
        model: attr_text(&dir.join("device").join("model")),
        serial: attr_text(&dir.join("device").join("serial")),
        transport: transport_of(&resolved, &dir.join("device")),
        partition_table: None,
        vid_pid: vid_pid_of(&resolved_device),
        port_path: None,
        partitions: partitions_of(sysfs, dir, name),
    };
    device.usb = device.transport == Transport::Usb;
    // Physical is the logical size whenever the kernel does not say
    // otherwise — the honest fallback for S04 consumers.
    device.physical_sector_size = attr_block_size(&dir.join("queue").join("physical_block_size"))
        .unwrap_or(device.sector_size);

    // Merge the udev record over the plain sysfs facts. The serial only
    // falls back (sysfs knows it just as well); the model is taken from
    // udev when present (it is the more complete string there); the
    // remaining keys answer questions sysfs cannot.
    if device.serial.is_none() {
        device.serial = lookup(&record, "ID_SERIAL_SHORT");
    }
    if let Some(model) = lookup(&record, "ID_MODEL") {
        device.model = Some(model);
    }
    device.partition_table = lookup(&record, "ID_PART_TABLE_TYPE");
    device.port_path = lookup(&record, "ID_PATH");
    if device.vid_pid.is_none() {
        let vid = lookup(&record, "ID_VENDOR_ID");
        let pid = lookup(&record, "ID_MODEL_ID");
        if let (Some(vid), Some(pid)) = (vid, pid) {
            device.vid_pid = Some(format!("{vid}:{pid}"));
        }
    }
    if lookup(&record, "ID_BUS").as_deref() == Some("usb") {
        device.usb = true;
    }

    device
        .partitions
        .sort_by(|a, b| (a.number, a.name.as_str()).cmp(&(b.number, b.name.as_str())));
    device
}

/// Which enumerated devices are write candidates — ANALYSIS.md §6,
/// mirroring Rufus's removable-only default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// Reveal internal fixed disks as well. Whoever turns this on must
    /// surface a destruction warning in the UI/CLI (PLAN §6 rule 4);
    /// this type only keeps the policy in one place.
    pub show_all: bool,
}

/// Apply [`Filter`] to an enumerated list, preserving its order.
///
/// Always removed — never valid targets, whatever the user asks for:
///
/// * zero-size entries: card readers with no card inserted,
/// * `loop*`: loopback mounts — their data vanishes with the mount,
/// * `ram*`: in-kernel RAM disks,
/// * `zram*`: compressed RAM disks (usually swap),
/// * `dm-*`: device-mapper volumes — the disk below them is the real
///   target,
/// * `md*`: md RAID sets — the members are the real targets,
/// * `sr*`: optical CD/DVD drives,
/// * anything with a virtual transport (the virtio bus).
///
/// Everything else is USB or removable by default; `show_all` reveal
/// mode keeps the internal fixed disks on top.
pub fn filter(mut devices: Vec<Device>, filter: Filter) -> Vec<Device> {
    devices.retain(|device| {
        if device.size_bytes == 0
            || device.transport == Transport::Virtual
            || is_builtin_name(&device.name)
        {
            return false;
        }
        filter.show_all || device.usb || device.removable
    });
    devices
}

/// Kernel names that never name real, writable media (see [`filter`]).
///
/// The prefix list lives in `rufus_core::safety::is_builtin_name`, the
/// same rule the final safety verdict applies: a thin wrapper here on
/// purpose, so the S04 discovery filter and the S05 verdict can never
/// drift apart (they must drop the same devices for the same reason).
fn is_builtin_name(name: &str) -> bool {
    rufus_core::safety::is_builtin_name(name)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::CoreError;
    use super::Filter;
    use super::SysfsRoot;
    use super::Transport;
    use super::enumerate;
    use super::filter;

    use crate::model::Device;
    use crate::model::Partition;

    // ------------------------------------------------------------------
    // Fixture helpers: programmatic synthetic sysfs trees, so no binary
    // fixture is ever committed and tests run on hardware-free CI.
    // ------------------------------------------------------------------

    /// A scratch sysfs tree. The `TempDir` handle is deliberately kept:
    /// dropping it would delete the tree mid-test.
    struct Fixture {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Fixture {
                _scratch: scratch,
                root,
            }
        }

        /// The sysfs root as discovery should see it.
        fn sysfs(&self) -> SysfsRoot {
            SysfsRoot::new(self.root.clone())
        }

        /// Write `rel` (creating parent directories) holding `content`.
        fn seed(&self, rel: &str, content: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent dirs");
            }
            fs::write(&path, content).unwrap_or_else(|err| panic!("seed {rel}: {err}"));
        }

        /// Create the empty directory `rel` (with parents).
        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.root.join(rel))
                .unwrap_or_else(|err| panic!("mkdir {rel}: {err}"));
        }

        /// Symlink `class/block/<name>` into the real device-tree path
        /// `real` (both relative to the fixture root), mirroring a live
        /// sysfs where the class entry is a link.
        fn link_disk(&self, name: &str, real: &str) {
            self.mkdir("class/block");
            symlink(
                self.root.join(real),
                self.root.join(format!("class/block/{name}")),
            )
            .unwrap_or_else(|err| panic!("link {name}: {err}"));
        }

        /// Write a udev record body, `E:`-prefixed like a real one.
        fn record(&self, major_minor: &str, pairs: &[(&str, &str)]) {
            let mut text = String::from("I:56732\n");
            for (key, value) in pairs {
                text.push_str("E:");
                text.push_str(key);
                text.push('=');
                text.push_str(value);
                text.push('\n');
            }
            self.seed(&format!("run/udev/data/b{major_minor}"), &text);
        }

        /// A physical disk `name`: attributes under its device-tree path
        /// `mount`, a class symlink to it, optionally a `device/`
        /// subdirectory (classification's physical marker).
        fn seed_class_disk(
            &self,
            name: &str,
            mount: &str,
            units: u64,
            removable: bool,
            with_device_dir: bool,
        ) {
            self.seed(&format!("{mount}/size"), &units.to_string());
            self.seed(
                &format!("{mount}/removable"),
                if removable { "1" } else { "0" },
            );
            self.seed(&format!("{mount}/dev"), "8:0");
            if with_device_dir {
                self.mkdir(&format!("{mount}/device"));
            }
            self.link_disk(name, mount);
        }

        /// Seed a fully-populated USB stick `name`: attributes, one
        /// partition (`<name>1`, 59 units, `vfat`), the four-up USB
        /// device node ids and matching udev records. Reference fixture
        /// for field mapping and identity stability.
        fn seed_usb_stick(&self, name: &str, units: u64) {
            let chain = "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0";
            let real = format!("{chain}/block/{name}");
            self.seed(&format!("{real}/size"), &units.to_string());
            self.seed(&format!("{real}/removable"), "1");
            self.seed(&format!("{real}/ro"), "0");
            self.seed(&format!("{real}/dev"), "8:16");
            self.seed(&format!("{real}/queue/logical_block_size"), "512");
            self.seed(&format!("{real}/queue/physical_block_size"), "512");
            // The `device` link aims at the SCSI device directory, the
            // place where the disk's vendor/model/serial attributes
            // surface in a live sysfs.
            self.seed(&format!("{chain}/vendor"), "SanDisk");
            self.seed(&format!("{chain}/model"), "Extreme");
            self.seed(&format!("{chain}/serial"), "4C530001120202116584");

            // idVendor/idProduct live on the USB device node, exactly
            // four ancestors above the device link target …/6:0:0:0.
            self.seed("devices/pci/usb1/1-2/idVendor", "0781");
            self.seed("devices/pci/usb1/1-2/idProduct", "5583");

            // Partition 1 and its filesystem record.
            let part = format!("{real}/{name}1");
            self.seed(&format!("{part}/size"), "59");
            self.seed(&format!("{part}/dev"), "8:17");

            self.record(
                "8:16",
                &[
                    ("ID_BUS", "usb"),
                    ("ID_MODEL", "Extreme"),
                    ("ID_PART_TABLE_TYPE", "dos"),
                    ("ID_PATH", "pci-0000:00:14.0-usb-0:2:1.0"),
                    ("ID_VENDOR_ID", "0781"),
                    ("ID_MODEL_ID", "5583"),
                ],
            );
            self.record("8:17", &[("ID_FS_TYPE", "vfat")]);

            self.link_disk(name, &real);
            symlink(
                self.root.join(chain),
                self.root.join(format!("{real}/device")),
            )
            .expect("link device");
        }
    }

    /// Find one enumerated device by kernel name (tests read by name).
    fn by_name<'a>(devices: &'a [Device], name: &str) -> &'a Device {
        devices
            .iter()
            .find(|device| device.name == name)
            .unwrap_or_else(|| panic!("device {name} must be enumerated"))
    }

    // ------------------------------------------------------------------
    // Field mapping
    // ------------------------------------------------------------------

    #[test]
    fn usb_stick_fields_map_completely() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);

        let devices = enumerate(&fixture.sysfs()).expect("fixture enumerates");
        assert_eq!(devices.len(), 1, "exactly the stick was seeded");
        let stick = by_name(&devices, "sdb");

        assert_eq!(
            stick.sysfs,
            format!("{}/class/block/sdb", fixture.root.display())
        );
        assert_eq!(stick.name, "sdb");
        assert_eq!(stick.dev_path, "/dev/sdb");
        assert_eq!(stick.size_bytes, 51_200, "100 x 512-byte units");
        assert_eq!(stick.sector_size, 512);
        assert_eq!(stick.physical_sector_size, 512);
        assert!(stick.removable);
        assert!(!stick.read_only);
        assert!(stick.usb);
        assert_eq!(stick.transport, Transport::Usb);
        assert_eq!(stick.vendor.as_deref(), Some("SanDisk"));
        assert_eq!(stick.model.as_deref(), Some("Extreme"));
        assert_eq!(stick.serial.as_deref(), Some("4C530001120202116584"));
        assert_eq!(stick.partition_table.as_deref(), Some("dos"));
        assert_eq!(stick.vid_pid.as_deref(), Some("0781:5583"));
        assert_eq!(
            stick.port_path.as_deref(),
            Some("pci-0000:00:14.0-usb-0:2:1.0")
        );
        assert_eq!(
            stick.partitions,
            vec![Partition {
                name: "sdb1".to_string(),
                number: Some(1),
                size_bytes: 30_208,
                fstype: Some("vfat".to_string()),
            }],
            "partition attributes map through the 512-byte units too"
        );
        assert_eq!(
            stick.identity(),
            "serial=4C530001120202116584|vidpid=0781:5583|path=pci-0000:00:14.0-usb-0:2:1.0",
        );
    }

    #[test]
    fn size_units_are_512_bytes_even_when_block_size_differs() {
        let fixture = Fixture::new();
        // `size` is 2 units; the logical block size is 4096. The byte
        // size must stay 2 * 512 — sysfs size is unit-based, never
        // sector-based (kernel contract, see the module header).
        fixture.seed("class/block/beefy/size", "2");
        fixture.seed("class/block/beefy/queue/logical_block_size", "4096");
        fixture.seed("class/block/beefy/queue/physical_block_size", "4096");
        fixture.seed("class/block/beefy/removable", "0");
        fixture.seed("class/block/beefy/dev", "7:5");

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "beefy");
        assert_eq!(device.size_bytes, 1024, "units x 512, not units x 4096");
        assert_eq!(device.sector_size, 4096);
        assert_eq!(device.physical_sector_size, 4096);
    }

    #[test]
    fn missing_attributes_degrade_to_defaults_not_errors() {
        let fixture = Fixture::new();
        // Only a `dev` node — no size, queue, device/ tree or records.
        fixture.seed("class/block/bare-disk/dev", "7:1");

        let devices = enumerate(&fixture.sysfs()).expect("a spartan device still lists");
        let device = by_name(&devices, "bare-disk");

        assert_eq!(device.size_bytes, 0);
        assert_eq!(device.sector_size, 512);
        assert_eq!(device.physical_sector_size, 512);
        assert!(!device.removable);
        assert!(!device.read_only);
        assert!(!device.usb);
        assert_eq!(device.vendor, None);
        assert_eq!(device.model, None);
        assert_eq!(device.serial, None);
        assert_eq!(device.transport, Transport::Unknown);
        assert_eq!(device.partition_table, None);
        assert_eq!(device.vid_pid, None);
        assert_eq!(device.port_path, None);
        assert!(device.partitions.is_empty());
        // Without anchors the identity degrades to the sysfs position.
        assert_eq!(device.identity(), format!("sysfs={}", device.sysfs));
    }

    #[test]
    fn device_alias_symlinks_and_files_in_class_block_are_handled() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);
        // Plain attribute file where a device directory would be: not a
        // device, and not a failure.
        fixture.seed("class/block/why.txt", "definitely not a device");

        let devices = enumerate(&fixture.sysfs()).expect("skipping a file is not an error");
        assert_eq!(
            devices.len(),
            1,
            "{:?}",
            devices.iter().map(|d| &d.name).collect::<Vec<_>>()
        );

        // And a completely missing class/block is the one fatal path.
        let empty = Fixture::new();
        let err = enumerate(&empty.sysfs()).expect_err("no class/block");
        assert!(matches!(err, CoreError::Io { .. }), "{err}");
        assert!(err.to_string().contains("class/block"), "{err}");
    }

    // ------------------------------------------------------------------
    // Partitions and sorting
    // ------------------------------------------------------------------

    #[test]
    fn partition_siblings_are_not_top_level_devices() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);
        // Live kernels list partitions as siblings in `class/block`:
        // mirror that layout — the class entry links at the real
        // partition directory, which carries the `partition` attribute.
        fixture.seed(
            "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0/block/sdb/sdb1/partition",
            "1",
        );
        fixture.record("8:17", &[("ID_FS_TYPE", "vfat"), ("ID_BUS", "usb")]);
        fixture.link_disk(
            "sdb1",
            "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0/block/sdb/sdb1",
        );

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        assert_eq!(
            devices.iter().map(|d| &d.name).collect::<Vec<_>>(),
            vec!["sdb"],
            "the sdb1 sibling must not enumerate as a disk"
        );
        let stick = by_name(&devices, "sdb");
        assert_eq!(
            stick.partitions,
            vec![Partition {
                name: "sdb1".to_string(),
                number: Some(1),
                size_bytes: 30_208,
                fstype: Some("vfat".to_string()),
            }],
            "the sibling partition still surfaces inside its disk"
        );
        // A disk must never collide with its own partition as a write
        // candidate, even when the partition record claims a USB bus.
        let mut identities: Vec<String> =
            devices.iter().map(crate::model::Device::identity).collect();
        identities.sort();
        identities.dedup();
        assert_eq!(
            identities.len(),
            devices.len(),
            "no two devices share an identity()"
        );
        let kept = filter(devices, Filter { show_all: false });
        assert_eq!(
            kept.iter().map(|d| &d.name).collect::<Vec<_>>(),
            vec!["sdb"],
            "the partition sibling must not become a write candidate"
        );
    }

    #[test]
    fn plain_digit_partitions_are_numbered_sorted_and_mapped() {
        let fixture = Fixture::new();
        fixture.seed("class/block/sdz/device/placeholder", "");
        fixture.seed("class/block/sdz/size", "100");
        fixture.seed("class/block/sdz/removable", "1");
        fixture.seed("class/block/sdz/dev", "7:0");
        // Seeding deliberately out of order: sorting is discovery's job.
        fixture.seed("class/block/sdz/sdz10/size", "30");
        fixture.seed("class/block/sdz/sdz10/dev", "7:10");
        fixture.seed("class/block/sdz/sdz1/size", "10");
        fixture.seed("class/block/sdz/sdz1/dev", "7:1");
        fixture.seed("class/block/sdz/sdz2/size", "20");
        fixture.seed("class/block/sdz/sdz2/dev", "7:2");
        // Junk: name-based suffix rules must exclude these.
        fixture.seed("class/block/sdz/sdzextra/size", "1");
        fixture.seed("class/block/sdz/queue/physical_block_size", "512");
        fixture.record("7:1", &[("ID_FS_TYPE", "ntfs")]);
        fixture.record("7:10", &[("ID_FS_TYPE", "exfat")]);

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "sdz");
        assert_eq!(
            device.partitions,
            vec![
                Partition {
                    name: "sdz1".to_string(),
                    number: Some(1),
                    size_bytes: 5_120,
                    fstype: Some("ntfs".to_string()),
                },
                Partition {
                    name: "sdz2".to_string(),
                    number: Some(2),
                    size_bytes: 10_240,
                    fstype: None,
                },
                Partition {
                    name: "sdz10".to_string(),
                    number: Some(10),
                    size_bytes: 15_360,
                    fstype: Some("exfat".to_string()),
                },
            ],
            "numbers sort, junk suffixes drop, records fill fstype"
        );
    }

    #[test]
    fn p_suffixed_partitions_are_listed_without_numbers() {
        let fixture = Fixture::new();
        fixture.seed("class/block/mmcblk0/device/placeholder", "");
        fixture.seed("class/block/mmcblk0/size", "100");
        fixture.seed("class/block/mmcblk0/removable", "0");
        fixture.seed("class/block/mmcblk0/dev", "7:20");
        fixture.seed("class/block/mmcblk0/mmcblk0p2/size", "40");
        fixture.seed("class/block/mmcblk0/mmcblk0p2/dev", "7:22");
        fixture.seed("class/block/mmcblk0/mmcblk0p1/size", "20");
        fixture.seed("class/block/mmcblk0/mmcblk0p1/dev", "7:21");

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "mmcblk0");
        assert_eq!(device.transport, Transport::Mmc, "the class name is mmc");
        assert_eq!(
            device.partitions,
            vec![
                Partition {
                    name: "mmcblk0p1".to_string(),
                    number: None,
                    size_bytes: 10_240,
                    fstype: None,
                },
                Partition {
                    name: "mmcblk0p2".to_string(),
                    number: None,
                    size_bytes: 20_480,
                    fstype: None,
                },
            ],
            "p-suffix partitions keep None numbers but real sizes"
        );
    }

    // ------------------------------------------------------------------
    // Transport classification
    // ------------------------------------------------------------------

    #[test]
    fn transport_classification_covers_the_buses() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);
        fixture.seed_class_disk(
            "atom",
            "devices/pci/ata1/host0/target0:0:0/0:0:0:0",
            4096,
            false,
            false,
        );
        fixture.seed_class_disk("nvm", "devices/pci/nvme/nvme0/nvme0n1", 4096, false, false);
        fixture.seed_class_disk(
            "mmcd",
            "devices/soc/mmc_host/mmc0/mmc0:0001",
            4096,
            false,
            false,
        );
        fixture.seed_class_disk("virt", "devices/pci/virtio-pci", 4096, true, false);
        fixture.seed_class_disk(
            "other",
            "devices/platform/odd-chip/other-fabric/unknown-disk",
            4096,
            false,
            true,
        );
        // No link into the device tree: classification is impossible.
        fixture.seed("class/block/bare-disk/dev", "7:1");

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        for (name, want) in [
            ("sdb", Transport::Usb),
            ("atom", Transport::Sata),
            ("nvm", Transport::Nvme),
            ("mmcd", Transport::Mmc),
            ("virt", Transport::Virtual),
            ("other", Transport::Other),
            ("bare-disk", Transport::Unknown),
        ] {
            let device = by_name(&devices, name);
            assert_eq!(device.transport, want, "{name} must classify as {want:?}");
            assert_eq!(
                device.usb,
                want == Transport::Usb,
                "{name}: usb flag follows the transport"
            );
        }
        // The classification order is the enumerate order.
        let mut names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            "enumerate output must be name-sorted"
        );
    }

    // ------------------------------------------------------------------
    // udev record merge
    // ------------------------------------------------------------------

    #[test]
    fn udev_record_fills_missing_facts_and_overrides_model() {
        let fixture = Fixture::new();
        fixture.seed("class/block/flash-stik/size", "2");
        fixture.seed("class/block/flash-stik/removable", "1");
        fixture.seed("class/block/flash-stik/ro", "0");
        fixture.seed("class/block/flash-stik/dev", "7:13");
        fixture.record(
            "7:13",
            &[
                ("ID_BUS", "usb"),
                ("ID_SERIAL_SHORT", "ABC123ABC"),
                ("ID_MODEL", "Recycle-Reader"),
                ("ID_PART_TABLE_TYPE", "gpt"),
                ("ID_PATH", "pci-0000:00:1a.0-scsi-0:0:0:0"),
                ("ID_VENDOR_ID", "0480"),
                ("ID_MODEL_ID", "B001"),
            ],
        );

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "flash-stik");
        // sysfs alone had no serial/model/ids: the record fills them.
        assert_eq!(device.serial.as_deref(), Some("ABC123ABC"));
        assert_eq!(device.model.as_deref(), Some("Recycle-Reader"));
        assert_eq!(device.partition_table.as_deref(), Some("gpt"));
        assert_eq!(
            device.port_path.as_deref(),
            Some("pci-0000:00:1a.0-scsi-0:0:0:0")
        );
        assert_eq!(device.vid_pid.as_deref(), Some("0480:B001"));
        // ID_BUS=usb overrides what the (absent) transport chain knew.
        assert!(device.usb, "ID_BUS=usb makes the stick a candidate");
        assert_eq!(device.transport, Transport::Unknown);
        assert_eq!(device.size_bytes, 1024);
        assert!(device.removable);
        assert!(!device.read_only);
    }

    #[test]
    fn udev_record_strings_are_sanitised_like_sysfs_ones() {
        let fixture = Fixture::new();
        fixture.seed("class/block/evil-disk/size", "100");
        fixture.seed("class/block/evil-disk/removable", "1");
        fixture.seed("class/block/evil-disk/dev", "8:16");
        // Every merged value carries hostile bytes; the sysfs side has
        // none (no device/ tree), so this isolates the record path.
        // Records are line-delimited (`parse` reads `lines()`), so a
        // value can never carry a literal `\n` from the file — the
        // dangerous bytes that reach `lookup` are ESC sequences and
        // control characters, which is also the reviewer's repro.
        fixture.record(
            "8:16",
            &[
                ("ID_MODEL", "EVIL\u{1b}[2Judev-model"),
                ("ID_SERIAL_SHORT", "ser\u{7}ial"),
                ("ID_PATH", "pci-\u{1b}esc"),
                ("ID_PART_TABLE_TYPE", "dos\u{5}"),
                ("ID_VENDOR_ID", "07\u{1}81"),
                ("ID_MODEL_ID", "5583"),
            ],
        );

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "evil-disk");
        let merged = format!(
            "{}|{}|{}|{}|{}",
            device.model.as_deref().unwrap_or(""),
            device.serial.as_deref().unwrap_or(""),
            device.partition_table.as_deref().unwrap_or(""),
            device.port_path.as_deref().unwrap_or(""),
            device.vid_pid.as_deref().unwrap_or(""),
        );
        assert!(
            merged.is_ascii(),
            "record strings must sanitise like sysfs ones: {merged:?}"
        );
        assert!(
            !merged.contains('\u{1b}'),
            "ESC must be neutralised: {merged:?}"
        );
        assert!(
            !merged.contains('\n'),
            "newlines must be neutralised: {merged:?}"
        );
        assert_eq!(device.model.as_deref(), Some("EVIL?[2Judev-model"));
        assert_eq!(device.serial.as_deref(), Some("ser?ial"));
        assert_eq!(device.partition_table.as_deref(), Some("dos?"));
        assert_eq!(device.port_path.as_deref(), Some("pci-?esc"));
        assert_eq!(device.vid_pid.as_deref(), Some("07?81:5583"));
    }

    #[test]
    fn identity_is_stable_across_different_roots() {
        let first = Fixture::new();
        let second = Fixture::new();
        first.seed_usb_stick("sdb", 100);
        second.seed_usb_stick("sdb", 100);

        let a = by_name(&enumerate(&first.sysfs()).expect("a"), "sdb").clone();
        let b = by_name(&enumerate(&second.sysfs()).expect("b"), "sdb").clone();
        assert_ne!(
            a.sysfs, b.sysfs,
            "the two fixtures live under different roots by construction"
        );
        assert_eq!(
            a.identity(),
            b.identity(),
            "serial + vid:pid + port make the identity root-independent"
        );
    }

    // ------------------------------------------------------------------
    // Candidate filter
    // ------------------------------------------------------------------

    #[test]
    fn malformed_dev_attribute_never_reaches_the_record_lookup() {
        let fixture = Fixture::new();
        fixture.seed("class/block/evil/size", "100");
        fixture.seed("class/block/evil/removable", "1");
        fixture.seed("class/block/evil/dev", "not-a-device");
        // A decoy record filed under the raw attribute text must be
        // ignored: only `digits:digits` keys ever hit the filesystem.
        fixture.seed("run/udev/data/bnot-a-device", "I:0\nE:ID_BUS=usb\n");

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let device = by_name(&devices, "evil");
        assert!(!device.usb, "a malformed dev must not merge any record");
        assert_eq!(device.serial, None);
        assert_eq!(device.partition_table, None);
    }

    #[test]
    fn default_filter_keeps_usb_and_removable_only() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);
        // Internal disk: neither USB nor removable.
        fixture.seed_class_disk(
            "sda",
            "devices/pci/ata1/host0/target0:0:0/0:0:0:0",
            4096,
            false,
            false,
        );
        // Card reader with no card: removable but zero-size.
        fixture.seed("class/block/sdd/size", "0");
        fixture.seed("class/block/sdd/removable", "1");
        fixture.seed("class/block/sdd/dev", "8:4");

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let kept = filter(devices, Filter { show_all: false });
        assert_eq!(
            kept.iter().map(|d| &d.name).collect::<Vec<_>>(),
            vec!["sdb"],
            "only the USB stick is a default candidate"
        );
    }

    #[test]
    fn show_all_reveals_fixed_disks_but_builtin_and_virtual_stay_hidden() {
        let fixture = Fixture::new();
        fixture.seed_usb_stick("sdb", 100);
        fixture.seed_class_disk(
            "sda",
            "devices/pci/ata1/host0/target0:0:0/0:0:0:0",
            4096,
            false,
            false,
        );
        // Removable-but-never-targetable names stay hidden even from
        // show-all (each is removable and sized, so the name rule is
        // what removes them).
        for name in ["loop0", "ram0", "zram0", "dm-0", "md0", "sr0"] {
            fixture.seed(&format!("class/block/{name}/size"), "4096");
            fixture.seed(&format!("class/block/{name}/removable"), "1");
        }
        // A virtio disk is virtual regardless of the removable bit.
        fixture.seed_class_disk("vdx", "devices/pci/virtio-pci", 4096, true, false);

        let devices = enumerate(&fixture.sysfs()).expect("enumerate");
        let show_all = filter(devices.clone(), Filter { show_all: true });
        assert_eq!(
            show_all.iter().map(|d| &d.name).collect::<Vec<_>>(),
            vec!["sda", "sdb"],
            "show-all reveals internal disks, still no builtins/virtuals"
        );
        let plain = filter(devices, Filter { show_all: false });
        assert_eq!(
            plain.len(),
            1,
            "{:?}",
            plain.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
        assert_eq!(plain[0].name, "sdb");
    }

    // ------------------------------------------------------------------
    // SysfsRoot pairing
    // ------------------------------------------------------------------

    #[test]
    fn sysfs_root_pairs_the_live_root_with_run_udev_only() {
        // The live root keeps the live record directory…
        let live = SysfsRoot::new("/sys");
        assert_eq!(live.root, PathBuf::from("/sys"));
        assert_eq!(live.udev_data, PathBuf::from("/run/udev/data"));
        // …and every other root is self-contained (fixture-safe).
        let fixture = SysfsRoot::new("/tmp/furus-sysfs-fixture");
        assert_eq!(
            fixture.udev_data,
            PathBuf::from("/tmp/furus-sysfs-fixture/run/udev/data")
        );
        // The explicit override is respected as given.
        let custom = SysfsRoot::with_udev("/tmp/root", "/tmp/records");
        assert_eq!(custom.udev_data, PathBuf::from("/tmp/records"));
    }
}
