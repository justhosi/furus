//! The device facts S04 harvests from sysfs and the udev data records.
//!
//! [`Device`] mirrors what Rufus shows in its device combo box plus what
//! later slices need: S05 recomputes the safety verdict from the sysfs
//! paths, the S06 plan carries the serial/sysfs identity and the S24a GUI
//! renders the human fields. The field names are fixed by PLAN §9-S04 —
//! keep them when adding anything, so plan devices, configs and the
//! parity ledger stay comparable across slices.

use serde::Serialize;

/// Bus transport, classified from the resolved sysfs path (never probed).
///
/// Discovery only needs to answer two questions reliably: "is this a USB
/// stick?" ([`usb`](Device::usb)) and "what should the label say?".
/// The transport chain is visible in the kernel device tree path, e.g.
/// `.../usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0/block/sdb`, so the
/// classification is best-effort by design and exotic buses land in
/// [`Transport::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// USB mass storage — the media Rufus exists for.
    Usb,
    /// SATA/SCSI-attached disk (device path through `ataN`/`hostM`).
    Sata,
    /// NVMe namespace on a controller device.
    Nvme,
    /// MMC/SD storage (`mmcblk*` under an `mmc` controller path).
    Mmc,
    /// Virtual disk (virtio and friends); never a candidate, even with
    /// show-all — [`filter`](crate::sysfs::filter) drops it
    /// unconditionally (PLAN §9) — but still enumerated so `--sysfs-root`
    /// fixtures and container plateaus stay truthful.
    Virtual,
    /// A real block device whose transport matches no known marker.
    Other,
    /// No `device` link: nothing to classify from.
    Unknown,
}

impl Transport {
    /// Lowercase tag, identical to the serialized JSON tag above
    /// (`"usb"`, `"sata"`, ...), so human CLI output never drifts from
    /// the machine-readable form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Usb => "usb",
            Transport::Sata => "sata",
            Transport::Nvme => "nvme",
            Transport::Mmc => "mmc",
            Transport::Virtual => "virtual",
            Transport::Other => "other",
            Transport::Unknown => "unknown",
        }
    }
}

/// One partition directory of an enumerated disk.
///
/// S04 lists these straight from sysfs; S05 re-derives the authoritative
/// table (start, type, flags) from the device itself. Keeping the S04
/// view distinct keeps discovery pure read-only sysfs work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    /// Kernel name (== sysfs directory name), e.g. `sdb1`.
    pub name: String,
    /// Partition number parsed from a plain-digit suffix (`sdb1` → 1).
    /// `None` for `p`-separated suffixes (`nvme0n1p1`) where the base/
    /// partition split is ambiguous; the entry is still published because
    /// S05 reads the table itself anyway.
    pub number: Option<u32>,
    /// Capacity in bytes (sysfs `size` is in 512-byte units).
    pub size_bytes: u64,
    /// `ID_FS_TYPE` from the udev data record (`"vfat"`, `"iso9660"`,
    /// ...), `None` when udev has no record or no filesystem.
    pub fstype: Option<String>,
}

/// A block device as discovered from sysfs + udev data (S04).
///
/// Field order is publish-facing: the CLI `--json` output serialises this
/// structure verbatim, so any reorder is a JSON-visible change and must
/// be deliberate. The fields S05 needs that discovery cannot honestly
/// fill in this slice (`partition_table` from the helper, mount state)
/// stay out of this type on purpose — [`sysfs`](crate::sysfs) does not
/// read block devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    /// Canonical sysfs path of the device directory, e.g.
    /// `<root>/class/block/sdb`. Stable within one root; *not* the stable
    /// config key — see [`Device::identity`].
    pub sysfs: String,
    /// Kernel name, e.g. `sdb` (the sysfs directory name).
    pub name: String,
    /// Device node path, e.g. `/dev/sdb`.
    ///
    /// `/dev/<name>` is used instead of the udev `DEVNAME` link: for
    /// whole disks the kernel names match 1:1, and reading udev
    /// `S:` symlinks would need a second record pass for no benefit in
    /// S04.
    pub dev_path: String,
    /// Capacity in bytes; `0` when sysfs has no readable `size`.
    pub size_bytes: u64,
    /// Logical block size; `512` when `queue/logical_block_size` is
    /// missing or unreadable (the kernel default for rotational media).
    pub sector_size: u32,
    /// Physical block size; falls back to [`sector_size`](Device::sector_size)
    /// when the attribute is missing, because none of the S04 consumers
    /// do offset math with it.
    pub physical_sector_size: u32,
    /// Card-removable flag from sysfs (`removable` attribute).
    pub removable: bool,
    /// Write-protected flag from sysfs (`ro` attribute).
    pub read_only: bool,
    /// `true` only when the transport chain is USB — the core
    /// "show USB sticks" filter depends on this.
    pub usb: bool,
    /// `device/vendor` text, `None` when absent (common on cheap sticks).
    pub vendor: Option<String>,
    /// `device/model` text, `None` when absent.
    pub model: Option<String>,
    /// Stable serial from sysfs or udev (`ID_SERIAL_SHORT`), `None` when
    /// the device has none.
    pub serial: Option<String>,
    /// Best-effort transport classification (see [`Transport`]).
    pub transport: Transport,
    /// `ID_PART_TABLE_TYPE` (e.g. `"dos"`, `"gpt"`), `None` when udev
    /// gives no answer; S05 re-reads the table itself.
    pub partition_table: Option<String>,
    /// USB `vid:pid`, e.g. `"0781:5583"`, from the sysfs USB device node
    /// or the udev `ID_VENDOR_ID`/`ID_MODEL_ID` pair.
    pub vid_pid: Option<String>,
    /// `ID_PATH` (udev's port chain, e.g.
    /// `pci-0000:00:14.0-usb-0:2:1.0`); distinguishes identical sticks in
    /// different sockets, but changes when the user plugs elsewhere.
    pub port_path: Option<String>,
    /// Partition directories of this disk, ordered by number then name.
    pub partitions: Vec<Partition>,
}

impl Device {
    /// The stable configuration key for this device (PLAN §9-S04).
    ///
    /// Anchors are hardware facts that survive being moved between
    /// sockets and machines: the serial and USB `vid:pid`. The port path
    /// is only joined when an anchor exists — it disambiguates identical
    /// sticks, but never anchors on it, because a port path changes when
    /// the stick moves.
    ///
    /// A device with neither serial nor `vid:pid` is *not* stably
    /// identifiable; the key degrades to `sysfs=<path>` (its position in
    /// the current enumeration) and the S24a GUI must warn that the
    /// user's per-device settings will not follow it around.
    #[must_use]
    pub fn identity(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(serial) = &self.serial {
            parts.push(format!("serial={serial}"));
        }
        if let Some(vid_pid) = &self.vid_pid {
            parts.push(format!("vidpid={vid_pid}"));
        }
        // The port path is a disambiguator, never an anchor: only join it
        // when at least one stable anchor exists.
        if (self.serial.is_some() || self.vid_pid.is_some())
            && let Some(port_path) = &self.port_path
        {
            parts.push(format!("path={port_path}"));
        }
        if parts.is_empty() {
            format!("sysfs={}", self.sysfs)
        } else {
            parts.join("|")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Device;
    use super::Partition;
    use super::Transport;

    /// Bare device with all interesting variants in place.
    fn sample() -> Device {
        Device {
            sysfs: "/sys/class/block/sdb".to_string(),
            name: "sdb".to_string(),
            dev_path: "/dev/sdb".to_string(),
            size_bytes: 31_103_926_272,
            sector_size: 512,
            physical_sector_size: 512,
            removable: true,
            read_only: false,
            usb: true,
            vendor: Some("SanDisk".to_string()),
            model: Some("Extreme".to_string()),
            serial: Some("4C530001120202116584".to_string()),
            transport: Transport::Usb,
            partition_table: Some("dos".to_string()),
            vid_pid: Some("0781:5583".to_string()),
            port_path: Some("pci-0000:00:14.0-usb-0:2:1.0".to_string()),
            partitions: vec![Partition {
                name: "sdb1".to_string(),
                number: Some(1),
                size_bytes: 23_750_025_472,
                fstype: Some("vfat".to_string()),
            }],
        }
    }

    #[test]
    fn identity_anchors_and_joins_disambiguators() {
        let device = sample();
        assert_eq!(
            device.identity(),
            "serial=4C530001120202116584|vidpid=0781:5583|path=pci-0000:00:14.0-usb-0:2:1.0",
        );

        // A serial alone is a valid anchor; the port path still rides along.
        let serial_only = sample();
        let mut device = serial_only;
        device.vid_pid = None;
        assert_eq!(
            device.identity(),
            "serial=4C530001120202116584|path=pci-0000:00:14.0-usb-0:2:1.0",
        );
    }

    #[test]
    fn identity_without_anchors_falls_back_to_sysfs_position() {
        let mut device = sample();
        device.serial = None;
        device.vid_pid = None;
        assert_eq!(device.identity(), "sysfs=/sys/class/block/sdb");
    }

    #[test]
    fn transport_tags_match_json_names() {
        for (transport, tag) in [
            (Transport::Usb, "usb"),
            (Transport::Sata, "sata"),
            (Transport::Nvme, "nvme"),
            (Transport::Mmc, "mmc"),
            (Transport::Virtual, "virtual"),
            (Transport::Other, "other"),
            (Transport::Unknown, "unknown"),
        ] {
            // The human tag and the serde `rename_all = "snake_case"`
            // JSON tag are the same spelling; the actual wire output is
            // pinned by the CLI's `list --json` test
            // `list_json_matches_the_default_filter`.
            assert_eq!(transport.as_str(), tag, "{transport:?} tag");
        }
    }
}
