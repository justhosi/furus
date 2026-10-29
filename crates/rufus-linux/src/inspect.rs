//! Read-only device sampling: everything the PLAN §6 verdict files (S05).
//!
//! [`inspect`] is the S05 half of the safety story: given one [`Device`]
//! (S04 facts) it opens the device node **readably** — never exclusively,
//! never for writing — and gathers what an erase would destroy. The
//! result is a [`Report`] (publish-facing facts: table layout, probed
//! filesystems, mounts, swap, holders) plus a [`Target`], the exact
//! input the [`judge`](rufus_core::safety::judge) chain in
//! `rufus-core::safety` needs. Judging is deliberately *not* done here:
//! PLAN §6 wants one verdict implementation with two enforcement
//! points, so whoever calls [`inspect`] judges the returned target.
//!
//! # Failure etiquette (PLAN §2 rule 5)
//!
//! [`inspect`] never returns `Err`. A device that cannot be opened or
//! read is a *refusal* (target.unreadable, judged first by the
//! precedence chain), not a CLI failure: a dead USB bridge or a
//! permission problem must still yield a human verdict. Within one
//! opened device, any read error marks the device unreadable and stops
//! the file-derived sampling at that point — except the GPT entry
//! array, which is *table* metadata: an unreadable array behind a
//! signed header is a warning plus the MBR fallback, matching how
//! [`detect_layout`] treats rotted metadata.
//!
//! # Read budget
//!
//! Each device is sampled with five small windows, chosen so every
//! superblock magic lives inside one of them: 64 KiB at 0 (MBR, FAT
//! BPB, ext superblock, swap page, UDF/ISO descriptors), 1 KiB at
//! +64 KiB (btrfs), 1 KiB at +128 KiB (ZFS label), the GPT header
//! sector, and the last sector (backup header). Partition probes cover
//! the first [`MAX_PROBED_PARTITIONS`] entries — a time bound, not a
//! media truth — each one 64 KiB. Nothing else is read.

use std::fs;
use std::io;
use std::os::unix::fs::FileExt;

use rufus_core::fsprobe::FsKind;
use rufus_core::fsprobe::Sample;
use rufus_core::fsprobe::probe;
use rufus_core::partition::Layout;
use rufus_core::partition::TablePartition;
use rufus_core::partition::detect_layout;
use rufus_core::partition::gpt_entry_range;
use rufus_core::safety::Target;
use rufus_core::text::device_text;

use crate::model::Device;
use crate::mounts::DevNum;
use crate::mounts::MountEntry;
use crate::mounts::MountTable;
use crate::mounts::SwapEntry;
use crate::mounts::dev_number;
use crate::mounts::holders;
use crate::mounts::swap_for;
use crate::sysfs::SysfsRoot;

/// How many partitions get a filesystem probe: 16 covers every stick
/// layout the tool creates and bounds init time per device (PLAN §2,
/// "small and fast") without telling anyone the rest doesn't exist.
const MAX_PROBED_PARTITIONS: usize = 16;
/// The leading read: 64 KiB hold LBA0, the FAT BPB, the ext superblock
/// (at +0x438), both swap page sizes and the UDF/ISO descriptors.
const WINDOW_MAIN: u64 = 0x1_0000;
/// The btrfs superblock window, 1 KiB read at +64 KiB.
const OFFSET_64K: u64 = 0x1_0000;
/// The ZFS label window, 1 KiB read at +128 KiB.
const OFFSET_128K: u64 = 0x2_0000;
/// Byte span of the two far windows (`at_64k`, `at_128k`).
const WINDOW_SUPER: u64 = 0x400;
/// Logical sector sizes the offset arithmetic is allowed to assume. A
/// reported size outside this set degrades to the floor value with a
/// warning; modern OCZ drives are the cautionary tale.
const SECTOR_SIZES: [u32; 4] = [512, 1024, 2048, 4096];
/// Sector-size fallback when the reported one is not in [`SECTOR_SIZES`].
const FALLBACK_SECTOR: u32 = 512;
/// The GPT read budget is 128 entries × 4096 bytes; mirrors
/// `rufus_core::partition` caps without importing internals.
const MAX_GPT_ENTRIES: u64 = 128;
const MAX_GPT_ENTRY_SIZE: u64 = 4096;

/// One sampled device, ready for the report and the verdict (see
/// [`Target`] for the verdict's own view of the same facts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The S04-discovered device this report describes.
    pub device: Device,
    /// The partition table as read from the device; `None` when LBA0
    /// holds neither a real MBR nor a protective one (blank/garbage —
    /// normal for a stick, the verdict stays answerable).
    pub layout: Option<Layout>,
    /// The whole-device superblock probe (LVM2 and friends surface here,
    /// spanning partitions).
    pub filesystem: Option<FsKind>,
    /// `(kernel partition name, kind)` per probed partition, table
    /// order, at most [`MAX_PROBED_PARTITIONS`] probes.
    pub partition_filesystems: Vec<(String, FsKind)>,
    /// Mounts that name this disk or one of its partitions (sysfs
    /// devnum against the mount table).
    pub mounts: Vec<MountEntry>,
    /// Swap entries covering the disk or a partition.
    pub swaps: Vec<SwapEntry>,
    /// Kernel names of everything stacked on top: disk holders first,
    /// then per-partition holders, each group sorted.
    pub holders: Vec<String>,
    /// The device (or a partition) backs the running system.
    pub system_disk: bool,
    /// ASCII, end-user-readable notes about rot and skipped work —
    /// warnings never abort the report.
    pub warnings: Vec<String>,
    /// Set only when the device could not be opened/read; carries the
    /// device path and the OS error, sanitised, one line.
    pub unreadable: Option<String>,
}

/// Call-site knobs for [`inspect`] — everything that is *not* a device
/// fact: the tables cached by the CLI and the write-mode flags from
/// PLAN §6 rule 4.
pub struct Options<'a> {
    /// The mount table to match device numbers against (usable both for
    /// a fixture file and the live one).
    pub mount_table: &'a MountTable,
    /// Parsed `/proc/swaps` rows.
    pub swaps: &'a [SwapEntry],
    /// Size of the image to be written, when already known.
    pub image_bytes: Option<u64>,
    /// "Show all devices" mode is on.
    pub allow_fixed: bool,
    /// The serial the user typed for the show-all confirmation.
    pub confirmed_serial: Option<&'a str>,
}

/// The inspect result: the publish-facing [`Report`] and the ready-made
/// [`Target`] for [`judge`](rufus_core::safety::judge).
#[derive(Debug, Clone)]
pub struct Inspected {
    /// What the device looks like (also the `analyze --json` payload).
    pub report: Report,
    /// The verdict input — judge this, not the report.
    pub target: Target,
}

/// Sample one device and return the report plus the ready judgement
/// input. Never fails (see the module header): a device that cannot be
/// read answers with `target.unreadable` set, and the caller decides.
#[must_use]
pub fn inspect(sysfs: &SysfsRoot, device: &Device, options: &Options<'_>) -> Inspected {
    let mut report = Report {
        device: device.clone(),
        layout: None,
        filesystem: None,
        partition_filesystems: Vec::new(),
        mounts: Vec::new(),
        swaps: Vec::new(),
        holders: Vec::new(),
        system_disk: false,
        warnings: Vec::new(),
        unreadable: None,
    };

    // The sector geometry is a local sanity decision, not a device
    // verdict: a reported size outside the known set degrades to 512
    // with a warning, because one wrong guess shifts every GPT offset.
    let (sector_size, sector_supported) = (
        device.sector_size,
        SECTOR_SIZES.contains(&device.sector_size),
    );
    if !sector_supported {
        report.warnings.push(format!(
            "sector size {} is unsupported, assuming {}",
            device.sector_size, FALLBACK_SECTOR
        ));
    }
    let sector_size = if sector_supported {
        sector_size
    } else {
        FALLBACK_SECTOR
    };

    // Opening a *directory* succeeds on Linux; the EISDIR surfaces on
    // the first read below and lands in `unreadable` like every other
    // read failure (no panic, no Err).
    match fs::File::open(&device.dev_path) {
        Ok(file) => {
            sample_device(&mut report, &file, device, sector_size);
        }
        Err(err) => {
            report.unreadable = Some(device_text(&format!("opening {}: {err}", device.dev_path)))
        }
    }

    // The table-side sampling is independent of the device file state,
    // so mounts/swaps/holders/system facts fill even an unreadable
    // report — verdict precedence decides what matters. A sysfs lookup
    // that *errors* (unreadable attribute, odd directory) is not the
    // same as an absent fact: degraded to a plain value it would read
    // fail-open ("not mounted", "no holders"), so the error is said
    // out loud in a warning while the report still completes.
    let mut devnums: Vec<DevNum> = Vec::new();
    if let Some(devnum) = devnum_or_warning(&mut report, sysfs, &device.name) {
        devnums.push(devnum);
    }
    for part in &device.partitions {
        if let Some(devnum) = devnum_or_warning(&mut report, sysfs, &part.name) {
            devnums.push(devnum);
        }
    }
    for devnum in &devnums {
        if let Some(entry) = options.mount_table.mount_of(*devnum) {
            // One mountpoint may resolve for several inputs (disk and
            // partition on the same line); keep the first.
            if report
                .mounts
                .iter()
                .all(|known| known.mountpoint != entry.mountpoint)
            {
                report.mounts.push(entry.clone());
            }
        }
    }
    for swap in device_swap_sources(device, options) {
        if report
            .swaps
            .iter()
            .all(|known| known.filename != swap.filename)
        {
            report.swaps.push(swap);
        }
    }
    report.holders = holders_or_warning(&mut report, sysfs, &device.name);
    for part in &device.partitions {
        // Bind first: `extend` borrows `report`, and so does the helper.
        let part_holders = holders_or_warning(&mut report, sysfs, &part.name);
        report.holders.extend(part_holders);
    }
    let protected = options.mount_table.protected_devices();
    report.system_disk = devnums.iter().any(|devnum| protected.contains(devnum));

    let mut filesystems = Vec::with_capacity(1 + report.partition_filesystems.len());
    if let Some(kind) = report.filesystem {
        filesystems.push((None, kind));
    }
    for (name, kind) in &report.partition_filesystems {
        filesystems.push((Some(name.clone()), *kind));
    }
    let target = Target {
        name: device_text(&device.name),
        dev_path: device_text(&device.dev_path),
        size_bytes: device.size_bytes,
        read_only: device.read_only,
        removable: device.removable,
        serial: device.serial.clone(),
        system_disk: report.system_disk,
        mounted_at: report.mounts.first().map(|entry| entry.mountpoint.clone()),
        swap_source: report.swaps.first().map(|entry| entry.filename.clone()),
        holders: report.holders.clone(),
        filesystems,
        image_bytes: options.image_bytes,
        allow_fixed: options.allow_fixed,
        confirmed_serial: options.confirmed_serial.map(str::to_owned),
        unreadable: report.unreadable.clone(),
    };
    Inspected { report, target }
}

/// The device's active swap sources, disk first then partitions (the
/// caller dedupes by filename).
fn device_swap_sources(device: &Device, options: &Options<'_>) -> Vec<SwapEntry> {
    let mut sources = Vec::new();
    if let Some(entry) = swap_for(options.swaps, &device.dev_path, &device.name) {
        sources.push(entry.clone());
    }
    for part in &device.partitions {
        let part_path = format!("/dev/{}", part.name);
        if let Some(entry) = swap_for(options.swaps, &part_path, &part.name) {
            sources.push(entry.clone());
        }
    }
    sources
}

/// The kernel name for a layout partition index: the sysfs-listed
/// partition with that number when present, else the plain-digit form of
/// the disk name (S04 lists with the same rule, and `p`-separated disks
/// such as `nvme0n1` get the `p` form their kernel uses).
fn partition_name(device: &Device, index: u32) -> String {
    if let Some(part) = device
        .partitions
        .iter()
        .find(|part| part.number == Some(index))
    {
        return part.name.clone();
    }
    let disk = device_text(&device.name);
    if device.partitions.iter().any(|part| part.number.is_none()) {
        format!("{disk}p{index}")
    } else {
        format!("{disk}{index}")
    }
}

/// A device number for `name`, or `None` when the sysfs `dev` lookup
/// failed. An absent/unparseable attribute is the normal degraded
/// answer (see [`dev_number`]); a real I/O *error* is additionally said
/// out loud as a warning — silently treating it as "no number" would
/// read as "not mounted", a fail-open on PLAN §2's fail-closed file
/// paths. The error text is sanitised so the warning stays ASCII.
fn devnum_or_warning(report: &mut Report, sysfs: &SysfsRoot, name: &str) -> Option<DevNum> {
    match dev_number(sysfs, name) {
        Ok(devnum) => devnum,
        Err(err) => {
            report.warnings.push(device_text(&format!(
                "cannot read the device number of {name}: {err}"
            )));
            None
        }
    }
}

/// Holder names for `name`, or empty when the sysfs lookup failed. An
/// absent directory is the normal "nothing stacked on top" (see
/// [`holders`]); a real I/O *error* (odd permissions, a stray file)
/// pushes a warning instead of reading as "no holders" — the fail-closed
/// caveat the same PLAN §2 rule asks for.
fn holders_or_warning(report: &mut Report, sysfs: &SysfsRoot, name: &str) -> Vec<String> {
    match holders(sysfs, name) {
        Ok(names) => names,
        Err(err) => {
            report.warnings.push(device_text(&format!(
                "cannot read the holders of {name}: {err}"
            )));
            Vec::new()
        }
    }
}

/// `u64` byte counts → slice lengths for values this module caps far
/// below the word size (≤ 512 KiB read windows); a hostile value still
/// clamps instead of panicking on 16-bit words.
fn slice_len(bytes: u64) -> usize {
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// Read `len` bytes at `offset`, tolerating kernel short reads and EOF:
/// a short (or empty) result is data, a real error is `Err`.
fn read_window(file: &fs::File, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    let len = slice_len(len);
    let mut buffer = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let cursor = offset
            .checked_add(filled as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read offset overflows"))?;
        let read = file.read_at(&mut buffer[filled..], cursor)?;
        if read == 0 {
            break; // EOF: the short buffer is the honest answer
        }
        filled += read;
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// One successful-or-marked window read: on error the reason lands in
/// `report.unreadable` (path + OS error, sanitised) and the caller stops
/// sampling.
fn sampled_window(
    report: &mut Report,
    file: &fs::File,
    device: &Device,
    offset: u64,
    len: u64,
    what: &str,
) -> Option<Vec<u8>> {
    match read_window(file, offset, len) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            report.unreadable = Some(device_text(&format!(
                "reading {} ({}): {err}",
                device.dev_path, what
            )));
            None
        }
    }
}

/// The file-derived half of [`inspect`]: superblock windows, table
/// layout, partition probes. Returns whether sampling completed; a
/// `false` has already set `report.unreadable`.
fn sample_device(report: &mut Report, file: &fs::File, device: &Device, sector_size: u32) -> bool {
    let sector_bytes = u64::from(sector_size);
    let sector_len = slice_len(sector_bytes);
    let Some(prefix) = sampled_window(report, file, device, 0, WINDOW_MAIN, "first 64 KiB") else {
        return false;
    };
    let Some(at_64k) = sampled_window(
        report,
        file,
        device,
        OFFSET_64K,
        WINDOW_SUPER,
        "btrfs window",
    ) else {
        return false;
    };
    let Some(at_128k) = sampled_window(
        report,
        file,
        device,
        OFFSET_128K,
        WINDOW_SUPER,
        "zfs window",
    ) else {
        return false;
    };
    report.filesystem = probe(&Sample {
        prefix: &prefix,
        at_64k: &at_64k,
        at_128k: &at_128k,
    });

    // The layout: LBA0 (clipped to one sector of the prefix — a short
    // prefix already means "less than a sector exists"), the header
    // sector behind it, the entry array it points at, and the last
    // sector for the backup-header cross-check.
    let lba0 = match prefix.get(..sector_len) {
        Some(sector) => sector,
        None => prefix.as_slice(),
    };
    let Some(header_sector) = sampled_window(
        report,
        file,
        device,
        sector_bytes,
        sector_bytes,
        "gpt header",
    ) else {
        return false;
    };
    let header = if header_sector.is_empty() {
        None
    } else {
        Some(header_sector)
    };

    // Entry array: sized by the header's own claims, capped so a
    // corrupt header cannot ask for a gigabyte. An unreadable array is
    // table rot (warning + MBR fallback), never `unreadable`.
    let mut entries = None;
    if let Some(range) = header.as_deref().and_then(gpt_entry_range) {
        let Some(span) = u64::from(range.count).checked_mul(u64::from(range.entry_size)) else {
            report
                .warnings
                .push("gpt entry array location overflows".to_owned());
            return finish_layout(report, device, file, lba0, &header, None, sector_size);
        };
        let span = span.min(MAX_GPT_ENTRIES * MAX_GPT_ENTRY_SIZE);
        let Some(offset) = range.entry_lba.checked_mul(sector_bytes) else {
            report
                .warnings
                .push("gpt entry array location overflows".to_owned());
            return finish_layout(report, device, file, lba0, &header, None, sector_size);
        };
        match read_window(file, offset, span) {
            Ok(entry_bytes) => entries = Some(entry_bytes),
            Err(err) => {
                report.warnings.push(format!(
                    "gpt entry array unreadable: {}",
                    device_text(&err.to_string())
                ));
                return finish_layout(report, device, file, lba0, &header, None, sector_size);
            }
        }
    }
    if !finish_layout(report, device, file, lba0, &header, entries, sector_size) {
        return false;
    }
    // The layout is taken out of the report so the probes below can fill
    // warnings/filesystems while iterating; it is put back before the
    // return — the borrowed `&[TablePartition]` view costs no clone.
    let Some(taken) = report.layout.take() else {
        return true; // no table at all (blank/foreign LBA0): nothing to probe
    };
    let completed = probe_partitions(report, file, device, &taken.partitions, sector_size);
    report.layout = Some(taken);
    completed
}

/// Wrap up the layout half after the entry-array decision: read the
/// last sector (best effort on short media), then hand everything to
/// [`detect_layout`], which owns the fallback rules.
fn finish_layout(
    report: &mut Report,
    device: &Device,
    file: &fs::File,
    lba0: &[u8],
    header: &Option<Vec<u8>>,
    entries: Option<Vec<u8>>,
    sector_size: u32,
) -> bool {
    let sector_bytes = u64::from(sector_size);
    let Some(last_sector) = sampled_window(
        report,
        file,
        device,
        device.size_bytes.saturating_sub(sector_bytes),
        sector_bytes,
        "last sector",
    ) else {
        return false;
    };
    let last = if last_sector.is_empty() {
        None
    } else {
        Some(last_sector)
    };
    let layout = detect_layout(
        lba0,
        header.as_deref().filter(|sector| !sector.is_empty()),
        entries.as_deref(),
        last.as_deref(),
        sector_size,
    );
    // Table rot is report-worthy, not just JSON-worthy: every table
    // note ("extended partition (type 0x0f)…", CRC and backup-header
    // checks) also becomes a report warning the human analyze output
    // prints as a `warning:` line (the JSON keeps both arrays, and the
    // `Layout`'s own list is untouched). Appended exactly once, here —
    // the take/restore path in `sample_device` re-installs the same
    // `Option` and never re-copies warnings, and no later collection
    // point adds table notes.
    if let Some(layout) = &layout {
        report.warnings.extend(layout.warnings.iter().cloned());
    }
    report.layout = layout;
    true
}

/// The partition-probe half: filesystems of the first
/// [`MAX_PROBED_PARTITIONS`] layout entries (`partitions` is the taken
/// layout's table, still in table order).
fn probe_partitions(
    report: &mut Report,
    file: &fs::File,
    device: &Device,
    partitions: &[TablePartition],
    sector_size: u32,
) -> bool {
    let sector_bytes = u64::from(sector_size);
    for part in partitions.iter().take(MAX_PROBED_PARTITIONS) {
        if part.size_bytes == 0 {
            continue; // historical slot: nothing to look into
        }
        let name = partition_name(device, part.index);
        let Some(offset) = part.start_lba.checked_mul(sector_bytes) else {
            report
                .warnings
                .push(format!("partition {name} start offset overflows"));
            continue;
        };
        if offset >= device.size_bytes {
            report.warnings.push(format!(
                "partition {name} starts beyond the end of the device"
            ));
            continue;
        }
        // The partition's own byte range on the device: the far windows
        // must never read across its end (a neighbour's superblock is
        // not this partition's data).
        let part_end = offset.saturating_add(part.size_bytes);
        let Some(window) = sampled_window(
            report,
            file,
            device,
            offset,
            WINDOW_MAIN,
            &format!("partition {name}"),
        ) else {
            return false;
        };
        let partition = format!("partition {name}");
        let Some(at_64k) = scoped_window(
            report, file, device, offset, part_end, OFFSET_64K, &partition,
        ) else {
            return false;
        };
        let Some(at_128k) = scoped_window(
            report,
            file,
            device,
            offset,
            part_end,
            OFFSET_128K,
            &partition,
        ) else {
            return false;
        };
        if let Some(kind) = probe(&Sample {
            prefix: &window,
            at_64k: &at_64k,
            at_128k: &at_128k,
        }) {
            report.partition_filesystems.push((name, kind));
        }
    }
    true
}

/// One far probe window (`far_offset` is [`OFFSET_64K`] for the btrfs
/// superblock, [`OFFSET_128K`] for the ZFS label — the very offsets the
/// whole-device path uses, so the two paths cannot drift) scoped to a
/// partition: the window is read only where its start lies inside the
/// partition's own byte range, and clamped to the partition end so a
/// short tail never reads a neighbouring partition's bytes. Everything
/// beyond the partition is other media's data: an out-of-range window
/// is an empty slice, the same "no bytes, no match" contract [`Sample`]
/// already defines for unreadable windows. A read *error* is still
/// fatal for the sampling ([`sampled_window`] marks it).
fn scoped_window(
    report: &mut Report,
    file: &fs::File,
    device: &Device,
    part_start: u64,
    part_end: u64,
    far_offset: u64,
    partition: &str,
) -> Option<Vec<u8>> {
    let Some(window_start) = part_start.checked_add(far_offset) else {
        return Some(Vec::new()); // corrupt geometry: no bytes of our own
    };
    if window_start >= part_end {
        return Some(Vec::new()); // the window lies in someone else's bytes
    }
    // Window start inside the range: short when the partition ends
    // mid-window, which is exactly what the device path treats as a
    // present-but-short window.
    let len = WINDOW_SUPER.min(part_end - window_start);
    sampled_window(report, file, device, window_start, len, partition)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;

    use rufus_core::fsprobe::FsKind;
    use rufus_core::partition::MBR_SIGNATURE;
    use rufus_core::partition::TableKind;
    use rufus_core::safety::Reason;
    use rufus_core::safety::SafetyVerdict;
    use rufus_core::safety::judge;

    use super::MountTable;
    use super::OFFSET_64K;
    use super::OFFSET_128K;
    use super::Options;
    use super::SwapEntry;
    use super::inspect;
    use crate::model::Device;
    use crate::mounts::parse_swaps;
    use crate::sysfs::SysfsRoot;
    use crate::sysfs::enumerate;

    /// The device-tree chain every seeded stick links in at (kept in one
    /// place so holder/mkdir paths stay in sync with the seeds).
    const STICK_CHAIN: &str = "devices/pci/usb1/1-2/1-2:1.0/host1/target1:0:0/6:0:0:0";
    /// EFI System Partition GUID, on-disk (mixed-endian) form.
    const EFI_TYPE_GUID_RAW: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];

    // ------------------------------------------------------------------
    // Fixture: synthetic sysfs tree + sparse scratch images
    // ------------------------------------------------------------------

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

        fn sysfs(&self) -> SysfsRoot {
            SysfsRoot::new(self.root.clone())
        }

        fn file_path(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        /// Create the empty directory `rel` (with parents).
        fn mkdir(&self, rel: &str) {
            fs::create_dir_all(self.root.join(rel))
                .unwrap_or_else(|err| panic!("mkdir {rel}: {err}"));
        }

        /// Write a fixture file (at `rel`, creating parent dirs) with
        /// `content`; returns its path for handing to a module's
        /// `read(None)`-style finder.
        fn write_text(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap_or(self.root.as_path()))
                .unwrap_or_else(|err| panic!("dirs {rel}: {err}"));
            fs::write(&path, content).unwrap_or_else(|err| panic!("seed {rel}: {err}"));
            path
        }

        /// A sparse scratch image of `bytes` length: `set_len` only, so
        /// even the 8 MiB cases cost no bulk zeroing.
        fn image(&self, rel: &str, bytes: u64) -> PathBuf {
            if let Some(parent) = self.root.join(rel).parent() {
                fs::create_dir_all(parent).unwrap_or_else(|err| panic!("image dir: {err}"));
            }
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.root.join(rel))
                .unwrap_or_else(|err| panic!("image {rel}: {err}"));
            file.set_len(bytes)
                .unwrap_or_else(|err| panic!("len {rel}: {err}"));
            self.root.join(rel)
        }

        /// Stamp `bytes` at `offset` of an image file.
        fn patch(&self, path: &Path, offset: u64, bytes: &[u8]) {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap_or_else(|err| panic!("open {:?}: {err}", path));
            file.seek(SeekFrom::Start(offset))
                .unwrap_or_else(|err| panic!("seek {:?}: {err}", path));
            file.write_all(bytes)
                .unwrap_or_else(|err| panic!("write {:?}: {err}", path));
        }

        /// Seed a USB stick `name` with the class/queue/device facts
        /// (S04 style) plus one partition `<name>1` with the next devnum;
        /// returns the discovered [`Device`] (devnum 8:16/8:17).
        fn seed_stick(&self, name: &str, units: u64, logical_block: Option<&str>) -> Device {
            let real = format!("{STICK_CHAIN}/block/{name}");
            self.write_text(&format!("{real}/size"), &units.to_string());
            self.write_text(&format!("{real}/removable"), "1");
            self.write_text(&format!("{real}/ro"), "0");
            self.write_text(&format!("{real}/dev"), "8:16");
            if let Some(logical_block) = logical_block {
                self.write_text(&format!("{real}/queue/logical_block_size"), logical_block);
            }
            // The physical `device` node the identity fields come from:
            // the link points at the four-up USB device directory.
            self.write_text(&format!("{STICK_CHAIN}/vendor"), "SanDisk");
            self.write_text(&format!("{STICK_CHAIN}/model"), "Test Stick");
            self.write_text(&format!("{STICK_CHAIN}/serial"), "SER123");
            let part = format!("{real}/{name}1");
            self.write_text(&format!("{part}/size"), "6144");
            self.write_text(&format!("{part}/dev"), "8:17");
            // Live kernels publish partitions as *siblings* under
            // class/block, with the `partition` attribute marking them
            // (S04 mirrors this in `partition_siblings_…`): without the
            // sibling link a `dev_number("sdb1")` lookup finds nothing.
            self.write_text(&format!("{part}/partition"), "1");

            std::os::unix::fs::symlink(
                self.root.join(STICK_CHAIN),
                self.root.join(format!("{real}/device")),
            )
            .unwrap_or_else(|err| panic!("link device: {err}"));

            let class_block = self.root.join("class").join("block");
            fs::create_dir_all(&class_block).unwrap_or_else(|err| panic!("mkdir class {err}"));
            std::os::unix::fs::symlink(self.root.join(&real), class_block.join(name))
                .unwrap_or_else(|err| panic!("link {name}: {err}"));
            // The partition sibling next to the disk's class entry.
            std::os::unix::fs::symlink(self.root.join(&part), class_block.join(format!("{name}1")))
                .unwrap_or_else(|err| panic!("link {name}1: {err}"));

            let devices = enumerate(&self.sysfs()).expect("fixture enumerates");
            devices
                .into_iter()
                .find(|device| device.name == name)
                .unwrap_or_else(|| panic!("{name} enumerates"))
        }
    }

    // ------------------------------------------------------------------
    // Byte builders: MBR boot sector, FAT32 BPB, 4K GPT geometry
    // ------------------------------------------------------------------

    /// An MBR LBA0 with one FAT32 entry in slot 0 (type `0x0b`).
    fn fat32_mbr_lba0(start: u32, sectors: u32) -> [u8; 512] {
        let mut lba0 = [0u8; 512];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        lba0[446] = 0x00;
        lba0[446 + 4] = 0x0b;
        lba0[446 + 8..446 + 12].copy_from_slice(&start.to_le_bytes());
        lba0[446 + 12..446 + 16].copy_from_slice(&sectors.to_le_bytes());
        lba0
    }

    /// An MBR LBA0 with two explicitly given slots (type id, start,
    /// sectors), so a fixture can pair an extended container with a
    /// real primary without a second one-entry builder.
    fn two_slot_mbr_lba0(first: (u8, u32, u32), second: (u8, u32, u32)) -> [u8; 512] {
        let mut lba0 = [0u8; 512];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        for (slot, &(type_id, start, sectors)) in [first, second].iter().enumerate() {
            let base = 446 + slot * 16;
            lba0[base] = 0x00;
            lba0[base + 4] = type_id;
            lba0[base + 8..base + 12].copy_from_slice(&start.to_le_bytes());
            lba0[base + 12..base + 16].copy_from_slice(&sectors.to_le_bytes());
        }
        lba0
    }

    /// A FAT32 boot sector assembled from the bytes fsprobe::probe
    /// checks: the `FAT32   ` tag at 82, a sane BPB size at 11, and the
    /// 0x55AA boot signature.
    fn fat32_boot_sector() -> [u8; 512] {
        let mut bpb = [0u8; 512];
        bpb[82..90].copy_from_slice(b"FAT32   ");
        bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
        bpb[510..512].copy_from_slice(&MBR_SIGNATURE);
        bpb
    }

    /// A protective-MBR LBA0 for a 4 KiB-sector disk (the GPT guard at
    /// the start of LBA 0, still signed at bytes 510..512).
    fn protective_lba0(start: u32, sectors: u32) -> [u8; 4096] {
        let mut lba0 = [0u8; 4096];
        lba0[510..512].copy_from_slice(&MBR_SIGNATURE);
        lba0[446] = 0x00;
        lba0[446 + 4] = 0xEE;
        lba0[446 + 8..446 + 12].copy_from_slice(&start.to_le_bytes());
        lba0[446 + 12..446 + 16].copy_from_slice(&sectors.to_le_bytes());
        lba0
    }

    /// A 4 KiB-sector GPT header sector: signature, revision, size, the
    /// two location LBAs, the entry array location and shapes. CRCs are
    /// left zeroed — the parser treats a mismatch as a warning, and a
    /// sealed fixture is worth no extra builder here.
    fn gpt_header_4k(
        entries_lba: u64,
        alternate_lba: u64,
        count: u32,
        entry_size: u32,
    ) -> [u8; 4096] {
        let mut header = [0u8; 4096];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes()); // my lba
        header[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
        header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        header[80..84].copy_from_slice(&count.to_le_bytes());
        header[84..88].copy_from_slice(&entry_size.to_le_bytes());
        header
    }

    /// A backup header that cross-checks: signature plus its own
    /// location (what `verified_backup` compares).
    fn gpt_backup_4k(lba: u64) -> [u8; 4096] {
        let mut sector = [0u8; 4096];
        sector[0..8].copy_from_slice(b"EFI PART");
        sector[24..32].copy_from_slice(&lba.to_le_bytes());
        sector
    }

    /// A GPT entry claiming [`first`..[`last`]] for the EFI type GUID.
    fn gpt_entry(first: u64, last: u64) -> [u8; 128] {
        let mut entry = [0u8; 128];
        entry[0..16].copy_from_slice(&EFI_TYPE_GUID_RAW);
        entry[32..40].copy_from_slice(&first.to_le_bytes());
        entry[40..48].copy_from_slice(&last.to_le_bytes());
        entry
    }

    /// The stick's dev_path pointed at a scratch image.
    fn with_image(mut device: Device, path: &Path) -> Device {
        device.dev_path = path.display().to_string();
        device
    }

    /// Options for a fixture with nothing else going on.
    fn options<'a>(table: &'a MountTable, swaps: &'a [SwapEntry]) -> Options<'a> {
        Options {
            mount_table: table,
            swaps,
            image_bytes: None,
            allow_fixed: false,
            confirmed_serial: None,
        }
    }

    /// An "empty system" mount table: everything mounted outside the
    /// system prefixes and outside the fixture's devnums.
    fn foreign_root_table() -> MountTable {
        MountTable::parse("1 0 252:0 / / rw,relatime - ext4 /dev/simroot rw\n")
            .expect("fixture table parses")
    }

    /// The same four-seed shorthands as the mountinfo rows: one line per
    /// fixture, nothing exotic.
    fn mount_line(majmin: &str, mountpoint: &str) -> String {
        format!("2 1 {majmin} / {mountpoint} rw,relatime - vfat /dev/{majmin} rw")
    }

    // ------------------------------------------------------------------
    // 1. The normal stick: MBR + FAT32, unmounted, Safe
    // ------------------------------------------------------------------

    #[test]
    fn mbr_fat32_stick_is_safe() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None); // 4 MiB
        assert_eq!(
            device.serial.as_deref(),
            Some("SER123"),
            "S04 facts ride along"
        );
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, 2048 * 512, &fat32_boot_sector());
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let report = inspected.report;
        assert_eq!(report.device, device, "the S04 facts are cloned verbatim");
        assert_eq!(report.layout.as_ref().map(|l| l.kind), Some(TableKind::Mbr));
        assert_eq!(
            report.partition_filesystems,
            vec![("sdb1".to_owned(), FsKind::Fat32)]
        );
        assert_eq!(
            report.filesystem, None,
            "the whole device is not a filesystem"
        );
        assert!(
            !report.system_disk,
            "the mount table's root is another disk"
        );
        assert!(report.mounts.is_empty(), "{:?}", report.mounts);
        assert!(report.holders.is_empty());
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert!(report.unreadable.is_none(), "{:?}", report.unreadable);
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }

    // ------------------------------------------------------------------
    // 2. The stick mounted by the desktop
    // ------------------------------------------------------------------

    #[test]
    fn mounted_stick_refuses_with_its_mountpoint() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, 2048 * 512, &fat32_boot_sector());
        let device = with_image(device, &image);

        let table = MountTable::parse(&format!(
            "{}\n{}",
            mount_line("252:0", "/"),
            mount_line("8:17", "/media/user/STICK"),
        ))
        .expect("fixture table parses");
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(inspected.report.mounts.len(), 1);
        assert_eq!(inspected.report.mounts[0].mountpoint, "/media/user/STICK");
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::Mounted {
                mountpoint: "/media/user/STICK".to_owned(),
            }),
        );
    }

    // ------------------------------------------------------------------
    // 3. The partition the running system boots from
    // ------------------------------------------------------------------

    #[test]
    fn system_disk_refuses_before_mount_state() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, 2048 * 512, &fat32_boot_sector());
        let device = with_image(device, &image);

        let table = MountTable::parse(&mount_line("8:17", "/")).expect("fixture table parses");
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert!(inspected.report.system_disk, "sdb1 mounts at /");
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::SystemDisk)
        );
    }

    // ------------------------------------------------------------------
    // 4. The partition running the pagefile
    // ------------------------------------------------------------------

    #[test]
    fn active_swap_refuses_with_its_source() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, 2048 * 512, &fat32_boot_sector());
        let device = with_image(device, &image);

        let swaps = parse_swaps(
            "Filename\t\tType\t\tSize\t\tUsed\t\tPriority\n\
             /dev/sdb1                       partition\t3000\t0\t-2\n",
        )
        .expect("swaps fixture parses");
        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &swaps));

        assert_eq!(
            inspected.report.swaps,
            vec![SwapEntry {
                filename: "/dev/sdb1".to_owned(),
                kind: "partition".to_owned(),
                size_kib: 3000,
                used_kib: 0,
                priority: -2,
            }],
        );
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::Swap {
                source: "/dev/sdb1".to_owned(),
            }),
        );
    }

    // ------------------------------------------------------------------
    // 5. A volume manager stacked on top
    // ------------------------------------------------------------------

    #[test]
    fn held_stick_refuses_with_its_holder() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        let device = with_image(device, &image);

        fixture.mkdir(&format!("{STICK_CHAIN}/block/sdb/holders/dm-0"));
        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(inspected.report.holders, vec!["dm-0".to_owned()]);
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::Holder {
                holder: "dm-0".to_owned()
            }),
        );
    }

    // ------------------------------------------------------------------
    // 6. An LVM2 physical volume across the whole device
    // ------------------------------------------------------------------

    #[test]
    fn lvm2_whole_device_is_refused_by_kind() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 512, b"LABELONE");
        fixture.patch(&image, 536, b"LVM2 001");
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        // No MBR signature anywhere, so the layout is None while the
        // whole-device probe names the volume manager.
        assert_eq!(inspected.report.layout, None);
        assert_eq!(inspected.report.filesystem, Some(FsKind::Lvm2));
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Lvm2,
                partition: None,
            }),
        );
    }

    // ------------------------------------------------------------------
    // 7. A 4 KiB-sector GPT disk: geometry follows the reported sector
    // ------------------------------------------------------------------

    #[test]
    fn four_kb_sector_gpt_reads_at_the_reported_geometry() {
        let fixture = Fixture::new();
        // 8192 units x 512 = 4 MiB; in 4 KiB sectors: 1024 sectors.
        let device = fixture.seed_stick("sdb", 8192, Some("4096"));
        assert_eq!(
            device.sector_size, 4096,
            "the queue attribute drives config"
        );
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);

        // Protective MBR in LBA0, header at offset 4096 (LBA1), entries
        // at 8192 (LBA2), one EFI partition at LBA 16..=1022.
        fixture.patch(&image, 0, &protective_lba0(1, 1023));
        fixture.patch(&image, 4096, &gpt_header_4k(2, 1023, 1, 128));
        fixture.patch(&image, 8192, &gpt_entry(16, 1022));
        // Backup header in the last sector (LBA 1023), cross-checking.
        fixture.patch(&image, 1023 * 4096, &gpt_backup_4k(1023));
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let report = inspected.report;
        let layout = report.layout.as_ref().expect("protective MBR plus GPT");
        assert_eq!(layout.kind, TableKind::Gpt);
        assert!(layout.backup_gpt, "the last-sector header cross-checks");
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].kind, "efi_system");
        // The partition window is not a filesystem (zeroed).
        assert!(report.partition_filesystems.is_empty());
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }

    // ------------------------------------------------------------------
    // 8. A device path that is a directory
    // ------------------------------------------------------------------

    #[test]
    fn directory_dev_path_refuses_without_panicking() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let dev_dir = fixture.file_path("no-device");
        fixture.mkdir("no-device");
        let device = with_image(device, &dev_dir);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let unreadable = inspected
            .report
            .unreadable
            .as_deref()
            .expect("marked unreadable");
        assert!(
            unreadable.contains(&dev_dir.display().to_string()),
            "the path is named: {unreadable}"
        );
        assert!(
            unreadable.contains("directory"),
            "the OS error names it: {unreadable}"
        );
        assert_eq!(inspected.report.layout, None, "no sampling happened");
        // The verdict is the first precedence, before every other rule.
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::Unreadable {
                detail: unreadable.to_owned(),
            }),
        );
    }

    // ------------------------------------------------------------------
    // 9. A zero-length image (card reader without a card)
    // ------------------------------------------------------------------

    #[test]
    fn zero_size_device_answers_zero_size() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 0, None); // sysfs size 0
        let image = fixture.image("sdb.img", 0);
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert!(
            inspected.report.unreadable.is_none(),
            "{:?}",
            inspected.report
        );
        assert_eq!(inspected.report.layout, None, "empty LBA0 is no table");
        assert_eq!(inspected.report.filesystem, None);
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::ZeroSize)
        );
    }

    // ------------------------------------------------------------------
    // Review B1: far-window filesystems (btrfs/ZFS) must be reachable
    // from *partition* probes too, bounded to the partition's own bytes
    // ------------------------------------------------------------------

    /// The first partition byte of every image below: LBA 2048. The
    /// sysfs partition attribute carries a different size than some
    /// MBR entries on purpose — probing reads the authoritative table,
    /// never the sysfs size view (S04 facts are informational).
    const PART_START: u64 = 2048 * 512;

    #[test]
    fn btrfs_magic_inside_a_partition_refuses_naming_it() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None); // 4 MiB disk
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        // A 3 MiB partition from LBA 2048: its btrfs window starts at
        // partition + 64 KiB, and the btrfs magic sits 0x40 into it.
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, PART_START + OFFSET_64K + 0x40, b"_BHRfS_M");
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(
            inspected.report.filesystem, None,
            "the whole-device window shows nothing here: the magic is partition-relative"
        );
        assert_eq!(
            inspected.report.partition_filesystems,
            vec![("sdb1".to_owned(), FsKind::Btrfs)],
        );
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Btrfs,
                partition: Some("sdb1".to_owned()),
            }),
        );
    }

    #[test]
    fn zfs_label_inside_a_partition_refuses_naming_it() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        // Same partition shape; the ZFS label magic sits right at the
        // start of the partition's +128 KiB window.
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(
            &image,
            PART_START + OFFSET_128K,
            &0x00BA_B10Cu64.to_le_bytes(),
        );
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(
            inspected.report.partition_filesystems,
            vec![("sdb1".to_owned(), FsKind::Zfs)],
        );
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Zfs,
                partition: Some("sdb1".to_owned()),
            }),
        );
    }

    #[test]
    fn far_window_magic_outside_the_partition_is_ignored() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        // A 64 KiB partition at LBA 2048 ends exactly where its 64 KiB
        // far window would begin, so both would-be windows lie in the
        // free space behind it: a probe that reads there attributes
        // neighbour bytes to this partition and would wrongly refuse.
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 128));
        fixture.patch(&image, PART_START + OFFSET_64K + 0x40, b"_BHRfS_M");
        fixture.patch(
            &image,
            PART_START + OFFSET_128K,
            &0x00BA_B10Cu64.to_le_bytes(),
        );
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert!(
            inspected.report.partition_filesystems.is_empty(),
            "{:?}",
            inspected.report.partition_filesystems
        );
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }

    #[test]
    fn far_window_short_but_inside_a_partition_still_matches() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        // A 129-sector partition ends 512 bytes into its 64 KiB far
        // window: the window is "present but short" (0x200 bytes), and
        // the btrfs magic at +0x40 lies fully inside the partition.
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 129));
        fixture.patch(&image, PART_START + OFFSET_64K + 0x40, b"_BHRfS_M");
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(
            inspected.report.partition_filesystems,
            vec![("sdb1".to_owned(), FsKind::Btrfs)],
            "a short tail window must not hide an inside magic"
        );
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Btrfs,
                partition: Some("sdb1".to_owned()),
            }),
        );
    }

    // ------------------------------------------------------------------
    // Whole-device window location: both pins kill an OFFSET_64K
    // mutation, which must leave the suite red, not green
    // ------------------------------------------------------------------

    #[test]
    fn whole_device_window_sits_exactly_at_offset_64k() {
        let fixture = Fixture::new();
        // 2 MiB device, blank LBA0: no layout, only the whole-device
        // windows decide.
        let device = fixture.seed_stick("sdb", 4096, None);
        let image = fixture.image("sdb.img", 2 * 1024 * 1024);
        // Deliberately literal offsets, not the module constants: this
        // test pins *where* the window is read (device+0x10000, magic
        // at +0x40), so a drifted constant cannot move the planted
        // bytes along with the probe.
        fixture.patch(&image, 0x1_0000 + 0x40, b"_BHRfS_M");
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(inspected.report.filesystem, Some(FsKind::Btrfs));
        assert_eq!(inspected.report.layout, None);
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Btrfs,
                partition: None,
            }),
        );
    }

    #[test]
    fn whole_device_window_decoy_at_wrong_offset_is_ignored() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 4096, None);
        let image = fixture.image("sdb.img", 2 * 1024 * 1024);
        // Literal again: a magic at device+0x11040 is 4 KiB below the
        // window base — a window that drifted past +0x11000 would
        // swallow it and must fail this test instead.
        fixture.patch(&image, 0x1_1000 + 0x40, b"_BHRfS_M");
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        assert_eq!(
            inspected.report.filesystem, None,
            "the decoy must stay outside the probed window"
        );
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }

    // ------------------------------------------------------------------
    // Review S3: the open-failure branch (as opposed to the read
    // failure a directory triggers — open() succeeds on directories)
    // ------------------------------------------------------------------

    #[test]
    fn missing_device_path_refuses_without_panicking() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        // A path that was never created: `File::open` itself fails.
        let never = fixture.file_path("never-created-device.img");
        let device = with_image(device, &never);
        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let detail = inspected
            .report
            .unreadable
            .as_deref()
            .expect("an open failure marks the device unreadable");
        assert!(
            detail.contains(&never.display().to_string()),
            "the offending path is named: {detail}"
        );
        assert_eq!(inspected.report.layout, None, "nothing was sampled");
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::Unreadable {
                detail: detail.to_owned(),
            }),
        );
    }

    // ------------------------------------------------------------------
    // Layout warnings reach the report warnings (once, at layout time —
    // the probe take/restore never copies them again)
    // ------------------------------------------------------------------

    #[test]
    fn extended_container_warning_reaches_the_report() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None); // 4 MiB disk
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        // Slot 0: the 0x0F extended container. Slot 1: a real Linux
        // primary (LBA 144 keeps its 64 KiB probe window on the image) —
        // the only entry the inventory keeps; the container drops out
        // with one warning per container entry.
        fixture.patch(
            &image,
            0,
            &two_slot_mbr_lba0((0x0f, 2048, 1000), (0x83, 144, 200)),
        );
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let report = inspected.report;
        assert_eq!(
            report.warnings,
            vec!["extended partition (type 0x0f): logical partitions are not listed"],
            "the table note reaches report.warnings, exactly once"
        );
        let layout = report.layout.as_ref().expect("plain MBR parses");
        assert_eq!(layout.kind, TableKind::Mbr);
        assert_eq!(layout.partitions.len(), 1, "the container is not listed");
        assert_eq!(layout.partitions[0].index, 2);
        assert_eq!(layout.partitions[0].kind, "linux");
        // The layout keeps its own copy for the JSON table contract.
        assert_eq!(layout.warnings, report.warnings);
        // Warnings are report-only: the verdict stays safe.
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }

    // ------------------------------------------------------------------
    // Review N3: sysfs lookups must fail closed — a real I/O error is
    // named in a warning, never silently read as "not mounted" / "no
    // holders"
    // ------------------------------------------------------------------

    #[test]
    fn unreadable_dev_attribute_warns_and_the_report_completes() {
        let fixture = Fixture::new();
        // The `dev` attribute exists but is a directory: read_to_string
        // hits EISDIR — deterministic, no permission tricks.
        fixture.mkdir("class/block/broken/dev");
        let devices = enumerate(&fixture.sysfs()).expect("fixture enumerates");
        let device = devices
            .into_iter()
            .find(|device| device.name == "broken")
            .unwrap_or_else(|| panic!("broken enumerates"));
        let image = fixture.image("broken.img", 1024 * 1024);
        let device = with_image(device, &image);

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let report = inspected.report;
        let number_warnings = report
            .warnings
            .iter()
            .filter(|warning| warning.contains("device number"))
            .count();
        assert_eq!(number_warnings, 1, "{:?}", report.warnings);
        let said = report
            .warnings
            .iter()
            .find(|warning| warning.contains("device number"))
            .map(String::as_str)
            .expect("the warning exists");
        assert!(said.contains("broken"), "the device is named: {said}");
        assert!(said.is_ascii(), "{said:?}");
        // The report still completes: nothing pretends the mount table
        // was consulted for a number it could not read.
        assert!(report.unreadable.is_none(), "{:?}", report.unreadable);
        assert!(report.mounts.is_empty());
        assert!(report.holders.is_empty());
        assert_eq!(report.layout, None, "the blank image has no table");
        assert_eq!(
            judge(&inspected.target),
            SafetyVerdict::Refuse(Reason::ZeroSize)
        );
    }

    #[test]
    fn unreadable_holders_directory_warns_and_degrades_to_empty() {
        let fixture = Fixture::new();
        let device = fixture.seed_stick("sdb", 8192, None);
        let image = fixture.image("sdb.img", 4 * 1024 * 1024);
        fixture.patch(&image, 0, &fat32_mbr_lba0(2048, 6144));
        fixture.patch(&image, 2048 * 512, &fat32_boot_sector());
        let device = with_image(device, &image);
        // `holders` exists but is a plain file: read_dir hits ENOTDIR —
        // deterministic, no permission tricks.
        fixture.write_text("class/block/sdb/holders", "");

        let table = foreign_root_table();
        let inspected = inspect(&fixture.sysfs(), &device, &options(&table, &[]));

        let report = inspected.report;
        assert_eq!(
            report.holders,
            Vec::<String>::new(),
            "degraded, not 'no holders' claimed silently"
        );
        let holders_warnings = report
            .warnings
            .iter()
            .filter(|warning| warning.contains("holders"))
            .count();
        assert_eq!(holders_warnings, 1, "{:?}", report.warnings);
        let said = report
            .warnings
            .iter()
            .find(|warning| warning.contains("holders"))
            .map(String::as_str)
            .expect("the warning exists");
        assert!(said.contains("sdb"), "the device is named: {said}");
        assert!(said.is_ascii(), "{said:?}");
        // The stick itself is still judged as the normal Safe case.
        assert_eq!(judge(&inspected.target), SafetyVerdict::Safe);
    }
}
