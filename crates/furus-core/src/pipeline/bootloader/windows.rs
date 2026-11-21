use std::path::Path;

use furus_proto::Filesystem;
use furus_proto::ImageRef;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::format::FormatOptions;
use crate::part::TableKind;
use crate::part::plan::LayoutKind;
use crate::part::plan::data_window;
use crate::part::plan::esp_window;
use crate::pipeline::event::Event;
use crate::pipeline::opener::MountedPartition;
use crate::pipeline::steps::RunContext;
use crate::pipeline::target::Target;
use crate::windows::bcd;

/// A [`Volume`] window over the whole-disk [`Target`] at
/// `[base, base + len)`: the ESP the Windows arm formats. The data
/// partition arrives through [`Opener::partition`](crate::pipeline::opener::Opener::partition),
/// but the ESP has no volume seam — only a node path for mounting —
/// so the formatter drives this window over the shared whole-disk
/// handle instead, bounded before every I/O like [`DiskView`].
pub(super) struct EspView<'a> {
    target: &'a mut dyn Target,
    base: u64,
    len: u64,
    sector_size: u32,
}

impl<'a> EspView<'a> {
    pub(super) fn new(target: &'a mut dyn Target, base: u64, len: u64, sector_size: u32) -> Self {
        Self {
            target,
            base,
            len,
            sector_size,
        }
    }
}

impl Volume for EspView<'_> {
    fn total_bytes(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len_u64 = u64::try_from(buf.len())
            .map_err(|_| CoreError::invalid("esp window read longer than u64: refusing"))?;
        let end = offset.checked_add(len_u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "esp window read of {} bytes at offset {offset} overflows u64: refusing",
                buf.len()
            ))
        })?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "esp window read of {} bytes at offset {offset} runs past the {len} byte window at base {base}: refusing",
                buf.len(),
                len = self.len,
                base = self.base
            )));
        }
        let at = self.base.checked_add(offset).ok_or_else(|| {
            CoreError::invalid(format!(
                "esp window base {base} plus offset {offset} overflows u64: refusing",
                base = self.base
            ))
        })?;
        self.target.read_at(at, buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let len_u64 = u64::try_from(buf.len())
            .map_err(|_| CoreError::invalid("esp window write longer than u64: refusing"))?;
        let end = offset.checked_add(len_u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "esp window write of {} bytes at offset {offset} overflows u64: refusing",
                buf.len()
            ))
        })?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "esp window write of {} bytes at offset {offset} runs past the {len} byte window at base {base}: refusing",
                buf.len(),
                len = self.len,
                base = self.base
            )));
        }
        let at = self.base.checked_add(offset).ok_or_else(|| {
            CoreError::invalid(format!(
                "esp window base {base} plus offset {offset} overflows u64: refusing",
                base = self.base
            ))
        })?;
        self.target.write_all_at(at, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.target.flush()
    }
}

/// Copy 16 raw GUID bytes out of `buf` at `at`, naming the field on
/// refusal. No indexing: the read stays total on a short buffer.
pub(super) fn guid_at(buf: &[u8], at: usize, field: &str) -> Result<[u8; 16]> {
    let window = buf.get(
        at..at
            .checked_add(16)
            .ok_or_else(|| CoreError::invalid(format!("{field} offset overflows: refusing")))?,
    );
    let bytes: &[u8] = window.ok_or_else(|| {
        CoreError::invalid(format!("stamped GPT is too short for {field}: refusing"))
    })?;
    bytes
        .try_into()
        .map_err(|_| CoreError::invalid(format!("stamped GPT {field} is not 16 bytes: refusing")))
}

/// Read one little-endian `u64` at `at`, naming the field on refusal.
pub(super) fn u64_at(buf: &[u8], at: usize, field: &str) -> Result<u64> {
    let end = at
        .checked_add(8)
        .ok_or_else(|| CoreError::invalid(format!("{field} offset overflows: refusing")))?;
    let window = buf.get(at..end).ok_or_else(|| {
        CoreError::invalid(format!("stamped GPT is too short for {field}: refusing"))
    })?;
    let unit: [u8; 8] = window
        .try_into()
        .map_err(|_| CoreError::invalid(format!("stamped GPT {field} is not 8 bytes: refusing")))?;
    Ok(u64::from_le_bytes(unit))
}

/// The two GPT partition identities [`windows_identity`] reads back from
/// the stamped table. `data` is the Windows partition the loader and
/// resume objects point at; `esp` is the EFI System Partition that
/// `{bootmgr}` points at on UEFI.
#[derive(Debug)]
pub(super) struct WindowsIdentities {
    pub(super) data: bcd::DeviceIdentity,
    pub(super) esp: bcd::DeviceIdentity,
}

/// Re-read the stamped GPT from the target and build both BCD device
/// identities from it: the disk GUID from the primary header, plus the
/// unique GUID of the entry whose LBA span is the planner's data window
/// (`data`, never a positional guess) and of the entry whose type is the
/// EFI System GUID (`esp`).
///
/// Every failure is [`CoreError::InvalidInput`] naming the problem:
/// an unreadable header or entry array, a missing signature, a
/// missing array location, an unparsable table, no data entry at the
/// planned span, or no ESP entry in the table.
pub(super) fn windows_identity(
    target: &mut dyn Target,
    sector_size: u32,
    size: u64,
) -> Result<WindowsIdentities> {
    let (data_offset, data_len) =
        data_window(LayoutKind::WindowsToGo, TableKind::Gpt, sector_size, size)?;
    let sector_u64 = u64::from(sector_size);
    if sector_u64 == 0 {
        return Err(CoreError::invalid(
            "stamped GPT sector size is zero: cannot locate the data partition".to_string(),
        ));
    }
    // The planner stamps 1 MiB-aligned spans, so a remainder here
    // means the size or the sector size the caller passed disagrees
    // with the stamped layout: refuse naming both numbers instead of
    // truncating through the division below.
    if data_offset % sector_u64 != 0 {
        return Err(CoreError::invalid(format!(
            "stamped GPT data offset {data_offset} is not a multiple of sector size {sector_size}: refusing"
        )));
    }
    if data_len % sector_u64 != 0 {
        return Err(CoreError::invalid(format!(
            "stamped GPT data length {data_len} is not a multiple of sector size {sector_size}: refusing"
        )));
    }
    let data_start_lba = data_offset / sector_u64;
    let data_sectors = data_len / sector_u64;
    let header_len = usize::try_from(sector_size).map_err(|_| {
        CoreError::invalid(format!(
            "stamped GPT sector size {sector_size} does not fit usize: refusing"
        ))
    })?;
    let mut header = vec![0u8; header_len];
    target.read_at(sector_u64, &mut header).map_err(|error| {
        CoreError::invalid(format!(
            "stamped GPT header cannot be read at offset {sector_u64}: {error}"
        ))
    })?;
    let signature_ok = header.get(..8) == Some(b"EFI PART".as_slice());
    if !signature_ok {
        return Err(CoreError::invalid(
            "stamped GPT header is missing the EFI PART signature: refusing".to_string(),
        ));
    }
    let disk_guid = guid_at(&header, 56, "disk GUID")?;
    let range = crate::part::gpt::gpt_entry_range(&header).ok_or_else(|| {
        CoreError::invalid("stamped GPT entry array location is missing: refusing".to_string())
    })?;
    let entry_size_u64 = u64::from(range.entry_size);
    let count_u64 = u64::from(range.count);
    let entries_len_u64 = count_u64.checked_mul(entry_size_u64).ok_or_else(|| {
        CoreError::invalid(format!(
            "stamped GPT entry array of {} entries times {} bytes overflows u64: refusing",
            range.count, range.entry_size
        ))
    })?;
    // The array cannot outgrow the device it is stamped on: a header
    // claiming more refuses before any allocation, so a corrupt
    // `count` × `size` never sizes the next read. (`gpt_entry_range`
    // already caps the shape at 128 entries of 4096 bytes, so the
    // worst honest allocation stays at 512 KiB.)
    if entries_len_u64 > size {
        return Err(CoreError::invalid(format!(
            "stamped GPT entry array of {entries_len_u64} bytes exceeds the {size} byte device: refusing"
        )));
    }
    let entries_len = usize::try_from(entries_len_u64).map_err(|_| {
        CoreError::invalid(format!(
            "stamped GPT entry array of {entries_len_u64} bytes does not fit usize: refusing"
        ))
    })?;
    let entries_base = range.entry_lba.checked_mul(sector_u64).ok_or_else(|| {
        CoreError::invalid(format!(
            "stamped GPT entry array at LBA {} times sector size {sector_size} overflows u64: refusing",
            range.entry_lba
        ))
    })?;
    let mut entries = vec![0u8; entries_len];
    target
        .read_at(entries_base, &mut entries)
        .map_err(|error| {
            CoreError::invalid(format!(
                "stamped GPT entry array cannot be read at offset {entries_base}: {error}"
            ))
        })?;
    // Validate through the parser first: a table that cannot be
    // parsed refuses here, while soft rot only warns inside.
    crate::part::gpt::parse_gpt(&header, &entries, sector_size)
        .map_err(|error| CoreError::invalid(format!("stamped GPT cannot be parsed: {error}")))?;
    let stride = usize::try_from(range.entry_size).map_err(|_| {
        CoreError::invalid(format!(
            "stamped GPT entry size {} does not fit usize: refusing",
            range.entry_size
        ))
    })?;
    let count = usize::try_from(range.count).map_err(|_| {
        CoreError::invalid(format!(
            "stamped GPT entry count {} does not fit usize: refusing",
            range.count
        ))
    })?;
    let mut data_identity: Option<bcd::DeviceIdentity> = None;
    let mut esp_identity: Option<bcd::DeviceIdentity> = None;
    let mut index = 0usize;
    while index < count {
        let base = index.checked_mul(stride).ok_or_else(|| {
            CoreError::invalid(format!(
                "stamped GPT entry {index} offset overflows: refusing"
            ))
        })?;
        let end = base.checked_add(stride).ok_or_else(|| {
            CoreError::invalid(format!("stamped GPT entry {index} end overflows: refusing"))
        })?;
        let Some(entry) = entries.get(base..end) else {
            break;
        };
        let Some(kind) = entry.get(..16) else {
            break;
        };
        let used = kind.iter().any(|byte| *byte != 0);
        if !used {
            index = index.saturating_add(1);
            continue;
        }
        // The ESP is found by its partition type GUID (the same bytes
        // the planner stamps, from `part::plan::EFI_SYSTEM_GUID`), never
        // by its position in the table. Its unique GUID at entry offset
        // 16 is what `{bootmgr}\11000001` must encode on UEFI.
        if kind == crate::part::plan::EFI_SYSTEM_GUID.as_slice() {
            let partition_guid = guid_at(entry, 16, "ESP partition GUID")?;
            esp_identity = Some(bcd::DeviceIdentity::Gpt {
                disk_guid,
                partition_guid,
            });
        }
        let first_lba = u64_at(entry, 32, "partition start")?;
        let last_lba = u64_at(entry, 40, "partition end")?;
        let Some(sectors) = last_lba
            .checked_sub(first_lba)
            .and_then(|delta| delta.checked_add(1))
        else {
            index = index.saturating_add(1);
            continue;
        };
        if first_lba == data_start_lba && sectors == data_sectors {
            let partition_guid = guid_at(entry, 16, "partition GUID")?;
            data_identity = Some(bcd::DeviceIdentity::Gpt {
                disk_guid,
                partition_guid,
            });
        }
        index = index.saturating_add(1);
    }
    let data = data_identity.ok_or_else(|| {
        CoreError::invalid(format!(
            "stamped GPT has no data partition at offset {data_offset} length {data_len}: refusing"
        ))
    })?;
    let esp = esp_identity.ok_or_else(|| {
        CoreError::invalid(
            "stamped GPT has no EFI System partition (ESP) entry for the boot manager: refusing"
                .to_string(),
        )
    })?;
    Ok(WindowsIdentities { data, esp })
}

/// Release both mounts after a failed Windows install step: a
/// release failure warns naming both errors, while the run still
/// reports the error that matters (the earlier one, never the
/// teardown's).
pub(super) fn release_both_after_failure(
    ctx: &mut RunContext<'_>,
    data: &mut dyn MountedPartition,
    esp: &mut dyn MountedPartition,
    during: &str,
) {
    if let Err(error) = data.release() {
        ctx.reporter.event(Event::Message {
            level: "warn",
            text: format!(
                "mount release failed after {during} (data): {error}; reporting the earlier error"
            ),
        });
    }
    if let Err(error) = esp.release() {
        ctx.reporter.event(Event::Message {
            level: "warn",
            text: format!(
                "mount release failed after {during} (esp): {error}; reporting the earlier error"
            ),
        });
    }
}

/// Fallback loader description when a WIM image carries no usable name
/// or description. A non-empty description is mandatory in the UEFI BCD:
/// bootmgr rejects a store whose OS loader lacks the 12000004 element
/// with 0xc0000001, so this cosmetic field must never come out blank.
const FALLBACK_LOADER_DESCRIPTION: &str = "Windows";

/// Pick the BCD loader description from a WIM image's metadata.
///
/// Prefers a non-empty image name, then a non-empty description, then
/// [`FALLBACK_LOADER_DESCRIPTION`]. Whitespace-only counts as empty.
pub(super) fn loader_description(name: &str, description: Option<&str>) -> String {
    if !name.trim().is_empty() {
        return name.to_string();
    }
    if let Some(description) = description.filter(|value| !value.trim().is_empty()) {
        return description.to_string();
    }
    FALLBACK_LOADER_DESCRIPTION.to_string()
}

/// Run the Windows arm: GPT-only, ESP-first, the WIM onto the raw NTFS
/// partition before any mount, then the post-apply customization.
///
/// The layout is GPT-only, so a non-GPT recorded table refuses up
/// front naming what is needed. The ESP formats as FAT32 through the
/// existing formatter (fresh serial, hidden sectors from the stamped
/// window), then the stamped GPT is re-read for the BCD identity. The
/// whole-disk handle releases next (the mounts need the partition
/// nodes, and the next `device` reopens from scratch; nothing in
/// between reopens it, so the apply's capacity comes from the stamped
/// data window rather than the partition volume), then the WIM's
/// boot index selects the image (1 unless the WIM reports a non-zero
/// one) and [`crate::windows::apply::apply_ntfs`] applies it to the raw
/// NTFS partition — before anything mounts, so the apply owns the
/// filesystem it writes. The data partition then mounts as NTFS and the
/// ESP mounts (an ESP mount failure releases the data mount first), and
/// [`crate::windows::to_go::install`] runs the post-apply customization
/// on the mounted tree: both BCD stores, the boot files, disabled
/// recovery and the offline SAN policy. Both mounts release on every
/// path: the earlier error wins and a release failure only warns,
/// naming both. One info line reports the applied file/byte counts
/// plus the placed file count.
pub(super) fn run_windows(ctx: &mut RunContext<'_>, image: &ImageRef) -> Result<()> {
    let cancelled = ctx.cancelled;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    match ctx.table {
        Some(TableKind::Gpt) => {}
        Some(_) => {
            return Err(CoreError::invalid(
                "windows installation needs a GPT table, the target carries a non-GPT table: refusing".to_string(),
            ));
        }
        None => {
            return Err(CoreError::invalid(
                "windows installation needs a recorded GPT table: refusing".to_string(),
            ));
        }
    }
    let (sector_size, size) = {
        let device = ctx.device()?;
        (device.sector_size(), device.size())
    };
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let (esp_offset, esp_len) =
        esp_window(LayoutKind::WindowsToGo, TableKind::Gpt, sector_size, size)?;
    // The planner stamps 1 MiB-aligned spans, so a remainder here
    // means the size or the sector size the caller passed disagrees
    // with the stamped layout: refuse naming both numbers instead of
    // truncating into the `u32` hidden-sectors field below.
    if esp_offset % u64::from(sector_size) != 0 {
        return Err(CoreError::invalid(format!(
            "windows ESP offset {esp_offset} is not a multiple of sector size {sector_size}: refusing"
        )));
    }
    let esp_start_lba = esp_offset / u64::from(sector_size);
    let esp_hidden = u32::try_from(esp_start_lba).map_err(|_| {
        CoreError::invalid(format!(
            "windows ESP start LBA {esp_start_lba} does not fit the u32 hidden-sectors field: refusing"
        ))
    })?;
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!("formatting ESP as FAT32 ({esp_len} bytes at offset {esp_offset})"),
    });
    {
        let device = ctx.device()?;
        let mut view = EspView::new(device, esp_offset, esp_len, sector_size);
        let options = FormatOptions {
            label: None,
            volume_id: crate::pipeline::mkfs::fresh_serial("esp")?,
            hidden_sectors: esp_hidden,
            oem: crate::fs::fat32::bpb::DEFAULT_OEM,
        };
        crate::fs::fat32::format::format(&mut view, &options)?;
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let identities = {
        let device = ctx.device()?;
        windows_identity(device, sector_size, size)?
    };
    // Release first: the mounts want their own claim on the partition
    // nodes, and an open exclusive whole-disk handle makes that claim
    // fail with EBUSY (see `release_device`).
    ctx.release_device()?;
    let installed = (|| -> Result<crate::windows::to_go::Installed> {
        let device_path = ctx.opener.partition_path()?;
        // The data partition's byte length comes from the stamped plan
        // geometry (the same `data_window` the opener's window and the
        // BCD identity above use), not from opening the partition
        // volume: opening it would re-cache the O_EXCL whole-disk
        // handle `release_device` just dropped, and the partition mount
        // below would then fail with EBUSY.
        let (_data_offset, capacity) =
            data_window(LayoutKind::WindowsToGo, TableKind::Gpt, sector_size, size)?;
        let path = Path::new(&image.path);
        let wim = crate::windows::wim::Wim::open(path)?;
        let info = wim.info()?;
        let image_index = if info.boot_index != 0 {
            info.boot_index
        } else {
            1
        };
        let applied = crate::windows::apply::apply_ntfs(
            &device_path,
            capacity,
            &wim,
            image_index,
            &mut *ctx.reporter,
            cancelled,
        )?;
        // The UEFI BCD needs a non-empty loader description (element
        // 12000004) or bootmgr fails with 0xc0000001. Derive it from the
        // image being applied; a metadata read failure or a missing index
        // falls back to "Windows" rather than failing the whole write.
        let description = wim
            .images()
            .ok()
            .and_then(|images| images.into_iter().find(|image| image.index == image_index))
            .map(|candidate| loader_description(&candidate.name, candidate.description.as_deref()))
            .unwrap_or_else(|| FALLBACK_LOADER_DESCRIPTION.to_string());
        let mut data = ctx.opener.mount_partition(&Filesystem::Ntfs)?;
        let mut esp = match ctx.opener.mount_esp() {
            Ok(esp) => esp,
            Err(mount_error) => {
                if let Err(release_error) = data.release() {
                    ctx.reporter.event(Event::Message {
                        level: "warn",
                        text: format!(
                            "mount release failed after the ESP mount (data): {release_error}; reporting the earlier error"
                        ),
                    });
                }
                return Err(mount_error);
            }
        };
        let request = crate::windows::to_go::Request {
            identity: identities.data,
            esp_identity: identities.esp,
            description: Some(description.as_str()),
            use_2023_bootloaders: false,
        };
        let outcome =
            crate::windows::to_go::install(data.as_mut(), esp.as_mut(), &request, applied);
        let installed = match outcome {
            Ok(installed) => installed,
            Err(error) => {
                release_both_after_failure(ctx, data.as_mut(), esp.as_mut(), "the windows install");
                return Err(error);
            }
        };
        let data_result = data.release();
        let esp_result = esp.release();
        match (data_result, esp_result) {
            (Ok(()), Ok(())) => {}
            (Err(first), Ok(())) => return Err(first),
            (Ok(()), Err(second)) => return Err(second),
            (Err(first), Err(second)) => {
                ctx.reporter.event(Event::Message {
                    level: "warn",
                    text: format!(
                        "mount release failed for both partitions (data: {first}; esp: {second}); reporting the data error"
                    ),
                });
                return Err(first);
            }
        }
        Ok(installed)
    })()?;
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!(
            "installed windows ({} files applied, {} bytes, {} boot files placed)",
            installed.applied.files,
            installed.applied.bytes,
            installed.files.len()
        ),
    });
    Ok(())
}
