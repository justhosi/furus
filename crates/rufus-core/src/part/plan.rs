//! The layout planner (PLAN §9-S08 "Layouts") rendered to absolute
//! sector writes.
//!
//! [`plan`] turns a [`PlanRequest`] — one of the four documented
//! layouts over a table kind and a sector size — into a
//! [`TablePlan`]: the partition list with 1-MiB-aligned, checked
//! geometry plus fresh `uuid` v4 GUIDs. [`render`] then visits the
//! real table writers (`mbr::write_mbr`, `gpt::write_gpt`) and
//! emits only the sectors that actually carry data — LBA0, the GPT
//! entry sectors, the two headers and the backup copies — never the
//! whole disk.
//!
//! **`render` is the only supported producer of table bytes.** The two
//! writers behind it are `pub(in crate::part)` and check only the
//! geometry they own (headroom, reversed spans, overlaps, the four-slot
//! MBR limit); bounding a caller's partition spans against
//! `first_usable`/`last_usable` is this module's job, done once in
//! `render_gpt`/`render_mbr`. The S17 write pipeline therefore consumes
//! [`Rendered`] and writes its [`SectorWrite`]s in order — it must not
//! reach past this module for the writers, which the module privacy
//! makes impossible outside `crate::part`.
//!
//! The four layouts (PLAN §9-S08): `single` (one data partition,
//! default for Linux ISOs), `uefi-ntfs` (a small FAT `UEFI_NTFS`
//! partition plus the data partition), `windows-togo` (ESP + MSR +
//! Windows data), `persistence` (Linux data + ext4 persistence tail).
//!
//! Rules the tests pin:
//!
//! * **Alignment** — every partition starts on the next 1 MiB
//!   boundary. The one documented exception: when the table itself
//!   dictates a first usable LBA that is already grid-aligned, that
//!   sector is the start (`planner_first_lba`); both legal tables
//!   dictate an unaligned first usable sector today, so in practice
//!   the grid rule decides everywhere.
//! * **No overlap with the table metadata** — the first partition can
//!   only start at or after the table's first usable sector, and the
//!   GPT layouts end at the usable ceiling (`last_lba - 33` on
//!   512-byte disks, `last_lba - 5` on 4096-byte disks); MBR has no
//!   backup copy, so its spans reach the final sector.
//! * **Fit refusals name the layout and the shortfall** — a disk too
//!   small for the request fails with the layout label plus the
//!   requested and available byte figures (via
//!   [`human_bytes`](crate::units::human_bytes)).
//! * **MBR limits** — at most four primary partitions (the writer's
//!   own rule; the planner holds the invariant), 32-bit LBA fields
//!   only, and `windows-togo` is refused outright because Microsoft
//!   Reserved has no MBR type byte.
//! * **GUIDs** — fresh `uuid` v4 values for the disk and every
//!   partition; the caller supplies nothing, so plans are
//!   reproducible only within a run (see [`fresh_guid_bytes`]).
//! * **Rendering** — GPT LBA0 is the protective MBR zero-padded to the
//!   sector size; the 16384-byte entry arrays ride one sector-sized
//!   `SectorWrite` per array sector, exactly where `write_gpt` places
//!   them; the round-trip through `detect_layout` reconstructs the
//!   plan with no CRC warnings.

use uuid::Uuid;

use crate::error::CoreError;
use crate::error::Result;
use crate::part::TableKind;
use crate::part::gpt::GptPartition;
use crate::part::gpt::write_gpt;
use crate::part::mbr::MbrPartition;
use crate::part::mbr::write_mbr;
use crate::part::put;
use crate::units::human_bytes;

/// One MiB, the alignment grid PLAN pins for planned partitions.
const MIB_BYTES: u64 = 1_048_576;

/// The GPT entry array's fixed byte size (128 entries × 128 bytes).
/// Divided by the sector size this yields the array's sector count —
/// 32 on 512-byte disks, 4 on 4096-byte disks, exact in both cases.
const GPT_ARRAY_BYTES: u64 = 128 * 128;

/// A blank LBA0 boot area: freshly planned MBR disks carry no boot
/// code (an ISO's own MBR is a later write-pipeline step, not a table
/// decision here).
const MBR_BLANK_BOOT_AREA: [u8; 446] = [0u8; 446];

/// EFI System Partition type GUID (`c12a7328-f81f-11d2-ba4b-...`) in
/// the on-disk mixed-endian byte order the entry format stores.
const EFI_SYSTEM_GUID: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
/// Microsoft Reserved type GUID (`e3c9e316-0b5c-4db8-...`) on-disk.
const MICROSOFT_RESERVED_GUID: [u8; 16] = [
    0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE,
];
/// Microsoft Basic Data type GUID (`ebd0a0a2-b9e5-4433-...`) on-disk —
/// the type Windows gives every ordinary data volume, whatever
/// filesystem sits on it.
const MICROSOFT_BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];
/// Linux filesystem data type GUID (`0fc63daf-8483-4772-...`) on-disk.
const LINUX_FILESYSTEM_GUID: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

/// The UEFI:NTFS ESP window when the request leaves the size to the
/// planner: 1 MiB, which comfortably holds the bootloader script.
const ESP_WINDOW_DEFAULT_BYTES: u64 = MIB_BYTES;
/// The Windows-to-go ESP window: 100 MiB, the Windows installer's own
/// sizing for a portable system disk.
const WINDOWS_TO_GO_ESP_BYTES: u64 = 100 * MIB_BYTES;
/// The Microsoft Reserved window: 16 MiB for every 8 GiB of disk,
/// pinned to the minimum Rufus needs the parts registry to survive.
const MICROSOFT_RESERVED_BYTES: u64 = 16 * MIB_BYTES;
/// The persistence window when the request leaves the size to the
/// planner: 256 MiB of ext4 backstore.
const PERSISTENCE_DEFAULT_BYTES: u64 = 256 * MIB_BYTES;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// Which of the PLAN §9-S08 layouts the planner should build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// One data partition over the whole usable span (the default for
    /// Linux ISOs, BIOS or UEFI).
    Single,
    /// A small FAT `UEFI_NTFS` partition followed by the data
    /// partition (the UEFI:NTFS boot shim for NTFS media).
    UefiNtfs,
    /// ESP 100 MiB + MSR 16 MiB + "Windows" data (portable Windows).
    /// GPT-only: the MSR has no MBR type byte.
    WindowsToGo,
    /// Linux data partition first, then the ext4 persistence tail.
    Persistence,
}

impl LayoutKind {
    /// The layout's label in every planner message (`windows-to-go`,
    /// ...), matching the PLAN §9-S08 names.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LayoutKind::Single => "single",
            LayoutKind::UefiNtfs => "uefi-ntfs",
            LayoutKind::WindowsToGo => "windows-to-go",
            LayoutKind::Persistence => "persistence",
        }
    }
}

/// What a `data` partition should describe once written.
///
/// The GPT type GUIDs collapse to two: the Linux filesystem GUID for
/// `Linux`, Microsoft Basic Data for the rest (Windows marks ordinary
/// FAT32/exFAT/NTFS volumes alike). The MBR type byte is where the
/// filesystems actually differentiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    /// Linux ext-family filesystem (`0x83` / Linux GUID).
    Linux,
    /// Microsoft's catch-all "basic data" type (`0x07`).
    MicrosoftBasicData,
    /// A FAT32 volume (`0x0c` FAT32 LBA / basic data GUID).
    Fat32,
    /// An exFAT volume (`0x07` / basic data GUID).
    Exfat,
    /// An NTFS volume (`0x07` / basic data GUID).
    Ntfs,
}

impl DataType {
    /// `(GPT type GUID on-disk bytes, MBR type byte)` for the type.
    #[must_use]
    fn ids(self) -> ([u8; 16], u8) {
        match self {
            DataType::Linux => (LINUX_FILESYSTEM_GUID, 0x83),
            DataType::MicrosoftBasicData => (MICROSOFT_BASIC_DATA_GUID, 0x07),
            DataType::Fat32 => (MICROSOFT_BASIC_DATA_GUID, 0x0c),
            DataType::Exfat | DataType::Ntfs => (MICROSOFT_BASIC_DATA_GUID, 0x07),
        }
    }
}

/// One planner request: which layout, on which table, over which
/// geometry — and the two tunable window sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanRequest {
    /// The layout to build.
    pub kind: LayoutKind,
    /// MBR or GPT. `WindowsToGo` requires GPT.
    pub table: TableKind,
    /// 512 or 4096, the disk's logical sector size.
    pub sector_size: u32,
    /// The device's final sector index (`size / sector - 1`).
    pub last_lba: u64,
    /// The `data` partition's type. `Single` and `UefiNtfs` take the
    /// type the caller asks for; `WindowsToGo` pins Microsoft Basic
    /// Data (a Windows layout) and `Persistence` pins the Linux
    /// types for both of its partitions (ext4 is the persistence
    /// filesystem, and the pair is meant for a Linux domain).
    pub data_type: DataType,
    /// The UEFI:NTFS ESP window; `0` selects the planner default
    /// (1 MiB). Whatever is supplied is rounded up to the 1 MiB grid
    /// (thereby also to a whole number of sectors).
    pub esp_bytes: u64,
    /// The persistence window; `0` selects the planner default
    /// (256 MiB). Rounded up to the 1 MiB grid like the ESP.
    pub persistence_bytes: u64,
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// One planned partition: its role, its table identification and the
/// absolute LBA span PLAN pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPartition {
    /// `"esp"`, `"msr"`, `"data"` or `"persistence"`.
    pub role: &'static str,
    /// GPT type GUID in on-disk mixed-endian bytes. Planned for every
    /// layout so the preview can show it, but read by the renderer
    /// only on the GPT path (MBR writes the `mbr_type` byte instead).
    pub type_guid: [u8; 16],
    /// Fresh per-partition unique GUID, on-disk bytes.
    pub unique_guid: [u8; 16],
    /// The MBR type byte of the partition: `0x0c` FAT32 LBA (the
    /// UEFI:NTFS ESP), `0x07` NTFS/exFAT/basic data, `0x83` Linux,
    /// `0xef` EFI system. `0x00` means "no MBR equivalent" — that is
    /// the Microsoft Reserved pseudo-partition's value, and it is
    /// precisely why `windows-to-go` refuses MBR tables: a `0x00`
    /// entry reads as an unused slot, so a table writer cannot express
    /// the MSR without pretending (render maps the reserved/`msr` role
    /// to `0x07` as the documented stand-in).
    pub mbr_type: u8,
    /// First LBA of the partition, 1 MiB grid-aligned.
    pub start_lba: u64,
    /// Last LBA of the partition, inclusive.
    pub last_lba: u64,
    /// Raw GPT attribute bitmap. Every planned partition carries `0`:
    /// nothing Rufus plans today needs a special-requirement bit.
    pub attributes: u64,
    /// The GPT entry name (≤ 36 ASCII characters). MBR tables carry
    /// no names — the writer ignores this field there.
    pub name: &'static str,
}

/// The planner's output: the table kind, a fresh disk GUID, and the
/// partitions in table order (esp before data, data before the
/// persistence tail, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablePlan {
    /// Which table format this plan is written for.
    pub kind: TableKind,
    /// Fresh disk GUID (`uuid` v4 on-disk bytes). On MBR tables the
    /// renderer uses its first four bytes as the disk signature.
    pub disk_guid: [u8; 16],
    /// The partitions in table order.
    pub partitions: Vec<PlannedPartition>,
}

/// One absolute-sector write the renderer produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectorWrite {
    /// The LBA to write to.
    pub lba: u64,
    /// The sector's bytes: exactly the logical sector size on GPT
    /// disks, 512 on the (physical-legacy) MBR image.
    pub bytes: Vec<u8>,
}

/// A rendered plan: everything the write pipeline must stamp, without
/// materialising the data-less middle of the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The table format the writes build.
    pub kind: TableKind,
    /// The writes in device order (LBA0 first, the backup header last).
    pub writes: Vec<SectorWrite>,
}

impl Rendered {
    /// Total bytes in the emitted writes (the payload the write
    /// pipeline must put down to build the table span).
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.writes
            .iter()
            .map(|write| write.bytes.len() as u64)
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Build any layout's request over a byte-sized disk: the one
/// constructor [`single_request`], [`Mkpart`](crate::pipeline::mkpart)
/// and the layout-aware window helpers share, so the stamped table
/// and the formatted window cannot disagree on inputs. `size_bytes`
/// is the whole-disk extent; `last_lba` derives as
/// `floor(size / sector) - 1`, leaving a trailing partial sector unused
/// by construction. A zero sector size or a disk smaller than one
/// sector refuses, naming the numbers.
///
/// `data_type` is the `data` partition's type; layouts that pin their
/// own types (`WindowsToGo`, `Persistence`) ignore it for the pinned
/// partitions (see [`plan`]).
pub fn request(
    kind: LayoutKind,
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
    data_type: DataType,
) -> Result<PlanRequest> {
    let sectors = size_bytes
        .checked_div(u64::from(sector_size))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "target of {size_bytes} bytes has sector size {sector_size}: refusing a zero sector size"
            ))
        })?;
    if sectors == 0 {
        return Err(CoreError::invalid(format!(
            "target of {size_bytes} bytes is smaller than one {sector_size} byte sector"
        )));
    }
    Ok(PlanRequest {
        kind,
        table,
        sector_size,
        last_lba: sectors - 1,
        data_type,
        esp_bytes: 0,
        persistence_bytes: 0,
    })
}

/// Build the `Single`-layout request [`Mkpart`](crate::pipeline::mkpart)
/// stamps: one Microsoft Basic Data partition over the whole usable
/// disk. A wrapper over [`request`]: the stamper and the platform
/// opener's window math share the one constructor, so the two cannot
/// disagree on inputs — both feed the same table, sector size and
/// byte size into the same [`plan`].
///
/// `size_bytes` is the whole-disk extent; `last_lba` derives as
/// `floor(size / sector) - 1`, leaving a trailing partial sector unused
/// by construction. A zero sector size or a disk smaller than one
/// sector refuses, naming the numbers (the stamper's wording, kept so
/// both sides report the same refusal).
pub fn single_request(table: TableKind, sector_size: u32, size_bytes: u64) -> Result<PlanRequest> {
    request(
        LayoutKind::Single,
        table,
        sector_size,
        size_bytes,
        DataType::MicrosoftBasicData,
    )
}

/// The byte window `(offset, len)` of one planned partition's span:
/// the shared overflow-checked LBA-to-bytes math behind
/// [`single_data_window`] and [`data_window`], so the two spell the
/// arithmetic once.
fn partition_window(partition: &PlannedPartition, sector_size: u32) -> Result<(u64, u64)> {
    let sector = u64::from(sector_size);
    let offset = partition.start_lba.checked_mul(sector).ok_or_else(|| {
        CoreError::invalid(format!(
            "partition start lba {} times sector size {sector_size} overflows the byte arithmetic",
            partition.start_lba
        ))
    })?;
    let sectors = partition
        .last_lba
        .checked_sub(partition.start_lba)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "partition lba range {}..={} overflows the byte arithmetic",
                partition.start_lba, partition.last_lba
            ))
        })?;
    let len = sectors.checked_mul(sector).ok_or_else(|| {
        CoreError::invalid(format!(
            "partition sector count {sectors} times sector size {sector_size} overflows the byte arithmetic"
        ))
    })?;
    Ok((offset, len))
}

/// The byte window `(offset, len)` of the planned partition with
/// `role` for `kind` on a `size_bytes` disk with `sector_size`-byte
/// sectors: the shared overflow-checked lookup behind [`data_window`]
/// (`"data"`) and [`esp_window`] (`"esp"`), so the two spell the
/// request-plus-plan-plus-lookup arithmetic once. Planned through the
/// same [`request`] plus [`plan`] the stamper runs, so the window is
/// the partition the table describes by construction — never a
/// positional literal. A plan with no such role (unreachable through
/// [`plan`] today) refuses naming the layout and the role instead of
/// indexing blindly.
fn role_window(
    kind: LayoutKind,
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
    role: &str,
) -> Result<(u64, u64)> {
    let request = request(
        kind,
        table,
        sector_size,
        size_bytes,
        DataType::MicrosoftBasicData,
    )?;
    let planned = plan(&request)?;
    let partition = planned
        .partitions
        .iter()
        .find(|partition| partition.role == role)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "the {} layout planned no {role} partition",
                kind.label()
            ))
        })?;
    partition_window(partition, sector_size)
}

/// The byte window `(offset, len)` of the `Single` layout's data
/// partition for `table` on a `size_bytes` disk with `sector_size`-byte
/// sectors: what the platform opener formats and verifies. Planned
/// through the same [`single_request`] plus [`plan`] the stamper runs,
/// so the window is the partition the table describes by construction —
/// not a second computation that could drift. The first (`data`)
/// partition wins; an empty plan (unreachable through [`plan`] today)
/// refuses instead of indexing blindly.
pub fn single_data_window(
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
) -> Result<(u64, u64)> {
    let request = single_request(table, sector_size, size_bytes)?;
    let planned = plan(&request)?;
    let partition = planned
        .partitions
        .first()
        .ok_or_else(|| CoreError::invalid("the single layout planned no partitions".to_string()))?;
    partition_window(partition, sector_size)
}

/// The byte window `(offset, len)` of `kind`'s `data` partition for
/// `table` on a `size_bytes` disk with `sector_size`-byte sectors:
/// the layout-aware form of [`single_data_window`] the platform
/// opener formats and verifies. Planned through the same [`request`]
/// plus [`plan`] the stamper runs, so the window is the partition the
/// table describes by construction. The partition whose `role` is
/// `"data"` wins — never a positional literal — so layouts whose data
/// sits elsewhere keep working: `WindowsToGo` (data third, after ESP
/// and MSR) and `Persistence` (data first, before the tail) resolve
/// through the same role the planner stamped. A plan with no `data`
/// role (unreachable through [`plan`] today) refuses instead of
/// indexing blindly.
pub fn data_window(
    kind: LayoutKind,
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
) -> Result<(u64, u64)> {
    role_window(kind, table, sector_size, size_bytes, "data")
}

/// The byte window `(offset, len)` of `kind`'s `esp` partition for
/// `table` on a `size_bytes` disk with `sector_size`-byte sectors:
/// the window the UEFI:NTFS shim image fills. The sibling of
/// [`data_window`] over the same shared lookup — the partition whose
/// `role` is `"esp"` wins, never a positional literal — so the window
/// is the partition the table describes by construction. Only the
/// layouts that stamp an ESP have one (`UefiNtfs` today, 1 MiB at the
/// 1 MiB grid; `WindowsToGo` 100 MiB); every other layout refuses
/// naming the layout instead of indexing blindly. The geometry does
/// not depend on the data partition's type, so the lookup plans with
/// the same fixed type [`data_window`] uses.
pub fn esp_window(
    kind: LayoutKind,
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
) -> Result<(u64, u64)> {
    role_window(kind, table, sector_size, size_bytes, "esp")
}

/// The 1-based table position of `kind`'s `data` partition for `table`
/// on a `size_bytes` disk with `sector_size`-byte sectors: what the
/// platform opener names the partition node with (say `/dev/sdb2`).
/// Derived from the planner's own role order — the index of the
/// `role == "data"` entry — so `UefiNtfs` (data second),
/// `WindowsToGo` (data third) and `Persistence` (data first) cannot
/// drift from the stamped table the way a literal position would. A
/// plan with no `data` role (unreachable through [`plan`] today)
/// refuses instead of naming a wrong node.
pub fn data_partition_number(
    kind: LayoutKind,
    table: TableKind,
    sector_size: u32,
    size_bytes: u64,
) -> Result<u32> {
    let request = request(
        kind,
        table,
        sector_size,
        size_bytes,
        DataType::MicrosoftBasicData,
    )?;
    let planned = plan(&request)?;
    let position = planned
        .partitions
        .iter()
        .position(|partition| partition.role == "data")
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "the {} layout planned no data partition",
                kind.label()
            ))
        })?;
    u32::try_from(position + 1).map_err(|_| {
        CoreError::invalid(format!(
            "the {} layout planned more partitions than a table position holds",
            kind.label()
        ))
    })
}

/// Plan a whole-disk layout: [`PlanRequest`] in, checked geometry plus
/// fresh GUIDs out.
///
/// Refusals (all [`CoreError`], every message ASCII):
///
/// * sector sizes other than 512/4096;
/// * `WindowsToGo` on MBR (the MSR has no MBR type byte — see
///   [`PlannedPartition::mbr_type`]);
/// * an MBR disk whose last LBA does not fit the 32-bit entry fields;
/// * a disk that cannot fit the requested layout — the message names
///   the layout and the shortfall in bytes.
///
/// Sector math saturates instead of wrapping (the shared
/// [`crate::part`] rule), and every window is rounded onto the 1 MiB
/// grid so no later partition can ever start unaligned.
#[must_use = "a plan that is never rendered wrote nothing"]
pub fn plan(req: &PlanRequest) -> Result<TablePlan> {
    if !matches!(req.sector_size, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "sector size must be 512 or 4096 bytes, got {}",
            req.sector_size
        )));
    }
    if req.kind == LayoutKind::WindowsToGo && req.table == TableKind::Mbr {
        return Err(CoreError::invalid(
            "windows-to-go layout cannot be written to an mbr table: microsoft reserved \
             partitions have no mbr type byte (a 0x00 entry reads as an unused slot); \
             render this layout on gpt",
        ));
    }
    if req.table == TableKind::Mbr && req.last_lba > u64::from(u32::MAX) {
        return Err(CoreError::invalid(format!(
            "mbr layouts cannot address the disk: its last lba {} does not fit the 32-bit entry fields",
            req.last_lba
        )));
    }

    let grid = grid_sectors(req.sector_size);
    let (min_first, end_limit) = table_frame(req.table, req.sector_size, req.last_lba);
    // The one alignment exception (planner_first_lba): the table's own
    // first usable LBA may already sit on the grid; both legal tables
    // dictate an unaligned one today, so the round-up decides.
    let first = if min_first % grid == 0 {
        min_first
    } else {
        align_up(min_first, grid)
    };
    // Empty usable range (disk smaller than the table itself): the
    // span is 0 and the fit refusal speaks — never a wrap or a fake
    // one-sector span.
    let span_bytes = (end_limit
        .checked_add(1)
        .and_then(|limit| limit.checked_sub(first)))
    .unwrap_or(0)
    .saturating_mul(u64::from(req.sector_size));
    let sector = u64::from(req.sector_size);

    let partitions = match req.kind {
        LayoutKind::Single => {
            if span_bytes < sector {
                return Err(cannot_fit(req.kind.label(), sector, span_bytes));
            }
            vec![partition_data(
                "data",
                first,
                end_limit,
                "Basic Data Partition",
                req.data_type,
            )?]
        }
        LayoutKind::UefiNtfs => {
            let esp = aligned_window(req.esp_bytes, ESP_WINDOW_DEFAULT_BYTES);
            if span_bytes < esp.saturating_add(sector) {
                return Err(cannot_fit(
                    req.kind.label(),
                    esp.saturating_add(sector),
                    span_bytes,
                ));
            }
            let esp_sectors = esp / sector;
            vec![
                PlannedPartition {
                    role: "esp",
                    type_guid: EFI_SYSTEM_GUID,
                    unique_guid: fresh_guid_bytes()?,
                    mbr_type: 0x0c,
                    start_lba: first,
                    last_lba: first + esp_sectors - 1,
                    attributes: 0,
                    name: "UEFI_NTFS",
                },
                partition_data(
                    "data",
                    first + esp_sectors,
                    end_limit,
                    "Basic Data Partition",
                    req.data_type,
                )?,
            ]
        }
        LayoutKind::WindowsToGo => {
            let required = WINDOWS_TO_GO_ESP_BYTES + MICROSOFT_RESERVED_BYTES + sector;
            if span_bytes < required {
                return Err(cannot_fit(req.kind.label(), required, span_bytes));
            }
            let esp_sectors = WINDOWS_TO_GO_ESP_BYTES / sector;
            let msr_sectors = MICROSOFT_RESERVED_BYTES / sector;
            vec![
                PlannedPartition {
                    role: "esp",
                    type_guid: EFI_SYSTEM_GUID,
                    unique_guid: fresh_guid_bytes()?,
                    mbr_type: 0x0c,
                    start_lba: first,
                    last_lba: first + esp_sectors - 1,
                    attributes: 0,
                    name: "EFI System Partition",
                },
                PlannedPartition {
                    role: "msr",
                    type_guid: MICROSOFT_RESERVED_GUID,
                    unique_guid: fresh_guid_bytes()?,
                    mbr_type: 0x00,
                    start_lba: first + esp_sectors,
                    last_lba: first + esp_sectors + msr_sectors - 1,
                    attributes: 0,
                    name: "Microsoft reserved partition",
                },
                partition_data(
                    "data",
                    first + esp_sectors + msr_sectors,
                    end_limit,
                    "Windows",
                    DataType::MicrosoftBasicData,
                )?,
            ]
        }
        LayoutKind::Persistence => {
            let persistence = aligned_window(req.persistence_bytes, PERSISTENCE_DEFAULT_BYTES);
            // The data partition also starts on the grid (`first`), so
            // the aligned persistence start must leave it at least one
            // whole grid block: the true minimum is the window plus
            // 1 MiB, not the window plus one sector.
            if span_bytes < persistence.saturating_add(MIB_BYTES) {
                return Err(cannot_fit(
                    req.kind.label(),
                    persistence.saturating_add(MIB_BYTES),
                    span_bytes,
                ));
            }
            // The alignment-down rounds the tail window's *start* to
            // the grid, so the persistence partition grows (data pays
            // the slack) and its start stays grid-aligned; its end is
            // the table's usable ceiling, which is not grid-aligned.
            // After the fit gate the raw start cannot fall below
            // `first + grid`; the checked path keeps the arithmetic
            // total regardless.
            let persistence_start = end_limit
                .checked_add(1)
                .and_then(|limit| limit.checked_sub(persistence / sector))
                .map(|raw| align_down(raw, grid))
                .ok_or_else(|| {
                    cannot_fit(
                        req.kind.label(),
                        persistence.saturating_add(MIB_BYTES),
                        span_bytes,
                    )
                })?;
            vec![
                partition_data(
                    "data",
                    first,
                    persistence_start - 1,
                    "Basic Data Partition",
                    DataType::Linux,
                )?,
                partition_data(
                    "persistence",
                    persistence_start,
                    end_limit,
                    "persistence",
                    DataType::Linux,
                )?,
            ]
        }
    };

    // Invariant the writer shares (write_mbr refuses > 4, write_gpt
    // refuses > 128): the planner can never produce such a plan for
    // the built-in layouts, the check simply pins it in one place.
    let limit = if req.table == TableKind::Mbr { 4 } else { 128 };
    if partitions.len() > limit {
        return Err(CoreError::invalid(format!(
            "{} table holds at most {limit} entries, this layout needs {}",
            match req.table {
                TableKind::Mbr => "mbr",
                TableKind::Gpt => "gpt",
            },
            partitions.len()
        )));
    }

    Ok(TablePlan {
        kind: req.table,
        disk_guid: fresh_guid_bytes()?,
        partitions,
    })
}

/// One `role` partition of `partition_type` over the span: the plain
/// `data` entries of every layout, and the `persistence` tail.
fn partition_data(
    role: &'static str,
    start_lba: u64,
    last_lba: u64,
    name: &'static str,
    partition_type: DataType,
) -> Result<PlannedPartition> {
    let (type_guid, mbr_type) = partition_type.ids();
    Ok(PlannedPartition {
        role,
        type_guid,
        unique_guid: fresh_guid_bytes()?,
        mbr_type,
        start_lba,
        last_lba,
        attributes: 0,
        name,
    })
}

/// The one alignment exception, spelled out: when the table dictates a
/// first usable LBA that is already grid-aligned, partitions may start
/// right there instead of on the next boundary.
///
/// Returns `(first usable LBA, last usable LBA)`. `end_limit` may be
/// *below* `min_first` (a disk too small for the table itself); the
/// fit check turns that into the layout's refusal, never a wrap.
fn table_frame(table: TableKind, sector_size: u32, last_lba: u64) -> (u64, u64) {
    match table {
        // MBR has no first-usable framing: LBA0 is the only sector the
        // table reserves, partitions start on the next grid boundary.
        TableKind::Mbr => (1, last_lba),
        // GPT: first usable right behind the primary entry array,
        // last usable right below the backup array — the same
        // geometry write_gpt stamps into the headers.
        TableKind::Gpt => {
            let array = gpt_array_sectors(sector_size);
            let backup_base = last_lba.saturating_sub(array);
            (2 + array, backup_base.saturating_sub(1))
        }
    }
}

/// `bytes` rounded up onto the 1 MiB grid (a whole number of sectors
/// comes with it, both legal sector sizes divide 1 MiB exactly);
/// `requested == 0` selects `default`. Saturating at `u64::MAX` — a
/// saturated window then fails the caller's fit check on its own
/// merits, with the layout label in the refusal.
#[must_use]
fn aligned_window(requested: u64, default: u64) -> u64 {
    let base = if requested == 0 { default } else { requested };
    base.div_ceil(MIB_BYTES).saturating_mul(MIB_BYTES)
}

/// The layout-and-shortfall fit refusal.
fn cannot_fit(label: &str, required: u64, available: u64) -> CoreError {
    let shortfall = required.saturating_sub(available);
    CoreError::invalid(format!(
        "{label} layout cannot fit the disk: needs {}, the aligned table leaves {}, \
         short by {}",
        human_bytes(required),
        human_bytes(available),
        human_bytes(shortfall)
    ))
}

/// A fresh `uuid` v4 GUID in the on-disk mixed-endian byte order the
/// GPT entry stores: `data1`/`data2`/`data3` little-endian, the final
/// eight bytes verbatim.
fn fresh_guid_bytes() -> Result<[u8; 16]> {
    let [
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
        b8,
        b9,
        b10,
        b11,
        b12,
        b13,
        b14,
        b15,
    ] = *Uuid::new_v4().as_bytes();
    let mut raw = [0u8; 16];
    put(&mut raw, 0, &[b3, b2, b1, b0])?;
    put(&mut raw, 4, &[b5, b4])?;
    put(&mut raw, 6, &[b7, b6])?;
    put(&mut raw, 8, &[b8, b9, b10, b11, b12, b13, b14, b15])?;
    Ok(raw)
}

/// Sectors per 1 MiB of disk (2048 on 512-byte, 256 on 4096-byte
/// disks — the planner only runs after the sector-size gate).
#[must_use]
fn grid_sectors(sector_size: u32) -> u64 {
    MIB_BYTES / u64::from(sector_size)
}

/// The GPT entry array's sector count at this sector size.
#[must_use]
fn gpt_array_sectors(sector_size: u32) -> u64 {
    GPT_ARRAY_BYTES.div_ceil(u64::from(sector_size))
}

/// Round `lba` up to the grid.
#[must_use]
fn align_up(lba: u64, grid: u64) -> u64 {
    lba.div_ceil(grid) * grid
}

/// Round `lba` down to the grid.
#[must_use]
fn align_down(lba: u64, grid: u64) -> u64 {
    lba / grid * grid
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a [`TablePlan`] to the absolute [`SectorWrite`]s the write
/// pipeline must stamp: LBA0 always; for GPT the primary header (LBA
/// 1), the primary entry array (from LBA 2), the backup entry array
/// (directly below the final sector) and the backup header (the final
/// sector). Nothing else — the middle of the disk is never touched by
/// the table, so it is never materialised here.
///
/// The renderer re-validates the plan against the geometry of the
/// call: a hand-built plan whose entries fall outside the usable
/// range, past the disk's final sector, beyond the 32-bit MBR fields,
/// or into a `0x00` type byte that would read as an unused slot is
/// refused rather than rendered as something the reader could not
/// reconstruct.
pub fn render(plan: &TablePlan, sector_size: u32, last_lba: u64) -> Result<Rendered> {
    if !matches!(sector_size, 512 | 4096) {
        return Err(CoreError::invalid(format!(
            "sector size must be 512 or 4096 bytes, got {sector_size}"
        )));
    }
    match plan.kind {
        TableKind::Mbr => render_mbr(plan, last_lba),
        TableKind::Gpt => render_gpt(plan, sector_size, last_lba),
    }
}

/// MBR: one 512-byte write (LBA0) — the image size does not depend on
/// the disk's logical sector, which is the legacy footprint by
/// design. Each planned partition becomes one primary entry; the
/// first partition carries the `0x80` boot flag (the conventional
/// "this is the one the BIOS tries" marking of a planned disk).
fn render_mbr(plan: &TablePlan, last_lba: u64) -> Result<Rendered> {
    let mut entries = Vec::with_capacity(plan.partitions.len());
    for (slot, planned) in plan.partitions.iter().enumerate() {
        let index = slot + 1;
        if planned.start_lba == 0 {
            return Err(CoreError::invalid(format!(
                "mbr entry {index} claims lba 0, which holds the table itself"
            )));
        }
        if planned.start_lba > planned.last_lba {
            return Err(CoreError::invalid(format!(
                "mbr entry {index} lbas are reversed ({}..{})",
                planned.start_lba, planned.last_lba
            )));
        }
        if planned.last_lba > last_lba {
            return Err(CoreError::invalid(format!(
                "mbr entry {index} ends at lba {} beyond the disk's last lba {last_lba}",
                planned.last_lba
            )));
        }
        let sectors = planned
            .last_lba
            .checked_sub(planned.start_lba)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| {
                CoreError::invalid(format!("mbr entry {index} sector count does not fit u64"))
            })?;
        let start = u32::try_from(planned.start_lba).map_err(|_| {
            CoreError::invalid(format!(
                "mbr entry {index} start lba {} does not fit the 32-bit entry fields",
                planned.start_lba
            ))
        })?;
        let count = u32::try_from(sectors).map_err(|_| {
            CoreError::invalid(format!(
                "mbr entry {index} sector count {sectors} does not fit the 32-bit entry fields"
            ))
        })?;
        let type_id = match planned.mbr_type {
            // The reserved role is the one partition that has no MBR
            // type of its own; 0x07 (basic data) is the documented
            // stand-in so the entry stays readable rather than
            // looking like an unused slot. Any other 0x00 is a mise.
            // The planner spells the role `msr`; a hand-built plan may
            // spell it `reserved` (no in-tree plan does), so both are
            // accepted as the same slot.
            0 => {
                if planned.role == "reserved" || planned.role == "msr" {
                    0x07
                } else {
                    return Err(CoreError::invalid(format!(
                        "mbr entry {index} (role {}) has no mbr type byte; a 0x00 entry \
                         reads as an unused slot",
                        planned.role
                    )));
                }
            }
            other => other,
        };
        entries.push(MbrPartition {
            type_id,
            start_lba: start,
            sectors: count,
            bootable: slot == 0,
        });
    }
    let [s0, s1, s2, s3, ..] = plan.disk_guid;
    let image = write_mbr(&MBR_BLANK_BOOT_AREA, [s0, s1, s2, s3], &entries)?;
    Ok(Rendered {
        kind: TableKind::Mbr,
        writes: vec![SectorWrite {
            lba: 0,
            bytes: image.to_vec(),
        }],
    })
}

/// GPT: honour `write_gpt`'s placement map, sector by sector. The
/// entry arrays (16384 bytes) are cut into one `SectorWrite` per array
/// sector; the protective MBR keeps its 512-byte footprint inside a
/// zero-padded LBA0 on 4096-byte disks.
fn render_gpt(plan: &TablePlan, sector_size: u32, last_lba: u64) -> Result<Rendered> {
    let partitions: Vec<GptPartition> = plan
        .partitions
        .iter()
        .map(|planned| GptPartition {
            type_guid: planned.type_guid,
            unique_guid: planned.unique_guid,
            first_lba: planned.start_lba,
            last_lba: planned.last_lba,
            attributes: planned.attributes,
            name: planned.name,
        })
        .collect();
    let image = write_gpt(sector_size, last_lba, plan.disk_guid, &partitions)?;

    // Bounds the plan must hold for the parsed table to say the same
    // thing the plan did: every span inside the usable range the
    // header declares (write_gpt already refuses reversed or
    // overlapping spans).
    for (slot, planned) in plan.partitions.iter().enumerate() {
        let index = slot + 1;
        let inside = planned.start_lba >= image.first_usable
            && planned.last_lba <= image.last_usable
            && planned.start_lba <= planned.last_lba;
        if !inside {
            return Err(CoreError::invalid(format!(
                "gpt entry {index} spans {}..{}, outside the header's usable range {}..{}",
                planned.start_lba, planned.last_lba, image.first_usable, image.last_usable
            )));
        }
    }

    let mut writes = vec![SectorWrite {
        lba: 0,
        bytes: padded_lba0(sector_size, &image.protective_mbr)?,
    }];
    writes.push(SectorWrite {
        lba: 1,
        bytes: image.primary_header.clone(),
    });
    writes.extend(chunk_writes(&image.primary_entries, 2, sector_size));
    let backup_base = image
        .backup_lba
        .checked_sub(gpt_array_sectors(sector_size))
        .ok_or_else(|| CoreError::invalid("gpt backup entry array does not fit the disk"))?;
    writes.extend(chunk_writes(
        &image.backup_entries,
        backup_base,
        sector_size,
    ));
    writes.push(SectorWrite {
        lba: image.backup_lba,
        bytes: image.backup_header.clone(),
    });
    Ok(Rendered {
        kind: TableKind::Gpt,
        writes,
    })
}

/// Cut `bytes` into sector-sized [`SectorWrite`]s starting at
/// `first_lba`. The GPT arrays divide the sector size exactly, so
/// every write carries the full sector's bytes.
fn chunk_writes(bytes: &[u8], first_lba: u64, sector_size: u32) -> Vec<SectorWrite> {
    bytes
        .chunks(sector_size as usize)
        .enumerate()
        .map(|(index, chunk)| SectorWrite {
            lba: first_lba + index as u64,
            bytes: chunk.to_vec(),
        })
        .collect()
}

/// LBA0 for a GPT disk: the protective MBR's 512 bytes in front,
/// zeroed to the logical sector size behind (4096-byte disks).
fn padded_lba0(sector_size: u32, protective: &[u8; 512]) -> Result<Vec<u8>> {
    let mut lba0 = vec![0u8; sector_size as usize];
    let Some(window) = lba0.get_mut(..512) else {
        return Err(CoreError::invalid(
            "the protective mbr does not fit the sector size",
        ));
    };
    window.copy_from_slice(protective);
    Ok(lba0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part::Layout;
    use crate::part::detect_layout;
    use crate::part::gpt::guid_to_string;
    use crate::part::gpt::parse_gpt;

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    /// A comfortably sized request for a layout: the smallest
    /// last_lba any case of the layout still plans on, in sectors.
    fn floor_lba(kind: LayoutKind, table: TableKind, sector_size: u32) -> u64 {
        let grid = grid_sectors(sector_size);
        let slack = match table {
            TableKind::Mbr => 1,
            TableKind::Gpt => match sector_size {
                512 => 33,
                _ => 5,
            },
        };
        let span = match kind {
            LayoutKind::Single => grid,
            LayoutKind::UefiNtfs => 2 * grid,
            LayoutKind::WindowsToGo => 117 * grid,
            LayoutKind::Persistence => 258 * grid, // window grid-blocks + one data block
        };
        span + slack
    }

    /// Plan a layout for `last_lba` with sane defaults: basic-data
    /// content and no explicit window overrides.
    fn plan_for(kind: LayoutKind, table: TableKind, sector_size: u32, last_lba: u64) -> TablePlan {
        plan(&PlanRequest {
            kind,
            table,
            sector_size,
            last_lba,
            data_type: DataType::MicrosoftBasicData,
            esp_bytes: 0,
            persistence_bytes: 0,
        })
        .unwrap_or_else(|error| panic!("plan {kind:?}/{table:?}/{last_lba}: {error}"))
    }

    /// Stamp the rendered writes into a zero-filled disk image.
    fn materialise(writes: &[SectorWrite], sector_size: u32, last_lba: u64) -> Vec<u8> {
        let sector = sector_size as usize;
        let mut buffer = vec![0u8; (last_lba as usize + 1) * sector];
        for write in writes {
            let at = write.lba as usize * sector;
            let end = at + write.bytes.len();
            buffer[at..end].copy_from_slice(&write.bytes);
        }
        buffer
    }

    /// The last usable sector the planner handed this table kind.
    fn usable_end(table: TableKind, sector_size: u32, last_lba: u64) -> u64 {
        match table {
            TableKind::Mbr => last_lba,
            TableKind::Gpt => last_lba - gpt_array_sectors(sector_size) - 1,
        }
    }

    /// Grid LBA for the sector size (2048 on 512-byte disks, 256 on
    /// 4096-byte disks).
    fn grid_of(sector_size: u32) -> u64 {
        grid_sectors(sector_size)
    }

    /// Every planner invariant that is not layout-specific: starts are
    /// grid-aligned, spans are ordered and contiguous, everything sits
    /// inside the table's usable frame.
    fn assert_plan_geometry(
        plan: &TablePlan,
        sector_size: u32,
        last_lba: u64,
        expect_roles: &[&str],
    ) {
        let grid = grid_of(sector_size);
        let roles: Vec<&str> = plan.partitions.iter().map(|p| p.role).collect();
        assert_eq!(roles, expect_roles, "roles in table order");
        let (min_first, end_limit) = table_frame(plan.kind, sector_size, last_lba);
        let end = usable_end(plan.kind, sector_size, last_lba);
        assert_eq!(end_limit, end, "the planner's frame is the usable frame");
        let mut previous_end: Option<u64> = None;
        for planned in &plan.partitions {
            assert_eq!(
                planned.start_lba % grid,
                0,
                "start {} is grid-aligned (grid {grid})",
                planned.start_lba
            );
            assert!(
                planned.start_lba >= min_first,
                "start {} stays clear of the table metadata",
                planned.start_lba
            );
            assert!(planned.last_lba <= end, "span ends inside the usable frame");
            assert!(planned.start_lba <= planned.last_lba, "span is non-empty");
            if let Some(prev) = previous_end {
                assert_eq!(
                    planned.start_lba,
                    prev + 1,
                    "contiguous with the previous partition (no gap, no overlap)"
                );
            }
            previous_end = Some(planned.last_lba);
        }
    }

    // ------------------------------------------------------------------
    // Single
    // ------------------------------------------------------------------

    #[test]
    fn single_fills_the_available_span_on_every_table() {
        for (table, sector_size, last_lba) in [
            (TableKind::Mbr, 512, 2048 * 20),
            (TableKind::Gpt, 512, 2048 * 20),
            (TableKind::Mbr, 4096, 256 * 20),
            (TableKind::Gpt, 4096, 256 * 20),
        ] {
            let req_plan = plan_for(LayoutKind::Single, table, sector_size, last_lba);
            assert_plan_geometry(&req_plan, sector_size, last_lba, &["data"]);
            let data = &req_plan.partitions[0];
            let first = grid_of(sector_size);
            assert_eq!(data.start_lba, first, "the aligned first sector");
            assert_eq!(data.last_lba, usable_end(table, sector_size, last_lba));
            // The one partition sums to exactly the available space.
            assert_eq!(
                (data.last_lba - data.start_lba + 1) * u64::from(sector_size),
                (usable_end(table, sector_size, last_lba) - first + 1) * u64::from(sector_size),
            );
        }
    }

    #[test]
    fn single_walks_type_selection_through_both_tables() {
        for data_type in [
            DataType::Linux,
            DataType::MicrosoftBasicData,
            DataType::Fat32,
            DataType::Exfat,
            DataType::Ntfs,
        ] {
            for table in [TableKind::Mbr, TableKind::Gpt] {
                let req_plan = plan(&PlanRequest {
                    kind: LayoutKind::Single,
                    table,
                    sector_size: 512,
                    last_lba: 2048 * 40,
                    data_type,
                    esp_bytes: 0,
                    persistence_bytes: 0,
                })
                .unwrap_or_else(|error| panic!("single with {data_type:?}: {error}"));
                let data = &req_plan.partitions[0];
                let (want_guid, want_mbr) = data_type.ids();
                assert_eq!(data.type_guid, want_guid);
                assert_eq!(data.mbr_type, want_mbr);
            }
        }
    }

    // ------------------------------------------------------------------
    // UefiNtfs
    // ------------------------------------------------------------------

    #[test]
    fn uefi_ntfs_esp_window_is_exact() {
        for (esp_bytes, want_window) in [
            (0, MIB_BYTES),                          // planner default: 1 MiB
            (512 * 1024, MIB_BYTES),                 // rounds up to 1 MiB
            (MIB_BYTES + 512 * 1024, 2 * MIB_BYTES), // to the 1 MiB grid
        ] {
            let last_lba = 2048 * 64;
            let req_plan = plan(&PlanRequest {
                kind: LayoutKind::UefiNtfs,
                table: TableKind::Gpt,
                sector_size: 512,
                last_lba,
                data_type: DataType::Ntfs,
                esp_bytes,
                persistence_bytes: 0,
            })
            .unwrap_or_else(|error| panic!("uefi-ntfs esp {esp_bytes}: {error}"));
            assert_plan_geometry(&req_plan, 512, last_lba, &["esp", "data"]);
            let esp = &req_plan.partitions[0];
            let data = &req_plan.partitions[1];
            assert_eq!(
                (esp.last_lba - esp.start_lba + 1) * 512,
                want_window,
                "esp window {esp_bytes} -> {want_window}"
            );
            assert_eq!(esp.start_lba, grid_of(512));
            assert_eq!(data.start_lba, esp.last_lba + 1, "no gap after the esp");
            assert_eq!(data.last_lba, usable_end(TableKind::Gpt, 512, last_lba));
            assert_eq!(esp.type_guid, EFI_SYSTEM_GUID, "EFI System GUID");
            assert_eq!(esp.mbr_type, 0x0c, "FAT32 LBA in the MBR view");
            assert_eq!(esp.name, "UEFI_NTFS");
        }
    }

    #[test]
    fn uefi_ntfs_on_mbr_keeps_the_two_partition_shape() {
        let last_lba = 2048 * 32;
        let req_plan = plan_for(LayoutKind::UefiNtfs, TableKind::Mbr, 512, last_lba);
        assert_plan_geometry(&req_plan, 512, last_lba, &["esp", "data"]);
        assert_eq!(req_plan.partitions[0].mbr_type, 0x0c);
        assert_eq!(req_plan.partitions[1].mbr_type, 0x07, "NTFS data");
    }

    // ------------------------------------------------------------------
    // WindowsToGo
    // ------------------------------------------------------------------

    #[test]
    fn windows_to_go_pins_the_three_windows() {
        let last_lba = 2048 * 512;
        let req_plan = plan_for(LayoutKind::WindowsToGo, TableKind::Gpt, 512, last_lba);
        assert_plan_geometry(&req_plan, 512, last_lba, &["esp", "msr", "data"]);
        let esp = &req_plan.partitions[0];
        let msr = &req_plan.partitions[1];
        let data = &req_plan.partitions[2];
        assert_eq!(
            (esp.last_lba - esp.start_lba + 1) * 512,
            100 * MIB_BYTES,
            "the esp window is exactly 100 MiB"
        );
        assert_eq!(
            (msr.last_lba - msr.start_lba + 1) * 512,
            16 * MIB_BYTES,
            "the msr window is exactly 16 MiB"
        );
        assert_eq!(
            guid_to_string(&msr.type_guid),
            "e3c9e316-0b5c-4db8-817d-f92df00215ae",
            "the Microsoft reserved GUID"
        );
        assert_eq!(msr.mbr_type, 0x00, "no MBR equivalent for the MSR");
        assert_eq!(
            guid_to_string(&esp.type_guid),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        );
        assert_eq!(
            guid_to_string(&data.type_guid),
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
            "Windows data is Microsoft basic data"
        );
        assert_eq!(data.name, "Windows");
        assert_eq!(data.start_lba, msr.last_lba + 1);
        assert_eq!(data.last_lba, usable_end(TableKind::Gpt, 512, last_lba));
    }

    #[test]
    fn windows_to_go_on_mbr_is_refused() {
        let error = plan(&PlanRequest {
            kind: LayoutKind::WindowsToGo,
            table: TableKind::Mbr,
            sector_size: 512,
            last_lba: 2048 * 512,
            data_type: DataType::MicrosoftBasicData,
            esp_bytes: 0,
            persistence_bytes: 0,
        })
        .expect_err("windows-to-go refuses mbr tables");
        let text = error.to_string();
        assert!(text.contains("windows-to-go"), "{text}");
        assert!(text.contains("mbr"), "{text}");
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    #[test]
    fn persistence_tail_sits_before_the_backup_area() {
        // A MiB-sized disk for clean arithmetic.
        let last_lba = 2048 * 300;
        let req_plan = plan_for(LayoutKind::Persistence, TableKind::Gpt, 512, last_lba);
        assert_plan_geometry(&req_plan, 512, last_lba, &["data", "persistence"]);
        let persistence = req_plan.partitions.last().expect("two partitions");
        // It must end no later than last_lba - 33 — the GPT backup
        // array starts right after it.
        assert!(
            persistence.last_lba <= last_lba - 33,
            "persistence ends at {} before the backup area at {}",
            persistence.last_lba,
            last_lba - 33
        );
        assert_eq!(
            persistence.last_lba,
            usable_end(TableKind::Gpt, 512, last_lba)
        );
        // Planner default: at least the requested 256 MiB (the grid
        // may grow it by the alignment slack).
        assert!(
            (persistence.last_lba - persistence.start_lba + 1) * 512 >= 256 * MIB_BYTES,
            "persistence window at least 256 MiB"
        );
        assert_eq!(persistence.name, "persistence");
        for planned in &req_plan.partitions {
            assert_eq!(planned.type_guid, LINUX_FILESYSTEM_GUID);
            assert_eq!(planned.mbr_type, 0x83);
        }
    }

    #[test]
    fn persistence_frequency_grows_with_the_request() {
        let last_lba = 2048 * 400;
        let req_plan = plan(&PlanRequest {
            kind: LayoutKind::Persistence,
            table: TableKind::Mbr,
            sector_size: 512,
            last_lba,
            data_type: DataType::Linux,
            esp_bytes: 0,
            persistence_bytes: 64 * MIB_BYTES,
        })
        .unwrap_or_else(|error| panic!("persistence 64 MiB: {error}"));
        assert_plan_geometry(&req_plan, 512, last_lba, &["data", "persistence"]);
        let persistence = req_plan.partitions.last().expect("two partitions");
        assert!(
            (persistence.last_lba - persistence.start_lba + 1) * 512 >= 64 * MIB_BYTES,
            "the requested window is honoured (grown by the grid at most)"
        );
        assert_eq!(persistence.last_lba, last_lba, "MBR has no backup area");
    }

    #[test]
    fn persistence_on_mbr_reaches_the_final_sector() {
        let last_lba = 2048 * 320;
        let req_plan = plan_for(LayoutKind::Persistence, TableKind::Mbr, 512, last_lba);
        assert_eq!(req_plan.partitions.last().expect("two").last_lba, last_lba);
    }

    // ------------------------------------------------------------------
    // Data windows and partition numbers
    // ------------------------------------------------------------------

    #[test]
    fn data_window_matches_the_planned_data_role() {
        // Every layout on both tables: the window is the `data` role's
        // span in bytes, and the number is its 1-based table position —
        // both read off the planner, never a literal.
        for (kind, number) in [
            (LayoutKind::Single, 1u32),
            (LayoutKind::UefiNtfs, 2u32),
            (LayoutKind::WindowsToGo, 3u32),
            (LayoutKind::Persistence, 1u32),
        ] {
            for table in [TableKind::Mbr, TableKind::Gpt] {
                if kind == LayoutKind::WindowsToGo && table == TableKind::Mbr {
                    continue; // the MSR has no MBR type byte
                }
                let last_lba = 2048 * 512;
                let size_bytes = (last_lba + 1) * 512;
                let req_plan = plan_for(kind, table, 512, last_lba);
                let data = req_plan
                    .partitions
                    .iter()
                    .find(|partition| partition.role == "data")
                    .expect("every layout plans a data partition");
                let (offset, len) =
                    data_window(kind, table, 512, size_bytes).expect("the data window plans");
                assert_eq!(offset, data.start_lba * 512, "{kind:?}/{table:?} offset");
                assert_eq!(
                    len,
                    (data.last_lba - data.start_lba + 1) * 512,
                    "{kind:?}/{table:?} length"
                );
                assert_eq!(
                    data_partition_number(kind, table, 512, size_bytes).expect("the number plans"),
                    number,
                    "{kind:?}/{table:?} position"
                );
            }
        }
    }

    #[test]
    fn data_window_agrees_with_single_data_window() {
        // The layout-aware window collapses to the legacy one on the
        // `Single` layout, on both tables.
        for table in [TableKind::Mbr, TableKind::Gpt] {
            let size_bytes = 64 * MIB_BYTES;
            assert_eq!(
                data_window(LayoutKind::Single, table, 512, size_bytes)
                    .expect("layout-aware plans"),
                single_data_window(table, 512, size_bytes).expect("legacy plans"),
                "{table:?} windows agree"
            );
            assert_eq!(
                data_partition_number(LayoutKind::Single, table, 512, size_bytes)
                    .expect("the number plans"),
                1,
                "{table:?} data is first"
            );
        }
    }

    #[test]
    fn esp_window_matches_the_planned_esp_role() {
        // The layouts that stamp an ESP resolve through the same role
        // the planner stamped: `UefiNtfs` is exactly 1 MiB at the 1 MiB
        // grid on both tables and both sector sizes, `WindowsToGo`
        // exactly 100 MiB.
        for (table, sector_size) in [
            (TableKind::Mbr, 512),
            (TableKind::Gpt, 512),
            (TableKind::Mbr, 4096),
            (TableKind::Gpt, 4096),
        ] {
            let size_bytes = 512 * MIB_BYTES;
            let (offset, len) = esp_window(LayoutKind::UefiNtfs, table, sector_size, size_bytes)
                .expect("the esp window plans");
            assert_eq!(offset, MIB_BYTES, "{table:?}/{sector_size} offset");
            assert_eq!(len, MIB_BYTES, "{table:?}/{sector_size} length");
        }
        let size_bytes = 512 * MIB_BYTES;
        let (offset, len) = esp_window(LayoutKind::WindowsToGo, TableKind::Gpt, 512, size_bytes)
            .expect("the windows-to-go esp plans");
        assert_eq!(offset, MIB_BYTES, "the esp still starts on the grid");
        assert_eq!(len, 100 * MIB_BYTES, "the esp window is exactly 100 MiB");
    }

    #[test]
    fn esp_window_refuses_layouts_without_an_esp() {
        // `Single` and `Persistence` stamp no ESP: the lookup refuses
        // naming the layout, never a positional guess. The disk is
        // 512 MiB so the persistence fit gate passes and the refusal
        // comes from the role lookup itself.
        for kind in [LayoutKind::Single, LayoutKind::Persistence] {
            for table in [TableKind::Mbr, TableKind::Gpt] {
                let error =
                    esp_window(kind, table, 512, 512 * MIB_BYTES).expect_err("no esp refuses");
                let text = error.to_string();
                assert!(text.contains(kind.label()), "names the layout: {text}");
                assert!(text.contains("esp"), "names the role: {text}");
                assert!(text.is_ascii(), "stays ASCII: {text}");
            }
        }
    }

    // ------------------------------------------------------------------
    // Refusals
    // ------------------------------------------------------------------

    #[test]
    fn over_large_requests_name_layout_and_shortfall() {
        // A 1 MiB disk cannot even hold the table itself.
        let tiny = |kind| {
            plan(&PlanRequest {
                kind,
                table: TableKind::Gpt,
                sector_size: 512,
                last_lba: 2047,
                data_type: DataType::MicrosoftBasicData,
                esp_bytes: 0,
                persistence_bytes: 0,
            })
            .err()
            .unwrap_or_else(|| panic!("a 1 MiB disk refuses {kind:?}"))
            .to_string()
        };
        let single = tiny(LayoutKind::Single);
        assert!(single.contains("single"), "{single}");
        assert!(single.contains("short by"), "{single}");
        assert!(single.contains("512 B"), "{single}");

        // A 4096-sector disk cannot hold the 116 MiB of windows-togo.
        let togo = plan(&PlanRequest {
            kind: LayoutKind::WindowsToGo,
            table: TableKind::Gpt,
            sector_size: 512,
            last_lba: 2048 * 100,
            data_type: DataType::Ntfs,
            esp_bytes: 0,
            persistence_bytes: 0,
        })
        .expect_err("a 100 MiB disk refuses windows-to-go")
        .to_string();
        assert!(togo.contains("windows-to-go"), "{togo}");
        assert!(togo.contains("short by"), "{togo}");

        // A megabyte-scale persistence window on a 300 MiB disk.
        let persistence = plan(&PlanRequest {
            kind: LayoutKind::Persistence,
            table: TableKind::Gpt,
            sector_size: 512,
            last_lba: 2048 * 300,
            data_type: DataType::Linux,
            esp_bytes: 0,
            persistence_bytes: 1024 * MIB_BYTES,
        })
        .expect_err("256 MiB short of a GiB window")
        .to_string();
        assert!(
            persistence.contains("persistence layout cannot fit"),
            "{persistence}"
        );
        assert!(persistence.contains("short by"), "{persistence}");
        assert!(persistence.contains("1.00 GiB"), "{persistence}");

        // An esp window that wants the whole disk.
        let esp = plan(&PlanRequest {
            kind: LayoutKind::UefiNtfs,
            table: TableKind::Gpt,
            sector_size: 512,
            last_lba: 2048 * 10,
            data_type: DataType::Ntfs,
            esp_bytes: 16 * MIB_BYTES,
            persistence_bytes: 0,
        })
        .expect_err("a 10 MiB disk refuses a 16 MiB esp")
        .to_string();
        assert!(esp.contains("uefi-ntfs layout cannot fit"), "{esp}");
        assert!(esp.contains("short by"), "{esp}");
    }

    #[test]
    fn bad_sector_sizes_and_mbr_32bit_limits_are_refused() {
        let error = plan(&PlanRequest {
            kind: LayoutKind::Single,
            table: TableKind::Gpt,
            sector_size: 2048,
            last_lba: 2048,
            data_type: DataType::Ntfs,
            esp_bytes: 0,
            persistence_bytes: 0,
        })
        .expect_err("2048 is not a supported sector size");
        assert!(error.to_string().contains("512 or 4096"), "{error}");

        let error = plan(&PlanRequest {
            kind: LayoutKind::Single,
            table: TableKind::Mbr,
            sector_size: 512,
            last_lba: u64::from(u32::MAX) + 1,
            data_type: DataType::Ntfs,
            esp_bytes: 0,
            persistence_bytes: 0,
        })
        .expect_err("MBR entries cannot hold 2^32 sectors");
        let text = error.to_string();
        assert!(text.contains("32-bit"), "{text}");
    }

    // ------------------------------------------------------------------
    // Rendering: placement and re-validation
    // ------------------------------------------------------------------

    #[test]
    fn gpt_render_places_exactly_the_metadata_and_entry_sectors() {
        let last_lba = 2048 * 16;
        let req_plan = plan_for(LayoutKind::Single, TableKind::Gpt, 512, last_lba);
        let rendered =
            render(&req_plan, 512, last_lba).unwrap_or_else(|error| panic!("render gpt: {error}"));

        // LBA0, the primary header (LBA 1), 32 primary entry sectors,
        // 32 backup entry sectors and the backup header: nothing else.
        let mut seen: Vec<u64> = rendered.writes.iter().map(|w| w.lba).collect();
        seen.sort_unstable();
        let mut expected: Vec<u64> = (0..34).collect();
        let mut backup: Vec<u64> = ((last_lba - 32)..=last_lba).collect();
        expected.append(&mut backup);
        seen.dedup();
        assert_eq!(seen, expected, "the placement map, nothing else");
        assert_eq!(
            rendered.writes.len(),
            34 + 33,
            "primary 34 + backup array 32 + header 1"
        );
        assert_eq!(
            rendered.byte_len(),
            67 * 512,
            "every write is one sector, 67 sectors in total"
        );
        for write in &rendered.writes {
            assert_eq!(write.bytes.len(), 512, "sector-sized write");
        }
    }

    #[test]
    fn mbr_render_is_one_512_byte_write() {
        let last_lba = floor_lba(LayoutKind::Persistence, TableKind::Mbr, 512);
        let req_plan = plan_for(LayoutKind::Persistence, TableKind::Mbr, 512, last_lba);
        let rendered =
            render(&req_plan, 512, last_lba).unwrap_or_else(|error| panic!("render mbr: {error}"));
        assert_eq!(rendered.kind, TableKind::Mbr);
        assert_eq!(rendered.writes.len(), 1);
        assert_eq!(rendered.writes[0].lba, 0);
        assert_eq!(rendered.writes[0].bytes.len(), 512);
        assert_eq!(rendered.byte_len(), 512);
    }

    #[test]
    fn render_refuses_hand_built_nonsense() {
        let last_lba = 2048 * 16;

        // A GPT entry past the disk's usable range.
        let mut beyond = plan_for(LayoutKind::Single, TableKind::Gpt, 512, last_lba);
        beyond.partitions[0].last_lba = last_lba;
        let error = render(&beyond, 512, last_lba)
            .expect_err("an entry that crosses the backup array is refused");
        assert!(error.to_string().contains("usable range"), "{error}");

        // An MBR entry claiming LBA 0 (the table itself).
        let mut on_zero = plan_for(LayoutKind::Single, TableKind::Mbr, 512, last_lba);
        on_zero.partitions[0].start_lba = 0;
        let error = render(&on_zero, 512, last_lba).expect_err("lba 0 cannot hold a partition");
        assert!(error.to_string().contains("lba 0"), "{error}");

        // An MBR entry whose start overflows the 32-bit entry fields
        // (the span itself is tiny; the render `last_lba` is grown so
        // the end-of-disk check does not fire first).
        let mut oversized = plan_for(LayoutKind::Single, TableKind::Mbr, 512, last_lba);
        oversized.partitions[0].start_lba = u64::from(u32::MAX) + 1;
        oversized.partitions[0].last_lba = u64::from(u32::MAX) + 3;
        let error = render(&oversized, 512, u64::from(u32::MAX) + 3)
            .expect_err("32-bit entry fields cannot hold this start");
        assert!(error.to_string().contains("32-bit"), "{error}");

        // ... and one whose sector count overflows instead.
        let count_oversized = plan_for(LayoutKind::Single, TableKind::Mbr, 512, last_lba);
        let mut count_oversized = count_oversized;
        count_oversized.partitions[0].start_lba = 1;
        count_oversized.partitions[0].last_lba = u64::from(u32::MAX) + 2;
        let error = render(&count_oversized, 512, u64::from(u32::MAX) + 2)
            .expect_err("32-bit entry fields cannot hold this count");
        assert!(error.to_string().contains("32-bit"), "{error}");

        // An MBR plan with a type-less non-reserved entry.
        let mut sans_type = plan_for(LayoutKind::Single, TableKind::Mbr, 512, last_lba);
        sans_type.partitions[0].mbr_type = 0x00;
        let error =
            render(&sans_type, 512, last_lba).expect_err("a 0x00 type reads as an unused slot");
        assert!(error.to_string().contains("no mbr type"), "{error}");

        // ... but the reserved role is allowed to fall back to 0x07.
        // The planner spells it `msr`, hand-built plans spell it
        // `reserved`; both must render the same way.
        for role in ["reserved", "msr"] {
            let reserved = PlannedPartition {
                role,
                type_guid: MICROSOFT_RESERVED_GUID,
                unique_guid: [0u8; 16],
                mbr_type: 0x00,
                start_lba: 2048,
                last_lba: 2048 + 32_767,
                attributes: 0,
                name: role,
            };
            let reserved_plan = TablePlan {
                kind: TableKind::Mbr,
                disk_guid: [0x11u8; 16],
                partitions: vec![reserved],
            };
            let rendered = render(&reserved_plan, 512, 2048 * 80)
                .unwrap_or_else(|error| panic!("{role} falls back: {error}"));
            let parsed_first = &rendered.writes[0].bytes[446..462];
            assert_eq!(parsed_first[4], 0x07, "the {role} role renders as 0x07");
        }
    }

    // ------------------------------------------------------------------
    // Round trips: render -> disk image -> detect_layout
    // ------------------------------------------------------------------

    /// Write the rendered sectors into a zeroed disk image, read the
    /// table back through `detect_layout`, and compare partition by
    /// partition with the plan.
    fn assert_round_trip(
        req_plan: &TablePlan,
        rendered: &Rendered,
        sector_size: u32,
        last_lba: u64,
    ) -> Layout {
        let buffer = materialise(&rendered.writes, sector_size, last_lba);
        let sector = sector_size as usize;
        let lba0 = &buffer[0..sector];
        let array = (gpt_array_sectors(sector_size) as usize) * sector;
        let (header, entries, last) = match req_plan.kind {
            TableKind::Gpt => (
                Some(&buffer[sector..2 * sector]),
                Some(&buffer[2 * sector..2 * sector + array]),
                Some(&buffer[last_lba as usize * sector..]),
            ),
            TableKind::Mbr => (None, None, None),
        };
        let layout = detect_layout(lba0, header, entries, last, sector_size)
            .unwrap_or_else(|| panic!("the rendered table must parse ({:?})", req_plan.kind));
        assert_eq!(layout.kind, req_plan.kind);
        assert!(
            layout.warnings.is_empty(),
            "a freshly rendered table has no warnings: {:?}",
            layout.warnings
        );
        assert_eq!(layout.partitions.len(), req_plan.partitions.len());
        for (slot, (planned, parsed)) in req_plan
            .partitions
            .iter()
            .zip(&layout.partitions)
            .enumerate()
        {
            assert_eq!(parsed.index, slot as u32 + 1, "1-based table position");
            assert_eq!(parsed.start_lba, planned.start_lba, "start lba");
            assert_eq!(
                parsed.sectors,
                planned.last_lba - planned.start_lba + 1,
                "sector count"
            );
            match req_plan.kind {
                TableKind::Gpt => {
                    assert_eq!(
                        parsed.name,
                        match planned.name {
                            "" => None,
                            non_empty => Some(non_empty.to_owned()),
                        },
                        "entry name survives the utf-16 round trip"
                    );
                    assert_eq!(parsed.attributes, Some(planned.attributes));
                    assert_eq!(
                        parsed.guid,
                        Some(guid_to_string(&planned.type_guid)),
                        "type guid on-disk bytes encode the canonical string"
                    );
                    assert_eq!(
                        parsed.unique_guid,
                        Some(guid_to_string(&planned.unique_guid))
                    );
                }
                TableKind::Mbr => {
                    assert!(parsed.name.is_none(), "mbr entries carry no name");
                    let slug = match planned.mbr_type {
                        0x0c => "fat32",
                        0x07 => "ntfs_exfat",
                        0x83 => "linux",
                        0xef => "efi_system",
                        other => panic!("unplanned mbr type 0x{other:02x} in a round trip"),
                    };
                    assert_eq!(parsed.kind, slug, "the mbr type byte maps to its slug");
                }
            }
        }
        // The GPT parse must be warning-free on its own (CRC checks).
        if let TableKind::Gpt = req_plan.kind {
            let (_, warnings) = parse_gpt(
                &buffer[sector..2 * sector],
                &buffer[2 * sector..2 * sector + array],
                sector_size,
            )
            .unwrap_or_else(|error| panic!("parse_gpt: {error}"));
            assert!(warnings.is_empty(), "parse_gpt crc checks: {:?}", warnings);
            assert!(layout.backup_gpt, "the backup header cross-checks");
        }
        layout
    }

    #[test]
    fn every_layout_round_trips_through_detect_layout() {
        // The disk grows a little above each layout's minimum so every
        // size class stays legal; the margin is 4 MiB in sectors.
        for (kind, table, sector_size) in [
            (LayoutKind::Single, TableKind::Gpt, 512),
            (LayoutKind::Single, TableKind::Mbr, 512),
            (LayoutKind::UefiNtfs, TableKind::Gpt, 512),
            (LayoutKind::UefiNtfs, TableKind::Mbr, 512),
            (LayoutKind::WindowsToGo, TableKind::Gpt, 512),
            (LayoutKind::Persistence, TableKind::Gpt, 512),
            (LayoutKind::Persistence, TableKind::Mbr, 512),
        ] {
            let last_lba = floor_lba(kind, table, sector_size) + 4 * grid_of(sector_size);
            let req_plan = plan_for(kind, table, sector_size, last_lba);
            let rendered = render(&req_plan, sector_size, last_lba)
                .unwrap_or_else(|error| panic!("render {kind:?}/{table:?}: {error}"));
            let layout = assert_round_trip(&req_plan, &rendered, sector_size, last_lba);
            assert!(
                layout
                    .partitions
                    .windows(2)
                    .all(|pair| pair[0].start_lba < pair[1].start_lba),
                "parsed partitions are strictly ordered"
            );
        }
    }

    #[test]
    fn round_trips_work_on_4096_byte_disks_too() {
        for (kind, table) in [
            (LayoutKind::Single, TableKind::Gpt),
            (LayoutKind::Single, TableKind::Mbr),
            (LayoutKind::UefiNtfs, TableKind::Gpt),
            (LayoutKind::UefiNtfs, TableKind::Mbr),
            (LayoutKind::WindowsToGo, TableKind::Gpt),
            (LayoutKind::Persistence, TableKind::Gpt),
            (LayoutKind::Persistence, TableKind::Mbr),
        ] {
            let last_lba = floor_lba(kind, table, 4096) + 4096;
            let req_plan = plan_for(kind, table, 4096, last_lba);
            let rendered = render(&req_plan, 4096, last_lba)
                .unwrap_or_else(|error| panic!("render {kind:?}/{table:?} @4096: {error}"));
            // GPT writes are sector-sized (the protective MBR is
            // padded up to 4096); the MBR image stays 512 everywhere.
            for write in &rendered.writes {
                let want = if req_plan.kind == TableKind::Gpt {
                    4096
                } else {
                    512
                };
                assert_eq!(
                    write.bytes.len(),
                    want,
                    "write at lba {} is sector-sized",
                    write.lba
                );
            }
            assert_round_trip(&req_plan, &rendered, 4096, last_lba);
        }
    }

    // ------------------------------------------------------------------
    // Property: random geometries plan, render, parse back equal
    // ------------------------------------------------------------------

    /// Small deterministic LCG (numerical-recipes constants), no
    /// dependency: one u64 stream drives every random decision.
    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    #[test]
    fn property_random_geometries_plan_render_parse_equal() {
        let mut state: u64 = 0xB5EE_D5A6_C0DE_FD00;
        let layouts = [
            LayoutKind::Single,
            LayoutKind::UefiNtfs,
            LayoutKind::WindowsToGo,
            LayoutKind::Persistence,
        ];
        for case in 0..200 {
            let sector_size = if case % 2 == 0 { 512 } else { 4096 };
            let kind = layouts[(lcg_next(&mut state) as usize) % layouts.len()];
            // windows-to-go exists on GPT only; fold the stream onto
            // the two tables accordingly.
            let table = match kind {
                LayoutKind::WindowsToGo => TableKind::Gpt,
                _ => match lcg_next(&mut state) % 2 {
                    0 => TableKind::Mbr,
                    _ => TableKind::Gpt,
                },
            };
            let floor = floor_lba(kind, table, sector_size);
            let last_lba = floor + lcg_next(&mut state) % (floor / 8 + grid_of(sector_size));
            let req_plan = plan_for(kind, table, sector_size, last_lba);

            // Planner invariants.
            let roles: &[&str] = match kind {
                LayoutKind::Single => &["data"],
                LayoutKind::UefiNtfs => &["esp", "data"],
                LayoutKind::WindowsToGo => &["esp", "msr", "data"],
                LayoutKind::Persistence => &["data", "persistence"],
            };
            assert_plan_geometry(&req_plan, sector_size, last_lba, roles);

            // Render, stamp into a zeroed image, parse back, compare.
            let rendered = render(&req_plan, sector_size, last_lba)
                .unwrap_or_else(|error| panic!("render {kind:?}/{table:?}@{last_lba}: {error}"));
            let layout = assert_round_trip(&req_plan, &rendered, sector_size, last_lba);

            // No overlap among parsed spans and every span in bounds.
            let (min_first, end) = table_frame(table, sector_size, last_lba);
            let _ = end;
            for parsed in &layout.partitions {
                let parsed_end = parsed.start_lba + parsed.sectors - 1;
                assert!(
                    parsed.start_lba >= min_first && parsed.start_lba <= parsed_end,
                    "parsed start {} in bounds",
                    parsed.start_lba
                );
                assert!(
                    parsed_end <= usable_end(table, sector_size, last_lba),
                    "parsed end {} in bounds",
                    parsed_end
                );
            }
            let mut spans: Vec<(u64, u64)> = layout
                .partitions
                .iter()
                .map(|p| (p.start_lba, p.start_lba + p.sectors - 1))
                .collect();
            spans.sort_unstable();
            for window in spans.windows(2) {
                assert!(
                    window[0].1 < window[1].0,
                    "parsed spans do not overlap: {:?} vs {:?}",
                    window[0],
                    window[1]
                );
            }

            // The rendered payload only ever touches the metadata
            // sectors the placement map names.
            for write in &rendered.writes {
                assert!(
                    write.lba < gpt_array_sectors(sector_size) + 2
                        || write.lba + 1 >= last_lba - gpt_array_sectors(sector_size),
                    "write at lba {} carries table metadata only",
                    write.lba
                );
            }
        }
    }
}
