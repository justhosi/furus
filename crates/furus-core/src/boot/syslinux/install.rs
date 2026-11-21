//! The Syslinux loader install: the boot record and the contiguous
//! stage file onto a FAT32 volume.
//!
//! [`install_loader`] loads the embedded VBR and core of a [`Family`]
//! and delegates to [`install_payloads`], the testable core over
//! explicit bytes: a present `/ldlinux.sys` refuses, one contiguous
//! cluster run is reserved ([`Fat32::allocate_contiguous`]), the
//! directory entry links at it ([`Fat32::link_file`]), the patched
//! core plus the ADV tail write at offset 0 ([`Fat32::write_at`]), the
//! patched VBR's boot code grafts onto the volume's boot sector
//! ([`Fat32::write_boot_code`]) and the pass flushes. [`super::patch`]
//! owns the byte patching (`syslinux_patch` plus the default ADV).
//! No logger, no messages: the return value carries the facts and the
//! caller logs, matching how the copy engine reports.

use super::Family;
use super::patch;
use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::load;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;
use crate::fs::fat32::bpb;

/// What [`install_payloads`] laid down: the family installed, the head
/// and length of its contiguous run, the core payload byte count, and
/// the stage file byte count (core plus the ADV tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    family: Family,
    first_cluster: u32,
    cluster_count: u32,
    core_bytes: u64,
    stage_bytes: u64,
}

impl Installed {
    /// The embedded family installed.
    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// Head cluster of the contiguous `/ldlinux.sys` run.
    #[must_use]
    pub fn first_cluster(&self) -> u32 {
        self.first_cluster
    }

    /// Clusters the run spans.
    #[must_use]
    pub fn cluster_count(&self) -> u32 {
        self.cluster_count
    }

    /// Byte count of the core payload (without the ADV tail).
    #[must_use]
    pub fn core_bytes(&self) -> u64 {
        self.core_bytes
    }

    /// Byte count of the stage file on the volume (core plus the
    /// 1024-byte ADV tail).
    #[must_use]
    pub fn stage_bytes(&self) -> u64 {
        self.stage_bytes
    }
}

/// Install the Syslinux loader of `family` onto `fat` from explicit
/// `vbr` and `core` bytes.
///
/// The steps run in this order: a present `/ldlinux.sys` refuses, the
/// volume sector size and payload lengths validate, one contiguous run
/// is reserved for the stage (core plus the 1024-byte ADV tail), the
/// directory entry links at it, the core and VBR patch for the file's
/// sector list, the patched core plus the ADV tail write at offset 0,
/// the patched VBR's boot code grafts onto the boot sector, and the
/// pass flushes. The allocation runs before the link so the run is
/// reserved before any directory entry points at it, and the graft
/// runs last — matching upstream — so a volume never carries Syslinux
/// boot code without its stage file.
///
/// The stage file is `core ++ 1024 bytes of ADV`: two identical
/// 512-byte sectors per `setadv.c:syslinux_reset_adv`, with the core's
/// sector map, sector pointers, ADV pointers, `"/"` directory string
/// and checksum patched over them (see [`patch::syslinux_patch`]).
/// FAT hidden/system/readonly attributes are intentionally not set:
/// the writer has no attribute API, and the loader does not need them.
///
/// The sector list is linear — `first_lba + i` — because the allocator
/// hands out a sequential cluster chain and [`Fat32::link_file`]
/// re-verifies that exact linkage before the entry lands.
///
/// A non-512-byte sector size refuses before any write: the ADV unit,
/// the `adv_sectors` count and the sector-pointer LBAs are all
/// 512-byte sectors, so patching one onto a 4Kn volume would mispoint
/// every address.
///
/// The only torn state is a stage file with no boot code: a failure
/// inside the stage write leaves an entry over a reserved run with
/// partial bytes, a failure after it leaves a complete stage file,
/// and neither carries boot code. Boot code without a stage file is
/// refused by ordering. The resume work of a later slice owns sweeping
/// the stage-side leftovers.
///
/// A present `/ldlinux.sys` refuses before any byte moves: this
/// installer has no unlink on [`Fat32`], so a second install could
/// neither replace nor remove the first and would leave an
/// unreferenced cluster run behind. The check reads `list_dir("/")`
/// and compares the dot-joined short name (`LDLINUX.SYS` — the user
/// text form, not the raw space-padded 8.3 field). Companions are
/// handled differently on purpose: they carry no sector map, so a
/// byte-identical file is provably the same payload and safe to keep,
/// while a stage file may hide another volume's sector map and is
/// never trusted that way.
///
/// The payload lengths validate before any byte moves: a `vbr` shorter
/// than a sector and a `core` of one sector or less (empty included)
/// refuse naming the lengths, so a swapped or truncated pair never
/// reaches the volume.
pub fn install_payloads(
    fat: &mut Fat32,
    family: Family,
    vbr: &[u8],
    core: &[u8],
) -> Result<Installed> {
    let present = fat
        .list_dir("/")?
        .iter()
        .any(|entry| entry.short_name == "LDLINUX.SYS");
    if present {
        return Err(CoreError::invalid(
            "ldlinux.sys is already present on the volume: this installer carries no unlink, \
             refusing a second install that would leave an unreferenced cluster run",
        ));
    }
    // The geometry's sector size is the volume's own: the formatter
    // cross-checks the store's `sector_size()` against it at format
    // time, so reading it here is the same refusal.
    let sector_bytes = u64::from(fat.geometry().bytes_per_sector);
    if sector_bytes != patch::SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "syslinux install needs 512 byte sectors for its adv and sector map, the volume carries {sector_bytes}: refusing"
        )));
    }
    let vbr_len = vbr.len();
    if vbr_len < bpb::BOOT_SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "syslinux vbr image is {vbr_len} bytes, a boot sector graft needs {} bytes: refusing",
            bpb::BOOT_SECTOR_BYTES
        )));
    }
    let core_len = u64::try_from(core.len())
        .map_err(|_| CoreError::invalid("a syslinux core longer than u64"))?;
    if core.len() <= bpb::BOOT_SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "syslinux core image is {} bytes, a stage file needs more than one sector ({} bytes): refusing",
            core.len(),
            bpb::BOOT_SECTOR_BYTES
        )));
    }
    let stage_len = core_len
        .checked_add(patch::ADV_BYTES as u64)
        .ok_or_else(|| CoreError::invalid("a syslinux stage longer than u64: refusing"))?;
    let (first_cluster, cluster_count) = fat.allocate_contiguous(stage_len)?;
    fat.link_file("/ldlinux.sys", first_cluster, stage_len)?;
    // Linear sector list over the reserved run: the allocator's chain
    // is sequential and the link just re-verified it.
    let run_base = fat.geometry().cluster_offset(first_cluster).ok_or_else(|| {
        CoreError::invalid(format!(
            "syslinux install: cluster {first_cluster} does not resolve on this volume: refusing"
        ))
    })?;
    if run_base % patch::SECTOR_BYTES != 0 {
        return Err(CoreError::invalid(format!(
            "syslinux install: cluster {first_cluster} sits at byte {run_base}, not a 512 byte sector edge: refusing"
        )));
    }
    let first_lba = run_base / patch::SECTOR_BYTES;
    let total = core_len.div_ceil(patch::SECTOR_BYTES) + patch::ADV_SECTORS;
    let sector_count = usize::try_from(total)
        .map_err(|_| CoreError::invalid("a syslinux sector list longer than usize: refusing"))?;
    let mut sectors = Vec::with_capacity(sector_count);
    for index in 0..total {
        let lba = first_lba
            .checked_add(index)
            .ok_or_else(|| CoreError::invalid("a syslinux sector lba overflows u64: refusing"))?;
        sectors.push(lba);
    }
    let patched = patch::syslinux_patch(core, vbr, &sectors, b"/")?;
    let adv = patch::default_adv();
    let mut stage = Vec::with_capacity(sector_count * patch::SECTOR_BYTES as usize);
    stage.extend_from_slice(&patched.core);
    stage.extend_from_slice(&adv);
    fat.write_at("/ldlinux.sys", 0, &stage)?;
    fat.write_boot_code(&patched.vbr)?;
    fat.flush()?;
    Ok(Installed {
        family,
        first_cluster,
        cluster_count,
        core_bytes: core_len,
        stage_bytes: stage_len,
    })
}

/// Install the Syslinux loader of `family` onto `fat`.
///
/// Loads the embedded VBR and core (verified against the manifest
/// pins) and delegates to [`install_payloads`], which carries the
/// ordering and torn-state contract.
pub fn install_loader(fat: &mut Fat32, family: Family) -> Result<Installed> {
    install_payloads_from(fat, family, &load)
}

/// Install the Syslinux loader of `family` onto `fat`, resolving the
/// embedded VBR and core through `load`.
///
/// The single loading path behind [`install_loader`] (which passes
/// [`load`](crate::boot::load)): callers that resolve payloads
/// differently — the pipeline passes its own closure so tests can
/// point it at the asset tree without the runtime asset directory —
/// inject that here instead of duplicating the two loads.
pub fn install_payloads_from(
    fat: &mut Fat32,
    family: Family,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    let vbr = load(family.vbr())?;
    let core = load(family.core())?;
    install_payloads(fat, family, vbr.bytes(), core.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::Resource;
    use crate::boot::load_from;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 64 MiB in bytes, the canonical small target here.
    const SIXTY_FOUR_MIB: u64 = 64 * 1024 * 1024;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution: the byte seam every test below
    /// reads through, so each one always executes.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// The pinned payload bytes of `resource`, read straight from the
    /// asset tree: the expected half of every byte comparison below.
    fn payload_bytes(resource: Resource) -> Vec<u8> {
        load_from(&resources_dir(), resource)
            .expect("the pinned payload loads")
            .bytes()
            .to_vec()
    }

    /// A [`Volume`] over shared bytes, so the tests can read sector 0
    /// and dump the image while [`Fat32`] owns the store: `Fat32`
    /// keeps its `Box<dyn Volume>` private and offers no raw-sector
    /// accessor of its own.
    #[derive(Debug, Clone)]
    struct SharedVolume {
        bytes: Rc<RefCell<Vec<u8>>>,
        sector_size: u32,
    }

    impl SharedVolume {
        fn blank(len: u64) -> Self {
            Self::blank_with_sector_size(len, 512)
        }

        fn blank_with_sector_size(len: u64, sector_size: u32) -> Self {
            let size = usize::try_from(len).expect("the ram size fits usize");
            Self {
                bytes: Rc::new(RefCell::new(vec![0u8; size])),
                sector_size,
            }
        }

        /// A copy of the first 512 bytes (the boot sector under test).
        fn boot_sector(&self) -> [u8; 512] {
            let borrowed = self.bytes.borrow();
            let window = borrowed.get(..512).expect("the image holds a boot sector");
            let mut sector = [0u8; 512];
            sector.copy_from_slice(window);
            sector
        }
    }

    impl Volume for SharedVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.borrow().len() as u64
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let borrowed = self.bytes.borrow();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get(start..end).expect("the test read fits");
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            let mut borrowed = self.bytes.borrow_mut();
            let start = usize::try_from(offset).expect("the test offset fits usize");
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, Fat32) {
        let backing = SharedVolume::blank(SIXTY_FOUR_MIB);
        let fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        (backing, fat)
    }

    fn le16(bytes: &[u8], at: usize) -> u16 {
        let window = bytes.get(at..at + 2).expect("the test window fits");
        u16::from_le_bytes([window[0], window[1]])
    }

    fn le32(bytes: &[u8], at: usize) -> u32 {
        let window = bytes.get(at..at + 4).expect("the test window fits");
        u32::from_le_bytes([window[0], window[1], window[2], window[3]])
    }

    fn le64(bytes: &[u8], at: usize) -> u64 {
        let window = bytes.get(at..at + 8).expect("the test window fits");
        u64::from_le_bytes([
            window[0], window[1], window[2], window[3], window[4], window[5], window[6], window[7],
        ])
    }

    /// Pin contiguity from the raw image bytes, independently of the
    /// return value: walk the first FAT copy at `first_cluster` and
    /// require sequential links ending in an end-of-chain marker, then
    /// require the stage bytes verbatim at the linear data-area offset
    /// (sequential cluster numbers are contiguous image bytes, so the
    /// verbatim span proves the linear placement too).
    fn assert_run_is_contiguous(
        backing: &SharedVolume,
        fat: &Fat32,
        first: u32,
        count: u32,
        stage: &[u8],
    ) {
        let geometry = fat.geometry();
        let fat_start = u64::from(geometry.reserved_sectors) * u64::from(geometry.bytes_per_sector);
        let image = backing.bytes.borrow();
        for offset in 0..count {
            let cluster = first.checked_add(offset).expect("the cluster numbers fit");
            let at = usize::try_from(fat_start + u64::from(cluster) * 4)
                .expect("the fat window fits usize");
            let window = image.get(at..at + 4).expect("the fat entry fits");
            let raw = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            if offset.checked_add(1).expect("the link count fits") < count {
                let next = cluster.checked_add(1).expect("the next cluster fits");
                assert_eq!(
                    raw, next,
                    "cluster {cluster} links to the next cluster, not {raw:#010x}"
                );
            } else {
                assert!(
                    raw >= 0x0FFF_FFF8,
                    "cluster {cluster} closes with end-of-chain, not {raw:#010x}"
                );
            }
        }
        let base = usize::try_from(
            geometry
                .cluster_offset(first)
                .expect("the run head resolves on the volume"),
        )
        .expect("the data offset fits usize");
        let window = image
            .get(base..base + stage.len())
            .expect("the stage span fits the image");
        assert_eq!(
            window, stage,
            "the stage bytes sit verbatim at the run head"
        );
    }

    /// Per-family patch pins: the sector totals, the EPA field offsets
    /// from the spec, and the data extents as `(first-relative start,
    /// length)` pairs.
    struct FamilyPins {
        total: u64,
        data_sectors: u16,
        dwords: u32,
        epa_offset: usize,
        advptr_offset: usize,
        dir_offset: usize,
        extents: Vec<(u64, u16)>,
    }

    fn pins_for(family: Family) -> FamilyPins {
        match family {
            Family::V407 => FamilyPins {
                total: 74,
                data_sectors: 72,
                dwords: 9122,
                epa_offset: 0x30a6,
                advptr_offset: 0x3798,
                dir_offset: 0x30bc,
                extents: vec![(1, 71)],
            },
            Family::V604 => FamilyPins {
                total: 136,
                data_sectors: 134,
                dwords: 17030,
                epa_offset: 0x1446,
                advptr_offset: 0x16d8,
                dir_offset: 0x145c,
                extents: vec![(1, 127), (128, 6)],
            },
        }
    }

    /// The shared install proof both families run: the boot sector
    /// carries the patched payload entry, the volume geometry and the
    /// payload code under the `0x55AA` signature with the file's first
    /// LBA at the VBR pointers; `/ldlinux.sys` is the patched core
    /// plus the exact ADV tail, reads back byte-identical over a
    /// contiguous run, and the geometry is untouched.
    fn proves_install(backing: &SharedVolume, fat: &mut Fat32, family: Family) {
        let pins = pins_for(family);
        let before_sector = backing.boot_sector();
        let before_geometry = *fat.geometry();
        let vbr = payload_bytes(family.vbr());
        let core = payload_bytes(family.core());
        let installed = install_payloads(fat, family, &vbr, &core).expect("the install runs");
        assert_eq!(installed.family(), family);
        assert_eq!(installed.core_bytes(), core.len() as u64);
        let stage_len = core.len() + patch::ADV_BYTES;
        assert_eq!(
            installed.stage_bytes(),
            stage_len as u64,
            "the stage adds the adv tail to the payload"
        );

        let first_lba = before_geometry
            .cluster_offset(installed.first_cluster())
            .expect("the head resolves")
            / patch::SECTOR_BYTES;

        // Boot sector: the grafted patched VBR. The pointers name the
        // file's first LBA and every other byte matches the graft of
        // the payload VBR with those two words replaced.
        let after_sector = backing.boot_sector();
        assert_eq!(
            &after_sector[0..11],
            &vbr[0..11],
            "the payload jump and OEM name win"
        );
        assert_eq!(
            2 + u16::from(after_sector[1]),
            0x5A,
            "the jump lands on the code at 0x5A"
        );
        assert_eq!(
            &after_sector[11..90],
            &before_sector[11..90],
            "the volume geometry survives the graft"
        );
        assert_eq!(
            &after_sector[90..0x11a],
            &vbr[90..0x11a],
            "the boot code before the pointers is the payload's"
        );
        assert_eq!(
            le32(&after_sector, 0x11a),
            first_lba as u32,
            "the low pointer names the first lba"
        );
        assert_eq!(
            le32(&after_sector, 0x120),
            0,
            "the high pointer is zero on this volume"
        );
        assert_eq!(
            &after_sector[0x11e..0x120],
            &vbr[0x11e..0x120],
            "the gap between the pointers is the payload's"
        );
        assert_eq!(
            &after_sector[0x124..510],
            &vbr[0x124..510],
            "the boot code past the pointers is the payload's"
        );
        assert_eq!(
            &after_sector[510..],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );
        // The backup boot sector mirrors the grafted primary,
        // matching WritePBR's two-pass loop (src/format.c): without it
        // fsck.fat -v reports differences between the boot sector and
        // its backup.
        {
            let image = backing.bytes.borrow();
            let primary = image.get(..512).expect("the primary sector fits");
            let backup = image.get(6 * 512..7 * 512).expect("the backup sector fits");
            assert_eq!(
                backup, primary,
                "the backup boot sector mirrors the primary"
            );
        }

        let listed = fat.list_dir("/").expect("the root lists");
        let entry = listed
            .iter()
            .find(|entry| entry.short_name == "LDLINUX.SYS")
            .expect("ldlinux.sys is listed");
        assert_eq!(entry.size_bytes, stage_len as u64, "the listed size");
        assert_eq!(
            entry.first_cluster,
            installed.first_cluster(),
            "the entry points at the reserved run"
        );
        let cluster_bytes = fat.geometry().cluster_bytes();
        assert_eq!(
            u64::from(installed.cluster_count()),
            (stage_len as u64).div_ceil(cluster_bytes),
            "the run spans the rounded-up stage"
        );

        // On-disk stage: the patched core plus the exact ADV tail.
        let on_disk = fat.read_file("/ldlinux.sys").expect("the stage reads back");
        assert_eq!(on_disk.len(), stage_len, "the file is core plus adv");
        assert_eq!(
            &on_disk[core.len()..],
            &patch::default_adv(),
            "the tail is exactly the default adv"
        );
        let patched = &on_disk[..core.len()];

        // Patch-area counts and EPA offsets pin the family.
        assert_eq!(
            le32(patched, 0x18),
            patch::LDLINUX_MAGIC,
            "the magic survives the patch"
        );
        assert_eq!(
            le16(patched, 0x18 + 0x08),
            pins.data_sectors,
            "data sectors"
        );
        assert_eq!(le16(patched, 0x18 + 0x0A), 2, "adv sectors");
        assert_eq!(le32(patched, 0x18 + 0x0C), pins.dwords, "dwords");
        assert_eq!(
            le16(patched, 0x18 + 0x16),
            pins.epa_offset as u16,
            "the epa offset is untouched"
        );
        let epa = pins.epa_offset;
        assert_eq!(
            le16(patched, epa),
            pins.advptr_offset as u16,
            "advptroffset"
        );
        assert_eq!(le16(patched, epa + 2), pins.dir_offset as u16, "diroffset");
        assert_eq!(le16(patched, epa + 4), 0x100, "dirlen");
        assert_eq!(le16(patched, epa + 10), 0x1ee, "secptroffset");
        assert_eq!(le16(patched, epa + 12), 192, "secptrcnt");

        // Directory holds "/" plus NUL.
        assert_eq!(
            &patched[pins.dir_offset..pins.dir_offset + 2],
            b"/\x00",
            "the subdirectory"
        );

        // ADV pointers name the last two sectors of the list.
        assert_eq!(
            le64(patched, pins.advptr_offset),
            first_lba + pins.total - 2,
            "first adv lba"
        );
        assert_eq!(
            le64(patched, pins.advptr_offset + 8),
            first_lba + pins.total - 1,
            "second adv lba"
        );

        // Sector map: the expected extents, reconstructed back into
        // the sector list, with zeros past the written entries.
        let mut expanded: Vec<u64> = Vec::new();
        for (index, (start, len)) in pins.extents.iter().enumerate() {
            let at = 0x1ee + index * 10;
            assert_eq!(le64(patched, at), first_lba + start, "extent {index} lba");
            assert_eq!(le16(patched, at + 8), *len, "extent {index} length");
            for step in 0..*len {
                expanded.push(first_lba + start + u64::from(step));
            }
        }
        let expected: Vec<u64> = (1..pins.total - 2).map(|step| first_lba + step).collect();
        assert_eq!(expanded, expected, "the map rebuilds the data sectors");
        let written = pins.extents.len() * 10;
        assert!(
            patched[0x1ee + written..0x1ee + 1920]
                .iter()
                .all(|&byte| byte == 0),
            "the map past the written entries stays zero"
        );

        // Checksum recomputed independently: zero the field, subtract
        // every covered dword from the magic, wrapping.
        let mut probe = patched.to_vec();
        probe[0x18 + 0x10..0x18 + 0x14].copy_from_slice(&0u32.to_le_bytes());
        let mut checksum = patch::LDLINUX_MAGIC;
        for index in 0..pins.dwords as usize {
            checksum = checksum.wrapping_sub(le32(&probe, index * 4));
        }
        assert_eq!(le32(patched, 0x18 + 0x10), checksum, "the checksum");

        // Nothing else in the core moved: every byte outside the patch
        // area, the map, the ADV pointers and the directory matches.
        let mut touched = vec![false; core.len()];
        for window in [
            0x18..0x18 + 0x18,
            0x1ee..0x1ee + 1920,
            pins.advptr_offset..pins.advptr_offset + 16,
            pins.dir_offset..pins.dir_offset + 0x100,
        ] {
            if let Some(area) = touched.get_mut(window) {
                area.fill(true);
            }
        }
        for (at, (&was, &is)) in core.iter().zip(patched.iter()).enumerate() {
            if !touched[at] {
                assert_eq!(is, was, "an unpatched byte moved at {at}");
            }
        }

        assert_run_is_contiguous(
            backing,
            fat,
            installed.first_cluster(),
            installed.cluster_count(),
            &on_disk,
        );

        assert_eq!(
            fat.geometry(),
            &before_geometry,
            "the install moves no geometry"
        );
    }

    #[test]
    fn install_604_lays_boot_code_and_stage_file() {
        let (backing, mut fat) = formatted();
        proves_install(&backing, &mut fat, Family::V604);
        // The 6.04 core is the 68121-byte resource 403.
        let core = payload_bytes(Resource::Syslinux604Core);
        assert_eq!(core.len(), 68121, "resource 403 keeps its pinned size");
    }

    #[test]
    fn install_407_lays_boot_code_and_stage_file() {
        let (backing, mut fat) = formatted();
        proves_install(&backing, &mut fat, Family::V407);
        // The 4.07 core is the 36488-byte resource 401.
        let core = payload_bytes(Resource::Syslinux407Core);
        assert_eq!(core.len(), 36488, "resource 401 keeps its pinned size");
    }

    #[test]
    fn second_install_is_refused() {
        let (_backing, mut fat) = formatted();
        let vbr = payload_bytes(Family::V604.vbr());
        let core = payload_bytes(Family::V604.core());
        let installed =
            install_payloads(&mut fat, Family::V604, &vbr, &core).expect("the first install runs");
        let _ = installed;
        let error = install_payloads(&mut fat, Family::V604, &vbr, &core)
            .expect_err("a second install refuses");
        let text = error.to_string();
        assert!(
            text.contains("ldlinux.sys"),
            "the refusal names the file: {text}"
        );
        assert!(text.is_ascii(), "the refusal stays ASCII: {text:?}");
    }

    #[test]
    fn short_payloads_are_refused_by_length() {
        let (_backing, mut fat) = formatted();
        let vbr = payload_bytes(Family::V604.vbr());
        let core = payload_bytes(Family::V604.core());
        // A 512-byte core (a swapped VBR, say) refuses naming its
        // length, and an empty one refuses too — neither is silently
        // accepted as a stage file.
        let short_core = vec![0u8; bpb::BOOT_SECTOR_BYTES];
        let error = install_payloads(&mut fat, Family::V604, &vbr, &short_core)
            .expect_err("a 512-byte core refuses");
        let text = error.to_string();
        assert!(
            text.contains(&short_core.len().to_string()),
            "the refusal names the core length: {text}"
        );
        let empty: Vec<u8> = Vec::new();
        let error = install_payloads(&mut fat, Family::V604, &vbr, &empty)
            .expect_err("an empty core refuses");
        assert!(
            error.to_string().contains("0 bytes"),
            "the refusal names the empty length: {text}"
        );
        // A short VBR refuses before any byte moves: the root stays
        // empty, so no stage file is left behind.
        let short_vbr = vec![0u8; bpb::BOOT_SECTOR_BYTES - 1];
        let error = install_payloads(&mut fat, Family::V604, &short_vbr, &core)
            .expect_err("a 511-byte vbr refuses");
        let text = error.to_string();
        assert!(
            text.contains(&short_vbr.len().to_string()),
            "the refusal names the vbr length: {text}"
        );
        assert!(
            text.contains(&bpb::BOOT_SECTOR_BYTES.to_string()),
            "the refusal names the needed length: {text}"
        );
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(
            listed.is_empty(),
            "a refused vbr leaves no stage file behind"
        );
    }

    #[test]
    fn non_512_byte_sectors_are_refused_before_any_write() {
        // A 4Kn volume formats but never installs: the ADV unit, the
        // adv_sectors count and the sector-pointer LBAs are all
        // 512-byte sectors, so patching one would mispoint every
        // address. The refusal lands before any write, so the root
        // stays empty.
        let backing = SharedVolume::blank_with_sector_size(300 * 1024 * 1024, 4096);
        let mut fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the 4kn volume formats");
        assert_eq!(
            fat.geometry().bytes_per_sector,
            4096,
            "the volume really is 4kn"
        );
        let vbr = payload_bytes(Family::V604.vbr());
        let core = payload_bytes(Family::V604.core());
        let error = install_payloads(&mut fat, Family::V604, &vbr, &core)
            .expect_err("a 4kn install refuses");
        let text = error.to_string();
        assert!(text.contains("512"), "names the needed size: {text}");
        assert!(text.contains("4096"), "names the volume size: {text}");
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
        let listed = fat.list_dir("/").expect("the root lists");
        assert!(listed.is_empty(), "a refused install writes nothing");
    }

    #[test]
    fn installed_volume_is_fsck_clean() {
        // Acceptance over the real checker: the image dumps to a
        // tempfile and `fsck.fat -n -v` (read-only: `-n` answers no to
        // every repair prompt) must exit 0 without reporting
        // differences between the boot sector and its backup — the
        // verbose flag matters, since without it the checker exits 0
        // over a stale backup silently. The tool resolves through
        // `PATH` (never a hardcoded path); when it is absent the test
        // skips. A checker that objects to the Syslinux boot code is a
        // real finding: report it, never work around it.
        let (backing, mut fat) = formatted();
        let vbr = payload_bytes(Family::V604.vbr());
        let core = payload_bytes(Family::V604.core());
        let installed =
            install_payloads(&mut fat, Family::V604, &vbr, &core).expect("the install runs");
        let _ = installed;
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("syslinux.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg("-v")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skip: the fsck acceptance needs fsck.fat on PATH ({error})");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !format!("{stdout}\n{stderr}")
                .contains("differences between boot sector and its backup"),
            "fsck.fat -v reports no boot/backup difference after the install: stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
}
