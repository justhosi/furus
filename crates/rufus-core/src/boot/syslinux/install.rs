//! The Syslinux loader install: the boot record and the contiguous
//! stage file onto a FAT32 volume.
//!
//! [`install_loader`] loads the embedded VBR and core of a [`Family`]
//! and delegates to [`install_payloads`], the testable core over
//! explicit bytes: a present `/ldlinux.sys` refuses, one contiguous
//! cluster run is reserved ([`Fat32::allocate_contiguous`]), the
//! directory entry links at it ([`Fat32::link_file`]), the core bytes
//! write at offset 0 ([`Fat32::write_at`]), the VBR's boot code grafts
//! onto the volume's boot sector ([`Fat32::write_boot_code`]) and the
//! pass flushes. No logger, no messages: the return value carries the
//! facts and the caller logs, matching how the copy engine reports.

use super::Family;
use crate::boot::load;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;
use crate::fs::fat32::bpb;

/// What [`install_payloads`] laid down: the family installed, the head
/// and length of its contiguous run, and the core's byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    family: Family,
    first_cluster: u32,
    cluster_count: u32,
    core_bytes: u64,
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

    /// Byte count of the core (`/ldlinux.sys` size on the volume).
    #[must_use]
    pub fn core_bytes(&self) -> u64 {
        self.core_bytes
    }
}

/// Install the Syslinux loader of `family` onto `fat` from explicit
/// `vbr` and `core` bytes.
///
/// The steps run in this order: a present `/ldlinux.sys` refuses, the
/// payload lengths validate, one contiguous run is reserved for the
/// core, the directory entry links at it, the core bytes write at
/// offset 0, the VBR's boot code grafts onto the boot sector, and the
/// pass flushes. The allocation runs before the link so the run is
/// reserved before any directory entry points at it, and the graft
/// runs last — matching upstream, and matching the later sector-map
/// patch which needs the file in place — so a volume never carries
/// Syslinux boot code without its stage file.
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
/// text form, not the raw space-padded 8.3 field).
///
/// The payload lengths validate before any byte moves: a `vbr` shorter
/// than a sector and a `core` of one sector or less (empty included)
/// refuse naming the lengths, so a swapped or truncated pair never
/// reaches the volume.
///
/// This installer writes the payload length exactly: the ADV /
/// sector-map tail layout (upstream writes `ldlinux.sys` plus
/// `2 * ADV_SIZE` before patching) is settled by the next slice.
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
            "syslinux core image is {} bytes, refusing a core of one sector or less ({} bytes): refusing",
            core.len(),
            bpb::BOOT_SECTOR_BYTES
        )));
    }
    let (first_cluster, cluster_count) = fat.allocate_contiguous(core_len)?;
    fat.link_file("/ldlinux.sys", first_cluster, core_len)?;
    fat.write_at("/ldlinux.sys", 0, core)?;
    fat.write_boot_code(vbr)?;
    fat.flush()?;
    Ok(Installed {
        family,
        first_cluster,
        cluster_count,
        core_bytes: core_len,
    })
}

/// Install the Syslinux loader of `family` onto `fat`.
///
/// Loads the embedded VBR and core (verified against the manifest
/// pins) and delegates to [`install_payloads`], which carries the
/// ordering and torn-state contract.
pub fn install_loader(fat: &mut Fat32, family: Family) -> Result<Installed> {
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
    }

    impl SharedVolume {
        fn blank(len: u64) -> Self {
            let size = usize::try_from(len).expect("the ram size fits usize");
            Self {
                bytes: Rc::new(RefCell::new(vec![0u8; size])),
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

    /// Pin contiguity from the raw image bytes, independently of the
    /// return value: walk the first FAT copy at `first_cluster` and
    /// require sequential links ending in an end-of-chain marker, then
    /// require the core bytes verbatim at the linear data-area offset
    /// (sequential cluster numbers are contiguous image bytes, so the
    /// verbatim span proves the linear placement too).
    fn assert_run_is_contiguous(
        backing: &SharedVolume,
        fat: &Fat32,
        first: u32,
        count: u32,
        core: &[u8],
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
            .get(base..base + core.len())
            .expect("the core span fits the image");
        assert_eq!(window, core, "the core bytes sit verbatim at the run head");
    }

    /// The shared install proof both families run: the boot sector
    /// carries the payload entry, the volume geometry and the payload
    /// code under the `0x55AA` signature, `/ldlinux.sys` lists with the
    /// core's size and reads back byte-identical over a contiguous run,
    /// and the geometry is untouched.
    fn proves_install(backing: &SharedVolume, fat: &mut Fat32, family: Family) {
        let before_sector = backing.boot_sector();
        let before_geometry = *fat.geometry();
        let vbr = payload_bytes(family.vbr());
        let core = payload_bytes(family.core());
        let installed = install_payloads(fat, family, &vbr, &core).expect("the install runs");
        assert_eq!(installed.family(), family);
        assert_eq!(installed.core_bytes(), core.len() as u64);

        let after_sector = backing.boot_sector();
        assert_eq!(
            &after_sector[0..11],
            &vbr[0..11],
            "the payload jump and OEM name win"
        );
        assert_eq!(
            &after_sector[0..3],
            &vbr[0..3],
            "the entry point is the payload's, never the formatter's"
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
            &after_sector[90..510],
            &vbr[90..510],
            "the boot code comes from the family VBR"
        );
        assert_eq!(
            &after_sector[510..],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );

        let listed = fat.list_dir("/").expect("the root lists");
        let entry = listed
            .iter()
            .find(|entry| entry.short_name == "LDLINUX.SYS")
            .expect("ldlinux.sys is listed");
        assert_eq!(entry.size_bytes, core.len() as u64, "the listed size");
        assert_eq!(
            entry.first_cluster,
            installed.first_cluster(),
            "the entry points at the reserved run"
        );
        let cluster_bytes = fat.geometry().cluster_bytes();
        assert_eq!(
            u64::from(installed.cluster_count()),
            (core.len() as u64).div_ceil(cluster_bytes),
            "the run spans the rounded-up core"
        );
        assert_run_is_contiguous(
            backing,
            fat,
            installed.first_cluster(),
            installed.cluster_count(),
            &core,
        );
        let read_back = fat.read_file("/ldlinux.sys").expect("the core reads back");
        assert_eq!(
            read_back, core,
            "the stage file is the payload byte for byte"
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
            error.to_string().contains('0'),
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
    fn installed_volume_is_fsck_clean() {
        // Acceptance over the real checker: the image dumps to a
        // tempfile and `fsck.fat -n` (read-only: `-n` answers no to
        // every repair prompt) must exit 0. The tool resolves through
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
            output.status.success(),
            "fsck.fat -n exits 0 after the install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
}
