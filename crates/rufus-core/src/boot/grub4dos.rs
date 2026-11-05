//! GRUB4DOS install: the 423-byte MBR window at disk offset 0, the
//! SBR past it, and the `grldr` loader at the volume root.
//!
//! ms-sys `write_grub4dos_mbr` (`src/ms-sys/br.c:365-372`) writes
//! `mbr_grub_0x0` (423 bytes, header comment: `First 423 bytes of MBR
//! from Grub4DOS (Converted from res/grub/grldr.mbr)`) at offset 0,
//! then the boot mark (`55 AA` at 510). The partition table area
//! (`423..510`) is untouched. Rufus `WriteSBR` (`src/format.c:900-976`)
//! takes the GRUB4DOS branch for resource 450 (`grldr.mbr`), refuses
//! `size <= 0x200` with the literal
//! `grldr.mbr is either not present or too small`, then skips the
//! first 512 bytes (`buf += 0x200; size -= 0x200`) and writes the
//! remainder at offset `0x200`.
//!
//! The first sector of asset `RCDATA_450.bin` is byte-identical to
//! `mbr_grub_0x0` for `0..423`, carries zeros in `423..510` and
//! `55 AA` at 510; asset bytes `512..8192` are the SBR. Resource 451
//! (`RCDATA_451.bin`, manifest name `grldr`) is the loader Rufus
//! copies to the volume root (`?:\\grldr`, `src/format.c:1464,
//! 1940-1945`; log `Installing: %s (Grub4DOS loader) %s`).
//!
//! Upstream Rufus never writes `menu.lst` (a grep of `src/` finds no
//! `menu.lst` anywhere), so this installer deliberately writes none
//! either: inventing one would boot a menu upstream never ships.
//!
//! [`install_boot`] needs a 512-byte-sector disk and writes the MBR
//! window plus the SBR; [`install_loader`] needs a FAT32 volume and
//! writes `/grldr`; [`install`] loads both payloads from the runtime
//! asset directory and delegates. `install_boot` itself only checks
//! the SBR against the disk end — the pipeline bounds it against the
//! Mkpart-planned post-MBR gap before calling, so a record can never
//! reach into the first partition.

use crate::boot::Resource;
use crate::boot::load;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::fs::fat32::Fat32;

/// Bytes of `grldr.mbr` the MBR window carries: ms-sys's 423-byte
/// `mbr_grub_0x0` (`src/ms-sys/br.c:365-372`).
pub const MBR_BYTES: usize = 423;

/// Sector size this installer writes: the MBR window, the SBR offset
/// and the boot mark are all 512-byte-sector geometry.
pub const SECTOR_BYTES: usize = 512;

/// Byte offset the SBR writes at: past the MBR sector, matching
/// `WriteSBR`'s `0x200` write.
pub const SBR_OFFSET: u64 = 512;

/// Loader path on the volume: the root `grldr` Rufus copies to
/// `?:\\grldr`.
pub const GRLDR_PATH: &str = "/grldr";

/// What [`install_boot`] wrote: the MBR-window byte count and the SBR
/// byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInstalled {
    mbr_bytes: usize,
    sbr_bytes: usize,
}

impl BootInstalled {
    /// Bytes of the MBR window landed at disk offset 0 (always
    /// [`MBR_BYTES`]).
    #[must_use]
    pub fn mbr_bytes(&self) -> usize {
        self.mbr_bytes
    }

    /// Bytes of the SBR landed at [`SBR_OFFSET`].
    #[must_use]
    pub fn sbr_bytes(&self) -> usize {
        self.sbr_bytes
    }
}

/// Install the GRUB4DOS boot record onto `disk` from explicit
/// `grldr_mbr` bytes (resource 450: one 512-byte MBR sector plus the
/// SBR behind it).
///
/// The steps run in this order: a non-512-byte sector size refuses, a
/// `grldr.mbr` of one sector or less refuses, an SBR that would run
/// past the disk end refuses, the current sector 0 is read so the
/// disk signature and partition table survive, the new sector 0 is
/// built in memory (`payload[0..423]`, current `423..510`, `55 AA` at
/// 510), the SBR (`payload[512..]`) writes at [`SBR_OFFSET`] first,
/// sector 0 writes last, and the pass flushes once.
///
/// The write order deliberately diverges from Rufus (which writes the
/// MBR first): writing the boot code last preserves the project rule
/// "never boot code without its payload" — a stray SBR under the old
/// MBR is inert, while a new MBR over a missing SBR would point at
/// garbage.
pub fn install_boot(disk: &mut dyn Volume, grldr_mbr: &[u8]) -> Result<BootInstalled> {
    let sector_size = disk.sector_size();
    if sector_size != 512 {
        return Err(CoreError::invalid(format!(
            "grub4dos install needs 512 byte sectors, the disk reports {sector_size}: refusing"
        )));
    }
    let mbr_len = grldr_mbr.len();
    if mbr_len <= SECTOR_BYTES {
        return Err(CoreError::invalid(format!(
            "grub4dos grldr.mbr is either not present or too small: {mbr_len} bytes: refusing"
        )));
    }
    let sbr_len = mbr_len
        .checked_sub(SECTOR_BYTES)
        .ok_or_else(|| CoreError::invalid("grub4dos sbr length underflows: refusing"))?;
    let sbr_len_u64 = u64::try_from(sbr_len)
        .map_err(|_| CoreError::invalid("a grub4dos sbr longer than u64: refusing"))?;
    let sbr_end = SBR_OFFSET
        .checked_add(sbr_len_u64)
        .ok_or_else(|| CoreError::invalid("a grub4dos sbr end overflows u64: refusing"))?;
    let total = disk.total_bytes();
    if sbr_end > total {
        return Err(CoreError::invalid(format!(
            "grub4dos sbr of {sbr_len} bytes at offset {SBR_OFFSET} ends at {sbr_end}, past the {total} byte disk: refusing"
        )));
    }
    let mut current = [0u8; SECTOR_BYTES];
    disk.read_exact_at(0, &mut current)?;
    let mut sector = [0u8; SECTOR_BYTES];
    let head = grldr_mbr
        .get(..MBR_BYTES)
        .ok_or_else(|| CoreError::invalid("grub4dos mbr lost its record window: refusing"))?;
    let kept = current.get(MBR_BYTES..510).ok_or_else(|| {
        CoreError::invalid("grub4dos disk sector lost its signature window: refusing")
    })?;
    sector
        .get_mut(..MBR_BYTES)
        .ok_or_else(|| CoreError::invalid("grub4dos sector lost its record window: refusing"))?
        .copy_from_slice(head);
    sector
        .get_mut(MBR_BYTES..510)
        .ok_or_else(|| CoreError::invalid("grub4dos sector lost its signature window: refusing"))?
        .copy_from_slice(kept);
    sector
        .get_mut(510..512)
        .ok_or_else(|| CoreError::invalid("grub4dos sector lost its boot mark: refusing"))?
        .copy_from_slice(&[0x55, 0xAA]);
    let sbr = grldr_mbr
        .get(SECTOR_BYTES..)
        .ok_or_else(|| CoreError::invalid("grub4dos mbr lost its sbr window: refusing"))?;
    disk.write_all_at(SBR_OFFSET, sbr)?;
    disk.write_all_at(0, &sector)?;
    disk.flush()?;
    Ok(BootInstalled {
        mbr_bytes: MBR_BYTES,
        sbr_bytes: sbr_len,
    })
}

/// What [`install_loader`] wrote: the loader byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderInstalled {
    bytes: usize,
}

impl LoaderInstalled {
    /// Bytes of `grldr` landed at [`GRLDR_PATH`].
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Install the GRUB4DOS loader onto `fat` from explicit `grldr` bytes
/// (resource 451).
///
/// Refuses an empty image, refuses an existing root `GRLDR` (the root
/// listing compared on the dot-joined short name, like
/// `syslinux::install`'s `LDLINUX.SYS` check), then `create_file` plus
/// a zero-offset `write_at` and one `flush()`.
pub fn install_loader(fat: &mut Fat32, grldr: &[u8]) -> Result<LoaderInstalled> {
    if grldr.is_empty() {
        return Err(CoreError::invalid(
            "grub4dos grldr is empty (0 bytes): refusing".to_string(),
        ));
    }
    let present = fat
        .list_dir("/")?
        .iter()
        .any(|entry| entry.short_name == "GRLDR");
    if present {
        return Err(CoreError::invalid(
            "grldr is already present on the volume: refusing to overwrite it",
        ));
    }
    let len = u64::try_from(grldr.len())
        .map_err(|_| CoreError::invalid("a grub4dos grldr longer than u64: refusing"))?;
    fat.create_file(GRLDR_PATH, len)?;
    fat.write_at(GRLDR_PATH, 0, grldr)?;
    fat.flush()?;
    Ok(LoaderInstalled { bytes: grldr.len() })
}

/// What [`install`] wrote: the boot record and the loader reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    boot: BootInstalled,
    loader: LoaderInstalled,
}

impl Installed {
    /// The boot-record report from [`install_boot`].
    #[must_use]
    pub fn boot(&self) -> BootInstalled {
        self.boot
    }

    /// The loader report from [`install_loader`].
    #[must_use]
    pub fn loader(&self) -> LoaderInstalled {
        self.loader
    }
}

/// Install GRUB4DOS onto `disk` (MBR window plus SBR) and `fat` (the
/// root loader).
///
/// Loads resource 450 (`grldr.mbr`) and 451 (`grldr`) through
/// [`load`] — which needs the runtime asset directory — and delegates
/// to [`install_loader`] and [`install_boot`], which carry the
/// ordering contracts. The loader lands first for exactly the torn
/// rule [`install_boot`] states: a failure leaves at most an inert
/// `/grldr`, never boot code without its payload. That is the reverse
/// of Rufus's call order, the same way [`install_boot`]'s own
/// sector-last order already reverses Rufus's MBR-first writes.
/// Tests use those two directly with bytes from
/// [`load_from`](crate::boot::load_from) instead (the same seam slice
/// 3's installer tests use).
pub fn install(disk: &mut dyn Volume, fat: &mut Fat32) -> Result<Installed> {
    let mbr = load(Resource::Grub4DosMbr)?;
    let grldr = load(Resource::Grub4DosCore)?;
    let loader = install_loader(fat, grldr.bytes())?;
    let boot = install_boot(disk, mbr.bytes())?;
    Ok(Installed { boot, loader })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::load_from;
    use crate::fs::VecVolume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution: every test below always executes.
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    /// The pinned payload bytes of `resource`, read straight from the
    /// asset tree.
    fn payload_bytes(resource: Resource) -> Vec<u8> {
        load_from(&resources_dir(), resource)
            .expect("the pinned payload loads")
            .bytes()
            .to_vec()
    }

    /// A 1 MiB disk prefilled with a recognisable pattern.
    fn prefilled_disk() -> VecVolume {
        let mut disk = VecVolume::new(1024 * 1024, 512).expect("the disk allocates");
        let filler: Vec<u8> = (0..1024 * 1024)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        disk.write_all_at(0, &filler).expect("the prefill lands");
        disk
    }

    #[test]
    fn install_boot_pins_every_window() {
        let mut disk = prefilled_disk();
        let before = disk.bytes().to_vec();
        let mbr = payload_bytes(Resource::Grub4DosMbr);
        assert_eq!(mbr.len(), 8192, "resource 450 keeps its 8192 bytes");
        let done = install_boot(&mut disk, &mbr).expect("the install runs");
        assert_eq!(done.mbr_bytes(), 423, "the mbr window is 423 bytes");
        assert_eq!(
            done.sbr_bytes(),
            8192 - 512,
            "the sbr is the payload past sector 0"
        );
        let after = disk.bytes().to_vec();
        assert_eq!(&after[..423], &mbr[..423], "0..423 is the payload window");
        assert_eq!(
            &after[423..510],
            &before[423..510],
            "423..510 keeps signature and partition table"
        );
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the boot mark closes the sector"
        );
        assert_eq!(
            &after[512..8192],
            &mbr[512..],
            "the sbr lands whole at offset 512"
        );
        assert_eq!(
            &after[8192..],
            &before[8192..],
            "every byte past 8192 is untouched"
        );
    }

    #[test]
    fn install_boot_refusals_name_their_numbers() {
        let mbr = payload_bytes(Resource::Grub4DosMbr);
        // Exactly one sector: the reference literal plus the length.
        let mut disk = prefilled_disk();
        let one_sector = mbr[..512].to_vec();
        let error = install_boot(&mut disk, &one_sector).expect_err("512 bytes refuse");
        let text = error.to_string();
        assert!(
            text.contains("grldr.mbr is either not present or too small"),
            "the reference literal: {text}"
        );
        assert!(text.contains("512"), "names the length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        // Empty: the same literal, naming 0.
        let error = install_boot(&mut disk, &[]).expect_err("empty refuses");
        let text = error.to_string();
        assert!(
            text.contains("grldr.mbr is either not present or too small"),
            "the reference literal: {text}"
        );
        assert!(text.contains("0 bytes"), "names the empty length: {text}");
        // A 4Kn disk: refused before any write, image identical after.
        let mut wide = VecVolume::new(8192, 4096).expect("the 4kn disk allocates");
        let before = wide.bytes().to_vec();
        let error = install_boot(&mut wide, &mbr).expect_err("a 4kn install refuses");
        let text = error.to_string();
        assert!(text.contains("512"), "names the required size: {text}");
        assert!(text.contains("4096"), "names the observed size: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(wide.bytes(), &before, "no byte moved in 8192 bytes of disk");
        // An SBR past the end names both values.
        let mut small = VecVolume::new(1024, 512).expect("the small disk allocates");
        let error = install_boot(&mut small, &mbr).expect_err("a past-the-end sbr refuses");
        let text = error.to_string();
        assert!(text.contains("8192"), "names the sbr end: {text}");
        assert!(text.contains("1024"), "names the disk total: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    /// A [`Volume`] over shared bytes, the same shim the syslinux
    /// installer tests use: `Fat32` keeps its store private, so the
    /// tests watch the image through the shared handle. No production
    /// seam was added for this.
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
    }

    impl crate::fs::Volume for SharedVolume {
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
            let end = start.checked_add(buf.len()).expect("the test write fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, Fat32) {
        let backing = SharedVolume::blank(64 * 1024 * 1024);
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

    #[test]
    fn install_loader_round_trips_and_refuses_a_second_write() {
        let (backing, mut fat) = formatted();
        let grldr = payload_bytes(Resource::Grub4DosCore);
        assert_eq!(grldr.len(), 42742, "resource 451 keeps its 42742 bytes");
        let done = install_loader(&mut fat, &grldr).expect("the first write lands");
        assert_eq!(done.bytes(), 42742, "the report counts 42742 bytes");
        let back = fat.read_file("/grldr").expect("the loader reads back");
        assert_eq!(back, grldr, "the loader is byte-identical");
        let listed = fat.list_dir("/").expect("the root lists");
        assert_eq!(listed.len(), 1, "exactly one entry in the root");
        assert_eq!(listed[0].short_name, "GRLDR", "the entry is GRLDR");
        let error = install_loader(&mut fat, &grldr).expect_err("a second write refuses");
        let text = error.to_string();
        assert!(text.contains("grldr"), "the refusal names the file: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("grub4dos.img");
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
            "fsck.fat -n exits 0 after the loader write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    #[test]
    fn install_loader_refuses_an_empty_image() {
        let (_backing, mut fat) = formatted();
        let error = install_loader(&mut fat, &[]).expect_err("empty refuses");
        let text = error.to_string();
        assert!(text.contains("0 bytes"), "names the empty length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }
}
