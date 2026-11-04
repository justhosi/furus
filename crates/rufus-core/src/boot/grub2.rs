//! GRUB2 BIOS install: the `boot.img` record at disk offset 0 plus
//! the whole `core.img` in the post-MBR gap.
//!
//! Rufus's `write_grub2_mbr` (`src/ms-sys/br.c:374`) writes a 432-byte
//! array taken from GRUB2's `boot.img` at disk offset 0, then the
//! `55 AA` boot mark; its header comment reads "First 432 bytes of
//! MBR from Grub2 (boot.img), with 2 bytes NOPed @0x66". The array
//! opens `EB 63 90`, pads with zeros to `0x5A` with `0x80` at `0x5B`,
//! carries `01 00 00 00`
//! at `0x5C` (kernel sector = 1) and `00 00 00 00` at `0x60` (high
//! dword), and runs code from `0x64`: `boot.img` loads that field as
//! `mov ebx,[0x7c5c]` / `[0x7c60]`, i.e. an 8-byte little-endian LBA
//! at `0x5C`. Bytes `432..510` (disk signature at 440, partition
//! table `446..510`) stay untouched, and `write_bootmark` puts
//! `55 AA` at 510. Rufus's `WriteSBR` (`src/format.c:900`) then
//! writes `core.img` whole at byte offset `0x200` (logical sector 1,
//! the post-MBR gap); Rufus never patches `0x5C` because the default
//! already matches sector 1. The PLAN requires the explicit patch, so
//! [`install`] writes it every time.
//!
//! No embedded fallback: the assets hold no GRUB2 `boot.img` or
//! `core.img`. [`install`] takes explicit bytes only; [`payloads`] is
//! the ISO-side lookup that produces them from the image, and any
//! other caller passes its own directory bytes straight in — an
//! embedded copy is never pretended.

use crate::copy::Source;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

use super::syslinux;

/// Bytes of `boot.img` the record carries: Rufus's 432-byte array
/// (`src/ms-sys/br.c:374`). A longer caller image is accepted and only
/// its first 432 bytes land.
pub const BOOT_IMG_BYTES: usize = 432;

/// Offset of the kernel-sector field inside the boot record: the
/// 8-byte little-endian LBA `boot.img` reads at `0x7c5c`.
pub const KERNEL_SECTOR_OFFSET: usize = 0x5c;

/// Length of the kernel-sector field in bytes.
pub const KERNEL_SECTOR_BYTES: usize = 8;

/// Kernel sector the field names: logical sector 1, the post-MBR gap
/// where [`CORE_OFFSET`] lands `core.img`.
pub const KERNEL_SECTOR: u64 = 1;

/// Byte offset `core.img` writes at: logical sector 1, the post-MBR
/// gap (`WriteSBR`'s `write_data(fp, 0x200, buf, size)`).
pub const CORE_OFFSET: u64 = 512;

/// Candidate payload directories as component stacks, in the order
/// the binary names them: `boot/grub/i386-pc`, then
/// `boot/grub2/i386-pc`.
pub const DIRS: &[&[&[u8]]] = &[
    &[b"boot" as &[u8], b"grub" as &[u8], b"i386-pc" as &[u8]],
    &[b"boot" as &[u8], b"grub2" as &[u8], b"i386-pc" as &[u8]],
];

/// Payload file name of the boot record inside a [`DIRS`] directory.
pub const BOOT_IMG: &str = "boot.img";

/// Payload file name of the core image inside a [`DIRS`] directory.
pub const CORE_IMG: &str = "core.img";

/// What [`install`] wrote: the boot-record byte count, the core byte
/// count, and the patched kernel sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    boot_bytes: usize,
    core_bytes: usize,
    kernel_sector: u64,
}

impl Installed {
    /// Bytes of the boot record landed at disk offset 0 (always
    /// [`BOOT_IMG_BYTES`]).
    #[must_use]
    pub fn boot_bytes(&self) -> usize {
        self.boot_bytes
    }

    /// Bytes of `core.img` landed at [`CORE_OFFSET`].
    #[must_use]
    pub fn core_bytes(&self) -> usize {
        self.core_bytes
    }

    /// Kernel sector patched into the record (always
    /// [`KERNEL_SECTOR`]).
    #[must_use]
    pub fn kernel_sector(&self) -> u64 {
        self.kernel_sector
    }
}

/// Install GRUB2 BIOS onto `disk` from explicit `boot_img` and
/// `core_img` bytes.
///
/// The steps run in this order: a non-512-byte sector size refuses, a
/// short `boot_img` refuses, an empty `core_img` refuses, a `core_img`
/// that would run past the disk end refuses, the current sector 0 is
/// read so the disk signature and partition table survive, the new
/// sector 0 is built in memory (`boot_img[..432]`, current
/// `432..510`, `KERNEL_SECTOR` as 8-byte LE at `0x5C`, `55 AA` at
/// 510), `core_img` writes at [`CORE_OFFSET`] first, sector 0 writes
/// last, and the pass flushes once.
///
/// The write order deliberately diverges from Rufus (which writes the
/// MBR first): writing the boot code last keeps the invariant that a
/// torn install never leaves a boot sector pointing at a `core.img`
/// that was not written — exactly slice 3's "never boot code without
/// a stage file".
///
/// There is no VBR variant here: GRUB2's `boot.img` needs the
/// post-MBR gap, so this installer only ever targets whole disks. The
/// 2-bytes-NOPed `@0x66` note is a property of Rufus's embedded copy,
/// not a runtime edit — the caller's bytes land verbatim outside the
/// kernel-sector field. FAT attributes are irrelevant (this writes raw
/// disk sectors, never a filesystem), and copying `grub.cfg` plus the
/// modules is a later slice.
pub fn install(disk: &mut dyn Volume, boot_img: &[u8], core_img: &[u8]) -> Result<Installed> {
    let sector_size = disk.sector_size();
    if sector_size != 512 {
        return Err(CoreError::invalid(format!(
            "grub2 install needs 512 byte sectors, the disk reports {sector_size}: refusing"
        )));
    }
    let boot_len = boot_img.len();
    if boot_len < BOOT_IMG_BYTES {
        return Err(CoreError::invalid(format!(
            "grub2 boot.img is {boot_len} bytes, the mbr record needs {BOOT_IMG_BYTES} bytes: refusing"
        )));
    }
    if core_img.is_empty() {
        return Err(CoreError::invalid(
            "grub2 core.img is empty (0 bytes): refusing".to_string(),
        ));
    }
    let total = disk.total_bytes();
    let core_len = u64::try_from(core_img.len())
        .map_err(|_| CoreError::invalid("a grub2 core.img longer than u64: refusing"))?;
    let core_end = CORE_OFFSET
        .checked_add(core_len)
        .ok_or_else(|| CoreError::invalid("a grub2 core.img end overflows u64: refusing"))?;
    if core_end > total {
        return Err(CoreError::invalid(format!(
            "grub2 core.img of {core_len} bytes at offset {CORE_OFFSET} runs past the {total} byte disk: refusing"
        )));
    }
    let mut current = [0u8; 512];
    disk.read_exact_at(0, &mut current)?;
    let mut sector = [0u8; 512];
    let head = boot_img
        .get(..BOOT_IMG_BYTES)
        .ok_or_else(|| CoreError::invalid("grub2 boot.img lost its record window: refusing"))?;
    let kept = current.get(BOOT_IMG_BYTES..510).ok_or_else(|| {
        CoreError::invalid("grub2 disk sector lost its signature window: refusing")
    })?;
    sector
        .get_mut(..BOOT_IMG_BYTES)
        .ok_or_else(|| CoreError::invalid("grub2 sector lost its record window: refusing"))?
        .copy_from_slice(head);
    sector
        .get_mut(BOOT_IMG_BYTES..510)
        .ok_or_else(|| CoreError::invalid("grub2 sector lost its signature window: refusing"))?
        .copy_from_slice(kept);
    sector
        .get_mut(KERNEL_SECTOR_OFFSET..KERNEL_SECTOR_OFFSET + KERNEL_SECTOR_BYTES)
        .ok_or_else(|| CoreError::invalid("grub2 sector lost its kernel field: refusing"))?
        .copy_from_slice(&KERNEL_SECTOR.to_le_bytes());
    sector
        .get_mut(510..512)
        .ok_or_else(|| CoreError::invalid("grub2 sector lost its boot mark: refusing"))?
        .copy_from_slice(&[0x55, 0xAA]);
    disk.write_all_at(CORE_OFFSET, core_img)?;
    disk.write_all_at(0, &sector)?;
    disk.flush()?;
    Ok(Installed {
        boot_bytes: BOOT_IMG_BYTES,
        core_bytes: core_img.len(),
        kernel_sector: KERNEL_SECTOR,
    })
}

/// GRUB2 payloads found in an image: the directory stack plus both
/// file payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payloads {
    dir: Vec<Vec<u8>>,
    boot_img: Vec<u8>,
    core_img: Vec<u8>,
}

impl Payloads {
    /// Directory stack as name bytes from the source root.
    #[must_use]
    pub fn dir(&self) -> &[Vec<u8>] {
        &self.dir
    }

    /// `/`-joined display form (`/boot/grub/i386-pc`): bytes outside
    /// printable ASCII (`0x20..=0x7E`) become `?`, the same shape as
    /// `syslinux::Located::path`.
    #[must_use]
    pub fn path(&self) -> String {
        display_dir(&self.dir)
    }

    /// The `boot.img` bytes.
    #[must_use]
    pub fn boot_img(&self) -> &[u8] {
        &self.boot_img
    }

    /// The `core.img` bytes.
    #[must_use]
    pub fn core_img(&self) -> &[u8] {
        &self.core_img
    }
}

/// Render one directory stack as the `/`-joined display form: bytes
/// outside printable ASCII become `?`, so the path stays ASCII
/// whatever the image names hold. An empty stack renders as `/`.
fn display_dir(dir: &[Vec<u8>]) -> String {
    if dir.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for component in dir.iter() {
        out.push('/');
        for byte in component.iter() {
            if (0x20..=0x7E).contains(byte) {
                out.push(*byte as char);
            } else {
                out.push('?');
            }
        }
    }
    out
}

/// Find the GRUB2 payloads over a [`Source`]: the first [`DIRS`]
/// candidate whose listing succeeds and holds regular files named
/// `boot.img` and `core.img` wins, and both read through
/// `syslinux::read` (absent names, symlinks, I/O and the 1 MiB cap
/// all behave as there).
///
/// Name matching folds ASCII case like `syslinux::locate`, while the
/// directory components resolve exactly and symlinks never count. A
/// listing error that is a real I/O error ([`CoreError::Io`])
/// propagates; any other listing refusal is a no-match for that
/// candidate. Returns `None` when no directory holds both files.
pub fn payloads(source: &dyn Source) -> Result<Option<Payloads>> {
    for candidate in DIRS.iter() {
        let mut dir: Vec<Vec<u8>> = Vec::new();
        for component in candidate.iter() {
            dir.push(component.to_vec());
        }
        let entries = match source.child_entries(&dir) {
            Ok(entries) => entries,
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => continue,
        };
        let mut has_boot = false;
        let mut has_core = false;
        for entry in entries.iter() {
            if entry.is_dir || entry.link.is_some() {
                continue;
            }
            if entry.name.eq_ignore_ascii_case(BOOT_IMG.as_bytes()) {
                has_boot = true;
            }
            if entry.name.eq_ignore_ascii_case(CORE_IMG.as_bytes()) {
                has_core = true;
            }
        }
        if !has_boot || !has_core {
            continue;
        }
        let Some(boot_img) = syslinux::read(source, &dir, BOOT_IMG)? else {
            continue;
        };
        let Some(core_img) = syslinux::read(source, &dir, CORE_IMG)? else {
            continue;
        };
        return Ok(Some(Payloads {
            dir,
            boot_img,
            core_img,
        }));
    }
    Ok(None)
}

// ------------------------------------------------------------------
// UEFI placement (the PLAN's step, not a Rufus port)
// ------------------------------------------------------------------

// Honesty first: Rufus does not install UEFI GRUB itself. It extracts
// the ISO and only applies a workaround that deletes
// `EFI\boot\bootx64.efi` when the ISO's copy is detected as broken
// (`0x14001c640.c:731-743`, log
// `Broken UEFI bootloader detected - Applying workaround:`). The PLAN
// instead asks us to place `grubx64.efi` at `efi/boot/bootx64.efi`:
// `install_uefi` is that placement step, not a port of a Rufus
// install function, and the broken-bootloader workaround is not
// implemented here.
//
// UEFI GRUB placement: the `grubx64.efi` image lands at
// `/EFI/boot/bootx64.efi` on the FAT32 volume (via `install_uefi`).
// The bytes come from the image through `efi_payload`: the first
// candidate directory below that holds a readable payload wins.

/// Destination directory of the UEFI bootloader on the volume.
pub const EFI_BOOT_DIR: &str = "/EFI/boot";

/// File name of the UEFI bootloader in [`EFI_BOOT_DIR`].
pub const EFI_BOOT_NAME: &str = "bootx64.efi";

/// Read cap for a UEFI payload in bytes (16 MiB): a real `grubx64.efi`
/// is some 2-4 MiB, which the 1 MiB syslinux cap cannot hold.
pub const MAX_EFI_BYTES: u64 = 16 * 1024 * 1024;

/// What [`install_uefi`] wrote: the payload byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UefiInstalled {
    bytes: usize,
}

impl UefiInstalled {
    /// Bytes of the UEFI image landed at the [`path`](Self::path).
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Destination path on the volume (`/EFI/boot/bootx64.efi`,
    /// `EFI_BOOT_DIR` plus `/` plus `EFI_BOOT_NAME` as one string).
    #[must_use]
    pub fn path(&self) -> String {
        format!("{EFI_BOOT_DIR}/{EFI_BOOT_NAME}")
    }
}

/// Place the `grubx64.efi` `image` at `/EFI/boot/bootx64.efi`.
///
/// Refuses an empty image, ensures `/EFI` and `/EFI/boot` exist (each
/// listed first and created with `mkdir` only when its listing errors
/// — single-level creation, the same rule as syslinux
/// `install_companions`), refuses an existing `bootx64.efi` there
/// (compared case-insensitively on the short name, `BOOTX64.EFI`),
/// then `create_file` plus a zero-offset `write_at` and one `flush()`.
pub fn install_uefi(fat: &mut crate::fs::fat32::Fat32, image: &[u8]) -> Result<UefiInstalled> {
    if image.is_empty() {
        return Err(CoreError::invalid(
            "grub2 uefi image is empty (0 bytes): refusing".to_string(),
        ));
    }
    for dir in ["/EFI", EFI_BOOT_DIR] {
        match fat.list_dir(dir) {
            Ok(_) => {}
            Err(_) => {
                fat.mkdir(dir)?;
            }
        }
    }
    let present = fat
        .list_dir(EFI_BOOT_DIR)?
        .iter()
        .any(|entry| entry.short_name.eq_ignore_ascii_case("BOOTX64.EFI"));
    if present {
        return Err(CoreError::invalid(format!(
            "grub2 uefi image is already present at '{EFI_BOOT_DIR}/{EFI_BOOT_NAME}': refusing to overwrite it"
        )));
    }
    let dest = format!("{EFI_BOOT_DIR}/{EFI_BOOT_NAME}");
    let len = u64::try_from(image.len())
        .map_err(|_| CoreError::invalid("a grub2 uefi image longer than u64: refusing"))?;
    fat.create_file(&dest, len)?;
    fat.write_at(&dest, 0, image)?;
    fat.flush()?;
    Ok(UefiInstalled { bytes: image.len() })
}

/// One UEFI payload candidate: a directory stack plus the file name
/// to read there.
const EFI_CANDIDATES: [(&[&[u8]], &str); 3] = [
    (&[b"efi" as &[u8], b"boot" as &[u8]], "grubx64.efi"),
    (&[b"efi" as &[u8], b"boot" as &[u8]], "bootx64.efi"),
    (
        &[b"boot" as &[u8], b"grub" as &[u8], b"x86_64-efi" as &[u8]],
        "grubx64.efi",
    ),
];

/// A UEFI payload found in an image: the directory stack, the file
/// name read there, and the payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiPayload {
    dir: Vec<Vec<u8>>,
    name: String,
    bytes: Vec<u8>,
}

impl EfiPayload {
    /// Directory stack as name bytes from the source root.
    #[must_use]
    pub fn dir(&self) -> &[Vec<u8>] {
        &self.dir
    }

    /// `/`-joined display form: bytes outside printable ASCII become
    /// `?`, the same shape as [`Payloads::path`].
    #[must_use]
    pub fn path(&self) -> String {
        display_dir(&self.dir)
    }

    /// File name read in the directory (`grubx64.efi` or
    /// `bootx64.efi`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The payload bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Find the UEFI payload over a [`Source`]: the first
/// `efi/boot/grubx64.efi`, `efi/boot/bootx64.efi`,
/// `boot/grub/x86_64-efi/grubx64.efi` that reads wins, each through
/// `syslinux::read_capped` at [`MAX_EFI_BYTES`].
///
/// Directories and symlinks read as absent (that is the reader's
/// contract). A listing error that is a real I/O error
/// ([`CoreError::Io`]) propagates; any other listing refusal is a
/// no-match for that candidate. Returns `None` when no candidate
/// holds a readable payload.
pub fn efi_payload(source: &dyn Source) -> Result<Option<EfiPayload>> {
    for (candidate, name) in EFI_CANDIDATES {
        let mut dir: Vec<Vec<u8>> = Vec::new();
        for component in candidate.iter() {
            dir.push(component.to_vec());
        }
        let Some(bytes) = syslinux::read_capped(source, &dir, name, MAX_EFI_BYTES)? else {
            continue;
        };
        return Ok(Some(EfiPayload {
            dir,
            name: name.to_string(),
            bytes,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::Entry;
    use crate::fs::VecVolume;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// 4 KiB scratch disk: sector 0 plus room for a small core.
    const DISK_BYTES: u64 = 4096;

    /// Synthetic `boot.img`: 600 bytes, a distinct byte per offset so
    /// any moved window shows. A longer image is deliberate: only the
    /// first 432 bytes may land.
    fn boot_image() -> Vec<u8> {
        (0..600)
            .map(|index| ((index * 7 + 3) % 251) as u8)
            .collect()
    }

    /// Synthetic `core.img`: 3000 bytes, same distinct-byte rule.
    fn core_image() -> Vec<u8> {
        (0..3000)
            .map(|index| ((index * 13 + 5) % 251) as u8)
            .collect()
    }

    /// A disk prefilled with a recognisable pattern, a disk signature
    /// at 440 and a partition-table pattern at 446..510.
    fn prefilled_disk() -> VecVolume {
        let mut disk = VecVolume::new(DISK_BYTES, 512).expect("the disk allocates");
        let mut filler: Vec<u8> = (0..DISK_BYTES)
            .map(|index| ((index * 11 + 7) % 251) as u8)
            .collect();
        filler[440..444].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        for (slot, byte) in filler[446..510].iter_mut().enumerate() {
            *byte = (slot % 251) as u8;
        }
        disk.write_all_at(0, &filler).expect("the prefill lands");
        disk
    }

    /// The sector `install` must produce, derived independently from
    /// the prefill and the caller bytes (never from the function's own
    /// output).
    fn expected_sector(prefill: &[u8], boot_img: &[u8]) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[..432].copy_from_slice(&boot_img[..432]);
        sector[432..510].copy_from_slice(&prefill[432..510]);
        sector[0x5c..0x64].copy_from_slice(&KERNEL_SECTOR.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xAA]);
        sector
    }

    #[test]
    fn kernel_field_is_patched_and_the_rest_is_verbatim() {
        let mut disk = prefilled_disk();
        let boot = boot_image();
        let core = core_image();
        let installed = install(&mut disk, &boot, &core).expect("the install runs");
        assert_eq!(installed.boot_bytes(), 432, "the record is 432 bytes");
        assert_eq!(
            installed.core_bytes(),
            3000,
            "the core keeps its 3000 bytes"
        );
        assert_eq!(installed.kernel_sector(), 1, "the kernel sector is 1");
        let mut seen = [0u8; 512];
        disk.read_exact_at(0, &mut seen).expect("sector 0 reads");
        assert_eq!(
            &seen[KERNEL_SECTOR_OFFSET..KERNEL_SECTOR_OFFSET + KERNEL_SECTOR_BYTES],
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "the kernel field is 1 little-endian"
        );
        assert_eq!(
            &seen[..0x5c],
            &boot[..0x5c],
            "code before the field is verbatim"
        );
        assert_eq!(
            &seen[0x64..432],
            &boot[0x64..432],
            "code after the field is verbatim"
        );
    }

    #[test]
    fn short_boot_and_empty_core_are_refused() {
        let mut disk = prefilled_disk();
        let core = core_image();
        let short = vec![0xA5u8; BOOT_IMG_BYTES - 1];
        let error = install(&mut disk, &short, &core).expect_err("431 bytes refuse");
        let text = error.to_string();
        assert!(
            text.contains(&short.len().to_string()),
            "the refusal names the boot length: {text}"
        );
        assert!(
            text.contains(&BOOT_IMG_BYTES.to_string()),
            "the refusal names the needed length: {text}"
        );
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
        let boot = boot_image();
        let error = install(&mut disk, &boot, &[]).expect_err("an empty core refuses");
        let text = error.to_string();
        assert!(
            text.contains("0 bytes"),
            "the refusal names the empty core: {text}"
        );
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
    }

    #[test]
    fn a_4kn_volume_is_refused_before_any_write() {
        let mut disk = VecVolume::new(8192, 4096).expect("the 4kn disk allocates");
        let before = disk.bytes().to_vec();
        let error =
            install(&mut disk, &boot_image(), &core_image()).expect_err("a 4kn install refuses");
        let text = error.to_string();
        assert!(text.contains("512"), "names the required size: {text}");
        assert!(text.contains("4096"), "names the observed size: {text}");
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
        assert_eq!(disk.bytes(), &before, "no byte moved in 8192 bytes of disk");
    }

    #[test]
    fn a_core_past_the_end_is_refused() {
        let mut disk = VecVolume::new(2048, 512).expect("the small disk allocates");
        let oversized = vec![0x5Au8; 2000];
        let error =
            install(&mut disk, &boot_image(), &oversized).expect_err("a past-the-end core refuses");
        let text = error.to_string();
        assert!(text.contains("2000"), "names the core length: {text}");
        assert!(text.contains("2048"), "names the disk total: {text}");
        assert!(text.is_ascii(), "the refusal stays ASCII: {text}");
    }

    #[test]
    fn successful_install_pins_every_window() {
        let mut disk = prefilled_disk();
        let before = disk.bytes().to_vec();
        let boot = boot_image();
        let core = core_image();
        install(&mut disk, &boot, &core).expect("the install runs");
        let after = disk.bytes().to_vec();
        assert_eq!(
            &after[..KERNEL_SECTOR_OFFSET],
            &boot[..KERNEL_SECTOR_OFFSET],
            "code before the kernel field is the caller head"
        );
        assert_eq!(
            &after[KERNEL_SECTOR_OFFSET + KERNEL_SECTOR_BYTES..432],
            &boot[KERNEL_SECTOR_OFFSET + KERNEL_SECTOR_BYTES..432],
            "code after the kernel field is the caller head"
        );
        assert_eq!(
            &after[432..510],
            &before[432..510],
            "432..510 keeps signature and partition table"
        );
        assert_eq!(
            &after[440..444],
            &[0xDE, 0xAD, 0xBE, 0xEF],
            "the signature survives"
        );
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the boot mark closes the sector"
        );
        assert_eq!(
            &after[512..512 + core.len()],
            &core,
            "the core lands whole at sector 1"
        );
        assert_eq!(
            &after[512 + core.len()..],
            &before[512 + core.len()..],
            "bytes past the core are untouched"
        );
        assert_eq!(
            &after[..512],
            &expected_sector(&before, &boot),
            "sector 0 matches the independent derivation"
        );
    }

    #[test]
    fn installing_twice_is_idempotent() {
        let mut disk = prefilled_disk();
        let boot = boot_image();
        let core = core_image();
        install(&mut disk, &boot, &core).expect("the first install runs");
        let once = disk.bytes().to_vec();
        let again = install(&mut disk, &boot, &core).expect("a second install runs");
        assert_eq!(disk.bytes(), &once, "the second install changes no byte");
        assert_eq!(again.boot_bytes(), 432, "the report repeats");
        assert_eq!(again.core_bytes(), core.len(), "the core count repeats");
        assert_eq!(again.kernel_sector(), 1, "the kernel sector repeats");
    }

    /// In-memory [`Source`] over explicit listings and file bytes, the
    /// same shape the `syslinux` tests use: directories keyed by
    /// component path, files keyed by full path.
    struct MemSource {
        dirs: HashMap<Vec<Vec<u8>>, Vec<Entry>>,
        files: HashMap<Vec<Vec<u8>>, Vec<u8>>,
    }

    impl MemSource {
        fn new() -> Self {
            Self {
                dirs: HashMap::new(),
                files: HashMap::new(),
            }
        }

        fn with_dir(mut self, dir: &[&[u8]], entries: Vec<Entry>) -> Self {
            let key: Vec<Vec<u8>> = dir.iter().map(|part| part.to_vec()).collect();
            self.dirs.insert(key, entries);
            self
        }

        fn with_file(mut self, path: &[&[u8]], bytes: &[u8]) -> Self {
            let key: Vec<Vec<u8>> = path.iter().map(|part| part.to_vec()).collect();
            self.files.insert(key, bytes.to_vec());
            self
        }
    }

    fn file_entry(name: &[u8], size: u64) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: false,
            size,
            mode: None,
            modified: None,
            accessed: None,
            link: None,
        }
    }

    fn dir_entry(name: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: true,
            size: 0,
            mode: None,
            modified: None,
            accessed: None,
            link: None,
        }
    }

    fn link_entry(name: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: false,
            size: 0,
            mode: None,
            modified: None,
            accessed: None,
            link: Some(b"target".to_vec()),
        }
    }

    impl Source for MemSource {
        fn root_entries(&self) -> Result<Vec<Entry>> {
            self.child_entries(&[])
        }

        fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            self.dirs
                .get(dir)
                .cloned()
                .ok_or_else(|| CoreError::invalid("no such directory".to_string()))
        }

        fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
            let bytes = self
                .files
                .get(file)
                .ok_or_else(|| CoreError::invalid("no such file".to_string()))?;
            let at = usize::try_from(offset)
                .map_err(|_| CoreError::invalid("offset does not fit".to_string()))?;
            if at > bytes.len() {
                return Err(CoreError::invalid("offset past end".to_string()));
            }
            let rest = &bytes[at..];
            let take = rest.len().min(buf.len());
            buf[..take].copy_from_slice(&rest[..take]);
            Ok(take)
        }
    }

    /// Both payload directories, each holding both files: the first
    /// candidate must win.
    fn both_tree() -> MemSource {
        MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub"), dir_entry(b"grub2")])
            .with_dir(
                &[b"boot", b"grub"],
                vec![dir_entry(b"i386-pc"), dir_entry(b"x86_64-efi")],
            )
            .with_dir(&[b"boot", b"grub2"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![
                    file_entry(b"boot.img", 4),
                    file_entry(b"core.img", 3),
                    file_entry(b"other.mod", 1),
                ],
            )
            .with_dir(
                &[b"boot", b"grub2", b"i386-pc"],
                vec![file_entry(b"boot.img", 5), file_entry(b"core.img", 6)],
            )
            .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], b"old!")
            .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], b"old")
            .with_file(&[b"boot", b"grub2", b"i386-pc", b"boot.img"], b"new!!")
            .with_file(&[b"boot", b"grub2", b"i386-pc", b"core.img"], b"newcore")
    }

    #[test]
    fn payloads_prefers_the_first_directory() {
        let found = payloads(&both_tree())
            .expect("the lookup reads")
            .expect("a payload dir exists");
        assert_eq!(
            found.dir(),
            &[b"boot".to_vec(), b"grub".to_vec(), b"i386-pc".to_vec()],
            "the first candidate wins"
        );
        assert_eq!(found.path(), "/boot/grub/i386-pc");
        assert_eq!(found.boot_img(), b"old!", "the first dir bytes win");
        assert_eq!(found.core_img(), b"old", "the first dir bytes win");
    }

    #[test]
    fn payloads_falls_through_to_the_second_directory() {
        // Only boot/grub2/i386-pc holds both files, spelled in upper
        // case: the components resolve exactly while the file names
        // fold case.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub"), dir_entry(b"grub2")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
            .with_dir(&[b"boot", b"grub2"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![file_entry(b"other.mod", 1)],
            )
            .with_dir(
                &[b"boot", b"grub2", b"i386-pc"],
                vec![file_entry(b"BOOT.IMG", 4), file_entry(b"CORE.IMG", 6)],
            )
            .with_file(&[b"boot", b"grub2", b"i386-pc", b"boot.img"], b"up!!")
            .with_file(&[b"boot", b"grub2", b"i386-pc", b"core.img"], b"upcore");
        let found = payloads(&source)
            .expect("the lookup reads")
            .expect("the second dir exists");
        assert_eq!(
            found.dir(),
            &[b"boot".to_vec(), b"grub2".to_vec(), b"i386-pc".to_vec()],
            "the second candidate wins"
        );
        assert_eq!(found.boot_img(), b"up!!", "the exact bytes return");
        assert_eq!(found.core_img(), b"upcore", "the exact bytes return");
    }

    #[test]
    fn payloads_returns_none_without_both_files() {
        // A tree with no payload directory at all.
        let bare = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", 1)]);
        assert!(
            payloads(&bare).expect("the lookup reads").is_none(),
            "no directory reads as none"
        );
        // A directory holding only boot.img is skipped.
        let half = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![file_entry(b"boot.img", 4)],
            )
            .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], b"lonely");
        assert!(
            payloads(&half).expect("the lookup reads").is_none(),
            "half a pair is no match"
        );
    }

    #[test]
    fn payloads_ignores_a_symlinked_boot_img() {
        // A symlink named boot.img never counts, even next to a real
        // core.img: the directory reads as incomplete.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
            .with_dir(
                &[b"boot", b"grub", b"i386-pc"],
                vec![link_entry(b"boot.img"), file_entry(b"core.img", 3)],
            )
            .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], b"core");
        assert!(
            payloads(&source).expect("the lookup reads").is_none(),
            "a symlinked boot.img never locates"
        );
    }

    /// A [`Volume`] over shared bytes, the same shim the syslinux
    /// installer tests use: `Fat32` keeps its store private, so the
    /// tests watch the image through the shared handle.
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
            let end = start.checked_add(buf.len()).expect("the test window fits");
            let window = borrowed.get_mut(start..end).expect("the test write fits");
            window.copy_from_slice(buf);
            Ok(())
        }
    }

    /// A freshly formatted 64 MiB volume plus the shared handle that
    /// still observes its bytes.
    fn formatted() -> (SharedVolume, crate::fs::fat32::Fat32) {
        use crate::fs::fat32::format::FormatOptions;
        let backing = SharedVolume::blank(64 * 1024 * 1024);
        let fat = crate::fs::fat32::Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        (backing, fat)
    }

    /// Synthetic UEFI image: 3 MiB of distinct bytes, inside the
    /// 16 MiB cap and above the 1 MiB syslinux one.
    fn uefi_image() -> Vec<u8> {
        (0..3 * 1024 * 1024)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect()
    }

    #[test]
    fn install_uefi_creates_dirs_and_round_trips() {
        let (backing, mut fat) = formatted();
        let image = uefi_image();
        let done = install_uefi(&mut fat, &image).expect("the install runs");
        assert_eq!(
            done.bytes(),
            3 * 1024 * 1024,
            "the report counts 3145728 bytes"
        );
        assert_eq!(
            done.path(),
            "/EFI/boot/bootx64.efi",
            "the path joins dir and name"
        );
        let efi = fat.list_dir("/EFI").expect("/EFI lists");
        assert_eq!(efi.len(), 1, "one entry under /EFI");
        let boot = fat.list_dir("/EFI/boot").expect("/EFI/boot lists");
        assert_eq!(boot.len(), 1, "one entry under /EFI/boot");
        assert_eq!(
            boot[0].short_name, "BOOTX64.EFI",
            "the entry is BOOTX64.EFI"
        );
        let back = fat
            .read_file("/EFI/boot/bootx64.efi")
            .expect("the image reads back");
        assert_eq!(back, image, "the payload is byte-identical");
        let error = install_uefi(&mut fat, &image).expect_err("a second install refuses");
        let text = error.to_string();
        assert!(
            text.contains("/EFI/boot/bootx64.efi"),
            "the refusal names the path: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let picture = scratch.path().join("uefi.img");
        std::fs::write(&picture, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&picture)
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
            "fsck.fat -n exits 0 after the uefi write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    #[test]
    fn install_uefi_refuses_an_empty_image() {
        let (_backing, mut fat) = formatted();
        let error = install_uefi(&mut fat, &[]).expect_err("empty refuses");
        let text = error.to_string();
        assert!(text.contains("0 bytes"), "names the empty length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    /// All three UEFI candidates present: the first directory's
    /// `grubx64.efi` must win.
    fn all_efi_tree() -> MemSource {
        MemSource::new()
            .with_dir(&[], vec![dir_entry(b"efi"), dir_entry(b"boot")])
            .with_dir(&[b"efi"], vec![dir_entry(b"boot")])
            .with_dir(
                &[b"efi", b"boot"],
                vec![file_entry(b"grubx64.efi", 4), file_entry(b"bootx64.efi", 5)],
            )
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"x86_64-efi")])
            .with_dir(
                &[b"boot", b"grub", b"x86_64-efi"],
                vec![file_entry(b"grubx64.efi", 6)],
            )
            .with_file(&[b"efi", b"boot", b"grubx64.efi"], b"one!")
            .with_file(&[b"efi", b"boot", b"bootx64.efi"], b"two!!")
            .with_file(
                &[b"boot", b"grub", b"x86_64-efi", b"grubx64.efi"],
                b"three!",
            )
    }

    #[test]
    fn efi_payload_prefers_the_first_candidate() {
        let found = efi_payload(&all_efi_tree())
            .expect("the lookup reads")
            .expect("a payload exists");
        assert_eq!(
            found.dir(),
            &[b"efi".to_vec(), b"boot".to_vec()],
            "the first directory wins"
        );
        assert_eq!(found.path(), "/efi/boot");
        assert_eq!(found.name(), "grubx64.efi");
        assert_eq!(found.bytes(), b"one!", "the first payload bytes win");
    }

    #[test]
    fn efi_payload_falls_through_and_returns_none() {
        // Only the third candidate holds a payload: the first two
        // directories read as absent.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
            .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"x86_64-efi")])
            .with_dir(
                &[b"boot", b"grub", b"x86_64-efi"],
                vec![file_entry(b"grubx64.efi", 6)],
            )
            .with_file(
                &[b"boot", b"grub", b"x86_64-efi", b"grubx64.efi"],
                b"three!",
            );
        let found = efi_payload(&source)
            .expect("the lookup reads")
            .expect("the third candidate exists");
        assert_eq!(found.path(), "/boot/grub/x86_64-efi");
        assert_eq!(found.name(), "grubx64.efi");
        assert_eq!(found.bytes(), b"three!", "the exact bytes return");
        // A bare tree holds nothing.
        let bare = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", 1)]);
        assert!(
            efi_payload(&bare).expect("the lookup reads").is_none(),
            "a bare tree reads as none"
        );
    }

    #[test]
    fn efi_payload_ignores_a_symlinked_candidate() {
        // A symlinked grubx64.efi reads as absent, so the lookup falls
        // past the first candidate to the second directory's real
        // bootx64.efi.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"efi")])
            .with_dir(&[b"efi"], vec![dir_entry(b"boot")])
            .with_dir(
                &[b"efi", b"boot"],
                vec![link_entry(b"grubx64.efi"), file_entry(b"bootx64.efi", 5)],
            )
            .with_file(&[b"efi", b"boot", b"bootx64.efi"], b"two!!");
        let found = efi_payload(&source)
            .expect("the lookup reads")
            .expect("the second name exists");
        assert_eq!(found.name(), "bootx64.efi");
        assert_eq!(found.bytes(), b"two!!", "the fall-through bytes return");
    }
}
