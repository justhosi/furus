//! Bootloader installation: the six embedded payloads plus one
//! installer per family, all in this module.
//!
//! The bytes live in `assets/resources/` and are pinned by
//! `assets/manifest.json`: each [`Resource`] carries its manifest id,
//! file name, exact size and SHA-256, and [`load_from`] refuses anything
//! that does not match all of them. [`load`] is the production entry
//! point (it resolves through [`asset_path`](crate::paths::asset_path));
//! [`load_from`] is the testable core over an explicit directory. The
//! six resources are the Syslinux 4.07 VBR/core (ids 400/401), the
//! Syslinux 6.04 VBR/core (402/403) and the Grub4DOS MBR/core
//! (450/451).
//!
//! [`syslinux`] installs either Syslinux family (family decision,
//! contiguous `ldlinux.sys` plus sector-map/ADV patch, companions,
//! config wrapper, obsolete-module substitution); [`grub2`] installs a
//! GRUB2 BIOS boot record and places a `grubx64.efi` image;
//! [`grub4dos`] writes the GRUB4DOS MBR window, SBR and root `grldr`.
//! Wiring these installers into the copy and pipeline paths is a later
//! slice, and no stick has been booted on hardware.

pub mod grub2;
pub mod grub4dos;
pub mod syslinux;

use std::path::Path;

use crate::error::CoreError;
use crate::error::Result;
use crate::hash::Algo;
use crate::hash::hash_reader;
use crate::paths::asset_path;

/// One embedded bootloader payload, pinned against `assets/manifest.json`.
///
/// The numeric ids are the manifest resource ids (400-403 Syslinux,
/// 450-451 Grub4DOS); the sizes and digests are the manifest `bytes` and
/// `sha256` values, so any manifest regeneration must update this enum
/// in lockstep (the load test below guards the drift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    /// Syslinux 4.07 VBR (`ldlinux.bss`), manifest id 400.
    Syslinux407Vbr,
    /// Syslinux 4.07 core (`ldlinux.sys`), manifest id 401.
    Syslinux407Core,
    /// Syslinux 6.04 VBR (`ldlinux.bss`), manifest id 402.
    Syslinux604Vbr,
    /// Syslinux 6.04 core (`ldlinux.sys`), manifest id 403.
    Syslinux604Core,
    /// Grub4DOS MBR (`grldr.mbr`), manifest id 450.
    Grub4DosMbr,
    /// Grub4DOS core (`grldr`), manifest id 451.
    Grub4DosCore,
}

impl Resource {
    /// Every variant, so the tests below load each payload and no new
    /// variant can skip that coverage silently (a new variant must be
    /// added here to keep the file-name test exhaustive).
    pub const ALL: [Resource; 6] = [
        Resource::Syslinux407Vbr,
        Resource::Syslinux407Core,
        Resource::Syslinux604Vbr,
        Resource::Syslinux604Core,
        Resource::Grub4DosMbr,
        Resource::Grub4DosCore,
    ];

    /// Manifest resource id.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Self::Syslinux407Vbr => 400,
            Self::Syslinux407Core => 401,
            Self::Syslinux604Vbr => 402,
            Self::Syslinux604Core => 403,
            Self::Grub4DosMbr => 450,
            Self::Grub4DosCore => 451,
        }
    }

    /// Bare file name under `assets/resources/`.
    #[must_use]
    pub fn file(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => "RCDATA_400.bin",
            Self::Syslinux407Core => "RCDATA_401.bin",
            Self::Syslinux604Vbr => "RCDATA_402.bin",
            Self::Syslinux604Core => "RCDATA_403.bin",
            Self::Grub4DosMbr => "RCDATA_450.bin",
            Self::Grub4DosCore => "RCDATA_451.bin",
        }
    }

    /// Exact manifest byte count; anything else refuses as corrupt.
    #[must_use]
    pub fn size(self) -> u64 {
        match self {
            Self::Syslinux407Vbr => 512,
            Self::Syslinux407Core => 36488,
            Self::Syslinux604Vbr => 512,
            Self::Syslinux604Core => 68121,
            Self::Grub4DosMbr => 8192,
            Self::Grub4DosCore => 42742,
        }
    }

    /// Pinned manifest SHA-256, lowercase hex.
    #[must_use]
    pub fn sha256(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => {
                "8dc6ec58b4f1df391db68d9e2165ccd47d84f4ba64675f87b677077aae5b53fa"
            }
            Self::Syslinux407Core => {
                "d5b6310740a596ba4367719a3dff4b3442f6da81cbeafbb0bf3fab026d8bc910"
            }
            Self::Syslinux604Vbr => {
                "cc40ba0349782cb4c9021e54dcc0a4540c3a8b96088b3a5648671926ef44d2f0"
            }
            Self::Syslinux604Core => {
                "73b62767a16200b9af193a7d5c94e9c294c6dbb6d5b17c15038c9f3173c9a7bc"
            }
            Self::Grub4DosMbr => "a2a8769371eb57c5e79b3cea4a911275af4743f10f420ed6d26e4eec5c865059",
            Self::Grub4DosCore => {
                "9a2c946704017fa8dc4e03a8a58d754d2d1607c2d2cd74f0e2920133f1192809"
            }
        }
    }

    /// Human-readable name for log and error messages.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Syslinux407Vbr => "Syslinux 4.07 VBR",
            Self::Syslinux407Core => "Syslinux 4.07 core",
            Self::Syslinux604Vbr => "Syslinux 6.04 VBR",
            Self::Syslinux604Core => "Syslinux 6.04 core",
            Self::Grub4DosMbr => "Grub4DOS MBR",
            Self::Grub4DosCore => "Grub4DOS core",
        }
    }
}

/// A verified payload: its [`Resource`] plus the exact bytes from disk.
///
/// The bytes are checked at load time (see [`load_from`]), so holding a
/// `Payload` means the size and digest already matched the pinned values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    resource: Resource,
    bytes: Vec<u8>,
}

impl Payload {
    /// The loaded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte count (always equals [`Resource::size`] of [`resource`](Self::resource)).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the payload holds no bytes (never true for the six pinned
    /// resources — every size is non-zero — but the [`len`](Self::len)
    /// companion keeps the API unsurprising).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Which resource these bytes were verified against.
    #[must_use]
    pub fn resource(&self) -> Resource {
        self.resource
    }
}

/// Load `resource` from the resolved asset directory.
///
/// Resolves through [`asset_path`](crate::paths::asset_path), then
/// delegates to [`load_from`] so the file-name join lives in one place.
pub fn load(resource: Resource) -> Result<Payload> {
    let path = asset_path(resource.file())?;
    // `asset_path` hands back the file itself; its parent is the
    // directory `load_from` joins against. The parent always exists in
    // practice (resolution joins a file onto a directory), but there is
    // no `unwrap` on that assumption — a bare name refuses by name.
    let dir = path.parent().ok_or_else(|| {
        CoreError::invalid(format!(
            "asset {} ({}) resolved to a path with no parent directory",
            resource.label(),
            resource.file()
        ))
    })?;
    load_from(dir, resource)
}

/// Load `resource` from `dir`, verifying exact size and SHA-256 against
/// the pinned values.
///
/// A missing or unreadable file surfaces as [`CoreError::Io`] (the path
/// names the file); a size or digest mismatch is
/// [`CoreError::InvalidInput`] naming the resource label, the file name,
/// and both the expected and actual numbers/digests, so a log line is
/// enough to tell corruption from mis-packaging.
pub fn load_from(dir: &Path, resource: Resource) -> Result<Payload> {
    let path = dir.join(resource.file());
    let bytes = std::fs::read(&path).map_err(|source| CoreError::io(&path, source))?;
    let actual_len = bytes.len() as u64;
    if actual_len != resource.size() {
        return Err(CoreError::invalid(format!(
            "payload {} ({}) has size {actual_len} bytes, expected {} bytes",
            resource.label(),
            resource.file(),
            resource.size()
        )));
    }
    // Hash the bytes just read rather than re-reading the file: one
    // read, one failure mode, no window for the file to change between
    // the size check and the digest.
    let actual_sha = hash_reader(Algo::Sha256, &bytes as &[u8])?;
    if actual_sha != resource.sha256() {
        return Err(CoreError::invalid(format!(
            "payload {} ({}) has SHA-256 {actual_sha}, expected {}",
            resource.label(),
            resource.file(),
            resource.sha256()
        )));
    }
    Ok(Payload { resource, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `assets/resources/` next to the workspace root, without going
    /// through asset-dir resolution (resolution depends on the
    /// environment; the anti-drift guard must not).
    fn resources_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/resources"
        ))
    }

    #[test]
    fn every_resource_loads_with_pinned_size_and_digest() {
        // The anti-drift guard: the file names, sizes and digests above
        // come from `assets/manifest.json`, so a manifest regeneration
        // that changes any of the six payloads fails here until the
        // enum is updated in lockstep.
        for resource in Resource::ALL {
            let payload = load_from(&resources_dir(), resource).expect("the pinned payload loads");
            assert_eq!(
                payload.len() as u64,
                resource.size(),
                "loaded length of {} matches the pinned size",
                resource.file()
            );
            assert_eq!(
                payload.resource(),
                resource,
                "the payload remembers its resource"
            );
            let actual = hash_reader(Algo::Sha256, payload.bytes()).expect("in-memory bytes hash");
            assert_eq!(
                actual,
                resource.sha256(),
                "SHA-256 of {} matches the pinned digest",
                resource.file()
            );
        }
    }

    #[test]
    fn missing_file_is_an_error_naming_the_resource() {
        // An empty directory: every load fails, and each error names its
        // file so the log says which payload is absent.
        let scratch = tempfile::tempdir().expect("scratch fits");
        for resource in Resource::ALL {
            let error = load_from(scratch.path(), resource).expect_err("a missing payload refuses");
            let text = error.to_string();
            assert!(
                text.contains(resource.file()),
                "the error names the file: {text}"
            );
        }
    }

    #[test]
    fn file_names_are_exactly_the_six_pinned_names() {
        // One assertion over every variant, so a future variant that is
        // added to `ALL` without a real payload file cannot slip past
        // the load test above (it would fail there on a missing file).
        let files: Vec<&str> = Resource::ALL.iter().map(|r| r.file()).collect();
        assert_eq!(
            files,
            [
                "RCDATA_400.bin",
                "RCDATA_401.bin",
                "RCDATA_402.bin",
                "RCDATA_403.bin",
                "RCDATA_450.bin",
                "RCDATA_451.bin",
            ],
            "the six pinned file names"
        );
    }

    #[test]
    fn resource_ids_are_the_six_manifest_ids() {
        // Sibling to the file-name guard: the numeric ids ride the same
        // manifest entries, so they pin in lockstep too.
        let ids: Vec<u16> = Resource::ALL.iter().map(|r| r.id()).collect();
        assert_eq!(
            ids,
            [400, 401, 402, 403, 450, 451],
            "the six manifest resource ids"
        );
    }

    #[test]
    fn truncated_file_is_an_error_naming_both_byte_counts() {
        // Copy a real payload and truncate it: the size check fires
        // before the digest, naming the file and both counts.
        let resource = Resource::Syslinux407Vbr;
        let bytes =
            std::fs::read(resources_dir().join(resource.file())).expect("the pinned file reads");
        let scratch = tempfile::tempdir().expect("scratch fits");
        let kept = bytes.len().saturating_sub(12);
        std::fs::write(scratch.path().join(resource.file()), &bytes[..kept])
            .expect("the truncated copy writes");
        let error = load_from(scratch.path(), resource).expect_err("a truncated payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(resource.file()),
            "the error names the file: {text}"
        );
        assert!(
            text.contains(&kept.to_string()),
            "the error names the actual count: {text}"
        );
        assert!(
            text.contains(&resource.size().to_string()),
            "the error names the expected count: {text}"
        );
    }

    #[test]
    fn flipped_byte_is_an_error_naming_both_digests() {
        // Copy a real payload with one byte flipped at the same size:
        // the digest check fires, naming the file and both digests.
        let resource = Resource::Syslinux407Vbr;
        let mut bytes =
            std::fs::read(resources_dir().join(resource.file())).expect("the pinned file reads");
        bytes[0] ^= 0x01;
        let scratch = tempfile::tempdir().expect("scratch fits");
        std::fs::write(scratch.path().join(resource.file()), &bytes)
            .expect("the flipped copy writes");
        let error = load_from(scratch.path(), resource).expect_err("a flipped payload refuses");
        let text = error.to_string();
        assert!(
            text.contains(resource.file()),
            "the error names the file: {text}"
        );
        let actual = hash_reader(Algo::Sha256, &bytes as &[u8]).expect("the flipped bytes hash");
        assert_ne!(actual, resource.sha256(), "the flip changes the digest");
        assert!(
            text.contains(&actual),
            "the error names the actual digest: {text}"
        );
        assert!(
            text.contains(resource.sha256()),
            "the error names the expected digest: {text}"
        );
    }
}

/// Acceptance: every installer composed on one filesystem, plus a
/// QEMU smoke test.
///
/// `one_stick_carries_every_installer` proves the installers compose
/// on a single FAT32 volume without stepping on each other — the
/// Syslinux stage, the GRUB4DOS loader and the UEFI image coexist,
/// the boot sector stays the Syslinux graft, and the image is
/// `fsck.fat` clean. It proves composition, not bootability: no menu
/// is shown and no stick has booted on hardware.
///
/// `images_boot_in_qemu_when_available` proves SeaBIOS accepts the
/// Syslinux-installed boot sector and hands off; it cannot see the
/// Syslinux menu, and the PLAN's "boots to a menu" done-when stays
/// unverified wherever QEMU is absent.
#[cfg(test)]
mod acceptance {
    use super::Resource;
    use super::load_from;
    use crate::boot::grub2;
    use crate::boot::grub4dos;
    use crate::boot::syslinux;
    use crate::error::Result;
    use crate::fs::Volume;
    use crate::fs::fat32::Fat32;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 128 MiB in bytes, one stick both tests share.
    const STICK_BYTES: u64 = 128 * 1024 * 1024;

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

    /// A [`Volume`] over shared bytes, so the tests can dump the image
    /// while [`Fat32`] owns the store. Local to this module because
    /// the same-shaped shim in `syslinux::install`'s tests is private
    /// there; no production seam was added for either.
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

    /// One formatted 128 MiB volume carrying the Syslinux 6.04 stage,
    /// flushed and ready for the other installers.
    ///
    /// Interpretation, stated plainly: the brief asks for
    /// `syslinux::install_loader`, but that wrapper differs from this
    /// path only in its `load()` resolution step (the runtime asset
    /// directory, which no test may depend on) — `load` delegates to
    /// `load_from` once resolved, so these are byte-identical payloads
    /// through the same `install_payloads` core.
    fn syslinux_installed() -> (SharedVolume, Fat32, Vec<u8>, Vec<u8>) {
        let backing = SharedVolume::blank(STICK_BYTES);
        let mut fat = Fat32::format(
            Box::new(backing.clone()),
            &FormatOptions {
                volume_id: 0x1234_5678,
                ..Default::default()
            },
        )
        .expect("the volume formats");
        let vbr = payload_bytes(Resource::Syslinux604Vbr);
        let core = payload_bytes(Resource::Syslinux604Core);
        syslinux::install_payloads(&mut fat, syslinux::Family::V604, &vbr, &core)
            .expect("the syslinux install runs");
        fat.flush().expect("the stage flushes");
        (backing, fat, vbr, core)
    }

    /// Synthetic UEFI image (~1.5 MiB) with a recognisable head and
    /// tail.
    fn uefi_image() -> Vec<u8> {
        const SIZE: usize = 3 * 1024 * 1024 / 2;
        (0..SIZE)
            .map(|index| ((index * 5 + 1) % 251) as u8)
            .collect()
    }

    #[test]
    fn one_stick_carries_every_installer() {
        let (backing, mut fat, vbr, core) = syslinux_installed();
        let grldr = payload_bytes(Resource::Grub4DosCore);
        grub4dos::install_loader(&mut fat, &grldr).expect("the grldr lands");
        let uefi = uefi_image();
        grub2::install_uefi(&mut fat, &uefi).expect("the uefi image lands");
        fat.flush().expect("every installer flushes");

        // The boot sector is still the Syslinux graft: the GRUB4DOS
        // loader install is a file write and must not touch it.
        let sector = backing.boot_sector();
        assert_eq!(
            &sector[0..11],
            &vbr[0..11],
            "the payload jump and OEM name survive every installer"
        );
        assert_eq!(
            2 + u16::from(sector[1]),
            0x5A,
            "the jump still lands on the code at 0x5A"
        );

        // The stage is the patched core plus the 1024-byte ADV tail.
        let stage = fat.read_file("/ldlinux.sys").expect("the stage reads");
        assert_eq!(
            stage.len(),
            core.len() + 1024,
            "the stage is core plus adv in 69145 bytes"
        );
        assert_eq!(
            &stage[core.len()..],
            &syslinux::patch::default_adv(),
            "the tail is exactly the default adv"
        );

        // Both companions read back whole.
        let back = fat.read_file("/grldr").expect("the loader reads");
        assert_eq!(back, grldr, "grldr is the asset byte for byte");
        let back = fat
            .read_file("/EFI/boot/bootx64.efi")
            .expect("the efi image reads");
        assert_eq!(back, uefi, "the efi image is byte-identical");

        // The root holds all three installers' entries.
        let listed = fat.list_dir("/").expect("the root lists");
        let shorts: Vec<&str> = listed
            .iter()
            .map(|entry| entry.short_name.as_str())
            .collect();
        for want in ["LDLINUX.SYS", "GRLDR", "EFI"] {
            assert!(shorts.contains(&want), "{want} is listed among {shorts:?}");
        }

        // Second passes are still refused, before any write each.
        let second = syslinux::install_payloads(&mut fat, syslinux::Family::V604, &vbr, &core)
            .expect_err("a second syslinux install refuses");
        assert!(
            second.to_string().contains("ldlinux.sys"),
            "the syslinux refusal names the file"
        );
        let second =
            grub4dos::install_loader(&mut fat, &grldr).expect_err("a second grldr install refuses");
        assert!(
            second.to_string().contains("grldr"),
            "the grldr refusal names the file"
        );
        let second =
            grub2::install_uefi(&mut fat, &uefi).expect_err("a second uefi install refuses");
        assert!(
            second.to_string().contains("/EFI/boot/bootx64.efi"),
            "the uefi refusal names the path"
        );

        // The composed image is fsck clean.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("stick.img");
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
            "fsck.fat -n exits 0 on the composed image ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    #[test]
    fn images_boot_in_qemu_when_available() {
        // Smoke shape (the loop-device suites use the same one): probe
        // `qemu-system-x86_64 --version`, and skip on any spawn error.
        // When QEMU runs, this proves SeaBIOS accepted the boot sector
        // and handed off to the Syslinux stage; it cannot see the
        // Syslinux menu, and the PLAN's "boots to a menu" done-when
        // stays unverified wherever QEMU is absent.
        let probe = std::process::Command::new("qemu-system-x86_64")
            .arg("--version")
            .output();
        let probed = probe.map(|output| output.status.success()).unwrap_or(false);
        if !probed {
            eprintln!("skip: qemu-system-x86_64 is not on PATH");
            return;
        }
        let (backing, _fat, _vbr, _core) = syslinux_installed();
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let picture = scratch.path().join("stick.img");
        std::fs::write(&picture, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let log = scratch.path().join("debug.log");
        let mut child = std::process::Command::new("qemu-system-x86_64")
            .arg("-m")
            .arg("128")
            .arg("-drive")
            .arg(format!("file={},format=raw,if=ide", picture.display()))
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-serial")
            .arg("none")
            .arg("-device")
            .arg("isa-debugcon,iobase=0x402,chardev=dbg")
            .arg("-chardev")
            .arg(format!("file,id=dbg,path={}", log.display()))
            .spawn()
            .expect("qemu spawns");
        // At most ~10 seconds of SeaBIOS time, then kill and reap.
        for _ in 0..100 {
            match child.try_wait().expect("qemu polls") {
                Some(_) => break,
                None => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let transcript = std::fs::read(&log).expect("the debug log reads");
        let text = String::from_utf8_lossy(&transcript);
        assert!(
            text.contains("Booting from Hard Disk"),
            "seabios hands off the hard disk"
        );
        assert!(
            !text.contains("Boot failed"),
            "seabios finds a bootable sector"
        );
    }
}
