//! Windows boot manager, fonts and BCD store placement (S21, slice 8 of 12).
//!
//! Question: after the image is applied and the BCD stores are built,
//! the target still cannot boot: nothing has copied the boot manager,
//! its fonts, or the stores onto the ESP (UEFI) and the data partition
//! (BIOS) the way real Rufus leaves them.
//!
//! What real Rufus does: it copies the applied image's own boot files —
//! `Windows/Boot/EFI/bootmgfw.efi` onto the ESP as both
//! `EFI/Microsoft/Boot/bootmgfw.efi` and `EFI/Boot/BOOTX64.EFI`,
//! `Windows/Boot/PCAT/bootmgr` onto the data partition root, plus
//! `boot.sdi`, `memtest.exe`/`memtest.efi` and the `Fonts` contents —
//! and writes the built BCD store next to them. Upstream Rufus uses
//! the 2023-signed `_EX` builds (`EFI_EX/bootmgfw_EX.efi` beside the
//! standard loader) only when the user opts in, and media written
//! that way then requires the "Windows UEFI CA 2023" Secure Boot
//! certificate; the standard files stay the default. This module
//! performs that copy host-side with plain file reads and writes:
//! no new dependency, no hive editing, nothing deleted, and
//! re-running overwrites the same paths.
//!
//! Decision: [`install`] takes `use_2023_bootloaders` for the opt-in.
//! With `false` it always uses `Windows/Boot/EFI/bootmgfw.efi` and
//! `Windows/Boot/PCAT/bootmgr`. With `true` it uses the `_EX` file
//! when present, falls back to the standard one when not, and also
//! prefers `Windows/Boot/Fonts_EX` over `Windows/Boot/Fonts` for
//! the font copy. [`install`] validates the store (non-empty, opening
//! with `regf`) and the `data` root (an existing directory), then
//! reads every required source into memory before the first write —
//! a BIOS install that finds `boot.sdi` missing fails with nothing
//! written — and copies per [`Firmware`]. UEFI writes the loader
//! twice, `memtest.efi` when the image carries one, every regular
//! file directly inside the chosen fonts directory (a missing fonts
//! directory simply copies nothing), and the store as
//! `EFI/Microsoft/Boot/BCD`. BIOS writes `bootmgr`, `boot/boot.sdi`
//! (the `PCAT` copy, falling back to the install-media
//! `Windows/Boot/DVD/PCAT/boot.sdi` that WinPE-derived trees carry
//! instead), `boot/memtest.exe` only when the image carries one, the
//! fonts into `boot/fonts/`, and the store as `boot/bcd`. A missing
//! boot manager and a missing BIOS `boot.sdi` refuse with
//! [`CoreError::InvalidInput`] naming the absent source, and every
//! written path lands in [`Placement::files`] in write order.
//!
//! The `PCAT_EX/bootmgr_EX` lookup exists for symmetry with the EFI
//! side but has not been observed on the 24H2 media (only `EFI_EX`
//! was): it is looked up, not presumed present.
//!
//! Limitations, stated plainly: the firmware fallback name is always
//! `BOOTX64.EFI`; ARM64 (`BOOTAA64.EFI`) and 32-bit (`BOOTIA32.EFI`)
//! media are not distinguished yet.

use std::path::Path;
use std::path::PathBuf;

use crate::error::CoreError;
use crate::error::Result;
use crate::windows::bcd::Firmware;

/// What one [`install`] wrote onto the target, in write order.
///
/// UEFI holds the loader twice, then `memtest.efi` when the image
/// carries one, then the fonts, then the store; BIOS holds
/// `bootmgr`, then `boot.sdi`, then `memtest.exe` when the image
/// carries one, then the fonts, then the store. Re-running writes the
/// same paths, so a second [`Placement`] compares equal to the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// Every file written, in write order.
    pub files: Vec<PathBuf>,
}

/// Refuse when `path` is not an existing directory, naming the path and
/// which root (`data` or `esp`) was wrong.
fn require_dir(path: &Path, role: &str) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    Err(CoreError::invalid(format!(
        "{role} path {} is not an existing directory",
        path.display()
    )))
}

/// Refuse an empty store or one that does not open with `regf`.
fn require_store(store: &[u8]) -> Result<()> {
    if store.is_empty() {
        return Err(CoreError::invalid(
            "bcd store is empty, nothing to write".to_string(),
        ));
    }
    if !store.starts_with(b"regf") {
        return Err(CoreError::invalid(
            "bcd store does not start with regf, refusing a non-hive store".to_string(),
        ));
    }
    Ok(())
}

/// Pick the boot manager source. Without the 2023 opt-in the standard
/// file is always used; with it the `_EX` build (the 2023-signed
/// loader, usable only on media that requires the "Windows UEFI CA
/// 2023" Secure Boot certificate) wins when it exists and the
/// standard file is the fallback. Refuses naming both candidates
/// when neither exists. The `PCAT_EX/bootmgr_EX` candidate is looked
/// up for symmetry but has not been observed on the 24H2 media.
fn pick_boot_manager(
    normal: &Path,
    updated: &Path,
    firmware_name: &str,
    use_2023_bootloaders: bool,
) -> Result<PathBuf> {
    if use_2023_bootloaders && updated.is_file() {
        return Ok(updated.to_path_buf());
    }
    if normal.is_file() {
        return Ok(normal.to_path_buf());
    }
    Err(CoreError::invalid(format!(
        "missing {firmware_name} boot manager: neither {} nor {} exists",
        normal.display(),
        updated.display()
    )))
}

/// Pick the font source directory. With the 2023 opt-in `Fonts_EX`
/// wins when it is a directory, otherwise the standard `Fonts` is
/// used; without the opt-in the standard `Fonts` is always used.
fn fonts_source(data: &Path, use_2023_bootloaders: bool) -> PathBuf {
    let updated = data.join("Windows/Boot/Fonts_EX");
    if use_2023_bootloaders && updated.is_dir() {
        return updated;
    }
    data.join("Windows/Boot/Fonts")
}

/// Read `boot.sdi`: the `PCAT` copy wins, with the install-media
/// `DVD/PCAT` copy as fallback (WinPE-derived trees carry only the
/// DVD copy). Refuses naming `boot.sdi` when neither exists.
fn read_boot_sdi(data: &Path) -> Result<Vec<u8>> {
    let primary = data.join("Windows/Boot/PCAT/boot.sdi");
    if primary.is_file() {
        return read_source(&primary, "boot.sdi");
    }
    let fallback = data.join("Windows/Boot/DVD/PCAT/boot.sdi");
    if fallback.is_file() {
        return read_source(&fallback, "boot.sdi");
    }
    Err(CoreError::invalid(format!(
        "missing boot.sdi source file {} (fallback {} also absent)",
        primary.display(),
        fallback.display()
    )))
}

/// Read a source file that must exist, naming it when it does not.
fn read_source(path: &Path, description: &str) -> Result<Vec<u8>> {
    if !path.is_file() {
        return Err(CoreError::invalid(format!(
            "missing {description} source file {}",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|cause| CoreError::io(path, cause))
}

/// Refuse when `dest` itself is a symlink, without following it: a
/// crafted image that ships a destination as a link must not redirect
/// the write outside the mount root.
fn refuse_dest_symlink(dest: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dest) {
        Ok(meta) if meta.file_type().is_symlink() => Err(CoreError::invalid(format!(
            "refusing to write {}: a crafted image must not redirect writes outside the mounted partition",
            dest.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CoreError::io(dest, error)),
    }
}

/// Require an existing `probe` to resolve inside `root`: canonicalize
/// both and refuse unless the probe starts with the root. Names
/// `dest` (the file about to be written) so the refusal points at
/// the offending path.
fn require_existing_inside(root: &Path, probe: &Path, dest: &Path) -> Result<()> {
    let root_canon = std::fs::canonicalize(root).map_err(|cause| CoreError::io(root, cause))?;
    let probe_canon = std::fs::canonicalize(probe).map_err(|cause| CoreError::io(probe, cause))?;
    if !probe_canon.starts_with(&root_canon) {
        return Err(CoreError::invalid(format!(
            "refusing to write {}: a crafted image must not redirect writes outside the mounted partition",
            dest.display()
        )));
    }
    Ok(())
}

/// Require the nearest existing ancestor of `parent` to resolve inside
/// `root`, before `parent` is created: a symlinked prefix (an applied
/// image that ships `boot` or `EFI` as a link) refuses here instead of
/// letting `create_dir_all` build directories outside the mount root.
fn require_prefix_inside(root: &Path, parent: &Path, dest: &Path) -> Result<()> {
    let mut probe: &Path = parent;
    loop {
        match std::fs::symlink_metadata(probe) {
            Ok(_) => return require_existing_inside(root, probe, dest),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => match probe.parent() {
                Some(next) if !next.as_os_str().is_empty() => {
                    probe = next;
                }
                _ => return require_existing_inside(root, root, dest),
            },
            Err(error) => return Err(CoreError::io(probe, error)),
        }
    }
}

/// Write `bytes` to `dest` under `root`, creating parent directories as
/// needed and recording the path. Existing files are overwritten, so
/// re-running is idempotent. Before every write the destination's
/// parent chain must resolve inside `root` (canonicalized) and the
/// destination itself must not be a symlink, or the write refuses.
fn write_dest(root: &Path, dest: &Path, bytes: &[u8], files: &mut Vec<PathBuf>) -> Result<()> {
    refuse_dest_symlink(dest)?;
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        require_prefix_inside(root, parent, dest)?;
        std::fs::create_dir_all(parent).map_err(|cause| CoreError::io(parent, cause))?;
        require_existing_inside(root, parent, dest)?;
        refuse_dest_symlink(dest)?;
    }
    std::fs::write(dest, bytes).map_err(|cause| CoreError::io(dest, cause))?;
    files.push(dest.to_path_buf());
    Ok(())
}

/// Write pre-read `fonts` (see [`read_fonts`]) into `dest_dir` under
/// `root`. An empty set writes nothing, not even the directory; any
/// other failure names the path. Names arrive in sorted order so
/// [`Placement::files`] stays deterministic. The same parent-inside
/// plus no-destination-symlink rule as [`write_dest`] applies to every
/// font file.
fn write_fonts(
    root: &Path,
    dest_dir: &Path,
    fonts: &[(PathBuf, Vec<u8>)],
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    if fonts.is_empty() {
        return Ok(());
    }
    require_prefix_inside(root, dest_dir, dest_dir)?;
    std::fs::create_dir_all(dest_dir).map_err(|cause| CoreError::io(dest_dir, cause))?;
    require_existing_inside(root, dest_dir, dest_dir)?;
    for (name, bytes) in fonts {
        let dest = dest_dir.join(name);
        refuse_dest_symlink(&dest)?;
        require_existing_inside(root, dest_dir, &dest)?;
        std::fs::write(&dest, bytes).map_err(|cause| CoreError::io(&dest, cause))?;
        files.push(dest);
    }
    Ok(())
}

/// Read every regular file directly inside `fonts_dir` into memory,
/// sorted by name. A missing source directory reads as empty; any
/// other failure names the path. Reading up front keeps [`install`]
/// from writing a half-copied font set when a later file fails.
fn read_fonts(fonts_dir: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let listing = match std::fs::read_dir(fonts_dir) {
        Ok(listing) => listing,
        Err(cause) => {
            if cause.kind() == std::io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(CoreError::io(fonts_dir, cause));
        }
    };
    let mut names: Vec<PathBuf> = Vec::new();
    for entry in listing {
        let entry = entry.map_err(|cause| CoreError::io(fonts_dir, cause))?;
        let kind = entry
            .file_type()
            .map_err(|cause| CoreError::io(entry.path(), cause))?;
        if kind.is_file() {
            names.push(entry.file_name().into());
        }
    }
    names.sort();
    let mut fonts = Vec::with_capacity(names.len());
    for name in &names {
        let source = fonts_dir.join(name);
        let bytes = std::fs::read(&source).map_err(|cause| CoreError::io(&source, cause))?;
        fonts.push((name.clone(), bytes));
    }
    Ok(fonts)
}

/// Copy the Windows boot manager, its support files and the built BCD
/// store from an applied image onto the target.
///
/// `data` is the root of the applied Windows partition (already
/// mounted), `esp` the root of the mounted ESP, `store` the BCD
/// bytes built by [`crate::windows::bcd::build`], and
/// `use_2023_bootloaders` opts into the 2023-signed `_EX` boot
/// managers: with `false` the standard `Windows/Boot/EFI/bootmgfw.efi`
/// and `Windows/Boot/PCAT/bootmgr` are always used; with `true` the
/// `_EX` file is used when present, the standard one is the fallback
/// when not, and `Windows/Boot/Fonts_EX` is preferred over
/// `Windows/Boot/Fonts` for the font copy. Media written from the
/// `_EX` loaders requires the "Windows UEFI CA 2023" Secure Boot
/// certificate, so the default stays `false`.
///
/// UEFI writes the loader as both `EFI/Microsoft/Boot/bootmgfw.efi`
/// and `EFI/Boot/BOOTX64.EFI` on the ESP, `memtest.efi` beside them
/// when the image carries `Windows/Boot/EFI/memtest.efi`, plus the
/// fonts and the store; BIOS writes `bootmgr`, `boot/boot.sdi` (the
/// `PCAT` copy, falling back to the install-media
/// `Windows/Boot/DVD/PCAT/boot.sdi`), `boot/memtest.exe` when
/// present, the fonts and the store on the data partition itself.
/// Parent directories are created as needed, existing files are
/// overwritten, nothing is ever deleted, and every written path is
/// returned in [`Placement::files`] in write order. Every required
/// source is read into memory before the first write, so a missing
/// `boot.sdi` fails with nothing written.
///
/// Refuses with [`CoreError::InvalidInput`] (or [`CoreError::Io` when
/// the filesystem itself fails) naming the path and what is wrong:
/// an empty or non-`regf` store, a `data` that is not an existing
/// directory, an `esp` that is not an existing directory (UEFI only:
/// BIOS never touches the ESP, so a missing `esp` path is fine
/// there), `esp` equal to `data`, a missing source boot manager, or
/// a missing `boot.sdi` on BIOS.
pub fn install(
    data: &Path,
    esp: &Path,
    firmware: Firmware,
    store: &[u8],
    use_2023_bootloaders: bool,
) -> Result<Placement> {
    require_store(store)?;
    require_dir(data, "data")?;
    if data == esp {
        return Err(CoreError::invalid(format!(
            "esp path {} must differ from the data path {}: they are separate filesystems",
            esp.display(),
            data.display()
        )));
    }
    if firmware == Firmware::Uefi {
        require_dir(esp, "esp")?;
    }
    let mut files: Vec<PathBuf> = Vec::new();
    // Every required source is read before the first write, and the
    // optional payloads (`memtest`, fonts) are read too, so a failure
    // below is a refusal with nothing written, never a half target.
    match firmware {
        Firmware::Uefi => {
            let normal = data.join("Windows/Boot/EFI/bootmgfw.efi");
            let updated = data.join("Windows/Boot/EFI_EX/bootmgfw_EX.efi");
            let source = pick_boot_manager(&normal, &updated, "uefi", use_2023_bootloaders)?;
            let loader = read_source(&source, "uefi boot manager")?;
            let memtest_source = data.join("Windows/Boot/EFI/memtest.efi");
            let memtest = if memtest_source.is_file() {
                Some(read_source(&memtest_source, "memtest.efi")?)
            } else {
                None
            };
            let fonts = read_fonts(&fonts_source(data, use_2023_bootloaders))?;
            let boot_dir = esp.join("EFI/Microsoft/Boot");
            write_dest(esp, &boot_dir.join("bootmgfw.efi"), &loader, &mut files)?;
            write_dest(esp, &esp.join("EFI/Boot/BOOTX64.EFI"), &loader, &mut files)?;
            if let Some(bytes) = &memtest {
                write_dest(esp, &boot_dir.join("memtest.efi"), bytes, &mut files)?;
            }
            write_fonts(esp, &boot_dir.join("Fonts"), &fonts, &mut files)?;
            write_dest(esp, &boot_dir.join("BCD"), store, &mut files)?;
        }
        Firmware::Bios => {
            let normal = data.join("Windows/Boot/PCAT/bootmgr");
            let updated = data.join("Windows/Boot/PCAT_EX/bootmgr_EX");
            let source = pick_boot_manager(&normal, &updated, "bios", use_2023_bootloaders)?;
            let manager = read_source(&source, "bios boot manager")?;
            let sdi = read_boot_sdi(data)?;
            let memtest_source = data.join("Windows/Boot/PCAT/memtest.exe");
            let memtest = if memtest_source.is_file() {
                Some(read_source(&memtest_source, "memtest.exe")?)
            } else {
                None
            };
            let fonts = read_fonts(&fonts_source(data, use_2023_bootloaders))?;
            write_dest(data, &data.join("bootmgr"), &manager, &mut files)?;
            let boot_dir = data.join("boot");
            write_dest(data, &boot_dir.join("boot.sdi"), &sdi, &mut files)?;
            if let Some(bytes) = &memtest {
                write_dest(data, &boot_dir.join("memtest.exe"), bytes, &mut files)?;
            }
            write_fonts(data, &boot_dir.join("fonts"), &fonts, &mut files)?;
            write_dest(data, &boot_dir.join("bcd"), store, &mut files)?;
        }
    }
    Ok(Placement { files })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EFI_LOADER: &[u8] = b"fake-bootmgfw-efi";
    const EFI_LOADER_EX: &[u8] = b"fake-bootmgfw-ex-2023-signed";
    const EFI_MEMTEST: &[u8] = b"fake-memtest-efi";
    const BIOS_LOADER: &[u8] = b"fake-bootmgr-bios";
    const BIOS_LOADER_EX: &[u8] = b"fake-bootmgr-ex-bios";
    const BOOT_SDI: &[u8] = b"fake-boot-sdi";
    const MEMTEST: &[u8] = b"fake-memtest-exe";
    const FONT_A: &[u8] = b"fake-font-segoe-slboot";
    const FONT_B: &[u8] = b"fake-font-segoe-slbrk";
    const FONT_EX: &[u8] = b"fake-font-2023-segoe";

    /// A `regf`-looking store: [`install`] only checks the prefix.
    fn fake_store() -> Vec<u8> {
        let mut store = b"regf-fake-bcd-store".to_vec();
        store.extend_from_slice(&[0u8; 64]);
        store
    }

    /// Write `bytes` at `rel` under `root`, creating parents.
    fn put(root: &Path, rel: &str, bytes: &[u8]) {
        let dest = root.join(rel);
        let parent = dest.parent().expect("fixture path must have a parent");
        std::fs::create_dir_all(parent).expect("fixture parent must create");
        std::fs::write(&dest, bytes).expect("fixture file must write");
    }

    /// Read a placed file back.
    fn read(path: &Path) -> Vec<u8> {
        std::fs::read(path).expect("placed file must read")
    }

    /// A synthetic applied-image tree with tiny fake payloads: the
    /// normal boot managers, `boot.sdi`, `memtest.exe`, `memtest.efi`
    /// and two fonts.
    fn full_tree() -> (tempfile::TempDir, tempfile::TempDir) {
        let data = tempfile::tempdir().expect("data scratch must create");
        let esp = tempfile::tempdir().expect("esp scratch must create");
        put(data.path(), "Windows/Boot/EFI/bootmgfw.efi", EFI_LOADER);
        put(data.path(), "Windows/Boot/EFI/memtest.efi", EFI_MEMTEST);
        put(data.path(), "Windows/Boot/PCAT/bootmgr", BIOS_LOADER);
        put(data.path(), "Windows/Boot/PCAT/boot.sdi", BOOT_SDI);
        put(data.path(), "Windows/Boot/PCAT/memtest.exe", MEMTEST);
        put(data.path(), "Windows/Boot/Fonts/font-a.ttf", FONT_A);
        put(data.path(), "Windows/Boot/Fonts/font-b.ttf", FONT_B);
        (data, esp)
    }

    /// A refusal must be `InvalidInput`, name `needle`, and stay ASCII.
    fn assert_invalid(result: Result<Placement>, needle: &str) {
        let err = result.expect_err("refusal expected");
        assert!(
            matches!(err, CoreError::InvalidInput { .. }),
            "must be InvalidInput, got {err}"
        );
        assert!(
            err.to_string().contains(needle),
            "must name {needle}, got {err}"
        );
        assert!(err.to_string().is_ascii(), "message must stay ASCII: {err}");
    }

    #[test]
    fn uefi_writes_loader_twice_fonts_and_bcd() {
        let (data, esp) = full_tree();
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Uefi, &store, false)
            .expect("uefi install must succeed");
        let boot = esp.path().join("EFI/Microsoft/Boot");
        let expected = vec![
            boot.join("bootmgfw.efi"),
            esp.path().join("EFI/Boot/BOOTX64.EFI"),
            boot.join("memtest.efi"),
            boot.join("Fonts/font-a.ttf"),
            boot.join("Fonts/font-b.ttf"),
            boot.join("BCD"),
        ];
        assert_eq!(placement.files, expected, "uefi must write in order");
        assert_eq!(read(&boot.join("bootmgfw.efi")), EFI_LOADER);
        assert_eq!(read(&esp.path().join("EFI/Boot/BOOTX64.EFI")), EFI_LOADER);
        assert_eq!(read(&boot.join("memtest.efi")), EFI_MEMTEST);
        assert_eq!(read(&boot.join("Fonts/font-a.ttf")), FONT_A);
        assert_eq!(read(&boot.join("Fonts/font-b.ttf")), FONT_B);
        assert_eq!(read(&boot.join("BCD")), store);
        // ESP and data stay separate: nothing lands in the data tree,
        // and the image tree is never copied onto the ESP.
        assert!(
            !data.path().join("EFI").exists(),
            "uefi must not write into the data tree"
        );
        assert!(
            !esp.path().join("Windows").exists(),
            "uefi must not copy the image tree onto the ESP"
        );
        assert!(
            !esp.path().join("bootmgr").exists(),
            "uefi must not write the bios boot manager"
        );
    }

    #[test]
    fn bios_writes_bootmgr_sdi_memtest_fonts_and_bcd() {
        let (data, esp) = full_tree();
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Bios, &store, false)
            .expect("bios install must succeed");
        let boot = data.path().join("boot");
        let expected = vec![
            data.path().join("bootmgr"),
            boot.join("boot.sdi"),
            boot.join("memtest.exe"),
            boot.join("fonts/font-a.ttf"),
            boot.join("fonts/font-b.ttf"),
            boot.join("bcd"),
        ];
        assert_eq!(placement.files, expected, "bios must write in order");
        assert_eq!(read(&data.path().join("bootmgr")), BIOS_LOADER);
        assert_eq!(read(&boot.join("boot.sdi")), BOOT_SDI);
        assert_eq!(read(&boot.join("memtest.exe")), MEMTEST);
        assert_eq!(read(&boot.join("fonts/font-a.ttf")), FONT_A);
        assert_eq!(read(&boot.join("fonts/font-b.ttf")), FONT_B);
        assert_eq!(read(&boot.join("bcd")), store);
        // The ESP is untouched by a BIOS install.
        assert!(
            std::fs::read_dir(esp.path())
                .expect("esp must list")
                .next()
                .is_none(),
            "bios must not write onto the ESP"
        );
    }

    #[test]
    fn standard_bootloaders_win_by_default_even_with_ex_present() {
        // The `_EX` files and `Fonts_EX` exist, but without the opt-in
        // the standard files are used and the `_EX` side is ignored.
        let (data, esp) = full_tree();
        put(
            data.path(),
            "Windows/Boot/EFI_EX/bootmgfw_EX.efi",
            EFI_LOADER_EX,
        );
        put(
            data.path(),
            "Windows/Boot/PCAT_EX/bootmgr_EX",
            BIOS_LOADER_EX,
        );
        put(data.path(), "Windows/Boot/Fonts_EX/font-x.ttf", FONT_EX);
        let store = fake_store();
        install(data.path(), esp.path(), Firmware::Uefi, &store, false)
            .expect("uefi install must succeed");
        assert_eq!(
            read(&esp.path().join("EFI/Microsoft/Boot/bootmgfw.efi")),
            EFI_LOADER,
            "without the opt-in uefi must copy the standard loader"
        );
        assert_eq!(
            read(&esp.path().join("EFI/Boot/BOOTX64.EFI")),
            EFI_LOADER,
            "without the opt-in the uefi fallback uses the standard loader"
        );
        assert!(
            !esp.path()
                .join("EFI/Microsoft/Boot/Fonts/font-x.ttf")
                .exists(),
            "without the opt-in Fonts_EX must be ignored"
        );
        install(data.path(), esp.path(), Firmware::Bios, &store, false)
            .expect("bios install must succeed");
        assert_eq!(
            read(&data.path().join("bootmgr")),
            BIOS_LOADER,
            "without the opt-in bios must copy the standard boot manager"
        );
        assert!(
            !data.path().join("boot/fonts/font-x.ttf").exists(),
            "without the opt-in bios must ignore Fonts_EX"
        );
    }

    #[test]
    fn opt_in_prefers_ex_and_fonts_ex() {
        let (data, esp) = full_tree();
        put(
            data.path(),
            "Windows/Boot/EFI_EX/bootmgfw_EX.efi",
            EFI_LOADER_EX,
        );
        put(
            data.path(),
            "Windows/Boot/PCAT_EX/bootmgr_EX",
            BIOS_LOADER_EX,
        );
        put(data.path(), "Windows/Boot/Fonts_EX/font-x.ttf", FONT_EX);
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Uefi, &store, true)
            .expect("uefi install must succeed");
        assert_eq!(
            read(&esp.path().join("EFI/Microsoft/Boot/bootmgfw.efi")),
            EFI_LOADER_EX,
            "opt-in uefi must copy the _EX loader"
        );
        assert_eq!(
            read(&esp.path().join("EFI/Boot/BOOTX64.EFI")),
            EFI_LOADER_EX,
            "opt-in uefi fallback must copy the _EX loader too"
        );
        let boot = esp.path().join("EFI/Microsoft/Boot");
        assert_eq!(
            read(&boot.join("Fonts/font-x.ttf")),
            FONT_EX,
            "opt-in uefi must copy Fonts_EX"
        );
        assert!(
            !boot.join("Fonts/font-a.ttf").exists(),
            "opt-in uefi must not also copy the standard fonts"
        );
        assert!(
            placement.files.contains(&boot.join("Fonts/font-x.ttf")),
            "opt-in fonts must be listed in order"
        );
        install(data.path(), esp.path(), Firmware::Bios, &store, true)
            .expect("bios install must succeed");
        assert_eq!(
            read(&data.path().join("bootmgr")),
            BIOS_LOADER_EX,
            "opt-in bios must copy the _EX boot manager"
        );
        assert_eq!(
            read(&data.path().join("boot/fonts/font-x.ttf")),
            FONT_EX,
            "opt-in bios must copy Fonts_EX"
        );
    }

    #[test]
    fn opt_in_falls_back_to_standard_without_ex() {
        // `Fonts_EX` alone (no `_EX` loader beside it) still selects
        // the `_EX` fonts while the loader falls back to standard.
        let (data, esp) = full_tree();
        put(data.path(), "Windows/Boot/Fonts_EX/font-x.ttf", FONT_EX);
        let store = fake_store();
        install(data.path(), esp.path(), Firmware::Uefi, &store, true)
            .expect("uefi install must succeed");
        assert_eq!(
            read(&esp.path().join("EFI/Microsoft/Boot/bootmgfw.efi")),
            EFI_LOADER,
            "opt-in without _EX must fall back to the standard loader"
        );
        assert_eq!(
            read(&esp.path().join("EFI/Microsoft/Boot/Fonts/font-x.ttf")),
            FONT_EX,
            "opt-in without _EX loader must still prefer Fonts_EX"
        );
        install(data.path(), esp.path(), Firmware::Bios, &store, true)
            .expect("bios install must succeed");
        assert_eq!(
            read(&data.path().join("bootmgr")),
            BIOS_LOADER,
            "opt-in without _EX must fall back to the standard boot manager"
        );
    }

    #[test]
    fn bios_uses_dvd_boot_sdi_fallback() {
        // WinPE-derived trees carry `boot.sdi` only under `DVD/PCAT`.
        let data = tempfile::tempdir().expect("data scratch must create");
        let esp = tempfile::tempdir().expect("esp scratch must create");
        put(data.path(), "Windows/Boot/PCAT/bootmgr", BIOS_LOADER);
        put(data.path(), "Windows/Boot/DVD/PCAT/boot.sdi", BOOT_SDI);
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Bios, &store, false)
            .expect("dvd fallback install must succeed");
        assert_eq!(
            read(&data.path().join("boot/boot.sdi")),
            BOOT_SDI,
            "bios must copy the DVD fallback boot.sdi"
        );
        assert_eq!(
            placement.files,
            vec![
                data.path().join("bootmgr"),
                data.path().join("boot/boot.sdi"),
                data.path().join("boot/bcd"),
            ],
            "dvd fallback writes bootmgr, sdi and the store"
        );
    }

    #[test]
    fn missing_boot_sdi_writes_nothing() {
        let data = tempfile::tempdir().expect("data scratch must create");
        let esp = tempfile::tempdir().expect("esp scratch must create");
        put(data.path(), "Windows/Boot/PCAT/bootmgr", BIOS_LOADER);
        let store = fake_store();
        let err = install(data.path(), esp.path(), Firmware::Bios, &store, false)
            .expect_err("missing boot.sdi must refuse");
        assert!(
            err.to_string().contains("boot.sdi"),
            "refusal must name boot.sdi, got {err}"
        );
        assert!(
            !data.path().join("bootmgr").exists(),
            "a missing boot.sdi must leave nothing written"
        );
        assert!(
            !data.path().join("boot").exists(),
            "a missing boot.sdi must not create the boot directory"
        );
    }

    #[test]
    fn second_install_writes_the_same_paths_and_bytes() {
        for firmware in [Firmware::Uefi, Firmware::Bios] {
            let (data, esp) = full_tree();
            let store = fake_store();
            let first = install(data.path(), esp.path(), firmware, &store, false)
                .expect("first install must succeed");
            let before: Vec<Vec<u8>> = first.files.iter().map(|path| read(path)).collect();
            let second = install(data.path(), esp.path(), firmware, &store, false)
                .expect("second install must succeed");
            assert_eq!(
                first.files, second.files,
                "re-running must list the same paths"
            );
            let after: Vec<Vec<u8>> = second.files.iter().map(|path| read(path)).collect();
            assert_eq!(before, after, "re-running must keep the same bytes");
        }
    }

    #[test]
    fn bios_without_memtest_and_fonts_still_installs() {
        let data = tempfile::tempdir().expect("data scratch must create");
        let esp = tempfile::tempdir().expect("esp scratch must create");
        put(data.path(), "Windows/Boot/PCAT/bootmgr", BIOS_LOADER);
        put(data.path(), "Windows/Boot/PCAT/boot.sdi", BOOT_SDI);
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Bios, &store, false)
            .expect("missing memtest and fonts must not refuse");
        let boot = data.path().join("boot");
        assert_eq!(
            placement.files,
            vec![
                data.path().join("bootmgr"),
                boot.join("boot.sdi"),
                boot.join("bcd"),
            ],
            "bios without memtest and fonts writes three files"
        );
        assert_eq!(read(&boot.join("bcd")), store);
    }

    #[test]
    fn uefi_without_memtest_and_fonts_copies_three_files() {
        // No `memtest.efi` and no fonts: both are optional on UEFI.
        let data = tempfile::tempdir().expect("data scratch must create");
        let esp = tempfile::tempdir().expect("esp scratch must create");
        put(data.path(), "Windows/Boot/EFI/bootmgfw.efi", EFI_LOADER);
        let store = fake_store();
        let placement = install(data.path(), esp.path(), Firmware::Uefi, &store, false)
            .expect("missing memtest and fonts must not refuse");
        let boot = esp.path().join("EFI/Microsoft/Boot");
        assert_eq!(
            placement.files,
            vec![
                boot.join("bootmgfw.efi"),
                esp.path().join("EFI/Boot/BOOTX64.EFI"),
                boot.join("BCD"),
            ],
            "uefi without memtest and fonts writes three files"
        );
        assert!(
            !boot.join("memtest.efi").exists(),
            "uefi must not invent a memtest.efi the image lacks"
        );
    }

    #[test]
    fn refusals_name_path_and_cause() {
        let (data, esp) = full_tree();
        let store = fake_store();
        assert_invalid(
            install(data.path(), esp.path(), Firmware::Uefi, &[], false),
            "empty",
        );
        assert_invalid(
            install(
                data.path(),
                esp.path(),
                Firmware::Uefi,
                b"not-a-hive",
                false,
            ),
            "regf",
        );
        // A data tree with no boot managers at all: the refusal names
        // both the standard and the `_EX` candidate files.
        let bare_data = tempfile::tempdir().expect("bare data must create");
        let bare_esp = tempfile::tempdir().expect("bare esp must create");
        assert_invalid(
            install(
                bare_data.path(),
                bare_esp.path(),
                Firmware::Uefi,
                &store,
                false,
            ),
            "bootmgfw.efi",
        );
        assert_invalid(
            install(
                bare_data.path(),
                bare_esp.path(),
                Firmware::Uefi,
                &store,
                false,
            ),
            "bootmgfw_EX.efi",
        );
        assert_invalid(
            install(
                bare_data.path(),
                bare_esp.path(),
                Firmware::Bios,
                &store,
                false,
            ),
            "bootmgr",
        );
        assert_invalid(
            install(
                bare_data.path(),
                bare_esp.path(),
                Firmware::Bios,
                &store,
                true,
            ),
            "bootmgr_EX",
        );
        // BIOS with a boot manager but no boot.sdi anywhere.
        let no_sdi = tempfile::tempdir().expect("no-sdi data must create");
        put(no_sdi.path(), "Windows/Boot/PCAT/bootmgr", BIOS_LOADER);
        assert_invalid(
            install(no_sdi.path(), esp.path(), Firmware::Bios, &store, false),
            "boot.sdi",
        );
        assert_invalid(
            install(no_sdi.path(), esp.path(), Firmware::Bios, &store, false),
            "DVD/PCAT/boot.sdi",
        );
        // ESP and data must differ, for both firmware paths.
        assert_invalid(
            install(data.path(), data.path(), Firmware::Uefi, &store, false),
            "differ",
        );
        assert_invalid(
            install(data.path(), data.path(), Firmware::Bios, &store, false),
            "differ",
        );
        // A missing data root refuses for both firmware paths.
        let missing = data.path().join("no-such-dir");
        assert_invalid(
            install(&missing, esp.path(), Firmware::Uefi, &store, false),
            "no-such-dir",
        );
        assert_invalid(
            install(&missing, esp.path(), Firmware::Bios, &store, true),
            "no-such-dir",
        );
        // UEFI needs an existing ESP directory ...
        let missing_esp = esp.path().join("no-such-esp");
        assert_invalid(
            install(data.path(), &missing_esp, Firmware::Uefi, &store, false),
            "no-such-esp",
        );
        let file_esp = esp.path().join("plain-file");
        std::fs::write(&file_esp, b"not a dir").expect("plain file must write");
        assert_invalid(
            install(data.path(), &file_esp, Firmware::Uefi, &store, false),
            "plain-file",
        );
        // ... while BIOS never touches the ESP, so a missing `esp`
        // path installs fine.
        let placement = install(data.path(), &missing_esp, Firmware::Bios, &store, false)
            .expect("bios must not need the esp");
        assert_eq!(
            read(&data.path().join("bootmgr")),
            BIOS_LOADER,
            "bios without an esp still places the boot manager"
        );
        assert!(
            placement
                .files
                .iter()
                .all(|path| !path.starts_with(&missing_esp)),
            "bios must write nothing under the missing esp"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_directory_refuses_without_writing_outside() {
        // A crafted image ships `boot` (BIOS) or `EFI` (UEFI) as a
        // symlink: every destination beneath it must refuse, naming the
        // offending path, with nothing written outside the root.
        let phrase = "a crafted image must not redirect writes outside the mounted partition";
        // BIOS: `data/boot` points outside.
        {
            let (data, esp) = full_tree();
            let store = fake_store();
            let outside = tempfile::tempdir().expect("outside must create");
            let link = data.path().join("boot");
            std::os::unix::fs::symlink(outside.path(), &link).expect("symlink must create");
            let err = install(data.path(), esp.path(), Firmware::Bios, &store, false)
                .expect_err("a symlinked boot dir must refuse");
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "must be InvalidInput, got {err}"
            );
            let text = err.to_string();
            assert!(
                text.contains(&link.display().to_string()) || text.contains("boot"),
                "{text}"
            );
            assert!(text.contains(phrase), "{text}");
            assert!(text.is_ascii(), "{text}");
            assert_eq!(
                std::fs::read_dir(outside.path())
                    .expect("outside must list")
                    .count(),
                0,
                "nothing is written through the symlinked boot dir"
            );
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link must stat")
                    .file_type()
                    .is_symlink(),
                "the refused install leaves the link itself alone"
            );
        }
        // UEFI: `esp/EFI` points outside.
        {
            let (data, esp) = full_tree();
            let store = fake_store();
            let outside = tempfile::tempdir().expect("outside must create");
            let link = esp.path().join("EFI");
            std::os::unix::fs::symlink(outside.path(), &link).expect("symlink must create");
            let err = install(data.path(), esp.path(), Firmware::Uefi, &store, false)
                .expect_err("a symlinked EFI dir must refuse");
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "must be InvalidInput, got {err}"
            );
            let text = err.to_string();
            assert!(text.contains("EFI"), "{text}");
            assert!(text.contains(phrase), "{text}");
            assert!(text.is_ascii(), "{text}");
            assert_eq!(
                std::fs::read_dir(outside.path())
                    .expect("outside must list")
                    .count(),
                0,
                "nothing is written through the symlinked EFI dir"
            );
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link must stat")
                    .file_type()
                    .is_symlink(),
                "the refused install leaves the link itself alone"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_destination_file_refuses_without_writing_outside() {
        // A crafted image ships a destination file itself as a symlink:
        // the write refuses without following the link.
        let phrase = "a crafted image must not redirect writes outside the mounted partition";
        // BIOS: `data/bootmgr` points at a host file.
        {
            let (data, esp) = full_tree();
            let store = fake_store();
            let outside = tempfile::tempdir().expect("outside must create");
            let target = outside.path().join("host-secret");
            std::fs::write(&target, b"host-secret-must-survive").expect("outside must write");
            let link = data.path().join("bootmgr");
            std::os::unix::fs::symlink(&target, &link).expect("symlink must create");
            let err = install(data.path(), esp.path(), Firmware::Bios, &store, false)
                .expect_err("a symlinked bootmgr must refuse");
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "must be InvalidInput, got {err}"
            );
            let text = err.to_string();
            assert!(text.contains(&link.display().to_string()), "{text}");
            assert!(text.contains(phrase), "{text}");
            assert!(text.is_ascii(), "{text}");
            assert_eq!(
                std::fs::read(&target).expect("outside must read"),
                b"host-secret-must-survive",
                "nothing is written through the symlinked file"
            );
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link must stat")
                    .file_type()
                    .is_symlink(),
                "the refused install leaves the link itself alone"
            );
        }
        // UEFI: the ESP store destination points at a host file. The
        // parent chain exists so the refusal names the file itself.
        {
            let (data, esp) = full_tree();
            let store = fake_store();
            let outside = tempfile::tempdir().expect("outside must create");
            let target = outside.path().join("host-secret");
            std::fs::write(&target, b"host-secret-must-survive").expect("outside must write");
            let boot_dir = esp.path().join("EFI/Microsoft/Boot");
            std::fs::create_dir_all(&boot_dir).expect("esp parents must create");
            let link = boot_dir.join("BCD");
            std::os::unix::fs::symlink(&target, &link).expect("symlink must create");
            let err = install(data.path(), esp.path(), Firmware::Uefi, &store, false)
                .expect_err("a symlinked BCD must refuse");
            assert!(
                matches!(err, CoreError::InvalidInput { .. }),
                "must be InvalidInput, got {err}"
            );
            let text = err.to_string();
            assert!(text.contains(&link.display().to_string()), "{text}");
            assert!(text.contains(phrase), "{text}");
            assert!(text.is_ascii(), "{text}");
            assert_eq!(
                std::fs::read(&target).expect("outside must read"),
                b"host-secret-must-survive",
                "nothing is written through the symlinked ESP file"
            );
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link must stat")
                    .file_type()
                    .is_symlink(),
                "the refused install leaves the link itself alone"
            );
        }
    }

    /// Copy a directory tree (regular files and subdirectories only).
    fn copy_tree(source: &Path, dest: &Path) {
        std::fs::create_dir_all(dest).expect("copy dest must create");
        let listing = std::fs::read_dir(source).expect("copy source must list");
        for entry in listing {
            let entry = entry.expect("copy entry must read");
            let kind = entry.file_type().expect("copy entry must stat");
            let target = dest.join(entry.file_name());
            if kind.is_dir() {
                copy_tree(&entry.path(), &target);
            } else if kind.is_file() {
                std::fs::copy(entry.path(), &target).expect("copy file must copy");
            }
        }
    }

    /// The real `Windows/Boot` tree from an extracted Windows or WinPE
    /// image. Ignored by default: set `RUFUS_TEST_WINDOWS_TREE` to the
    /// extracted tree root to run it.
    ///
    /// What this now proves: the default install copies the standard
    /// boot managers even when the `_EX` files exist, the opt-in
    /// install takes the `_EX` files (falling back to standard where
    /// the tree has none, as `PCAT_EX` is unobserved), the UEFI
    /// `memtest.efi` lands on the ESP when the tree carries one, and
    /// the BIOS `boot.sdi` comes from the `DVD/PCAT` fallback on
    /// WinPE-derived trees — all real Microsoft bytes.
    #[test]
    #[ignore]
    fn real_windows_tree_places_boot_files() {
        let Ok(tree) = std::env::var("RUFUS_TEST_WINDOWS_TREE") else {
            println!("skip: RUFUS_TEST_WINDOWS_TREE is not set");
            return;
        };
        let tree = PathBuf::from(tree);
        let store = fake_store();
        let updated = tree.join("Windows/Boot/EFI_EX/bootmgfw_EX.efi");
        let normal = tree.join("Windows/Boot/EFI/bootmgfw.efi");
        assert!(
            normal.is_file() || updated.is_file(),
            "real tree must carry a uefi boot manager"
        );
        let bios_updated = tree.join("Windows/Boot/PCAT_EX/bootmgr_EX");
        let bios_normal = tree.join("Windows/Boot/PCAT/bootmgr");
        assert!(
            bios_normal.is_file() || bios_updated.is_file(),
            "real tree must carry a bios boot manager"
        );
        // UEFI default: the standard loader even when `_EX` exists.
        let esp = tempfile::tempdir().expect("esp scratch must create");
        install(&tree, esp.path(), Firmware::Uefi, &store, false)
            .expect("real uefi install must succeed");
        let normal_bytes = std::fs::read(&normal).expect("real loader must read");
        let boot = esp.path().join("EFI/Microsoft/Boot");
        assert_eq!(
            read(&boot.join("bootmgfw.efi")),
            normal_bytes,
            "default uefi must copy the standard boot manager"
        );
        assert_eq!(
            read(&esp.path().join("EFI/Boot/BOOTX64.EFI")),
            normal_bytes,
            "default uefi fallback must copy the standard boot manager"
        );
        assert_eq!(read(&boot.join("BCD")), store);
        // UEFI opt-in: the `_EX` loader when present, else standard.
        let esp_ex = tempfile::tempdir().expect("opt-in esp must create");
        install(&tree, esp_ex.path(), Firmware::Uefi, &store, true)
            .expect("real opt-in uefi install must succeed");
        let wanted = if updated.is_file() { &updated } else { &normal };
        let wanted_bytes = std::fs::read(wanted).expect("real loader must read");
        let boot_ex = esp_ex.path().join("EFI/Microsoft/Boot");
        assert_eq!(
            read(&boot_ex.join("bootmgfw.efi")),
            wanted_bytes,
            "opt-in uefi must copy the _EX loader when present"
        );
        assert_eq!(
            read(&esp_ex.path().join("EFI/Boot/BOOTX64.EFI")),
            wanted_bytes,
            "opt-in uefi fallback must match"
        );
        // UEFI memory diagnostics: placed when the tree carries the
        // source, skipped when it does not.
        let memtest_source = tree.join("Windows/Boot/EFI/memtest.efi");
        if memtest_source.is_file() {
            assert_eq!(
                read(&boot.join("memtest.efi")),
                std::fs::read(&memtest_source).expect("real memtest must read"),
                "uefi must copy the real memtest.efi"
            );
        } else {
            println!("note: real tree carries no EFI memtest.efi to place");
            assert!(
                !boot.join("memtest.efi").exists(),
                "uefi must not invent a memtest.efi the tree lacks"
            );
        }
        // The real fonts must have been found and copied byte for byte
        // (the default install always uses the standard directory).
        let fonts_dir = tree.join("Windows/Boot/Fonts");
        let mut names: Vec<PathBuf> = Vec::new();
        let listing = std::fs::read_dir(&fonts_dir).expect("real fonts must list");
        for entry in listing {
            let entry = entry.expect("real font entry must read");
            if entry.file_type().expect("real font must stat").is_file() {
                names.push(entry.file_name().into());
            }
        }
        assert!(!names.is_empty(), "real tree must carry boot fonts");
        names.sort();
        for name in &names {
            let source_bytes = std::fs::read(fonts_dir.join(name)).expect("real font must read");
            assert_eq!(
                read(&boot.join("Fonts").join(name)),
                source_bytes,
                "font must copy byte for byte"
            );
        }
        // BIOS installs into a scratch copy, so the real tree is never
        // written to. WinPE's `PCAT` carries no `boot.sdi` (it lives in
        // the install media's `DVD/PCAT` instead): the install itself
        // must take the fallback, with no seeding by the test.
        let data_spot = tempfile::tempdir().expect("bios data must create");
        copy_tree(&tree, data_spot.path());
        let bios_wanted = if bios_updated.is_file() {
            &bios_updated
        } else {
            &bios_normal
        };
        install(data_spot.path(), esp.path(), Firmware::Bios, &store, false)
            .expect("real bios install must succeed");
        assert_eq!(
            read(&data_spot.path().join("bootmgr")),
            std::fs::read(&bios_normal).expect("real bootmgr must read"),
            "default bios must copy the standard boot manager"
        );
        let sdi_primary = tree.join("Windows/Boot/PCAT/boot.sdi");
        let sdi_fallback = tree.join("Windows/Boot/DVD/PCAT/boot.sdi");
        let sdi_wanted = if sdi_primary.is_file() {
            &sdi_primary
        } else {
            &sdi_fallback
        };
        assert!(
            sdi_wanted.is_file(),
            "real tree must carry a boot.sdi in PCAT or DVD/PCAT"
        );
        assert_eq!(
            read(&data_spot.path().join("boot/boot.sdi")),
            std::fs::read(sdi_wanted).expect("real boot.sdi must read"),
            "bios must copy the real boot.sdi through the DVD fallback when needed"
        );
        // BIOS opt-in: the `_EX` boot manager when present (unobserved
        // on 24H2, so this usually re-proves the standard fallback).
        let data_ex = tempfile::tempdir().expect("opt-in bios data must create");
        copy_tree(&tree, data_ex.path());
        install(data_ex.path(), esp.path(), Firmware::Bios, &store, true)
            .expect("real opt-in bios install must succeed");
        assert_eq!(
            read(&data_ex.path().join("bootmgr")),
            std::fs::read(bios_wanted).expect("real bootmgr must read"),
            "opt-in bios must copy the _EX boot manager when present"
        );
        assert_eq!(read(&data_spot.path().join("boot/bcd")), store);
        let copied_fonts =
            std::fs::read_dir(data_spot.path().join("boot/fonts")).expect("bios fonts must list");
        assert_eq!(
            copied_fonts.count(),
            names.len(),
            "bios must copy every real font"
        );
    }
}
