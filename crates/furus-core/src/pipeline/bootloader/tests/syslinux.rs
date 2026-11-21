use super::*;

#[test]
fn syslinux_604_installs_stage_companions_and_config() {
    let (backing, mut fat) = formatted();
    let source = syslinux_604_tree();
    let installed =
        tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
    let Installed::Syslinux {
        family,
        dir,
        companions,
        config_path,
        messages,
        ..
    } = installed
    else {
        panic!("a syslinux install reports the Syslinux variant");
    };
    assert_eq!(family, Family::V604, "the 6.04 family wins");
    assert_eq!(dir, "/isolinux", "the located directory");
    assert_eq!(
        companions,
        [
            "ldlinux.c32".to_string(),
            "menu.c32".to_string(),
            "vesamenu.c32".to_string(),
            "libutil.c32".to_string(),
        ],
        "all four companions in order"
    );
    assert_eq!(config_path, "/syslinux.cfg", "the wrapper path");
    assert_eq!(
        messages[0], "  Will use '/isolinux' for Syslinux",
        "the located line prints first"
    );
    assert_eq!(
        messages[1], "  Detected Syslinux version: 6.04 (from '/isolinux/isolinux.bin')",
        "the detection line is verbatim"
    );
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    // The wrapper chains back to the image's own config.
    let expected =
        boot_syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
    let back = fat
        .read_file("/syslinux.cfg")
        .expect("the wrapper reads back");
    assert_eq!(back, expected, "the wrapper is byte-identical");
    // The stage and the boot sector are the 6.04 payload's.
    let core = asset_loader(Resource::Syslinux604Core)
        .expect("the core loads")
        .bytes()
        .to_vec();
    let stage = fat.read_file("/ldlinux.sys").expect("the stage reads back");
    assert_eq!(
        stage.len(),
        core.len() + 1024,
        "the stage adds 1024 adv bytes"
    );
    let sector = backing.boot_sector();
    assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
    assert_eq!(
        2 + u16::from(sector[1]),
        0x5A,
        "the jump targets the code at 0x5A"
    );
    assert_eq!(
        &sector[3..11],
        b"SYSLINUX",
        "the payload OEM marks the volume"
    );
    for name in ["ldlinux.c32", "menu.c32", "vesamenu.c32", "libutil.c32"] {
        let path = format!("/isolinux/{name}");
        let back = fat.read_file(&path).expect("the companion reads back");
        assert_eq!(back, name.as_bytes(), "the companion is byte-identical");
    }
}

#[test]
fn syslinux_407_logs_its_detection_and_needs_no_library() {
    let (_backing, mut fat) = formatted();
    let source = syslinux_407_tree();
    let installed =
        tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
    let Installed::Syslinux {
        family,
        companions,
        messages,
        ..
    } = installed
    else {
        panic!("a syslinux install reports the Syslinux variant");
    };
    assert_eq!(family, Family::V407, "the 4.07 family wins");
    assert_eq!(
        messages[0], "  Will use '/isolinux' for Syslinux",
        "the located line prints first"
    );
    assert_eq!(
        messages[1], "  Detected Syslinux version: 4.07 (from '/isolinux/isolinux.bin')",
        "the detection line is verbatim"
    );
    assert_eq!(
        companions,
        Vec::<String>::new(),
        "no companions ship with this tree"
    );
    // Only the wrapper config caution-free install ran: the one
    // companion present is the wrapper's own chain target.
    let back = fat
        .read_file("/syslinux.cfg")
        .expect("the wrapper reads back");
    assert_eq!(
        back,
        boot_syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
        "the wrapper chains to the held config"
    );
}

#[test]
fn bannerless_tree_forces_the_family_from_the_library() {
    // No banner anywhere but `ldlinux.c32` present: the family is
    // forced to 6.04 with the reference warning line.
    let source = payload_tree(b"no banner here", &["isolinux.cfg", "ldlinux.c32"]);
    let (_backing, mut fat) = formatted();
    let installed =
        tree_install(&source, &mut fat, &BootloaderMode::Auto).expect("the forced install runs");
    let Installed::Syslinux {
        family, messages, ..
    } = installed
    else {
        panic!("a forced install reports the Syslinux variant");
    };
    assert_eq!(family, Family::V604, "the library forces 6.04");
    assert_eq!(messages[0], "auto: probing syslinux", "the probe is logged");
    assert_eq!(
        messages[1], "  Will use '/isolinux' for Syslinux",
        "the located line prints next"
    );
    assert_eq!(
        messages[2], "  Warning: Could not detect Isolinux version - Forcing to 6.04 (embedded)",
        "the forcing line is verbatim"
    );
}

#[test]
fn syslinux_604_without_the_library_refuses_before_any_write() {
    // Banner says 6.04 but `ldlinux.c32` is absent: the required
    // module is missing, so the install refuses with the image
    // byte-identical.
    let source = payload_tree(b"ISOLINUX 6.04 20140611 ETCD", &["isolinux.cfg"]);
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
        .expect_err("a library-less 6.04 refuses");
    let text = error.to_string();
    assert!(text.contains("6.04"), "names the family: {text}");
    assert!(text.contains("ldlinux.c32"), "names the module: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no byte moved in 67108864 bytes of image"
    );
}

#[test]
fn bare_tree_refuses_without_pretending_grub_support() {
    // Nothing Syslinux-like anywhere: the explicit mode refuses
    // naming what is missing instead of pretending GRUB support.
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (_backing, mut fat) = formatted();
    let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
        .expect_err("a bare tree refuses");
    let text = error.to_string();
    assert!(
        text.contains("no syslinux payloads"),
        "says what is missing: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn auto_bare_tree_lists_all_three_probes() {
    // Nothing bootloader-like anywhere: `Auto` walks the whole
    // chain and refuses once, naming every probe it ran.
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (_backing, mut fat) = formatted();
    let error =
        tree_install(&source, &mut fat, &BootloaderMode::Auto).expect_err("a bare tree refuses");
    let text = error.to_string();
    assert!(text.contains("syslinux"), "names the first probe: {text}");
    assert!(text.contains("grub2"), "names the second probe: {text}");
    assert!(text.contains("grldr"), "names the third probe: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn none_mode_writes_nothing() {
    let source = syslinux_604_tree();
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let installed =
        tree_install(&source, &mut fat, &BootloaderMode::None).expect("none always runs");
    assert_eq!(
        installed,
        Installed::Skipped,
        "a skipped install reports Skipped"
    );
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no byte moved in 67108864 bytes of image"
    );
}

#[test]
fn every_mode_passes_the_shared_gate() {
    // All modes pass the shared table today: `Windows` passes here
    // and is wired in `run` (mount-based, like `UefiNtfs`), while
    // a future variant fails closed here until it is named.
    // (`UefiNtfs` passes here too; its disk-only arm lives in
    // `run`, and the tree core refuses it as invalid — see the
    // next test.)
    for mode in [
        BootloaderMode::Auto,
        BootloaderMode::Syslinux,
        BootloaderMode::Grub2,
        BootloaderMode::Grub4dos,
        BootloaderMode::UefiNtfs,
        BootloaderMode::Freedos,
        BootloaderMode::Kolibri,
        BootloaderMode::MsDos,
        BootloaderMode::Windows,
        BootloaderMode::None,
    ] {
        check_mode(&mode).expect("a wired mode passes the gate");
    }
}

#[test]
fn install_tree_refuses_uefi_ntfs_as_disk_only() {
    // The shim lands on the whole disk with no tree and no FAT32
    // volume, so the tree core refuses it — as invalid, not not
    // implemented (the installer exists, in `run`), naming the
    // whole-disk path.
    let source = syslinux_604_tree();
    let (_backing, mut fat) = formatted();
    let error = tree_install(&source, &mut fat, &BootloaderMode::UefiNtfs)
        .expect_err("a tree uefi-ntfs refuses");
    assert!(
        !matches!(error, CoreError::NotImplemented { .. }),
        "a wired mode is never NotImplemented: {error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("uefi-ntfs"), "names the mode: {text}");
    assert!(text.contains("whole disk"), "names the path: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn install_tree_refuses_windows_as_mount_based() {
    // The WIM applies onto the mounted data and ESP partitions, so
    // the tree core refuses it — as invalid, not not implemented
    // (the installer exists, in `run`), naming the mounted path.
    let source = syslinux_604_tree();
    let (_backing, mut fat) = formatted();
    let error = tree_install(&source, &mut fat, &BootloaderMode::Windows)
        .expect_err("windows has no tree installer");
    assert!(
        !matches!(error, CoreError::NotImplemented { .. }),
        "a wired mode is never NotImplemented: {error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("windows"), "names the mode: {text}");
    assert!(text.contains("mounted"), "names the path: {text}");
    assert!(text.contains("tree install"), "names the refusal: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]

fn existing_syslinux_cfg_refuses_without_boot_code() {
    // The wrapper path already exists: companions land first, then
    // `write_config` refuses — leaving the formatter's boot sector
    // byte-identical and no `/ldlinux.sys` behind.
    let source = syslinux_604_tree();
    let (backing, mut fat) = formatted();
    let text = boot_syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
    fat.create_file("/syslinux.cfg", text.len() as u64)
        .expect("the copy lands first");
    fat.write_at("/syslinux.cfg", 0, &text)
        .expect("the copy writes");
    let before_sector = backing.boot_sector();
    let error = tree_install(&source, &mut fat, &BootloaderMode::Syslinux)
        .expect_err("an existing wrapper refuses");
    let text = error.to_string();
    assert!(text.contains("syslinux.cfg"), "names the file: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.boot_sector(),
        before_sector,
        "the boot sector is the formatter's still"
    );
    let listed = fat.list_dir("/isolinux").expect("the payload dir lists");
    assert!(
        listed.iter().all(|entry| entry.short_name != "LDLINUX.SYS"),
        "no stage file was linked"
    );
    let back = fat
        .read_file("/isolinux/menu.c32")
        .expect("the companion reads back");
    assert_eq!(back, b"menu.c32", "companions landed before the refusal");
}

#[test]
fn installed_image_is_fsck_clean() {
    let (backing, mut fat) = formatted();
    let source = syslinux_604_tree();
    tree_install(&source, &mut fat, &BootloaderMode::Syslinux).expect("the install runs");
    fat.flush().expect("the install flushes");
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let image = scratch.path().join("bootloader.img");
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
