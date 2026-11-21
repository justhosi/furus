use super::*;

/// A GRUB2 payload tree: `/boot/grub/i386-pc/boot.img` (600
/// patterned bytes) and `core.img` (3000 patterned bytes), plus an
/// EFI payload when asked.
fn grub_tree(with_efi: bool) -> (MemSource, Vec<u8>, Vec<u8>) {
    let boot: Vec<u8> = (0..600)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
    let core: Vec<u8> = (0..3000)
        .map(|index| ((index * 13 + 5) % 251) as u8)
        .collect();
    let mut root = vec![dir_entry(b"boot")];
    if with_efi {
        root.push(dir_entry(b"efi"));
    }
    let mut source = MemSource::new()
        .with_dir(&[], root)
        .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
        .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
        .with_dir(
            &[b"boot", b"grub", b"i386-pc"],
            vec![
                file_entry(b"boot.img", &boot),
                file_entry(b"core.img", &core),
            ],
        )
        .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], &boot)
        .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], &core);
    if with_efi {
        source = source
            .with_dir(&[b"efi"], vec![dir_entry(b"boot")])
            .with_dir(
                &[b"efi", b"boot"],
                vec![file_entry(b"grubx64.efi", b"efi-bytes")],
            )
            .with_file(&[b"efi", b"boot", b"grubx64.efi"], b"efi-bytes");
    }
    (source, boot, core)
}

/// A whole-disk double behind [`DiskView`], prefilled with a
/// recognisable pattern. Two MiB: big enough for the planner to
/// lay a first partition past the post-MBR gap the BIOS arms
/// bound through.
fn prefilled_disk() -> (VecTarget, Vec<u8>) {
    const SIZE: usize = 2 * 1024 * 1024;
    let target = VecTarget::new(SIZE as u64, 512).expect("the disk allocates");
    let before: Vec<u8> = (0..SIZE)
        .map(|index| ((index * 11 + 7) % 251) as u8)
        .collect();
    target.write_all_at(0, &before).expect("the prefill lands");
    (target, before)
}

#[test]
fn grub2_installs_bios_and_places_uefi() {
    let (source, boot, core) = grub_tree(true);
    let (backing, mut fat) = formatted();
    let (mut target, before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let installed = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub2,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect("the install runs");
    let Installed::Grub2 {
        dir,
        core_bytes,
        uefi_placed,
        messages,
    } = installed
    else {
        panic!("a grub2 install reports the Grub2 variant");
    };
    assert_eq!(dir, "/boot/grub/i386-pc", "the payload directory");
    assert_eq!(core_bytes, 3000, "the core keeps its 3000 bytes");
    assert_eq!(
        uefi_placed.as_deref(),
        Some("/EFI/boot/bootx64.efi"),
        "the uefi image lands"
    );
    assert_eq!(
        messages[0], "found grub2 bios payloads at '/boot/grub/i386-pc'",
        "discovery first"
    );
    // MBR windows straight from the disk bytes.
    let mut sector = [0u8; 512];
    disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
    assert_eq!(&sector[..0x5c], &boot[..0x5c], "record head verbatim");
    assert_eq!(
        &sector[0x5c..0x64],
        &1u64.to_le_bytes(),
        "the kernel field names sector 1"
    );
    assert_eq!(&sector[0x64..432], &boot[0x64..432], "record tail verbatim");
    assert_eq!(
        &sector[432..510],
        &before[432..510],
        "signature window kept"
    );
    assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
    let mut core_back = vec![0u8; 3000];
    disk.read_exact_at(512, &mut core_back)
        .expect("the core reads");
    assert_eq!(core_back, core, "the core lands whole at sector 1");
    // UEFI file on the partition, byte-identical.
    let back = fat
        .read_file("/EFI/boot/bootx64.efi")
        .expect("the efi image reads");
    assert_eq!(back, b"efi-bytes", "the efi payload lands whole");
    // The composed partition is fsck clean.
    fat.flush().expect("the partition flushes");
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let image = scratch.path().join("grub2.img");
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
    assert!(
        output.status.success(),
        "fsck.fat -n exits 0 after the grub2 install ({})",
        output.status
    );
}

#[test]
fn grub2_core_overrunning_the_gap_refuses() {
    // A 2 MiB device whose first partition the planner starts at
    // `gap_end`: a core ending one byte inside that partition
    // refuses naming both numbers, with the device byte-identical.
    // The boundary comes from the same helper the installer uses,
    // so the test cannot drift from it.
    const SIZE: u64 = 2 * 1024 * 1024;
    let (gap_end, _) =
        crate::part::plan::single_data_window(TableKind::Mbr, 512, SIZE).expect("the gap plans");
    let core_len = (gap_end - 512 + 1) as usize;
    let boot: Vec<u8> = (0..600)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
    let core: Vec<u8> = (0..core_len)
        .map(|index| ((index * 13 + 5) % 251) as u8)
        .collect();
    let source = MemSource::new()
        .with_dir(&[], vec![dir_entry(b"boot")])
        .with_dir(&[b"boot"], vec![dir_entry(b"grub")])
        .with_dir(&[b"boot", b"grub"], vec![dir_entry(b"i386-pc")])
        .with_dir(
            &[b"boot", b"grub", b"i386-pc"],
            vec![
                file_entry(b"boot.img", &boot),
                file_entry(b"core.img", &core),
            ],
        )
        .with_file(&[b"boot", b"grub", b"i386-pc", b"boot.img"], &boot)
        .with_file(&[b"boot", b"grub", b"i386-pc", b"core.img"], &core);
    let (_backing, mut fat) = formatted();
    let mut target = VecTarget::new(SIZE, 512).expect("the disk allocates");
    let before = {
        let mut snapshot = vec![0u8; SIZE as usize];
        target
            .read_at(0, &mut snapshot)
            .expect("the disk reads back");
        snapshot
    };
    let mut disk = DiskView::new(&mut target);
    let error = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub2,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect_err("an overrunning core refuses");
    let text = error.to_string();
    assert!(
        text.contains(&core_len.to_string()),
        "names the core length: {text}"
    );
    assert!(
        text.contains(&gap_end.to_string()),
        "names the gap end: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    let mut after = vec![0u8; SIZE as usize];
    target.read_at(0, &mut after).expect("the disk reads back");
    assert_eq!(after, before, "no byte moved in 2097152 bytes of disk");
}

#[test]
fn grub2_without_a_recorded_table_refuses() {
    let (source, _boot, _core) = grub_tree(false);
    let (_backing, mut fat) = formatted();
    let (mut target, _before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let error = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub2,
        None,
        None,
        &|| false,
        &asset_loader,
    )
    .expect_err("a table-less grub2 refuses");
    let text = error.to_string();
    assert!(
        text.contains("recorded partition table"),
        "names the missing bound: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn grub2_without_payloads_refuses_before_any_device_write() {
    let source = syslinux_407_tree();
    let (_backing, mut fat) = formatted();
    let (mut target, before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let error = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub2,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect_err("a payload-less grub2 refuses");
    let text = error.to_string();
    assert!(text.contains("/boot/grub/i386-pc"), "names the dir: {text}");
    assert!(text.contains("boot.img"), "names the record: {text}");
    assert!(text.contains("core.img"), "names the core: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    let mut after = vec![0u8; before.len()];
    target.read_at(0, &mut after).expect("the disk reads back");
    assert_eq!(after, before, "no byte moved in 2097152 bytes of disk");
}

#[test]
fn grub4dos_keeps_an_existing_grldr() {
    // The volume already carries `/grldr` (the copy step placed
    // the image's own): the embedded bytes stay out, the file is
    // untouched, but MBR+SBR still land.
    let (source, _boot, _core) = grub_tree(false);
    let (_backing, mut fat) = formatted();
    fat.create_file("/grldr", 11).expect("the copy lands first");
    fat.write_at("/grldr", 0, b"image-grldr")
        .expect("the copy writes");
    fat.flush().expect("the copy flushes");
    let (mut target, _before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let installed = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub4dos,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect("the install runs");
    let Installed::Grub4dos {
        sbr_bytes,
        messages,
    } = installed
    else {
        panic!("a grub4dos install reports the Grub4dos variant");
    };
    assert!(
        messages.iter().any(|line| line.contains("keeping it")),
        "the skip is reported: {messages:?}"
    );
    let back = fat.read_file("/grldr").expect("the loader reads");
    assert_eq!(back, b"image-grldr", "the volume bytes are unchanged");
    let mbr = asset_loader(Resource::Grub4DosMbr)
        .expect("the mbr loads")
        .bytes()
        .to_vec();
    assert_eq!(
        sbr_bytes as usize,
        mbr.len() - 512,
        "the sbr spans the rest"
    );
    let mut sector = [0u8; 512];
    disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
    assert_eq!(&sector[..423], &mbr[..423], "the mbr window lands");
    assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
}

#[test]
fn grub4dos_refuses_without_a_root_grldr() {
    // No root `/grldr` (neither the image tree nor a caller placed
    // one): the arm refuses before any write. It names the file
    // Furus downloads, leaves the root empty and the disk byte for
    // byte unchanged, so no boot code lands without its loader.
    let (source, _boot, _core) = grub_tree(false);
    let (_backing, mut fat) = formatted();
    let (mut target, before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let error = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub4dos,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect_err("a grub4dos install without a loader refuses");
    let text = error.to_string();
    assert!(text.contains("real grldr"), "names the need: {text}");
    assert!(
        text.contains("grub4dos-0.4.6a/grldr"),
        "names the download: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    let listed = fat.list_dir("/").expect("the root lists");
    assert!(listed.is_empty(), "no loader lands at the root: {listed:?}");
    let mut after = vec![0u8; before.len()];
    disk.read_exact_at(0, &mut after)
        .expect("the disk reads back");
    assert_eq!(
        after, before,
        "no byte moves: the arm refuses before writing"
    );
}

#[test]
fn uefi_skipped_when_already_present() {
    // Source and volume both carry the file: placement skips, the
    // partition stays byte-identical, the BIOS record still lands.
    let (source, boot, _core) = grub_tree(true);
    let (backing, mut fat) = formatted();
    fat.mkdir("/EFI").expect("the copy makes /EFI");
    fat.mkdir("/EFI/boot").expect("the copy makes boot");
    fat.create_file("/EFI/boot/bootx64.efi", 9)
        .expect("the copy lands first");
    fat.write_at("/EFI/boot/bootx64.efi", 0, b"copy-efi!")
        .expect("the copy writes");
    fat.flush().expect("the copy flushes");
    let before = backing.bytes.borrow().clone();
    let (mut target, _disk_before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let installed = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Grub2,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect("the install runs");
    let Installed::Grub2 { uefi_placed, .. } = &installed else {
        panic!("a grub2 install reports the Grub2 variant");
    };
    assert_eq!(
        uefi_placed.as_deref(),
        None,
        "placement skips the present file"
    );
    assert!(
        installed
            .messages()
            .iter()
            .any(|line| line.contains("keeping it")),
        "the skip is reported"
    );
    let back = fat
        .read_file("/EFI/boot/bootx64.efi")
        .expect("the efi file reads");
    assert_eq!(back, b"copy-efi!", "the volume bytes are unchanged");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no partition byte moved"
    );
    let mut sector = [0u8; 512];
    disk.read_exact_at(0, &mut sector).expect("sector 0 reads");
    assert_eq!(
        &sector[..0x5c],
        &boot[..0x5c],
        "the bios record still lands"
    );
    assert_eq!(
        &sector[0x5c..0x64],
        &1u64.to_le_bytes(),
        "the kernel field still patches"
    );
}

#[test]
fn auto_prefers_syslinux_when_both_are_present() {
    // Isolinux tree plus GRUB tree plus root grldr: Syslinux wins
    // the chain with no probe lines ahead of its own messages.
    let mut source = syslinux_604_tree();
    let (grub, _boot, _core) = grub_tree(false);
    for (dir, entries) in grub.dirs {
        source.dirs.entry(dir).or_default().extend(entries);
    }
    for (path, bytes) in grub.files {
        source.files.insert(path, bytes);
    }
    source
        .dirs
        .entry(Vec::new())
        .or_default()
        .push(file_entry(b"grldr", b"old"));
    source
        .files
        .insert(vec![b"grldr".to_vec()], b"old".to_vec());
    let (_backing, mut fat) = formatted();
    let (mut target, _before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let installed = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Auto,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect("auto runs");
    let Installed::Syslinux { messages, .. } = installed else {
        panic!("syslinux wins the auto chain");
    };
    assert_eq!(
        messages[0], "auto: probing syslinux",
        "the winning probe is logged"
    );
    assert_eq!(
        messages[1], "  Will use '/isolinux' for Syslinux",
        "then the branch reports"
    );
}

#[test]
fn auto_falls_through_to_grub2_over_grldr() {
    // GRUB tree plus root grldr, no isolinux: the syslinux probe
    // misses (logged), GRUB2 wins.
    let (mut source, _boot, _core) = grub_tree(false);
    source
        .dirs
        .entry(Vec::new())
        .or_default()
        .push(file_entry(b"grldr", b"old"));
    source
        .files
        .insert(vec![b"grldr".to_vec()], b"old".to_vec());
    let (_backing, mut fat) = formatted();
    let (mut target, _before) = prefilled_disk();
    let mut disk = DiskView::new(&mut target);
    let installed = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Auto,
        Some(TableKind::Mbr),
        None,
        &|| false,
        &asset_loader,
    )
    .expect("auto runs");
    let Installed::Grub2 { messages, .. } = installed else {
        panic!("grub2 wins over a bare grldr");
    };
    assert_eq!(
        messages[0], "auto: probing syslinux",
        "the first probe is logged"
    );
    assert_eq!(
        messages[1], "auto: probing grub2",
        "the second probe is logged"
    );
    assert_eq!(
        messages[2], "found grub2 bios payloads at '/boot/grub/i386-pc'",
        "the winner identifies itself"
    );
}
