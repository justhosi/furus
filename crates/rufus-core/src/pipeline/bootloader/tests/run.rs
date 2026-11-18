use super::uefi::UEFI_DISK_BYTES;
use super::uefi::prefilled_uefi_disk;
use super::uefi::uefi_image_bytes;
use super::*;

#[test]
fn run_none_reports_and_writes_nothing() {
    let partitions = Rc::new(Cell::new(0usize));
    let opener = CountingOpener {
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context(&opener, &mut reporter);
    run(
        &mut ctx,
        &BootloaderMode::None,
        &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
        &rufus_proto::Filesystem::Fat32,
        None,
    )
    .expect("none always runs");
    assert_eq!(partitions.get(), 0, "the partition never opens");
    assert_eq!(reporter.events.len(), 1, "one info event at most");
}

#[test]
fn run_wired_modes_reach_the_image() {
    // `Freedos` and `Kolibri` are wired: with a bogus image path
    // the run gets past the shared gate to the image open (an I/O
    // refusal naming the path), never `NotImplemented` — and the
    // partition still never opens.
    for mode in [BootloaderMode::Freedos, BootloaderMode::Kolibri] {
        let partitions = Rc::new(Cell::new(0usize));
        let opener = CountingOpener {
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context(&opener, &mut reporter);
        let error = run(
            &mut ctx,
            &mode,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Fat32,
            None,
        )
        .expect_err("a missing image refuses");
        assert!(
            !matches!(error, CoreError::NotImplemented { .. }),
            "a wired mode is never NotImplemented: {error:?}"
        );
        assert_eq!(partitions.get(), 0, "the partition never opens");
    }
}

#[test]
fn run_uefi_ntfs_writes_the_image_and_reports_both_lines() {
    // Through the real `run` path with a bogus image path (proving
    // no image tree opens) on an NTFS plan: the image lands at the
    // 1 MiB ESP offset, the head and the data window keep the
    // prefill, the data partition never opens, the disk flushes
    // once, and both log lines report.
    seed_exe_assets();
    let (target, before) = prefilled_uefi_disk();
    let partitions = Rc::new(Cell::new(0usize));
    let opener = DiskOpener {
        target: target.clone(),
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Mbr));
    run(
        &mut ctx,
        &BootloaderMode::UefiNtfs,
        &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
        &rufus_proto::Filesystem::Ntfs,
        None,
    )
    .expect("the run lands");
    assert_eq!(partitions.get(), 0, "the data partition never opens");
    let texts: Vec<&str> = reporter
        .events
        .iter()
        .filter_map(|event| match event {
            crate::pipeline::event::Event::Message { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        texts.contains(&"Writing UEFI:NTFS data..."),
        "the reference line reports: {texts:?}"
    );
    assert!(
        texts.contains(&"wrote UEFI:NTFS image (1048576 bytes at offset 1048576)"),
        "the completion line names bytes and offset: {texts:?}"
    );
    let after = target.bytes().expect("the disk reads back");
    let image = uefi_image_bytes();
    assert_eq!(
        &after[1024 * 1024..2 * 1024 * 1024],
        &image[..],
        "the image lands whole at the ESP offset"
    );
    assert_eq!(
        &after[..1024 * 1024],
        &before[..1024 * 1024],
        "the head keeps the prefill"
    );
    let (data_offset, data_len) =
        crate::part::plan::data_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, UEFI_DISK_BYTES)
            .expect("the data window plans");
    assert_eq!(
        &after[data_offset as usize..(data_offset + data_len) as usize],
        &before[data_offset as usize..(data_offset + data_len) as usize],
        "the data window's bytes are untouched"
    );
    assert_eq!(target.flushes(), 1, "the run flushes the disk once");
}

#[test]
fn run_uefi_ntfs_refuses_fat32_before_any_write() {
    // A FAT32 plan refuses naming the filesystem, with the device
    // byte-identical and the partition never opened.
    seed_exe_assets();
    let (target, before) = prefilled_uefi_disk();
    let partitions = Rc::new(Cell::new(0usize));
    let opener = DiskOpener {
        target: target.clone(),
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Mbr));
    let error = run(
        &mut ctx,
        &BootloaderMode::UefiNtfs,
        &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
        &rufus_proto::Filesystem::Fat32,
        None,
    )
    .expect_err("a fat32 plan refuses");
    let text = error.to_string();
    assert!(text.contains("fat32"), "names the filesystem: {text}");
    assert!(text.contains("NTFS or exFAT"), "names the rule: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(partitions.get(), 0, "the data partition never opens");
    assert_eq!(
        target.bytes().expect("the disk reads back"),
        before,
        "no byte moved in 67108864 bytes of disk"
    );
}

#[test]
fn run_uefi_ntfs_without_a_table_refuses() {
    // No recorded table, no window: the run refuses before any
    // write, with the device byte-identical.
    seed_exe_assets();
    let (target, before) = prefilled_uefi_disk();
    let partitions = Rc::new(Cell::new(0usize));
    let opener = DiskOpener {
        target: target.clone(),
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, None);
    let error = run(
        &mut ctx,
        &BootloaderMode::UefiNtfs,
        &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
        &rufus_proto::Filesystem::Ntfs,
        None,
    )
    .expect_err("a table-less run refuses");
    let text = error.to_string();
    assert!(
        text.contains("recorded partition table"),
        "names the missing bound: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(partitions.get(), 0, "the data partition never opens");
    assert_eq!(
        target.bytes().expect("the disk reads back"),
        before,
        "no byte moved in 67108864 bytes of disk"
    );
}
