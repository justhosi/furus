use super::*;

/// 64 MiB whole-disk double for the UEFI:NTFS arm: big enough for
/// the planner to lay the 1 MiB ESP window on, small enough to
/// snapshot in RAM.
pub(super) const UEFI_DISK_BYTES: u64 = 64 * 1024 * 1024;

/// A whole-disk double prefilled with a recognisable pattern, plus
/// the pattern for the untouched comparisons.
pub(super) fn prefilled_uefi_disk() -> (VecTarget, Vec<u8>) {
    let target = VecTarget::new(UEFI_DISK_BYTES, 512).expect("the disk allocates");
    let before: Vec<u8> = (0..UEFI_DISK_BYTES as usize)
        .map(|index| ((index * 11 + 7) % 251) as u8)
        .collect();
    target.write_all_at(0, &before).expect("the prefill lands");
    (target, before)
}

/// The pinned shim bytes through the asset-tree loader (what
/// production's [`crate::boot::load`] resolves to, without the
/// runtime asset directory).
pub(super) fn uefi_image_bytes() -> Vec<u8> {
    asset_loader(Resource::UefiNtfsImage)
        .expect("the shim loads")
        .bytes()
        .to_vec()
}

/// Run the disk-only arm over `target` with explicit `image`
/// bytes: the helper-level seam every UEFI test below shares (a
/// [`DiskView`] bridges the target into the [`Volume`] the arm
/// speaks).
fn uefi_install(
    target: &mut VecTarget,
    table: Option<TableKind>,
    filesystem: &Filesystem,
    image: &[u8],
) -> Result<Installed> {
    let mut disk = DiskView::new(target);
    install_uefi_ntfs(&mut disk, table, filesystem, image)
}

#[test]
fn uefi_ntfs_installs_the_image_at_the_esp_window() {
    // The pinned 1 MiB lands whole at the 1 MiB ESP offset the
    // planner stamps for the `UefiNtfs` layout; the head and the
    // whole data window keep the prefill.
    let (mut target, before) = prefilled_uefi_disk();
    let image = uefi_image_bytes();
    let installed = uefi_install(&mut target, Some(TableKind::Mbr), &Filesystem::Ntfs, &image)
        .expect("the install runs");
    let Installed::UefiNtfs {
        bytes,
        offset,
        messages,
    } = installed
    else {
        panic!("a uefi-ntfs install reports the UefiNtfs variant");
    };
    assert_eq!(bytes, boot_uefi_ntfs::IMAGE_BYTES, "the whole image counts");
    assert_eq!(offset, 1024 * 1024, "the planner's ESP offset");
    assert_eq!(
        messages,
        ["Writing UEFI:NTFS data...".to_string()],
        "the reference line reports"
    );
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    let after = target.bytes().expect("the disk reads back");
    assert_eq!(
        &after[offset as usize..(offset + bytes) as usize],
        &image[..],
        "the image lands whole at the ESP offset"
    );
    assert_eq!(
        &after[..offset as usize],
        &before[..offset as usize],
        "not one byte before the window moved"
    );
    let (data_offset, data_len) =
        crate::part::plan::data_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, UEFI_DISK_BYTES)
            .expect("the data window plans");
    assert_eq!(
        &after[data_offset as usize..(data_offset + data_len) as usize],
        &before[data_offset as usize..(data_offset + data_len) as usize],
        "the data window's bytes are untouched"
    );
}

#[test]
fn uefi_ntfs_takes_ntfs_and_exfat_and_refuses_the_rest() {
    // The reference's filesystem rule (`furus.c:2032-2037`): NTFS
    // and exFAT run, every other plan filesystem refuses naming
    // itself, before any write.
    for filesystem in [Filesystem::Ntfs, Filesystem::Exfat] {
        let (mut target, _before) = prefilled_uefi_disk();
        let image = uefi_image_bytes();
        let installed = uefi_install(&mut target, Some(TableKind::Mbr), &filesystem, &image)
            .expect("ntfs and exfat run");
        assert!(
            matches!(installed, Installed::UefiNtfs { .. }),
            "{filesystem:?} reports the UefiNtfs variant"
        );
    }
    for filesystem in [
        Filesystem::Fat32,
        Filesystem::Ext2,
        Filesystem::Ext3,
        Filesystem::Ext4,
        Filesystem::Udf,
    ] {
        let (mut target, before) = prefilled_uefi_disk();
        let image = uefi_image_bytes();
        let error = uefi_install(&mut target, Some(TableKind::Mbr), &filesystem, &image)
            .expect_err("other filesystems refuse");
        let text = error.to_string();
        assert!(
            text.contains(filesystem_name(&filesystem)),
            "names the filesystem: {text}"
        );
        assert!(text.contains("NTFS or exFAT"), "names the rule: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            target.bytes().expect("the disk reads back"),
            before,
            "no byte moved in 67108864 bytes of disk"
        );
    }
}

#[test]
fn uefi_ntfs_without_a_recorded_table_refuses() {
    // No table, no window: the `gap_end`-style honesty gate fires
    // before any write.
    let (mut target, before) = prefilled_uefi_disk();
    let image = uefi_image_bytes();
    let error = uefi_install(&mut target, None, &Filesystem::Ntfs, &image)
        .expect_err("a table-less uefi-ntfs refuses");
    let text = error.to_string();
    assert!(
        text.contains("recorded partition table"),
        "names the missing bound: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        target.bytes().expect("the disk reads back"),
        before,
        "no byte moved in 67108864 bytes of disk"
    );
}

#[test]
fn uefi_ntfs_oversized_image_refuses_before_any_write() {
    // One byte past the ESP window: the pre-write bound check
    // fires naming the offset, the length and the limit, with the
    // device byte-identical.
    let (offset, len) =
        crate::part::plan::esp_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, UEFI_DISK_BYTES)
            .expect("the window plans");
    let oversized = vec![0xA5u8; (len + 1) as usize];
    let (mut target, before) = prefilled_uefi_disk();
    let error = uefi_install(
        &mut target,
        Some(TableKind::Mbr),
        &Filesystem::Ntfs,
        &oversized,
    )
    .expect_err("an overrunning image refuses");
    let text = error.to_string();
    assert!(
        text.contains(&offset.to_string()),
        "names the offset: {text}"
    );
    assert!(
        text.contains(&(len + 1).to_string()),
        "names the length: {text}"
    );
    assert!(
        text.contains(&(offset + len).to_string()),
        "names the limit: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        target.bytes().expect("the disk reads back"),
        before,
        "no byte moved in 67108864 bytes of disk"
    );
}
