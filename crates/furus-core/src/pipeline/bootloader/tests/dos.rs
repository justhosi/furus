use super::*;

#[test]
fn freedos_installs_payloads_locale_and_record() {
    // A fresh FAT32 image through the `Freedos` arm: the
    // `COMMAND.COM`/`KERNEL.SYS` pair, the `LOCALE` directory with
    // its 25 files, `AUTOEXEC.BAT` and the FreeDOS record. The
    // source tree is bare on purpose: the arm never reads it (the
    // write step already copied it), so a tree without any DOS
    // files still installs.
    use crate::boot::dos_locale::DosFlavor;
    use crate::boot::dos_locale::Locale;
    seed_exe_assets();
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let installed = tree_install(&source, &mut fat, &BootloaderMode::Freedos)
        .expect("the freedos install runs");
    let Installed::Freedos {
        files_written,
        files_kept,
        bytes,
        messages,
    } = installed
    else {
        panic!("a freedos install reports the Freedos variant");
    };
    // The US locale plans no `CONFIG.SYS`: 27 payloads plus the
    // echo-only `AUTOEXEC.BAT` write, nothing kept.
    assert_eq!(files_written, 28, "27 payloads plus AUTOEXEC.BAT");
    assert_eq!(files_kept, 0, "a fresh install keeps nothing");
    assert!(bytes > 0, "bytes count the written files");
    assert_eq!(
        messages[0], "Will use DOS keyboard 'us' [US-English]",
        "the locale keyboard line leads"
    );
    assert_eq!(
        messages[1], "Will use codepage 437 [US-English]",
        "the locale codepage line follows"
    );
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    let back = fat
        .read_file("/COMMAND.COM")
        .expect("COMMAND.COM reads back");
    assert!(!back.is_empty(), "COMMAND.COM landed");
    let back = fat.read_file("/KERNEL.SYS").expect("KERNEL.SYS reads back");
    assert!(!back.is_empty(), "KERNEL.SYS landed");
    let listed = fat.list_dir("/LOCALE").expect("the locale lists");
    assert_eq!(listed.len(), 25, "LOCALE holds the 25 locale files");
    let planned = crate::boot::dos_locale::plan(DosFlavor::FreeDos, &Locale::us());
    let back = fat
        .read_file("/AUTOEXEC.BAT")
        .expect("AUTOEXEC.BAT reads back");
    assert_eq!(
        back,
        planned.autoexec_bat(),
        "AUTOEXEC.BAT equals the locale plan bytes"
    );
    let sector = backing.boot_sector();
    assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
    assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
    // The run summary names counts, bytes and the record.
    let summary = freedos_summary(files_written, files_kept, bytes);
    assert!(summary.contains("28"), "names the files: {summary}");
    assert!(
        summary.contains(&bytes.to_string()),
        "names the bytes: {summary}"
    );
    assert!(
        summary.contains("boot record"),
        "names the record: {summary}"
    );
    assert!(summary.is_ascii(), "stays ASCII: {summary}");
}

/// Synthetic KolibriOS loader bytes (1 KiB of distinct bytes): a
/// stand-in with a realistic shape, not a KolibriOS payload.
fn kolibri_loader_bytes() -> Vec<u8> {
    (0..1024)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect()
}

/// A source tree holding the exact `HD_Load/USB_Boot/MTLD_F32`
/// path with `loader` bytes.
fn kolibri_tree(loader: &[u8]) -> MemSource {
    MemSource::new()
        .with_dir(&[], vec![dir_entry(b"HD_Load")])
        .with_dir(&[b"HD_Load"], vec![dir_entry(b"USB_Boot")])
        .with_dir(
            &[b"HD_Load", b"USB_Boot"],
            vec![file_entry(b"MTLD_F32", loader)],
        )
        .with_file(&[b"HD_Load", b"USB_Boot", b"MTLD_F32"], loader)
}

#[test]
fn kolibri_installs_loader_and_record() {
    // A synthetic tree carrying `/HD_Load/USB_Boot/MTLD_F32`: the
    // arm places `/MTLD_F32` byte-identical and writes the Kolibri
    // record, reporting discovery, placement and the record.
    let loader = kolibri_loader_bytes();
    let source = kolibri_tree(&loader);
    let (backing, mut fat) = formatted();
    let installed = tree_install(&source, &mut fat, &BootloaderMode::Kolibri)
        .expect("the kolibri install runs");
    let Installed::Kolibri {
        bytes,
        kept,
        messages,
    } = installed
    else {
        panic!("a kolibri install reports the Kolibri variant");
    };
    assert_eq!(bytes, loader.len() as u64, "the loader bytes count");
    assert!(!kept, "a fresh write is not kept");
    assert_eq!(
        messages[0], "found kolibri loader at '/HD_Load/USB_Boot/MTLD_F32'",
        "discovery first"
    );
    assert!(
        messages[1].contains("placed kolibri loader at '/MTLD_F32'"),
        "placement next: {messages:?}"
    );
    assert!(
        messages[1].contains(&bytes.to_string()),
        "placement names the bytes: {messages:?}"
    );
    assert_eq!(
        messages[2], "installed kolibri boot record",
        "the record last"
    );
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    let back = fat.read_file("/MTLD_F32").expect("the loader reads back");
    assert_eq!(back, loader, "the loader is byte-identical");
    let sector = backing.boot_sector();
    assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
    assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
    // The run summary names bytes, the path and the record.
    let summary = kolibri_summary(bytes, kept);
    assert!(
        summary.contains(&bytes.to_string()),
        "names the bytes: {summary}"
    );
    assert!(summary.contains("/MTLD_F32"), "names the path: {summary}");
    assert!(
        summary.contains("boot record"),
        "names the record: {summary}"
    );
    assert!(summary.is_ascii(), "stays ASCII: {summary}");
}

#[test]
fn kolibri_keeps_an_identical_loader() {
    // A second install over identical bytes keeps them: the copy
    // step legitimately places the file first, so nothing writes —
    // but the record still lands and the skip is reported.
    let loader = kolibri_loader_bytes();
    let source = kolibri_tree(&loader);
    let (_backing, mut fat) = formatted();
    let first =
        tree_install(&source, &mut fat, &BootloaderMode::Kolibri).expect("the first install runs");
    assert!(
        matches!(first, Installed::Kolibri { kept: false, .. }),
        "a fresh write is not kept"
    );
    let again = tree_install(&source, &mut fat, &BootloaderMode::Kolibri)
        .expect("identical bytes are kept");
    let Installed::Kolibri {
        bytes,
        kept,
        messages,
    } = again
    else {
        panic!("a kept install reports the Kolibri variant");
    };
    assert!(kept, "the second install reports kept");
    assert_eq!(
        bytes,
        loader.len() as u64,
        "the kept report counts the bytes"
    );
    assert!(
        messages.iter().any(|line| line.contains("keeping it")),
        "the skip is reported: {messages:?}"
    );
    let back = fat
        .read_file("/MTLD_F32")
        .expect("the kept file reads back");
    assert_eq!(back, loader, "kept bytes unchanged");
}

#[test]
fn kolibri_without_a_loader_refuses_leaving_everything_identical() {
    // A tree without the loader path refuses naming it, with the
    // volume and the disk byte-identical (the record runs last, so
    // a loader refusal leaves sector 0 untouched).
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let mut target = VecTarget::new(512, 512).expect("one sector fits");
    let disk_before = target.bytes().expect("the disk reads back");
    let mut disk = DiskView::new(&mut target);
    let error = install_tree(
        &source,
        &mut fat,
        &mut disk,
        &BootloaderMode::Kolibri,
        None,
        None,
        &|| false,
        &asset_loader,
    )
    .expect_err("a loader-less kolibri refuses");
    let text = error.to_string();
    assert!(
        text.contains("HD_Load/USB_Boot/MTLD_F32"),
        "names the path: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no volume byte moved in 67108864 bytes of image"
    );
    assert_eq!(
        target.bytes().expect("the disk reads back"),
        disk_before,
        "no disk byte moved"
    );
}

/// Synthetic `IO.SYS`-shaped bytes at the exact expected size
/// with the reference signature planted: stand-in bytes for the
/// arm tests — synthetic, not real DOS bytes.
fn msdos_io_sys_input() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..crate::boot::msdos::IO_SYS_BYTES)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
    let end =
        crate::boot::msdos::IO_SYS_SIGNATURE_OFFSET + crate::boot::msdos::IO_SYS_SIGNATURE.len();
    bytes[crate::boot::msdos::IO_SYS_SIGNATURE_OFFSET..end]
        .copy_from_slice(&crate::boot::msdos::IO_SYS_SIGNATURE);
    bytes
}

/// Synthetic `COMMAND.COM`-shaped bytes at the exact expected size
/// with the reference signature planted: stand-in bytes for the
/// arm tests — synthetic, not real DOS bytes.
fn msdos_command_com_input() -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..crate::boot::msdos::COMMAND_COM_BYTES)
        .map(|index| ((index * 5 + 1) % 251) as u8)
        .collect();
    let end = crate::boot::msdos::COMMAND_COM_SIGNATURE_OFFSET
        + crate::boot::msdos::COMMAND_COM_SIGNATURE.len();
    bytes[crate::boot::msdos::COMMAND_COM_SIGNATURE_OFFSET..end]
        .copy_from_slice(&crate::boot::msdos::COMMAND_COM_SIGNATURE);
    bytes
}

/// A scratch directory holding the three user-supplied files: the
/// caller passes the exact bytes, so the patch-miss test reuses
/// the same seam with short inputs.
fn msdos_scratch(io_sys: &[u8], msdos_sys: &[u8], command_com: &[u8]) -> tempfile::TempDir {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    std::fs::write(scratch.path().join("IO.SYS"), io_sys).expect("IO.SYS lands");
    std::fs::write(scratch.path().join("MSDOS.SYS"), msdos_sys).expect("MSDOS.SYS lands");
    std::fs::write(scratch.path().join("COMMAND.COM"), command_com).expect("COMMAND.COM lands");
    scratch
}

/// Run [`install_tree`] with `dir` as the plan's `msdos_dir`: the
/// arm reads the directory, never the tree, so callers pass a
/// bare source on purpose.
fn msdos_install(source: &MemSource, fat: &mut Fat32, dir: &Path) -> Result<Installed> {
    let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
    install_tree(
        source,
        fat,
        &mut dummy,
        &BootloaderMode::MsDos,
        None,
        Some(dir),
        &|| false,
        &asset_loader,
    )
}

#[test]
fn msdos_installs_user_files_with_io_sys_first_and_contiguous() {
    // A fresh FAT32 image through the `MsDos` arm: the three
    // user-supplied files land with both patches applied, `IO.SYS`
    // first, in one contiguous run, and sector 0 untouched (the
    // formatter's standard record stands — MS-DOS uses it).
    let io_sys = msdos_io_sys_input();
    let msdos_sys = vec![0xABu8; 2048];
    let command_com = msdos_command_com_input();
    let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let before = backing.boot_sector();
    let installed =
        msdos_install(&source, &mut fat, scratch.path()).expect("the msdos install runs");
    let Installed::MsDos {
        written,
        kept,
        bytes,
        patch_states,
        messages,
    } = installed
    else {
        panic!("an msdos install reports the MsDos variant");
    };
    assert_eq!(written, 3, "three files written");
    assert_eq!(kept, 0, "a fresh install keeps nothing");
    assert_eq!(
        bytes,
        (io_sys.len() + msdos_sys.len() + command_com.len()) as u64,
        "the bytes count the three files"
    );
    assert_eq!(
        patch_states,
        (
            crate::boot::msdos::PatchState::Applied,
            crate::boot::msdos::PatchState::Applied
        ),
        "both patches land"
    );
    assert_eq!(messages.len(), 2, "no skip notes: {messages:?}");
    assert_eq!(messages[0], "Patching IO.SYS...", "the bios line first");
    assert_eq!(
        messages[1], "Patching COMMAND.COM...",
        "the shell line next"
    );
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );

    // The root holds the three files, with IO.SYS first.
    let listed = fat.list_dir("/").expect("the root lists");
    let shorts: Vec<&str> = listed
        .iter()
        .map(|entry| entry.short_name.as_str())
        .collect();
    assert_eq!(
        shorts,
        vec!["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
        "the root lists the three files with IO.SYS first"
    );

    // The patched files carry 0xEB at the reference offsets and
    // are otherwise byte-identical to the supplied copies; the
    // kernel is verbatim.
    let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
    assert_eq!(back.len(), io_sys.len(), "the bios length holds");
    assert_eq!(
        back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
        0xEB,
        "the bios patch byte lands"
    );
    for (index, (&was, &is)) in io_sys.iter().zip(back.iter()).enumerate() {
        if index == crate::boot::msdos::IO_SYS_PATCH_OFFSET {
            continue;
        }
        assert_eq!(was, is, "only the patch byte differs at {index}");
    }
    let back = fat.read_file("/MSDOS.SYS").expect("MSDOS.SYS reads back");
    assert_eq!(back, msdos_sys, "the kernel is byte-correct");
    let back = fat
        .read_file("/COMMAND.COM")
        .expect("COMMAND.COM reads back");
    assert_eq!(back.len(), command_com.len(), "the shell length holds");
    assert_eq!(
        back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
        0xEB,
        "the shell patch byte lands"
    );

    // IO.SYS sits in one contiguous run ending in end-of-chain:
    // walk the first FAT copy straight from the raw image. The
    // allocator journals the chain and the arm never flushes, so
    // the caller-side flush below materializes it first.
    fat.flush().expect("the caller-side flush runs");
    let geometry = *fat.geometry();
    let io_entry = listed
        .iter()
        .find(|entry| entry.short_name == "IO.SYS")
        .expect("IO.SYS is listed");
    let cluster_bytes = geometry.cluster_bytes();
    let clusters = (crate::boot::msdos::IO_SYS_BYTES as u64).div_ceil(cluster_bytes);
    let count = u32::try_from(clusters).expect("the test run fits u32");
    let fat_start = u64::from(geometry.reserved_sectors) * u64::from(geometry.bytes_per_sector);
    let image = backing.bytes.borrow();
    for offset in 0..count {
        let cluster = io_entry
            .first_cluster
            .checked_add(offset)
            .expect("the test cluster fits");
        let at =
            usize::try_from(fat_start + u64::from(cluster) * 4).expect("the fat window fits usize");
        let window = image.get(at..at + 4).expect("the fat entry fits");
        let raw = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
        if offset + 1 < count {
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

    // Sector 0 is untouched: MS-DOS uses the standard FAT record,
    // so the formatter's stands.
    assert_eq!(backing.boot_sector(), before, "no boot-sector byte moved");

    // The composed image is fsck clean (read-only check over a
    // dumped tempfile; the tool resolves through `PATH`).
    let dump = tempfile::tempdir().expect("a scratch directory");
    let dumped = dump.path().join("msdos.img");
    std::fs::write(&dumped, backing.bytes.borrow().as_slice()).expect("the image dumps");
    let output = match std::process::Command::new("fsck.fat")
        .arg("-n")
        .arg("-v")
        .arg(&dumped)
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
        "fsck.fat -n -v exits 0 after the msdos install ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    // The run summary names the files, the kept count and the bytes.
    let summary = msdos_summary(written, kept, bytes);
    assert!(summary.contains("3"), "names the files: {summary}");
    assert!(
        summary.contains(&bytes.to_string()),
        "names the bytes: {summary}"
    );
    assert!(summary.contains("msdos"), "names the mode: {summary}");
    assert!(summary.is_ascii(), "stays ASCII: {summary}");
}

#[test]
fn msdos_second_install_keeps() {
    // A second install over identical bytes keeps all three: the
    // kept files report with the reference `Kept existing`
    // lines, and nothing writes.
    let io_sys = msdos_io_sys_input();
    let msdos_sys = vec![0xABu8; 2048];
    let command_com = msdos_command_com_input();
    let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (_backing, mut fat) = formatted();
    msdos_install(&source, &mut fat, scratch.path()).expect("the first install runs");
    let again = msdos_install(&source, &mut fat, scratch.path()).expect("identical bytes are kept");
    let Installed::MsDos {
        written,
        kept,
        messages,
        ..
    } = again
    else {
        panic!("a kept install reports the MsDos variant");
    };
    assert_eq!(written, 0, "nothing writes twice");
    assert_eq!(kept, 3, "all three files kept");
    for name in ["IO.SYS", "MSDOS.SYS", "COMMAND.COM"] {
        assert!(
            messages
                .iter()
                .any(|line| line == &format!("  Kept existing '{name}'")),
            "the kept line reports {name}: {messages:?}"
        );
    }
    assert!(
        messages.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    let back = fat.read_file("/IO.SYS").expect("the kept file reads back");
    assert_eq!(back.len(), io_sys.len(), "kept bytes unchanged");
    assert_eq!(
        back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
        0xEB,
        "the kept patch byte holds"
    );
}

#[test]
fn msdos_patch_miss_is_noted_and_copied_verbatim() {
    // Short inputs miss the size check: the install still lands
    // every file verbatim and replays the reference skip notes
    // after each `Patching ...` line.
    let io_sys = vec![0x11u8; 1024];
    let msdos_sys = vec![0x22u8; 512];
    let command_com = vec![0x33u8; 1024];
    let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (_backing, mut fat) = formatted();
    let installed = msdos_install(&source, &mut fat, scratch.path())
        .expect("a size-missed install still lands");
    let Installed::MsDos {
        patch_states,
        messages,
        ..
    } = installed
    else {
        panic!("a missed install reports the MsDos variant");
    };
    assert_eq!(
        patch_states,
        (
            crate::boot::msdos::PatchState::UnexpectedSize { observed: 1024 },
            crate::boot::msdos::PatchState::UnexpectedSize { observed: 1024 }
        ),
        "both misses report their observed lengths"
    );
    assert_eq!(
        messages,
        vec![
            "Patching IO.SYS...".to_string(),
            "  unexpected file size".to_string(),
            "Patching COMMAND.COM...".to_string(),
            "  unexpected file size".to_string(),
        ],
        "each miss replays the reference note"
    );
    let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
    assert_eq!(back, io_sys, "a missed file copies verbatim");
    let back = fat
        .read_file("/COMMAND.COM")
        .expect("COMMAND.COM reads back");
    assert_eq!(back, command_com, "a missed shell copies verbatim");
}

#[test]
fn msdos_without_a_directory_refuses_naming_the_flag() {
    // No directory means no honest install: the arm refuses
    // naming `--msdos-dir` before any write, with the volume
    // byte-identical.
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let error = tree_install(&source, &mut fat, &BootloaderMode::MsDos)
        .expect_err("a directory-less msdos refuses");
    let text = error.to_string();
    assert!(text.contains("--msdos-dir"), "names the flag: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no volume byte moved in 67108864 bytes of image"
    );
}

#[test]
fn msdos_missing_directory_refuses_naming_it() {
    // A directory that does not exist is refused naming it, with
    // the volume byte-identical (the load runs before any write).
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let missing = scratch.path().join("no-such-dir");
    let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
    let error = install_tree(
        &source,
        &mut fat,
        &mut dummy,
        &BootloaderMode::MsDos,
        None,
        Some(&missing),
        &|| false,
        &asset_loader,
    )
    .expect_err("a missing directory refuses");
    let text = error.to_string();
    assert!(
        text.contains(&missing.display().to_string()),
        "names the directory: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no volume byte moved in 67108864 bytes of image"
    );
}

#[test]
fn msdos_directory_slot_refuses() {
    // A directory sitting in a payload slot (`IO.SYS` as a
    // directory, not a file) refuses naming it instead of
    // failing on the read, with the volume byte-identical.
    let scratch = tempfile::tempdir().expect("a scratch directory");
    std::fs::create_dir(scratch.path().join("IO.SYS")).expect("the directory lands");
    std::fs::write(scratch.path().join("MSDOS.SYS"), b"kernel-bytes").expect("the kernel lands");
    std::fs::write(scratch.path().join("COMMAND.COM"), b"shell-bytes").expect("the shell lands");
    let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
    let source = source.with_file(&[b"a.txt"], b"x");
    let (backing, mut fat) = formatted();
    let before = backing.bytes.borrow().clone();
    let error =
        msdos_install(&source, &mut fat, scratch.path()).expect_err("a directory slot refuses");
    let text = error.to_string();
    assert!(text.contains("IO.SYS"), "names the slot: {text}");
    assert!(text.contains("regular file"), "names the problem: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.bytes.borrow().as_slice(),
        before.as_slice(),
        "no volume byte moved in 67108864 bytes of image"
    );
}

/// Sparse block size: one FAT32 cluster at most (64 KiB), so a
/// block never straddles more than a couple of writes.
const SPARSE_BLOCK: u64 = 64 * 1024;

/// A sparse in-memory [`Volume`] reporting a large `total_bytes`
/// while storing only the windows written (zero elsewhere): the
/// stand-in for a multi-gigabyte device no test may allocate — a
/// real 32 GiB file would blow the tmpfs under `/tmp`, and a
/// 32 GiB `Vec` would blow the heap, while the format's few MiB
/// of FAT writes cost MiB here. Cloned handles share the blocks
/// (like [`SharedVolume`]), so the test still observes the
/// formatter's bytes after [`Fat32::format`] returns.
#[derive(Debug, Clone)]
struct SparseVolume {
    blocks: Rc<RefCell<BTreeMap<u64, Vec<u8>>>>,
    total: u64,
}

impl SparseVolume {
    fn large(total: u64) -> Self {
        Self {
            blocks: Rc::new(RefCell::new(BTreeMap::new())),
            total,
        }
    }

    /// A copy of the stored blocks, for the unchanged comparisons.
    fn snapshot(&self) -> BTreeMap<u64, Vec<u8>> {
        self.blocks.borrow().clone()
    }

    /// Checked byte window of `len` bytes at `offset`, naming
    /// offset, length and total on refusal.
    fn window(&self, offset: u64, len: usize, direction: &str) -> Result<(u64, u64)> {
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "sparse test {direction} overflows the byte arithmetic"
            ))
        })?;
        if end > self.total {
            return Err(CoreError::invalid(format!(
                "sparse test {direction} of {len} bytes at offset {offset} runs past the {} byte volume",
                self.total,
            )));
        }
        Ok((offset, end))
    }
}

impl Volume for SparseVolume {
    fn total_bytes(&self) -> u64 {
        self.total
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
        let (_, end) = self.window(offset, buf.len(), "read")?;
        buf.fill(0);
        if buf.is_empty() {
            return Ok(());
        }
        let stored = self.blocks.borrow();
        let mut cursor = offset;
        let mut done = 0usize;
        while cursor < end {
            let index = cursor / SPARSE_BLOCK;
            let base = index * SPARSE_BLOCK;
            let stop = (base + SPARSE_BLOCK).min(end);
            let take = usize::try_from(stop - cursor).expect("a sparse block window fits usize");
            if let Some(block) = stored.get(&index) {
                let from =
                    usize::try_from(cursor - base).expect("a sparse block offset fits usize");
                buf[done..done + take].copy_from_slice(&block[from..from + take]);
            }
            done += take;
            cursor = stop;
        }
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
        let (_, end) = self.window(offset, buf.len(), "write")?;
        if buf.is_empty() {
            return Ok(());
        }
        let mut stored = self.blocks.borrow_mut();
        let mut cursor = offset;
        let mut done = 0usize;
        while cursor < end {
            let index = cursor / SPARSE_BLOCK;
            let base = index * SPARSE_BLOCK;
            let stop = (base + SPARSE_BLOCK).min(end);
            let take = usize::try_from(stop - cursor).expect("a sparse block window fits usize");
            let block = stored
                .entry(index)
                .or_insert_with(|| vec![0u8; SPARSE_BLOCK as usize]);
            let from = usize::try_from(cursor - base).expect("a sparse block offset fits usize");
            block[from..from + take].copy_from_slice(&buf[done..done + take]);
            done += take;
            cursor = stop;
        }
        Ok(())
    }
}

#[test]
fn msdos_refuses_a_64kib_cluster_volume_before_any_write() {
    // 32 GiB is the first geometry tier with 64 KiB clusters (see
    // `CLUSTER_TIERS`/`LARGE_CLUSTER_BYTES`): MS-DOS cannot boot
    // from it, so the arm refuses with the reference MSG_110
    // sentence before any file lands. The volume is a sparse
    // double (see `SparseVolume`), so the format's few MiB of FAT
    // writes cost MiB, not GiB.
    let io_sys = msdos_io_sys_input();
    let msdos_sys = vec![0xABu8; 2048];
    let command_com = msdos_command_com_input();
    let scratch = msdos_scratch(&io_sys, &msdos_sys, &command_com);
    let backing = SparseVolume::large(32 * 1024 * 1024 * 1024);
    let mut fat = Fat32::format(
        Box::new(backing.clone()),
        &FormatOptions {
            volume_id: 0x1234_5678,
            ..Default::default()
        },
    )
    .expect("the large volume formats");
    assert_eq!(
        fat.geometry().cluster_bytes(),
        65_536,
        "the tier premise holds: 32 GiB formats with 64 KiB clusters"
    );
    let before = backing.snapshot();
    let error =
        install_msdos(&mut fat, scratch.path(), &|| false).expect_err("a 64 KiB cluster refuses");
    let text = error.to_string();
    assert!(
        text.contains("MS-DOS cannot boot from a drive using a 64 kilobytes Cluster size."),
        "the refusal carries the reference sentence verbatim: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        backing.snapshot(),
        before,
        "no volume byte moved: the gate fires before any file write"
    );
}
