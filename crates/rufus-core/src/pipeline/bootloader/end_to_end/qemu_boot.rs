use super::qemu;
use super::*;

/// Build the Syslinux 4.07 fixture ISO: the same descriptor and
/// directory shape as [`syslinux_iso`], but a 4.07 banner and no
/// `.c32` files. 4.07 needs no core library, which is what makes
/// it the bootable fixture: 6.04 needs real `.c32` modules no
/// test can provide, so a 6.04 stick can never get past its
/// loader.
fn syslinux_407_iso() -> Vec<u8> {
    use crate::copy::source::fixture::*;
    const ROOT: u32 = 20;
    const DIR: u32 = 21;
    const BIN: u32 = 22;
    const CFG: u32 = 23;
    let banner = b"ISOLINUX 4.07 20130725 test-image".to_vec();
    // Lowercase identifiers with `;1` versions, like
    // [`syslinux_iso`]: the reader resolves file opens exactly.
    let files: Vec<(&[u8], u32, Vec<u8>)> = vec![
        (b"isolinux.bin;1", BIN, banner),
        (b"isolinux.cfg;1", CFG, b"DEFAULT linux\n".to_vec()),
    ];
    let mut image = vec![0u8; 32 * SECTOR_BYTES];
    let mut put = |sector: u32, bytes: &[u8]| {
        let base = sector as usize * SECTOR_BYTES;
        image[base..base + bytes.len()].copy_from_slice(bytes);
    };
    put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
    put(17, &boot_sector());
    put(18, &terminator_sector());
    let root = vec![
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"isolinux"),
    ];
    let mut dir = vec![
        encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
    ];
    for (identifier, sector, bytes) in &files {
        dir.push(encode_record(*sector, bytes.len() as u32, 0, identifier));
    }
    put(ROOT, &dir_sector(&root));
    put(DIR, &dir_sector(&dir));
    for (_, sector, bytes) in &files {
        put(*sector, bytes);
    }
    image
}

/// Build the GRUB2 boot fixture ISO from test-time bytes: real
/// `boot.img` and `core.img` under `boot/grub/i386-pc/` (what the
/// GRUB2 arm installs) plus the `grub.cfg` the Write step copies
/// to the partition (what the booted core reads). File data
/// starts at sector 24 and packs contiguously; the image sizes
/// itself around the three payloads.
fn grub2_boot_iso(boot: &[u8], core: &[u8], cfg: &[u8]) -> Vec<u8> {
    use crate::copy::source::fixture::*;
    const ROOT: u32 = 20;
    const BOOT: u32 = 21;
    const GRUB: u32 = 22;
    const PC: u32 = 23;
    let boot_at = 24u32;
    let core_at = boot_at + boot.len().div_ceil(SECTOR_BYTES) as u32;
    let cfg_at = core_at + core.len().div_ceil(SECTOR_BYTES) as u32;
    let total = (cfg_at as usize + cfg.len().div_ceil(SECTOR_BYTES) + 1) * SECTOR_BYTES;
    let mut image = vec![0u8; total];
    let mut put = |sector: u32, bytes: &[u8]| {
        let base = sector as usize * SECTOR_BYTES;
        image[base..base + bytes.len()].copy_from_slice(bytes);
    };
    put(16, &primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32));
    put(17, &boot_sector());
    put(18, &terminator_sector());
    let root = vec![
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"boot"),
    ];
    let boot_dir = vec![
        encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"grub"),
    ];
    let grub_dir = vec![
        encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(BOOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"i386-pc"),
        encode_record(cfg_at, cfg.len() as u32, 0, b"grub.cfg;1"),
    ];
    let pc_dir = vec![
        encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(boot_at, boot.len() as u32, 0, b"boot.img;1"),
        encode_record(core_at, core.len() as u32, 0, b"core.img;1"),
    ];
    put(ROOT, &dir_sector(&root));
    put(BOOT, &dir_sector(&boot_dir));
    put(GRUB, &dir_sector(&grub_dir));
    put(PC, &dir_sector(&pc_dir));
    put(boot_at, boot);
    put(core_at, core);
    put(cfg_at, cfg);
    image
}

/// Run the acceptance plan over a fresh file-backed disk and hand
/// back the scratch directory (it owns the disk file, so it must
/// outlive the QEMU boot) plus the disk path to boot. `write_copy`
/// inserts a `Write { mode: Copy }` step between `Mkfs` and
/// `Bootloader` for the GRUB2 arm, whose `grub.cfg` must reach
/// the partition; every other arm reads the image tree straight
/// from the file, like [`acceptance_one`].
fn boot_disk(
    iso_bytes: &[u8],
    image_len: u64,
    mode: rufus_proto::BootloaderMode,
    write_copy: bool,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let iso_path = scratch.path().join("boot.iso");
    std::fs::write(&iso_path, iso_bytes).expect("the iso writes");
    let disk_path = scratch.path().join("disk.img");
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&disk_path)
        .expect("the disk creates")
        .set_len(DISK_BYTES)
        .expect("the disk sizes");
    let (base, len) =
        single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans");
    let opener = EndToEndOpener {
        path: disk_path.clone(),
        disk_len: DISK_BYTES,
        base,
        len,
    };
    let mut plan = acceptance_plan(
        &iso_path,
        image_len,
        Filesystem::Fat32,
        rufus_proto::Layout::Single,
        mode,
        None,
    );
    if write_copy {
        // The copy must land before the bootloader step; look the
        // step up rather than assume its index in the plan.
        let bootloader = plan
            .steps
            .iter()
            .position(|step| matches!(step, rufus_proto::Step::Bootloader { .. }))
            .expect("the acceptance plan carries a bootloader step");
        plan.steps.insert(
            bootloader,
            rufus_proto::Step::Write {
                mode: rufus_proto::WriteMode::Copy,
            },
        );
    }
    let mut reporter = Recorder::default();
    crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
        false
    })
    .expect("the boot plan runs");
    (scratch, disk_path)
}

/// Whether `grub-mkimage` answers `--version`: the GRUB2 boot
/// test builds its `core.img` at test time, so it gates on this
/// alongside [`qemu::have_qemu`].
fn have_grub_mkimage() -> bool {
    std::process::Command::new("grub-mkimage")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn syslinux_407_boots_to_its_prompt_in_qemu() {
    // Through the full six-step plan (partition table included)
    // with the 4.07 fixture: the installed VBR and stage are the
    // real embedded 4.07 payloads, so the stick boots for real.
    if !qemu::have_qemu() {
        eprintln!("skip: qemu-system-x86_64 is not on PATH");
        return;
    }
    seed_exe_assets();
    let iso = syslinux_407_iso();
    let (_scratch, disk) = boot_disk(
        &iso,
        32 * SECTOR_BYTES as u64,
        rufus_proto::BootloaderMode::Syslinux,
        false,
    );
    let screen =
        qemu::capture(&disk, std::time::Duration::from_secs(10)).expect("qemu captures the screen");
    qemu::log(&screen);
    assert!(
        screen.iter().any(|line| line.contains("SYSLINUX 4.07")),
        "the loader banner shows: {screen:?}"
    );
    assert!(
        screen.iter().any(|line| line == "boot:"),
        "the loader prompt shows: {screen:?}"
    );
}

#[test]
#[ignore = "needs a caller-supplied grldr: resource 451 is GRUB2 core.img and Rufus downloads the loader"]
fn grub4dos_boots_to_its_prompt_in_qemu() {
    // Only a real GRUB4DOS `grldr` can produce this prompt, and no
    // loader is bundled. The test therefore reads one from the path
    // in `RUFUS_TEST_GRLDR` (run it with `--ignored`) and skips
    // without it, rather than assert a prompt it cannot produce.
    // The image carries that loader at its root, the record is the
    // embedded MBR/SBR (resource 450), and the boot runs for real.
    let Some(grldr_path) = std::env::var_os("RUFUS_TEST_GRLDR") else {
        eprintln!("skip: set RUFUS_TEST_GRLDR to a real grldr to run this boot test");
        return;
    };
    if !qemu::have_qemu() {
        eprintln!("skip: qemu-system-x86_64 is not on PATH");
        return;
    }
    seed_exe_assets();
    let grldr = std::fs::read(&grldr_path).expect("the caller's grldr reads");
    let iso = syslinux_iso_with(Some(&grldr));
    let (_scratch, disk) = boot_disk(
        &iso,
        iso.len() as u64,
        rufus_proto::BootloaderMode::Grub4dos,
        true,
    );
    let screen =
        qemu::capture(&disk, std::time::Duration::from_secs(10)).expect("qemu captures the screen");
    qemu::log(&screen);
    assert!(
        screen.iter().any(|line| line.contains("grub>")),
        "the loader prompt shows: {screen:?}"
    );
}

#[test]
fn freedos_boots_to_its_shell_in_qemu() {
    // Through the full six-step plan (partition table included:
    // the kernel assigns drive letters from partition tables
    // only). The payloads and the record are the embedded ones,
    // so the stick boots for real into the kernel and its shell.
    if !qemu::have_qemu() {
        eprintln!("skip: qemu-system-x86_64 is not on PATH");
        return;
    }
    seed_exe_assets();
    let iso = syslinux_iso();
    let (_scratch, disk) = boot_disk(
        &iso,
        32 * SECTOR_BYTES as u64,
        rufus_proto::BootloaderMode::Freedos,
        false,
    );
    let screen =
        qemu::capture(&disk, std::time::Duration::from_secs(12)).expect("qemu captures the screen");
    qemu::log(&screen);
    assert!(
        screen
            .iter()
            .any(|line| line.contains("FreeDOS kernel 2043")),
        "the kernel banner shows: {screen:?}"
    );
    // The kernel's own `C: HD1, Pri[ 1], ...` line also contains
    // "C:", so the shell is pinned by its FreeCom prompt instead.
    assert!(
        screen.iter().any(|line| line.ends_with("C:\\>")),
        "the FreeCom prompt shows: {screen:?}"
    );
    assert!(
        screen.iter().any(|line| line.contains("FreeCom version")),
        "the FreeCom banner shows: {screen:?}"
    );
}

#[test]
fn grub2_bios_boots_its_shell_and_reads_its_config_in_qemu() {
    // Genuine GRUB2 binaries only: `core.img` is built at test
    // time with the host `grub-mkimage` (prefix `/boot/grub`, an
    // early config that roots the boot partition, and every
    // module the boot needs embedded — no module loads from
    // disk), and the record is the host `boot.img`. Both reach
    // the stick through the image tree, exactly like a real
    // image's payloads; the Write step copies the tree
    // (including `grub.cfg`) to the partition first.
    if !qemu::have_qemu() {
        eprintln!("skip: qemu-system-x86_64 is not on PATH");
        return;
    }
    if !have_grub_mkimage() {
        eprintln!("skip: grub-mkimage is not on PATH");
        return;
    }
    let boot_img = match std::fs::read("/usr/lib/grub/i386-pc/boot.img") {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("skip: the grub2 boot record is not present ({error})");
            return;
        }
    };
    seed_exe_assets();
    let build = tempfile::tempdir().expect("a grub scratch directory");
    std::fs::write(
        build.path().join("early.cfg"),
        b"search --set=root --file /boot/grub/grub.cfg\nset prefix=($root)/boot/grub\n",
    )
    .expect("the early config writes");
    let core_path = build.path().join("core.img");
    let built = std::process::Command::new("grub-mkimage")
        .arg("-O")
        .arg("i386-pc")
        .arg("-o")
        .arg(&core_path)
        .arg("-p")
        .arg("/boot/grub")
        .arg("-c")
        .arg(build.path().join("early.cfg"))
        .args([
            "biosdisk",
            "part_msdos",
            "fat",
            "normal",
            "configfile",
            "search",
            "search_fs_file",
            "echo",
        ])
        .output();
    let output = match built {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skip: grub-mkimage did not run ({error})");
            return;
        }
    };
    if !output.status.success() {
        eprintln!(
            "skip: grub-mkimage could not build the test core.img ({})",
            output.status
        );
        return;
    }
    let core_img = std::fs::read(&core_path).expect("the test core reads back");
    let cfg = b"set timeout=0\necho GRUB2-OK\n";
    let iso = grub2_boot_iso(&boot_img, &core_img, cfg);
    let iso_len = iso.len() as u64;
    let (_scratch, disk) = boot_disk(&iso, iso_len, rufus_proto::BootloaderMode::Grub2, true);
    // Fresh boot: the banner and the shell prove the record
    // handed off to the core and the core reached `normal`.
    let screen =
        qemu::capture(&disk, std::time::Duration::from_secs(10)).expect("qemu captures the screen");
    qemu::log(&screen);
    assert!(
        screen.iter().any(|line| line.contains("GNU GRUB")),
        "the grub banner shows: {screen:?}"
    );
    assert!(
        screen.iter().any(|line| line.contains("grub>")),
        "the grub shell shows: {screen:?}"
    );
    // Driven shell: `configfile` loads the `grub.cfg` the Write
    // step copied, proving the booted core reads the partition.
    // (Boot-time `echo` output does not survive to the captured
    // screen — the line below is what a driven load shows.)
    let keys = [
        "c", "o", "n", "f", "i", "g", "f", "i", "l", "e", "spc", "slash", "b", "o", "o", "t",
        "slash", "g", "r", "u", "b", "slash", "g", "r", "u", "b", "dot", "c", "f", "g", "ret",
    ];
    let screen = qemu::capture_keys(&disk, std::time::Duration::from_secs(9), &keys)
        .expect("qemu drives the shell");
    qemu::log(&screen);
    assert!(
        screen.iter().any(|line| line.contains("GRUB2-OK")),
        "the copied config runs: {screen:?}"
    );
}
