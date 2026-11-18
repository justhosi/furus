use std::fs::OpenOptions;
use std::os::unix::fs::FileExt as _;

use crate::boot::Resource;
use crate::boot::load_from;
use crate::boot::syslinux;
use crate::error::CoreError;
use crate::error::Result as TestResult;
use crate::fs::Volume;
use crate::fs::fat32::Fat32;
use crate::iso::FLAG_DIRECTORY;
use crate::iso::SECTOR_BYTES;
use crate::part::TableKind;
use crate::part::plan::LayoutKind;
use crate::part::plan::data_window;
use crate::part::plan::esp_window;
use crate::part::plan::single_data_window;
use crate::pipeline::target::Target;
use rufus_proto::DeviceRef;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;
use rufus_proto::Options;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;

/// 128 MiB stick image for the run.
const DISK_BYTES: u64 = 128 * 1024 * 1024;

/// Stand-in GRUB4DOS `grldr` bytes for the fixtures. No real loader
/// is bundled (resource 451 is GRUB2's `core.img`), so the tests
/// carry a patterned blob and check only the file plumbing.
fn stand_in_grldr() -> Vec<u8> {
    (0..4096)
        .map(|index| ((index * 3 + 1) % 251) as u8)
        .collect()
}

/// Build the fixture ISO: primary + boot + terminator descriptors,
/// a root holding `ISOLINUX/`, and six payload files under it, from
/// the shared `copy::fixture` sector builders.
fn syslinux_iso() -> Vec<u8> {
    syslinux_iso_with(None)
}

/// The Syslinux 6.04 fixture, optionally carrying a root `grldr`
/// file (the image's own GRUB4DOS loader, which the GRUB4DOS arm
/// needs on the volume). The loader starts at sector 32, past the
/// 32-sector base image, and the descriptor's volume size follows
/// the real image length.
fn syslinux_iso_with(grldr: Option<&[u8]>) -> Vec<u8> {
    use crate::copy::source::fixture::*;
    const ROOT: u32 = 20;
    const DIR: u32 = 21;
    const BIN: u32 = 22;
    const CFG: u32 = 23;
    const C32: u32 = 24;
    const MENU: u32 = 25;
    const VESA: u32 = 26;
    const LIB: u32 = 27;
    const LOADER: u32 = 32;
    let loader_sectors = grldr.map_or(0, |bytes| bytes.len().div_ceil(SECTOR_BYTES));
    let total_sectors = 32 + loader_sectors;
    let banner = b"ISOLINUX 6.04 20140611 test-image".to_vec();
    // Lowercase identifiers throughout: like the directory
    // above, the reader resolves file opens exactly, so only
    // lowercase names round-trip through locate and read.
    let files: Vec<(&[u8], u32, Vec<u8>)> = vec![
        (b"isolinux.bin;1", BIN, banner),
        (b"isolinux.cfg;1", CFG, b"DEFAULT linux\n".to_vec()),
        (b"ldlinux.c32;1", C32, b"ldlinux-c32-stub".to_vec()),
        (b"menu.c32;1", MENU, b"menu-stub".to_vec()),
        (b"vesamenu.c32;1", VESA, b"vesamenu-stub".to_vec()),
        (b"libutil.c32;1", LIB, b"libutil-stub".to_vec()),
    ];
    let mut image = vec![0u8; total_sectors * SECTOR_BYTES];
    let mut put = |sector: u32, bytes: &[u8]| {
        let base = sector as usize * SECTOR_BYTES;
        image[base..base + bytes.len()].copy_from_slice(bytes);
    };
    let mut primary = primary_sector("TESTVOL", ROOT, SECTOR_BYTES as u32);
    let total = total_sectors as u32;
    primary[80..84].copy_from_slice(&total.to_le_bytes());
    primary[84..88].copy_from_slice(&total.to_be_bytes());
    put(16, &primary);
    put(17, &boot_sector());
    put(18, &terminator_sector());
    let mut root = vec![
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        // Lowercase on purpose: the engine resolves payload
        // directory components exactly (only file names fold
        // case), so an upper-case directory is never located.
        encode_record(DIR, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"isolinux"),
    ];
    if let Some(bytes) = grldr {
        root.push(encode_record(LOADER, bytes.len() as u32, 0, b"grldr;1"));
        put(LOADER, bytes);
    }
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

/// Build the GRUB2 fixture ISO plus its payload bytes: primary +
/// boot + terminator descriptors, `boot/grub/i386-pc/` holding
/// `boot.img` (600 patterned bytes) and `core.img` (3000 patterned
/// bytes). Lowercase identifiers with `;1` versions, like
/// [`syslinux_iso`]: the reader resolves directory components
/// exactly and strips the file versions.
fn grub2_iso() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::copy::source::fixture::*;
    const ROOT: u32 = 20;
    const BOOT: u32 = 21;
    const GRUB: u32 = 22;
    const PC: u32 = 23;
    const BOOTIMG: u32 = 24;
    const COREIMG: u32 = 25;
    let boot: Vec<u8> = (0..600)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
    let core: Vec<u8> = (0..3000)
        .map(|index| ((index * 13 + 5) % 251) as u8)
        .collect();
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
    ];
    let pc_dir = vec![
        encode_record(PC, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(GRUB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(BOOTIMG, boot.len() as u32, 0, b"boot.img;1"),
        encode_record(COREIMG, core.len() as u32, 0, b"core.img;1"),
    ];
    put(ROOT, &dir_sector(&root));
    put(BOOT, &dir_sector(&boot_dir));
    put(GRUB, &dir_sector(&grub_dir));
    put(PC, &dir_sector(&pc_dir));
    put(BOOTIMG, &boot);
    put(COREIMG, &core);
    (image, boot, core)
}

/// Build the KolibriOS fixture ISO plus its loader bytes: the
/// descriptors plus a 1 KiB loader file under the exact reference
/// directories (`HD_Load`, then `USB_Boot`). The directory
/// components keep their case: the locator resolves them exactly,
/// unlike file names.
fn kolibri_iso() -> (Vec<u8>, Vec<u8>) {
    use crate::copy::source::fixture::*;
    const ROOT: u32 = 20;
    const HD: u32 = 21;
    const USB: u32 = 22;
    const LOADER: u32 = 23;
    let loader: Vec<u8> = (0..1024)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
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
        encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"HD_Load"),
    ];
    let hd_dir = vec![
        encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(ROOT, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(USB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"USB_Boot"),
    ];
    let usb_dir = vec![
        encode_record(USB, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x00"),
        encode_record(HD, SECTOR_BYTES as u32, FLAG_DIRECTORY, b"\x01"),
        encode_record(LOADER, loader.len() as u32, 0, b"MTLD_F32;1"),
    ];
    put(ROOT, &dir_sector(&root));
    put(HD, &dir_sector(&hd_dir));
    put(USB, &dir_sector(&usb_dir));
    put(LOADER, &loader);
    (image, loader)
}

/// A whole-disk [`Target`] over one open file with a declared
/// extent: the tempdir-backed disk image the run drives. Opens a
/// fresh handle per `device()` call (like the file-seam opener),
/// so every handle sees the same bytes. Sparse-backed: the file is
/// sized with `set_len`, and wipe/Mkfs pay only their real writes.
#[derive(Debug)]
struct FileTarget {
    file: std::fs::File,
    path: std::path::PathBuf,
    len: u64,
}

impl FileTarget {
    fn open(path: &std::path::Path, len: u64) -> TestResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| CoreError::io(path, source))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            len,
        })
    }
}

impl Target for FileTarget {
    fn size(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end > self.len)
        {
            return Err(CoreError::invalid(format!(
                "test read of {} bytes at offset {offset} runs past the {} byte disk",
                buf.len(),
                self.len
            )));
        }
        self.file
            .read_exact_at(buf, offset)
            .map_err(|source| CoreError::io(&self.path, source))
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> TestResult<()> {
        self.write_all_at_cancellable(offset, buf, usize::MAX, &|| false)?;
        Ok(())
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> TestResult<u64> {
        if chunk == 0 {
            return Err(CoreError::invalid("write chunk size must be non-zero"));
        }
        if offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end > self.len)
        {
            return Err(CoreError::invalid(format!(
                "test write of {} bytes at offset {offset} runs past the {} byte disk",
                buf.len(),
                self.len
            )));
        }
        let mut done = 0usize;
        while done < buf.len() {
            if cancelled() {
                return Ok(done as u64);
            }
            let piece = (buf.len() - done).min(chunk);
            self.file
                .write_all_at(&buf[done..done + piece], offset + done as u64)
                .map_err(|source| CoreError::io(&self.path, source))?;
            done += piece;
        }
        Ok(done as u64)
    }

    fn flush(&self) -> TestResult<()> {
        self.file
            .sync_all()
            .map_err(|source| CoreError::io(&self.path, source))
    }
}

/// A [`Volume`] window over the disk file at `[base, base + len)`:
/// the data partition the native formatters write, planned with the
/// same [`single_data_window`] call the pipeline stamps with, so the
/// formatted window is the stamped partition by construction.
#[derive(Debug)]
struct PartFile {
    file: std::fs::File,
    base: u64,
    len: u64,
}

impl PartFile {
    fn open(path: &std::path::Path, base: u64, len: u64) -> TestResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| CoreError::io(path, source))?;
        Ok(Self { file, base, len })
    }
}

impl Volume for PartFile {
    fn total_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| CoreError::invalid("test partition read overflows".to_string()))?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "test partition read of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.file
            .read_exact_at(buf, self.base + offset)
            .map_err(|source| CoreError::io("<partition window>", source))
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| CoreError::invalid("test partition write overflows".to_string()))?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "test partition write of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.file
            .write_all_at(buf, self.base + offset)
            .map_err(|source| CoreError::io("<partition window>", source))
    }

    fn flush(&mut self) -> TestResult<()> {
        self.file
            .sync_all()
            .map_err(|source| CoreError::io("<partition window>", source))
    }

    fn sector_size(&self) -> u32 {
        512
    }
}

/// The mount stand-in: a real temp directory standing in for the
/// kernel mount. Before the copy, `partition.img` materialises the
/// partition window bytes; on release, the temp tree's contents
/// merge into the partition window through the real `Fat32` API
/// and the volume flushes. That merge is what proves the copy's
/// bytes round-trip into the partition window: a kernel mount
/// would expose the live filesystem instead, which no unprivileged
/// test can do, so the shim stands in for `mount(2)` without
/// calling it.
struct MountShim {
    dir: tempfile::TempDir,
    path: std::path::PathBuf,
    base: u64,
    len: u64,
}

impl MountShim {
    fn mount(path: &std::path::Path, base: u64, len: u64) -> TestResult<Self> {
        let dir = tempfile::tempdir().expect("the mount dir allocates");
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| CoreError::io(path, source))?;
        let mut window = vec![0u8; usize::try_from(len).expect("the window fits usize")];
        file.read_exact_at(&mut window, base)
            .map_err(|source| CoreError::io(path, source))?;
        std::fs::write(dir.path().join("partition.img"), &window).expect("the window stages");
        Ok(Self {
            dir,
            path: path.to_path_buf(),
            base,
            len,
        })
    }
}

impl crate::pipeline::opener::MountedPartition for MountShim {
    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    fn free_bytes(&self) -> TestResult<u64> {
        // Fixture scale only: plenty for a 60 KiB ISO tree. A
        // kernel mount would report statvfs here.
        Ok(1 << 40)
    }

    fn release(&mut self) -> TestResult<()> {
        let staged = std::fs::read(self.dir.path().join("partition.img"))
            .expect("the staged window reads back");
        let staged_len = u64::try_from(staged.len()).expect("the stage fits u64");
        if staged_len != self.len {
            return Err(CoreError::invalid(format!(
                "test mount staged {staged_len} bytes for a {} byte window: refusing",
                self.len
            )));
        }
        // Merge what the copy walk landed in the temp tree into
        // the live window, then flush: this is the assertion
        // surface that proves the copy's bytes reached the image.
        // (The staged window above only guards the size now — the
        // copy never touched the window, so there is nothing to
        // restore from it.)
        let mut fat = Fat32::open(Box::new(
            PartFile::open(&self.path, self.base, self.len).expect("the merge window opens"),
        ))
        .expect("the merge volume opens");
        merge_dir(&mut fat, self.dir.path(), "")?;
        fat.flush()?;
        Ok(())
    }
}

/// Copy one temp-tree level into the FAT32 volume: directories are
/// created (when the listing misses them) before descending, files
/// are created and written whole, and only the shim's own
/// `partition.img` is skipped. Everything the walk produced lands —
/// including the companions, which the bootloader step then keeps
/// by byte comparison instead of refusing. Anything that is
/// neither a file nor a directory refuses — the fixture tree holds
/// no symlinks, and silently dropping one would hide a lost entry.
fn merge_dir(fat: &mut Fat32, fs_dir: &std::path::Path, fat_dir: &str) -> TestResult<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(fs_dir)
        .map_err(|source| CoreError::io(fs_dir, source))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|source| CoreError::io(fs_dir, source))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_str().ok_or_else(|| {
            CoreError::invalid(format!(
                "test mount entry '{}' is not UTF-8: refusing",
                name.to_string_lossy()
            ))
        })?;
        if name_str == "partition.img" {
            continue;
        }
        let dest = if fat_dir.is_empty() {
            format!("/{name_str}")
        } else {
            format!("{fat_dir}/{name_str}")
        };
        let file_type = entry
            .file_type()
            .map_err(|source| CoreError::io(entry.path(), source))?;
        if file_type.is_dir() {
            match fat.list_dir(&dest) {
                Ok(_) => {}
                Err(_) => {
                    fat.mkdir(&dest)?;
                }
            }
            merge_dir(fat, &entry.path(), &dest)?;
        } else if file_type.is_file() {
            let bytes = std::fs::read(entry.path())
                .map_err(|source| CoreError::io(entry.path(), source))?;
            fat.create_file(&dest, bytes.len() as u64)?;
            fat.write_at(&dest, 0, &bytes)?;
        } else {
            return Err(CoreError::invalid(format!(
                "test mount entry '{dest}' is neither a file nor a directory: refusing"
            )));
        }
    }
    Ok(())
}

/// Fixture opener over one disk image file: the device is a fresh
/// [`FileTarget`] per call, the partition a [`PartFile`] window at
/// the Mkpart-planned offset, the mount the [`MountShim`] stand-in.
#[derive(Debug, Clone)]
struct EndToEndOpener {
    path: std::path::PathBuf,
    disk_len: u64,
    base: u64,
    len: u64,
}

impl crate::pipeline::opener::Opener for EndToEndOpener {
    fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
        Ok(Box::new(FileTarget::open(&self.path, self.disk_len)?))
    }

    fn partition(&self) -> TestResult<Box<dyn Volume>> {
        Ok(Box::new(PartFile::open(&self.path, self.base, self.len)?))
    }

    fn partition_path(&self) -> TestResult<std::path::PathBuf> {
        Err(CoreError::invalid(
            "test opener has no partition node".to_string(),
        ))
    }

    fn mount_partition(
        &self,
        _filesystem: &Filesystem,
    ) -> TestResult<Box<dyn crate::pipeline::opener::MountedPartition>> {
        Ok(Box::new(MountShim::mount(&self.path, self.base, self.len)?))
    }
}

/// A recording reporter: every event in run order.
#[derive(Debug, Default)]
struct Recorder {
    events: Vec<crate::pipeline::event::Event>,
}

impl crate::pipeline::event::Reporter for Recorder {
    fn event(&mut self, event: crate::pipeline::event::Event) {
        self.events.push(event);
    }
}

/// `assets/resources/` next to the workspace root, for the pinned
/// core size below.
fn resources_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/resources"
    ))
}

/// Seed `<exe_dir>/../share/rufus-linux/assets` from the manifest
/// tree so the production `load()` path resolves with no
/// environment variables. This is the resolver's own third
/// candidate (`Env::assets_dir` order); `load()` verifies exact
/// size and SHA-256 on every load, so the seed cannot plant wrong
/// bytes silently. Writes only under `target/` (gitignored),
/// idempotent across reruns. The single seeder every lib test
/// shares (unit and end-to-end alike): each payload stages to a
/// unique temp name in the same directory and is `rename`d into
/// place, and `rename` onto one filesystem is atomic — parallel
/// test threads never observe a truncated asset, which a direct
/// `write` of the final name allowed.
pub(crate) fn seed_exe_assets() {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static SEED_TICK: AtomicU64 = AtomicU64::new(0);
    let exe = std::env::current_exe().expect("the test exe resolves");
    let dir = exe
        .parent()
        .expect("the exe has a dir")
        .join("../share/rufus-linux/assets");
    std::fs::create_dir_all(&dir).expect("the asset dir creates");
    let mut names: Vec<String> = vec![
        // The Syslinux arm loads 400/401 for a 4.07 image and
        // 402/403 for a 6.04 one, chosen from the image banner.
        "RCDATA_400.bin".to_string(),
        "RCDATA_401.bin".to_string(),
        "RCDATA_402.bin".to_string(),
        "RCDATA_403.bin".to_string(),
        // The GRUB4DOS arm loads resource 450 through the
        // production path, so its tests seed it here too.
        "RCDATA_450.bin".to_string(),
        "RCDATA_502.bin".to_string(),
    ];
    for id in 300..=326u32 {
        // The FreeDOS arm loads resources 300-326 through the
        // production path, so its tests seed them here too.
        names.push(format!("RCDATA_{id}.bin"));
    }
    for name in &names {
        let bytes = std::fs::read(resources_dir().join(name)).expect("the pinned asset reads");
        let staged = dir.join(format!(
            ".{name}.seed-{}-{}.tmp",
            std::process::id(),
            SEED_TICK.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&staged, &bytes).expect("the asset stages");
        std::fs::rename(&staged, dir.join(name)).expect("the asset lands");
    }
}

#[test]
fn full_plan_installs_syslinux_end_to_end() {
    // Seed the resolver first: the run below exercises the real
    // production `load()` path, which needs the asset directory.
    seed_exe_assets();
    // A real ISO file (the image tree opens from a path) and a
    // 128 MiB sparse disk image file, both under one scratch dir.
    // No `mount(2)`, no privileges: the opener below serves the
    // file, and the mount shim stands in with a temp directory.
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let iso_path = scratch.path().join("syslinux.iso");
    std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
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
    let plan = Plan {
        version: PLAN_VERSION,
        created_by: "bootloader-e2e".to_string(),
        device: DeviceRef {
            path: "/dev/test".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        },
        image: ImageRef {
            path: iso_path.display().to_string(),
            size_bytes: 32 * SECTOR_BYTES as u64,
            sha256: String::new(),
            kind: ImageKind::Iso,
        },
        options: Options {
            scheme: rufus_proto::Scheme::Mbr,
            target: rufus_proto::Target::Dual,
            filesystem: Filesystem::Fat32,
            label: None,
            cluster_bytes: None,
            quick_format: true,
            bad_blocks: false,
            verify: false,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
            msdos_dir: None,
        },
        steps: vec![
            rufus_proto::Step::Wipe,
            rufus_proto::Step::Mklabel {
                scheme: rufus_proto::Scheme::Mbr,
            },
            rufus_proto::Step::Mkpart {
                scheme: rufus_proto::Scheme::Mbr,
                layout: rufus_proto::Layout::Single,
            },
            rufus_proto::Step::Mkfs {
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick: true,
            },
            rufus_proto::Step::Write {
                mode: rufus_proto::WriteMode::Copy,
            },
            rufus_proto::Step::Bootloader {
                mode: rufus_proto::BootloaderMode::Auto,
            },
            rufus_proto::Step::Finalize,
        ],
        confirm: String::new(),
    };
    let options = crate::pipeline::RunOptions {
        verify: false,
        badblocks: false,
        retries: 3,
        retry_delay: std::time::Duration::ZERO,
        reset_usb: false,
    };
    let mut reporter = Recorder::default();
    let report = crate::pipeline::run(&plan, &opener, &options, &mut reporter, &|| false)
        .expect("the full plan runs");
    // All seven steps ran, in order, with no refusal anywhere.
    let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
    assert_eq!(
        names,
        [
            "wipe",
            "mklabel",
            "mkpart",
            "mkfs",
            "write",
            "bootloader",
            "finalize"
        ],
        "every step runs in order"
    );
    for event in &reporter.events {
        if let crate::pipeline::event::Event::Message { text, .. } = event {
            assert!(!text.contains("not implemented"), "no step refused: {text}");
        }
    }
    // The stamped MBR entry points at the same window the opener
    // serves: the table and the test agree on the offset.
    let disk = std::fs::OpenOptions::new()
        .read(true)
        .open(&disk_path)
        .expect("the disk reopens");
    let mut entry = [0u8; 16];
    disk.read_exact_at(&mut entry, 446)
        .expect("the mbr entry reads");
    let start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
    assert_eq!(
        u64::from(start) * 512,
        base,
        "the table entry names the data window"
    );
    // The partition window is fsck clean.
    let mut window = vec![0u8; len as usize];
    disk.read_exact_at(&mut window, base)
        .expect("the window reads");
    let picture = scratch.path().join("part.img");
    std::fs::write(&picture, &window).expect("the window dumps");
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
    assert!(
        output.status.success(),
        "fsck.fat -n exits 0 on the installed partition ({})",
        output.status
    );
    // Files and boot sector through a fresh handle over the same
    // window: the stage, the companions with the ISO's bytes, the
    // wrapper, and the grafted record.
    let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
    let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
    let core = load_from(&resources_dir(), Resource::Syslinux604Core)
        .expect("the core loads")
        .bytes()
        .to_vec();
    let stage = fat.read_file("/ldlinux.sys").expect("the stage reads");
    assert_eq!(
        stage.len(),
        core.len() + 1024,
        "the stage is core plus adv in 69145 bytes"
    );
    for (name, bytes) in [
        ("ldlinux.c32", b"ldlinux-c32-stub".as_slice()),
        ("menu.c32", b"menu-stub".as_slice()),
        ("vesamenu.c32", b"vesamenu-stub".as_slice()),
        ("libutil.c32", b"libutil-stub".as_slice()),
    ] {
        let path = format!("/isolinux/{name}");
        let back = fat.read_file(&path).expect("the companion reads back");
        assert_eq!(back, bytes, "{name} keeps the ISO bytes");
    }
    // The copy's own output, merged into the image on release:
    // this reads back out of the partition image, not the temp
    // dir, so it fails if the merge ever drops the walk's files.
    let back = fat
        .read_file("/isolinux/isolinux.cfg")
        .expect("the copied config reads back");
    assert_eq!(
        back, b"DEFAULT linux\n",
        "the copy output survived the merge into the image"
    );
    let back = fat
        .read_file("/syslinux.cfg")
        .expect("the wrapper reads back");
    assert_eq!(
        back,
        syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
        "the wrapper chains to the located config"
    );
    let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
    let mut sector = [0u8; 512];
    view.read_exact_at(0, &mut sector).expect("sector 0 reads");
    assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
    assert_eq!(
        &sector[3..11],
        b"SYSLINUX",
        "the payload OEM marks the volume"
    );
    assert_eq!(
        2 + u16::from(sector[1]),
        0x5A,
        "the jump targets the code at 0x5A"
    );
}

/// Synthetic user-supplied MS-DOS directory: exact-size `IO.SYS`
/// and `COMMAND.COM` with the reference signatures planted plus a
/// 2 KiB `MSDOS.SYS` — stand-in bytes (synthetic, not real DOS
/// bytes), the same shape the arm-level tests use. The directory
/// returns alongside so it outlives the run.
fn msdos_user_dir() -> tempfile::TempDir {
    use crate::boot::msdos as dos;
    let mut io_sys: Vec<u8> = (0..dos::IO_SYS_BYTES)
        .map(|index| ((index * 7 + 3) % 251) as u8)
        .collect();
    let end = dos::IO_SYS_SIGNATURE_OFFSET + dos::IO_SYS_SIGNATURE.len();
    io_sys[dos::IO_SYS_SIGNATURE_OFFSET..end].copy_from_slice(&dos::IO_SYS_SIGNATURE);
    let mut command_com: Vec<u8> = (0..dos::COMMAND_COM_BYTES)
        .map(|index| ((index * 5 + 1) % 251) as u8)
        .collect();
    let end = dos::COMMAND_COM_SIGNATURE_OFFSET + dos::COMMAND_COM_SIGNATURE.len();
    command_com[dos::COMMAND_COM_SIGNATURE_OFFSET..end]
        .copy_from_slice(&dos::COMMAND_COM_SIGNATURE);
    let dir = tempfile::tempdir().expect("the dos dir allocates");
    std::fs::write(dir.path().join("IO.SYS"), &io_sys).expect("IO.SYS lands");
    std::fs::write(dir.path().join("MSDOS.SYS"), vec![0xABu8; 2048]).expect("MSDOS.SYS lands");
    std::fs::write(dir.path().join("COMMAND.COM"), &command_com).expect("COMMAND.COM lands");
    dir
}

/// The MS-DOS plan over `iso` with `dos` as its user-supplied
/// directory (`None` for the refusal test): wipe, table,
/// partition, format, bootloader, finalize — never a write step,
/// since `IO.SYS` must be the first root entry of the fresh
/// volume.
fn msdos_plan(iso: &std::path::Path, dos: Option<&std::path::Path>) -> Plan {
    Plan {
        version: PLAN_VERSION,
        created_by: "bootloader-msdos-e2e".to_string(),
        device: DeviceRef {
            path: "/dev/test".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        },
        image: ImageRef {
            path: iso.display().to_string(),
            size_bytes: 32 * SECTOR_BYTES as u64,
            sha256: String::new(),
            kind: ImageKind::Iso,
        },
        options: Options {
            scheme: rufus_proto::Scheme::Mbr,
            target: rufus_proto::Target::Dual,
            filesystem: Filesystem::Fat32,
            label: None,
            cluster_bytes: None,
            quick_format: true,
            bad_blocks: false,
            verify: false,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
            msdos_dir: dos.map(|dir| dir.display().to_string()),
        },
        steps: vec![
            rufus_proto::Step::Wipe,
            rufus_proto::Step::Mklabel {
                scheme: rufus_proto::Scheme::Mbr,
            },
            rufus_proto::Step::Mkpart {
                scheme: rufus_proto::Scheme::Mbr,
                layout: rufus_proto::Layout::Single,
            },
            rufus_proto::Step::Mkfs {
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick: true,
            },
            rufus_proto::Step::Bootloader {
                mode: rufus_proto::BootloaderMode::MsDos,
            },
            rufus_proto::Step::Finalize,
        ],
        confirm: String::new(),
    }
}

/// A sparse 128 MiB disk image plus the opener serving it at the
/// Mkpart-planned window: the shared rig both MS-DOS run tests
/// drive (the refusal test snapshots the window between runs).
fn msdos_rig(scratch: &tempfile::TempDir) -> (std::path::PathBuf, EndToEndOpener, u64, u64) {
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
    (disk_path, opener, base, len)
}

/// The run options every MS-DOS run below shares: no read-back
/// check, no surface scan, instant retries.
fn msdos_run_options() -> crate::pipeline::RunOptions {
    crate::pipeline::RunOptions {
        verify: false,
        badblocks: false,
        retries: 3,
        retry_delay: std::time::Duration::ZERO,
        reset_usb: false,
    }
}

#[test]
fn msdos_plan_installs_user_files_end_to_end() {
    // The full pipeline proves both wirings at once: `run_step`
    // threads `plan.options.msdos_dir` into `bootloader::run`,
    // which threads it into `install_tree`. Reverting either to
    // `None` refuses the run naming `--msdos-dir`, so this test
    // fails. The ISO is only the still-required detection record:
    // the arm never reads the tree (the plan carries no write
    // step), and `run` never even opens it (see
    // `msdos_plan_ignores_an_image_with_no_tree`).
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let iso_path = scratch.path().join("dos.iso");
    std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
    let (disk_path, opener, base, len) = msdos_rig(&scratch);
    let dos = msdos_user_dir();
    let mut reporter = Recorder::default();
    let plan = msdos_plan(&iso_path, Some(dos.path()));
    let report = crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
        false
    })
    .expect("the msdos plan runs");
    // All six steps ran, in order, with no transfer anywhere.
    let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
    assert_eq!(
        names,
        [
            "wipe",
            "mklabel",
            "mkpart",
            "mkfs",
            "bootloader",
            "finalize"
        ],
        "every step runs in order, with no write step"
    );
    // The three files land through a fresh handle over the same
    // window — which is what proves the run flushed — with both
    // patches applied and the kernel byte-correct.
    let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
    let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
    let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
    assert_eq!(
        back.len(),
        crate::boot::msdos::IO_SYS_BYTES,
        "the bios length holds"
    );
    assert_eq!(
        back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
        0xEB,
        "the bios patch byte lands"
    );
    let back = fat.read_file("/MSDOS.SYS").expect("MSDOS.SYS reads back");
    assert_eq!(back, vec![0xABu8; 2048], "the kernel is byte-correct");
    let back = fat
        .read_file("/COMMAND.COM")
        .expect("COMMAND.COM reads back");
    assert_eq!(
        back.len(),
        crate::boot::msdos::COMMAND_COM_BYTES,
        "the shell length holds"
    );
    assert_eq!(
        back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
        0xEB,
        "the shell patch byte lands"
    );
    // The run reports the reference lines plus the summary.
    let texts: Vec<&str> = reporter
        .events
        .iter()
        .filter_map(|event| match event {
            crate::pipeline::event::Event::Message { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        texts.contains(&"Patching IO.SYS..."),
        "the bios line reports: {texts:?}"
    );
    assert!(
        texts.contains(&"Patching COMMAND.COM..."),
        "the shell line reports: {texts:?}"
    );
    let total =
        (crate::boot::msdos::IO_SYS_BYTES + 2048 + crate::boot::msdos::COMMAND_COM_BYTES) as u64;
    let summary = format!("installed msdos (3 files written, 0 kept, {total} bytes)");
    assert!(
        texts.contains(&summary.as_str()),
        "the summary names the files: {texts:?}"
    );
    assert!(
        texts.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
}

#[test]
fn msdos_plan_ignores_an_image_with_no_tree() {
    // The arm never reads the image tree, and `run` short-circuits
    // past the tree setup: a plan whose image is not an ISO at all
    // (patterned bytes, no descriptors) still installs. The kind
    // stays `Iso` and the CLI still requires the `--image`
    // argument — only the readability requirement is gone.
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let iso_path = scratch.path().join("dos.iso");
    let garbage: Vec<u8> = (0..4096)
        .map(|index| ((index * 11 + 7) % 251) as u8)
        .collect();
    std::fs::write(&iso_path, &garbage).expect("the non-image writes");
    let (disk_path, opener, base, len) = msdos_rig(&scratch);
    let dos = msdos_user_dir();
    let mut reporter = Recorder::default();
    let plan = msdos_plan(&iso_path, Some(dos.path()));
    let report = crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
        false
    })
    .expect("a tree-less image still installs msdos");
    let names: Vec<&str> = report.steps.iter().map(|step| step.step).collect();
    assert_eq!(
        names,
        [
            "wipe",
            "mklabel",
            "mkpart",
            "mkfs",
            "bootloader",
            "finalize"
        ],
        "every step runs in order, with no write step"
    );
    let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
    let mut fat = Fat32::open(Box::new(view)).expect("the volume opens");
    let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
    assert_eq!(
        back.len(),
        crate::boot::msdos::IO_SYS_BYTES,
        "the bios lands without any image tree"
    );
    let back = fat
        .read_file("/COMMAND.COM")
        .expect("COMMAND.COM reads back");
    assert_eq!(
        back.len(),
        crate::boot::msdos::COMMAND_COM_BYTES,
        "the shell lands without any image tree"
    );
}

#[test]
fn msdos_plan_without_its_directory_refuses_leaving_the_volume_identical() {
    // Same rig, two phases: format first, snapshot the partition
    // window, then run the bootloader step with `msdos_dir: None`
    // (as a hand-built plan without one would carry). The refusal
    // names `--msdos-dir` (step-wrapped as `bootloader`) and not
    // one window byte moves: the gate fires before any write, and
    // a failed step never flushes on its behalf.
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let iso_path = scratch.path().join("dos.iso");
    std::fs::write(&iso_path, syslinux_iso()).expect("the iso writes");
    let (disk_path, opener, base, len) = msdos_rig(&scratch);
    let mut reporter = Recorder::default();
    let mut setup = msdos_plan(&iso_path, None);
    setup.steps.truncate(4);
    crate::pipeline::run(
        &setup,
        &opener,
        &msdos_run_options(),
        &mut reporter,
        &|| false,
    )
    .expect("wipe through mkfs runs");
    let disk = std::fs::OpenOptions::new()
        .read(true)
        .open(&disk_path)
        .expect("the disk reopens");
    let mut before = vec![0u8; len as usize];
    disk.read_exact_at(&mut before, base)
        .expect("the window snapshots");
    let mut reporter = Recorder::default();
    let mut plan = msdos_plan(&iso_path, None);
    plan.steps = vec![rufus_proto::Step::Bootloader {
        mode: rufus_proto::BootloaderMode::MsDos,
    }];
    let error = crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
        false
    })
    .expect_err("a directory-less msdos refuses");
    assert!(
        matches!(
            error,
            crate::error::CoreError::Step {
                step: "bootloader",
                ..
            }
        ),
        "the refusal is step-wrapped: {error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("--msdos-dir"), "names the flag: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    let mut after = vec![0u8; len as usize];
    disk.read_exact_at(&mut after, base)
        .expect("the window reads back");
    assert_eq!(after, before, "no volume byte moved");
}

/// A real `pipeline::run` step plan for the acceptance table:
/// wipe, table, partition, format, bootloader, finalize — never a
/// transfer step, which no bootloader arm needs (every arm reads
/// the image file itself, or nothing at all).
fn acceptance_plan(
    iso: &std::path::Path,
    image_len: u64,
    filesystem: Filesystem,
    layout: rufus_proto::Layout,
    mode: rufus_proto::BootloaderMode,
    dos: Option<&std::path::Path>,
) -> Plan {
    Plan {
        version: PLAN_VERSION,
        created_by: "bootloader-acceptance".to_string(),
        device: DeviceRef {
            path: "/dev/test".to_string(),
            block_device: false,
            size_bytes: None,
            serial: None,
            model: None,
            sysfs: None,
        },
        image: ImageRef {
            path: iso.display().to_string(),
            size_bytes: image_len,
            sha256: String::new(),
            kind: ImageKind::Iso,
        },
        options: Options {
            scheme: rufus_proto::Scheme::Mbr,
            target: rufus_proto::Target::Dual,
            filesystem: filesystem.clone(),
            label: None,
            cluster_bytes: None,
            quick_format: true,
            bad_blocks: false,
            verify: false,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
            msdos_dir: dos.map(|dir| dir.display().to_string()),
        },
        steps: vec![
            rufus_proto::Step::Wipe,
            rufus_proto::Step::Mklabel {
                scheme: rufus_proto::Scheme::Mbr,
            },
            rufus_proto::Step::Mkpart {
                scheme: rufus_proto::Scheme::Mbr,
                layout,
            },
            rufus_proto::Step::Mkfs {
                filesystem: filesystem.clone(),
                label: None,
                cluster_bytes: None,
                quick: true,
            },
            rufus_proto::Step::Bootloader { mode },
            rufus_proto::Step::Finalize,
        ],
        confirm: String::new(),
    }
}

/// One mode of the acceptance table on its own fresh file-backed
/// disk, so modes cannot mask each other. The `UefiNtfs` and
/// `None` modes run in two phases (set up, snapshot the data
/// window, then the bootloader step) so the test pins that the
/// arm itself leaves the data window alone; every other mode runs
/// the whole six-step plan at once.
fn acceptance_one(mode: rufus_proto::BootloaderMode) {
    use rufus_proto::BootloaderMode as Mode;
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    // Fixtures up front (a few hundred KiB total): the syslinux
    // image serves every arm that ignores the tree, the GRUB2 and
    // Kolibri images carry their payloads, and the MS-DOS image is
    // patterned garbage proving no tree is ever opened.
    let syslinux = syslinux_iso();
    let grub4dos = syslinux_iso_with(Some(&stand_in_grldr()));
    let (grub2_image, grub2_boot, grub2_core) = grub2_iso();
    let (kolibri_image, kolibri_loader) = kolibri_iso();
    let garbage: Vec<u8> = (0..4096)
        .map(|index| ((index * 11 + 7) % 251) as u8)
        .collect();
    let (iso_bytes, image_len): (&[u8], u64) = match mode {
        Mode::Grub2 => (&grub2_image, 32 * SECTOR_BYTES as u64),
        Mode::Kolibri => (&kolibri_image, 32 * SECTOR_BYTES as u64),
        Mode::MsDos => (&garbage, garbage.len() as u64),
        // The GRUB4DOS arm refuses without a root loader on the
        // volume. The acceptance plan has no copy step, so the
        // stand-in loader is staged onto the volume directly (see
        // the two-phase branch below); the image only names it.
        Mode::Grub4dos => (&grub4dos, grub4dos.len() as u64),
        _ => (&syslinux, 32 * SECTOR_BYTES as u64),
    };
    let iso_path = scratch.path().join("acceptance.iso");
    std::fs::write(&iso_path, iso_bytes).expect("the iso writes");
    let dos = (mode == Mode::MsDos).then(msdos_user_dir);
    // The UEFI:NTFS data partition lives in the two-partition
    // window; every other mode formats the single data window.
    let uefi = mode == Mode::UefiNtfs;
    let disk_path = scratch.path().join("disk.img");
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&disk_path)
        .expect("the disk creates")
        .set_len(DISK_BYTES)
        .expect("the disk sizes");
    let (base, len) = if uefi {
        data_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, DISK_BYTES)
            .expect("the uefi data window plans")
    } else {
        single_data_window(TableKind::Mbr, 512, DISK_BYTES).expect("the data window plans")
    };
    let opener = EndToEndOpener {
        path: disk_path.clone(),
        disk_len: DISK_BYTES,
        base,
        len,
    };
    let filesystem = if uefi {
        Filesystem::Exfat
    } else {
        Filesystem::Fat32
    };
    let layout = if uefi {
        rufus_proto::Layout::UefiNtfs
    } else {
        rufus_proto::Layout::Single
    };
    let plan = acceptance_plan(
        &iso_path,
        image_len,
        filesystem,
        layout,
        mode.clone(),
        dos.as_ref().map(|dir| dir.path()),
    );
    // Step names in run order, asserted after every run below.
    let step_names = |report: &crate::pipeline::RunReport| {
        report
            .steps
            .iter()
            .map(|step| step.step)
            .collect::<Vec<_>>()
    };
    // Sector 0 of the data window through a fresh handle: the
    // record fingerprints below all read it this way, which is
    // what proves the run flushed.
    let boot_sector = || {
        let disk = std::fs::OpenOptions::new()
            .read(true)
            .open(&disk_path)
            .expect("the disk reopens");
        let mut sector = [0u8; 512];
        disk.read_exact_at(&mut sector, base)
            .expect("sector 0 reads");
        sector
    };
    // The data window through a fresh volume handle (flush proof
    // for the file fingerprints).
    let open_volume = || {
        let view = PartFile::open(&disk_path, base, len).expect("the view reopens");
        Fat32::open(Box::new(view)).expect("the volume opens")
    };
    // The GRUB4DOS fingerprint: the staged root loader is kept
    // byte-identical and the MBR+SBR land over it. Both paths
    // below reach it (the two-phase one returns early).
    let grub4dos_fingerprint = || {
        let expected = stand_in_grldr();
        let mut fat = open_volume();
        let back = fat.read_file("/GRLDR").expect("the loader reads back");
        assert_eq!(back, expected, "the staged loader is kept byte-identical");
        let mbr = load_from(&resources_dir(), Resource::Grub4DosMbr)
            .expect("the mbr loads")
            .bytes()
            .to_vec();
        let disk = std::fs::OpenOptions::new()
            .read(true)
            .open(&disk_path)
            .expect("the disk reopens");
        let mut sector = [0u8; 512];
        disk.read_exact_at(&mut sector, 0).expect("sector 0 reads");
        assert_eq!(&sector[..423], &mbr[..423], "the mbr window lands");
        assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        let sbr = &mbr[512..];
        let mut sbr_back = vec![0u8; sbr.len()];
        disk.read_exact_at(&mut sbr_back, 512)
            .expect("the sbr reads");
        assert_eq!(sbr_back, sbr, "the sbr lands whole at sector 1");
    };
    if uefi || mode == Mode::None || mode == Mode::Grub4dos {
        // Two phases: format first, snapshot the window, then the
        // bootloader step alone. A single plan could not isolate
        // the arm's own writes from the formatter's.
        let mut setup = plan.clone();
        setup.steps.truncate(4);
        let mut reporter = Recorder::default();
        crate::pipeline::run(
            &setup,
            &opener,
            &msdos_run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("wipe through mkfs runs");
        if mode == Mode::Grub4dos {
            // The copy step would place the image's root loader
            // here; the plan has none, so stage the stand-in with
            // the same byte-taking core the arm's loader uses.
            let mut fat = open_volume();
            crate::boot::grub4dos::install_loader(&mut fat, &stand_in_grldr())
                .expect("the staged loader lands");
        }
        let disk = std::fs::OpenOptions::new()
            .read(true)
            .open(&disk_path)
            .expect("the disk reopens");
        let mut before = vec![0u8; len as usize];
        disk.read_exact_at(&mut before, base)
            .expect("the window snapshots");
        let mut phase = plan.clone();
        phase.steps = if uefi {
            // `Mklabel` re-records the table: every `run` starts
            // context-free, so the second phase must stamp it again
            // before the arm resolves its ESP window.
            vec![
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Bootloader {
                    mode: Mode::UefiNtfs,
                },
                rufus_proto::Step::Finalize,
            ]
        } else if mode == Mode::Grub4dos {
            // The GRUB4DOS arm bounds its record by the recorded
            // table, so this phase stamps the record first too.
            vec![
                rufus_proto::Step::Mklabel {
                    scheme: rufus_proto::Scheme::Mbr,
                },
                rufus_proto::Step::Bootloader {
                    mode: Mode::Grub4dos,
                },
            ]
        } else {
            vec![rufus_proto::Step::Bootloader { mode: mode.clone() }]
        };
        let mut reporter = Recorder::default();
        let report = crate::pipeline::run(
            &phase,
            &opener,
            &msdos_run_options(),
            &mut reporter,
            &|| false,
        )
        .expect("the bootloader phase runs");
        if uefi {
            assert_eq!(
                step_names(&report),
                ["mklabel", "bootloader", "finalize"],
                "the uefi phase runs in order"
            );
            let (offset, esp_len) =
                esp_window(LayoutKind::UefiNtfs, TableKind::Mbr, 512, DISK_BYTES)
                    .expect("the esp window plans");
            assert_eq!(
                esp_len,
                crate::boot::uefi_ntfs::IMAGE_BYTES,
                "the esp window holds the whole shim"
            );
            let shim = load_from(&resources_dir(), Resource::UefiNtfsImage)
                .expect("the shim loads")
                .bytes()
                .to_vec();
            let mut window = vec![0u8; esp_len as usize];
            disk.read_exact_at(&mut window, offset)
                .expect("the esp window reads");
            assert_eq!(window, shim, "the shim lands whole at the esp offset");
        } else if mode == Mode::Grub4dos {
            assert_eq!(
                step_names(&report),
                ["mklabel", "bootloader"],
                "the grub4dos phase runs in order"
            );
        } else {
            assert_eq!(
                step_names(&report),
                ["bootloader"],
                "the bootloader phase runs its one step"
            );
        }
        let mut after = vec![0u8; len as usize];
        disk.read_exact_at(&mut after, base)
            .expect("the window reads back");
        assert_eq!(
            after, before,
            "the {mode:?} arm leaves the data window alone"
        );
        if mode == Mode::Grub4dos {
            grub4dos_fingerprint();
        }
        return;
    }
    let mut reporter = Recorder::default();
    let report = crate::pipeline::run(&plan, &opener, &msdos_run_options(), &mut reporter, &|| {
        false
    })
    .expect("the acceptance plan runs");
    assert_eq!(
        step_names(&report),
        [
            "wipe",
            "mklabel",
            "mkpart",
            "mkfs",
            "bootloader",
            "finalize"
        ],
        "every step runs in order, with no write step"
    );
    match mode {
        Mode::Syslinux => {
            // The stage lands and the payload record grafts:
            // companions and the wrapper are the arm tests'
            // province (`syslinux_604_installs_stage_companions_and_config`).
            let mut fat = open_volume();
            let stage = fat.read_file("/LDLINUX.SYS").expect("the stage reads back");
            assert!(!stage.is_empty(), "the stage lands");
            let sector = boot_sector();
            assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
            assert_eq!(
                &sector[3..11],
                b"SYSLINUX",
                "the payload oem marks the volume"
            );
            assert_eq!(
                2 + u16::from(sector[1]),
                0x5A,
                "the jump targets the code at 0x5A"
            );
        }
        Mode::Grub2 => {
            // The BIOS record plus the whole core image on the
            // disk itself (sectors 0 and 1, not the partition
            // window); the UEFI placement has no payload in this
            // image, so nothing is placed (see
            // `grub2_installs_bios_and_places_uefi` for the placed
            // case).
            let disk = std::fs::OpenOptions::new()
                .read(true)
                .open(&disk_path)
                .expect("the disk reopens");
            let mut sector = [0u8; 512];
            disk.read_exact_at(&mut sector, 0).expect("sector 0 reads");
            assert_eq!(&sector[..0x5c], &grub2_boot[..0x5c], "record head verbatim");
            assert_eq!(
                &sector[0x5c..0x64],
                &1u64.to_le_bytes(),
                "the kernel field names sector 1"
            );
            assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
            let mut core_back = vec![0u8; grub2_core.len()];
            disk.read_exact_at(&mut core_back, 512)
                .expect("the core reads");
            assert_eq!(core_back, grub2_core, "the core lands whole at sector 1");
        }
        Mode::Grub4dos => {
            // Every GRUB4DOS run takes the two-phase branch above,
            // which runs this same fingerprint; the refusal without
            // a loader is `grub4dos_refuses_without_a_root_grldr`.
            grub4dos_fingerprint();
        }
        Mode::Freedos => {
            // The pair, the 25 locale files and the rendered
            // `AUTOEXEC.BAT`: 28 files, plus the record (the locale
            // plan lines are the arm tests' province,
            // `install_us_builds_the_full_volume`).
            let mut fat = open_volume();
            for name in ["/COMMAND.COM", "/KERNEL.SYS", "/AUTOEXEC.BAT"] {
                let back = fat.read_file(name).expect("the file reads back");
                assert!(!back.is_empty(), "{name} lands");
            }
            let listed = fat.list_dir("/LOCALE").expect("the locale lists");
            assert_eq!(listed.len(), 25, "LOCALE holds the 25 locale files");
            let entries = fat.list_dir("/").expect("the root lists");
            let mut root: Vec<&str> = entries
                .iter()
                .map(|entry| entry.short_name.as_str())
                .collect();
            root.sort_unstable();
            assert_eq!(
                root,
                vec!["AUTOEXEC.BAT", "COMMAND.COM", "KERNEL.SYS", "LOCALE"],
                "the root holds the pair plus AUTOEXEC.BAT beside LOCALE"
            );
            let sector = boot_sector();
            assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
            assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        }
        Mode::Kolibri => {
            // The image-tree loader byte-identical at the root,
            // plus the record (the keep path is the arm tests'
            // province).
            let mut fat = open_volume();
            let back = fat.read_file("/MTLD_F32").expect("the loader reads back");
            assert_eq!(back, kolibri_loader, "the loader is byte-identical");
            let sector = boot_sector();
            assert_eq!(&sector[0..3], &[0xEB, 0x58, 0x90], "the payload jump lands");
            assert_eq!(&sector[510..512], &[0x55, 0xAA], "the boot mark closes");
        }
        Mode::MsDos => {
            // The three user files with `IO.SYS` first and both
            // patches applied (the keep and miss paths are the arm
            // tests' province).
            let mut fat = open_volume();
            let listed = fat.list_dir("/").expect("the root lists");
            let shorts: Vec<&str> = listed
                .iter()
                .map(|entry| entry.short_name.as_str())
                .collect();
            assert_eq!(
                shorts,
                vec!["IO.SYS", "MSDOS.SYS", "COMMAND.COM"],
                "IO.SYS lands first"
            );
            let back = fat.read_file("/IO.SYS").expect("IO.SYS reads back");
            assert_eq!(
                back[crate::boot::msdos::IO_SYS_PATCH_OFFSET],
                0xEB,
                "the bios patch byte lands"
            );
            let back = fat
                .read_file("/COMMAND.COM")
                .expect("COMMAND.COM reads back");
            assert_eq!(
                back[crate::boot::msdos::COMMAND_COM_PATCH_OFFSET],
                0xEB,
                "the shell patch byte lands"
            );
        }
        Mode::UefiNtfs | Mode::Auto | Mode::None => {
            panic!("the two-phase arms above return early; auto is never accepted here");
        }
        Mode::Windows => {
            panic!(
                "the windows arm is mount-based, not fingerprint-based: it applies a WIM onto the mounted data and ESP partitions, so it stays outside the fingerprint table"
            );
        }
    }
}

/// Acceptance across every wired bootloader mode: each mode runs a
/// real `pipeline::run` step plan on its own fresh file-backed
/// disk and leaves its fingerprint behind. The `UefiNtfs` and
/// `None` arms run in two phases so the data-window comparison
/// isolates the arm from the formatter; the exFAT data partition
/// for `UefiNtfs` formats natively (NTFS would need the host
/// tool). Every fingerprint reads through a fresh handle, which
/// is what proves each run flushed.
#[test]
fn every_wired_mode_installs_its_fingerprint_end_to_end() {
    // One asset seeding for the arms that load production
    // payloads (FreeDOS, GRUB4DOS, UEFI:NTFS); the rest read the
    // image tree or the user directory only.
    seed_exe_assets();
    use rufus_proto::BootloaderMode as Mode;
    for mode in [
        Mode::Syslinux,
        Mode::Grub2,
        Mode::Grub4dos,
        Mode::UefiNtfs,
        Mode::Freedos,
        Mode::Kolibri,
        Mode::MsDos,
        Mode::None,
    ] {
        acceptance_one(mode);
    }
}
