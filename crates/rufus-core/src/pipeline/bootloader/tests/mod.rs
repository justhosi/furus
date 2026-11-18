//! Unit tests for the bootloader arms (S23 split).
//!
//! The shared fixtures and test doubles live here; each arm keeps its own
//! tests in a sibling file, so no single file owns the whole 7,600-line
//! original. Every test body is unchanged — only its module path moved.

use super::*;
use crate::boot::Resource;
use crate::boot::load_from;
use crate::copy::Entry;
use crate::copy::Source;
use crate::error::Result as TestResult;
use crate::fs::VecVolume;
use crate::fs::Volume;
use crate::fs::fat32::format::FormatOptions;
use crate::part::plan::LayoutKind;
use crate::pipeline::target::VecTarget;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::rc::Rc;

/// `assets/resources/` next to the workspace root, without going
/// through asset-dir resolution: the loader seam every install
/// below points at, so each one always executes.
fn resources_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/resources"
    ))
}

/// Asset-tree loader for [`install_tree`]: what production's
/// [`crate::boot::load`] resolves to, without the runtime asset
/// directory.
fn asset_loader(resource: Resource) -> TestResult<Payload> {
    load_from(&resources_dir(), resource)
}

/// In-memory [`Source`] over explicit listings and file bytes, the
/// same pattern the `copy` and `syslinux` tests use.
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

fn file_entry(name: &[u8], bytes: &[u8]) -> Entry {
    Entry {
        name: name.to_vec(),
        is_dir: false,
        size: bytes.len() as u64,
        mode: Some(0o644),
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
        mode: Some(0o755),
        modified: None,
        accessed: None,
        link: None,
    }
}

impl Source for MemSource {
    fn root_entries(&self) -> TestResult<Vec<Entry>> {
        self.child_entries(&[])
    }

    fn child_entries(&self, dir: &[Vec<u8>]) -> TestResult<Vec<Entry>> {
        self.dirs
            .get(dir)
            .cloned()
            .ok_or_else(|| CoreError::invalid("test source has no such directory".to_string()))
    }

    fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> TestResult<usize> {
        let bytes = self
            .files
            .get(file)
            .ok_or_else(|| CoreError::invalid("test source has no such file".to_string()))?;
        let at = usize::try_from(offset).expect("the test offset fits usize");
        if at > bytes.len() {
            return Err(CoreError::invalid(
                "test read runs past its file".to_string(),
            ));
        }
        let rest = bytes.get(at..).expect("the test window fits");
        let take = rest.len().min(buf.len());
        let (head, _) = rest.split_at(take);
        let dest = buf.get_mut(..take).expect("the test buffer fits");
        dest.copy_from_slice(head);
        Ok(take)
    }
}

/// One `/isolinux` directory holding `isolinux.bin` with `banner`
/// plus one file per name in `extra` (each holding its own name as
/// bytes).
fn payload_tree(banner: &[u8], extra: &[&str]) -> MemSource {
    let mut entries = vec![file_entry(b"isolinux.bin", banner)];
    let mut source = MemSource::new().with_dir(&[], vec![dir_entry(b"isolinux")]);
    for name in extra {
        entries.push(file_entry(name.as_bytes(), name.as_bytes()));
    }
    source = source.with_dir(&[b"isolinux"], entries);
    source = source.with_file(&[b"isolinux", b"isolinux.bin"], banner);
    for name in extra {
        source = source.with_file(&[b"isolinux", name.as_bytes()], name.as_bytes());
    }
    source
}

/// A 6.04 payload tree: banner, config, the core library and all
/// three optional companions.
fn syslinux_604_tree() -> MemSource {
    payload_tree(
        b"ISOLINUX 6.04 20140611 ETCD",
        &[
            "isolinux.cfg",
            "ldlinux.c32",
            "menu.c32",
            "vesamenu.c32",
            "libutil.c32",
        ],
    )
}

/// A 4.07 payload tree: banner and config only, no core library.
fn syslinux_407_tree() -> MemSource {
    payload_tree(b"ISOLINUX 4.07 20130725 ETCD", &["isolinux.cfg"])
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

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> TestResult<()> {
        let borrowed = self.bytes.borrow();
        let start = usize::try_from(offset).expect("the test offset fits usize");
        let end = start.checked_add(buf.len()).expect("the test window fits");
        let window = borrowed.get(start..end).expect("the test read fits");
        buf.copy_from_slice(window);
        Ok(())
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> TestResult<()> {
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
fn formatted() -> (SharedVolume, Fat32) {
    let backing = SharedVolume::blank(64 * 1024 * 1024);
    let fat = Fat32::format(
        Box::new(backing.clone()),
        &FormatOptions {
            volume_id: 0x1234_5678,
            ..Default::default()
        },
    )
    .expect("the volume formats");
    (backing, fat)
}

/// Run [`install_tree`] with the asset loader and a whole-disk
/// double the Syslinux path never touches (one sector is plenty):
/// the Syslinux-shaped calls share this so the disk argument does
/// not repeat in every test.
fn tree_install(source: &MemSource, fat: &mut Fat32, mode: &BootloaderMode) -> Result<Installed> {
    tree_install_table(source, fat, mode, None)
}

/// [`tree_install`] with an explicit recorded table kind for the
/// BIOS arms' gap bound; `None` exercises the no-table refusal.
fn tree_install_table(
    source: &MemSource,
    fat: &mut Fat32,
    mode: &BootloaderMode,
    table: Option<TableKind>,
) -> Result<Installed> {
    let mut dummy = VecVolume::new(512, 512).expect("one sector fits");
    install_tree(
        source,
        fat,
        &mut dummy,
        mode,
        table,
        None,
        &|| false,
        &asset_loader,
    )
}

/// An [`Opener`](crate::pipeline::opener::Opener) that counts
/// `partition()` calls and refuses them: the non-FAT32 test
/// proves the step never opens the partition.
struct CountingOpener {
    partitions: Rc<Cell<usize>>,
}

impl crate::pipeline::opener::Opener for CountingOpener {
    fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
        Err(CoreError::invalid("test opener has no device".to_string()))
    }

    fn partition(&self) -> TestResult<Box<dyn Volume>> {
        self.partitions.set(self.partitions.get() + 1);
        Err(CoreError::invalid(
            "test opener has no partition".to_string(),
        ))
    }

    fn partition_path(&self) -> TestResult<std::path::PathBuf> {
        Err(CoreError::invalid("test opener has no node".to_string()))
    }
}

/// A test [`Opener`](crate::pipeline::opener::Opener) serving one
/// shared [`VecTarget`](crate::pipeline::target::VecTarget) as the
/// whole disk while counting `partition()` calls: the UEFI run
/// path must never open the data partition.
#[derive(Debug, Clone)]
struct DiskOpener {
    target: VecTarget,
    partitions: Rc<Cell<usize>>,
}

impl crate::pipeline::opener::Opener for DiskOpener {
    fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
        Ok(Box::new(self.target.clone()))
    }

    fn partition(&self) -> TestResult<Box<dyn Volume>> {
        self.partitions.set(self.partitions.get() + 1);
        Err(CoreError::invalid(
            "test opener has no partition".to_string(),
        ))
    }

    fn partition_path(&self) -> TestResult<std::path::PathBuf> {
        Err(CoreError::invalid("test opener has no node".to_string()))
    }
}

/// A [`Reporter`](crate::pipeline::event::Reporter) that records
/// every event in order.
#[derive(Debug, Default)]
struct Recorder {
    events: Vec<crate::pipeline::event::Event>,
}

impl crate::pipeline::event::Reporter for Recorder {
    fn event(&mut self, event: crate::pipeline::event::Event) {
        self.events.push(event);
    }
}

/// A [`RunContext`](crate::pipeline::steps::RunContext) over any
/// test opener with an explicit recorded table, for the `run`
/// tests below.
fn run_context_table<'a>(
    opener: &'a dyn crate::pipeline::opener::Opener,
    reporter: &'a mut Recorder,
    table: Option<TableKind>,
) -> crate::pipeline::steps::RunContext<'a> {
    crate::pipeline::steps::RunContext {
        opener,
        target: None,
        table,
        partitioned: None,
        logger: crate::log::Logger::new(crate::log::Level::Info),
        reporter,
        cancelled: &|| false,
        options: crate::pipeline::RunOptions {
            verify: false,
            badblocks: false,
            retries: 3,
            retry_delay: std::time::Duration::ZERO,
            reset_usb: false,
        },
    }
}

/// [`run_context_table`] with no recorded table, over the counting
/// opener.
fn run_context<'a>(
    opener: &'a CountingOpener,
    reporter: &'a mut Recorder,
) -> crate::pipeline::steps::RunContext<'a> {
    run_context_table(opener, reporter, None)
}

/// The one shared asset seeder lives in [`super::end_to_end`]:
/// every UEFI test below calls it there, so parallel threads stage
/// through unique temp names plus an atomic `rename` and never race
/// on the final asset bytes.
use crate::pipeline::bootloader::end_to_end::seed_exe_assets;

fn image_ref(path: &str, kind: rufus_proto::ImageKind) -> rufus_proto::ImageRef {
    rufus_proto::ImageRef {
        path: path.to_string(),
        size_bytes: 0,
        sha256: String::new(),
        kind,
    }
}

#[test]
fn run_refuses_a_non_fat32_filesystem_before_opening() {
    // exFAT with a bogus image path: the filesystem refusal lands
    // first, so `partition()` is never called.
    let partitions = Rc::new(Cell::new(0usize));
    let opener = CountingOpener {
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context(&opener, &mut reporter);
    let error = run(
        &mut ctx,
        &BootloaderMode::Syslinux,
        &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
        &rufus_proto::Filesystem::Exfat,
        None,
    )
    .expect_err("a non-fat32 plan refuses");
    let text = error.to_string();
    assert!(text.contains("exfat"), "names the filesystem: {text}");
    assert!(text.contains("FAT32"), "names the wired one: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(partitions.get(), 0, "the partition never opens");
}

// Arm internals the tests drive directly (private outside the
// bootloader module, visible to this descendant).
use super::uefi_ntfs::install_uefi_ntfs;
use crate::boot::syslinux as boot_syslinux;
use crate::boot::uefi_ntfs as boot_uefi_ntfs;

mod dos;
mod grub;
mod run;
mod syslinux;
mod uefi;
mod windows;
