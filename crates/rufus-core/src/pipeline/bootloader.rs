//! The bootloader step: Syslinux installation from the image tree.
//!
//! What is wired today: Syslinux only, FAT32 only. `Auto` behaves
//! exactly like an explicit `Syslinux` request — a tree without
//! Syslinux payloads refuses, and GRUB/GRUB4DOS/UEFI auto-detection is
//! a later slice. The other [`BootloaderMode`]s refuse as not
//! implemented, each naming its mode.
//!
//! The obsolete-module replacement ([`Obsolete`](crate::boot::syslinux::Obsolete))
//! is deliberately not applied here: no newer module bytes are
//! bundled, so there is nothing honest to substitute with — declared
//! gap, same as the copy wiring leaves it.
//!
//! Order inside [`install_tree`] (a correctness requirement mirroring
//! slice 3's "boot code last" invariant): companions first, then the
//! generated config, then the boot record via
//! [`install_loader`](crate::boot::syslinux::install_loader) last,
//! then one flush. A refused or failed config never leaves a boot
//! record behind, and a refused boot record never lands without its
//! companions.

use std::path::Path;

use rufus_proto::BootloaderMode;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;

use crate::boot::Payload;
use crate::boot::Resource;
use crate::boot::syslinux;
use crate::boot::syslinux::Family;
use crate::copy::IsoSource;
use crate::copy::Source as TreeSource;
use crate::copy::UdfSource;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::FileVolume;
use crate::fs::fat32::Fat32;
use crate::iso::IsoReader;
use crate::pipeline::event::Event;
use crate::pipeline::steps::RunContext;
use crate::report::syslinux_banner;
use crate::udf::UdfReader;

/// Refuse every [`BootloaderMode`] with no wired installer, naming
/// the mode: one table shared by [`install_tree`] and [`run`], so an
/// unwired mode never reaches the image or the device through either
/// entry point.
fn check_mode(mode: &BootloaderMode) -> Result<()> {
    match mode {
        BootloaderMode::None | BootloaderMode::Syslinux | BootloaderMode::Auto => Ok(()),
        BootloaderMode::Grub2 => Err(CoreError::NotImplemented {
            what: "grub2 bootloader installation (wired in a later slice)",
        }),
        BootloaderMode::Grub4dos => Err(CoreError::NotImplemented {
            what: "grub4dos bootloader installation (wired in a later slice)",
        }),
        BootloaderMode::UefiNtfs => Err(CoreError::NotImplemented {
            what: "uefi_ntfs bootloader installation (wired in a later slice)",
        }),
        BootloaderMode::Freedos => Err(CoreError::NotImplemented {
            what: "freedos bootloader installation (wired in a later slice)",
        }),
    }
}

/// What [`install_tree`] installed: the family and directory, the
/// stage size, the companions written, the config path, and every log
/// line the run reports, in reference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installed {
    family: Option<Family>,
    dir: String,
    stage_bytes: u64,
    companions: Vec<String>,
    config_path: String,
    messages: Vec<String>,
}

impl Installed {
    /// The installed family (`None` when `mode` was `None` and
    /// nothing was written).
    #[must_use]
    pub fn family(&self) -> Option<Family> {
        self.family
    }

    /// Located payload directory in display form (`/isolinux`, or `/`
    /// for a root payload; empty when skipped).
    #[must_use]
    pub fn dir(&self) -> &str {
        &self.dir
    }

    /// Stage-file byte count (`0` when skipped).
    #[must_use]
    pub fn stage_bytes(&self) -> u64 {
        self.stage_bytes
    }

    /// Companion names written, in install order.
    #[must_use]
    pub fn companions(&self) -> &[String] {
        &self.companions
    }

    /// Config path written (`/syslinux.cfg`; empty when skipped).
    #[must_use]
    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    /// Log lines in reference order: selection, located directory,
    /// then companion cautions.
    #[must_use]
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

/// Install the bootloader `mode` from the image `source` onto `fat`.
///
/// Pure core over explicit inputs (no `RunContext`), so unit tests
/// drive it against an in-memory FAT32 and a fixture source. `load`
/// resolves the embedded payloads (production passes
/// [`crate::boot::load`]; tests pass a `load_from` closure over the
/// asset tree, since `load` needs the runtime asset directory), and
/// `cancelled` is polled before the first write and before the boot
/// record.
///
/// `None` writes nothing and returns the skipped result — the correct
/// mode for a `Dd` plan, whose image boot code already landed
/// verbatim. `Syslinux` and `Auto` run the Syslinux install; every
/// other mode refuses as not implemented, naming itself.
pub(crate) fn install_tree(
    source: &dyn TreeSource,
    fat: &mut Fat32,
    mode: &BootloaderMode,
    cancelled: &dyn Fn() -> bool,
    load: &dyn Fn(Resource) -> Result<Payload>,
) -> Result<Installed> {
    const SKIPPED: Installed = Installed {
        family: None,
        dir: String::new(),
        stage_bytes: 0,
        companions: Vec::new(),
        config_path: String::new(),
        messages: Vec::new(),
    };
    match mode {
        BootloaderMode::None => return Ok(SKIPPED),
        _ => check_mode(mode)?,
    }
    let Some(located) = syslinux::locate(source)? else {
        return Err(CoreError::invalid(
            "no syslinux payloads found in the image: refusing a syslinux install (grub, grub4dos and uefi auto-detection arrive in a later slice)",
        ));
    };
    // Banner scan over the well-known loader names in the located
    // directory, first hit with a parseable banner wins. Three
    // explicit reads is cheap (absent names return `None` without
    // I/O past the listing) and honest: nothing outside this
    // directory is consulted.
    let mut detected = None;
    for name in ["isolinux.bin", "syslinux.bin", "ldlinux.bin"] {
        let Some(bytes) = syslinux::read(source, located.dir(), name)? else {
            continue;
        };
        if let Some(version) = syslinux_banner(&bytes) {
            detected = Some(syslinux::Detected {
                version,
                source: format!("{}/{}", located.path(), name),
            });
            break;
        }
    }
    let inventory = syslinux::inventory(source, located.dir())?;
    let has_ldlinux_c32 = inventory.present().contains(&"ldlinux.c32");
    let selection = syslinux::select(detected, has_ldlinux_c32);
    let missing = inventory.required_missing(selection.family());
    if !missing.is_empty() {
        return Err(CoreError::invalid(format!(
            "syslinux {} install needs {} but the image lacks it: refusing before any write",
            selection.family().version(),
            missing.join(", "),
        )));
    }
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let target = located.path();
    let placed = syslinux::install_companions(fat, source, located.dir(), &target)?;
    // The wrapper chains back to the image's own config: prefer the
    // config file the directory actually holds, defaulting to the
    // conventional name when neither is there.
    let cfg_name = if syslinux::read(source, located.dir(), "isolinux.cfg")?.is_some() {
        "isolinux.cfg"
    } else if syslinux::read(source, located.dir(), "syslinux.cfg")?.is_some() {
        "syslinux.cfg"
    } else {
        "isolinux.cfg"
    };
    let config_path = if target == "/" {
        format!("/{cfg_name}")
    } else {
        format!("{target}/{cfg_name}")
    };
    let text = syslinux::config_text(config_path.as_bytes())?;
    syslinux::write_config(fat, &text)?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let loader = syslinux::install_payloads_from(fat, selection.family(), load)?;
    let mut messages: Vec<String> = Vec::new();
    messages.extend(selection.messages().iter().cloned());
    messages.extend(located.messages().iter().cloned());
    messages.extend(placed.cautions.iter().cloned());
    Ok(Installed {
        family: Some(selection.family()),
        dir: target,
        stage_bytes: loader.stage_bytes(),
        companions: placed.written,
        config_path: "/syslinux.cfg".to_string(),
        messages,
    })
}

/// Filesystem name in plan vocabulary (`fat32`, `exfat`, ...).
fn filesystem_name(filesystem: &Filesystem) -> &'static str {
    match filesystem {
        Filesystem::Fat32 => "fat32",
        Filesystem::Exfat => "exfat",
        Filesystem::Ntfs => "ntfs",
        Filesystem::Ext2 => "ext2",
        Filesystem::Ext3 => "ext3",
        Filesystem::Ext4 => "ext4",
        Filesystem::Udf => "udf",
    }
}

/// Run the bootloader step: Syslinux from the image tree onto the
/// freshly formatted data partition.
///
/// `None` reports one info line and writes nothing. Unwired modes
/// refuse up front through the shared [`check_mode`] table (they never
/// reach the image or the device), then non-FAT32 filesystems refuse
/// naming the plan filesystem, then the image tree opens exactly like
/// `write::run_copy` does. The partition opens next; a cancellation
/// check follows before the first write (no partial-cleanup machinery
/// is needed — the directory tree can be reformatted, so a torn step
/// reports and the next run starts clean), then the install, one
/// flush, and the run message.
pub(crate) fn run(
    ctx: &mut RunContext<'_>,
    mode: &BootloaderMode,
    image: &ImageRef,
    filesystem: &Filesystem,
) -> Result<()> {
    if *mode == BootloaderMode::None {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: "bootloader: none requested, leaving the image boot code untouched".to_string(),
        });
        return Ok(());
    }
    // Unwired installers never reach the image or the device: same
    // table as `install_tree` (see `check_mode`).
    check_mode(mode)?;
    // `write::refuse_unsupported_kind` stays private to write.rs and
    // that module is out of scope here, so this arm carries its own
    // Iso/Raw-only table with this note: only tree images can hold
    // Syslinux payloads, and every other kind names itself on refusal.
    match image.kind {
        ImageKind::Iso | ImageKind::Raw => {}
        ref other => {
            return Err(CoreError::invalid(format!(
                "bootloader refuses an image of kind '{other}': no tree reader takes it"
            )));
        }
    }
    if *filesystem != Filesystem::Fat32 {
        return Err(CoreError::invalid(format!(
            "bootloader installation needs a FAT32 volume, the plan carries {}: only FAT32 is wired",
            filesystem_name(filesystem)
        )));
    }
    let volume = FileVolume::open(Path::new(&image.path))?;
    let source: Box<dyn TreeSource> = match &image.kind {
        ImageKind::Iso => Box::new(IsoSource::new(IsoReader::open(Box::new(volume))?)),
        ImageKind::Raw => match UdfReader::open(Box::new(volume)) {
            Ok(reader) => Box::new(UdfSource::new(reader)),
            Err(udf_error) => {
                return Err(CoreError::invalid(format!(
                    "bootloader refuses a raw image: it is neither an ISO9660 nor a UDF tree (UDF open failed: {udf_error})"
                )));
            }
        },
        // Every other kind refused above; this names the kind rather
        // than assuming the match is exhaustive forever.
        other => {
            return Err(CoreError::invalid(format!(
                "bootloader refuses an image of kind '{other}': no tree reader takes it"
            )));
        }
    };
    let mut fat = Fat32::open(ctx.opener.partition()?)?;
    if (ctx.cancelled)() {
        return Err(CoreError::Cancelled);
    }
    let installed = install_tree(&*source, &mut fat, mode, ctx.cancelled, &crate::boot::load)?;
    fat.flush()?;
    for message in installed.messages() {
        ctx.reporter.event(Event::Message {
            level: "info",
            text: message.clone(),
        });
    }
    let family = installed
        .family()
        .map(|family| family.version())
        .unwrap_or("?");
    ctx.reporter.event(Event::Message {
        level: "info",
        text: format!(
            "installed {family} Syslinux into '{}' ({} companions, config {}, {} stage bytes)",
            installed.dir(),
            installed.companions().len(),
            installed.config_path(),
            installed.stage_bytes(),
        ),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::Resource;
    use crate::boot::load_from;
    use crate::copy::Entry;
    use crate::copy::Source;
    use crate::error::Result as TestResult;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::Cell;
    use std::cell::RefCell;
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

    #[test]
    fn syslinux_604_installs_stage_companions_and_config() {
        let (backing, mut fat) = formatted();
        let source = syslinux_604_tree();
        let installed = install_tree(
            &source,
            &mut fat,
            &BootloaderMode::Syslinux,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        assert_eq!(
            installed.family(),
            Some(Family::V604),
            "the 6.04 family wins"
        );
        assert_eq!(installed.dir(), "/isolinux", "the located directory");
        assert_eq!(
            installed.companions(),
            &[
                "ldlinux.c32".to_string(),
                "menu.c32".to_string(),
                "vesamenu.c32".to_string(),
                "libutil.c32".to_string(),
            ],
            "all four companions in order"
        );
        assert_eq!(installed.config_path(), "/syslinux.cfg", "the wrapper path");
        assert_eq!(
            installed.messages()[0],
            "  Detected Syslinux version: 6.04 (from '/isolinux/isolinux.bin')",
            "the detection line is verbatim"
        );
        assert_eq!(
            installed.messages()[1],
            "  Will use '/isolinux' for Syslinux",
            "the located line is verbatim"
        );
        assert!(
            installed.messages().iter().all(|line| line.is_ascii()),
            "every message stays ASCII"
        );
        // The wrapper chains back to the image's own config.
        let expected =
            syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
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
        let installed = install_tree(
            &source,
            &mut fat,
            &BootloaderMode::Syslinux,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
        assert_eq!(
            installed.family(),
            Some(Family::V407),
            "the 4.07 family wins"
        );
        assert_eq!(
            installed.messages()[0],
            "  Detected Syslinux version: 4.07 (from '/isolinux/isolinux.bin')",
            "the detection line is verbatim"
        );
        assert_eq!(
            installed.companions(),
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
            syslinux::config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
            "the wrapper chains to the held config"
        );
    }

    #[test]
    fn bannerless_tree_forces_the_family_from_the_library() {
        // No banner anywhere but `ldlinux.c32` present: the family is
        // forced to 6.04 with the reference warning line.
        let source = payload_tree(b"no banner here", &["isolinux.cfg", "ldlinux.c32"]);
        let (_backing, mut fat) = formatted();
        let installed = install_tree(
            &source,
            &mut fat,
            &BootloaderMode::Auto,
            &|| false,
            &asset_loader,
        )
        .expect("the forced install runs");
        assert_eq!(
            installed.family(),
            Some(Family::V604),
            "the library forces 6.04"
        );
        assert_eq!(
            installed.messages()[0],
            "  Warning: Could not detect Isolinux version - Forcing to 6.04 (embedded)",
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
        let error = install_tree(
            &source,
            &mut fat,
            &BootloaderMode::Syslinux,
            &|| false,
            &asset_loader,
        )
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
    fn bare_tree_refuses_with_the_later_slice_note() {
        // Nothing Syslinux-like anywhere: both modes refuse alike,
        // naming the gap instead of pretending GRUB support.
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", b"x")]);
        let source = source.with_file(&[b"a.txt"], b"x");
        for mode in [BootloaderMode::Syslinux, BootloaderMode::Auto] {
            let (_backing, mut fat) = formatted();
            let error = install_tree(&source, &mut fat, &mode, &|| false, &asset_loader)
                .expect_err("a bare tree refuses");
            let text = error.to_string();
            assert!(
                text.contains("no syslinux payloads"),
                "says what is missing: {text}"
            );
            assert!(text.contains("later slice"), "names the gap: {text}");
            assert!(text.is_ascii(), "stays ASCII: {text}");
        }
    }

    #[test]
    fn none_mode_writes_nothing() {
        let source = syslinux_604_tree();
        let (backing, mut fat) = formatted();
        let before = backing.bytes.borrow().clone();
        let installed = install_tree(
            &source,
            &mut fat,
            &BootloaderMode::None,
            &|| false,
            &asset_loader,
        )
        .expect("none always runs");
        assert_eq!(installed.family(), None, "no family for a skipped install");
        assert_eq!(installed.stage_bytes(), 0, "no stage for a skipped install");
        assert!(
            installed.companions().is_empty(),
            "no companions for a skipped install"
        );
        assert_eq!(
            backing.bytes.borrow().as_slice(),
            before.as_slice(),
            "no byte moved in 67108864 bytes of image"
        );
    }

    #[test]
    fn unimplemented_modes_name_themselves() {
        let source = syslinux_604_tree();
        for (mode, name) in [
            (BootloaderMode::Grub2, "grub2"),
            (BootloaderMode::Grub4dos, "grub4dos"),
            (BootloaderMode::UefiNtfs, "uefi_ntfs"),
            (BootloaderMode::Freedos, "freedos"),
        ] {
            let (_backing, mut fat) = formatted();
            let error = install_tree(&source, &mut fat, &mode, &|| false, &asset_loader)
                .expect_err("an unwired mode refuses");
            assert!(
                matches!(error, CoreError::NotImplemented { .. }),
                "a mode refusal is NotImplemented: {error:?}"
            );
            let text = error.to_string();
            assert!(text.contains(name), "names the mode: {text}");
            assert!(text.contains("later slice"), "names the gap: {text}");
        }
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

    /// A [`RunContext`](crate::pipeline::steps::RunContext) over the
    /// counting opener, for the `run` tests below.
    fn run_context<'a>(
        opener: &'a CountingOpener,
        reporter: &'a mut Recorder,
    ) -> crate::pipeline::steps::RunContext<'a> {
        crate::pipeline::steps::RunContext {
            opener,
            target: None,
            table: None,
            partitioned: false,
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
        )
        .expect_err("a non-fat32 plan refuses");
        let text = error.to_string();
        assert!(text.contains("exfat"), "names the filesystem: {text}");
        assert!(text.contains("FAT32"), "names the wired one: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(partitions.get(), 0, "the partition never opens");
    }

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
        )
        .expect("none always runs");
        assert_eq!(partitions.get(), 0, "the partition never opens");
        assert_eq!(reporter.events.len(), 1, "one info event at most");
    }

    #[test]
    fn run_unimplemented_mode_never_reaches_the_image() {
        let partitions = Rc::new(Cell::new(0usize));
        let opener = CountingOpener {
            partitions: Rc::clone(&partitions),
        };
        let mut reporter = Recorder::default();
        let mut ctx = run_context(&opener, &mut reporter);
        let error = run(
            &mut ctx,
            &BootloaderMode::Grub2,
            &image_ref("missing.iso", rufus_proto::ImageKind::Iso),
            &rufus_proto::Filesystem::Fat32,
        )
        .expect_err("grub2 is not wired");
        assert!(
            matches!(error, CoreError::NotImplemented { .. }),
            "a mode refusal is NotImplemented: {error:?}"
        );
        assert_eq!(partitions.get(), 0, "the partition never opens");
    }

    #[test]
    fn installed_image_is_fsck_clean() {
        let (backing, mut fat) = formatted();
        let source = syslinux_604_tree();
        install_tree(
            &source,
            &mut fat,
            &BootloaderMode::Syslinux,
            &|| false,
            &asset_loader,
        )
        .expect("the install runs");
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
}
