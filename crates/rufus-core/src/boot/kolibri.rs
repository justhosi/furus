//! KolibriOS loader placement: the `MTLD_F32` file at the volume root.
//!
//! Reference behaviour, verified in the binary (the PLAN's "write
//! `HD_Load/USB_Boot/MTLD_F32` as the boot record" wording is wrong):
//! `0x140011ac0` logs `Installing: %s (KolibriOS loader)` and calls
//! the copy helper `0x14001e450`, which copies
//! `HD_Load/USB_Boot/MTLD_F32` (source string at file offset `0x1531f0`
//! of the unpacked exe) out of the ISO9660 or UDF tree to the target
//! file `?:\MTLD_F32` (destination string at `0x152a28`). On failure
//! the reference logs `WARNING: Loader installation failed -
//! KolibriOS will not boot!` (at `0x153210`) and the run continues —
//! Rufus does not abort the write. The `DAT_140218339` flag guarding
//! that block is set when the image root holds `kolibri.img`
//! (`0x140017f40.c:395-400`): flag and loader always go together.
//!
//! The partition's boot record is *not* the standard FAT32 one on a
//! KolibriOS stick: `0x140010320.c:112-131` calls `FUN_140075d80` in
//! the FAT32 case when the KolibriOS flag is set, and only the
//! non-KolibriOS case gets the standard FAT32 record (`FUN_140072d20`;
//! `FUN_14007ba60` is the FAT16 standard record). `FUN_140075d80`
//! writes a 512-byte VBR — 11 bytes at offset 0, 11 at `0x47`, `0x1ae`
//! at `0x52`, `0xaa55` at the tail — whose embedded boot code carries
//! the strings `Cannot find file MTLD_F32` and `Bad cluster`: a
//! KolibriOS stick needs both that record and this file. FAT16 is
//! refused outright with `FAT16 is not supported for KolibriOS`
//! (`0x140010320.c:69-72`), and the reference writes `0x80` at `0x24`
//! (FAT16) / `0x40` (FAT32) of sector 0 of the volume — the `BS_DrvNum`
//! field, not the MBR partition-entry active flag.
//!
//! That record lives in this project now: [`install_boot_record`]
//! writes the [`records`](super::records) transcription of the
//! `FUN_140075d80` payload through the BPB-preserving graft, so a
//! stick from this slice carries both the loader and its boot record.
//! Two honest notes stay. First, the graft keeps the volume's own
//! `0x0B..0x5A` BPB window, so the volume label is preserved rather
//! than replaced with the reference's `NO NAME    `. Second, the
//! reference writes nothing past sector 0 for this record (unlike the
//! FreeDOS one, which also touches sectors 1-2 — see
//! [`freedos`](super::freedos)), while this crate additionally mirrors
//! the grafted record into the FAT32 backup boot sector (sector 6),
//! matching `WritePBR`'s two-pass loop (`src/format.c`): without the
//! mirror `fsck.fat` reports differences between the boot sector and
//! its backup. [`locate`] finds the loader in the
//! image and [`install_loader`] writes it at the volume root. Nothing
//! here flushes: the caller owns the flush, the same convention as
//! [`install_companions`](super::syslinux::install_companions) and
//! [`install_payloads`](super::syslinux::install_payloads).

use super::records;
use super::syslinux::read_capped;
use crate::copy::Source;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;

/// First source directory component of the loader path in the image
/// (`HD_Load` of the reference's `HD_Load/USB_Boot/MTLD_F32`, source
/// string at file offset `0x1531f0` of the unpacked exe). Directory
/// resolve exactly — the ISO and UDF adapters match each component
/// byte for byte — so an upper-case `HD_LOAD` directory never finds
/// the loader.
pub const DIR_HD_LOAD: &[u8] = b"HD_Load";

/// Second source directory component of the loader path in the image
/// (`USB_Boot` of `HD_Load/USB_Boot/MTLD_F32`). Resolves exactly like
/// [`DIR_HD_LOAD`].
pub const DIR_USB_BOOT: &[u8] = b"USB_Boot";

/// Loader file name in the source tree and at the volume root
/// (`MTLD_F32`, destination `?:\MTLD_F32` at file offset `0x152a28`).
/// Only the name folds ASCII case on lookup (image trees commonly
/// spell names in upper case), like `syslinux::locate`'s marker
/// names; the directory components never do.
pub const LOADER_NAME: &str = "MTLD_F32";

/// Destination path of the loader on the volume: the volume root, the
/// `?:\MTLD_F32` target the reference copies to.
pub const DEST_PATH: &str = "/MTLD_F32";

/// Read cap for the loader in bytes (1 MiB): the real `MTLD_F32` is on
/// the order of tens of KiB, so 1 MiB holds any real loader with room
/// to spare while matching the 1 MiB ceiling the syslinux reader uses
/// for its own scans — a hostile image still cannot make this module
/// buffer a crafted multi-gigabyte file.
pub const MAX_LOADER_BYTES: u64 = 1024 * 1024;

/// A located KolibriOS loader: the directory stack it was read from
/// plus the loader bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    dir: Vec<Vec<u8>>,
    bytes: Vec<u8>,
}

impl Located {
    /// Directory stack as name bytes from the source root.
    #[must_use]
    pub fn dir(&self) -> &[Vec<u8>] {
        &self.dir
    }

    /// `/`-joined display form plus the file name
    /// (`/HD_Load/USB_Boot/MTLD_F32`): bytes outside printable ASCII
    /// (`0x20..=0x7E`) become `?`, so the log line stays ASCII
    /// whatever the image names hold — the same shape as
    /// `syslinux::Located::path`.
    #[must_use]
    pub fn path(&self) -> String {
        let mut out = String::new();
        for component in self.dir.iter() {
            out.push('/');
            for byte in component.iter() {
                if (0x20..=0x7E).contains(byte) {
                    out.push(*byte as char);
                } else {
                    out.push('?');
                }
            }
        }
        out.push('/');
        out.push_str(LOADER_NAME);
        out
    }

    /// The loader bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Find the KolibriOS loader over a [`Source`]: the exact
/// `HD_Load/USB_Boot` directory holding a readable `MTLD_F32`.
///
/// The directory stack resolves exactly (a file named `HD_Load`, or
/// an upper-case `HD_LOAD` directory, never lists), while the file
/// name folds ASCII case through
/// [`read_capped`](super::syslinux::read_capped) at
/// [`MAX_LOADER_BYTES`] — symlinks and directories of that name read
/// as absent. A listing error that is a real I/O error
/// ([`CoreError::Io`]) propagates; any other listing refusal is a
/// no-match. Returns `None` when the tree holds no readable loader.
pub fn locate(source: &dyn Source) -> Result<Option<Located>> {
    let dir = vec![DIR_HD_LOAD.to_vec(), DIR_USB_BOOT.to_vec()];
    // A successful listing is what proves the exact directory exists:
    // the adapters refuse a child listing under a plain file, so a
    // file in either directory slot reads as no match here.
    if let Err(error) = source.child_entries(&dir) {
        if matches!(error, CoreError::Io { .. }) {
            return Err(error);
        }
        return Ok(None);
    }
    let Some(bytes) = read_capped(source, &dir, LOADER_NAME, MAX_LOADER_BYTES)? else {
        return Ok(None);
    };
    Ok(Some(Located { dir, bytes }))
}

/// What [`install_loader`] did: the loader byte count and whether the
/// file was already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    bytes: u64,
    kept: bool,
}

impl Installed {
    /// Bytes of the loader at [`DEST_PATH`].
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// True when `/MTLD_F32` already held byte-identical content: the
    /// copy step legitimately places it first by walking the whole
    /// tree, so an identical file is the expected state and nothing
    /// was written.
    #[must_use]
    pub fn kept(&self) -> bool {
        self.kept
    }
}

/// Write the `loader` bytes at the volume root as `/MTLD_F32`.
///
/// Follows [`install_companions`](super::syslinux::install_companions)'
/// policy exactly: an existing `/MTLD_F32` counts as kept — and
/// nothing is written — when its bytes equal the image's copy;
/// differing bytes refuse naming the file, since silently keeping a
/// foreign loader would boot it. Absent means `create_file` plus a
/// zero-offset `write_at`. Refuses an empty loader naming `0 bytes`.
/// Does not flush: the caller owns the flush.
pub fn install_loader(fat: &mut Fat32, loader: &[u8]) -> Result<Installed> {
    if loader.is_empty() {
        return Err(CoreError::invalid(
            "kolibri loader is empty (0 bytes): refusing".to_string(),
        ));
    }
    let bytes = u64::try_from(loader.len()).map_err(|_| {
        CoreError::invalid("a kolibri loader longer than u64: refusing".to_string())
    })?;
    let already = fat.list_dir("/")?.iter().any(|entry| {
        entry.name.eq_ignore_ascii_case(LOADER_NAME)
            || entry.short_name.eq_ignore_ascii_case(LOADER_NAME)
    });
    if already {
        let back = fat.read_file(DEST_PATH)?;
        if back.as_slice() == loader {
            return Ok(Installed { bytes, kept: true });
        }
        return Err(CoreError::invalid(format!(
            "kolibri loader '{LOADER_NAME}' already present at '/' differs from the image's copy: refusing to overwrite it"
        )));
    }
    fat.create_file(DEST_PATH, bytes)?;
    fat.write_at(DEST_PATH, 0, loader)?;
    Ok(Installed { bytes, kept: false })
}

/// Write the KolibriOS FAT32 boot record onto the volume's boot
/// sector: the `FUN_140075d80` payload as transcribed in
/// [`records`](super::records) (head at `0x0`, the `MTLD_F32` boot
/// code at `0x52`, `55 AA` at `0x1FE`).
///
/// Goes through the BPB-preserving graft
/// ([`records::write`](super::records::write)): the record's entry
/// and code win, the volume's own `0x0B..0x5A` geometry — volume
/// label included — survives, the grafted record is mirrored into the
/// FAT32 backup boot sector (sector 6, matching `WritePBR`'s two-pass
/// loop in `src/format.c`), and sectors 1 and 2 are untouched. Does
/// not flush: the caller owns the flush.
pub fn install_boot_record(fat: &mut Fat32) -> Result<()> {
    records::write(fat, &records::kolibri_fat32())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::Entry;
    use crate::error::Result as TestResult;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// In-memory [`Source`] over explicit listings and file bytes, the
    /// same pattern the `syslinux` tests use: directories keyed by
    /// component path, files keyed by full path, symlinks listable.
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

    fn file_entry(name: &[u8], size: u64) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: false,
            size,
            mode: None,
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
            mode: None,
            modified: None,
            accessed: None,
            link: None,
        }
    }

    fn link_entry(name: &[u8]) -> Entry {
        Entry {
            name: name.to_vec(),
            is_dir: false,
            size: 0,
            mode: None,
            modified: None,
            accessed: None,
            link: Some(b"target".to_vec()),
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

    /// Synthetic loader bytes (48 KiB of distinct bytes): a stand-in
    /// with a realistic size — the real `MTLD_F32` is on the order of
    /// tens of KiB — not a KolibriOS payload, and big enough to span
    /// twelve 4 KiB read windows.
    fn loader_bytes() -> Vec<u8> {
        (0..48 * 1024)
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
                vec![file_entry(b"MTLD_F32", loader.len() as u64)],
            )
            .with_file(&[b"HD_Load", b"USB_Boot", b"MTLD_F32"], loader)
    }

    #[test]
    fn constants_pin_the_reference_strings() {
        assert_eq!(DIR_HD_LOAD, b"HD_Load", "the top directory");
        assert_eq!(DIR_USB_BOOT, b"USB_Boot", "the inner directory");
        assert_eq!(LOADER_NAME, "MTLD_F32", "the loader name");
        assert_eq!(DEST_PATH, "/MTLD_F32", "the volume-root destination");
        assert_eq!(
            MAX_LOADER_BYTES, 1_048_576,
            "the cap is 1 MiB, room for a tens-of-KiB loader"
        );
    }

    #[test]
    fn locate_finds_the_exact_tree() {
        let loader = loader_bytes();
        let found = locate(&kolibri_tree(&loader))
            .expect("the lookup reads")
            .expect("the exact tree locates");
        assert_eq!(
            found.dir(),
            &[b"HD_Load".to_vec(), b"USB_Boot".to_vec()],
            "the directory stack resolves"
        );
        assert_eq!(found.path(), "/HD_Load/USB_Boot/MTLD_F32");
        assert!(found.path().is_ascii(), "the log path stays ASCII");
        assert_eq!(found.bytes(), &loader, "the bytes return whole");
    }

    #[test]
    fn locate_returns_none_without_the_tree() {
        // A bare tree holds nothing.
        let bare = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", 1)]);
        assert!(
            locate(&bare).expect("the lookup reads").is_none(),
            "a bare tree reads as none"
        );
        // The top directory without the inner one is no match.
        let half = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_Load")])
            .with_dir(&[b"HD_Load"], vec![file_entry(b"other.txt", 1)]);
        assert!(
            locate(&half).expect("the lookup reads").is_none(),
            "a missing USB_Boot reads as none"
        );
        // Both directories without the file is no match.
        let no_file = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_Load")])
            .with_dir(&[b"HD_Load"], vec![dir_entry(b"USB_Boot")])
            .with_dir(
                &[b"HD_Load", b"USB_Boot"],
                vec![file_entry(b"other.txt", 1)],
            );
        assert!(
            locate(&no_file).expect("the lookup reads").is_none(),
            "a missing MTLD_F32 reads as none"
        );
    }

    #[test]
    fn locate_ignores_a_file_named_hd_load() {
        // A plain file named `HD_Load` at the root is not a directory:
        // the child listing under it refuses, which reads as no match.
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"HD_Load", 5)]);
        assert!(
            locate(&source).expect("the lookup reads").is_none(),
            "a file of that name never counts"
        );
    }

    #[test]
    fn locate_resolves_directories_exactly_but_folds_the_file_name() {
        // An upper-case `HD_LOAD` directory never matches: directory
        // components resolve exactly.
        let upper = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_LOAD")])
            .with_dir(&[b"HD_LOAD"], vec![dir_entry(b"USB_Boot")])
            .with_dir(&[b"HD_LOAD", b"USB_Boot"], vec![file_entry(b"MTLD_F32", 4)])
            .with_file(&[b"HD_LOAD", b"USB_Boot", b"MTLD_F32"], b"up!!");
        assert!(
            locate(&upper).expect("the lookup reads").is_none(),
            "an upper-case directory never locates"
        );
        // A lower-case file name still matches: only the name folds.
        let loader = loader_bytes();
        let lower = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_Load")])
            .with_dir(&[b"HD_Load"], vec![dir_entry(b"USB_Boot")])
            .with_dir(
                &[b"HD_Load", b"USB_Boot"],
                vec![file_entry(b"mtld_f32", loader.len() as u64)],
            )
            .with_file(&[b"HD_Load", b"USB_Boot", b"MTLD_F32"], &loader);
        let found = locate(&lower)
            .expect("the lookup reads")
            .expect("a folded name locates");
        assert_eq!(found.bytes(), &loader, "the folded bytes return");
    }

    #[test]
    fn locate_ignores_a_symlinked_loader() {
        // A symlink named `MTLD_F32` reads as absent, so the lookup
        // finds nothing even though the directories resolve.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"HD_Load")])
            .with_dir(&[b"HD_Load"], vec![dir_entry(b"USB_Boot")])
            .with_dir(&[b"HD_Load", b"USB_Boot"], vec![link_entry(b"MTLD_F32")]);
        assert!(
            locate(&source).expect("the lookup reads").is_none(),
            "a symlinked loader never locates"
        );
    }

    #[test]
    fn locate_propagates_a_real_listing_error() {
        // An I/O listing error is not a no-match: it propagates, the
        // way the syslinux lookup treats `CoreError::Io`.
        struct IoSource;
        impl Source for IoSource {
            fn root_entries(&self) -> TestResult<Vec<Entry>> {
                Err(CoreError::io(
                    std::path::Path::new("/test"),
                    std::io::Error::other("test io"),
                ))
            }
            fn child_entries(&self, _dir: &[Vec<u8>]) -> TestResult<Vec<Entry>> {
                Err(CoreError::io(
                    std::path::Path::new("/test"),
                    std::io::Error::other("test io"),
                ))
            }
            fn read_bytes(
                &self,
                _file: &[Vec<u8>],
                _offset: u64,
                _buf: &mut [u8],
            ) -> TestResult<usize> {
                Err(CoreError::invalid("unreachable".to_string()))
            }
        }
        let error = locate(&IoSource).expect_err("an I/O listing error propagates");
        assert!(
            matches!(error, CoreError::Io { .. }),
            "the I/O error keeps its shape: {error}"
        );
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
            let end = start.checked_add(buf.len()).expect("the test write fits");
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
    fn install_loader_writes_and_round_trips() {
        let (_backing, mut fat) = formatted();
        let loader = loader_bytes();
        let done = install_loader(&mut fat, &loader).expect("the install runs");
        assert_eq!(
            done.bytes(),
            loader.len() as u64,
            "the report counts the loader bytes"
        );
        assert!(!done.kept(), "a fresh write is not kept");
        let root = fat.list_dir("/").expect("the root lists");
        assert!(
            root.iter().any(|entry| entry.short_name == "MTLD_F32"),
            "MTLD_F32 is listed among {:?}",
            root.iter()
                .map(|entry| &entry.short_name)
                .collect::<Vec<_>>()
        );
        let back = fat.read_file("/MTLD_F32").expect("the loader reads back");
        assert_eq!(back, loader, "the loader is byte-identical");
    }

    #[test]
    fn install_loader_keeps_identical_bytes() {
        // A second install over identical bytes keeps them: the copy
        // step legitimately places the file first, so nothing writes.
        let (_backing, mut fat) = formatted();
        let loader = loader_bytes();
        install_loader(&mut fat, &loader).expect("the first install runs");
        let again = install_loader(&mut fat, &loader).expect("identical bytes are kept");
        assert!(again.kept(), "the second install reports kept");
        assert_eq!(
            again.bytes(),
            loader.len() as u64,
            "the kept report still counts the bytes"
        );
        let back = fat
            .read_file("/MTLD_F32")
            .expect("the kept file reads back");
        assert_eq!(back, loader, "kept bytes unchanged");
    }

    #[test]
    fn install_loader_refuses_differing_bytes() {
        // A foreign `/MTLD_F32` refuses naming the file and stays
        // untouched — keeping it would boot a foreign loader.
        let (_backing, mut fat) = formatted();
        let loader = loader_bytes();
        let foreign = b"foreign-loader-bytes".to_vec();
        fat.create_file("/MTLD_F32", foreign.len() as u64)
            .expect("a foreign file lands first");
        fat.write_at("/MTLD_F32", 0, &foreign)
            .expect("the foreign write lands");
        let error = install_loader(&mut fat, &loader).expect_err("differing bytes refuse");
        let text = error.to_string();
        assert!(text.contains("MTLD_F32"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let back = fat.read_file("/MTLD_F32").expect("the file still reads");
        assert_eq!(back, foreign, "foreign bytes untouched");
    }

    #[test]
    fn install_loader_refuses_a_directory_in_the_slot() {
        // A directory named `MTLD_F32` at the root is not a loader to
        // compare against: the install refuses (naming the path) and
        // writes nothing — the directory stays a directory.
        let (_backing, mut fat) = formatted();
        let loader = loader_bytes();
        fat.mkdir("/MTLD_F32").expect("a directory lands first");
        let error = install_loader(&mut fat, &loader).expect_err("a directory refuses");
        let text = error.to_string();
        assert!(text.contains("MTLD_F32"), "names the path: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let root = fat.list_dir("/").expect("the root lists");
        assert_eq!(root.len(), 1, "nothing was written beside the directory");
        let back = fat
            .read_file("/MTLD_F32")
            .expect_err("the slot is still a directory");
        assert!(
            back.to_string().contains("MTLD_F32"),
            "the directory refusal names the path: {back}"
        );
    }

    #[test]
    fn install_loader_refuses_an_empty_loader() {
        let (_backing, mut fat) = formatted();
        let error = install_loader(&mut fat, &[]).expect_err("an empty loader refuses");
        let text = error.to_string();
        assert!(text.contains("0 bytes"), "names the empty length: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let root = fat.list_dir("/").expect("the root lists");
        assert!(
            root.iter()
                .all(|entry| !entry.short_name.eq_ignore_ascii_case("MTLD_F32")),
            "no loader file was created"
        );
    }

    #[test]
    fn installed_image_is_fsck_clean() {
        // Acceptance over the real checker: the image dumps to a
        // tempfile and `fsck.fat -n` (read-only) must exit 0. The tool
        // resolves through `PATH`; when it is absent the test skips.
        // No flush inside `install_loader` itself: the caller-side
        // flush below publishes the allocation to the image.
        let (backing, mut fat) = formatted();
        let loader = loader_bytes();
        install_loader(&mut fat, &loader).expect("the install runs");
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("kolibri.img");
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
            "fsck.fat -n exits 0 after the loader write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }

    /// A copy of one 512-byte sector of the image under test.
    fn sector(backing: &SharedVolume, index: usize) -> [u8; 512] {
        let borrowed = backing.bytes.borrow();
        let start = index.checked_mul(512).expect("the test offset fits");
        let window = borrowed
            .get(start..start + 512)
            .expect("the test sector fits");
        let mut sector = [0u8; 512];
        sector.copy_from_slice(window);
        sector
    }

    #[test]
    fn install_boot_record_writes_the_kolibri_sector() {
        // The record proof on a real 64 MiB image: the payload head
        // and code land through the graft, the whole `0x0B..0x5A` BPB
        // window (label included) survives byte-identical — the graft
        // takes only the record's `0x00..0x0B` entry and `0x5A..0x1FE`
        // code, so the payload legitimately owns exactly those two
        // windows — the `55 AA` tail closes the sector, the grafted
        // record is mirrored byte-identical into the backup boot sector
        // (sector 6, matching `WritePBR`'s two-pass loop in
        // `src/format.c`), sectors 1 (FSInfo) through 5 are
        // byte-identical to before the call, a second write changes
        // nothing, and the jump really moved off the formatter's own
        // `EB 3C 90` (the OEM name is `MSWIN4.1` on both sides, so the
        // jump — not the OEM — is the discriminator). The dumped image
        // is `fsck.fat` clean with no boot/backup difference; the tool
        // resolves through `PATH` and the test skips when absent.
        let (backing, mut fat) = formatted();
        fat.flush().expect("the pre-write flush runs");
        let before = sector(&backing, 0);
        let before_fsinfo = sector(&backing, 1);
        let before_second = sector(&backing, 2);
        let before_mid: Vec<[u8; 512]> = (3..6).map(|index| sector(&backing, index)).collect();
        install_boot_record(&mut fat).expect("the record writes");
        let record = crate::boot::records::kolibri_fat32();
        let after = sector(&backing, 0);
        assert_eq!(
            &after[0..11],
            &record[0..11],
            "the payload jump and oem name win"
        );
        assert_eq!(
            &after[11..90],
            &before[11..90],
            "the graft keeps the whole bpb window, label included"
        );
        assert_eq!(
            &after[90..510],
            &record[90..510],
            "the boot code is the payload's"
        );
        assert_eq!(
            &after[510..512],
            &[0x55, 0xAA],
            "the signature closes the sector"
        );
        assert_eq!(
            sector(&backing, 6),
            after,
            "the backup boot sector mirrors the primary"
        );
        assert_eq!(
            sector(&backing, 1),
            before_fsinfo,
            "the write preserves the fsinfo sector"
        );
        assert_eq!(
            sector(&backing, 2),
            before_second,
            "the write preserves sector 2"
        );
        for (position, want) in before_mid.iter().enumerate() {
            let index = position + 3;
            assert_eq!(
                &sector(&backing, index),
                want,
                "the write preserves sector {index}"
            );
        }
        assert_eq!(
            &before[0..3],
            &[0xEB, 0x3C, 0x90],
            "the formatter's own jump"
        );
        assert_eq!(
            &after[0..3],
            &[0xEB, 0x58, 0x90],
            "the payload jump replaces it"
        );
        install_boot_record(&mut fat).expect("the second write runs");
        assert_eq!(sector(&backing, 0), after, "a second write changes nothing");
        assert_eq!(
            sector(&backing, 6),
            after,
            "a second write keeps the backup mirrored"
        );
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("kolibri-record.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = match std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg("-v")
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
            !format!("{stdout}\n{stderr}")
                .contains("differences between boot sector and its backup"),
            "fsck.fat -v reports no boot/backup difference after the record write: stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the record write ({}): stdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
    }
}
