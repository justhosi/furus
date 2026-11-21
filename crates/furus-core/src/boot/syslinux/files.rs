//! Syslinux companion files and the `syslinux.cfg` wrapper.
//!
//! The stage file alone does not boot an ISO's menu: the payload
//! directory's companions (`ldlinux.c32` and friends) must land next
//! to it, and when the target has no `syslinux.cfg` upstream generates
//! a wrapper that chains back to the ISO's own config. [`inventory`]
//! reports which companions a source tree holds, [`install_companions`]
//! copies the present ones onto the volume, and [`config_text`] /
//! [`write_config`] build and lay down the wrapper. Nothing here
//! flushes: the caller owns the flush, the same convention as
//! [`install_payloads`](super::install_payloads).

use crate::copy::Source;
use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::Fat32;

use super::Family;
use super::read;

/// Companion modules a Syslinux payload directory may carry, in
/// upstream's install order.
pub const COMPANIONS: [&str; 4] = ["ldlinux.c32", "menu.c32", "vesamenu.c32", "libutil.c32"];

/// What each [`COMPANIONS`] entry is and whether the install requires
/// it: `ldlinux.c32` is the 6.04 core library every 6.04 config needs
/// (required for 6.04, optional for 4.07 — that is why slice 2 warns on
/// its absence under a 6.04 banner); `menu.c32` and `vesamenu.c32` are
/// the text and graphical menu modules (optional, and the only two
/// modules the obsolete-replacement policy ever substitutes); and
/// `libutil.c32` is the runtime library both menus need (optional on
/// its own, required in practice whenever a menu ships).
pub const COMPANION_REQUIRED_604: &str = "ldlinux.c32";

/// The caution upstream logs per missing companion
/// (`0x140054f60:488`), verbatim.
pub fn caution_for(name: &str) -> String {
    format!(
        "Caution: No '{name}' was provided. The target will be missing a required Syslinux file!"
    )
}

/// Which of [`COMPANIONS`] a source tree holds in the located payload
/// directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    present: Vec<&'static str>,
    missing: Vec<&'static str>,
}

/// Triage one payload directory: for every [`COMPANIONS`] name, read
/// it through [`read`] (case-insensitive name match; a symlink of that
/// name reads as absent) and sort it into present or missing. A real
/// listing I/O error propagates; any other listing refusal reads as
/// absent, exactly like [`read`] treats it.
pub fn inventory(source: &dyn Source, dir: &[Vec<u8>]) -> Result<Inventory> {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for name in COMPANIONS {
        match read(source, dir, name)? {
            Some(_) => present.push(name),
            None => missing.push(name),
        }
    }
    Ok(Inventory { present, missing })
}

impl Inventory {
    /// Companion names the source tree holds.
    #[must_use]
    pub fn present(&self) -> &[&'static str] {
        &self.present
    }

    /// Companion names the source tree lacks.
    #[must_use]
    pub fn missing(&self) -> &[&'static str] {
        &self.missing
    }

    /// One [`caution_for`] line per missing name, in [`COMPANIONS`]
    /// order.
    #[must_use]
    pub fn cautions(&self) -> Vec<String> {
        self.missing.iter().map(|name| caution_for(name)).collect()
    }

    /// Required-but-missing companions for `family`: 6.04 needs
    /// `ldlinux.c32`, 4.07 needs none of the four (its core has no
    /// `.c32` dependency).
    #[must_use]
    pub fn required_missing(&self, family: Family) -> Vec<&'static str> {
        match family {
            Family::V604 => self
                .missing
                .iter()
                .copied()
                .filter(|name| *name == COMPANION_REQUIRED_604)
                .collect(),
            Family::V407 => Vec::new(),
        }
    }
}

/// Build the upstream config wrapper for `config_path`
/// (`0x14001c640.c:750-775`; literal bytes at exe offsets `0x155cf8`
/// and `0x155d30`):
///
/// ```text
/// DEFAULT loadconfig
///
/// LABEL loadconfig
///   CONFIG <path>
///   APPEND <dir>/
/// ```
///
/// where `<dir>` is `config_path` truncated at its last `/`. The
/// slash-appending variant is the one implemented because the
/// directory above never carries a trailing slash; the alternative
/// upstream variant (exe offset `0x155dc0`, `APPEND %s` with no slash)
/// belongs to a path that hands the directory down pre-slashed, which
/// this constructor never produces.
///
/// Refuses (ASCII, naming the input) when the path is empty, holds no
/// `/`, leaves the directory part empty, or holds a byte outside
/// `0x20..=0x7E`: the wrapper is a text file and the path lands in it
/// verbatim, so anything unprintable would corrupt it.
pub fn config_text(config_path: &[u8]) -> Result<Vec<u8>> {
    if config_path.is_empty() {
        return Err(CoreError::invalid(
            "syslinux config wrapper refuses an empty config path: refusing",
        ));
    }
    for (at, byte) in config_path.iter().enumerate() {
        if !(0x20..=0x7E).contains(byte) {
            return Err(CoreError::invalid(format!(
                "syslinux config wrapper refuses config path byte 0x{byte:02X} at offset {at}: paths land in the wrapper verbatim"
            )));
        }
    }
    let slash = config_path
        .iter()
        .rposition(|byte| *byte == b'/')
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux config wrapper refuses '{}': no directory part to chain back to",
                String::from_utf8_lossy(config_path)
            ))
        })?;
    let dir = config_path.get(..slash).ok_or_else(|| {
        CoreError::invalid("syslinux config wrapper lost its directory window: refusing")
    })?;
    if dir.is_empty() {
        return Err(CoreError::invalid(format!(
            "syslinux config wrapper refuses '{}': the directory part is empty",
            String::from_utf8_lossy(config_path)
        )));
    }
    let mut text = b"DEFAULT loadconfig\n\nLABEL loadconfig\n  CONFIG ".to_vec();
    text.extend_from_slice(config_path);
    text.extend_from_slice(b"\n  APPEND ");
    text.extend_from_slice(dir);
    text.extend_from_slice(b"/\n");
    Ok(text)
}

/// Write the wrapper `text` as `/syslinux.cfg` (`create_file` plus a
/// zero-offset `write_at`), refusing when one already exists: the root
/// listing is compared on the dot-joined short name (`SYSLINUX.CFG`),
/// the way `install.rs` checks `LDLINUX.SYS`.
///
/// An existing config belongs to the ISO and is left alone; the
/// `syslinux.org` rename path belongs to the copy wiring, which is
/// still a declared gap. Does not flush: the caller owns the flush.
pub fn write_config(fat: &mut Fat32, text: &[u8]) -> Result<()> {
    let present = fat
        .list_dir("/")?
        .iter()
        .any(|entry| entry.short_name == "SYSLINUX.CFG");
    if present {
        return Err(CoreError::invalid(
            "syslinux.cfg is already present on the volume: the iso owns its config, refusing to overwrite it",
        ));
    }
    let len = u64::try_from(text.len())
        .map_err(|_| CoreError::invalid("a syslinux config longer than u64: refusing"))?;
    fat.create_file("/syslinux.cfg", len)?;
    fat.write_at("/syslinux.cfg", 0, text)?;
    Ok(())
}

/// What [`install_companions`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionInstall {
    /// Companion names written, in [`COMPANIONS`] order.
    pub written: Vec<String>,
    /// Companion names already present with byte-identical content,
    /// counted as kept and left unwritten, in [`COMPANIONS`] order.
    pub kept: Vec<String>,
    /// One [`caution_for`] line per missing name, in [`COMPANIONS`]
    /// order.
    pub cautions: Vec<String>,
}

/// Copy every present companion from the payload directory onto the
/// volume under `target_dir`.
///
/// Each present name reads through [`read`] and lands at
/// `target_dir/<name>` (`create_file` plus a zero-offset `write_at`).
/// An existing destination counts as kept — and nothing is written —
/// when its bytes equal the image's copy: the copy step legitimately
/// places these files first by walking the whole tree, so an
/// identical file is the expected state, not a conflict. Differing
/// bytes refuse naming the file, since silently keeping a foreign
/// module would boot it. Missing names contribute their
/// [`caution_for`] line and no file. `target_dir` itself is created
/// with `mkdir` when it is not `/` and cannot be listed.
///
/// The destination directory is a parameter because the payload
/// directory varies per ISO (`/isolinux`, `/syslinux`, `/`, ...): the
/// companions must sit next to `ldlinux.sys` and the config, so the
/// caller passes the located payload directory's display path
/// ([`Located::path`](super::Located::path)) — `/` for a root payload
/// — and this call creates it when the formatter left no such
/// directory. Only single-level creation is attempted; anything
/// deeper refuses out of the path validation. Does not flush: the
/// caller owns the flush.
pub fn install_companions(
    fat: &mut Fat32,
    source: &dyn Source,
    dir: &[Vec<u8>],
    target_dir: &str,
) -> Result<CompanionInstall> {
    if target_dir != "/" {
        match fat.list_dir(target_dir) {
            Ok(_) => {}
            Err(_) => {
                fat.mkdir(target_dir)?;
            }
        }
    }
    let mut written = Vec::new();
    let mut kept = Vec::new();
    let mut cautions = Vec::new();
    for name in COMPANIONS {
        let Some(bytes) = read(source, dir, name)? else {
            cautions.push(caution_for(name));
            continue;
        };
        let dest = if target_dir == "/" {
            format!("/{name}")
        } else {
            format!("{target_dir}/{name}")
        };
        let already = fat.list_dir(target_dir)?.iter().any(|entry| {
            entry.name.eq_ignore_ascii_case(name) || entry.short_name.eq_ignore_ascii_case(name)
        });
        if already {
            // Byte-identical means satisfied: the copy step walks the
            // whole tree, so it placed this file first. Anything else
            // is a genuine conflict — keeping it would boot a module
            // the image never shipped, so it refuses instead.
            let back = fat.read_file(&dest)?;
            if back == bytes {
                kept.push(name.to_string());
                continue;
            }
            return Err(CoreError::invalid(format!(
                "syslinux companion '{name}' already present at '{target_dir}' differs from the image's copy: refusing to overwrite it"
            )));
        }
        let len = u64::try_from(bytes.len()).map_err(|_| {
            CoreError::invalid(format!(
                "syslinux companion '{name}' is longer than u64: refusing"
            ))
        })?;
        fat.create_file(&dest, len)?;
        fat.write_at(&dest, 0, &bytes)?;
        written.push(name.to_string());
    }
    Ok(CompanionInstall {
        written,
        kept,
        cautions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::Entry;
    use crate::copy::Source;
    use crate::error::Result as TestResult;
    use crate::fs::Volume;
    use crate::fs::fat32::format::FormatOptions;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// In-memory [`Source`] over explicit listings and file bytes, the
    /// same pattern the `copy` tests use: directories keyed by
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

    fn file_entry(name: &[u8], bytes: &[u8]) -> (Entry, Vec<u8>) {
        (
            Entry {
                name: name.to_vec(),
                is_dir: false,
                size: bytes.len() as u64,
                mode: Some(0o644),
                modified: None,
                accessed: None,
                link: None,
            },
            bytes.to_vec(),
        )
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

    /// A payload directory holding every companion plus a marker, so
    /// `inventory` sees all four present.
    fn full_tree() -> MemSource {
        let mut source = MemSource::new().with_dir(&[], vec![dir_entry(b"isolinux")]);
        let mut entries = vec![file_entry(b"isolinux.bin", b"bin").0];
        let mut files = Vec::new();
        for name in COMPANIONS {
            let (entry, bytes) = file_entry(name.as_bytes(), format!("{name}-bytes").as_bytes());
            entries.push(entry);
            files.push((name, bytes));
        }
        source = source.with_dir(&[b"isolinux"], entries);
        for (name, bytes) in files {
            source = source.with_file(&[b"isolinux", name.as_bytes()], &bytes);
        }
        source
    }

    fn isolinux_dir() -> Vec<Vec<u8>> {
        vec![b"isolinux".to_vec()]
    }

    #[test]
    fn companions_pin_exactly() {
        assert_eq!(
            COMPANIONS,
            ["ldlinux.c32", "menu.c32", "vesamenu.c32", "libutil.c32"],
            "the four upstream companion names"
        );
        for name in COMPANIONS {
            assert!(name.is_ascii(), "every name is ascii: {name}");
        }
        assert_eq!(
            COMPANION_REQUIRED_604, "ldlinux.c32",
            "the 6.04 required module"
        );
    }

    #[test]
    fn inventory_sees_present_and_missing() {
        let found = inventory(&full_tree(), &isolinux_dir()).expect("the triage runs");
        assert_eq!(found.present(), &COMPANIONS, "all four present");
        assert!(found.missing().is_empty(), "none missing");
        assert!(found.cautions().is_empty(), "no cautions");

        // Only ldlinux.c32 on disk: three missing, three cautions.
        let (entry, bytes) = file_entry(b"ldlinux.c32", b"core-lib");
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![entry])
            .with_file(&[b"isolinux", b"ldlinux.c32"], &bytes);
        let found = inventory(&source, &isolinux_dir()).expect("the triage runs");
        assert_eq!(found.present(), &["ldlinux.c32"], "one present");
        assert_eq!(
            found.missing(),
            &["menu.c32", "vesamenu.c32", "libutil.c32"],
            "three missing"
        );
        assert_eq!(
            found.cautions(),
            vec![
                "Caution: No 'menu.c32' was provided. The target will be missing a required Syslinux file!"
                    .to_string(),
                "Caution: No 'vesamenu.c32' was provided. The target will be missing a required Syslinux file!"
                    .to_string(),
                "Caution: No 'libutil.c32' was provided. The target will be missing a required Syslinux file!"
                    .to_string(),
            ],
            "one exact caution line per missing name"
        );
    }

    #[test]
    fn inventory_counts_a_symlink_as_absent() {
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![link_entry(b"ldlinux.c32")]);
        let found = inventory(&source, &isolinux_dir()).expect("the triage runs");
        assert!(found.present().is_empty(), "a symlink is never present");
        assert_eq!(
            found.missing(),
            &COMPANIONS,
            "every companion reads as missing"
        );
    }

    #[test]
    fn required_missing_follows_the_family() {
        let (entry, bytes) = file_entry(b"menu.c32", b"menu");
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![entry])
            .with_file(&[b"isolinux", b"menu.c32"], &bytes);
        let found = inventory(&source, &isolinux_dir()).expect("the triage runs");
        assert_eq!(
            found.required_missing(Family::V604),
            vec!["ldlinux.c32"],
            "6.04 requires the missing core library"
        );
        assert!(
            found.required_missing(Family::V407).is_empty(),
            "4.07 requires none of the four"
        );
        let full = inventory(&full_tree(), &isolinux_dir()).expect("the triage runs");
        assert!(
            full.required_missing(Family::V604).is_empty(),
            "a present library requires nothing"
        );
    }

    #[test]
    fn config_text_is_byte_exact() {
        assert_eq!(
            config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds"),
            b"DEFAULT loadconfig\n\nLABEL loadconfig\n  CONFIG /isolinux/isolinux.cfg\n  APPEND /isolinux/\n".to_vec(),
            "the isolinux wrapper"
        );
        assert_eq!(
            config_text(b"/boot/x86_64/loader/isolinux.cfg").expect("the wrapper builds"),
            b"DEFAULT loadconfig\n\nLABEL loadconfig\n  CONFIG /boot/x86_64/loader/isolinux.cfg\n  APPEND /boot/x86_64/loader/\n".to_vec(),
            "the nested wrapper"
        );
    }

    #[test]
    fn config_text_refuses_bad_paths() {
        for (path, fragment) in [
            (&b""[..], "empty"),
            (&b"isolinux.cfg"[..], "no directory"),
            (&b"/isolinux.cfg"[..], "empty"),
        ] {
            let error = config_text(path).expect_err("a bad path refuses");
            let text = error.to_string();
            assert!(text.is_ascii(), "stays ASCII: {text}");
            assert!(
                text.contains(fragment),
                "names the shape ({fragment}): {text}"
            );
        }
        let mut nonlocal = b"/isolinux/isolinux.cfg".to_vec();
        nonlocal[4] = 0xC3;
        let error = config_text(&nonlocal).expect_err("a non-ascii byte refuses");
        let text = error.to_string();
        assert!(text.contains("0xC3"), "names the byte: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
    }

    /// A [`Volume`] over shared bytes, the same shim `install.rs`
    /// tests use: `Fat32` keeps its store private, so the tests watch
    /// the image through the shared handle.
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
    fn write_config_round_trips_and_refuses_a_second_write() {
        let (backing, mut fat) = formatted();
        let text = config_text(b"/isolinux/isolinux.cfg").expect("the wrapper builds");
        write_config(&mut fat, &text).expect("the first write lands");
        // No flush inside: the bytes are already readable back, and
        // the image dumps straight to the checker below.
        let back = fat
            .read_file("/syslinux.cfg")
            .expect("the config reads back");
        assert_eq!(back, text, "the wrapper is byte-identical");
        let error = write_config(&mut fat, &text).expect_err("a second write refuses");
        let text_error = error.to_string();
        assert!(
            text_error.contains("syslinux.cfg"),
            "the refusal names the file: {text_error}"
        );
        assert!(text_error.is_ascii(), "stays ASCII: {text_error}");
        // No flush inside `write_config` itself: the caller-side flush
        // below is what publishes the allocation to the image, exactly
        // as the later wiring will do before it dumps or boots.
        fat.flush().expect("the caller-side flush runs");
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let image = scratch.path().join("config.img");
        std::fs::write(&image, backing.bytes.borrow().as_slice()).expect("the image dumps");
        let output = std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&image)
            .output()
            .expect("fsck.fat runs");
        assert!(
            output.status.success(),
            "fsck.fat -n exits 0 after the config write: {}",
            output.status
        );
        let _ = backing;
    }

    #[test]
    fn install_companions_lands_files_and_cautions() {
        let (_backing, mut fat) = formatted();
        // Two present, two missing: the files land under a created
        // /isolinux, the missing pair yields cautions.
        let (menu, menu_bytes) = file_entry(b"menu.c32", b"menu-bytes");
        let (lib, lib_bytes) = file_entry(b"libutil.c32", b"lib-bytes");
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![menu, lib])
            .with_file(&[b"isolinux", b"menu.c32"], &menu_bytes)
            .with_file(&[b"isolinux", b"libutil.c32"], &lib_bytes);
        let done = install_companions(&mut fat, &source, &isolinux_dir(), "/isolinux")
            .expect("the install runs");
        assert_eq!(
            done.written,
            vec!["menu.c32".to_string(), "libutil.c32".to_string()],
            "the present pair in companion order"
        );
        assert_eq!(
            done.cautions,
            vec![caution_for("ldlinux.c32"), caution_for("vesamenu.c32"),],
            "the missing pair yields cautions"
        );
        let listed = fat.list_dir("/isolinux").expect("the target lists");
        assert_eq!(listed.len(), 2, "two entries landed");
        let back = fat
            .read_file("/isolinux/menu.c32")
            .expect("menu reads back");
        assert_eq!(back, menu_bytes, "menu bytes identical");
        let back = fat
            .read_file("/isolinux/libutil.c32")
            .expect("libutil reads back");
        assert_eq!(back, lib_bytes, "libutil bytes identical");

        // A second run over identical bytes keeps instead of
        // refusing: the copy step legitimately places these first.
        let again = install_companions(&mut fat, &source, &isolinux_dir(), "/isolinux")
            .expect("identical bytes are kept");
        assert!(
            again.written.is_empty(),
            "nothing writes twice: {:?}",
            again.written
        );
        assert_eq!(
            again.kept,
            vec!["menu.c32".to_string(), "libutil.c32".to_string()],
            "the present pair reports kept"
        );
        assert_eq!(again.cautions.len(), 2, "cautions repeat");
    }

    #[test]
    fn install_companions_keeps_identical_bytes_untouched() {
        // Pre-create one companion with exactly the image's bytes,
        // leave the other absent: the run keeps the first, writes the
        // second, and changes no byte of the first.
        let (menu, menu_bytes) = file_entry(b"menu.c32", b"menu-bytes");
        let (lib, lib_bytes) = file_entry(b"libutil.c32", b"lib-bytes");
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![menu, lib])
            .with_file(&[b"isolinux", b"menu.c32"], &menu_bytes)
            .with_file(&[b"isolinux", b"libutil.c32"], &lib_bytes);
        let (_backing, mut fat) = formatted();
        fat.mkdir("/isolinux").expect("the copy makes the dir");
        fat.create_file("/isolinux/menu.c32", menu_bytes.len() as u64)
            .expect("the copy lands first");
        fat.write_at("/isolinux/menu.c32", 0, &menu_bytes)
            .expect("the copy writes");
        let done = install_companions(&mut fat, &source, &isolinux_dir(), "/isolinux")
            .expect("identical bytes are kept");
        assert_eq!(
            done.written,
            vec!["libutil.c32".to_string()],
            "only the absent file writes"
        );
        assert_eq!(
            done.kept,
            vec!["menu.c32".to_string()],
            "the identical file reports kept"
        );
        let back = fat
            .read_file("/isolinux/menu.c32")
            .expect("kept file reads back");
        assert_eq!(back, menu_bytes, "kept bytes unchanged");
    }

    #[test]
    fn install_companions_refuses_differing_bytes() {
        // Pre-create one companion with foreign bytes: the run
        // refuses naming it, writes nothing for it, and leaves the
        // file untouched — keeping it would boot a foreign module.
        let (menu, menu_bytes) = file_entry(b"menu.c32", b"menu-bytes");
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![menu])
            .with_file(&[b"isolinux", b"menu.c32"], &menu_bytes);
        let (_backing, mut fat) = formatted();
        fat.mkdir("/isolinux").expect("the copy makes the dir");
        fat.create_file("/isolinux/menu.c32", 7)
            .expect("a foreign file lands first");
        fat.write_at("/isolinux/menu.c32", 0, b"foreign")
            .expect("the foreign write lands");
        let error = install_companions(&mut fat, &source, &isolinux_dir(), "/isolinux")
            .expect_err("differing bytes refuse");
        let text = error.to_string();
        assert!(text.contains("menu.c32"), "names the file: {text}");
        assert!(text.contains("differs"), "names the conflict: {text}");
        assert!(text.is_ascii(), "stays ASCII: {text}");
        let back = fat
            .read_file("/isolinux/menu.c32")
            .expect("the file still reads");
        assert_eq!(back, b"foreign", "foreign bytes untouched");
    }

    #[test]
    fn install_companions_writes_to_the_root() {
        let (_backing, mut fat) = formatted();
        let done = install_companions(&mut fat, &full_tree(), &isolinux_dir(), "/")
            .expect("the install runs");
        assert_eq!(
            done.written.len(),
            4,
            "all four companions land at the root"
        );
        assert!(done.cautions.is_empty(), "nothing missing, no cautions");
        let back = fat.read_file("/vesamenu.c32").expect("vesamenu reads back");
        assert_eq!(back, b"vesamenu.c32-bytes", "root bytes identical");
    }
}
