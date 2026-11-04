//! Obsolete Syslinux module replacement (`copy::Replacer`).
//!
//! Upstream replaces two stale ISO modules — `menu.c32` and
//! `vesamenu.c32` — with the caller-supplied downloads, but only when
//! the detected major version is below 5 (`0x140031e30:800-830`).
//! [`Obsolete`] carries that policy: the family decides whether any
//! substitution happens at all, and the entry table (name plus bytes)
//! decides what each substituted file becomes. The walker logs the
//! `Will replace obsolete` warning itself; this impl logs nothing and
//! takes no logger.
//!
//! Honest limit: no `.c32` bytes exist in `assets/`, so a 6.04 ISO's
//! own modules always copy verbatim — only the 4.07 obsolete pair can
//! be substituted, and only from bytes the caller supplies (Rufus's
//! downloaded `Rufus\syslinux-<ver>` files).

use std::path::Path;

use crate::copy::Replacement;
use crate::copy::Replacer;
use crate::error::CoreError;
use crate::error::Result;

use super::Family;

/// Module names the replacement policy covers: exactly upstream's two
/// table entries (`PTR_s_menu_c32_140142550`, two entries).
/// `ldlinux.c32` is never replaced — it is a required companion for
/// 6.04, not an obsolete one.
pub const OBSOLETE_MODULES: [&str; 2] = ["menu.c32", "vesamenu.c32"];

/// Obsolete-module substitutions for one install: the family gates
/// whether anything is replaced, and each entry is a `(name, bytes)`
/// pair to write under the matched file's destination name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obsolete {
    family: Family,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Obsolete {
    /// No substitutions under any family: the table is empty (and the
    /// family is the never-replacing 6.04, so both gates stay shut).
    #[must_use]
    pub fn none() -> Self {
        Self {
            family: Family::V604,
            entries: Vec::new(),
        }
    }

    /// Substitutions for `family` from explicit `(name, bytes)` pairs.
    /// Entries whose name falls outside [`OBSOLETE_MODULES`] are
    /// ignored (dropped, never matched): the table mirrors upstream's
    /// two entries, and anything wider would substitute files the
    /// reference never touches. The name comparison folds ASCII case,
    /// matching how the walker will match later.
    #[must_use]
    pub fn new(family: Family, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        let kept = entries
            .into_iter()
            .filter(|(name, _)| {
                OBSOLETE_MODULES
                    .iter()
                    .any(|known| name.eq_ignore_ascii_case(known.as_bytes()))
            })
            .collect();
        Self {
            family,
            entries: kept,
        }
    }

    /// Substitutions for `family` from a caller directory: `menu.c32`
    /// and `vesamenu.c32` are read when they exist there, absent ones
    /// are skipped without error — a partial companion set just
    /// replaces less. Any other I/O failure names the file.
    pub fn from_dir(family: Family, dir: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        for name in OBSOLETE_MODULES {
            let path = dir.join(name);
            match std::fs::read(&path) {
                Ok(bytes) => entries.push((name.as_bytes().to_vec(), bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(CoreError::io(&path, error)),
            }
        }
        Ok(Self::new(family, entries))
    }

    /// The family this table substitutes under.
    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// Table entries as `(name, bytes)` pairs.
    #[must_use]
    pub fn entries(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.entries
    }
}

impl Replacer for Obsolete {
    /// The substitute bytes for one file, or `None` to copy it
    /// verbatim: only when the family is 4.07 (upstream gates on major
    /// below 5) and the file name matches a table entry, ASCII
    /// case-insensitively, with `mode: None` so the source entry's
    /// mode still lands.
    ///
    /// `source_path` is ignored on purpose: the two modules are the
    /// only files this policy ever substitutes in any directory, so
    /// matching by name alone is faithful to the reference — a
    /// `menu.c32` wherever the walker meets one is the obsolete
    /// module.
    fn replacement(&self, _source_path: &[u8], name: &[u8]) -> Option<Replacement> {
        if self.family != Family::V407 {
            return None;
        }
        let (_, bytes) = self
            .entries
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))?;
        Some(Replacement {
            bytes: bytes.clone(),
            mode: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::CopyOptions;
    use crate::copy::Entry;
    use crate::copy::Progress;
    use crate::copy::Source;
    use crate::copy::walk;
    use crate::error::Result as TestResult;
    use std::collections::HashMap;

    fn obsolete_v407() -> Obsolete {
        Obsolete::new(
            Family::V407,
            vec![
                (b"menu.c32".to_vec(), b"new-menu".to_vec()),
                (b"vesamenu.c32".to_vec(), b"new-vesamenu".to_vec()),
            ],
        )
    }

    #[test]
    fn obsolete_modules_pin_the_pair() {
        assert_eq!(
            OBSOLETE_MODULES,
            ["menu.c32", "vesamenu.c32"],
            "upstream's two table entries"
        );
        for name in OBSOLETE_MODULES {
            assert!(name.is_ascii(), "every name is ascii: {name}");
        }
    }

    #[test]
    fn replacement_covers_both_names_case_insensitively() {
        let table = obsolete_v407();
        for name in [
            &b"menu.c32"[..],
            &b"MENU.C32"[..],
            &b"vesamenu.c32"[..],
            &b"VesaMenu.C32"[..],
        ] {
            let found = table
                .replacement(b"isolinux", name)
                .expect("the module is substituted");
            assert_eq!(
                found.mode,
                None,
                "the source entry's mode still lands for {}",
                String::from_utf8_lossy(name)
            );
        }
        assert_eq!(
            table
                .replacement(b"", b"menu.c32")
                .expect("root matches too")
                .bytes,
            b"new-menu",
            "matching ignores the directory"
        );
        assert_eq!(
            table
                .replacement(b"isolinux", b"vesamenu.c32")
                .expect("vesamenu matches")
                .bytes,
            b"new-vesamenu",
            "each name maps to its own bytes"
        );
    }

    #[test]
    fn replacement_is_neutral_for_604_and_other_names() {
        let table = obsolete_v407();
        assert!(
            table.replacement(b"isolinux", b"ldlinux.c32").is_none(),
            "the core library is never replaced"
        );
        assert!(
            table.replacement(b"isolinux", b"libutil.c32").is_none(),
            "a non-table companion copies verbatim"
        );
        let newer = Obsolete::new(
            Family::V604,
            vec![(b"menu.c32".to_vec(), b"new-menu".to_vec())],
        );
        assert!(
            newer.replacement(b"isolinux", b"menu.c32").is_none(),
            "6.04 copies its own modules verbatim"
        );
        assert!(
            Obsolete::none().replacement(b"", b"menu.c32").is_none(),
            "the empty table replaces nothing"
        );
    }

    #[test]
    fn new_ignores_names_outside_the_table() {
        let table = Obsolete::new(
            Family::V407,
            vec![
                (b"menu.c32".to_vec(), b"new-menu".to_vec()),
                (b"grub.exe".to_vec(), b"not-a-module".to_vec()),
            ],
        );
        assert_eq!(table.entries().len(), 1, "one entry survives");
        assert_eq!(
            table.entries()[0].0,
            b"menu.c32",
            "the table member is the survivor"
        );
        assert!(
            table.replacement(b"", b"grub.exe").is_none(),
            "the dropped name copies verbatim"
        );
    }

    #[test]
    fn from_dir_reads_one_both_or_neither() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        // Neither: an empty table, no error.
        let empty = Obsolete::from_dir(Family::V407, scratch.path()).expect("absent is fine");
        assert!(empty.entries().is_empty(), "no files, no entries");

        // One: the present file lands, the absent one stays silent.
        std::fs::write(scratch.path().join("menu.c32"), b"disk-menu").expect("the fixture writes");
        let one = Obsolete::from_dir(Family::V407, scratch.path()).expect("partial is fine");
        assert_eq!(one.entries().len(), 1, "one entry");
        assert_eq!(
            one.replacement(b"x", b"menu.c32")
                .expect("menu substitutes")
                .bytes,
            b"disk-menu",
            "the disk bytes win"
        );
        assert!(
            one.replacement(b"x", b"vesamenu.c32").is_none(),
            "the absent file still copies verbatim"
        );

        // Both.
        std::fs::write(scratch.path().join("vesamenu.c32"), b"disk-vesa")
            .expect("the fixture writes");
        let both = Obsolete::from_dir(Family::V604, scratch.path()).expect("both read");
        assert_eq!(both.entries().len(), 2, "two entries");
        assert_eq!(both.family(), Family::V604, "the family rides along");
    }

    /// In-memory [`Source`] over explicit listings and file bytes, the
    /// same pattern the `copy` tests use.
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

    /// A recording [`Progress`]: every warning line, in order.
    #[derive(Debug, Default)]
    struct Recorder {
        warns: Vec<String>,
    }

    impl Progress for Recorder {
        fn report(&mut self, _done_bytes: u64, _total_bytes: u64) {}

        fn warn(&mut self, text: &str) {
            self.warns.push(text.to_string());
        }
    }

    #[test]
    fn walk_substitutes_through_the_replacer() {
        // One obsolete module plus one verbatim file under /isolinux:
        // the walk must land the table bytes for the first, copy the
        // second, and report exactly one replacement warning.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(
                &[b"isolinux"],
                vec![
                    file_entry(b"menu.c32", b"old-menu"),
                    file_entry(b"other.txt", b"plain"),
                ],
            )
            .with_file(&[b"isolinux", b"menu.c32"], b"old-menu")
            .with_file(&[b"isolinux", b"other.txt"], b"plain");
        let table = obsolete_v407();
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let mut progress = Recorder::default();
        let options = CopyOptions {
            free_bytes: None,
            replacer: Some(&table),
            fat32_limit: false,
        };
        let summary =
            walk(&source, scratch.path(), &options, &mut progress).expect("the walk runs");
        assert_eq!(summary.files, 2, "two files copied");
        assert_eq!(
            std::fs::read(scratch.path().join("isolinux").join("menu.c32"))
                .expect("the substituted file reads"),
            b"new-menu",
            "the table bytes land"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("isolinux").join("other.txt"))
                .expect("the plain file reads"),
            b"plain",
            "the other file copies verbatim"
        );
        assert_eq!(
            progress.warns,
            vec!["Will replace obsolete 'isolinux/menu.c32'".to_string()],
            "the walk reports the one replacement"
        );
    }
}
