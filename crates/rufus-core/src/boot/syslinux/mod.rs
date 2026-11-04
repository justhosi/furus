//! Syslinux family selection and payload-directory lookup (S19 slice 2).
//!
//! A detected Isolinux version string (for example `6.04` or `4.07`,
//! banner-scanned by the report) selects the embedded family: major 5
//! and above uses the 6.04 resources, major 4 and below uses the 4.07
//! resources. When nothing was detected the family is forced from the
//! presence of `/isolinux/ldlinux.c32` (present means 6.04, absent
//! means 4.07); a detected major that disagrees with that presence
//! still wins but logs the reference conflict warning. [`locate`]
//! finds the payload directory over a [`Source`](crate::copy::Source)
//! and [`read`] fetches one file from it. This module decides and
//! reads only: [`install`] owns the write half —
//! [`install::install_loader`] loads the family's embedded payloads
//! and [`install::install_payloads`] (the testable core over explicit
//! bytes) grafts the patched VBR boot code onto a FAT32 volume's boot
//! sector and lays the patched core plus the ADV tail down as a
//! contiguous `/ldlinux.sys` — while everything else in this file
//! never patches a sector and never creates a file. [`patch`] owns
//! the byte patching: upstream `syslinux_patch` plus the default ADV.
//!
//! [`install`]: self::install
//! [`patch`]: self::patch

mod install;
pub mod patch;

pub use install::Installed;
pub use install::install_loader;
pub use install::install_payloads;
pub use patch::Patched;
pub use patch::default_adv;
pub use patch::syslinux_patch;

use super::Resource;
use crate::copy::Source;
use crate::error::CoreError;
use crate::error::Result;

/// One embedded Syslinux family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Syslinux 4.07 (manifest ids 400/401).
    V407,
    /// Syslinux 6.04 (manifest ids 402/403).
    V604,
}

impl Family {
    /// Display version of the family (`4.07` or `6.04`).
    #[must_use]
    pub fn version(self) -> &'static str {
        match self {
            Self::V407 => "4.07",
            Self::V604 => "6.04",
        }
    }

    /// Numeric major of the family (4 or 6).
    #[must_use]
    pub fn major(self) -> u16 {
        match self {
            Self::V407 => 4,
            Self::V604 => 6,
        }
    }

    /// VBR resource of the family.
    #[must_use]
    pub fn vbr(self) -> Resource {
        match self {
            Self::V407 => Resource::Syslinux407Vbr,
            Self::V604 => Resource::Syslinux604Vbr,
        }
    }

    /// Core (`ldlinux.sys`) resource of the family.
    #[must_use]
    pub fn core(self) -> Resource {
        match self {
            Self::V407 => Resource::Syslinux407Core,
            Self::V604 => Resource::Syslinux604Core,
        }
    }

    /// Family for a detected major: 5 and above is 6.04.
    ///
    /// A 5.x image gets the 6.04 assets because the 4.07 payloads
    /// cannot read the 5.x `.c32` layout.
    #[must_use]
    pub fn from_major(major: u16) -> Family {
        if major >= 5 {
            Family::V604
        } else {
            Family::V407
        }
    }
}

/// A banner-scanned Isolinux version and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// Version text as the report carries it (for example `6.04-pre1`).
    pub version: String,
    /// Image path the version was scanned from (for example
    /// `/isolinux/isolinux.bin`).
    pub source: String,
}

impl Detected {
    /// Numeric major of [`version`](Self::version), when it parses.
    ///
    /// Parses the leading run of ASCII digits, a `.`, and another digit
    /// run (each run non-empty with a numeric value below 256); the
    /// rest of the string (such as `-pre1`) is ignored. Anything else
    /// reads as `None`. No indexing past the end anywhere: every byte
    /// goes through `get`.
    #[must_use]
    pub fn major(&self) -> Option<u16> {
        parse_major(&self.version)
    }
}

/// Parse ASCII decimal digits to `u16`, refusing empty input,
/// non-digits and overflow.
fn parse_decimal_u16(digits: &[u8]) -> Option<u16> {
    if digits.is_empty() {
        return None;
    }
    let mut value: u16 = 0;
    for byte in digits.iter() {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte.saturating_sub(b'0')),
            _ => return None,
        };
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Major of a version string per [`Detected::major`].
fn parse_major(version: &str) -> Option<u16> {
    let bytes = version.as_bytes();
    let mut cursor: usize = 0;
    let major_start = cursor;
    while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
        cursor = cursor.saturating_add(1);
    }
    let major_text = bytes.get(major_start..cursor)?;
    if major_text.is_empty() {
        return None;
    }
    let major = parse_decimal_u16(major_text)?;
    if major >= 256 {
        return None;
    }
    if bytes.get(cursor) != Some(&b'.') {
        return None;
    }
    cursor = cursor.saturating_add(1);
    let minor_start = cursor;
    while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
        cursor = cursor.saturating_add(1);
    }
    let minor_text = bytes.get(minor_start..cursor)?;
    if minor_text.is_empty() {
        return None;
    }
    let minor = parse_decimal_u16(minor_text)?;
    if minor >= 256 {
        return None;
    }
    Some(major)
}

/// The chosen family plus the log lines the reference emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    family: Family,
    detected: Option<Detected>,
    messages: Vec<String>,
}

impl Selection {
    /// The chosen embedded family.
    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// The detected version that drove the choice, when one parsed.
    #[must_use]
    pub fn detected(&self) -> Option<&Detected> {
        self.detected.as_ref()
    }

    /// Log lines in the order the reference emits them: the detection
    /// line or the forcing warning first, then the conflict warning
    /// when it applies.
    #[must_use]
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

/// Choose the embedded family from an optional detection and the
/// `ldlinux.c32` presence.
///
/// A detected version whose major parses selects the family through
/// [`Family::from_major`](Family::from_major); the messages then hold
/// `  Detected Syslinux version: {version} (from '{source}')` plus the
/// conflict warning when the major disagrees with the `.c32` presence
/// (major below 5 with the file present, or major 5 and above with it
/// absent). With no detection — or with a `Detected` whose version
/// does not parse — the family is forced from the `.c32` presence and
/// the messages hold `  Warning: Could not detect Isolinux version -
/// Forcing to {version} (embedded)` naming that embedded version; a
/// malformed string is never trusted silently.
#[must_use]
pub fn select(detected: Option<Detected>, has_ldlinux_c32: bool) -> Selection {
    match detected {
        Some(candidate) => match candidate.major() {
            Some(major) => {
                let family = Family::from_major(major);
                let mut messages = vec![format!(
                    "  Detected Syslinux version: {} (from '{}')",
                    candidate.version, candidate.source
                )];
                if (major < 5 && has_ldlinux_c32) || (major >= 5 && !has_ldlinux_c32) {
                    messages.push(
                        "  Warning: Conflict between Isolinux version and the presence of ldlinux.c32..."
                            .to_string(),
                    );
                }
                Selection {
                    family,
                    detected: Some(candidate),
                    messages,
                }
            }
            None => {
                let family = if has_ldlinux_c32 {
                    Family::V604
                } else {
                    Family::V407
                };
                let messages = vec![format!(
                    "  Warning: Could not detect Isolinux version - Forcing to {} (embedded)",
                    family.version()
                )];
                Selection {
                    family,
                    detected: None,
                    messages,
                }
            }
        },
        None => {
            let family = if has_ldlinux_c32 {
                Family::V604
            } else {
                Family::V407
            };
            let messages = vec![format!(
                "  Warning: Could not detect Isolinux version - Forcing to {} (embedded)",
                family.version()
            )];
            Selection {
                family,
                detected: None,
                messages,
            }
        }
    }
}

/// Candidate payload directories as component stacks, in reference
/// order: `isolinux`, `boot/isolinux`, `syslinux`, `boot/syslinux`,
/// then the two openSUSE layouts the reference string table carries
/// (`boot/x86_64/loader`, `boot/i386/loader`).
pub const DIRS: &[&[&[u8]]] = &[
    &[b"isolinux" as &[u8]],
    &[b"boot" as &[u8], b"isolinux" as &[u8]],
    &[b"syslinux" as &[u8]],
    &[b"boot" as &[u8], b"syslinux" as &[u8]],
    &[b"boot" as &[u8], b"x86_64" as &[u8], b"loader" as &[u8]],
    &[b"boot" as &[u8], b"i386" as &[u8], b"loader" as &[u8]],
];

/// Render one directory stack as the `/`-joined display form
/// (`/isolinux`, `/boot/x86_64/loader`): bytes outside printable ASCII
/// (`0x20..=0x7E`) become `?`, so log lines stay ASCII whatever the
/// image names hold. An empty stack renders as `/`.
fn display_dir(dir: &[Vec<u8>]) -> String {
    if dir.is_empty() {
        return "/".to_string();
    }
    let mut out = String::new();
    for component in dir.iter() {
        out.push('/');
        for byte in component.iter() {
            if (0x20..=0x7E).contains(byte) {
                out.push(*byte as char);
            } else {
                out.push('?');
            }
        }
    }
    out
}

/// True when `name` is one of the marker files a payload directory
/// must hold. Only the marker and file *names* fold case here (image
/// trees commonly spell these names in upper case); the directory
/// components of [`DIRS`] do not — the ISO and UDF adapters resolve
/// each component exactly, so an upper-case `ISOLINUX` directory is
/// never found. Symlinks never count as holders (see [`locate`]).
fn is_marker(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"isolinux.bin")
        || name.eq_ignore_ascii_case(b"isolinux.cfg")
        || name.eq_ignore_ascii_case(b"syslinux.cfg")
        || name.eq_ignore_ascii_case(b"ldlinux.c32")
}

/// A located payload directory and its log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    dir: Vec<Vec<u8>>,
    messages: Vec<String>,
}

impl Located {
    /// Directory stack as name bytes from the root.
    #[must_use]
    pub fn dir(&self) -> &[Vec<u8>] {
        &self.dir
    }

    /// `/`-joined display form (see [`display_dir`]).
    #[must_use]
    pub fn path(&self) -> String {
        display_dir(&self.dir)
    }

    /// The single `  Will use '{path}' for Syslinux` line.
    #[must_use]
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

/// Find the first [`DIRS`] candidate that exists as a directory and
/// holds at least one marker file (`isolinux.bin`, `isolinux.cfg`,
/// `syslinux.cfg`, `ldlinux.c32`).
///
/// A candidate whose name exists as a plain file never counts (only a
/// listing that succeeds counts as a directory), and a directory
/// without any marker file is skipped. A listing error that is a real
/// I/O error ([`CoreError::Io`]) propagates; any other listing refusal
/// (absent path, file in a directory slot) reads as no match for that
/// candidate, following how `report::read_bin` splits `CoreError::Io`
/// from the rest.
pub fn locate(source: &dyn Source) -> Result<Option<Located>> {
    for candidate in DIRS.iter() {
        let mut dir: Vec<Vec<u8>> = Vec::new();
        for component in candidate.iter() {
            dir.push(component.to_vec());
        }
        let entries = if dir.is_empty() {
            match source.root_entries() {
                Ok(entries) => entries,
                Err(error @ CoreError::Io { .. }) => return Err(error),
                Err(_) => continue,
            }
        } else {
            match source.child_entries(&dir) {
                Ok(entries) => entries,
                Err(error @ CoreError::Io { .. }) => return Err(error),
                Err(_) => continue,
            }
        };
        let mut holds = false;
        for entry in entries.iter() {
            if entry.is_dir {
                continue;
            }
            if entry.link.is_some() {
                continue;
            }
            if is_marker(&entry.name) {
                holds = true;
                break;
            }
        }
        if !holds {
            continue;
        }
        let path = display_dir(&dir);
        let messages = vec![format!("  Will use '{path}' for Syslinux")];
        return Ok(Some(Located { dir, messages }));
    }
    Ok(None)
}

/// Cap on a single [`read`] in bytes (1 MiB): the same ceiling the
/// report uses for its version scans (`MAX_BINARY_SCAN`), so a hostile
/// image cannot make this module buffer a crafted multi-gigabyte
/// config or binary.
const MAX_READ_BYTES: u64 = 1024 * 1024;

/// Read window for [`read`] in bytes (4 KiB).
const READ_CHUNK: usize = 4096;

/// Map text for messages to ASCII: every control or non-ASCII
/// character becomes `?`, so error lines stay ASCII whatever the
/// caller passes as a file name.
fn ascii_safe(text: &str) -> String {
    text.chars()
        .map(|next| {
            if next.is_ascii() && !next.is_control() {
                next
            } else {
                '?'
            }
        })
        .collect()
}

/// Read one whole file from the located directory.
///
/// The size comes from the directory listing and the bytes stream
/// through [`Source::read_bytes`] in 4 KiB windows (read to EOF with
/// the listed size, never read-then-discard past the cap). Returns
/// `None` when the name is absent, names a directory, or names a
/// symlink (each reads as absent, not as an error). Refuses a name that
/// carries a `/`, `\` or NUL byte, or that is `.` or `..`, and refuses
/// a file larger than [`MAX_READ_BYTES`]. A listing I/O error
/// propagates like in [`locate`]; any other listing refusal reads as
/// absent. Read errors propagate: the file was listed, so a short read
/// is corruption, not absence.
pub fn read(source: &dyn Source, dir: &[Vec<u8>], name: &str) -> Result<Option<Vec<u8>>> {
    if name.is_empty() {
        return Err(CoreError::invalid(
            "syslinux read refuses an empty file name".to_string(),
        ));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(CoreError::invalid(format!(
            "syslinux read refuses the file name '{}': names must be one component",
            ascii_safe(name)
        )));
    }
    if name == "." || name == ".." {
        return Err(CoreError::invalid(format!(
            "syslinux read refuses the file name '{}': reserved names never read",
            ascii_safe(name)
        )));
    }
    let want = name.as_bytes();
    let entries = if dir.is_empty() {
        match source.root_entries() {
            Ok(entries) => entries,
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => return Ok(None),
        }
    } else {
        match source.child_entries(dir) {
            Ok(entries) => entries,
            Err(error @ CoreError::Io { .. }) => return Err(error),
            Err(_) => return Ok(None),
        }
    };
    let mut found_size: Option<u64> = None;
    for entry in entries.iter() {
        if !entry.name.eq_ignore_ascii_case(want) {
            continue;
        }
        if entry.is_dir || entry.link.is_some() {
            return Ok(None);
        }
        found_size = Some(entry.size);
        break;
    }
    let size = match found_size {
        Some(size) => size,
        None => return Ok(None),
    };
    if size > MAX_READ_BYTES {
        return Err(CoreError::invalid(format!(
            "syslinux read of '{}' is {size} bytes, past the 1 MiB read cap of {MAX_READ_BYTES} bytes: refusing",
            ascii_safe(name)
        )));
    }
    let count = usize::try_from(size).map_err(|_| {
        CoreError::invalid(format!(
            "syslinux read of '{}' size {size} does not fit this machine's address space",
            ascii_safe(name)
        ))
    })?;
    let mut full: Vec<Vec<u8>> = dir.to_vec();
    full.push(want.to_vec());
    let mut out = Vec::new();
    out.try_reserve(count).map_err(|_| {
        CoreError::invalid(format!(
            "syslinux read of '{}' size {size} cannot be buffered",
            ascii_safe(name)
        ))
    })?;
    let mut buf = vec![0u8; READ_CHUNK];
    let mut offset: u64 = 0;
    while offset < size {
        let remaining = size.saturating_sub(offset);
        let chunk = (READ_CHUNK as u64).min(remaining);
        let width = usize::try_from(chunk).map_err(|_| {
            CoreError::invalid(format!(
                "syslinux read of '{}' window {chunk} does not fit this machine's address space",
                ascii_safe(name)
            ))
        })?;
        let dest = buf.get_mut(..width).ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux read of '{}' window {width} runs past the {READ_CHUNK} byte buffer",
                ascii_safe(name)
            ))
        })?;
        let placed = source.read_bytes(&full, offset, dest)?;
        if placed == 0 {
            return Err(CoreError::invalid(format!(
                "syslinux read of '{}' ends at {offset} of {size} bytes: refusing a short read",
                ascii_safe(name)
            )));
        }
        let window = dest.get(..placed).ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux read of '{}' window of {placed} bytes runs past the {width} byte window",
                ascii_safe(name)
            ))
        })?;
        out.extend_from_slice(window);
        let placed_u64 = u64::try_from(placed).map_err(|_| {
            CoreError::invalid(format!(
                "syslinux read of '{}' place count {placed} does not fit the offset arithmetic",
                ascii_safe(name)
            ))
        })?;
        offset = offset.checked_add(placed_u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "syslinux read of '{}' offset {offset} overflows the byte offset arithmetic",
                ascii_safe(name)
            ))
        })?;
        if (out.len() as u64) > MAX_READ_BYTES {
            return Err(CoreError::invalid(format!(
                "syslinux read of '{}' runs past the 1 MiB read cap: refusing",
                ascii_safe(name)
            )));
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::Entry;
    use std::collections::HashMap;

    fn detected(version: &str, source: &str) -> Detected {
        Detected {
            version: version.to_string(),
            source: source.to_string(),
        }
    }

    #[test]
    fn family_mapping_covers_old_new_and_malformed() {
        // Each pair is the version text plus the family `select` must
        // pick for it (through `from_major`); the malformed string
        // must not parse at all.
        let cases: &[(&str, Option<u16>, Family)] = &[
            ("4.07", Some(4), Family::V407),
            ("5.10", Some(5), Family::V604),
            ("6.04", Some(6), Family::V604),
            ("6.04-pre1", Some(6), Family::V604),
            ("3.86", Some(3), Family::V407),
        ];
        for (text, major, family) in cases {
            let seen = detected(text, "/isolinux/isolinux.bin");
            assert_eq!(seen.major(), *major, "major of {text}");
            if let Some(number) = major {
                assert_eq!(Family::from_major(*number), *family, "family of {text}");
            }
        }
        assert_eq!(
            detected("not-a-version", "/isolinux/isolinux.bin").major(),
            None,
            "a malformed version has no major"
        );
        assert_eq!(detected("", "/x").major(), None, "empty has no major");
        assert_eq!(detected("6.", "/x").major(), None, "missing minor refuses");
        assert_eq!(detected(".04", "/x").major(), None, "missing major refuses");
        assert_eq!(
            detected("256.0", "/x").major(),
            None,
            "a major at 256 refuses"
        );
        assert_eq!(
            detected("6.256", "/x").major(),
            None,
            "a minor at 256 refuses"
        );
        // Family accessors stay pinned.
        assert_eq!(Family::V407.version(), "4.07");
        assert_eq!(Family::V604.version(), "6.04");
        assert_eq!(Family::V407.major(), 4);
        assert_eq!(Family::V604.major(), 6);
        assert_eq!(Family::V407.vbr(), Resource::Syslinux407Vbr);
        assert_eq!(Family::V407.core(), Resource::Syslinux407Core);
        assert_eq!(Family::V604.vbr(), Resource::Syslinux604Vbr);
        assert_eq!(Family::V604.core(), Resource::Syslinux604Core);
    }

    #[test]
    fn select_detected_new_with_c32_has_no_conflict() {
        let picked = select(Some(detected("6.04", "/isolinux/isolinux.bin")), true);
        assert_eq!(picked.family(), Family::V604);
        assert_eq!(picked.messages().len(), 1, "{:?}", picked.messages());
        assert!(
            picked.messages()[0].contains("Detected Syslinux version: 6.04"),
            "{:?}",
            picked.messages()
        );
        assert!(
            picked.messages()[0].contains("/isolinux/isolinux.bin"),
            "{:?}",
            picked.messages()
        );
        assert!(picked.detected().is_some());
    }

    #[test]
    fn select_detected_old_without_c32_has_no_conflict() {
        let picked = select(Some(detected("4.07", "/isolinux/isolinux.bin")), false);
        assert_eq!(picked.family(), Family::V407);
        assert_eq!(picked.messages().len(), 1, "{:?}", picked.messages());
        assert!(
            !picked.messages()[0].contains("Conflict"),
            "{:?}",
            picked.messages()
        );
    }

    #[test]
    fn select_detected_new_without_c32_warns_conflict() {
        let picked = select(Some(detected("6.04", "/isolinux/isolinux.bin")), false);
        assert_eq!(picked.family(), Family::V604);
        assert_eq!(picked.messages().len(), 2, "{:?}", picked.messages());
        assert!(
            picked.messages()[1].contains("Conflict between Isolinux version"),
            "{:?}",
            picked.messages()
        );
    }

    #[test]
    fn select_detected_old_with_c32_warns_conflict() {
        let picked = select(Some(detected("4.07", "/isolinux/isolinux.bin")), true);
        assert_eq!(picked.family(), Family::V407);
        assert_eq!(picked.messages().len(), 2, "{:?}", picked.messages());
        assert!(
            picked.messages()[1].contains("Conflict between Isolinux version"),
            "{:?}",
            picked.messages()
        );
    }

    #[test]
    fn select_undetected_forces_from_c32_presence() {
        let with = select(None, true);
        assert_eq!(with.family(), Family::V604);
        assert_eq!(with.messages().len(), 1, "{:?}", with.messages());
        assert!(
            with.messages()[0].contains("Could not detect Isolinux version - Forcing to 6.04"),
            "{:?}",
            with.messages()
        );
        assert!(with.detected().is_none());

        let without = select(None, false);
        assert_eq!(without.family(), Family::V407);
        assert!(
            without.messages()[0].contains("Could not detect Isolinux version - Forcing to 4.07"),
            "{:?}",
            without.messages()
        );
    }

    #[test]
    fn select_malformed_falls_back_to_c32_rule() {
        let picked = select(Some(detected("bogus", "/isolinux/isolinux.bin")), true);
        assert_eq!(picked.family(), Family::V604);
        assert_eq!(picked.messages().len(), 1, "{:?}", picked.messages());
        assert!(
            picked.messages()[0].contains("Could not detect Isolinux version - Forcing to 6.04"),
            "{:?}",
            picked.messages()
        );
        assert!(picked.detected().is_none());
    }

    /// In-memory [`Source`] over explicit listings and file bytes.
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
        fn root_entries(&self) -> Result<Vec<Entry>> {
            match self.dirs.get(&Vec::new()) {
                Some(entries) => Ok(entries.clone()),
                None => Err(CoreError::invalid("no such directory".to_string())),
            }
        }

        fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            match self.dirs.get(dir) {
                Some(entries) => Ok(entries.clone()),
                None => Err(CoreError::invalid("no such directory".to_string())),
            }
        }

        fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
            let bytes = match self.files.get(file) {
                Some(bytes) => bytes,
                None => {
                    return Err(CoreError::invalid("no such file".to_string()));
                }
            };
            let at = usize::try_from(offset)
                .map_err(|_| CoreError::invalid("offset does not fit".to_string()))?;
            if at > bytes.len() {
                return Err(CoreError::invalid("offset past end".to_string()));
            }
            let rest = &bytes[at..];
            let take = rest.len().min(buf.len());
            buf[..take].copy_from_slice(&rest[..take]);
            Ok(take)
        }
    }

    fn isolinux_tree() -> MemSource {
        MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux"), dir_entry(b"boot")])
            .with_dir(
                &[b"isolinux"],
                vec![
                    file_entry(b"isolinux.bin", 4),
                    file_entry(b"isolinux.cfg", 3),
                ],
            )
            .with_dir(&[b"boot"], vec![dir_entry(b"isolinux")])
            .with_dir(
                &[b"boot", b"isolinux"],
                vec![file_entry(b"syslinux.cfg", 2)],
            )
            .with_file(&[b"isolinux", b"isolinux.bin"], b"bin!")
            .with_file(&[b"isolinux", b"isolinux.cfg"], b"cfg")
            .with_file(&[b"boot", b"isolinux", b"syslinux.cfg"], b"hi")
    }

    #[test]
    fn locate_prefers_first_candidate() {
        let found = locate(&isolinux_tree())
            .expect("locate reads")
            .expect("a payload dir exists");
        assert_eq!(
            found.dir(),
            &[b"isolinux".to_vec()],
            "the first candidate wins"
        );
        assert_eq!(found.path(), "/isolinux");
        assert_eq!(found.messages().len(), 1);
        assert_eq!(
            found.messages()[0],
            "  Will use '/isolinux' for Syslinux",
            "the Will use line carries the path"
        );
        assert!(found.messages()[0].is_ascii(), "messages stay ASCII");
    }

    #[test]
    fn locate_skips_a_file_named_isolinux() {
        // A plain file named `isolinux` at the root is not a directory:
        // the lookup must fall through to `boot/isolinux`.
        let source = MemSource::new()
            .with_dir(&[], vec![file_entry(b"isolinux", 5), dir_entry(b"boot")])
            .with_dir(&[b"boot"], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"boot", b"isolinux"], vec![file_entry(b"ldlinux.c32", 1)]);
        let found = locate(&source)
            .expect("locate reads")
            .expect("the second candidate exists");
        assert_eq!(
            found.dir(),
            &[b"boot".to_vec(), b"isolinux".to_vec()],
            "a file of that name never counts"
        );
        assert_eq!(found.path(), "/boot/isolinux");
    }

    #[test]
    fn locate_skips_a_directory_without_markers() {
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![file_entry(b"other.txt", 1)]);
        assert!(
            locate(&source).expect("locate reads").is_none(),
            "a directory without any marker file is skipped"
        );
    }

    #[test]
    fn locate_returns_none_when_nothing_matches() {
        let source = MemSource::new().with_dir(&[], vec![file_entry(b"a.txt", 1)]);
        assert!(
            locate(&source).expect("locate reads").is_none(),
            "a tree with no payload dir reads as none"
        );
    }

    #[test]
    fn read_returns_exact_bytes_and_none_for_missing() {
        let source = isolinux_tree();
        let dir = vec![b"isolinux".to_vec()];
        let bytes = read(&source, &dir, "isolinux.bin")
            .expect("present reads")
            .expect("present is some");
        assert_eq!(bytes, b"bin!");
        assert!(
            read(&source, &dir, "missing.cfg")
                .expect("missing reads")
                .is_none(),
            "a missing name reads as none"
        );
    }

    #[test]
    fn read_returns_none_for_a_directory() {
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(
                &[b"isolinux"],
                vec![dir_entry(b"isolinux.cfg"), file_entry(b"ldlinux.c32", 1)],
            );
        let dir = vec![b"isolinux".to_vec()];
        assert!(
            read(&source, &dir, "isolinux.cfg")
                .expect("a directory reads")
                .is_none(),
            "a directory of that name reads as none"
        );
    }

    #[test]
    fn read_refuses_separators_and_reserved_names() {
        let source = isolinux_tree();
        let dir = vec![b"isolinux".to_vec()];
        for bad in ["a/b", "..", "a\0b"] {
            let error = read(&source, &dir, bad).expect_err("bad names refuse");
            let text = error.to_string();
            assert!(text.is_ascii(), "error stays ASCII: {text:?}");
            assert!(text.contains("refuses"), "error refuses: {text:?}");
        }
        let backslash = read(&source, &dir, "a\\b").expect_err("backslash refuses");
        assert!(backslash.to_string().contains("refuses"));
    }

    #[test]
    fn read_spans_more_than_one_window() {
        // 10 000 bytes need three 4 KiB windows (4096 + 4096 + 1808):
        // the chunks must join back into the exact file bytes.
        let bytes: Vec<u8> = (0..10_000).map(|index| (index % 251) as u8).collect();
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(
                &[b"isolinux"],
                vec![file_entry(b"isolinux.cfg", bytes.len() as u64)],
            )
            .with_file(&[b"isolinux", b"isolinux.cfg"], &bytes);
        let dir = vec![b"isolinux".to_vec()];
        let read = read(&source, &dir, "isolinux.cfg")
            .expect("a multi-window file reads")
            .expect("present is some");
        assert_eq!(read, bytes, "every window lands in order");
    }

    #[test]
    fn read_refuses_a_file_past_the_cap() {
        // The listing alone drives the refusal: no file bytes are ever
        // read, so none are seeded.
        let over = MAX_READ_BYTES + 1;
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![file_entry(b"big.bin", over)]);
        let dir = vec![b"isolinux".to_vec()];
        let error = read(&source, &dir, "big.bin").expect_err("past the cap refuses");
        let text = error.to_string();
        assert!(text.contains("1 MiB"), "the refusal names the cap: {text}");
        assert!(
            text.contains(&over.to_string()),
            "the refusal names the size: {text}"
        );
    }

    #[test]
    fn read_refuses_a_short_read() {
        // The listing claims 100 bytes but the store holds 10: the
        // second window reads 0 bytes, which is corruption, not EOF.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![file_entry(b"short.bin", 100)])
            .with_file(&[b"isolinux", b"short.bin"], b"0123456789");
        let dir = vec![b"isolinux".to_vec()];
        let error = read(&source, &dir, "short.bin").expect_err("a short read refuses");
        let text = error.to_string();
        assert!(
            text.contains("short read"),
            "the refusal names the shape: {text}"
        );
    }

    #[test]
    fn locate_ignores_a_symlink_marker() {
        // A symlink named like a marker is not a holder: the directory
        // reads as marker-less, so the lookup finds nothing.
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![link_entry(b"isolinux.bin")]);
        assert!(
            locate(&source).expect("locate reads").is_none(),
            "a symlink marker never locates a payload directory"
        );
    }

    #[test]
    fn read_treats_a_symlink_as_absent() {
        let source = MemSource::new()
            .with_dir(&[], vec![dir_entry(b"isolinux")])
            .with_dir(&[b"isolinux"], vec![link_entry(b"isolinux.cfg")]);
        let dir = vec![b"isolinux".to_vec()];
        assert!(
            read(&source, &dir, "isolinux.cfg")
                .expect("a symlink reads")
                .is_none(),
            "a symlink of that name reads as absent"
        );
    }
}
