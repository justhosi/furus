//! Mount state without /bin/mount: `/proc/self/mountinfo`, `/proc/swaps`
//! and sysfs holders (S05).
//!
//! Rufus on Windows learns what a device is *in use for* from the
//! Win32 API (volumes in use, pagefile, active swap); on Linux the same
//! questions are file parsing plus one sysfs walk. This module owns
//! them all:
//!
//! * [`MountTable`] — the mount table from `/proc/self/mountinfo`
//!   (device number → mountpoint), from which
//!   [`protected_devices`](MountTable::protected_devices) derives the
//!   device numbers backing the running system;
//! * [`SwapEntry`] rows from `/proc/swaps`, matched per device with
//!   [`swap_for`];
//! * [`holders`] — the kernel names of everything stacked *on top* of a
//!   device (dm-crypt, LVM, mdraid, bcache).
//!
//! Nothing here spawns a process, and every string that comes out of a
//! file goes through [`rufus_core::text::device_text`]: mount data,
//! swap filenames and holder names are all device/kernel-supplied text
//! that ends up in one-line reports and log files.
//!
//! # Parsing contracts
//!
//! `/proc/self/mountinfo` is one line per mount with six mandatory
//! fields before a `-` separator and three after it:
//!
//! ```text
//! id parent major:minor root mountpoint options [optional...] - fstype source superopts
//! ```
//!
//! The kernel escapes whitespace, backslash and newline *inside* a field
//! as one of four octal forms (`\040` space, `\011` tab, `\012` newline,
//! `\134` backslash), which is exactly what makes naive whitespace
//! splitting safe: a raw `\040` cannot become a field boundary. Fields
//! are therefore split on raw whitespace first and octal-unescaped
//! afterwards, in one pass (a decoded `\134` backslash is literal,
//! never re-expanded), and any other backslash sequence is malformed —
//! the kernel emits only the four forms, so anything else is rot, and
//! the parser refuses the line instead of guessing.
//!
//! `/proc/swaps` is a single header row plus five-column body lines; a
//! body line that is not five columns of the right shapes is malformed,
//! reported with its 1-based line number.

use std::fs;
use std::io;
use std::path::Path;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::text::device_text;

use crate::sysfs::SysfsRoot;

/// Where the mount table lives when the caller does not supply a file.
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
/// Where the swap table lives when the caller does not supply a file.
const SWAPS_PATH: &str = "/proc/swaps";
/// Mandatory mountinfo fields before the `-` separator: id, parent,
/// device number, root, mountpoint, mount options.
const MOUNTINFO_REQUIRED_BEFORE: usize = 6;
/// Mandatory mountinfo fields after the separator: fstype, source,
/// superblock options.
const MOUNTINFO_REQUIRED_AFTER: usize = 3;
/// Mandatory /proc/swaps fields: filename, kind, size, used, priority.
const SWAPS_FIELDS: usize = 5;

/// A Linux device number: `(major, minor)` as the kernel reports it.
pub type DevNum = (u32, u32);

/// One parsed `/proc/self/mountinfo` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Device `major` number.
    pub major: u32,
    /// Device `minor` number.
    pub minor: u32,
    /// Mount point. Already octal-unescaped *and* sanitised through
    /// [`device_text`] — the two steps every kernel-supplied string that
    /// reaches a report needs, done once here.
    pub mountpoint: String,
    /// Filesystem type of the mount.
    pub fstype: String,
    /// Mount source as the kernel reports it (device path or virtual
    /// source name such as `tmpfs`).
    pub source: String,
    /// Mount options; the optional fields between options and the `-`
    /// separator (shared/master ids) ride along, joined with spaces, so
    /// nothing the kernel reports is silently dropped.
    pub options: String,
}

impl MountEntry {
    /// The `(major, minor)` device number of the mount.
    #[must_use]
    pub fn devnum(&self) -> DevNum {
        (self.major, self.minor)
    }
}

/// The whole mount table, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    /// Strict parse: a non-empty malformed line is a
    /// [`CoreError::InvalidInput`] naming the 1-based line. Empty lines
    /// are skipped (blank separators, trailing newline).
    pub fn parse(text: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            entries.push(parse_mountinfo_line(index + 1, line)?);
        }
        Ok(Self { entries })
    }

    /// Read and parse a mountinfo file. `None` reads
    /// `/proc/self/mountinfo`; a fixture path parses the same table the
    /// kernel's own `fs/proc_namespace.c` would print. `None` follows
    /// the thread-group leader's namespace, so a caller that unshared
    /// from a non-leader thread must pass the thread-specific path
    /// (such as `/proc/thread-self/mountinfo`) instead.
    pub fn read(path: Option<&Path>) -> Result<Self> {
        let path = path.unwrap_or_else(|| Path::new(MOUNTINFO_PATH));
        let text = fs::read_to_string(path).map_err(|err| CoreError::io(path, err))?;
        Self::parse(&text)
    }

    /// The parsed entries, in file order.
    #[must_use]
    pub fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    /// First entry whose `major:minor` matches, in file order. A device
    /// mounted more than once surfaces its first mount only.
    #[must_use]
    pub fn mount_of(&self, dev: DevNum) -> Option<&MountEntry> {
        self.entries.iter().find(|entry| entry.devnum() == dev)
    }

    /// Device numbers backing the running system: entries whose
    /// mountpoint is `/` or lies inside `/boot`, `/usr` or `/var`,
    /// path-boundary aware (`/boot/efi` and `/usr/local` count;
    /// `/bootable` and `/various` do not). First occurrence wins, so a
    /// device mounted at two system paths is reported once.
    #[must_use]
    pub fn protected_devices(&self) -> Vec<DevNum> {
        let mut devices: Vec<DevNum> = Vec::new();
        for entry in &self.entries {
            if !mounts_system_prefix(&entry.mountpoint) {
                continue;
            }
            if !devices.contains(&entry.devnum()) {
                devices.push(entry.devnum());
            }
        }
        devices
    }
}

/// Whether a (already sanitised, kernel-reported) mountpoint is the
/// system root or lies inside one of the prefix directories whose
/// content survives a reboot.
fn mounts_system_prefix(mountpoint: &str) -> bool {
    const SYSTEM_PREFIXES: [&str; 3] = ["/boot", "/usr", "/var"];
    if mountpoint == "/" {
        return true;
    }
    // Boundary aware: the prefix either matches exactly or is followed
    // by a path separator — `/boot/efi` keeps the boundary, `/bootable`
    // is a different directory name.
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| match mountpoint.strip_prefix(prefix) {
            Some(rest) => rest.is_empty() || rest.starts_with('/'),
            None => false,
        })
}

/// One kernel octal escape, decoded: `\040` space, `\011` tab, `\012`
/// newline, `\134` backslash. Returns `None` for every other sequence —
/// the kernel emits only these four, and the parser refuses guesses.
fn unescape_octal(after_backslash: &[u8]) -> Option<char> {
    let forms = after_backslash.get(..3)?;
    match forms {
        b"040" => Some(' '),
        b"011" => Some('\t'),
        b"012" => Some('\n'),
        b"134" => Some('\\'),
        _ => None,
    }
}

/// Decode all kernel octal escapes in one whitespace-separated field.
///
/// Single pass: a decoded `\134` backslash is literal, and the bytes
/// that follow it are never re-expanded. `None` on any escape that is
/// not one of the four kernel forms, or a dangling backslash.
fn unescape_field(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut decoded = String::with_capacity(raw.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            let escape = unescape_octal(bytes.get(cursor + 1..)?)?;
            decoded.push(escape);
            cursor += 4;
        } else {
            // Non-ASCII bytes ride along lossy; the shared sanitiser
            // applied to every field below neutralises them.
            let unit = decoded_len(&raw[cursor..]);
            decoded.push_str(&raw[cursor..cursor + unit]);
            cursor += unit;
        }
    }
    Some(decoded)
}

/// Length in bytes of the first char of `text` (`0` for empty; the call
/// sites pass non-empty remainders). A `str` slice always starts at a
/// char boundary here because the cursor advances on UTF-8 boundaries
/// only, so this cannot split a character — the safe spelling of
/// `next().unwrap_or(1)`.
fn decoded_len(text: &str) -> usize {
    text.chars().next().map_or(0, char::len_utf8)
}

/// Parse one non-empty mountinfo line.
fn parse_mountinfo_line(line_number: usize, line: &str) -> Result<MountEntry> {
    let malformed = |what: &str| {
        CoreError::invalid(format!("mountinfo line {line_number} is malformed: {what}"))
    };
    // Split first, unescape after (see the module header): the kernel
    // escapes whitespace inside fields precisely so raw whitespace
    // tokens stay field boundaries.
    let mut tokens: Vec<String> = Vec::new();
    for raw in line.split_whitespace() {
        tokens.push(unescape_field(raw).ok_or_else(|| malformed("bad octal escape"))?);
    }
    // The separator is the first standalone `-` token; everything before
    // it needs the mandatory fields, everything after exactly fstype +
    // source + superblock options.
    let Some(separator) = tokens.iter().position(|token| token == "-") else {
        return Err(malformed("no '-' separator"));
    };
    if separator < MOUNTINFO_REQUIRED_BEFORE {
        return Err(malformed("fields before '-' are too few"));
    }
    if tokens.len() != separator + 1 + MOUNTINFO_REQUIRED_AFTER {
        return Err(malformed(
            "fields after '-' must be fstype, source, superopts",
        ));
    }
    let Some((major, minor)) = parse_devnum(&tokens[2]) else {
        return Err(malformed("major:minor is not digits:digits"));
    };
    // Every kernel string is device text: sanitise all of them, even
    // the ones (fstype, options) no report string interpolates yet.
    let mut options = tokens[5].clone();
    for optional in &tokens[MOUNTINFO_REQUIRED_BEFORE..separator] {
        options.push(' ');
        options.push_str(optional);
    }
    Ok(MountEntry {
        major,
        minor,
        mountpoint: device_text(&tokens[4]),
        fstype: device_text(&tokens[separator + 1]),
        source: device_text(&tokens[separator + 2]),
        options: device_text(&options),
    })
}

/// Parse `major:minor` and reject anything else, mirroring the S04
/// `udev_db::is_valid_major_minor` contract: digits on both sides of one
/// colon, then plain `u32`s (a digit soup that overflows is not a device
/// number the kernel reported).
fn parse_devnum(text: &str) -> Option<DevNum> {
    let (major, minor) = text.split_once(':')?;
    if major.is_empty() || minor.is_empty() {
        return None;
    }
    if !major.bytes().all(|b| b.is_ascii_digit()) || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// One parsed `/proc/swaps` body line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    /// Swap-on path as the kernel reports it (`/dev/sdb1`, a swapfile...).
    pub filename: String,
    /// `partition` or `file`.
    pub kind: String,
    /// Total swap space in KiB.
    pub size_kib: u64,
    /// Currently used swap space in KiB.
    pub used_kib: u64,
    /// Swap priority (negative for kernel defaults).
    pub priority: i32,
}

/// Parse `/proc/swaps` text. The `Filename` header line is skipped; a
/// malformed body line is a [`CoreError::InvalidInput`] naming the
/// 1-based line. Empty lines are skipped.
pub fn parse_swaps(text: &str) -> Result<Vec<SwapEntry>> {
    let mut swaps = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let malformed = |what: &str| {
            CoreError::invalid(format!("swaps line {} is malformed: {what}", index + 1))
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"Filename") {
            continue; // the header row
        }
        if fields.len() != SWAPS_FIELDS {
            return Err(malformed(
                "body lines have five fields (filename, kind, size, used, priority)",
            ));
        }
        let size_kib = fields[2]
            .parse()
            .map_err(|_not_a_number| malformed("size is not a number"))?;
        let used_kib = fields[3]
            .parse()
            .map_err(|_not_a_number| malformed("used is not a number"))?;
        let priority = fields[4]
            .parse()
            .map_err(|_not_a_number| malformed("priority is not a number"))?;
        swaps.push(SwapEntry {
            filename: device_text(fields[0]),
            kind: device_text(fields[1]),
            size_kib,
            used_kib,
            priority,
        });
    }
    Ok(swaps)
}

/// Read and parse a swaps file. `None` reads `/proc/swaps`.
pub fn read_swaps(path: Option<&Path>) -> Result<Vec<SwapEntry>> {
    let path = path.unwrap_or_else(|| Path::new(SWAPS_PATH));
    let text = fs::read_to_string(path).map_err(|err| CoreError::io(path, err))?;
    parse_swaps(&text)
}

/// The [`SwapEntry`], if any, that covers a device: an exact `dev_path`
/// match (`/dev/sdb1`), or a basename match with the kernel name
/// (`sdb1`) for sources the kernel spells differently.
#[must_use]
pub fn swap_for<'a>(entries: &'a [SwapEntry], dev_path: &str, name: &str) -> Option<&'a SwapEntry> {
    entries.iter().find(|entry| {
        entry.filename == dev_path
            || Path::new(&entry.filename)
                .file_name()
                .is_some_and(|base| base == name)
    })
}

/// Kernel names in `<root>/class/block/<name>/holders` (`dm-0`, `md127`,
/// `bcache0`...), sorted. A missing directory is an empty list, not an
/// error — "nothing holds this device" is the normal answer. An unsafe
/// `name` (not one plain path component) is refused the same way, so a
/// hostile kernel name can never steer this lookup outside sysfs.
pub fn holders(sysfs: &SysfsRoot, name: &str) -> Result<Vec<String>> {
    if !is_safe_name(name) {
        return Ok(Vec::new());
    }
    let dir = sysfs.class_block().join(name).join("holders");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        // No holders directory: the normal "nothing stacked on top".
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(CoreError::io(&dir, err)),
    };
    let mut names = Vec::new();
    for entry in entries {
        // A holder entry that races a teardown is skipped, never fatal.
        let Ok(entry) = entry else { continue };
        let raw = entry.file_name().to_string_lossy().into_owned();
        names.push(device_text(&raw));
    }
    names.sort();
    Ok(names)
}

/// The `dev` attribute of a class entry (`"8:16"`), as a device number.
///
/// `Ok(None)` when the attribute is absent or unparseable — cheap
/// readers and fixture trees omit `dev` freely, and both shapes mean
/// "this lookup has nothing to say". Garbage that is *present* counts as
/// unparseable rather than as an error; anything but digits:digits is
/// refused (the S04 `is_valid_major_minor` contract).
pub fn dev_number(sysfs: &SysfsRoot, name: &str) -> Result<Option<DevNum>> {
    if !is_safe_name(name) {
        return Ok(None);
    }
    let path = sysfs.class_block().join(name).join("dev");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        // A vanished hotplug entry or a fixture without the attribute:
        // absence is an answer, not a failure.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CoreError::io(&path, err)),
    };
    Ok(parse_devnum(&device_text(&text)))
}

/// Whether `name` is exactly one plain path component — the guard for
/// every `<root>/class/block/<name>` interpolation here (the same idea
/// as the `udev_db` record-file guard, which keeps `b8:16` a filename).
fn is_safe_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/')
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::CoreError;
    use super::MountEntry;
    use super::MountTable;
    use super::SwapEntry;
    use super::dev_number;
    use super::holders;
    use super::parse_swaps;
    use super::swap_for;
    use crate::sysfs::SysfsRoot;

    /// A minimal mountinfo line: six fields before `-`, three after.
    fn line(majmin: &str, mountpoint: &str) -> String {
        format!("1 0 {majmin} / {mountpoint} rw,relatime - vfat /dev/x rw")
    }

    /// Parse a fixture of already well-formed lines (panics in tests).
    fn table(lines: &str) -> MountTable {
        MountTable::parse(lines).expect("fixture table parses")
    }

    // ------------------------------------------------------------------
    // mountinfo parsing
    // ------------------------------------------------------------------

    #[test]
    fn mountinfo_octal_escapes_decode_inside_fields() {
        // The kernel escapes a literal space in the mountpoint as a
        // `\040`, which must NOT become a field boundary.
        let parsed = table("36 1 8:17 / /media/my\\040stick rw,relatime - vfat /dev/sdb1 rw");
        assert_eq!(
            parsed.entries(),
            vec![MountEntry {
                major: 8,
                minor: 17,
                mountpoint: "/media/my stick".to_owned(),
                fstype: "vfat".to_owned(),
                source: "/dev/sdb1".to_owned(),
                options: "rw,relatime".to_owned(),
            }],
        );
    }

    #[test]
    fn mountinfo_all_four_escapes_and_a_literal_backslash() {
        let parsed = table("1 0 8:1 / /m\\011n\\012x\\134y rw - t /dev/x rw");
        // The decoded tab/newline are real whitespace now — the output
        // sanitiser turns them into `?` before anyone reports them.
        assert_eq!(parsed.entries()[0].mountpoint, "/m?n?x\\y");
        // \134 decodes to a literal backslash that is NOT re-expanded:
        // `\134040` is backslash followed by the digits "040".
        let parsed = table("1 0 8:1 / /a\\134040b rw - t /dev/x rw");
        assert_eq!(parsed.entries()[0].mountpoint, "/a\\040b");
    }

    #[test]
    fn mountinfo_optional_fields_before_the_separator() {
        let parsed =
            table("18 11 8:17 / /media/sd rw,relatime shared:9 master:4 - vfat /dev/sdb1 rw");
        // Optionals ride along in `options`, joined with spaces.
        assert_eq!(parsed.entries()[0].options, "rw,relatime shared:9 master:4");
    }

    #[test]
    fn mountinfo_lookup_first_match_wins_in_file_order() {
        let parsed = table(&format!(
            "{}\n{}",
            line("8:17", "/first"),
            line("8:17", "/second"),
        ));
        assert_eq!(
            parsed.mount_of((8, 17)).map(|m| m.mountpoint.as_str()),
            Some("/first"),
            "file order, not best match"
        );
        assert!(
            parsed.mount_of((9, 9)).is_none(),
            "no entry for another device"
        );
    }

    #[test]
    fn mountinfo_malformed_lines_carry_their_numbers() {
        // Too few fields before the separator.
        let err = MountTable::parse("1 0 8:1 / /m").expect_err("too short");
        assert!(err.to_string().contains("line 1"), "{err}");

        // No separator at all.
        let err = MountTable::parse("1 0 8:1 / /m rw vfat /dev/x rw").expect_err("no separator");
        assert!(err.to_string().contains("line 1"), "{err}");

        // Devnum that is not digits:digits.
        let err = MountTable::parse("1 0 8:x / /m rw - vfat /dev/x rw").expect_err("devnum");
        assert!(err.to_string().contains("line 1"), "{err}");

        // Fields after the separator: exactly three.
        let err = MountTable::parse("1 0 8:1 / /m rw - vfat /dev/x rw extra").expect_err("extra");
        assert!(err.to_string().contains("line 1"), "{err}");

        // A bad octal escape is malformed, never a guess.
        let err = MountTable::parse("1 0 8:1 / /m\\777 rw - vfat /dev/x rw").expect_err("escape");
        assert!(err.to_string().contains("bad octal escape"), "{err}");

        // Later line: the number follows the line, not the failure.
        let text = "1 0 8:1 / / rw - vfat /dev/x rw\n2 0 bad:dev / /two rw - vfat /dev/x rw\n";
        let err = MountTable::parse(text).expect_err("second line");
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn mountinfo_empty_file_is_an_empty_table() {
        let parsed = table("\n\n");
        assert!(parsed.entries().is_empty(), "empty lines never parse");
    }

    #[test]
    fn mountinfo_read_uses_the_given_path_or_live_proc() {
        let scratch = tempfile::tempdir().expect("scratch");
        let path = scratch.path().join("mountinfo");
        fs::write(&path, line("8:16", "/fixture")).expect("fixture written");
        let parsed = MountTable::read(Some(&path)).expect("fixture reads");
        assert_eq!(parsed.entries()[0].mountpoint, "/fixture");

        // A missing explicit file is an Io error naming the path.
        let err = MountTable::read(Some(&scratch.path().join("nope"))).expect_err("missing file");
        assert!(matches!(err, CoreError::Io { .. }), "{err}");
        assert!(
            err.to_string().contains("nope"),
            "the missing path is named: {err}"
        );
    }

    /// The canary against real kernel output, run only where Linux
    /// itself printed the table this machine boots with.
    #[test]
    fn live_mountinfo_parses() {
        let live = MountTable::read(None).expect("live /proc/self/mountinfo");
        assert!(
            !live.entries().is_empty(),
            "a Linux /proc/self/mountinfo lists the running mounts"
        );
        assert!(
            !live.protected_devices().is_empty(),
            "the namespace's own root mount is in the table"
        );
    }

    #[test]
    fn protected_devices_cover_the_boundary_cases() {
        // /bootable and /various share prefixes but are NOT system
        // paths; /boot/efi and /usr/local sit inside them, past the
        // boundary.
        let parsed = table(
            "1 0 7:1 / /bootable rw - t /dev/x rw\n\
             2 0 7:2 / /boot/efi rw - t /dev/y rw\n\
             3 0 7:3 / /various rw - t /dev/z rw\n\
             4 0 7:4 / /var rw - t /dev/v rw\n\
             5 0 7:5 / /usr/local rw - t /dev/u rw\n\
             6 0 7:6 / /hidden rw - t /dev/h rw",
        );
        let mut devices = parsed.protected_devices();
        devices.sort_unstable();
        assert_eq!(devices, vec![(7, 2), (7, 4), (7, 5)]);

        // The root mount covers its device, and a device mounted at two
        // system paths collapses to one entry (first occurrence wins).
        let parsed = table(
            "1 0 9:1 / / rw - t /dev/root rw\n\
             2 0 9:1 / /boot rw - t /dev/root rw\n\
             3 0 9:2 / /various rw - t /dev/noise rw",
        );
        assert_eq!(parsed.protected_devices(), vec![(9, 1)]);
    }

    #[test]
    fn mount_strings_arrive_sanitised() {
        // Hostile bytes in kernel-supplied strings cannot reach a
        // one-line report: control/non-ASCII mapped to `?`.
        let parsed = table("1 0 8:1 / /mnt/\u{1b}bad\\012name rw - t /dev/x rw");
        assert_eq!(parsed.entries()[0].mountpoint, "/mnt/?bad?name");
    }

    // ------------------------------------------------------------------
    // swaps
    // ------------------------------------------------------------------

    fn swaps_fixture() -> Vec<SwapEntry> {
        parse_swaps(
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
             /dev/sdb1                        partition\t3000\t0\t-2\n",
        )
        .expect("fixture parses")
    }

    #[test]
    fn swaps_fields_map_and_the_header_is_skipped() {
        let swaps = swaps_fixture();
        assert_eq!(
            swaps,
            vec![SwapEntry {
                filename: "/dev/sdb1".to_owned(),
                kind: "partition".to_owned(),
                size_kib: 3000,
                used_kib: 0,
                priority: -2,
            }],
        );
        assert!(parse_swaps("").expect("empty file").is_empty());
    }

    #[test]
    fn swaps_malformed_body_lines_carry_their_numbers() {
        // A row shape: exactly five columns, every number parseable.
        let err =
            parse_swaps("Filename Type Size Used Priority\n/dev/sdb1 partition 3000 obviously\n")
                .expect_err("too few columns");
        assert!(err.to_string().contains("line 2"), "{err}");

        // Non-numeric values are malformed too.
        let err = parse_swaps("Filename Type Size Used Priority\n/dev/sdb1 partition xx 0 -2\n")
            .expect_err("bad number");
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn swap_for_matches_exact_and_basename() {
        let swaps = swaps_fixture();
        // Exact dev-path match.
        assert!(swap_for(&swaps, "/dev/sdb1", "sdb1").is_some());
        // Basename match when the caller spells the path differently.
        assert!(swap_for(&swaps, "/dev/elsewhere/sdb1", "sdb1").is_some());
        // No match for another device.
        assert!(swap_for(&swaps, "/dev/sdc1", "sdc1").is_none());
    }

    // ------------------------------------------------------------------
    // holders and dev numbers (synthetic sysfs tree)
    // ------------------------------------------------------------------

    struct Tree {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            // The path is captured before the handle moves into the
            // struct, so the directory dies with the test.
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Self {
                _scratch: scratch,
                root,
            }
        }

        fn sysfs(&self) -> SysfsRoot {
            SysfsRoot::new(self.root.clone())
        }

        /// One class entry `<name>` with its `dev` attribute (optional).
        fn seed_disk(&self, name: &str, dev: Option<&str>) {
            let dir = self.root.join("class").join("block").join(name);
            fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("mkdir {name}: {err}"));
            if let Some(dev) = dev {
                fs::write(dir.join("dev"), dev).unwrap_or_else(|err| panic!("seed {name}: {err}"));
            }
        }

        fn seed_holder(&self, disk: &str, holder: &str) {
            let dir = self
                .root
                .join("class")
                .join("block")
                .join(disk)
                .join("holders")
                .join(holder);
            fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("holder {holder}: {err}"));
        }
    }

    #[test]
    fn holders_lists_sorted_and_tolerates_a_missing_directory() {
        let tree = Tree::new();
        tree.seed_disk("sdb", Some("8:16"));
        tree.seed_holder("sdb", "md127");
        tree.seed_holder("sdb", "dm-0"); // deliberately out of order
        assert_eq!(
            holders(&tree.sysfs(), "sdb").expect("reads"),
            vec!["dm-0".to_owned(), "md127".to_owned()],
            "sorted kernel-name order, not readdir order"
        );

        // The non-default holder set sorts on its own members.
        let other = Tree::new();
        other.seed_disk("sda", Some("8:0"));
        other.seed_holder("sda", "bcache0");
        assert_eq!(
            holders(&other.sysfs(), "sda").expect("reads"),
            vec!["bcache0".to_owned()]
        );

        // No holders directory: empty, not an error.
        let no_holders = holders(&tree.sysfs(), "plain-disk").expect("reads");
        assert!(no_holders.is_empty());
        // A missing class entry behaves the same way.
        let gone = holders(&other.sysfs(), "gone").expect("reads");
        assert!(gone.is_empty());
    }

    #[test]
    fn dev_number_reads_digits_and_tolerates_absence_and_garbage() {
        let tree = Tree::new();
        tree.seed_disk("sdb", Some("8:16"));
        tree.seed_disk("fat-numbers", Some("99999999999999:1"));
        tree.seed_disk("nonsense", Some("not-a-device"));
        tree.seed_disk("no-colon", Some("816"));
        tree.seed_disk("bare", None); // no dev attribute at all

        let sysfs = tree.sysfs();
        assert_eq!(dev_number(&sysfs, "sdb").expect("reads"), Some((8, 16)));
        // Unparseable values answer None (absence semantics).
        assert_eq!(dev_number(&sysfs, "fat-numbers").expect("reads"), None);
        assert_eq!(dev_number(&sysfs, "nonsense").expect("reads"), None);
        assert_eq!(dev_number(&sysfs, "no-colon").expect("reads"), None);
        assert_eq!(dev_number(&sysfs, "bare").expect("reads"), None);
        // A missing class entry, too.
        assert_eq!(dev_number(&sysfs, "gone").expect("reads"), None);
    }
}
