//! Reading udev's flat data records without libudev (S04).
//!
//! `systemd-udevd` keeps one plain-text record per device under
//! `/run/udev/data/b<major>:<minor>`; its lines carry the same properties
//! libudev exposes (`ID_BUS`, `ID_SERIAL_SHORT`, `ID_MODEL`, ...). Parsing
//! them directly keeps this crate free of libudev FFI, and records become
//! plain fixture files in tests.
//!
//! A missing record is normal, never an error: udev may not run at all
//! (containers, minimal test fixtures) and sysfs alone already answers
//! most discovery questions. [`read_record`] therefore returns `None`
//! instead of a `Result` and callers simply skip the merge.

use std::fs;
use std::path::Path;

/// A parsed udev data record.
///
/// Deliberately *not* a `HashMap`: records hold a dozen properties and
/// callers ask for a handful of well-known keys, so a small typed view
/// keeps the public surface (and iteration-order commitments) minimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdevRecord {
    /// Parsed `KEY=value` pairs in file order.
    entries: Vec<(String, String)>,
}

impl UdevRecord {
    /// Value of `key`, or `None` when the record lacks it. Repeated keys
    /// surface the first occurrence, matching libudev's merge semantics.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find_map(|(known, value)| (known == key).then_some(value.as_str()))
    }
}

/// Whether `major_minor` is a well-formed `major:minor` pair (digits on
/// both sides of one colon). Guards the `b{major_minor}` filename below
/// against traversal (`..`, `/`) smuggled in through a sysfs `dev`
/// attribute.
pub(crate) fn is_valid_major_minor(text: &str) -> bool {
    let Some((major, minor)) = text.split_once(':') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

/// Read the record for `major_minor` (e.g. `"8:16"`) from `dir`, i.e. the
/// file `<dir>/b<major_minor>` (`/run/udev/data/b8:16` on a live system).
///
/// Returns `None` when the directory or the file is missing or unreadable
/// — see the module header for why that is not an error — and when
/// `major_minor` is not a `major:minor` pair (never a lookup path).
#[must_use]
pub fn read_record(dir: &Path, major_minor: &str) -> Option<UdevRecord> {
    if !is_valid_major_minor(major_minor) {
        return None;
    }
    let path = dir.join(format!("b{major_minor}"));
    let text = fs::read_to_string(&path).ok()?;
    Some(parse(&text))
}

/// Parse record text into a [`UdevRecord`].
///
/// Real records are `KEY=value` lines with an `E:` prefix on the
/// environment entries and metadata lines without `=` (an `I:` header,
/// `S:` symlinks, ...); blanks and `#` comments are ignored and every
/// entry is split at the **first** `=` so values may contain further
/// ones. Both `KEY=value` and `E:KEY=value` forms map to the same key.
fn parse(text: &str) -> UdevRecord {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((raw_key, value)) = line.split_once('=') else {
            // Header/symlink/metadata lines carry no property.
            continue;
        };
        let key = raw_key.strip_prefix("E:").unwrap_or(raw_key).trim();
        if key.is_empty() {
            continue;
        }
        entries.push((key.to_string(), value.to_string()));
    }
    UdevRecord { entries }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::is_valid_major_minor;
    use super::parse;
    use super::read_record;

    #[test]
    fn keys_and_values_split_at_the_first_equals_sign() {
        let record = parse(
            "I:1022\n\
             E:ID_BUS=usb\n\
             E:ID_PART_TABLE_TYPE=gpt\n\
             E:KEY_WITH=IN=VALUE=deep\n",
        );
        assert_eq!(record.get("ID_BUS"), Some("usb"));
        assert_eq!(record.get("ID_PART_TABLE_TYPE"), Some("gpt"));
        assert_eq!(
            record.get("KEY_WITH"),
            Some("IN=VALUE=deep"),
            "only the first '=' separates"
        );
        assert_eq!(record.get("I"), None, "header lines are not properties");
        assert_eq!(record.get("MISSING"), None);
    }

    #[test]
    fn blanks_comments_and_prefixless_lines_are_tolerated() {
        let record = parse("\n\n# a comment\n   \nKEY=value\n");
        assert_eq!(record.get("KEY"), Some("value"));
        assert_eq!(record.entries.len(), 1, "nothing else was stored");
    }

    #[test]
    fn record_files_and_the_e_prefix_work_together() {
        // A realistic /run/udev/data/b8:16 record.
        let dir = tempfile::tempdir().expect("scratch dir");
        fs::write(
            dir.path().join("b8:16"),
            "I:56732\n\
             E:ID_BUS=usb\n\
             E:ID_SERIAL_SHORT=4C530001120202116584\n",
        )
        .expect("seed record");
        let record = read_record(dir.path(), "8:16").expect("record exists");
        assert_eq!(record.get("ID_SERIAL_SHORT"), Some("4C530001120202116584"));

        // Missing file and missing directory are None, not errors.
        assert_eq!(read_record(dir.path(), "7:0"), None);
        assert_eq!(read_record(Path::new("/no/such/data"), "8:16"), None);
    }

    #[test]
    fn malformed_major_minor_never_hits_the_filesystem() {
        let dir = tempfile::tempdir().expect("scratch dir");
        // A decoy filed under a bad key must never be read: the guard
        // runs before the lookup.
        fs::write(dir.path().join("bnot-a-device"), "E:ID_BUS=usb\n").expect("seed decoy");
        for bad in [
            "", "8", "8:", ":16", "8:16:1", "8:x", "x:16", "../evil", "8/16", "b8:16", " 8:16",
            "8:16 ",
        ] {
            assert!(!is_valid_major_minor(bad), "key {bad:?} is malformed");
            assert_eq!(
                read_record(dir.path(), bad),
                None,
                "key {bad:?} must not look up"
            );
        }
        assert!(is_valid_major_minor("8:16"));
        assert!(is_valid_major_minor("0:0"));
    }
}
