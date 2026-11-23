//! One shared volume-label validator and sanitiser (S36.1).
//!
//! Every filesystem write path has its own label ceiling, but a plan is
//! sealed — and the helper gates it — before any of those formatters run.
//! Without a single shared rule an overlong label (for example the
//! 18-byte `Fedora-KDE-Live-45`) survives planning, wipe and mkpart run,
//! and only `mkfs` refuses at the very end, after the device has already
//! been destroyed. This module is that one rule: [`validate_label`]
//! refuses before anything destructive, and [`sanitize_label`] offers a
//! best-effort clean-up for callers that can afford to change the label.
//!
//! The rules below are taken from the repo's *actual* on-disk encoders,
//! not from the rough sketch in the PLAN:
//!
//! * FAT32 — [`crate::fs::fat32::bpb`] keeps an 11-byte ASCII field and
//!   rejects controls, non-ASCII and the Windows-forbidden characters;
//! * exFAT — [`crate::fs::exfat::format`] keeps 11 UTF-16 units and
//!   rejects controls plus the same forbidden characters;
//! * ext2/3/4 — [`crate::fs::ext`] requires ASCII and at most 16 bytes;
//! * NTFS — [`crate::fs::ntfs`] passes the label to `mkntfs -L` and
//!   reads it back as UTF-16; the format's own ceiling is 32 units;
//! * UDF — [`crate::fs::udf`] allows UTF-8 up to 126 bytes.
//!
//! Two deliberate differences from the prose spec are pinned here:
//!
//! * the spec calls ext's ceiling "16 UTF-8 bytes"; the repo's
//!   [`crate::fs::ext::Options::with_label`] checks `is_ascii()`, so the
//!   shared rule is 16 **ASCII** bytes (a stricter, on-disk-grounded
//!   rule). A multi-byte UTF-8 label is refused rather than silently
//!   accepted and then mangled by `mke2fs`;
//! * the spec calls UDF's ceiling "30 bytes"; the repo measured 126
//!   bytes with `mkudffs` ([`crate::fs::udf::Options::with_label`]), so
//!   126 is the real limit. The 30-byte figure is stale.
//!
//! exFAT's encoder does not reject DEL (`U+007F`), but FAT32 does. The
//! shared validator rejects it for exFAT too and the sanitiser strips
//! it, so one printable-ASCII rule applies everywhere it is meaningful
//! rather than a format-specific surprise.

use furus_proto::Filesystem;

use crate::error::CoreError;

/// Characters Windows forbids in a volume label: `" * / : < > ? \ |`.
/// The same nine bytes the FAT32 encoder's `FORBIDDEN_LABEL_CHARS` names.
const FORBIDDEN: [char; 9] = ['"', '*', '/', ':', '<', '>', '?', '\\', '|'];

/// Windows-forbidden bytes, for the byte-oriented FAT32 check.
const FORBIDDEN_BYTES: [u8; 9] = [0x22, 0x2A, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x5C, 0x7C];

/// exFAT's UTF-16 analogue of [`FORBIDDEN_BYTES`].
const FORBIDDEN_UNITS: [u16; 9] = [0x22, 0x2A, 0x2F, 0x3A, 0x3C, 0x3E, 0x3F, 0x5C, 0x7C];

fn forbidden(c: char) -> bool {
    FORBIDDEN.contains(&c)
}

/// Validate `label` against the on-disk rules of `fs`.
///
/// An empty label means "no label" for every filesystem and is always
/// accepted — the encoders all map `Some("")` to their no-label state
/// (UDF is the one exception that stores the empty string verbatim,
/// which is still valid). Every refusal is a
/// [`CoreError::InvalidInput`] naming the limit or the offending
/// character, so the planner can surface it as a usage error and the
/// helper as `invalid_label` without losing the reason.
pub fn validate_label(label: &str, fs: Filesystem) -> Result<(), CoreError> {
    if label.is_empty() {
        return Ok(());
    }
    match fs {
        Filesystem::Fat32 => validate_fat32(label),
        Filesystem::Exfat => validate_exfat(label),
        Filesystem::Ext2 | Filesystem::Ext3 | Filesystem::Ext4 => validate_ext(label),
        Filesystem::Ntfs => validate_ntfs(label),
        Filesystem::Udf => validate_udf(label),
    }
}

fn validate_fat32(label: &str) -> Result<(), CoreError> {
    let bytes = label.as_bytes();
    if bytes.len() > 11 {
        return Err(CoreError::invalid(format!(
            "volume label is {} bytes long, the fat32 label field holds at most 11 ascii bytes",
            bytes.len()
        )));
    }
    for &byte in bytes {
        if byte < 0x20 || byte == 0x7F {
            return Err(CoreError::invalid(format!(
                "volume label carries a control byte (0x{byte:02X}), fat32 labels are plain ascii text"
            )));
        }
        if byte >= 0x80 {
            return Err(CoreError::invalid(
                "volume label carries a non-ascii byte, fat32 labels are plain ascii text",
            ));
        }
        if FORBIDDEN_BYTES.contains(&byte) {
            return Err(CoreError::invalid(format!(
                "volume label carries '{}' which windows forbids in a fat32 label",
                char::from(byte)
            )));
        }
    }
    Ok(())
}

fn validate_exfat(label: &str) -> Result<(), CoreError> {
    let units: Vec<u16> = label.encode_utf16().collect();
    if units.len() > 11 {
        return Err(CoreError::invalid(format!(
            "an exfat label holds 11 characters, this one needs {}",
            units.len()
        )));
    }
    for unit in units {
        // DEL is rejected here (but not by the exFAT encoder) so the
        // shared printable-ASCII rule is consistent with FAT32.
        if unit < 0x20 || unit == 0x7F || FORBIDDEN_UNITS.contains(&unit) {
            return Err(CoreError::invalid(format!(
                "an exfat label cannot contain the character U+{unit:04X}"
            )));
        }
    }
    Ok(())
}

fn validate_ext(label: &str) -> Result<(), CoreError> {
    // The spec says "16 UTF-8 bytes"; the repo's `Options::with_label`
    // also demands ASCII, and the on-disk `s_volume_name` is 16 bytes.
    if !label.is_ascii() {
        return Err(CoreError::invalid(
            "ext label must be at most 16 bytes of ascii (the on-disk s_volume_name field is 16 bytes)",
        ));
    }
    if label.len() > 16 {
        return Err(CoreError::invalid(format!(
            "ext label is {} bytes long, the label must be at most 16 bytes of ascii",
            label.len()
        )));
    }
    if label.as_bytes().contains(&0) {
        return Err(CoreError::invalid(
            "ext label carries a NUL byte, which terminates the on-disk label field",
        ));
    }
    Ok(())
}

fn validate_ntfs(label: &str) -> Result<(), CoreError> {
    let units = label.encode_utf16().count();
    if units > 32 {
        return Err(CoreError::invalid(format!(
            "an ntfs label holds 32 UTF-16 units, this one needs {units}"
        )));
    }
    if label.contains('\0') {
        return Err(CoreError::invalid(
            "an ntfs label cannot contain a NUL character",
        ));
    }
    Ok(())
}

fn validate_udf(label: &str) -> Result<(), CoreError> {
    // The spec's "30 bytes" is stale: `mkudffs` accepts 126 UTF-8 bytes
    // (see `fs::udf::Options::with_label`).
    if label.len() > 126 {
        return Err(CoreError::invalid(format!(
            "udf label is {} bytes long, the label must be at most 126 utf-8 bytes",
            label.len()
        )));
    }
    if label.contains('\0') {
        return Err(CoreError::invalid(
            "a udf label cannot contain a NUL character",
        ));
    }
    Ok(())
}

/// Best-effort clean-up of `raw` into a label [`validate_label`] accepts.
///
/// Characters the target filesystem cannot store are dropped (not
/// replaced), leading/trailing whitespace is trimmed, ASCII letters are
/// uppercased for FAT32, and the result is cut on the right boundary:
/// a UTF-8 character boundary for FAT32/ext/UDF, a whole UTF-16 unit
/// boundary for exFAT/NTFS (a surrogate pair is never split). The
/// contract `validate_label(&sanitize_label(raw, fs), fs).is_ok()` holds
/// for **any** input string, including one made entirely of rejected
/// characters — the result is then empty, which every filesystem treats
/// as "no label".
#[must_use]
pub fn sanitize_label(raw: &str, fs: Filesystem) -> String {
    match fs {
        Filesystem::Fat32 => {
            let kept: String = raw
                .chars()
                .filter(|c| c.is_ascii() && *c >= ' ' && *c != '\u{7f}' && !forbidden(*c))
                .collect();
            truncate_utf8(kept.trim().to_ascii_uppercase().as_str(), 11)
        }
        Filesystem::Exfat => {
            let kept: String = raw
                .chars()
                .filter(|c| *c >= ' ' && *c != '\u{7f}' && !forbidden(*c))
                .collect();
            truncate_utf16(kept.trim(), 11)
        }
        Filesystem::Ext2 | Filesystem::Ext3 | Filesystem::Ext4 => {
            let kept: String = raw.chars().filter(|c| c.is_ascii() && *c != '\0').collect();
            truncate_utf8(kept.trim(), 16)
        }
        Filesystem::Ntfs => {
            let kept: String = raw.chars().filter(|c| *c != '\0').collect();
            truncate_utf16(kept.trim(), 32)
        }
        Filesystem::Udf => {
            let kept: String = raw.chars().filter(|c| *c != '\0').collect();
            truncate_utf8(kept.trim(), 126)
        }
    }
}

/// Cut `s` to at most `max_bytes`, backing up to a UTF-8 boundary.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// Cut `s` to at most `max_units` UTF-16 units, keeping whole chars so a
/// surrogate pair is never split. `String` cannot hold an unpaired
/// surrogate in the first place, so counting whole chars is sufficient.
fn truncate_utf16(s: &str, max_units: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let need = ch.len_utf16();
        if used + need > max_units {
            break;
        }
        out.push(ch);
        used += need;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Filesystem; 7] = [
        Filesystem::Fat32,
        Filesystem::Exfat,
        Filesystem::Ntfs,
        Filesystem::Ext2,
        Filesystem::Ext3,
        Filesystem::Ext4,
        Filesystem::Udf,
    ];

    #[test]
    fn empty_is_no_label_everywhere() {
        for fs in ALL {
            validate_label("", fs.clone()).unwrap_or_else(|err| panic!("{fs:?}: {err}"));
        }
    }

    #[test]
    fn fat32_rejects_the_18_byte_live_label() {
        let err = validate_label("Fedora-KDE-Live-45", Filesystem::Fat32)
            .expect_err("18 bytes cannot fit an 11-byte field");
        let text = err.to_string();
        assert!(text.contains("11"), "{text}");
        assert!(text.contains("18"), "{text}");
        assert!(matches!(err, CoreError::InvalidInput { .. }));
    }

    #[test]
    fn fat32_rejects_controls_non_ascii_and_forbidden() {
        let fs = Filesystem::Fat32;
        for bad in [
            "a\u{1}b", "a\u{7f}b", "a\u{e9}b", "a/b", "a\\b", "a*b", "a:b", "a<b", "a>b", "a?b",
            "a|b", "a\"b",
        ] {
            assert!(
                validate_label(bad, fs.clone()).is_err(),
                "fat32 refuses {bad:?}"
            );
        }
        validate_label("ABCDEFGHIJK", fs.clone()).expect("exactly 11 ascii bytes fit");
        validate_label("boot-label", fs).expect("printable ascii with a dash fits");
    }

    #[test]
    fn exfat_counts_utf16_units_and_forbids_controls() {
        let fs = Filesystem::Exfat;
        validate_label(
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            fs.clone(),
        )
        .expect("11 non-ascii utf-16 units fit");
        assert!(validate_label("\u{e9}".repeat(12).as_str(), fs.clone()).is_err());
        // One emoji is two UTF-16 units: five of them (10 units) fit,
        // six (12 units) do not.
        validate_label("😀😀😀😀😀", fs.clone()).expect("10 utf-16 units fit");
        assert!(validate_label("😀😀😀😀😀😀", fs.clone()).is_err());
        assert!(
            validate_label("a\u{7f}b", fs.clone()).is_err(),
            "DEL is rejected"
        );
        assert!(validate_label("a/b", fs).is_err());
    }

    #[test]
    fn ext_is_ascii_only_and_nul_free() {
        for fs in [Filesystem::Ext2, Filesystem::Ext3, Filesystem::Ext4] {
            validate_label("A".repeat(16).as_str(), fs.clone()).expect("16 ascii bytes fit");
            assert!(validate_label("A".repeat(17).as_str(), fs.clone()).is_err());
            assert!(
                validate_label("é", fs.clone()).is_err(),
                "ext is ascii only"
            );
            assert!(
                validate_label("a\0b", fs.clone()).is_err(),
                "NUL is refused"
            );
        }
    }

    #[test]
    fn ntfs_counts_utf16_units_and_refuses_nul() {
        let fs = Filesystem::Ntfs;
        validate_label("R".repeat(32).as_str(), fs.clone()).expect("32 units fit");
        assert!(validate_label("R".repeat(33).as_str(), fs.clone()).is_err());
        validate_label("😀".repeat(16).as_str(), fs.clone()).expect("32 utf-16 units fit");
        assert!(validate_label("😀".repeat(17).as_str(), fs.clone()).is_err());
        assert!(validate_label("a\0b", fs).is_err(), "NUL is refused");
    }

    #[test]
    fn udf_allows_126_utf8_bytes_and_utf8_text() {
        let fs = Filesystem::Udf;
        validate_label("A".repeat(126).as_str(), fs.clone()).expect("126 bytes fit");
        assert!(validate_label("A".repeat(127).as_str(), fs.clone()).is_err());
        validate_label("é😀 label", fs.clone()).expect("utf-8 text is allowed");
        assert!(validate_label("a\0b", fs).is_err(), "NUL is refused");
    }

    #[test]
    fn sanitizing_the_live_label_fits_fat32() {
        let clean = sanitize_label("Fedora-KDE-Live-45", Filesystem::Fat32);
        assert_eq!(clean, "FEDORA-KDE-");
        validate_label(&clean, Filesystem::Fat32).expect("the cleaned label is storable");
    }

    #[test]
    fn sanitizer_cuts_utf16_without_splitting_a_surrogate_pair() {
        // 5 emoji = 10 units, the 6th needs 2 more and would overflow 11.
        let clean = sanitize_label("😀😀😀😀😀😀", Filesystem::Exfat);
        assert_eq!(clean, "😀😀😀😀😀");
        validate_label(&clean, Filesystem::Exfat).expect("no lone surrogate survives");
        let clean = sanitize_label("😀".repeat(17).as_str(), Filesystem::Ntfs);
        assert_eq!(clean, "😀".repeat(16));
        validate_label(&clean, Filesystem::Ntfs).expect("no lone surrogate survives");
    }

    #[test]
    fn sanitizer_cuts_utf8_on_a_character_boundary() {
        // 126 ASCII bytes plus a 4-byte emoji: the emoji must be dropped
        // whole rather than leaving a broken UTF-8 fragment.
        let raw = format!("{}{}", "A".repeat(126), "😀");
        let clean = sanitize_label(&raw, Filesystem::Udf);
        assert_eq!(clean, "A".repeat(126));
        validate_label(&clean, Filesystem::Udf).expect("clean utf-8 survives");
    }

    /// The central invariant: no matter how hostile the input, the
    /// sanitiser returns something the validator accepts. A small table
    /// of awkward strings, checked against every filesystem.
    #[test]
    fn sanitize_then_validate_always_succeeds() {
        // Owned long strings kept alive for the whole loop, so the
        // table can borrow them without a dropped temporary.
        let long_ascii = "A".repeat(200);
        let many_emoji = "😀".repeat(20);
        let many_accents = "é".repeat(14);
        let inputs: &[&str] = &[
            "",
            "   ",
            "FURUS",
            "fedora-kde-live-45",
            "a/b:c*d?e<f>g|h\"i\\j",
            "a\u{1}b\u{7f}c",
            "\u{0}\u{0}",
            "éééééééééééééé",
            "😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀",
            long_ascii.as_str(),
            many_emoji.as_str(),
            many_accents.as_str(),
            "  trailing and leading  ",
            "mix é 😀 / \\ : * ? < > | \u{1f}",
            "\u{4e2d}\u{6587}\u{6807}\u{7b7e}",
        ];
        for &raw in inputs {
            for fs in ALL.iter() {
                let clean = sanitize_label(raw, fs.clone());
                validate_label(&clean, fs.clone()).unwrap_or_else(|err| {
                    panic!("sanitise({raw:?}, {fs:?}) = {clean:?} still fails: {err}")
                });
            }
        }
    }
}
