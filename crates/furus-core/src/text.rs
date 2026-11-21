//! The one sanitiser for untrusted device-supplied text (S05).
//!
//! Strings that originate from hardware — sysfs attributes, udev record
//! values, USB descriptors, GPT/MBR partition labels — are untrusted on
//! two axes: they can be arbitrarily long garbage *and* they can carry
//! control characters (a `\n` breaks the one-line human format, an ESC
//! sequence is a terminal-injection vector) or non-ASCII bytes (which
//! would leak through as mojibake or smuggle lookalikes into logs).
//!
//! Every module that turns device bytes into a display/JSON string must
//! route through [`device_text`] — there is exactly one sanitiser and no
//! second implementation that could drift from it (PLAN §6 rule 8: log
//! lines must be attachable to bug reports, so they must never embed
//! hostile bytes in the first place).
//!
//! The neutralisation rule is deliberately lossy and simple: trim, then
//! map every control or non-ASCII `char` to `?`. A lossless escaping
//! scheme would make the device list differ on screen vs. JSON, and a
//! whitelist would silently drop characters on one device and not the
//! next; `?` is honest about "there was something here, not printable".

/// Sanitise device-supplied text for terminal and JSON output.
///
/// Trims ASCII/Unicode whitespace first, then maps every control or
/// non-ASCII character to `?` and everything else passes through. The
/// order matters: trimming before mapping keeps an all-whitespace string
/// empty instead of turning it into a run of `?`.
///
/// The semantics are byte-identical to what S04 discovery applied inline
/// (`sysfs::attr_text` trimmed, then neutralised) — this function is that
/// pipeline, promoted so later slices cannot reimplement it slightly
/// differently.
#[must_use]
pub fn device_text(raw: &str) -> String {
    raw.trim()
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::device_text;

    #[test]
    fn trims_surrounding_whitespace_first() {
        assert_eq!(device_text("  SanDisk Ultra  "), "SanDisk Ultra");
        // An entirely blank value collapses to empty, not to "???".
        assert_eq!(device_text("\t\n "), "");
    }

    #[test]
    fn control_characters_become_question_marks() {
        // ESC (terminal injection), BEL, CR, NUL: each maps to exactly
        // one `?`, preserving the length of the visible placeholder.
        assert_eq!(device_text("EVIL\u{1b}[2Jmodel"), "EVIL?[2Jmodel");
        assert_eq!(device_text("ser\u{7}ial"), "ser?ial");
        assert_eq!(device_text("a\rb"), "a?b");
        assert_eq!(device_text("a\u{0}b"), "a?b");
        assert_eq!(device_text("a\u{7f}b"), "a?b");
    }

    #[test]
    fn non_ascii_becomes_question_marks() {
        assert_eq!(device_text("é"), "?");
        assert_eq!(device_text("aéc"), "a?c");
        assert_eq!(
            device_text("中"),
            "?",
            "a CJK code point is one char, one `?`"
        );
        assert_eq!(device_text("Verl\u{00e4}uf"), "Verl?uf");
        // Non-ASCII whitespace is trimmed before the mapping even sees it.
        assert_eq!(device_text("\u{a0}"), "");
    }

    #[test]
    fn empty_stays_empty_and_valid_ascii_passes_through() {
        assert_eq!(device_text(""), "");
        assert_eq!(device_text("/dev/sdb1"), "/dev/sdb1");
        // Graphic ASCII punctuation survives untouched, including `?`.
        assert_eq!(device_text("0781:5583 (SanDisk)"), "0781:5583 (SanDisk)");
        assert_eq!(
            device_text("pci-0000:00:14.0-usb-0:2:1.0"),
            "pci-0000:00:14.0-usb-0:2:1.0"
        );
    }

    #[test]
    fn output_is_ascii_and_lenient_multi_line_never_happens() {
        let clean = device_text("\u{1b}[01;31mmedium\u{9}\u{b5}long");
        assert!(clean.is_ascii(), "{clean:?}");
        assert!(!clean.contains('\n') && !clean.contains('\r'), "{clean:?}");
    }
}
