//! Joliet (UCS-2BE) name decoding (S14, slice 2).
//!
//! *Measured* — the Joliet layout the cross-check pins: file and
//! directory identifiers as UCS-2 big-endian units (two bytes each,
//! so every identifier is an even length), the `;1` version suffix and
//! one trailing `.` stripped after decoding exactly like the primary
//! tree strips them before it, and the volume identifier as 16 UCS-2BE
//! units padded with trailing space units. Surrogate pairs combine per
//! Unicode (high `D800..DC00` plus low `DC00..E000` make
//! `10000..110000`); anything else in the surrogate range is corrupt.
//! Every fact below is pinned twice: by synthetic fixtures built unit
//! by unit in the `#[cfg(test)]` module, and by one real `xorriso`
//! Joliet image in the slice report.
//!
//! *Inferred* — that real mastering tools space-pad (not NUL-pad) the
//! volume identifier; the decoder trims both paddings, so either way
//! reads, and the slice report says which one the real image used.
//!
//! Refusals, not panics: an odd-length name field, an unpaired
//! surrogate, or a NUL inside a name is refused with the byte offset
//! named (callers add the path); the label trims its padding first and
//! then decodes under the same rules.

use crate::error::CoreError;
use crate::error::Result;

/// First high-surrogate unit (inclusive): `D800..DC00` opens a pair.
const HIGH_MIN: u16 = 0xD800;
/// First low-surrogate unit (exclusive end of the high range).
const HIGH_END: u16 = 0xDC00;
/// First unit past the low-surrogate range (exclusive end).
const LOW_END: u16 = 0xE000;
/// Base added to a decoded surrogate pair (pairs address
/// `10000..110000`).
const PAIR_BASE: u32 = 0x1_0000;
/// Trailing padding unit in volume identifiers: NUL.
const PAD_NUL: u16 = 0x0000;
/// Trailing padding unit in volume identifiers: space.
const PAD_SPACE: u16 = 0x0020;

/// UCS-2BE bytes to units: two bytes per unit, so an odd-length field
/// is refused naming its length. The defensive byte reads cannot miss
/// (the length check pins the shape first), but every access stays
/// checked all the same.
fn to_units(field: &[u8], what: &str) -> Result<Vec<u16>> {
    if !field.len().is_multiple_of(2) {
        return Err(CoreError::invalid(format!(
            "{what} of {} bytes has an odd length: UCS-2BE units are two bytes each",
            field.len()
        )));
    }
    let mut units = Vec::new();
    let mut at: usize = 0;
    while at < field.len() {
        let hi = field.get(at).copied().ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} ends before byte {at} of {} bytes",
                field.len()
            ))
        })?;
        let lo = field.get(at + 1).copied().ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} ends before byte {} of {} bytes",
                at + 1,
                field.len()
            ))
        })?;
        units.push(u16::from_be_bytes([hi, lo]));
        at += 2;
    }
    Ok(units)
}

/// Strict UCS-2BE units to text: surrogate pairs combine, lone units
/// map directly. Refuses an unpaired surrogate or a NUL, naming the
/// byte offset of the offending unit; the `from_u32` fallbacks cannot
/// trigger (every non-surrogate unit and every combined pair is a
/// scalar value) but keep the decoder total without panicking.
fn decode_units(units: &[u16], what: &str) -> Result<String> {
    let mut out = String::new();
    let mut index: usize = 0;
    while index < units.len() {
        let unit = units
            .get(index)
            .copied()
            .ok_or_else(|| CoreError::invalid(format!("{what} ends before unit {index}")))?;
        let byte = index.checked_mul(2).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} unit index {index} overflows the byte arithmetic"
            ))
        })?;
        if (HIGH_MIN..HIGH_END).contains(&unit) {
            let low = units.get(index + 1).copied().ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} has an unpaired high surrogate at byte offset {byte}: \
                     no unit follows it"
                ))
            })?;
            if !(HIGH_END..LOW_END).contains(&low) {
                return Err(CoreError::invalid(format!(
                    "{what} has an unpaired high surrogate at byte offset {byte}: \
                     the following unit is not a low surrogate"
                )));
            }
            let value = PAIR_BASE + (u32::from(unit - HIGH_MIN) << 10) + u32::from(low - HIGH_END);
            let decoded = char::from_u32(value).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} surrogate pair at byte offset {byte} is not a Unicode scalar value"
                ))
            })?;
            out.push(decoded);
            index += 2;
        } else if (HIGH_END..LOW_END).contains(&unit) {
            return Err(CoreError::invalid(format!(
                "{what} has an unpaired low surrogate at byte offset {byte}"
            )));
        } else {
            if unit == 0 {
                return Err(CoreError::invalid(format!(
                    "{what} has a NUL character at byte offset {byte}: \
                     NULs are refused inside Joliet names"
                )));
            }
            let decoded = char::from_u32(u32::from(unit)).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} unit {unit} at byte offset {byte} is not a Unicode scalar value"
                ))
            })?;
            out.push(decoded);
            index += 1;
        }
    }
    Ok(out)
}

/// Decode a Joliet file or directory identifier: strict UCS-2BE, no
/// trimming (identifiers are exactly sized; dot records never reach
/// here — callers skip `.`/`..` first, since those are one byte long).
pub fn decode_name(identifier: &[u8]) -> Result<String> {
    decode_units(&to_units(identifier, "joliet name")?, "joliet name")
}

/// Decode a 32-byte Joliet volume-identifier field: trailing NUL and
/// space units are padding and trim first, the rest decodes under the
/// same strict rules as a name.
pub fn decode_label(field: &[u8]) -> Result<String> {
    let mut units = to_units(field, "joliet volume identifier")?;
    let mut keep = units.len();
    while keep > 0
        && matches!(
            units.get(keep - 1).copied(),
            Some(PAD_NUL) | Some(PAD_SPACE)
        )
    {
        keep -= 1;
    }
    units.truncate(keep);
    decode_units(&units, "joliet volume identifier")
}

/// Display/matching form of a decoded Joliet name: the `;1` version
/// suffix and one trailing `.` stripped, mirroring
/// [`strip_version`](crate::iso::record::strip_version) on decoded
/// text.
#[must_use]
pub fn strip_version(name: &str) -> String {
    let without_suffix = name.strip_suffix(";1").unwrap_or(name);
    without_suffix
        .strip_suffix('.')
        .unwrap_or(without_suffix)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_bmp_units_decode() {
        assert_eq!(
            decode_name(&[0, b'B', 0, b'.']).expect("pairs decode"),
            "B."
        );
        // U+00E9 as one unit, U+0041 beside it.
        assert_eq!(
            decode_name(&[0, 0x41, 0, 0xE9]).expect("the BMP unit decodes"),
            "A\u{e9}"
        );
    }

    #[test]
    fn surrogate_pair_combines_to_astral() {
        // U+1F600 as D83D DE00.
        assert_eq!(
            decode_name(&[0xD8, 0x3D, 0xDE, 0x00]).expect("the pair combines"),
            "\u{1f600}"
        );
    }

    #[test]
    fn odd_length_names_byte_count_in_the_refusal() {
        let error = decode_name(&[0, b'A', 0]).expect_err("three bytes refuse");
        let text = error.to_string();
        assert!(text.contains("3"), "{text}");
        assert!(text.contains("odd"), "{text}");
    }

    #[test]
    fn unpaired_surrogates_name_the_byte_offset() {
        // Lone high surrogate at the end (offset 2).
        let error = decode_name(&[0, b'A', 0xD8, 0x00]).expect_err("the lone high refuses");
        let text = error.to_string();
        assert!(text.contains("surrogate"), "{text}");
        assert!(text.contains("2"), "{text}");
        // High surrogate followed by a non-low unit (offset 0).
        let error = decode_name(&[0xD8, 0x00, 0, b'A']).expect_err("the bad follower refuses");
        assert!(error.to_string().contains("surrogate"), "{error}");
        // Lone low surrogate (offset 0).
        let error = decode_name(&[0xDC, 0x00]).expect_err("the lone low refuses");
        assert!(error.to_string().contains("surrogate"), "{error}");
    }

    #[test]
    fn nul_inside_a_name_refused() {
        let error = decode_name(&[0, b'A', 0, 0, 0, b'B']).expect_err("the NUL refuses");
        let text = error.to_string();
        assert!(text.contains("NUL"), "{text}");
        assert!(text.contains("2"), "{text}");
    }

    #[test]
    fn strip_version_cuts_semicolon_one_and_trailing_dot() {
        assert_eq!(strip_version("B.TXT;1"), "B.TXT");
        assert_eq!(strip_version("FILE.;1"), "FILE");
        assert_eq!(strip_version("DIR"), "DIR");
        assert_eq!(strip_version("A."), "A");
        assert_eq!(strip_version("A;12"), "A;12");
        assert_eq!(strip_version(";1"), "");
        assert_eq!(strip_version("caf\u{e9}.txt;1"), "caf\u{e9}.txt");
    }

    #[test]
    fn label_trims_space_and_nul_padding() {
        // "AB" space-padded to four units.
        assert_eq!(
            decode_label(&[0, b'A', 0, b'B', 0, 0x20, 0, 0x20]).expect("spaces trim"),
            "AB"
        );
        // "AB" NUL-padded instead.
        assert_eq!(
            decode_label(&[0, b'A', 0, b'B', 0, 0, 0, 0]).expect("NULs trim"),
            "AB"
        );
        // Interior NULs are not padding: refused like in a name.
        let error = decode_label(&[0, b'A', 0, 0, 0, b'B', 0, 0x20]).expect_err("interior NUL");
        assert!(error.to_string().contains("NUL"), "{error}");
    }
}
