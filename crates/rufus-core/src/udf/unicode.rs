//! OSTA compressed Unicode names and d-strings (S15, slice 1).
//!
//! UDF stores text as compressed Unicode: the first byte is the
//! compression id — 8 for one byte per character (latin-1), 16 for two
//! bytes big-endian per character — followed by the characters. Fixed
//! fields (like the logical volume identifier) are d-strings: the string
//! bytes run from the field start and the field's *last* byte holds the
//! significant length (compression id included), the rest is padding.
//!
//! *Measured* — on the `mkudffs -l LABEL` images (see the slice report):
//! the logical volume identifier field reads `08 4C 41 42 45 4C`,
//! NUL-padded, with the last field byte `06`: the significant window is
//! the first 6 bytes, decoding to `LABEL`. Every file name on the
//! kernel-populated image uses compression id 8 with the id counted in
//! the length (`SUBDIR` travels as 7 bytes: `08` plus six letters).
//!
//! *Inferred* — compression id 16 (spec text, ECMA-167 1/7.2.1): no
//! measured image carries one, so the big-endian decoding with surrogate
//! pairing mirrors [`joliet`](crate::iso::joliet) and stays strictly
//! refusing (odd length, unpaired surrogates and NUL all refuse).

use crate::error::CoreError;
use crate::error::Result;

/// Compression id for one-byte (latin-1) characters.
const COMPRESS_8: u8 = 8;

/// Compression id for two-byte big-endian characters.
const COMPRESS_16: u8 = 16;

/// First high-surrogate unit (inclusive): `D800..DC00` opens a pair.
const HIGH_MIN: u16 = 0xD800;
/// First low-surrogate unit (exclusive end of the high range).
const HIGH_END: u16 = 0xDC00;
/// First unit past the low-surrogate range (exclusive end).
const LOW_END: u16 = 0xE000;
/// Base added to a decoded surrogate pair (pairs address `10000..110000`).
const PAIR_BASE: u32 = 0x1_0000;

/// Decode OSTA compressed Unicode `data` (compression id first): id 8
/// maps each byte to its latin-1 code point, id 16 decodes big-endian
/// units with surrogate pairing. Anything else refuses naming the id and
/// the byte offset of the id, as do an empty input, an odd-length id-16
/// body, an unpaired surrogate and a NUL — all with `what` for context.
pub fn decode_osta(data: &[u8], what: &str) -> Result<String> {
    let id = data
        .first()
        .copied()
        .ok_or_else(|| CoreError::invalid(format!("{what} is empty: no compression id to read")))?;
    let body = data.get(1..).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} ends before its name bytes past the compression id"
        ))
    })?;
    match id {
        COMPRESS_8 => decode_latin1(body, what),
        COMPRESS_16 => decode_units16(body, what),
        other => Err(CoreError::invalid(format!(
            "{what} has compression id {other} at byte offset 0: only 8 (one byte latin-1) \
             and 16 (two byte big endian) are supported"
        ))),
    }
}

/// Decode a fixed-size d-string `field`: the last byte is the significant
/// length (compression id included), the bytes before it are compressed
/// Unicode, the bytes after it are padding. Refuses a significant length
/// running past the field, naming both numbers; trailing spaces and NULs
/// of the decoded text are trimmed as padding.
pub fn decode_dstring(field: &[u8], what: &str) -> Result<String> {
    let len = field.len();
    let last = field.last().copied().ok_or_else(|| {
        CoreError::invalid(format!("{what} is empty: no d-string length byte to read"))
    })?;
    let significant = usize::from(last);
    if significant > len.saturating_sub(1) {
        return Err(CoreError::invalid(format!(
            "{what} d-string claims a significant length of {significant} bytes in a {len} \
             byte field: the length byte must not run past the field"
        )));
    }
    let data = field.get(..significant).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} d-string of {significant} bytes runs past its {len} byte field"
        ))
    })?;
    let decoded = decode_osta(data, what)?;
    let mut trimmed = decoded.as_str();
    while trimmed.ends_with(' ') || trimmed.ends_with('\0') {
        let shortened = trimmed.get(..trimmed.len().saturating_sub(1));
        match shortened {
            Some(rest) => trimmed = rest,
            None => break,
        }
    }
    Ok(trimmed.to_string())
}

/// One byte per character: each byte is its latin-1 code point (always a
/// valid `char`). A NUL byte refuses naming its offset — names never
/// carry one, mirroring the Joliet rule.
fn decode_latin1(body: &[u8], what: &str) -> Result<String> {
    let mut out = String::new();
    for (index, byte) in body.iter().copied().enumerate() {
        if byte == 0 {
            return Err(CoreError::invalid(format!(
                "{what} has a NUL byte at name offset {}: names never carry NUL",
                index + 1
            )));
        }
        out.push(char::from(byte));
    }
    Ok(out)
}

/// Two bytes big-endian per character with surrogate pairing, mirroring
/// the Joliet decoder: an odd body length, an unpaired surrogate or a NUL
/// refuses naming the byte offset (counted from the compression id, so
/// callers can find the byte on disk).
fn decode_units16(body: &[u8], what: &str) -> Result<String> {
    if !body.len().is_multiple_of(2) {
        return Err(CoreError::invalid(format!(
            "{what} of {} name bytes has an odd length: compression id 16 units are two \
             bytes each",
            body.len()
        )));
    }
    let mut units = Vec::new();
    let mut at: usize = 0;
    while at < body.len() {
        let hi = body.get(at).copied().ok_or_else(|| {
            CoreError::invalid(format!("{what} ends before name byte {}", at + 1))
        })?;
        let lo = body.get(at + 1).copied().ok_or_else(|| {
            CoreError::invalid(format!("{what} ends before name byte {}", at + 2))
        })?;
        units.push(u16::from_be_bytes([hi, lo]));
        at = at.checked_add(2).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} name offset {at} overflows the byte arithmetic"
            ))
        })?;
    }
    let mut out = String::new();
    let mut index: usize = 0;
    while index < units.len() {
        let unit = units
            .get(index)
            .copied()
            .ok_or_else(|| CoreError::invalid(format!("{what} ends before name unit {index}")))?;
        let byte = index.checked_mul(2).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} name unit index {index} overflows the byte arithmetic"
            ))
        })?;
        // Byte offsets count from the compression id, hence + 1.
        let byte = byte.saturating_add(1);
        if (HIGH_MIN..HIGH_END).contains(&unit) {
            let low = units.get(index + 1).copied().ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} has an unpaired high surrogate at name byte offset {byte}: \
                     no unit follows it"
                ))
            })?;
            if !(HIGH_END..LOW_END).contains(&low) {
                return Err(CoreError::invalid(format!(
                    "{what} has an unpaired high surrogate at name byte offset {byte}: \
                     the following unit is not a low surrogate"
                )));
            }
            let value = PAIR_BASE + (u32::from(unit - HIGH_MIN) << 10) + u32::from(low - HIGH_END);
            let decoded = char::from_u32(value).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} surrogate pair at name byte offset {byte} is not a Unicode \
                     scalar value"
                ))
            })?;
            out.push(decoded);
            index += 2;
        } else if (HIGH_END..LOW_END).contains(&unit) {
            return Err(CoreError::invalid(format!(
                "{what} has an unpaired low surrogate at name byte offset {byte}"
            )));
        } else {
            if unit == 0 {
                return Err(CoreError::invalid(format!(
                    "{what} has a NUL character at name byte offset {byte}: names never carry NUL"
                )));
            }
            let decoded = char::from_u32(u32::from(unit)).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} unit {unit:04x} at name byte offset {byte} is not a Unicode \
                     scalar value"
                ))
            })?;
            out.push(decoded);
            index += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_decodes_bytes_directly() {
        assert_eq!(
            decode_osta(&[8, b'L', b'A', 0xE9], "test").expect("latin-1 decodes"),
            "LA\u{e9}"
        );
    }

    #[test]
    fn units16_decode_big_endian_with_a_pair() {
        // "A" plus U+1F600 (grinning face) as a surrogate pair.
        let data = [16, 0x00, 0x41, 0xD8, 0x3D, 0xDE, 0x00];
        assert_eq!(
            decode_units16(&data[1..], "test").expect("the pair decodes"),
            "A\u{1f600}"
        );
    }

    #[test]
    fn unknown_compression_id_names_id_and_offset() {
        let error = decode_osta(&[3, b'A'], "test name").expect_err("id 3 refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains("offset 0"), "{text}");
        assert!(text.contains("test name"), "{text}");
    }

    #[test]
    fn empty_input_refuses() {
        let error = decode_osta(&[], "test name").expect_err("empty refuses");
        assert!(error.to_string().contains("empty"), "{:?}", error);
    }

    #[test]
    fn odd_units16_length_refuses() {
        let error = decode_osta(&[16, 0x00], "test name").expect_err("odd refuses");
        let text = error.to_string();
        assert!(text.contains("odd"), "{text}");
    }

    #[test]
    fn unpaired_surrogate_refuses() {
        let error = decode_osta(&[16, 0xD8, 0x3D], "test name").expect_err("a lone high refuses");
        let text = error.to_string();
        assert!(text.contains("unpaired"), "{text}");
    }

    #[test]
    fn nul_inside_a_name_refuses() {
        let error = decode_osta(&[8, b'A', 0], "test name").expect_err("NUL refuses");
        let text = error.to_string();
        assert!(text.contains("NUL"), "{text}");
    }

    #[test]
    fn dstring_uses_the_last_byte_as_the_length() {
        // `LABEL` the way mkudffs writes it: id 8, five letters, NUL
        // padding, significant length 6 in the last field byte.
        let mut field = [0u8; 32];
        field[0] = 8;
        field[1..6].copy_from_slice(b"LABEL");
        field[31] = 6;
        assert_eq!(
            decode_dstring(&field, "test label").expect("the d-string decodes"),
            "LABEL"
        );
    }

    #[test]
    fn dstring_trims_trailing_spaces() {
        let mut field = [b' '; 32];
        field[0] = 8;
        field[1..5].copy_from_slice(b"PAD ");
        field[31] = 6;
        assert_eq!(
            decode_dstring(&field, "test label").expect("padding trims"),
            "PAD"
        );
    }

    #[test]
    fn dstring_length_past_the_field_refuses() {
        let mut field = [0u8; 32];
        field[31] = 40;
        let error = decode_dstring(&field, "test label").expect_err("40 past 32 refuses");
        let text = error.to_string();
        assert!(text.contains("40"), "{text}");
        assert!(text.contains("32"), "{text}");
    }
}
