//! UDF descriptor tags: parse, locate and CRC-check (S15, slice 1).
//!
//! Every UDF structure slice 1 reads (the anchor pointer, each volume
//! descriptor, the file set descriptor, file identifier descriptors and
//! file entries) opens with a 16-byte descriptor tag: the tag id (`u16`
//! at 0), version (`u16` at 2), checksum byte (at 4), serial (`u16` at 6),
//! CRC (`u16` at 8), CRC length (`u16` at 10) and tag location (`u32` at
//! 12), all little-endian.
//!
//! *Measured* — against `mkudffs --utf8 --media-type=hd
//! --udfrev=0x0201 -b <512|2048>` images from udftools 2.3 inside
//! `archlinux:latest` (see the slice report): the CRC is CRC-16/ITU-T
//! (polynomial `0x1021`, initial value 0, no reflection, no final xor)
//! over the `crc_len` bytes right after the tag, verified on every
//! descriptor of three images (empty `-b 2048`, empty `-b 512`, and a
//! kernel-populated `-b 2048` with a subdirectory and four files
//! volume-wide, three of them in the root). The
//! same run shows version 3 with a nonzero checksum byte on every tag
//! (54 on the 64MiB `-b 2048` anchor and 235 on the 64MiB `-b 512`
//! one — the ECMA-167 sum of the other tag bytes mod 256; the anchor tag
//! covers the two extents, so the value depends only on the layout —
//! block size and extent positions — not on the volume UUID or
//! timestamps, and repeats for a given image shape — 203 on the empty
//! `-b 2048` verification image's file set
//! descriptor and 192 on its root parent entry, both image-specific
//! values that move with the volume UUID, timestamps and tag serials),
//! and this reader deliberately verifies neither field: the (id,
//! location, CRC) triple the walk enforces already refuses every
//! corruption class the fixtures cover, so the version and checksum are
//! a scope line, not a gap. The location semantics the walk relies on
//! are measured too: descriptors in
//! a volume descriptor sequence carry the absolute block number, while
//! the file set descriptor, file entries and file identifier descriptors
//! carry the partition-relative block number.
//!
//! *Inferred* — the 16-byte field positions themselves (spec text,
//! ECMA-167 3/7.2): every offset below was confirmed by parsing the real
//! images, but no independent tool was available to cross-check the
//! layout beyond that agreement.

use crate::error::CoreError;
use crate::error::Result;

/// Length of every descriptor tag in bytes.
pub const TAG_LEN: usize = 16;

/// CRC-16/ITU-T polynomial (`x^16 + x^12 + x^5 + 1`), as ECMA-167 defines it.
const CRC_POLY: u16 = 0x1021;

/// One parsed descriptor tag: the identity, the CRC window and the
/// claimed location. The checksum byte and the version travel nowhere:
/// real images write version 3 with an ECMA sum-checksum byte there (see
/// the module header), and the reader enforces neither — the (id,
/// location, CRC) triple carries the validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Tag identifier (2 = anchor pointer, 6 = logical volume, 256 =
    /// file set, 257 = file identifier, 261/266 = file entries, ...).
    pub id: u16,
    /// Descriptor CRC: CRC-16/ITU-T over the `crc_len` bytes after the tag.
    pub crc: u16,
    /// How many bytes after the tag the CRC covers.
    pub crc_len: u16,
    /// Claimed block number of this descriptor.
    pub location: u32,
}

/// Parse the tag at the start of `block`: refuses a block shorter than
/// [`TAG_LEN`] naming both lengths. Every field reads through `get`, so
/// a short block can never panic.
pub fn parse(block: &[u8], what: &str) -> Result<Tag> {
    let bytes = block.get(..TAG_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} is {} bytes long: a descriptor tag needs {TAG_LEN} bytes",
            block.len()
        ))
    })?;
    let word = |at: usize| {
        bytes
            .get(at..at + 2)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} ends inside its descriptor tag at bytes {at}..{}",
                    at + 2
                ))
            })
            .and_then(|pair| {
                pair.try_into().map(u16::from_le_bytes).map_err(|_| {
                    CoreError::invalid(format!(
                        "{what} tag bytes {at}..{} do not form a u16",
                        at + 2
                    ))
                })
            })
    };
    let quad = |at: usize| {
        bytes
            .get(at..at + 4)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} ends inside its descriptor tag at bytes {at}..{}",
                    at + 4
                ))
            })
            .and_then(|four| {
                four.try_into().map(u32::from_le_bytes).map_err(|_| {
                    CoreError::invalid(format!(
                        "{what} tag bytes {at}..{} do not form a u32",
                        at + 4
                    ))
                })
            })
    };
    Ok(Tag {
        id: word(0)?,
        crc: word(8)?,
        crc_len: word(10)?,
        location: quad(12)?,
    })
}

/// Verify `tag`'s CRC over `block`: the `crc_len` bytes right after the
/// tag must fit in the block and their CRC-16/ITU-T must equal the stored
/// value. Refuses an overrunning window and a mismatch, naming the
/// stored and computed values in hex.
pub fn verify_crc(block: &[u8], tag: &Tag, what: &str) -> Result<()> {
    let len = usize::from(tag.crc_len);
    let end = len.checked_add(TAG_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} CRC length {len} overflows the offset arithmetic"
        ))
    })?;
    let covered = block.get(TAG_LEN..end).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} CRC window {TAG_LEN}..{end} runs past the {} byte block: \
             the descriptor claims {len} CRC bytes it does not carry",
            block.len()
        ))
    })?;
    let computed = crc16_itu_t(covered);
    if computed != tag.crc {
        return Err(CoreError::invalid(format!(
            "{what} descriptor CRC mismatch: stored {stored:04x} against computed \
             {computed:04x} over {len} bytes",
            stored = tag.crc,
        )));
    }
    Ok(())
}

/// CRC-16/ITU-T: polynomial `0x1021`, initial value 0, no reflection, no
/// final xor — the checksum ECMA-167 puts in every descriptor tag. The
/// shifts use wrapping arithmetic so no input can panic.
#[must_use]
pub fn crc16_itu_t(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for byte in data.iter().copied() {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = crc.wrapping_shl(1) ^ CRC_POLY;
            } else {
                crc = crc.wrapping_shl(1);
            }
        }
    }
    crc
}

/// Stamp a tag with `id`/`crc_len`/`location` onto the first 16 bytes of
/// `block` (test helper shared by every `udf` test module) and fix the
/// CRC over the covered window, mirroring what real images carry
/// (version 3; the checksum byte stays zero because production code
/// never checks it, so fixtures need no real checksum there).
/// Test-only: production code never writes tags, so this lives behind
/// `cfg(test)`.
#[cfg(test)]
pub(crate) fn stamp_tag(block: &mut [u8], id: u16, crc_len: u16, location: u32) {
    block[0..2].copy_from_slice(&id.to_le_bytes());
    block[2..4].copy_from_slice(&3u16.to_le_bytes());
    block[4] = 0;
    block[5] = 0;
    block[6..8].copy_from_slice(&1u16.to_le_bytes());
    let end = TAG_LEN + usize::from(crc_len);
    let crc = crc16_itu_t(&block[TAG_LEN..end]);
    block[8..10].copy_from_slice(&crc.to_le_bytes());
    block[10..12].copy_from_slice(&crc_len.to_le_bytes());
    block[12..16].copy_from_slice(&location.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::stamp_tag;
    use super::*;

    #[test]
    fn crc_matches_the_standard_check_vector() {
        // The CRC-16/ITU-T (XMODEM) check value for nine ASCII digits:
        // pins the polynomial, the zero init and the lack of reflection
        // without any UDF image.
        assert_eq!(crc16_itu_t(b"123456789"), 0x31C3);
        assert_eq!(crc16_itu_t(b""), 0x0000);
        assert_eq!(crc16_itu_t(&[0u8; 496]), 0x0000);
    }

    #[test]
    fn parse_reads_the_tag_fields() {
        let mut block = [0u8; 64];
        stamp_tag(&mut block, 6, 48, 97);
        let tag = parse(&block, "test block").expect("the stamped tag parses");
        assert_eq!(tag.id, 6);
        assert_eq!(tag.crc_len, 48);
        assert_eq!(tag.location, 97);
        verify_crc(&block, &tag, "test block").expect("the stamped CRC verifies");
    }

    #[test]
    fn short_block_refuses_naming_both_lengths() {
        let error = parse(&[0u8; 10], "short block").expect_err("10 bytes carry no tag");
        let text = error.to_string();
        assert!(text.contains("10"), "{text}");
        assert!(text.contains("16"), "{text}");
    }

    #[test]
    fn crc_mismatch_names_both_values() {
        let mut block = [0u8; 64];
        stamp_tag(&mut block, 6, 48, 97);
        block[20] ^= 0xFF;
        let tag = parse(&block, "test block").expect("the tag still parses");
        let error = verify_crc(&block, &tag, "test block").expect_err("the flipped byte refuses");
        let text = error.to_string();
        assert!(text.contains("mismatch"), "{text}");
        assert!(text.contains("48"), "{text}");
    }

    #[test]
    fn overrunning_crc_window_refuses() {
        let mut block = [0u8; 64];
        stamp_tag(&mut block, 6, 48, 97);
        // Lie about the window without fixing the CRC: parsing works,
        // the window check fires first.
        block[10..12].copy_from_slice(&60u16.to_le_bytes());
        let tag = parse(&block, "test block").expect("the tag still parses");
        let error = verify_crc(&block, &tag, "test block").expect_err("60 bytes do not fit");
        let text = error.to_string();
        assert!(text.contains("60"), "{text}");
        assert!(text.contains("64"), "{text}");
    }
}
