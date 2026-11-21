//! The WIM header: the 208-byte little-endian prologue of a `.wim` file.
//!
//! Layout (offsets and sizes in bytes, verified byte for byte against
//! `wimlib`-generated images on the maintainer's host):
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 8 | magic `MSWIM\0\0\0` ([`MAGIC`]) |
//! | 8 | 4 | `cbSize`, always [`HEADER_SIZE`] |
//! | 12 | 4 | version: [`VERSION`] (1.13), or [`SOLID_VERSION`]
//! (1.14, solid archives / ESD) |
//! | 16 | 4 | flags: bit `0x2` means "has compression", `0x20000` is
//! XPRESS, `0x40000` is LZX, `0x80000` is LZMS, `0x80` is RP_FIX |
//! | 20 | 4 | chunk size (0 for stored streams, 32768 for XPRESS/LZX,
//! 131072 for LZMS) |
//! | 24 | 16 | GUID (opaque to this reader, never interpreted) |
//! | 40 | 2 | part number (1-based) |
//! | 42 | 2 | total parts |
//! | 44 | 4 | image count |
//! | 48 | 24 | offset-table resource |
//! | 72 | 24 | XML resource (the only resource this reader follows) |
//! | 96 | 24 | boot metadata resource |
//! | 120 | 4 | boot index (0 means none) |
//! | 124 | 24 | integrity resource |
//! | 148 | 60 | reserved, never interpreted |
//!
//! Each 24-byte resource is `{u64 size_and_flags; u64 offset; u64
//! original_size}`: the top 8 bits of the first `u64` are flags and the
//! low 56 bits are the size in the WIM.
//!
//! [`WimHeader::parse`] refuses (with [`CoreError`](crate::CoreError)
//! messages naming the offending field) anything that is not exactly
//! this shape: a short buffer, a wrong magic, a `cbSize` other than
//! 208, a version other than 1.13 or solid 1.14, impossible part
//! numbers, an absurd image count, or a boot index past the last
//! image. Unusual compression flag combinations are *not* refused:
//! the reader only reports the compression label and never
//! decompresses, so unknown bits map to the closest known
//! [`Compression`] (see [`Compression::from_flags`]) instead of
//! failing the whole header.
//!
//! Solid archives (ESD, header version 1.14) parse like plain WIMs:
//! the reviewer's LZMS-artifact measurement shows the XML resource
//! inside them is the same stored UTF-16 (`size_in_wim ==
//! original_size`, `FF FE`, `<WIM>`), so no separate code path is
//! needed.

use crate::error::CoreError;
use crate::error::Result;

/// The WIM magic: `MSWIM\0\0\0` at offset 0.
pub const MAGIC: [u8; 8] = *b"MSWIM\0\0\0";

/// The WIM header length in bytes: `cbSize` must equal this.
pub const HEADER_SIZE: u32 = 208;

/// The plain WIM version this reader accepts: 1.13.
pub const VERSION: u32 = 0x0001_0D00;

/// The solid-archive (ESD) version this reader accepts: 1.14.
/// `wimlib` writes this for `--compress=LZMS` and
/// `--compress=LZX --solid` images; the XML resource inside them is
/// the same stored UTF-16 as in plain WIMs.
pub const SOLID_VERSION: u32 = 0x0000_0E00;

/// Cap on accepted image counts: a real WIM holds a handful of images,
/// so anything past this is a corrupt or hostile header, not a library.
/// The XML scanner applies the same cap to its image list.
pub(crate) const MAX_IMAGE_COUNT: u32 = 10_000;

/// Flags bit: the WIM carries compressed streams.
const FLAG_HAS_COMPRESSION: u32 = 0x2;

/// Flags bit: LZX compression.
const FLAG_LZX: u32 = 0x0004_0000;

/// Flags bit: LZMS compression.
const FLAG_LZMS: u32 = 0x0008_0000;

/// One 24-byte resource extent: where a resource lives in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceHeader {
    /// Size in the WIM (low 56 bits of the first `u64`).
    pub size: u64,
    /// Absolute file offset of the resource.
    pub offset: u64,
    /// Uncompressed size (equals `size` for stored resources).
    pub original_size: u64,
    /// Resource flags (top 8 bits of the first `u64`).
    pub flags: u8,
}

/// The WIM payload compression, derived from the header flags. This is
/// a report label only: the reader never decompresses anything (see
/// the [module docs](super)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Bit `0x2` is clear: stored streams.
    None,
    /// XPRESS streams (`0x20000`).
    Xpress,
    /// LZX streams (`0x40000`).
    Lzx,
    /// LZMS streams (`0x80000`).
    Lzms,
}

impl Compression {
    /// Derive the label from the raw header flags. `0x2` clear means
    /// [`Compression::None`]; otherwise the highest known bit wins when
    /// several are set (real producers set exactly one). A set `0x2`
    /// with none of the known bits falls back to
    /// [`Compression::Xpress`]: the reader only reports the label and
    /// never picks a decompressor by it, so refusing the whole header
    /// over an unknown bit would be worse than the closest known label.
    fn from_flags(flags: u32) -> Self {
        if flags & FLAG_HAS_COMPRESSION == 0 {
            return Self::None;
        }
        if flags & FLAG_LZMS != 0 {
            Self::Lzms
        } else if flags & FLAG_LZX != 0 {
            Self::Lzx
        } else {
            // XPRESS (`0x20000`) proper, or a set `0x2` with none of
            // the known bits: either way the closest known label is
            // Xpress (see the method docs).
            Self::Xpress
        }
    }

    /// The short label (`"none"`, `"xpress"`, `"lzx"`, `"lzms"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Xpress => "xpress",
            Self::Lzx => "lzx",
            Self::Lzms => "lzms",
        }
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parsed WIM header: the counts and labels plus the four resource
/// extents. Only the `xml` extent is ever followed (by
/// [`WimReader`](super::reader::WimReader)); the rest is carried so the
/// report layer can quote it without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimHeader {
    /// Number of images in the WIM (`<= 10_000`).
    pub image_count: u32,
    /// Compression label from the flags (report-only, see
    /// [`Compression`]).
    pub compression: Compression,
    /// Chunk size for compressed streams (0 for stored streams).
    pub chunk_size: u32,
    /// 1-based part number of this file.
    pub part_number: u16,
    /// Total parts of the split WIM.
    pub total_parts: u16,
    /// Default boot image (`None` when the header says 0).
    pub boot_index: Option<u32>,
    /// Offset-table resource extent.
    pub offset_table: ResourceHeader,
    /// XML resource extent (the image metadata).
    pub xml: ResourceHeader,
    /// Boot metadata resource extent.
    pub boot_metadata: ResourceHeader,
    /// Integrity table resource extent.
    pub integrity: ResourceHeader,
}

/// Read a little-endian `u16` at `at`. Total (no indexing, no panic):
/// the `None` case is unreachable after the length check in
/// [`WimHeader::parse`] and stays an error rather than a trap.
fn le_u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    bytes
        .get(at..at.saturating_add(2))
        .and_then(|window| window.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| CoreError::invalid("wim header is too short for its own fields"))
}

/// Read a little-endian `u32` at `at` (same contract as
/// [`le_u16_at`]).
fn le_u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    bytes
        .get(at..at.saturating_add(4))
        .and_then(|window| window.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| CoreError::invalid("wim header is too short for its own fields"))
}

/// Read a little-endian `u64` at `at` (same contract as
/// [`le_u16_at`]).
fn le_u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    bytes
        .get(at..at.saturating_add(8))
        .and_then(|window| window.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| CoreError::invalid("wim header is too short for its own fields"))
}

/// Read one 24-byte resource at `at` (same contract as
/// [`le_u16_at`]).
fn resource_at(bytes: &[u8], at: usize) -> Result<ResourceHeader> {
    let size_and_flags = le_u64_at(bytes, at)?;
    let offset = le_u64_at(bytes, at.saturating_add(8))?;
    let original_size = le_u64_at(bytes, at.saturating_add(16))?;
    Ok(ResourceHeader {
        size: size_and_flags & 0x00FF_FFFF_FFFF_FFFF,
        offset,
        original_size,
        flags: (size_and_flags >> 56) as u8,
    })
}

impl WimHeader {
    /// Parse the 208-byte header. Every refusal is a
    /// [`CoreError::invalid`](crate::CoreError) naming the offending
    /// field (with the value in hex where that helps): short buffer,
    /// wrong magic, `cbSize`, version, part numbers, image count, boot
    /// index. Both [`VERSION`] and [`SOLID_VERSION`] are accepted;
    /// compression flag combinations are never refused (see
    /// [`Compression::from_flags`]).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE as usize {
            return Err(CoreError::invalid(format!(
                "wim header needs {} bytes, got {}",
                HEADER_SIZE,
                bytes.len()
            )));
        }
        if bytes.get(0..MAGIC.len()) != Some(MAGIC.as_slice()) {
            let mut seen = String::new();
            if let Some(window) = bytes.get(0..MAGIC.len()) {
                for byte in window {
                    seen.push_str(&format!("{byte:02x}"));
                }
            }
            return Err(CoreError::invalid(format!(
                "wim magic mismatch: expected 4d5357494d000000, got {seen}"
            )));
        }
        let cb_size = le_u32_at(bytes, 8)?;
        if cb_size != HEADER_SIZE {
            return Err(CoreError::invalid(format!(
                "wim cbSize is {cb_size} (0x{cb_size:08x}), expected {HEADER_SIZE}"
            )));
        }
        let version = le_u32_at(bytes, 12)?;
        if version != VERSION && version != SOLID_VERSION {
            return Err(CoreError::invalid(format!(
                "wim version is 0x{version:08x}, expected 0x{VERSION:08x} or 0x{SOLID_VERSION:08x}"
            )));
        }
        let flags = le_u32_at(bytes, 16)?;
        let chunk_size = le_u32_at(bytes, 20)?;
        // Bytes 24..40 are the GUID: opaque, never interpreted.
        let part_number = le_u16_at(bytes, 40)?;
        let total_parts = le_u16_at(bytes, 42)?;
        if total_parts == 0 {
            return Err(CoreError::invalid(
                "wim total_parts is 0, but a WIM always has at least one part",
            ));
        }
        if part_number == 0 || part_number > total_parts {
            return Err(CoreError::invalid(format!(
                "wim part_number is {part_number} with total_parts {total_parts}: \
                 a part must be between 1 and total_parts"
            )));
        }
        let image_count = le_u32_at(bytes, 44)?;
        if image_count > MAX_IMAGE_COUNT {
            return Err(CoreError::invalid(format!(
                "wim image_count is {image_count}, over the {MAX_IMAGE_COUNT} image cap"
            )));
        }
        let offset_table = resource_at(bytes, 48)?;
        let xml = resource_at(bytes, 72)?;
        let boot_metadata = resource_at(bytes, 96)?;
        let boot_index_raw = le_u32_at(bytes, 120)?;
        if boot_index_raw > image_count {
            return Err(CoreError::invalid(format!(
                "wim boot_index is {boot_index_raw} but image_count is only {image_count}"
            )));
        }
        let integrity = resource_at(bytes, 124)?;
        // Bytes 148..208 are reserved: never interpreted.
        Ok(Self {
            image_count,
            compression: Compression::from_flags(flags),
            chunk_size,
            part_number,
            total_parts,
            boot_index: if boot_index_raw == 0 {
                None
            } else {
                Some(boot_index_raw)
            },
            offset_table,
            xml,
            boot_metadata,
            integrity,
        })
    }

    /// The `(offset, size)` byte window of the XML resource, validated
    /// against `volume_size`. A plain `(offset, size)` pair is returned
    /// rather than a `Range`: it keeps the MSRV-friendly integer style
    /// of the rest of the reader and reads the same at the call site.
    /// Refusals name the `xml` resource: a size over
    /// [`MAX_XML_BYTES`](super::MAX_XML_BYTES), an `offset + size`
    /// that overflows, or a window running past the volume end.
    pub fn checked_xml_range(&self, volume_size: u64) -> Result<(u64, u64)> {
        let size = self.xml.size;
        if size > super::MAX_XML_BYTES {
            return Err(CoreError::invalid(format!(
                "wim xml resource size {size} is over the {} byte cap",
                super::MAX_XML_BYTES
            )));
        }
        let end = self.xml.offset.checked_add(size).ok_or_else(|| {
            CoreError::invalid(format!(
                "wim xml resource at offset {} with size {size} \
                 overflows the byte offset arithmetic",
                self.xml.offset
            ))
        })?;
        if end > volume_size {
            return Err(CoreError::invalid(format!(
                "wim xml resource at offset {} with size {size} \
                 runs past the {volume_size} byte volume end",
                self.xml.offset
            )));
        }
        Ok((self.xml.offset, size))
    }
}

#[cfg(test)]
pub(crate) fn wim_bytes(xml_utf16le: &[u8], compression_flags: u32) -> Vec<u8> {
    /// XML offset: 208 rounded up to a multiple of 72.
    const XML_OFFSET: usize = 216;
    // Note: these header offsets are the parser's own, so a transposed
    // offset here is invisible to the suite — the offsets are pinned by
    // the measured layout in the module docs instead.
    let mut out = vec![0u8; XML_OFFSET + xml_utf16le.len()];
    out[0..8].copy_from_slice(&MAGIC);
    out[8..12].copy_from_slice(&HEADER_SIZE.to_le_bytes());
    out[12..16].copy_from_slice(&VERSION.to_le_bytes());
    out[16..20].copy_from_slice(&compression_flags.to_le_bytes());
    out[20..24].copy_from_slice(&0u32.to_le_bytes());
    // GUID bytes 24..40 stay zero: the parser never reads them.
    out[40..42].copy_from_slice(&1u16.to_le_bytes());
    out[42..44].copy_from_slice(&1u16.to_le_bytes());
    out[44..48].copy_from_slice(&2u32.to_le_bytes());
    // The XML resource at 72: the measured resource flags are 2.
    let size_and_flags = xml_utf16le.len() as u64 | (2u64 << 56);
    out[72..80].copy_from_slice(&size_and_flags.to_le_bytes());
    out[80..88].copy_from_slice(&(XML_OFFSET as u64).to_le_bytes());
    out[88..96].copy_from_slice(&(xml_utf16le.len() as u64).to_le_bytes());
    // boot_index 0 (none); offset-table, boot metadata and integrity
    // stay empty: the parser carries them but never validates them.
    out[XML_OFFSET..].copy_from_slice(xml_utf16le);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wim::MAX_XML_BYTES;

    fn utf16le(text: &str) -> Vec<u8> {
        let mut out = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn valid_bytes() -> Vec<u8> {
        wim_bytes(&utf16le("<WIM></WIM>"), 0x20082)
    }

    fn message(result: Result<WimHeader>) -> String {
        result.expect_err("the header must be refused").to_string()
    }

    #[test]
    fn magic_constant_matches_the_measured_bytes() {
        // The fixture writes the constant, so a typo in it would pass
        // the round trip: pin the constant against literal bytes.
        assert_eq!(MAGIC, *b"MSWIM\0\0\0");
    }

    #[test]
    fn solid_version_parses_like_plain() {
        // Pinned to the literal 1.14 bytes, not the constant, so a
        // wrong SOLID_VERSION is caught: solid archives (ESD) from
        // `--compress=LZMS` / `--compress=LZX --solid` carry version
        // 0x0000_0E00 little-endian.
        let mut bytes = valid_bytes();
        bytes[12..16].copy_from_slice(&[0x00, 0x0E, 0x00, 0x00]);
        let header = WimHeader::parse(&bytes).expect("solid 1.14 parses");
        assert_eq!(header.image_count, 2);
        assert_eq!(header.compression, Compression::Xpress);
        assert_eq!(header.xml.offset, 216);
    }

    #[test]
    fn round_trip_of_the_measured_layout() {
        let xml = utf16le("<WIM></WIM>");
        let header = WimHeader::parse(&wim_bytes(&xml, 0x20082)).expect("the fixture parses");
        assert_eq!(header.image_count, 2);
        assert_eq!(header.compression, Compression::Xpress);
        assert_eq!(header.compression.as_str(), "xpress");
        assert_eq!(header.compression.to_string(), "xpress");
        assert_eq!(header.part_number, 1);
        assert_eq!(header.total_parts, 1);
        assert_eq!(header.boot_index, None);
        assert_eq!(header.chunk_size, 0);
        assert_eq!(header.xml.size, xml.len() as u64);
        assert_eq!(header.xml.offset, 216);
        assert_eq!(header.xml.original_size, xml.len() as u64);
        assert_eq!(header.xml.flags, 2);
    }

    #[test]
    fn compression_labels_follow_the_flags() {
        for (flags, label) in [
            (0u32, Compression::None),
            (0x20082u32, Compression::Xpress),
            (0x40002u32, Compression::Lzx),
            (0x80002u32, Compression::Lzms),
            // 0x2 with none of the known bits: closest known value.
            (0x2u32, Compression::Xpress),
        ] {
            let mut bytes = valid_bytes();
            bytes[16..20].copy_from_slice(&flags.to_le_bytes());
            let header = WimHeader::parse(&bytes).expect("flags never refuse");
            assert_eq!(header.compression, label, "flags 0x{flags:08x}");
            assert_eq!(header.compression.to_string(), label.as_str());
        }
        assert_eq!(Compression::None.as_str(), "none");
        assert_eq!(Compression::Lzx.as_str(), "lzx");
        assert_eq!(Compression::Lzms.as_str(), "lzms");
    }

    #[test]
    fn short_buffer_names_the_header_length() {
        for len in [0, 1, 207] {
            let text = message(WimHeader::parse(&vec![0u8; len]));
            assert!(text.contains("wim header"), "{text}");
            assert!(text.contains("208"), "{text}");
        }
    }

    #[test]
    fn bad_magic_names_magic() {
        let mut bytes = valid_bytes();
        bytes[0] = b'X';
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("magic"), "{text}");
    }

    #[test]
    fn bad_cbsize_names_cbsize() {
        let mut bytes = valid_bytes();
        bytes[8..12].copy_from_slice(&209u32.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("cbSize"), "{text}");
    }

    #[test]
    fn bad_version_names_version() {
        let mut bytes = valid_bytes();
        bytes[12..16].copy_from_slice(&0x0001_0C00u32.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("version"), "{text}");
    }

    #[test]
    fn part_numbers_name_their_fields() {
        let mut bytes = valid_bytes();
        bytes[42..44].copy_from_slice(&0u16.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("total_parts"), "{text}");

        let mut bytes = valid_bytes();
        bytes[40..42].copy_from_slice(&0u16.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("part_number"), "{text}");

        let mut bytes = valid_bytes();
        bytes[40..42].copy_from_slice(&2u16.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("part_number"), "{text}");
    }

    #[test]
    fn image_count_cap_names_image_count() {
        let mut bytes = valid_bytes();
        bytes[44..48].copy_from_slice(&10_001u32.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("image_count"), "{text}");

        // The boundary itself still parses.
        let mut bytes = valid_bytes();
        bytes[44..48].copy_from_slice(&10_000u32.to_le_bytes());
        let header = WimHeader::parse(&bytes).expect("10000 images parse");
        assert_eq!(header.image_count, 10_000);
    }

    #[test]
    fn boot_index_names_boot_index() {
        let mut bytes = valid_bytes();
        bytes[120..124].copy_from_slice(&3u32.to_le_bytes());
        let text = message(WimHeader::parse(&bytes));
        assert!(text.contains("boot_index"), "{text}");

        // Equal to the image count is fine; only past it refuses.
        let mut bytes = valid_bytes();
        bytes[120..124].copy_from_slice(&2u32.to_le_bytes());
        let header = WimHeader::parse(&bytes).expect("boot index 2 of 2 parses");
        assert_eq!(header.boot_index, Some(2));
    }

    #[test]
    fn checked_xml_range_happy_path_and_refusals() {
        let xml = utf16le("<WIM></WIM>");
        let header = WimHeader::parse(&wim_bytes(&xml, 0x20082)).expect("the fixture parses");
        let total = 216 + xml.len() as u64;
        assert_eq!(
            header.checked_xml_range(total).expect("the range fits"),
            (216, xml.len() as u64)
        );

        // Offset past the volume end.
        let mut oversized = header.clone();
        oversized.xml.offset = total + 100;
        oversized.xml.size = 1;
        let text = oversized
            .checked_xml_range(total)
            .expect_err("the range must not fit")
            .to_string();
        assert!(text.contains("xml"), "{text}");

        // Size over the cap (no 16 MiB buffer needed: the check runs
        // before any read).
        let mut huge = header.clone();
        huge.xml.size = MAX_XML_BYTES + 1;
        let text = huge
            .checked_xml_range(u64::MAX)
            .expect_err("the cap must refuse")
            .to_string();
        assert!(text.contains("xml"), "{text}");

        // Offset arithmetic overflow.
        let mut overflow = header.clone();
        overflow.xml.offset = u64::MAX;
        overflow.xml.size = 1;
        let text = overflow
            .checked_xml_range(u64::MAX)
            .expect_err("the overflow must refuse")
            .to_string();
        assert!(text.contains("xml"), "{text}");
    }
}
