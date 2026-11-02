//! Read a WIM off a [`Volume`](crate::fs::Volume): the header plus
//! its XML resource.
//!
//! [`WimReader::open`] reads exactly the 208-byte header at offset 0;
//! [`WimReader::xml`] validates the XML extent against the volume size
//! (see [`WimHeader::checked_xml_range`](super::header::WimHeader::checked_xml_range)),
//! reads exactly that many bytes — never `read_to_end` on an untrusted
//! size — and parses them.
//!
//! The one declared gap: a resource that does not start with a UTF-16
//! BOM or a `<` byte is reported as absent (`Ok(None)`), not as an
//! error. Per the module docs the XML is stored uncompressed, so such
//! bytes mean a producer stored the resource compressed (or the extent
//! points at non-XML data); the reader has no decompressor by design
//! and says so by returning `None`. Any I/O failure, on the other
//! hand, is a [`CoreError`](crate::CoreError).

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::wim::header::HEADER_SIZE;
use crate::wim::header::WimHeader;
use crate::wim::xml;
use crate::wim::xml::WimXml;

/// True when `bytes` look like the plain (stored, uncompressed) XML
/// resource: a UTF-16LE BOM (`FF FE`) or a `<` first byte (which also
/// covers BOM-less UTF-16LE, whose first byte is `<`). Shared with the
/// report layer, which reads the resource through file windows rather
/// than a whole volume.
pub(crate) fn is_stored_xml(bytes: &[u8]) -> bool {
    matches!(
        (bytes.first(), bytes.get(1)),
        (Some(0xFF), Some(0xFE)) | (Some(0x3C), _)
    )
}

/// An opened WIM: the parsed header. The XML is read on demand with
/// [`xml`](Self::xml) so callers that only need the counts never pay
/// for the resource read.
#[derive(Debug, Clone)]
pub struct WimReader {
    header: WimHeader,
}

impl WimReader {
    /// Open the WIM on `volume`: read exactly [`HEADER_SIZE`] bytes at
    /// offset 0 and parse them (see
    /// [`WimHeader::parse`](super::header::WimHeader::parse) for the
    /// refusals). A short volume fails the read with the bounds named;
    /// use [`probe`](super::probe) first when absence must not error.
    pub fn open(volume: &dyn Volume) -> Result<Self> {
        let mut bytes = [0u8; HEADER_SIZE as usize];
        volume.read_exact_at(0, &mut bytes)?;
        Ok(Self {
            header: WimHeader::parse(&bytes)?,
        })
    }

    /// The parsed header.
    #[must_use]
    pub fn header(&self) -> &WimHeader {
        &self.header
    }

    /// Read and parse the XML resource: `Ok(None)` when the resource
    /// bytes are not plain UTF-16 (the compressed-resource case, a
    /// declared gap documented above — never an error), `Ok(Some)`
    /// otherwise. The range is cap-checked before any read and the
    /// buffer is grown with `try_reserve`, so a hostile extent errors
    /// instead of aborting the process.
    pub fn xml(&self, volume: &dyn Volume) -> Result<Option<WimXml>> {
        let (offset, size) = self.header.checked_xml_range(volume.total_bytes())?;
        let len = usize::try_from(size).map_err(|_| {
            CoreError::invalid(format!(
                "wim xml resource size {size} does not fit this machine's address space"
            ))
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve(len).map_err(|_| {
            CoreError::invalid(format!("wim xml resource size {size} cannot be buffered"))
        })?;
        bytes.resize(len, 0);
        volume.read_exact_at(offset, &mut bytes)?;
        if !is_stored_xml(&bytes) {
            return Ok(None);
        }
        Ok(Some(xml::parse(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::wim::header::wim_bytes;

    fn utf16le(text: &str, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(&[0xFF, 0xFE]);
        }
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn memory_volume(bytes: &[u8]) -> VecVolume {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the fixture fits in RAM");
        if !bytes.is_empty() {
            volume.write_all_at(0, bytes).expect("the fixture writes");
        }
        volume
    }

    const TWO_IMAGES: &str = "<WIM><IMAGE INDEX=\"1\"><NAME>Test Edition</NAME><DISPLAYNAME>Test</DISPLAYNAME><DESCRIPTION>Synthetic</DESCRIPTION></IMAGE><IMAGE INDEX=\"2\"><NAME>Second Edition</NAME></IMAGE><TOTALBYTES>16</TOTALBYTES></WIM>";

    #[test]
    fn full_path_reads_two_images_over_vec_volume() {
        let bytes = wim_bytes(&utf16le(TWO_IMAGES, true), 0x20082);
        let volume = memory_volume(&bytes);
        let reader = WimReader::open(&volume).expect("the fixture opens");
        assert_eq!(reader.header().image_count, 2);
        let parsed = reader
            .xml(&volume)
            .expect("the xml reads")
            .expect("the resource is plain UTF-16");
        assert_eq!(parsed.images.len(), 2);
        assert_eq!(parsed.images[0].index, 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Test Edition"));
        assert_eq!(parsed.images[0].display_name.as_deref(), Some("Test"));
        assert_eq!(parsed.images[0].description.as_deref(), Some("Synthetic"));
        assert_eq!(parsed.images[1].index, 2);
        assert_eq!(parsed.images[1].name.as_deref(), Some("Second Edition"));
        // The second image carries no DISPLAYNAME: it stays None.
        assert_eq!(parsed.images[1].display_name, None);
        assert_eq!(parsed.images[1].description, None);
        assert_eq!(parsed.total_bytes, Some(16));
    }

    #[test]
    fn xml_without_bom_reads_but_raw_bytes_are_none() {
        // No BOM: the first byte is `<`, so the resource still reads.
        let bytes = wim_bytes(&utf16le(TWO_IMAGES, false), 0x20082);
        let volume = memory_volume(&bytes);
        let reader = WimReader::open(&volume).expect("the fixture opens");
        let parsed = reader
            .xml(&volume)
            .expect("the xml reads")
            .expect("a `<`-led resource reads");
        assert_eq!(parsed.images.len(), 2);

        // Raw `<`-less bytes: the compressed-resource case, a declared
        // gap that reads as absent rather than erroring.
        let bytes = wim_bytes(b"\x78\x9c\x01\x02\x03\x04", 0x20082);
        let volume = memory_volume(&bytes);
        let reader = WimReader::open(&volume).expect("the fixture opens");
        assert_eq!(reader.xml(&volume).expect("raw bytes never error"), None);

        // An empty resource reads as absent the same way.
        let bytes = wim_bytes(b"", 0x20082);
        let volume = memory_volume(&bytes);
        let reader = WimReader::open(&volume).expect("the fixture opens");
        assert_eq!(reader.xml(&volume).expect("empty bytes never error"), None);
    }

    #[test]
    fn short_volume_fails_open_with_bounds_named() {
        let volume = VecVolume::new(100, 512).expect("the fixture fits in RAM");
        let text = WimReader::open(&volume)
            .expect_err("a short volume cannot open")
            .to_string();
        assert!(text.contains("100"), "{text}");
    }
}
