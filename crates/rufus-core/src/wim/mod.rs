//! The WIM reader (S16, slice 2 of 6): the `.wim` header and its XML
//! resource, which slice 3 wires into [`report::analyze`](crate::report::analyze).
//!
//! *Measured* — WIMs generated with `wimlib` in `docker run
//! archlinux:latest` with `--compress=none|XPRESS|LZX|LZMS`: the XML
//! resource is always stored uncompressed, as UTF-16LE with a `FF FE`
//! BOM at the offset the header names, in all four modes
//! (`size_in_wim == original_size` every time, and the bytes at the
//! offset decode to `<WIM>...`). That measurement is why there is no
//! decompressor here: implementing XPRESS/LZX/LZMS would be dead code
//! against every producer observed. The defensive behaviour, should a
//! future producer ever store the resource compressed, is to report
//! the XML as absent ([`WimReader::xml`] returns `Ok(None)` when the
//! bytes are not plain UTF-16) rather than fail the analysis.
//!
//! Caps (hostile images stay small and bounded): the XML resource is
//! refused past [`MAX_XML_BYTES`], the scanner keeps at most
//! [`MAX_DEPTH`](xml) open elements and 4096 characters of text per
//! field, and the buffer is grown with `try_reserve` so an absurd
//! extent errors instead of aborting. See [`header`] for the header
//! refusals and [`xml`] for the scanner contract.

pub mod header;
pub mod reader;
pub mod xml;

pub use header::Compression;
pub use header::HEADER_SIZE;
pub use header::ResourceHeader;
pub use header::WimHeader;
pub use reader::WimReader;
pub use xml::ImageXml;
pub use xml::WimVersion;
pub use xml::WimXml;

use crate::error::Result;
use crate::fs::Volume;

/// Cap on the XML resource size in bytes (16 MiB): real WIM XML is a
/// few KiB, so anything past this is a corrupt or hostile extent, not
/// a dictionary.
pub const MAX_XML_BYTES: u64 = 16 * 1024 * 1024;

/// True when the volume opens with the WIM magic: reads 8 bytes at
/// offset 0 and compares against [`MAGIC`](header::MAGIC). A volume
/// shorter than 8 bytes simply has no magic and reads `Ok(false)` —
/// never an I/O error for the short case. A genuine I/O refusal inside
/// the covered window is a real error and is returned (the bytes were
/// supposed to be there), mirroring the report's ISO probe.
pub fn probe(volume: &dyn Volume) -> Result<bool> {
    if volume.total_bytes() < header::MAGIC.len() as u64 {
        return Ok(false);
    }
    let mut magic = [0u8; header::MAGIC.len()];
    volume.read_exact_at(0, &mut magic)?;
    Ok(magic == header::MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::wim::header::wim_bytes;

    fn memory_volume(bytes: &[u8]) -> VecVolume {
        let mut volume = VecVolume::new(bytes.len() as u64, 512).expect("the fixture fits in RAM");
        if !bytes.is_empty() {
            volume.write_all_at(0, bytes).expect("the fixture writes");
        }
        volume
    }

    #[test]
    fn probe_matches_magic_only() {
        // A 4-byte volume is short: absent magic, never an error.
        let volume = VecVolume::new(4, 512).expect("the fixture fits in RAM");
        assert!(!probe(&volume).expect("a short volume never errors"));

        // A WIM probes positive (XPRESS flags, as measured).
        let bytes = wim_bytes(&[0xFF, 0xFE, 0x3C, 0x00], 0x20082);
        assert!(probe(&memory_volume(&bytes)).expect("the fixture probes"));

        // An ISO-like buffer (CD001, no WIM magic) probes negative.
        let mut iso_like = vec![0u8; 64];
        iso_like[0..5].copy_from_slice(b"CD001");
        assert!(!probe(&memory_volume(&iso_like)).expect("no magic"));

        // All zeroes of header length: no magic either.
        let blank = VecVolume::new(208, 512).expect("the fixture fits in RAM");
        assert!(!probe(&blank).expect("a blank volume never errors"));
    }
}
