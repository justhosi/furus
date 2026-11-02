//! FFU header-triple validation.
//!
//! A Full Flash Update file carries three headers up front: the image
//! header (`ImageFlash`, 24 bytes: `cbSize`, the signature, the
//! manifest length, the chunk size), the security header
//! (`SignedImage `, 32 bytes: `cbSize`, the signature, the chunk size
//! in KiB, the hash algorithm, the catalog and hash-table sizes) and
//! the store header (248 bytes: update type, struct and format
//! versions, platform id, block size, write/validate descriptor counts
//! and the GPT table indexes). Real DISM files lead with the security
//! header (Rufus's own `vhd.c` probes `SignedImage ` at offset 4, and
//! the published DISM logs print the security header first); the
//! image-first order keeps the S03 detection working. Both orders put
//! the store header at byte 56 and the manifest, catalog, hash table
//! and payload after byte 304. All fields are little-endian.
//!
//! No FFU producer exists on this host, so every layout fact here is
//! inferred from the header shapes and the two published real-DISM
//! logs quoted in the module header (see `image`): there is no
//! whole-header checksum field to verify (integrity rides in the
//! catalog and hash table, whose windows are bounds-checked here),
//! and payload hash verification belongs to slice 4.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

use super::le_u16_at;
use super::le_u32_at;
use super::read_at;
use super::window;

/// Length of the image header in bytes.
const IMAGE_HEADER_LEN: u64 = 24;
/// Length of the security header in bytes.
const SECURITY_HEADER_LEN: u64 = 32;
/// Length of the store header in bytes.
const STORE_HEADER_LEN: u64 = 248;
/// First byte after the three headers (56 plus the 248-byte store).
const HEADERS_END: u64 = 304;
/// Shortest file that can hold the three headers in either order.
const HEADERS_PREFIX: u64 = 56;
/// `ImageFlash  ` (ten letters plus two spaces), the image signature.
const IMAGE_SIGNATURE: &[u8] = b"ImageFlash  ";
/// `SignedImage ` (eleven letters plus one space), the security signature.
const SECURITY_SIGNATURE: &[u8] = b"SignedImage ";
/// `cbSize` of the security header, leading a security-first file.
const SECURITY_SIZE: u32 = 32;
/// Hash algorithm id of SHA-256 (`CALG_SHA_256`).
const ALG_SHA256: u32 = 32780;
/// Full (not partial) flash: the only update type readable standalone.
const UPDATE_FULL: u32 = 0;
/// Store-struct major version (`MajorVersion`, validates the struct).
const STORE_MAJOR_1: u16 = 1;
/// Accepted image-format major versions (`FullFlashMajorVersion`):
/// phone-era 1 through DISM-era 2 and 3.
const FORMAT_MAJORS: [u16; 3] = [1, 2, 3];

/// Offset of `cbSize` within the image header.
const IMAGE_SIZE_AT: usize = 0;
/// Offset of the signature within the image header.
const IMAGE_SIG_AT: usize = 4;
/// Length of either signature.
const SIG_LEN: usize = 12;
/// Offset of the manifest length within the image header.
const IMAGE_MANIFEST_AT: usize = 16;
/// Offset of the chunk size within the image header.
const IMAGE_CHUNK_AT: usize = 20;
/// Offset of `cbSize` within the security header.
const SECURITY_SIZE_AT: usize = 0;
/// Offset of the signature within the security header.
const SECURITY_SIG_AT: usize = 4;
/// Offset of the chunk size in KiB within the security header.
const SECURITY_CHUNK_AT: usize = 16;
/// Offset of the hash algorithm within the security header.
const SECURITY_ALG_AT: usize = 20;
/// Offset of the catalog size within the security header.
const SECURITY_CATALOG_AT: usize = 24;
/// Offset of the hash-table size within the security header.
const SECURITY_HASHTABLE_AT: usize = 28;
/// Offset of the update type within the store header.
const STORE_UPDATE_AT: usize = 0;
/// Offset of the struct major version within the store header.
const STORE_MAJOR_AT: usize = 4;
/// Offset of the struct minor version within the store header.
const STORE_MINOR_AT: usize = 6;
/// Offset of the format major version within the store header.
const STORE_FORMAT_MAJOR_AT: usize = 8;
/// Offset of the format minor version within the store header.
const STORE_FORMAT_MINOR_AT: usize = 10;
/// Offset of the block size within the store header.
const STORE_BLOCK_AT: usize = 204;
/// Offset of the write-descriptor count within the store header.
const STORE_WRITE_COUNT_AT: usize = 208;
/// Offset of the final GPT block count within the store header.
const STORE_FINAL_COUNT_AT: usize = 244;

/// Whether `prefix` (the first bytes of the file) shows an
/// image-first FFU: either the bare `ImageFlash` magic at 0 (the S03
/// probe, kept so detection never narrows) or the `ImageFlash  `
/// signature at 4. The `cbSize` is deliberately *not* part of the
/// decision: a damaged size must still commit to this layout and
/// refuse on its header size, never fall back to raw. Shared by
/// [`detect`](super::detect) and [`validate`]: what detection commits
/// to, validation parses.
pub(crate) fn is_image_first(prefix: &[u8]) -> bool {
    if prefix.starts_with(b"ImageFlash") {
        return true;
    }
    window(prefix, IMAGE_SIG_AT, SIG_LEN, "ffu image header signature")
        .is_ok_and(|sig| sig == IMAGE_SIGNATURE)
}

/// Whether `prefix` shows a security-first FFU: the `SignedImage `
/// signature at 4 (the layout real DISM files use, which Rufus's own
/// `vhd.c` probes the same way). Like [`is_image_first`] the `cbSize`
/// stays out of the decision so a damaged size refuses by name.
/// Shared like [`is_image_first`].
pub(crate) fn is_security_first(prefix: &[u8]) -> bool {
    window(
        prefix,
        SECURITY_SIG_AT,
        SIG_LEN,
        "ffu security header signature",
    )
    .is_ok_and(|sig| sig == SECURITY_SIGNATURE)
}

/// Validate a file [`detect`](super::detect) committed to
/// [`ImageKind::Ffu`](super::ImageKind::Ffu): the image header (`cbSize` 24, the `ImageFlash`
/// signature, a non-zero manifest length and chunk size), the security
/// header (`cbSize` 32, the `SignedImage ` signature, a matching chunk
/// size, SHA-256, non-zero catalog and hash-table sizes), the manifest
/// plus catalog plus hash-table window inside the file, and the store
/// header (struct version 1.0, format version 1..=3, full update,
/// non-zero block size, write-descriptor and final-table counts).
///
/// Both file orders validate the same store header from byte 56 on;
/// only the first 56 bytes swap. Each refusal names the field and the
/// reason.
pub(crate) fn validate(volume: &dyn Volume, total: u64) -> Result<()> {
    if total < HEADERS_PREFIX {
        return Err(CoreError::invalid(format!(
            "ffu file of {total} bytes is shorter than the 56 byte header prefix \
             (image, security and store headers)"
        )));
    }
    let prefix = read_at(volume, total, 0, HEADERS_PREFIX, "ffu header prefix")?;
    // The store header sits at byte 56 in both orders; only the first
    // 56 bytes swap. The layout decision is the detector's own
    // (`is_image_first` / `is_security_first`), so validation parses
    // exactly what detection committed to.
    let (image_base, security_base) = if is_image_first(&prefix) {
        (0, IMAGE_HEADER_LEN)
    } else if is_security_first(&prefix) {
        (SECURITY_HEADER_LEN, 0)
    } else {
        return Err(CoreError::invalid(
            "ffu header prefix matches neither the ImageFlash-first nor the \
             security-first layout: refusing a file the detector committed to FFU",
        ));
    };
    let image = read_at(
        volume,
        total,
        image_base,
        IMAGE_HEADER_LEN,
        "ffu image header",
    )?;
    let security = read_at(
        volume,
        total,
        security_base,
        SECURITY_HEADER_LEN,
        "ffu security header",
    )?;

    let image_size = le_u32_at(&image, IMAGE_SIZE_AT, "ffu image header size")?;
    if image_size != IMAGE_HEADER_LEN as u32 {
        return Err(CoreError::invalid(format!(
            "ffu image header size {image_size} is not 24"
        )));
    }
    if window(&image, IMAGE_SIG_AT, SIG_LEN, "ffu image header signature")? != IMAGE_SIGNATURE {
        return Err(CoreError::invalid(
            "ffu image header signature is not ImageFlash: refusing a corrupt header",
        ));
    }
    let manifest = le_u32_at(&image, IMAGE_MANIFEST_AT, "ffu manifest length")?;
    if manifest == 0 {
        return Err(CoreError::invalid(
            "ffu manifest length is zero: no stores described",
        ));
    }
    let chunk = le_u32_at(&image, IMAGE_CHUNK_AT, "ffu image header chunk size")?;
    if chunk == 0 {
        return Err(CoreError::invalid("ffu image header chunk size is zero"));
    }

    let security_size = le_u32_at(&security, SECURITY_SIZE_AT, "ffu security header size")?;
    if security_size != SECURITY_SIZE {
        return Err(CoreError::invalid(format!(
            "ffu security header size {security_size} is not 32"
        )));
    }
    if window(
        &security,
        SECURITY_SIG_AT,
        SIG_LEN,
        "ffu security header signature",
    )? != SECURITY_SIGNATURE
    {
        return Err(CoreError::invalid(
            "ffu security header signature is not SignedImage: refusing a corrupt header",
        ));
    }
    let chunk_kb = le_u32_at(
        &security,
        SECURITY_CHUNK_AT,
        "ffu security header chunk size",
    )?;
    if chunk_kb != chunk {
        return Err(CoreError::invalid(format!(
            "ffu security header chunk size {chunk_kb} disagrees with the image header \
             chunk size {chunk}"
        )));
    }
    let algorithm = le_u32_at(&security, SECURITY_ALG_AT, "ffu security header algorithm")?;
    if algorithm != ALG_SHA256 {
        return Err(CoreError::invalid(format!(
            "ffu security header algorithm {algorithm} is not 32780 (SHA-256)"
        )));
    }
    let catalog = le_u32_at(&security, SECURITY_CATALOG_AT, "ffu catalog size")?;
    if catalog == 0 {
        return Err(CoreError::invalid(
            "ffu catalog size is zero: no signature to check",
        ));
    }
    let hash_table = le_u32_at(&security, SECURITY_HASHTABLE_AT, "ffu hash table size")?;
    if hash_table == 0 {
        return Err(CoreError::invalid(
            "ffu hash table size is zero: no integrity data",
        ));
    }
    // The manifest, catalog and hash table must at least fit past the
    // headers, wherever exactly each sits: a necessary bound that
    // catches truncation without guessing their order.
    let claimed = HEADERS_END
        .checked_add(u64::from(manifest))
        .and_then(|sum| sum.checked_add(u64::from(catalog)))
        .and_then(|sum| sum.checked_add(u64::from(hash_table)))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu manifest {manifest}, catalog {catalog} and hash table {hash_table} \
                 overflow the byte offset arithmetic"
            ))
        })?;
    if claimed > total {
        return Err(CoreError::invalid(format!(
            "ffu headers claim {claimed} bytes (304 header bytes plus manifest {manifest}, \
             catalog {catalog} and hash table {hash_table}) past the {total} byte file end"
        )));
    }

    let store = read_at(
        volume,
        total,
        HEADERS_PREFIX,
        STORE_HEADER_LEN,
        "ffu store header",
    )?;
    let update = le_u32_at(&store, STORE_UPDATE_AT, "ffu store header update type")?;
    if update != UPDATE_FULL {
        return Err(CoreError::invalid(format!(
            "ffu store header update type {update} is not 0 (full flash): \
             partial images need their base"
        )));
    }
    let major = le_u16_at(&store, STORE_MAJOR_AT, "ffu store header major version")?;
    if major != STORE_MAJOR_1 {
        return Err(CoreError::invalid(format!(
            "ffu store header major version {major} is not 1"
        )));
    }
    let minor = le_u16_at(&store, STORE_MINOR_AT, "ffu store header minor version")?;
    if minor != 0 {
        return Err(CoreError::invalid(format!(
            "ffu store header minor version {minor} is not 0"
        )));
    }
    let format_major = le_u16_at(&store, STORE_FORMAT_MAJOR_AT, "ffu format major version")?;
    if !FORMAT_MAJORS.contains(&format_major) {
        return Err(CoreError::invalid(format!(
            "ffu format major version {format_major} is not 1, 2 or 3"
        )));
    }
    let format_minor = le_u16_at(&store, STORE_FORMAT_MINOR_AT, "ffu format minor version")?;
    if format_minor != 0 {
        return Err(CoreError::invalid(format!(
            "ffu format minor version {format_minor} is not 0"
        )));
    }
    let block_size = le_u32_at(&store, STORE_BLOCK_AT, "ffu store header block size")?;
    if block_size == 0 {
        return Err(CoreError::invalid("ffu store header block size is zero"));
    }
    let write_count = le_u32_at(&store, STORE_WRITE_COUNT_AT, "ffu write descriptor count")?;
    if write_count == 0 {
        return Err(CoreError::invalid(
            "ffu write descriptor count is zero: no blocks stored",
        ));
    }
    let final_count = le_u32_at(&store, STORE_FINAL_COUNT_AT, "ffu final table block count")?;
    if final_count == 0 {
        return Err(CoreError::invalid("ffu final table block count is zero"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// A well-formed header triple plus a 100-byte manifest, a 64-byte
    /// catalog and a 128-byte hash table, padded to `total` bytes.
    /// `security_first` swaps the first two headers.
    fn valid_disk(security_first: bool, total: usize) -> Vec<u8> {
        let mut image = vec![0u8; 24];
        image[0..4].copy_from_slice(&24u32.to_le_bytes());
        image[4..16].copy_from_slice(b"ImageFlash  ");
        image[16..20].copy_from_slice(&100u32.to_le_bytes());
        image[20..24].copy_from_slice(&128u32.to_le_bytes());
        let mut security = vec![0u8; 32];
        security[0..4].copy_from_slice(&32u32.to_le_bytes());
        security[4..16].copy_from_slice(b"SignedImage ");
        security[16..20].copy_from_slice(&128u32.to_le_bytes());
        security[20..24].copy_from_slice(&32780u32.to_le_bytes());
        security[24..28].copy_from_slice(&64u32.to_le_bytes());
        security[28..32].copy_from_slice(&128u32.to_le_bytes());
        let mut store = vec![0u8; 248];
        store[4..6].copy_from_slice(&1u16.to_le_bytes());
        store[8..10].copy_from_slice(&3u16.to_le_bytes());
        store[204..208].copy_from_slice(&131072u32.to_le_bytes());
        store[208..212].copy_from_slice(&172004u32.to_le_bytes());
        store[244..248].copy_from_slice(&172004u32.to_le_bytes());

        let mut disk = vec![0xA5u8; 4096];
        if security_first {
            disk[0..32].copy_from_slice(&security);
            disk[32..56].copy_from_slice(&image);
        } else {
            disk[0..24].copy_from_slice(&image);
            disk[24..56].copy_from_slice(&security);
        }
        disk[56..304].copy_from_slice(&store);
        disk.resize(total, 0xA5);
        disk
    }

    /// Validate `disk` through a memory volume of exactly that length.
    fn validate_disk(disk: &[u8]) -> Result<()> {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        validate(&volume, disk.len() as u64)
    }

    #[test]
    fn both_file_orders_validate() {
        validate_disk(&valid_disk(false, 4096)).expect("the image-first file validates");
        validate_disk(&valid_disk(true, 4096)).expect("the security-first file validates");
    }

    #[test]
    fn truncated_prefix_and_unknown_layout_refuse() {
        let error = validate_disk(&valid_disk(false, 40)).unwrap_err();
        assert!(error.to_string().contains("56 byte header prefix"));

        let mut disk = valid_disk(false, 4096);
        disk[0..10].copy_from_slice(b"NotAnFFUx!");
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("neither"));
    }

    #[test]
    fn image_and_security_header_refusals_name_their_field() {
        let mut disk = valid_disk(false, 4096);
        disk[0..4].copy_from_slice(&25u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("image header size 25"));

        let mut disk = valid_disk(false, 4096);
        disk[16..20].copy_from_slice(&0u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("manifest length is zero"));

        let mut disk = valid_disk(false, 4096);
        disk[24..28].copy_from_slice(&33u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("security header size 33"));

        let mut disk = valid_disk(false, 4096);
        disk[24 + 16..24 + 20].copy_from_slice(&64u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("disagrees with the image header")
        );

        let mut disk = valid_disk(false, 4096);
        disk[24 + 20..24 + 24].copy_from_slice(&32772u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("not 32780"));

        // The manifest, catalog and hash table do not fit.
        let mut disk = valid_disk(false, 596);
        disk[16..20].copy_from_slice(&100_000u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("past the 596 byte file end"));
    }

    #[test]
    fn store_header_refusals_name_their_field() {
        let mut disk = valid_disk(false, 4096);
        disk[56 + 8..56 + 10].copy_from_slice(&4u16.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("format major version 4"));

        let mut disk = valid_disk(false, 4096);
        disk[56..60].copy_from_slice(&1u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("update type 1"));

        let mut disk = valid_disk(false, 4096);
        disk[56 + 204..56 + 208].copy_from_slice(&0u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("block size is zero"));

        let mut disk = valid_disk(false, 4096);
        disk[56 + 208..56 + 212].copy_from_slice(&0u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("write descriptor count is zero"));

        let mut disk = valid_disk(false, 4096);
        disk[56 + 244..56 + 248].copy_from_slice(&0u32.to_le_bytes());
        let error = validate_disk(&disk).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("final table block count is zero")
        );
    }
}
