//! FFU header-triple validation, plus the logical reader.
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
//!
//! The reader ([`FfuReader`]) exposes the logical bytes as a
//! [`Volume`](crate::fs::Volume): the virtual size is the final-table
//! block count times the store block size, and each stored block
//! (below the write-descriptor count) maps to its payload window past
//! the manifest, catalog and hash table.
//!
//! *Inferred* — everything the reader maps: the manifest, catalog,
//! hash-table and payload adjacency order (the DISM-log order the
//! validator bounds but never parses apart), the identity order of
//! the stored blocks (write descriptor `i` covers flash block `i`),
//! and the zero-read of blocks past the stored count (unwritten flash
//! on the target). That identity mapping is assumed, not checked: the
//! reader never parses the write-descriptor table, so an FFU with
//! out-of-order or duplicated write descriptors would be misread
//! rather than refused. No `qemu-img`, DISM or Hyper-V sample exists on
//! this host to pin any of it down, so the unit tests below drive
//! synthetic triples only, and every refusal names its field.

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

/// The three headers in file order: the image and security headers
/// (whichever order the file keeps) plus the store header at byte 56
/// both orders share.
struct Layout {
    image: Vec<u8>,
    security: Vec<u8>,
    store: Vec<u8>,
}

/// Read the three headers: the 56-byte prefix decides the file order
/// with the detector's own commit (`is_image_first` /
/// `is_security_first`), so validation and the reader parse exactly
/// what detection promised. A prefix matching neither order is
/// refused by name.
fn read_layout(volume: &dyn Volume, total: u64) -> Result<Layout> {
    if total < HEADERS_PREFIX {
        return Err(CoreError::invalid(format!(
            "ffu file of {total} bytes is shorter than the 56 byte header prefix \
             (image, security and store headers)"
        )));
    }
    let prefix = read_at(volume, total, 0, HEADERS_PREFIX, "ffu header prefix")?;
    // The store header sits at byte 56 in both orders; only the first
    // 56 bytes swap.
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
    let store = read_at(
        volume,
        total,
        HEADERS_PREFIX,
        STORE_HEADER_LEN,
        "ffu store header",
    )?;
    Ok(Layout {
        image,
        security,
        store,
    })
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
    let layout = read_layout(volume, total)?;
    let image_size = le_u32_at(&layout.image, IMAGE_SIZE_AT, "ffu image header size")?;
    if image_size != IMAGE_HEADER_LEN as u32 {
        return Err(CoreError::invalid(format!(
            "ffu image header size {image_size} is not 24"
        )));
    }
    if window(
        &layout.image,
        IMAGE_SIG_AT,
        SIG_LEN,
        "ffu image header signature",
    )? != IMAGE_SIGNATURE
    {
        return Err(CoreError::invalid(
            "ffu image header signature is not ImageFlash: refusing a corrupt header",
        ));
    }
    let manifest = le_u32_at(&layout.image, IMAGE_MANIFEST_AT, "ffu manifest length")?;
    if manifest == 0 {
        return Err(CoreError::invalid(
            "ffu manifest length is zero: no stores described",
        ));
    }
    let chunk = le_u32_at(&layout.image, IMAGE_CHUNK_AT, "ffu image header chunk size")?;
    if chunk == 0 {
        return Err(CoreError::invalid("ffu image header chunk size is zero"));
    }

    let security_size = le_u32_at(
        &layout.security,
        SECURITY_SIZE_AT,
        "ffu security header size",
    )?;
    if security_size != SECURITY_SIZE {
        return Err(CoreError::invalid(format!(
            "ffu security header size {security_size} is not 32"
        )));
    }
    if window(
        &layout.security,
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
        &layout.security,
        SECURITY_CHUNK_AT,
        "ffu security header chunk size",
    )?;
    if chunk_kb != chunk {
        return Err(CoreError::invalid(format!(
            "ffu security header chunk size {chunk_kb} disagrees with the image header \
             chunk size {chunk}"
        )));
    }
    let algorithm = le_u32_at(
        &layout.security,
        SECURITY_ALG_AT,
        "ffu security header algorithm",
    )?;
    if algorithm != ALG_SHA256 {
        return Err(CoreError::invalid(format!(
            "ffu security header algorithm {algorithm} is not 32780 (SHA-256)"
        )));
    }
    let catalog = le_u32_at(&layout.security, SECURITY_CATALOG_AT, "ffu catalog size")?;
    if catalog == 0 {
        return Err(CoreError::invalid(
            "ffu catalog size is zero: no signature to check",
        ));
    }
    let hash_table = le_u32_at(
        &layout.security,
        SECURITY_HASHTABLE_AT,
        "ffu hash table size",
    )?;
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

    let store = &layout.store;
    let update = le_u32_at(store, STORE_UPDATE_AT, "ffu store header update type")?;
    if update != UPDATE_FULL {
        return Err(CoreError::invalid(format!(
            "ffu store header update type {update} is not 0 (full flash): \
             partial images need their base"
        )));
    }
    let major = le_u16_at(store, STORE_MAJOR_AT, "ffu store header major version")?;
    if major != STORE_MAJOR_1 {
        return Err(CoreError::invalid(format!(
            "ffu store header major version {major} is not 1"
        )));
    }
    let minor = le_u16_at(store, STORE_MINOR_AT, "ffu store header minor version")?;
    if minor != 0 {
        return Err(CoreError::invalid(format!(
            "ffu store header minor version {minor} is not 0"
        )));
    }
    let format_major = le_u16_at(store, STORE_FORMAT_MAJOR_AT, "ffu format major version")?;
    if !FORMAT_MAJORS.contains(&format_major) {
        return Err(CoreError::invalid(format!(
            "ffu format major version {format_major} is not 1, 2 or 3"
        )));
    }
    let format_minor = le_u16_at(store, STORE_FORMAT_MINOR_AT, "ffu format minor version")?;
    if format_minor != 0 {
        return Err(CoreError::invalid(format!(
            "ffu format minor version {format_minor} is not 0"
        )));
    }
    let block_size = le_u32_at(store, STORE_BLOCK_AT, "ffu store header block size")?;
    if block_size == 0 {
        return Err(CoreError::invalid("ffu store header block size is zero"));
    }
    let write_count = le_u32_at(store, STORE_WRITE_COUNT_AT, "ffu write descriptor count")?;
    if write_count == 0 {
        return Err(CoreError::invalid(
            "ffu write descriptor count is zero: no blocks stored",
        ));
    }
    let final_count = le_u32_at(store, STORE_FINAL_COUNT_AT, "ffu final table block count")?;
    if final_count == 0 {
        return Err(CoreError::invalid("ffu final table block count is zero"));
    }
    Ok(())
}

/// The store geometry the reader maps: the payload block size, the
/// stored-block count, the final (virtual) block count and the file
/// offset the payload starts at.
struct Geometry {
    block_size: u64,
    write_count: u64,
    virtual_size: u64,
    payload_base: u64,
}

/// Read the store geometry out of the validated headers: the payload
/// starts past the headers plus the manifest, catalog and hash table
/// (the adjacency order the DISM logs show — inferred, see the module
/// header), the virtual size is the final-table block count times the
/// block size, and the stored payload must fit inside the file.
/// Each refusal names the field and the value.
fn read_geometry(layout: &Layout, total: u64) -> Result<Geometry> {
    let manifest = le_u32_at(&layout.image, IMAGE_MANIFEST_AT, "ffu manifest length")?;
    let catalog = le_u32_at(&layout.security, SECURITY_CATALOG_AT, "ffu catalog size")?;
    let hash_table = le_u32_at(
        &layout.security,
        SECURITY_HASHTABLE_AT,
        "ffu hash table size",
    )?;
    let payload_base = HEADERS_END
        .checked_add(u64::from(manifest))
        .and_then(|sum| sum.checked_add(u64::from(catalog)))
        .and_then(|sum| sum.checked_add(u64::from(hash_table)))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu manifest {manifest}, catalog {catalog} and hash table {hash_table} \
                 overflow the byte offset arithmetic"
            ))
        })?;
    let block_size = le_u32_at(&layout.store, STORE_BLOCK_AT, "ffu store header block size")?;
    let block_size = u64::from(block_size);
    let write_count = le_u32_at(
        &layout.store,
        STORE_WRITE_COUNT_AT,
        "ffu write descriptor count",
    )?;
    let write_count = u64::from(write_count);
    let final_count = le_u32_at(
        &layout.store,
        STORE_FINAL_COUNT_AT,
        "ffu final table block count",
    )?;
    let final_count = u64::from(final_count);
    let virtual_size = final_count.checked_mul(block_size).ok_or_else(|| {
        CoreError::invalid(format!(
            "ffu final table of {final_count} blocks of {block_size} bytes \
             overflows the byte offset arithmetic"
        ))
    })?;
    let payload_len = write_count.checked_mul(block_size).ok_or_else(|| {
        CoreError::invalid(format!(
            "ffu store of {write_count} blocks of {block_size} bytes \
             overflows the byte offset arithmetic"
        ))
    })?;
    let payload_end = payload_base.checked_add(payload_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "ffu payload of {payload_len} bytes at offset {payload_base} \
             overflows the byte offset arithmetic"
        ))
    })?;
    if payload_end > total {
        return Err(CoreError::invalid(format!(
            "ffu payload of {payload_len} bytes at offset {payload_base} \
             (bytes {payload_base}..{payload_end}) runs past the {total} byte file end"
        )));
    }
    Ok(Geometry {
        block_size,
        write_count,
        virtual_size,
        payload_base,
    })
}

/// The logical FFU volume: the flashed bytes as a read-only
/// [`Volume`].
///
/// Stored blocks (below the write-descriptor count) read their
/// `block_size` payload window in identity order past the manifest,
/// catalog and hash table; blocks past the stored count (unwritten
/// flash on the target) read as zeros. Every mapping in this
/// paragraph is inferred — no sample exists on this host — and every
/// mapping is bounds-checked before I/O with checked arithmetic.
/// Nothing is cached.
pub(crate) struct FfuReader {
    file: Box<dyn Volume>,
    file_total: u64,
    virtual_size: u64,
    block_size: u64,
    write_count: u64,
    payload_base: u64,
}

impl std::fmt::Debug for FfuReader {
    /// The virtual size and the layout: the file itself has no useful
    /// textual shape (it is an open store), so it is not rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfuReader")
            .field("virtual_size", &self.virtual_size)
            .field("block_size", &self.block_size)
            .field("write_count", &self.write_count)
            .finish_non_exhaustive()
    }
}

/// Open the validated FFU `file` (a `total` byte store [`validate`]
/// accepted) as its logical volume.
pub(crate) fn open(file: Box<dyn Volume>, total: u64) -> Result<FfuReader> {
    validate(file.as_ref(), total)?;
    let layout = read_layout(file.as_ref(), total)?;
    let geometry = read_geometry(&layout, total)?;
    Ok(FfuReader {
        file,
        file_total: total,
        virtual_size: geometry.virtual_size,
        block_size: geometry.block_size,
        write_count: geometry.write_count,
        payload_base: geometry.payload_base,
    })
}

impl FfuReader {
    /// Map one virtual span starting at `cur` (with `end` the read's
    /// end): the file offset (`None` reads as zeros) plus the span
    /// length, capped so the span never crosses a block boundary (a
    /// fresh stored/zero decision applies past it) nor `end`.
    fn span(&self, cur: u64, end: u64) -> Result<(Option<u64>, u64)> {
        let block = cur.checked_div(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu offset {cur} with {} byte blocks overflows the block number arithmetic",
                self.block_size
            ))
        })?;
        let base = block.checked_mul(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu block {block} with {} byte blocks overflows the byte offset arithmetic",
                self.block_size
            ))
        })?;
        let within = cur.checked_sub(base).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu offset {cur} runs before its block {block} base {base}"
            ))
        })?;
        let block_end = base.checked_add(self.block_size).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu block {block} with {} byte blocks overflows the byte offset arithmetic",
                self.block_size
            ))
        })?;
        let left = block_end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu offset {cur} runs past its block {block} end {block_end}"
            ))
        })?;
        let wanted = end.checked_sub(cur).ok_or_else(|| {
            CoreError::invalid(format!("ffu read position {cur} runs past its end {end}"))
        })?;
        let span = left.min(wanted);
        if block >= self.write_count {
            return Ok((None, span));
        }
        let file_off = self
            .payload_base
            .checked_add(block.checked_mul(self.block_size).ok_or_else(|| {
                CoreError::invalid(format!(
                    "ffu block {block} with {} byte blocks \
                     overflows the byte offset arithmetic",
                    self.block_size
                ))
            })?)
            .and_then(|block_start| block_start.checked_add(within))
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "ffu block {block} at offset {within} overflows the byte offset arithmetic"
                ))
            })?;
        let span_end = file_off.checked_add(span).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu block {block} read of {span} bytes at offset {file_off} \
                 overflows the byte offset arithmetic"
            ))
        })?;
        if span_end > self.file_total {
            return Err(CoreError::invalid(format!(
                "ffu block {block} (bytes {file_off}..{span_end}) runs past \
                 the {} byte file end",
                self.file_total
            )));
        }
        Ok((Some(file_off), span))
    }
}

impl Volume for FfuReader {
    /// The final-table block count times the store block size: the
    /// flashed extent, headers and tables excluded.
    fn total_bytes(&self) -> u64 {
        self.virtual_size
    }

    /// Fill `buf` from `offset`, mapping each span through the store
    /// table (stored blocks read their payload, blocks past the
    /// stored count read as zeros). The window is bounds-checked
    /// against the virtual size before any I/O, naming the length,
    /// the offset and the virtual size; writes are refused.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len = u64::try_from(buf.len()).map_err(|_| {
            CoreError::invalid("ffu read length does not fit the byte offset arithmetic")
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "ffu read of {len} bytes at offset {offset} overflows the byte offset arithmetic"
            ))
        })?;
        if end > self.virtual_size {
            return Err(CoreError::invalid(format!(
                "ffu read of {} bytes at offset {offset} runs past the {} byte virtual size",
                buf.len(),
                self.virtual_size
            )));
        }
        let mut done: usize = 0;
        let mut cur = offset;
        let total_len = buf.len();
        while cur < end {
            let (file_off, span) = self.span(cur, end)?;
            let count = usize::try_from(span).map_err(|_| {
                CoreError::invalid(format!(
                    "ffu read span {span} does not fit this machine's usize"
                ))
            })?;
            let window_end = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("ffu read position overflows the offset arithmetic")
            })?;
            if window_end > total_len {
                return Err(CoreError::invalid(format!(
                    "ffu read window {done}..{window_end} runs past the {total_len} byte buffer"
                )));
            }
            let dest = buf.get_mut(done..window_end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "ffu read window {done}..{window_end} is not addressable"
                ))
            })?;
            match file_off {
                Some(at) => self.file.read_exact_at(at, dest)?,
                None => dest.fill(0),
            }
            done = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("ffu read position overflows the offset arithmetic")
            })?;
            cur = cur.checked_add(span).ok_or_else(|| {
                CoreError::invalid("ffu read position overflows the offset arithmetic")
            })?;
        }
        Ok(())
    }

    /// An FFU image is opened read-only: any write is refused naming
    /// the length and the offset, and the store is left untouched.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        Err(CoreError::invalid(format!(
            "refusing to write {} bytes at offset {offset}: a ffu image volume is read-only",
            buf.len()
        )))
    }
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

    /// A tiny readable disk: an image-first triple with a 100-byte
    /// manifest, a 64-byte catalog and a 128-byte hash table (payload
    /// at 596), 512-byte blocks, 3 stored blocks and a 5-block final
    /// table (a 2560 byte virtual disk in a 2132 byte file). Block 0
    /// and block 2 carry markers; block 1 is stored zeros.
    const READ_BLOCK: u64 = 512;
    const READ_PAYLOAD: usize = 596;

    fn readable_disk() -> Vec<u8> {
        let mut disk = valid_disk(false, READ_PAYLOAD + 3 * READ_BLOCK as usize);
        disk[56 + 204..56 + 208].copy_from_slice(&(READ_BLOCK as u32).to_le_bytes());
        disk[56 + 208..56 + 212].copy_from_slice(&3u32.to_le_bytes());
        disk[56 + 244..56 + 248].copy_from_slice(&5u32.to_le_bytes());
        disk[READ_PAYLOAD..READ_PAYLOAD + 16].copy_from_slice(b"FFU-BLK0-MARK-00");
        disk[READ_PAYLOAD + 2 * READ_BLOCK as usize + READ_BLOCK as usize - 16
            ..READ_PAYLOAD + 3 * READ_BLOCK as usize]
            .copy_from_slice(b"FFU-BLK2-TAIL-00");
        disk
    }

    /// Open `disk` as its logical volume through a memory store.
    fn open_disk(disk: &[u8]) -> FfuReader {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect("the valid disk opens")
    }

    /// Open `disk` expecting refusal: the error, not the reader.
    fn open_disk_err(disk: &[u8]) -> CoreError {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect_err("the corrupt disk refuses")
    }

    /// Read `len` bytes at `offset` from `reader`.
    fn read_from(reader: &FfuReader, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        reader
            .read_exact_at(offset, &mut out)
            .expect("the read fits");
        out
    }

    #[test]
    fn reader_maps_stored_blocks_and_zeroes_unwritten_flash() {
        let reader = open_disk(&readable_disk());
        assert_eq!(reader.total_bytes(), 5 * READ_BLOCK);

        assert_eq!(&read_from(&reader, 0, 16), b"FFU-BLK0-MARK-00");
        // Block 1 is stored fill (0xA5): stored bytes pass through,
        // which unwritten flash below never does.
        assert_eq!(read_from(&reader, READ_BLOCK, 64), vec![0xA5u8; 64]);
        assert_eq!(
            &read_from(&reader, 3 * READ_BLOCK - 16, 16),
            b"FFU-BLK2-TAIL-00"
        );
        // Blocks past the stored count read as zeros.
        assert_eq!(
            read_from(&reader, 3 * READ_BLOCK, 2 * READ_BLOCK as usize),
            vec![0u8; 2 * READ_BLOCK as usize]
        );

        // A read may span the last stored block and unwritten flash:
        // the marker tail first, then zeros.
        let mut mixed = vec![0u8; 32];
        reader
            .read_exact_at(3 * READ_BLOCK - 10, &mut mixed)
            .expect("the spanning read fits");
        assert_eq!(&mixed[..10], b"K2-TAIL-00");
        assert!(mixed[10..].iter().all(|byte| *byte == 0));

        // A read ending exactly on the virtual size fits; one byte
        // past it names the length, the offset and the virtual size.
        read_from(&reader, 5 * READ_BLOCK - 10, 10);
        let mut past = vec![0u8; 11];
        let error = reader
            .read_exact_at(5 * READ_BLOCK - 10, &mut past)
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("11 bytes"), "{text}");
        assert!(text.contains("virtual size"), "{text}");

        let mut reader = reader;
        let error = reader.write_all_at(0, b"x").unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error:?}");
    }

    #[test]
    fn truncated_payload_and_geometry_refusals_name_their_field() {
        let pristine = readable_disk();

        // The stored payload does not fit: the file ends 100 bytes
        // into the last stored block.
        let mut disk = pristine.clone();
        disk.truncate(READ_PAYLOAD + 2 * READ_BLOCK as usize + 100);
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("runs past"), "{error:?}");

        // A store claiming more blocks than the file holds refuses
        // naming the payload window and the file end.
        let mut disk = pristine.clone();
        disk[56 + 208..56 + 212].copy_from_slice(&u32::MAX.to_le_bytes());
        let error = open_disk_err(&disk);
        assert!(error.to_string().contains("runs past"), "{error:?}");

        assert_eq!(pristine, readable_disk(), "the mutants left no trace");
    }
}
