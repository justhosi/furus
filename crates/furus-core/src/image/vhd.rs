//! VHD footer and dynamic-header validation, plus the logical reader.
//!
//! The footer is the 512 bytes at size minus 512 (`conectix`, format
//! version, data offset, creator, sizes, geometry, disk type, checksum,
//! GUID); a dynamic disk continues at the footer's data offset with a
//! 1024-byte `cxsparse` header and its block allocation table. All
//! multi-byte fields are big-endian. Layout facts come from the two
//! `qemu-img 11.1.3` images measured for this slice (fixed and dynamic
//! `-f vpc` at 64 MiB); the interpretation of each field follows the
//! long-stable VHD layout every producer writes.
//!
//! The reader ([`VhdReader`]) exposes the logical bytes as a
//! [`Volume`](crate::fs::Volume): a fixed disk reads file bytes
//! `0..current_size` (the footer is not part of the volume); a dynamic
//! disk maps each virtual block through its BAT entry (a big-endian
//! sector number, `0xFFFFFFFF` for unallocated) to a file block holding
//! a sector bitmap followed by the payload sectors.
//!
//! *Measured* — `qemu-img 11.1.3` in `archlinux:latest`: a fixed disk
//! converted from a 64 MiB raw file (`qemu-img convert -f raw -O vpc
//! -o subformat=fixed`) reads back as the 67125248 byte virtual size
//! (the CHS-rounded size from the footer, 16384 bytes larger than the
//! raw) followed by the footer, byte-exact against `qemu-img convert
//! -O raw`; a dynamic disk (`-o subformat=dynamic`) maps 2 MiB blocks
//! through big-endian BAT entries to a one-sector (512 byte) bitmap
//! plus payload, byte-exact the same way. Markers written with `dd`
//! into the raw at 0, 1 MiB, 2 MiB, 32 MiB and the last 512 bytes all
//! read back at their virtual offsets through both readers.
//!
//! *Inferred* — the sector-bitmap bit order (most-significant bit
//! first: bit 7 of byte 0 tracks the block's first sector). No
//! producer on this host emits a partial bitmap (`qemu-img convert`
//! and `qemu-io` both stamp full `0xFF` bitmaps), so the order was
//! pinned two ways. Against `qemu-io`: a hand-patched bitmap of `00
//! 80 ...` makes `qemu-io -f vpc` read sector 8 as present, which
//! only the MSB-first reading explains. In the unit fixture below:
//! a single bitmap byte of `0x80` marks only sector 0 present while
//! sectors 1 and 7 carry stale payload markers under clear bits, so
//! sector 0 reads its marker and sector 7 reads zeros — an asymmetric
//! byte, where MSB-first and LSB-first disagree and the test would
//! fail under either order's mirror. One honest divergence stays:
//! that same `qemu-io` reads payload bytes even for sectors whose bit
//! is clear, while this reader follows the spec and the slice mandate
//! and returns zeros for them — the two agree on every real image,
//! where allocated blocks carry full bitmaps.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

use super::be_u32_at;
use super::be_u64_at;
use super::read_at;
use super::window;

/// Length of the VHD footer in bytes.
const FOOTER_LEN: u64 = 512;
/// Length of the dynamic-disk header in bytes.
const DYN_HEADER_LEN: u64 = 1024;
/// `conectix`, the footer cookie.
const FOOTER_COOKIE: &[u8] = b"conectix";
/// `cxsparse`, the dynamic-header cookie.
const DYN_COOKIE: &[u8] = b"cxsparse";
/// The only file-format version the VHD layout defines (1.0).
const FORMAT_VERSION_1_0: u32 = 0x0001_0000;
/// Data offset of a fixed disk: no dynamic header follows.
const FIXED_DATA_OFFSET: u64 = 0xFFFF_FFFF_FFFF_FFFF;
/// Disk type of a fixed VHD.
const TYPE_FIXED: u32 = 2;
/// Disk type of a dynamic VHD.
const TYPE_DYNAMIC: u32 = 3;
/// Disk type of a differencing VHD (refused: it needs its parent).
const TYPE_DIFFERENCING: u32 = 4;
/// Bytes per BAT entry (one big-endian sector number each).
const BAT_ENTRY_LEN: u64 = 4;
/// BAT entry of a block with no storage: reads as zeros.
const BAT_UNALLOCATED: u32 = 0xFFFF_FFFF;
/// Bytes per payload sector: the block bitmap tracks one bit per
/// 512-byte sector.
const SECTOR_LEN: u64 = 512;
/// Bits tracked by one bitmap byte.
const BITS_PER_BYTE: u64 = 8;

/// Offset of the cookie within the footer.
const FOOTER_COOKIE_AT: usize = 0;
/// Offset of the file-format version within the footer.
const FOOTER_VERSION_AT: usize = 12;
/// Offset of the data offset within the footer.
const FOOTER_DATA_OFFSET_AT: usize = 16;
/// Offset of the creator application tag within the footer.
const FOOTER_CREATOR_AT: usize = 28;
/// Length of the creator application tag.
const FOOTER_CREATOR_LEN: usize = 4;
/// Offset of the current size within the footer.
const FOOTER_CURRENT_SIZE_AT: usize = 48;
/// Offset of the disk type within the footer.
const FOOTER_TYPE_AT: usize = 60;
/// Offset of the checksum within the footer.
const FOOTER_CHECKSUM_AT: usize = 64;

/// Offset of the BAT offset within the dynamic header.
const DYN_TABLE_OFFSET_AT: usize = 16;
/// Offset of the header version within the dynamic header.
const DYN_VERSION_AT: usize = 24;
/// Offset of the maximum BAT entry count within the dynamic header.
const DYN_MAX_ENTRIES_AT: usize = 28;
/// Offset of the block size within the dynamic header.
const DYN_BLOCK_SIZE_AT: usize = 32;
/// Offset of the checksum within the dynamic header.
const DYN_CHECKSUM_AT: usize = 36;

/// Validate a file [`detect`](super::detect) committed to
/// [`ImageKind::Vhd`](super::ImageKind::Vhd): the footer cookie, checksum, format version,
/// creator tag, disk type and size, plus the dynamic header and its
/// BAT window for dynamic disks.
///
/// Check order: cookie, checksum (untrusted bytes are not dispatched
/// on before they prove intact), format version, creator, disk type,
/// sizes, then the dynamic chain. Fixed (2) and dynamic (3) disks are
/// accepted; differencing (4) is refused for needing its parent image,
/// and any other type value is refused by number.
pub(crate) fn validate(volume: &dyn Volume, total: u64) -> Result<()> {
    if total < FOOTER_LEN {
        return Err(CoreError::invalid(format!(
            "vhd footer: file of {total} bytes is shorter than the 512 byte footer"
        )));
    }
    let base = total - FOOTER_LEN;
    let footer = read_at(volume, total, base, FOOTER_LEN, "vhd footer")?;
    let cookie = window(
        &footer,
        FOOTER_COOKIE_AT,
        FOOTER_COOKIE.len(),
        "vhd footer cookie",
    )?;
    if cookie != FOOTER_COOKIE {
        return Err(CoreError::invalid(
            "vhd footer cookie is not conectix: refusing a file the detector committed to VHD",
        ));
    }
    check_checksum(&footer, FOOTER_CHECKSUM_AT, "vhd footer")?;

    let version = be_u32_at(&footer, FOOTER_VERSION_AT, "vhd file format version")?;
    if version != FORMAT_VERSION_1_0 {
        return Err(CoreError::invalid(format!(
            "vhd file format version {version:#010x} is not 1.0 (0x00010000)"
        )));
    }

    let creator = window(
        &footer,
        FOOTER_CREATOR_AT,
        FOOTER_CREATOR_LEN,
        "vhd creator application",
    )?;
    if !creator.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(CoreError::invalid(
            "vhd creator application is not printable ASCII: refusing a corrupt footer",
        ));
    }

    let disk_type = be_u32_at(&footer, FOOTER_TYPE_AT, "vhd disk type")?;
    let current = be_u64_at(&footer, FOOTER_CURRENT_SIZE_AT, "vhd current size")?;
    if current == 0 {
        return Err(CoreError::invalid("vhd current size is zero"));
    }
    match disk_type {
        TYPE_FIXED => {
            // A fixed disk carries no dynamic header: its data offset
            // is all ones (the real `qemu-img -f vpc` fixed image reads
            // exactly that).
            let data_offset = be_u64_at(&footer, FOOTER_DATA_OFFSET_AT, "vhd data offset")?;
            if data_offset != FIXED_DATA_OFFSET {
                return Err(CoreError::invalid(format!(
                    "vhd fixed disk data offset {data_offset:#018x} is not all ones \
                     (no dynamic header follows a fixed disk)"
                )));
            }
            let want = current.checked_add(FOOTER_LEN).ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhd fixed disk current size {current} overflows with the 512 byte footer"
                ))
            })?;
            if total != want {
                return Err(CoreError::invalid(format!(
                    "vhd fixed disk: file of {total} bytes is not the current size \
                     {current} plus the 512 byte footer"
                )));
            }
        }
        TYPE_DYNAMIC => {
            let data_offset = be_u64_at(&footer, FOOTER_DATA_OFFSET_AT, "vhd data offset")?;
            validate_dynamic(volume, total, current, data_offset)?;
        }
        TYPE_DIFFERENCING => {
            return Err(CoreError::invalid(
                "vhd disk type 4 (differencing): parent images are not readable standalone",
            ));
        }
        other => {
            return Err(CoreError::invalid(format!(
                "vhd disk type {other} is not fixed (2) or dynamic (3)"
            )));
        }
    }
    Ok(())
}

/// Validate the dynamic header at `data_offset` of a disk whose footer
/// promised `current` bytes: the `cxsparse` cookie, the checksum, the
/// header version, a non-zero block size and table count, a BAT window
/// inside the file, and a table large enough to cover the disk
/// (`ceil(current / block_size)` entries).
fn validate_dynamic(volume: &dyn Volume, total: u64, current: u64, data_offset: u64) -> Result<()> {
    let header = read_at(
        volume,
        total,
        data_offset,
        DYN_HEADER_LEN,
        "vhd dynamic header",
    )?;
    if !header.starts_with(DYN_COOKIE) {
        return Err(CoreError::invalid(
            "vhd dynamic header cookie is not cxsparse: refusing a corrupt dynamic disk",
        ));
    }
    check_checksum(&header, DYN_CHECKSUM_AT, "vhd dynamic header")?;

    let version = be_u32_at(&header, DYN_VERSION_AT, "vhd dynamic header version")?;
    if version != FORMAT_VERSION_1_0 {
        return Err(CoreError::invalid(format!(
            "vhd dynamic header version {version:#010x} is not 1.0 (0x00010000)"
        )));
    }

    let block_size = be_u32_at(&header, DYN_BLOCK_SIZE_AT, "vhd dynamic header block size")?;
    if block_size == 0 {
        return Err(CoreError::invalid("vhd dynamic header block size is zero"));
    }
    let max_entries = be_u32_at(&header, DYN_MAX_ENTRIES_AT, "vhd maximum table entries")?;
    if max_entries == 0 {
        return Err(CoreError::invalid("vhd maximum table entries is zero"));
    }
    let table_offset = be_u64_at(&header, DYN_TABLE_OFFSET_AT, "vhd table offset")?;
    if table_offset == 0 {
        return Err(CoreError::invalid(
            "vhd table offset is zero: it would alias the footer copy dynamic disks carry at 0",
        ));
    }
    let table_len = u64::from(max_entries)
        .checked_mul(BAT_ENTRY_LEN)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block table of {max_entries} entries overflows the byte offset arithmetic"
            ))
        })?;
    let table_end = table_offset.checked_add(table_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd block table of {table_len} bytes at offset {table_offset} \
             overflows the byte offset arithmetic"
        ))
    })?;
    if table_end > total {
        return Err(CoreError::invalid(format!(
            "vhd block table of {table_len} bytes at offset {table_offset} \
             (bytes {table_offset}..{table_end}) runs past the {total} byte file end"
        )));
    }
    let block = u64::from(block_size);
    let required = current
        .checked_add(block - 1)
        .and_then(|rounded| rounded.checked_div(block))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd current size {current} with {block} byte blocks overflows the block count arithmetic"
            ))
        })?;
    if required > u64::from(max_entries) {
        return Err(CoreError::invalid(format!(
            "vhd current size {current} needs {required} block table entries for {block} byte \
             blocks but the header allows {max_entries}"
        )));
    }
    Ok(())
}

/// Check the one's-complement checksum stored at `at` of a `len`-byte
/// header: the stored value must equal the bitwise negation of the sum
/// of every other byte. The sum of at most 1024 bytes below 256 each
/// stays far below `u32::MAX`, so the `u32` accumulation cannot
/// overflow (512 times 255 is 130560).
fn check_checksum(header: &[u8], at: usize, what: &str) -> Result<()> {
    let stored = be_u32_at(header, at, &format!("{what} checksum"))?;
    let mut sum: u32 = 0;
    for (index, byte) in header.iter().enumerate() {
        if index < at || index >= at + 4 {
            sum += u32::from(*byte);
        }
    }
    let computed = !sum;
    if stored != computed {
        return Err(CoreError::invalid(format!(
            "{what} checksum mismatch: stored {stored:08x} against computed {computed:08x}"
        )));
    }
    Ok(())
}

/// How a [`VhdReader`] maps virtual bytes onto the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VhdLayout {
    /// File bytes `0..virtual_size` read through unchanged (the footer
    /// past them is not part of the volume).
    Fixed,
    /// BAT lookup plus sector bitmap per block (see [`VhdReader`]).
    Dynamic {
        /// File offset of the BAT (one big-endian sector number per
        /// 4 bytes).
        table_offset: u64,
        /// Payload bytes per block (2097152 on the measured image).
        block_size: u64,
        /// BAT entry count (an index past it is refused, never read).
        max_entries: u32,
    },
}

/// The logical VHD volume: the file's virtual bytes as a read-only
/// [`Volume`].
///
/// A fixed disk is the identity map over `0..virtual_size`; a dynamic
/// disk resolves each virtual byte to its block (`offset / block_size`),
/// reads that block's BAT entry, and — for allocated blocks — to the
/// payload sector the bitmap marks present. Unallocated BAT entries
/// (`0xFFFFFFFF`) and clear bitmap bits both read as zeros; no read
/// ever reaches the footers (at 0 or at the file end), the dynamic
/// header, the BAT or the bitmaps themselves. Every mapping is
/// bounds-checked before I/O with checked arithmetic, and any BAT
/// entry whose block window runs past the file end is refused naming
/// the entry, the sector and the file length. Tables are read
/// positionally on demand (4 bytes per BAT entry, 1 byte per bitmap
/// byte): nothing is cached, so a repeated read costs the same store
/// reads again.
pub(crate) struct VhdReader {
    file: Box<dyn Volume>,
    file_total: u64,
    virtual_size: u64,
    layout: VhdLayout,
}

impl std::fmt::Debug for VhdReader {
    /// The virtual size and the layout: the file itself has no useful
    /// textual shape (it is an open store), so it is not rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdReader")
            .field("virtual_size", &self.virtual_size)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

/// Open the validated VHD `file` (a `total` byte store [`validate`]
/// accepted) as its logical volume.
pub(crate) fn open(file: Box<dyn Volume>, total: u64) -> Result<VhdReader> {
    validate(file.as_ref(), total)?;
    let base = total.checked_sub(FOOTER_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd file of {total} bytes is shorter than the 512 byte footer"
        ))
    })?;
    let footer = read_at(file.as_ref(), total, base, FOOTER_LEN, "vhd footer")?;
    let virtual_size = be_u64_at(&footer, FOOTER_CURRENT_SIZE_AT, "vhd current size")?;
    let disk_type = be_u32_at(&footer, FOOTER_TYPE_AT, "vhd disk type")?;
    let layout = match disk_type {
        TYPE_FIXED => VhdLayout::Fixed,
        TYPE_DYNAMIC => {
            let data_offset = be_u64_at(&footer, FOOTER_DATA_OFFSET_AT, "vhd data offset")?;
            let header = read_at(
                file.as_ref(),
                total,
                data_offset,
                DYN_HEADER_LEN,
                "vhd dynamic header",
            )?;
            let block_size =
                be_u32_at(&header, DYN_BLOCK_SIZE_AT, "vhd dynamic header block size")?;
            let max_entries = be_u32_at(&header, DYN_MAX_ENTRIES_AT, "vhd maximum table entries")?;
            let table_offset = be_u64_at(&header, DYN_TABLE_OFFSET_AT, "vhd table offset")?;
            VhdLayout::Dynamic {
                table_offset,
                block_size: u64::from(block_size),
                max_entries,
            }
        }
        other => {
            return Err(CoreError::invalid(format!(
                "vhd disk type {other} is not fixed (2) or dynamic (3)"
            )));
        }
    };
    Ok(VhdReader {
        file,
        file_total: total,
        virtual_size,
        layout,
    })
}

/// Bitmap bytes covering `block_size` payload bytes at one bit per
/// 512-byte sector, rounded up to whole sectors (one sector per 2 MiB
/// block on the measured image). Checked arithmetic throughout: any
/// overflow is refused naming the block size.
fn bitmap_len(block_size: u64) -> Result<u64> {
    let sectors = block_size
        .checked_add(SECTOR_LEN - 1)
        .and_then(|rounded| rounded.checked_div(SECTOR_LEN))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block size {block_size} overflows the sector count arithmetic"
            ))
        })?;
    let bytes = sectors
        .checked_add(BITS_PER_BYTE - 1)
        .and_then(|rounded| rounded.checked_div(BITS_PER_BYTE))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block of {sectors} sectors overflows the bitmap size arithmetic"
            ))
        })?;
    bytes
        .checked_add(SECTOR_LEN - 1)
        .and_then(|rounded| rounded.checked_div(SECTOR_LEN))
        .and_then(|count| count.checked_mul(SECTOR_LEN))
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd bitmap of {bytes} bytes overflows the sector rounding arithmetic"
            ))
        })
}

/// Read one big-endian BAT sector number: `index` counts in entries
/// from `table_offset`, and an index past `max_entries` is refused
/// naming both numbers before any I/O.
fn bat_entry(
    file: &dyn Volume,
    file_total: u64,
    table_offset: u64,
    max_entries: u32,
    index: u64,
) -> Result<u32> {
    if index >= u64::from(max_entries) {
        return Err(CoreError::invalid(format!(
            "vhd block {index} is past the {max_entries} block table entries"
        )));
    }
    let at = table_offset
        .checked_add(index.checked_mul(BAT_ENTRY_LEN).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block table entry {index} overflows the byte offset arithmetic"
            ))
        })?)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd block table entry {index} at offset {table_offset} \
                 overflows the byte offset arithmetic"
            ))
        })?;
    let bytes = super::read_at(file, file_total, at, BAT_ENTRY_LEN, "vhd block table entry")?;
    super::be_u32_at(&bytes, 0, "vhd block table entry")
}

/// The file window of an allocated dynamic block: `bitmap_len` bitmap
/// bytes at `block_start` plus `block_size` payload bytes after them.
/// A block running past the file end is refused naming the BAT entry,
/// the sector and the file length.
fn block_window(file_total: u64, entry: u64, sector: u32, block_size: u64) -> Result<(u64, u64)> {
    let block_start = u64::from(sector).checked_mul(SECTOR_LEN).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd BAT entry {entry} sector {sector} overflows the byte offset arithmetic"
        ))
    })?;
    let bitmap = bitmap_len(block_size)?;
    let payload = block_start.checked_add(bitmap).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd BAT entry {entry} sector {sector} with {bitmap} bitmap bytes \
             overflows the byte offset arithmetic"
        ))
    })?;
    let end = payload.checked_add(block_size).ok_or_else(|| {
        CoreError::invalid(format!(
            "vhd BAT entry {entry} sector {sector} with {block_size} payload bytes \
             overflows the byte offset arithmetic"
        ))
    })?;
    if end > file_total {
        return Err(CoreError::invalid(format!(
            "vhd BAT entry {entry} sector {sector} (bytes {block_start}..{end}) runs past \
             the {file_total} byte file end"
        )));
    }
    Ok((block_start, bitmap))
}

impl VhdReader {
    /// Map one virtual span starting at `cur` (with `end` the read's
    /// end): the file offset (`None` reads as zeros) plus the span
    /// length, capped so the span never crosses a sector boundary (a
    /// fresh bitmap lookup applies past it) nor `end`.
    fn span(&self, cur: u64, end: u64) -> Result<(Option<u64>, u64)> {
        match self.layout {
            VhdLayout::Fixed => {
                let span = end.checked_sub(cur).ok_or_else(|| {
                    CoreError::invalid(format!("vhd read position {cur} runs past its end {end}"))
                })?;
                Ok((Some(cur), span))
            }
            VhdLayout::Dynamic {
                table_offset,
                block_size,
                max_entries,
            } => {
                let block = cur.checked_div(block_size).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhd offset {cur} with {block_size} byte blocks \
                         overflows the block number arithmetic"
                    ))
                })?;
                let base = block.checked_mul(block_size).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhd block {block} with {block_size} byte blocks \
                         overflows the byte offset arithmetic"
                    ))
                })?;
                let within = cur.checked_sub(base).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhd offset {cur} runs before its block {block} base {base}"
                    ))
                })?;
                let entry = bat_entry(
                    self.file.as_ref(),
                    self.file_total,
                    table_offset,
                    max_entries,
                    block,
                )?;
                if entry == BAT_UNALLOCATED {
                    let block_end = base.checked_add(block_size).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhd block {block} with {block_size} byte blocks \
                             overflows the byte offset arithmetic"
                        ))
                    })?;
                    let left = block_end.checked_sub(cur).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhd offset {cur} runs past its block {block} end {block_end}"
                        ))
                    })?;
                    let wanted = end.checked_sub(cur).ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhd read position {cur} runs past its end {end}"
                        ))
                    })?;
                    return Ok((None, left.min(wanted)));
                }
                let (block_start, bitmap) =
                    block_window(self.file_total, block, entry, block_size)?;
                let sector = within.checked_div(SECTOR_LEN).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhd offset {cur} in block {block} overflows the sector number arithmetic"
                    ))
                })?;
                let sector_off = within % SECTOR_LEN;
                let span = (SECTOR_LEN - sector_off).min(end - cur);
                let bit_at = block_start
                    .checked_add(sector / BITS_PER_BYTE)
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhd block {block} sector {sector} bitmap byte \
                         overflows the byte offset arithmetic"
                        ))
                    })?;
                let byte = super::read_at(
                    self.file.as_ref(),
                    self.file_total,
                    bit_at,
                    1,
                    "vhd block bitmap byte",
                )?;
                let byte = byte.first().ok_or_else(|| {
                    CoreError::invalid(format!(
                        "vhd block {block} sector {sector} bitmap byte is missing"
                    ))
                })?;
                // MSB first: bit 7 of byte 0 tracks the block's first
                // sector (pinned against qemu-io, see the module docs).
                if (*byte >> (7 - (sector % BITS_PER_BYTE))) & 1 == 0 {
                    return Ok((None, span));
                }
                let file_off = block_start
                    .checked_add(bitmap)
                    .and_then(|payload| payload.checked_add(sector.checked_mul(SECTOR_LEN)?))
                    .and_then(|sector_base| sector_base.checked_add(sector_off))
                    .ok_or_else(|| {
                        CoreError::invalid(format!(
                            "vhd block {block} sector {sector} at offset {sector_off} \
                             overflows the byte offset arithmetic"
                        ))
                    })?;
                Ok((Some(file_off), span))
            }
        }
    }
}

impl Volume for VhdReader {
    /// The virtual size from the footer (without any footer copy): a
    /// fixed disk is 512 bytes shorter than its file, a dynamic disk
    /// far shorter.
    fn total_bytes(&self) -> u64 {
        self.virtual_size
    }

    /// Fill `buf` from `offset`, mapping each span through the BAT and
    /// the bitmaps (dynamic) or straight through (fixed). The window is
    /// bounds-checked against the virtual size before any I/O, naming
    /// the length, the offset and the virtual size; writes are refused.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let len = u64::try_from(buf.len()).map_err(|_| {
            CoreError::invalid("vhd read length does not fit the byte offset arithmetic")
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "vhd read of {len} bytes at offset {offset} overflows the byte offset arithmetic"
            ))
        })?;
        if end > self.virtual_size {
            return Err(CoreError::invalid(format!(
                "vhd read of {} bytes at offset {offset} runs past the {} byte virtual size",
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
                    "vhd read span {span} does not fit this machine's usize"
                ))
            })?;
            let window_end = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("vhd read position overflows the offset arithmetic")
            })?;
            if window_end > total_len {
                return Err(CoreError::invalid(format!(
                    "vhd read window {done}..{window_end} runs past the {total_len} byte buffer"
                )));
            }
            let dest = buf.get_mut(done..window_end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "vhd read window {done}..{window_end} is not addressable"
                ))
            })?;
            match file_off {
                Some(at) => self.file.read_exact_at(at, dest)?,
                None => dest.fill(0),
            }
            done = done.checked_add(count).ok_or_else(|| {
                CoreError::invalid("vhd read position overflows the offset arithmetic")
            })?;
            cur = cur.checked_add(span).ok_or_else(|| {
                CoreError::invalid("vhd read position overflows the offset arithmetic")
            })?;
        }
        Ok(())
    }

    /// A VHD is opened read-only: any write is refused naming the
    /// length and the offset, and the store is left untouched.
    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        Err(CoreError::invalid(format!(
            "refusing to write {} bytes at offset {offset}: a vhd image volume is read-only",
            buf.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;

    /// Footer field offsets shared with the fixtures.
    const FOOTER_SIZE: usize = 512;

    /// A well-formed fixed-disk footer for a `total` byte file whose
    /// virtual size is `total - 512`, checksum fixed.
    fn fixed_footer(total: u64) -> Vec<u8> {
        let mut footer = vec![0u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
        footer[24..28].copy_from_slice(&0x327Bu32.to_be_bytes());
        footer[28..32].copy_from_slice(b"qemu");
        footer[32..36].copy_from_slice(&0x0005_0003u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        let current = total - 512;
        footer[40..48].copy_from_slice(&current.to_be_bytes());
        footer[48..56].copy_from_slice(&current.to_be_bytes());
        footer[56..60].copy_from_slice(&[0x03, 0xC4, 0x08, 0x11]);
        footer[60..64].copy_from_slice(&TYPE_FIXED.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        footer
    }

    /// Fix the one's-complement checksum at `at` of `header`.
    fn stamp_checksum(header: &mut [u8], at: usize) {
        let mut sum: u32 = 0;
        for (index, byte) in header.iter().enumerate() {
            if index < at || index >= at + 4 {
                sum += u32::from(*byte);
            }
        }
        header[at..at + 4].copy_from_slice(&(!sum).to_be_bytes());
    }

    /// A well-formed dynamic disk: footer copy, dynamic header, BAT,
    /// footer; `current` virtual bytes in `block_size` byte blocks.
    fn dynamic_disk(current: u64, block_size: u32) -> Vec<u8> {
        let max_entries = current.div_ceil(u64::from(block_size)) as u32;
        let table_offset: u64 = 1536;
        let data_offset: u64 = 512;
        let mut header = vec![0u8; 1024];
        header[0..8].copy_from_slice(b"cxsparse");
        header[8..16].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
        header[16..24].copy_from_slice(&table_offset.to_be_bytes());
        header[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        header[28..32].copy_from_slice(&max_entries.to_be_bytes());
        header[32..36].copy_from_slice(&block_size.to_be_bytes());
        stamp_checksum(&mut header, DYN_CHECKSUM_AT);

        let mut footer = vec![0u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&data_offset.to_be_bytes());
        footer[28..32].copy_from_slice(b"qemu");
        footer[32..36].copy_from_slice(&0x0005_0003u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&current.to_be_bytes());
        footer[48..56].copy_from_slice(&current.to_be_bytes());
        footer[60..64].copy_from_slice(&TYPE_DYNAMIC.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);

        let bat_len = max_entries as usize * 4;
        let total = (table_offset + bat_len as u64).div_ceil(512) * 512 + 512;
        let mut disk = vec![0xFFu8; total as usize];
        disk[0..512].copy_from_slice(&footer);
        disk[512..1536].copy_from_slice(&header);
        let end = (total - 512) as usize;
        disk[end..end + 512].copy_from_slice(&footer);
        disk
    }

    /// Validate `disk` through a memory volume of exactly that length.
    fn validate_disk(disk: &[u8]) -> Result<()> {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        validate(&volume, disk.len() as u64)
    }

    #[test]
    fn valid_fixed_and_dynamic_disks_pass() {
        let total: u64 = 67_125_248 + 512;
        let mut disk = vec![0u8; total as usize];
        let footer = fixed_footer(total);
        disk[total as usize - 512..].copy_from_slice(&footer);
        validate_disk(&disk).expect("the fixed disk validates");

        let dynamic = dynamic_disk(67_125_248, 2_097_152);
        validate_disk(&dynamic).expect("the dynamic disk validates");
    }

    #[test]
    fn truncated_footer_and_bad_cookie_refuse() {
        let volume = VecVolume::new(511, 512).expect("the RAM");
        let error = validate(&volume, 511).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("shorter than the 512 byte footer")
        );

        let mut disk = vec![0u8; 1024];
        disk[512..520].copy_from_slice(b"conectiy");
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("not conectix"));
    }

    #[test]
    fn bad_footer_checksum_refuses_naming_both_values() {
        let total: u64 = 4096 + 512;
        let mut disk = vec![0u8; total as usize];
        let mut footer = fixed_footer(total);
        footer[100] ^= 0x01;
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("checksum mismatch"), "{text}");
        assert!(text.contains("stored"), "{text}");
        assert!(text.contains("computed"), "{text}");
    }

    #[test]
    fn wrong_version_and_creator_and_type_refuse() {
        let total: u64 = 4096 + 512;
        let mut footer = fixed_footer(total);
        footer[12..16].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        let mut disk = vec![0u8; total as usize];
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("format version"));

        let mut footer = fixed_footer(total);
        footer[28..32].copy_from_slice(&[0xFF, 0x00, b'a', b'b']);
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("creator application"));

        for (disk_type, phrase) in [(TYPE_DIFFERENCING, "differencing"), (7u32, "not fixed")] {
            let mut footer = fixed_footer(total);
            footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
            stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
            disk[total as usize - 512..].copy_from_slice(&footer);
            let error = validate_disk(&disk).unwrap_err();
            assert!(error.to_string().contains(phrase), "{error:?}");
        }
    }

    #[test]
    fn fixed_size_mismatch_and_zero_current_size_refuse() {
        let total: u64 = 4096 + 512;
        let footer = fixed_footer(total + 512);
        let mut disk = vec![0u8; total as usize];
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("plus the 512 byte footer"));

        let mut footer = fixed_footer(total);
        footer[48..56].copy_from_slice(&0u64.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        assert!(error.to_string().contains("current size is zero"));

        // A fixed disk pointing at a dynamic header is corrupt: the
        // data offset must stay all ones.
        let mut footer = fixed_footer(total);
        footer[16..24].copy_from_slice(&512u64.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);
        disk[total as usize - 512..].copy_from_slice(&footer);
        let error = validate_disk(&disk).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("data offset"), "{text}");
        assert!(text.contains("all ones"), "{text}");
    }

    #[test]
    fn dynamic_chain_refusals_name_their_field() {
        // Bad dynamic checksum: flip a reserved byte, keep the cookie.
        let mut dynamic = dynamic_disk(1_048_576, 2_097_152);
        dynamic[600] ^= 0x40;
        let error = validate_disk(&dynamic).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("dynamic header checksum mismatch")
        );

        // Truncated dynamic header: point the data offset 100 bytes
        // before the file end so its 1024-byte window overruns.
        let mut cut = dynamic_disk(1_048_576, 2_097_152);
        let total = cut.len() as u64;
        let end = cut.len() - 512;
        cut[end + 16..end + 24].copy_from_slice(&(total - 100).to_be_bytes());
        stamp_checksum(&mut cut[end..end + 512], FOOTER_CHECKSUM_AT);
        let error = validate_disk(&cut).unwrap_err();
        assert!(error.to_string().contains("dynamic header"));

        // Table too small for the virtual size: claim one entry for a
        // two-block disk.
        let mut small = dynamic_disk(2 * 2_097_152, 2_097_152);
        small[512 + 28..512 + 32].copy_from_slice(&1u32.to_be_bytes());
        stamp_checksum(&mut small[512..1536], DYN_CHECKSUM_AT);
        let error = validate_disk(&small).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("needs 2 block table entries"), "{text}");
    }

    /// Open `disk` as its logical volume through a memory store.
    fn open_disk(disk: &[u8]) -> VhdReader {
        let mut volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        volume.write_all_at(0, disk).expect("the fixture fits");
        open(Box::new(volume), disk.len() as u64).expect("the valid disk opens")
    }

    /// Read `len` bytes at `offset` from `reader`.
    fn read_from(reader: &VhdReader, offset: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        reader
            .read_exact_at(offset, &mut out)
            .expect("the read fits");
        out
    }

    #[test]
    fn fixed_reader_passes_payload_through_without_the_footer() {
        let total: u64 = 4096 + 512;
        let mut disk = vec![0x5Au8; total as usize];
        disk[0..16].copy_from_slice(b"FIXED-PAYLOAD-00");
        disk[4096 - 16..4096].copy_from_slice(b"LAST-PAYLOAD-BYT");
        disk[total as usize - 512..].copy_from_slice(&fixed_footer(total));
        let reader = open_disk(&disk);
        // The virtual size drops the footer, not the payload.
        assert_eq!(reader.total_bytes(), 4096);
        let all = read_from(&reader, 0, 4096);
        assert_eq!(all, &disk[..4096]);
        assert_eq!(&all[..16], b"FIXED-PAYLOAD-00");
        assert_eq!(&all[4096 - 16..], b"LAST-PAYLOAD-BYT");

        // A read ending exactly on the virtual size fits; one byte
        // past it names the length, the offset and the virtual size.
        read_from(&reader, 4086, 10);
        let mut past = vec![0u8; 11];
        let error = reader.read_exact_at(4086, &mut past).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("11 bytes"), "{text}");
        assert!(text.contains("4086"), "{text}");
        assert!(text.contains("4096 byte virtual size"), "{text}");

        // The volume is read-only.
        let mut reader = reader;
        let error = reader.write_all_at(0, b"x").unwrap_err();
        assert!(error.to_string().contains("read-only"), "{error:?}");
    }

    /// A small dynamic disk: 8192 virtual bytes in two 4096 byte
    /// blocks (8 sectors each, so the bitmap is a single byte in one
    /// sector). Block 0 lives at sector 4 with only sector 0 marked
    /// present (`0x80`, MSB first); sectors 1 and 7 carry stale
    /// payload markers under clear bits, and block 1 is unallocated.
    fn dynamic_small() -> Vec<u8> {
        let current: u64 = 8192;
        let block_size: u32 = 4096;
        let max_entries: u32 = 2;
        let table_offset: u64 = 1536;
        let data_offset: u64 = 512;
        let mut header = vec![0u8; 1024];
        header[0..8].copy_from_slice(b"cxsparse");
        header[8..16].copy_from_slice(&FIXED_DATA_OFFSET.to_be_bytes());
        header[16..24].copy_from_slice(&table_offset.to_be_bytes());
        header[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        header[28..32].copy_from_slice(&max_entries.to_be_bytes());
        header[32..36].copy_from_slice(&block_size.to_be_bytes());
        stamp_checksum(&mut header, DYN_CHECKSUM_AT);

        let mut footer = vec![0u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&data_offset.to_be_bytes());
        footer[28..32].copy_from_slice(b"qemu");
        footer[32..36].copy_from_slice(&0x0005_0003u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&current.to_be_bytes());
        footer[48..56].copy_from_slice(&current.to_be_bytes());
        footer[60..64].copy_from_slice(&TYPE_DYNAMIC.to_be_bytes());
        stamp_checksum(&mut footer, FOOTER_CHECKSUM_AT);

        // BAT, block 0 (bitmap plus 8 payload sectors), footer.
        let total: usize = 6656 + 512;
        let mut disk = vec![0u8; total];
        disk[0..512].copy_from_slice(&footer);
        disk[512..1536].copy_from_slice(&header);
        disk[1536..1540].copy_from_slice(&4u32.to_be_bytes());
        disk[1540..1544].copy_from_slice(&BAT_UNALLOCATED.to_be_bytes());
        disk[2048] = 0x80;
        disk[2560..2576].copy_from_slice(b"SECTOR0-MARK-000");
        disk[2560 + 7 * 512..2560 + 7 * 512 + 16].copy_from_slice(b"SECTOR7-MARK-000");
        disk[2560 + 512..2576 + 512].copy_from_slice(b"STALE-SECTOR-001");
        disk[6656..].copy_from_slice(&footer);
        disk
    }

    #[test]
    fn dynamic_reader_maps_blocks_honouring_the_bitmap() {
        let reader = open_disk(&dynamic_small());
        assert_eq!(reader.total_bytes(), 8192);

        // The one present sector reads its payload ...
        assert_eq!(&read_from(&reader, 0, 16), b"SECTOR0-MARK-000");
        // ... while clear bitmap bits read as zeros even though the
        // file holds stale payload bytes there (spec behaviour;
        // qemu-io is laxer, see the module docs): sector 1 and sector
        // 7 both carry markers on disk. Sector 7 is the asymmetric
        // half of the `0x80` bitmap byte, so this assertion is what
        // pins the MSB-first order — under LSB-first it would read
        // the marker back.
        assert_eq!(read_from(&reader, 512, 32), vec![0u8; 32]);
        assert_eq!(read_from(&reader, 7 * 512, 16), vec![0u8; 16]);
        // ... and an unallocated block reads as zeros.
        assert_eq!(read_from(&reader, 4096, 4096), vec![0u8; 4096]);

        // A read may span a present sector and a clear-bit sector:
        // the marker head first, then zeros on both sides of the
        // sector boundary.
        let mut mixed = vec![0u8; 520];
        reader
            .read_exact_at(6, &mut mixed)
            .expect("the spanning read fits");
        assert_eq!(&mixed[..10], b"0-MARK-000");
        assert!(mixed[10..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn dynamic_reader_refusals_name_entry_sector_and_file() {
        // A BAT entry pointing past the file end refuses on read.
        let mut disk = dynamic_small();
        disk[1536..1540].copy_from_slice(&100_000u32.to_be_bytes());
        let reader = open_disk(&disk);
        let mut out = vec![0u8; 1];
        let error = reader.read_exact_at(0, &mut out).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("BAT entry 0"), "{text}");
        assert!(text.contains("sector 100000"), "{text}");
        assert!(text.contains("byte file end"), "{text}");

        // A block index past the table is refused before any I/O.
        let volume = VecVolume::new(disk.len() as u64, 512).expect("the RAM for the fixture");
        let error = bat_entry(&volume, disk.len() as u64, 1536, 2, 2).unwrap_err();
        assert!(error.to_string().contains("past the 2 block table entries"));
    }

    /// Counting in-memory [`Volume`]: records store reads through a
    /// shared counter so the mapping cost of each virtual read is
    /// observable. Test-only.
    struct CountingVolume {
        bytes: Vec<u8>,
        reads: std::rc::Rc<std::cell::Cell<u64>>,
    }

    impl Volume for CountingVolume {
        fn total_bytes(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            let start = offset as usize;
            let end = start + buf.len();
            let window = self.bytes.get(start..end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "read of {} bytes at offset {offset} runs past the volume end",
                    buf.len()
                ))
            })?;
            buf.copy_from_slice(window);
            Ok(())
        }

        fn write_all_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<()> {
            Err(CoreError::invalid("counting volume is read-only"))
        }
    }

    #[test]
    fn dynamic_reader_mapping_cost_is_one_bat_read_plus_use() {
        let disk = dynamic_small();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let counting = CountingVolume {
            bytes: disk,
            reads: std::rc::Rc::clone(&reads),
        };
        let total = counting.total_bytes();
        let reader = open(Box::new(counting), total).expect("the valid disk opens");
        reads.set(0);

        // An unallocated block costs exactly the BAT entry read.
        let mut out = vec![0u8; 64];
        reader
            .read_exact_at(5000, &mut out)
            .expect("the unallocated read fits");
        assert_eq!(out, vec![0u8; 64]);
        assert_eq!(reads.get(), 1, "one BAT entry read, no bitmap, no data");

        // A clear bitmap bit adds exactly the bitmap byte read; a
        // present sector adds its payload read on top. Nothing is
        // cached: the BAT entry is re-read every time.
        reader
            .read_exact_at(512, &mut out)
            .expect("the absent-sector read fits");
        assert_eq!(reads.get(), 1 + 2, "BAT plus bitmap byte");
        reader
            .read_exact_at(0, &mut out)
            .expect("the present-sector read fits");
        assert_eq!(reads.get(), 1 + 2 + 3, "BAT plus bitmap byte plus payload");
    }
}
