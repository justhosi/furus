//! File set descriptor, file entries, extents and file data (S15,
//! slices 1-2).
//!
//! The logical volume's file set address leads to the file set descriptor
//! (tag 256), whose root directory ICB (a long address) leads to the root
//! file entry. Every directory and every file reads the same way: resolve
//! the ICB, parse the file entry, join its allocation extents (or take
//! the embedded bytes), and hand the first `information length` bytes to
//! the caller ([`fid`](super::fid) for directories, the reader for files).
//!
//! *Measured* — on the `mkudffs --udfrev=0x0201` images (see the slice
//! report): the file set descriptor's tag location is its
//! partition-relative block number; the root ICB has length one block and
//! partition reference 0; small directories and files are *extended* file
//! entries (tag 266) with ICB flags 3 (embedded: the bytes sit directly in
//! the descriptor, `length of allocation descriptors` of them after the
//! extended attributes) — an 88-byte subdirectory, a 19-byte file, a
//! 14-byte file holding a NUL byte and non-ASCII content, a 3-byte file;
//! a 10000-byte file carries one inline long allocation descriptor (type
//! 1) after the fixed 216-byte body with zero extended attributes, one
//!    10000-byte extent; every measured extent has type bits 0, partition
//!    reference 0 and zero implementation-use bytes; the ICB file-type byte
//!    reads 4 for directories and 5 for regular files; strategy type is 4
//!    throughout. Multi-extent directories, FIFOs (9) and symlinks (12)
//!    appear only in synthetic fixtures, never on these images.
//!
//! *Inferred* — the plain file entry offsets (tag 261: extended-attribute
//! area at 176, lengths at 168/172 — no measured image carries one, so
//! the offsets follow the Linux `fileEntry` struct for ECMA-167 4/14.9),
//! the ICB file-type values outside 4/5 (the ECMA-167 4/14.6.6 table
//! as Linux's `ICBTAG_FILE_TYPE_*` and OpenBSD's `UDF_ICB_FILETYPE_*`
//! agree: 0 unspecified, 1 unallocated, 2 integrity, 3 indirect, 6 block
//! device, 7 char device, 8 extended attributes, 9 FIFO, 10 socket,
//! 11 terminal, 12 symlink, 13 stream directory, 248 VAT, 249 realtime,
//! 250 metadata main, 251 metadata mirror), short allocation descriptor
//! shapes (spec text: every measured extent is long), and the extent-type
//! bits (only recorded extents are accepted; anything else refuses).

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;
use crate::udf::LongAd;
use crate::udf::MAX_DIR_BYTES;
use crate::udf::MAX_DIR_EXTENTS;
use crate::udf::MAX_FILE_BYTES;
use crate::udf::PartitionDesc;
use crate::udf::le_u16;
use crate::udf::le_u32;
use crate::udf::le_u64;
use crate::udf::parse_long_ad;
use crate::udf::read_block;
use crate::udf::read_bytes;
use crate::udf::tag;

/// File set descriptor tag id.
const TAG_FSD: u16 = 256;
/// File entry tag id.
const TAG_FE: u16 = 261;
/// Extended file entry tag id (what `mkudffs` writes for directories).
const TAG_EXTFE: u16 = 266;

/// Offset of the root directory ICB in a file set descriptor.
const FSD_ROOT_AT: usize = 400;

/// Offset of the ICB flags in a file entry's ICB tag (tag is 16 bytes,
/// flags are the last 2 of the 20-byte ICB tag).
const FE_FLAGS_AT: usize = 16 + 18;
/// Offset of the file-type byte in a file entry's ICB tag (the 12th of
/// the 20 ICB tag bytes: 4 prior + 2 strategy + 2 parameter + 2 maximum +
/// 1 reserved, then the type). Same in both entry shapes.
const FE_TYPE_AT: usize = 16 + 11;
/// Offset of the information length (both entry shapes).
const FE_INFO_AT: usize = 56;
/// Allocation type mask of the ICB flags (bits 0-2).
const FE_AD_MASK: u16 = 7;
/// Short allocation descriptors: extents in the entry's own partition.
const AD_SHORT: u16 = 0;
/// Long allocation descriptors: extents with their own partition refs.
const AD_LONG: u16 = 1;
/// Extended allocation descriptors: refused (never seen, unsupported).
const AD_EXTENDED: u16 = 2;
/// Embedded data: the descriptor bytes after the extended attributes
/// *are* the file data.
const AD_EMBEDDED: u16 = 3;

/// Offset of the extended-attribute and allocation lengths in a plain
/// file entry (spec text — no measured sample).
const FE_LENGTHS_AT: usize = 168;
/// Offset of the extended-attribute area in a plain file entry.
const FE_EA_AT: usize = 176;
/// Offset of the extended-attribute and allocation lengths in an
/// extended file entry (measured: 0 and 40/280).
const EXT_LENGTHS_AT: usize = 208;
/// Offset of the extended-attribute area in an extended file entry.
const EXT_EA_AT: usize = 216;

/// Length of a short allocation descriptor (length, position).
const SHORT_AD_LEN: usize = 8;
/// Length of a long allocation descriptor (length, block, reference).
const LONG_AD_LEN: usize = 16;
/// Offset of the partition reference in a long allocation descriptor.
const LONG_AD_PART_AT: usize = 8;

/// Extent-type bits (top two bits of an allocation extent length).
const EXTENT_TYPE_SHIFT: u32 = 30;
/// Recorded and allocated: the only extent type with readable data.
const EXTENT_RECORDED: u32 = 0;
/// Allocated but not recorded: names space with no valid data in it.
/// Refused like every other non-recorded type: reading it would fabricate
/// bytes the volume never recorded.
const EXTENT_UNRECORDED: u32 = 1;
/// Not allocated: free space, never data.
const EXTENT_FREE: u32 = 2;
/// Next extent: a pointer at a further descriptor chain, never data. The
/// reader follows no chains, so this refuses with its own message.
const EXTENT_NEXT: u32 = 3;

/// ICB file-type byte values (ECMA-167 4/14.6.6; measured on real images
/// for directories, regular files, FIFOs and symlinks, the rest per the
/// Linux and OpenBSD headers — see the module header).
pub const TYPE_UNDEF: u8 = 0;
pub const TYPE_UNALLOCATED: u8 = 1;
pub const TYPE_INTEGRITY: u8 = 2;
pub const TYPE_INDIRECT: u8 = 3;
/// Directories: the only type `read_dir` lists.
pub const TYPE_DIRECTORY: u8 = 4;
/// Regular files: the only type `read_file` reads.
pub const TYPE_FILE: u8 = 5;
pub const TYPE_BLOCK_DEVICE: u8 = 6;
pub const TYPE_CHAR_DEVICE: u8 = 7;
pub const TYPE_EXTENDED_ATTR: u8 = 8;
pub const TYPE_FIFO: u8 = 9;
pub const TYPE_SOCKET: u8 = 10;
pub const TYPE_TERMINAL: u8 = 11;
/// Symbolic links: refused everywhere (their targets are path-component
/// records, never decoded here).
pub const TYPE_SYMLINK: u8 = 12;
pub const TYPE_STREAM_DIR: u8 = 13;
pub const TYPE_VAT: u8 = 248;
pub const TYPE_REALTIME: u8 = 249;
pub const TYPE_META_MAIN: u8 = 250;
pub const TYPE_META_MIRROR: u8 = 251;

/// Display name of an ICB file-type byte for refusal messages: ASCII,
/// suitable for error strings. Unknown values read as `unknown file type
/// {n}` so no volume can smuggle non-ASCII into a log line.
#[must_use]
pub fn file_type_name(file_type: u8) -> String {
    match file_type {
        TYPE_UNDEF => String::from("unspecified"),
        TYPE_UNALLOCATED => String::from("unallocated space entry"),
        TYPE_INTEGRITY => String::from("partition integrity entry"),
        TYPE_INDIRECT => String::from("indirect entry"),
        TYPE_DIRECTORY => String::from("directory"),
        TYPE_FILE => String::from("regular file"),
        TYPE_BLOCK_DEVICE => String::from("block device"),
        TYPE_CHAR_DEVICE => String::from("character device"),
        TYPE_EXTENDED_ATTR => String::from("extended attributes record"),
        TYPE_FIFO => String::from("FIFO"),
        TYPE_SOCKET => String::from("socket"),
        TYPE_TERMINAL => String::from("terminal entry"),
        TYPE_SYMLINK => String::from("symbolic link"),
        TYPE_STREAM_DIR => String::from("stream directory"),
        TYPE_VAT => String::from("virtual allocation table"),
        TYPE_REALTIME => String::from("realtime file"),
        TYPE_META_MAIN => String::from("metadata main file"),
        TYPE_META_MIRROR => String::from("metadata mirror file"),
        other => format!("unknown file type {other}"),
    }
}

/// The file set descriptor as slice 1 reads it: the root directory ICB.
/// Everything else the descriptor carries (timestamps, identifiers, the
/// next extent, the system stream) belongs to later slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSetDescriptor {
    /// Long address of the root directory's file entry.
    pub root_icb: LongAd,
}

/// One parsed file entry: the allocation type with either the embedded
/// bytes or the raw allocation descriptors. Extended attributes are
/// skipped (their length only moves the data start); interpreting them
/// belongs to a later slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// True for an extended file entry (tag 266), false for tag 261.
    pub extended: bool,
    /// ICB file-type byte (4 directory, 5 regular file, 12 symlink, ...):
    /// decides whether the entry lists, reads or refuses.
    pub file_type: u8,
    /// Information length: the valid data prefix in bytes.
    pub info_len: u64,
    /// Embedded file bytes (allocation type 3 only).
    pub embedded: Vec<u8>,
    /// Raw allocation descriptors (types 0 and 1 only).
    pub ads: Vec<AllocDesc>,
}

/// One raw allocation descriptor: the extent length with its address. The
/// extent-type bits must already be clear (recorded); anything else is
/// refused at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocDesc {
    /// Extent in the file entry's own partition.
    Short {
        /// Extent length in bytes (top two type bits clear).
        len: u32,
        /// Partition-relative block number of the extent.
        pos: u32,
    },
    /// Extent with its own partition reference.
    Long {
        /// Extent length in bytes (top two type bits clear).
        len: u32,
        /// Partition-relative block number of the extent.
        lbn: u32,
        /// Index into the logical volume's partition map table.
        part: u16,
    },
}

/// One collected data segment: the partition-relative block where it
/// starts (for file identifier tag-location checks) with its byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSeg {
    /// Partition-relative block number of the segment's first block.
    pub start: u32,
    /// Segment length in bytes.
    pub len: u64,
}

/// One allocation extent resolved to an absolute byte window: the
/// partition-bounds check has already passed, so the window is safe to
/// read. Windows join in file order; a file's first `information length`
/// bytes across them are its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedExtent {
    /// Partition-relative block number of the extent's first block.
    pub rel: u32,
    /// Absolute byte offset of the extent's first byte.
    pub offset: u64,
    /// Extent length in bytes (type bits already stripped).
    pub len: u64,
}

/// Read the file set descriptor at absolute block `abs_lbn` (whose
/// partition-relative number is `rel_lbn`): tag id 256, location matching
/// `rel_lbn`, a passing CRC, then the root ICB.
pub fn read_fsd(
    volume: &dyn Volume,
    size: u32,
    abs_lbn: u32,
    rel_lbn: u32,
) -> Result<FileSetDescriptor> {
    let total = volume.total_bytes();
    let block = read_block(volume, abs_lbn, size, total, "file set descriptor")?;
    let tag = tag::parse(&block, "file set descriptor")?;
    if tag.id != TAG_FSD {
        return Err(CoreError::invalid(format!(
            "file set descriptor at block {abs_lbn} has tag id {} not {TAG_FSD}",
            tag.id
        )));
    }
    if tag.location != rel_lbn {
        return Err(CoreError::invalid(format!(
            "file set descriptor at block {abs_lbn} claims tag location {} not the \
             partition-relative block {rel_lbn}",
            tag.location
        )));
    }
    tag::verify_crc(&block, &tag, "file set descriptor")?;
    Ok(FileSetDescriptor {
        root_icb: parse_long_ad(&block, FSD_ROOT_AT, "file set descriptor")?,
    })
}

/// Read the file entry at absolute block `abs_lbn` (partition-relative
/// `rel_lbn`): tag id 261 or 266, location matching `rel_lbn`, a passing
/// CRC, then the ICB file type and flags, information length and
/// allocation area. Extended allocation descriptors (type 2) and unknown
/// types refuse naming the value: type 2 points at a tag-258 allocation
/// extent elsewhere on the volume, a chain this reader does not follow,
/// so entries using it refuse even though the descriptor shape is known.
pub fn read_file_entry(
    volume: &dyn Volume,
    size: u32,
    abs_lbn: u32,
    rel_lbn: u32,
) -> Result<FileEntry> {
    let total = volume.total_bytes();
    let block = read_block(volume, abs_lbn, size, total, "file entry")?;
    let tag = tag::parse(&block, "file entry")?;
    let extended = match tag.id {
        TAG_FE => false,
        TAG_EXTFE => true,
        other => {
            return Err(CoreError::invalid(format!(
                "file entry at block {abs_lbn} has tag id {other} not {TAG_FE} or \
                 {TAG_EXTFE}: refusing a non file entry"
            )));
        }
    };
    if tag.location != rel_lbn {
        return Err(CoreError::invalid(format!(
            "file entry at block {abs_lbn} claims tag location {} not the \
             partition-relative block {rel_lbn}",
            tag.location
        )));
    }
    tag::verify_crc(&block, &tag, "file entry")?;
    let what = format!("file entry at block {abs_lbn}");
    let file_type = block.get(FE_TYPE_AT).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} ends before its file type byte at {FE_TYPE_AT}"
        ))
    })?;
    let flags = le_u16(&block, FE_FLAGS_AT, &what)?;
    let ad_type = flags & FE_AD_MASK;
    let info_len = le_u64(&block, FE_INFO_AT, &what)?;
    let (lengths_at, ea_at) = if extended {
        (EXT_LENGTHS_AT, EXT_EA_AT)
    } else {
        (FE_LENGTHS_AT, FE_EA_AT)
    };
    let ea_len = u64::from(le_u32(&block, lengths_at, &what)?);
    let ad_len = u64::from(le_u32(&block, lengths_at + 4, &what)?);
    let data_at = (ea_at as u64).checked_add(ea_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} extended attributes run past the arithmetic"
        ))
    })?;
    let data_end = data_at.checked_add(ad_len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} allocation area of {ad_len} bytes overflows the arithmetic"
        ))
    })?;
    if data_end > u64::from(size) {
        return Err(CoreError::invalid(format!(
            "{what} allocation area of {ad_len} bytes past {ea_len} extended attribute bytes \
             runs past the {size} byte block"
        )));
    }
    match ad_type {
        AD_EMBEDDED => {
            let start = usize::try_from(data_at).map_err(|_| {
                CoreError::invalid(format!("{what} data offset {data_at} is not addressable"))
            })?;
            let end = usize::try_from(data_end).map_err(|_| {
                CoreError::invalid(format!("{what} data end {data_end} is not addressable"))
            })?;
            let embedded = block.get(start..end).ok_or_else(|| {
                CoreError::invalid(format!(
                    "{what} embedded data {start}..{end} runs past the block"
                ))
            })?;
            Ok(FileEntry {
                extended,
                file_type,
                info_len,
                embedded: embedded.to_vec(),
                ads: Vec::new(),
            })
        }
        AD_SHORT | AD_LONG => {
            let unit = if ad_type == AD_SHORT {
                SHORT_AD_LEN
            } else {
                LONG_AD_LEN
            } as u64;
            if !ad_len.is_multiple_of(unit) {
                return Err(CoreError::invalid(format!(
                    "{what} allocation area of {ad_len} bytes is not a multiple of the \
                     {unit} byte allocation descriptor"
                )));
            }
            // No count cap here: the entry block itself bounds how many
            // descriptors fit, and each caller caps the join through
            // `resolve_extents` with its own limit.
            let area = block
                .get(
                    usize::try_from(data_at).map_err(|_| {
                        CoreError::invalid(format!(
                            "{what} data offset {data_at} is not addressable"
                        ))
                    })?..usize::try_from(data_end).map_err(|_| {
                        CoreError::invalid(format!("{what} data end {data_end} is not addressable"))
                    })?,
                )
                .ok_or_else(|| {
                    CoreError::invalid(format!("{what} allocation area runs past the block"))
                })?;
            let mut ads = Vec::new();
            let mut at: usize = 0;
            let mut index: u64 = 0;
            while at < area.len() {
                let desc = area.get(at..at + unit as usize).ok_or_else(|| {
                    CoreError::invalid(format!("{what} allocation descriptor at {at} is truncated"))
                })?;
                let raw_len = le_u32(desc, 0, &what)?;
                let extent_type = raw_len >> EXTENT_TYPE_SHIFT;
                match extent_type {
                    EXTENT_RECORDED => {}
                    EXTENT_NEXT => {
                        return Err(CoreError::invalid(format!(
                            "{what} allocation descriptor {index} is a next-extent pointer \
                             (type {EXTENT_NEXT}): extent chains are not followed, so the \
                             entry refuses"
                        )));
                    }
                    EXTENT_UNRECORDED => {
                        return Err(CoreError::invalid(format!(
                            "{what} allocation descriptor {index} has extent type \
                             {EXTENT_UNRECORDED} (allocated but not recorded): only recorded \
                             extents (type {EXTENT_RECORDED}) carry readable data"
                        )));
                    }
                    EXTENT_FREE => {
                        return Err(CoreError::invalid(format!(
                            "{what} allocation descriptor {index} has extent type \
                             {EXTENT_FREE} (not allocated): only recorded extents (type \
                             {EXTENT_RECORDED}) carry readable data"
                        )));
                    }
                    other => {
                        return Err(CoreError::invalid(format!(
                            "{what} allocation descriptor {index} has extent type {other}: \
                             only recorded extents (type {EXTENT_RECORDED}) carry readable \
                             data"
                        )));
                    }
                }
                let len = raw_len & 0x3FFF_FFFF;
                if ad_type == AD_SHORT {
                    ads.push(AllocDesc::Short {
                        len,
                        pos: le_u32(desc, 4, &what)?,
                    });
                } else {
                    ads.push(AllocDesc::Long {
                        len,
                        lbn: le_u32(desc, 4, &what)?,
                        part: le_u16(desc, LONG_AD_PART_AT, &what)?,
                    });
                }
                at = at.saturating_add(unit as usize);
                index = index.saturating_add(1);
            }
            Ok(FileEntry {
                extended,
                file_type,
                info_len,
                embedded: Vec::new(),
                ads,
            })
        }
        AD_EXTENDED => Err(CoreError::invalid(format!(
            "{what} uses extended allocation descriptors (type {AD_EXTENDED}): their extents \
             live in a tag-258 allocation extent descriptor elsewhere on the volume, a chain \
             this reader does not follow, so only short (0), long (1) and embedded (3) \
             descriptors are supported"
        ))),
        other => Err(CoreError::invalid(format!(
            "{what} has unknown allocation descriptor type {other}: only short (0), long (1) \
             and embedded (3) descriptors are supported"
        ))),
    }
}

/// Collect the first `info_len` bytes of a directory's data: embedded
/// bytes pass through, short and long extents resolve through
/// [`resolve_extents`] (every window checked against its partition extent
/// before I/O, never just the store). Returns the bytes with the segment
/// layout for tag-location checks (`fe_rel` is the file entry's own
/// partition-relative block, which anchors embedded data).
/// Refuses an information length past the collected bytes, a total past
/// [`MAX_DIR_BYTES`], and any extent escaping its partition — each naming
/// the numbers.
///
/// Eight parameters because the call needs the whole addressing context
/// at once; bundling them would only hide the same fields.
#[allow(clippy::too_many_arguments)]
pub fn collect_data(
    volume: &dyn Volume,
    size: u32,
    maps: &[u16],
    partitions: &[PartitionDesc],
    home: &PartitionDesc,
    entry: &FileEntry,
    what: &str,
    fe_rel: u32,
) -> Result<(Vec<u8>, Vec<DataSeg>)> {
    if !entry.ads.is_empty() || entry.info_len > entry.embedded.len() as u64 {
        return collect_extents(volume, size, maps, partitions, home, entry, what);
    }
    let len = usize::try_from(entry.info_len).map_err(|_| {
        CoreError::invalid(format!(
            "{what} information length {} is not addressable",
            entry.info_len
        ))
    })?;
    let data = entry.embedded.get(..len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} information length {} runs past the {} embedded bytes",
            entry.info_len,
            entry.embedded.len()
        ))
    })?;
    Ok((
        data.to_vec(),
        vec![DataSeg {
            start: fe_rel,
            len: entry.info_len,
        }],
    ))
}

/// Extent-backed (and over-long embedded) collection: resolve every
/// allocation extent against its partition, then join them in order
/// through [`resolve_extents`] and cut to the information length. A summed
/// length past the information length is not an error: only the length
/// reads, and the tail bytes (block padding, as the `-b 512` image shows)
/// are never returned.
fn collect_extents(
    volume: &dyn Volume,
    size: u32,
    maps: &[u16],
    partitions: &[PartitionDesc],
    home: &PartitionDesc,
    entry: &FileEntry,
    what: &str,
) -> Result<(Vec<u8>, Vec<DataSeg>)> {
    let total = volume.total_bytes();
    if entry.ads.is_empty() {
        return Err(CoreError::invalid(format!(
            "{what} information length {} runs past the {} embedded bytes: the entry \
             carries no allocation descriptors to back it",
            entry.info_len,
            entry.embedded.len()
        )));
    }
    let windows = resolve_extents(
        size,
        maps,
        partitions,
        home,
        &entry.ads,
        what,
        MAX_DIR_EXTENTS,
    )?;
    let mut collected: u64 = 0;
    for window in &windows {
        collected = collected.checked_add(window.len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} extent lengths overflow the byte arithmetic"
            ))
        })?;
    }
    if entry.info_len > collected {
        return Err(CoreError::invalid(format!(
            "{what} information length {} runs past the {collected} collected extent bytes",
            entry.info_len
        )));
    }
    if collected > MAX_DIR_BYTES {
        return Err(CoreError::invalid(format!(
            "{what} directory data of {collected} bytes runs past the {MAX_DIR_BYTES} byte cap"
        )));
    }
    let count = usize::try_from(collected).map_err(|_| {
        CoreError::invalid(format!("{what} data length {collected} is not addressable"))
    })?;
    let mut out = Vec::new();
    out.try_reserve(count).map_err(|_| {
        CoreError::invalid(format!(
            "{what} directory data of {collected} bytes cannot be buffered"
        ))
    })?;
    let mut segs = Vec::new();
    for window in &windows {
        let bytes = read_bytes(volume, window.offset, window.len, total, what)?;
        out.extend_from_slice(&bytes);
        segs.push(DataSeg {
            start: window.rel,
            len: window.len,
        });
    }
    let keep = usize::try_from(entry.info_len).map_err(|_| {
        CoreError::invalid(format!(
            "{what} information length {} is not addressable",
            entry.info_len
        ))
    })?;
    let data = out.get(..keep).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} information length {} runs past the {} collected bytes",
            entry.info_len,
            out.len()
        ))
    })?;
    Ok((data.to_vec(), segs))
}

/// Resolve every allocation descriptor to an absolute byte window,
/// checking each against its partition extent *before* any I/O: the
/// extent must start inside the partition (`rel` below its length in
/// blocks) and its `ceil(len / size)` blocks must end inside it. The raw
/// store extent is never the authority — an extent that fits the store
/// but escapes the partition still refuses, naming the file (`what`), the
/// descriptor index and the byte range. At most `max_extents` descriptors
/// join: bounds the I/O one entry can demand.
#[allow(clippy::too_many_arguments)]
pub fn resolve_extents(
    size: u32,
    maps: &[u16],
    partitions: &[PartitionDesc],
    home: &PartitionDesc,
    ads: &[AllocDesc],
    what: &str,
    max_extents: usize,
) -> Result<Vec<ResolvedExtent>> {
    if size == 0 {
        return Err(CoreError::invalid(format!(
            "{what} cannot resolve extents with a zero block size"
        )));
    }
    if ads.len() > max_extents {
        return Err(CoreError::invalid(format!(
            "{what} claims {} allocation descriptors past the {max_extents} extent cap",
            ads.len()
        )));
    }
    let mut out = Vec::new();
    for (index, desc) in ads.iter().enumerate() {
        let (len, partition, rel) = match desc {
            AllocDesc::Short { len, pos } => (u64::from(*len), *home, *pos),
            AllocDesc::Long { len, lbn, part } => {
                let resolved = resolve_map(maps, partitions, *part, what)?;
                (u64::from(*len), resolved, *lbn)
            }
        };
        if rel >= partition.length {
            return Err(CoreError::invalid(format!(
                "{what} allocation descriptor {index} starts at partition-relative block \
                 {rel}: partition {} holds only {} blocks",
                partition.number, partition.length
            )));
        }
        let need = len.div_ceil(u64::from(size));
        let end_rel = u64::from(rel).checked_add(need).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} allocation descriptor {index} at partition-relative block {rel} \
                 overflows the block arithmetic"
            ))
        })?;
        let abs = partition.start.checked_add(rel).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} allocation descriptor {index} at partition-relative block {rel} \
                 overflows the block number"
            ))
        })?;
        let offset = u64::from(abs).checked_mul(u64::from(size)).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} allocation descriptor {index} at block {abs} overflows the byte \
                 offset arithmetic"
            ))
        })?;
        let end = offset.checked_add(len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} allocation descriptor {index} of {len} bytes at offset {offset} \
                 overflows the byte offset arithmetic"
            ))
        })?;
        if end_rel > u64::from(partition.length) {
            return Err(CoreError::invalid(format!(
                "{what} allocation descriptor {index} of {len} bytes at partition-relative \
                 blocks {rel}..{end_rel} runs past partition {} of {} blocks (absolute \
                 bytes {offset}..{end})",
                partition.number, partition.length
            )));
        }
        out.push(ResolvedExtent { rel, offset, len });
    }
    Ok(out)
}

/// Check a file's information length against its resolved windows: an
/// information length past the summed extent bytes refuses (the entry
/// promises data its extents do not hold), a sum past [`MAX_FILE_BYTES`]
/// refuses, and a non-addressable length refuses. A sum past the length is
/// fine: reads stop at the length, and the tail is never returned.
pub fn check_file_bounds(info_len: u64, windows: &[ResolvedExtent], what: &str) -> Result<()> {
    let mut collected: u64 = 0;
    for window in windows {
        collected = collected.checked_add(window.len).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} extent lengths overflow the byte arithmetic"
            ))
        })?;
    }
    if info_len > collected {
        return Err(CoreError::invalid(format!(
            "{what} information length {info_len} runs past the {collected} collected extent bytes"
        )));
    }
    if collected > MAX_FILE_BYTES {
        return Err(CoreError::invalid(format!(
            "{what} file data of {collected} bytes runs past the {MAX_FILE_BYTES} byte cap"
        )));
    }
    let _ = usize::try_from(info_len).map_err(|_| {
        CoreError::invalid(format!(
            "{what} information length {info_len} is not addressable"
        ))
    })?;
    Ok(())
}

/// Read the first `keep` bytes across `windows` (file order, clamped at
/// `keep`): every window read is bounds-checked before its I/O. An empty
/// read returns no bytes without touching the store.
pub fn read_windows(
    volume: &dyn Volume,
    windows: &[ResolvedExtent],
    keep: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let total = volume.total_bytes();
    let count = usize::try_from(keep)
        .map_err(|_| CoreError::invalid(format!("{what} read length {keep} is not addressable")))?;
    let mut out = Vec::new();
    out.try_reserve(count).map_err(|_| {
        CoreError::invalid(format!(
            "{what} file data of {keep} bytes cannot be buffered"
        ))
    })?;
    let mut remaining = keep;
    for window in windows {
        if remaining == 0 {
            break;
        }
        let take = window.len.min(remaining);
        let bytes = read_bytes(volume, window.offset, take, total, what)?;
        out.extend_from_slice(&bytes);
        remaining = remaining.saturating_sub(take);
    }
    if remaining > 0 {
        return Err(CoreError::invalid(format!(
            "{what} file windows hold {} fewer bytes than the {keep} requested: refusing a \
             short read",
            remaining
        )));
    }
    Ok(out)
}

/// Read up to `buf.len()` bytes at `offset` across `windows` (file order):
/// returns the bytes placed (0 at end of file). Refuses an offset past
/// `file_len`, naming both; every window read is bounds-checked before
/// its I/O.
pub fn read_windows_at(
    volume: &dyn Volume,
    windows: &[ResolvedExtent],
    file_len: u64,
    offset: u64,
    buf: &mut [u8],
    what: &str,
) -> Result<usize> {
    if offset > file_len {
        return Err(CoreError::invalid(format!(
            "{what} read at offset {offset} runs past the {file_len} byte file"
        )));
    }
    if buf.is_empty() || offset == file_len {
        return Ok(0);
    }
    let total = volume.total_bytes();
    let mut want = (file_len.saturating_sub(offset)).min(buf.len() as u64);
    let mut skip = offset;
    let mut placed: usize = 0;
    for window in windows {
        if want == 0 {
            break;
        }
        if skip >= window.len {
            skip = skip.saturating_sub(window.len);
            continue;
        }
        let at = window.offset.checked_add(skip).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} read window at offset {} overflows the byte arithmetic",
                window.offset
            ))
        })?;
        let take = (window.len.saturating_sub(skip)).min(want);
        let count = usize::try_from(take).map_err(|_| {
            CoreError::invalid(format!("{what} read length {take} is not addressable"))
        })?;
        let bytes = read_bytes(volume, at, take, total, what)?;
        let buffer_len = buf.len();
        let end_placed = placed.saturating_add(count);
        let dest = buf.get_mut(placed..end_placed).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} read window {placed}..{end_placed} runs past the {buffer_len} byte buffer"
            ))
        })?;
        let src = bytes.get(..count).ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} read of {take} bytes runs past the bytes returned"
            ))
        })?;
        dest.copy_from_slice(src);
        placed = placed.saturating_add(count);
        want = want.saturating_sub(take);
        skip = 0;
    }
    if want > 0 {
        return Err(CoreError::invalid(format!(
            "{what} file windows end {want} bytes before the requested read: refusing a \
             short read"
        )));
    }
    Ok(placed)
}

/// Resolve a partition reference through the map table to its partition
/// descriptor: refuses a reference past the table and a number with no
/// descriptor, naming both.
pub fn resolve_map(
    maps: &[u16],
    partitions: &[PartitionDesc],
    reference: u16,
    what: &str,
) -> Result<PartitionDesc> {
    let number = maps.get(usize::from(reference)).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} partition reference {reference} runs past the {} partition maps",
            maps.len()
        ))
    })?;
    partitions
        .iter()
        .find(|seen| seen.number == number)
        .copied()
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} partition reference {reference} maps to partition {number} with no \
                 partition descriptor"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::VecVolume;
    use crate::udf::stamp_tag;

    const SIZE: u32 = 512;

    /// File set block with the root ICB (length `SIZE`, block `lbn`,
    /// reference 0) at absolute block `abs`.
    fn fsd_block(abs: u32, lbn: u32) -> Vec<u8> {
        let _ = abs;
        let mut block = vec![0u8; SIZE as usize];
        block[400..404].copy_from_slice(&SIZE.to_le_bytes());
        block[404..408].copy_from_slice(&lbn.to_le_bytes());
        stamp_tag(&mut block, TAG_FSD, (SIZE - 16) as u16, lbn);
        block
    }

    /// Extended file entry block with `embedded` bytes as its data,
    /// information length `info`, file type `ftype`, at absolute block
    /// `abs` claiming partition-relative `rel`.
    fn ext_entry(abs: u32, rel: u32, embedded: &[u8], info: u64, ftype: u8) -> Vec<u8> {
        let _ = abs;
        let mut block = vec![0u8; SIZE as usize];
        block[27] = ftype;
        block[16 + 18..16 + 20].copy_from_slice(&AD_EMBEDDED.to_le_bytes());
        block[56..64].copy_from_slice(&info.to_le_bytes());
        block[208..212].copy_from_slice(&0u32.to_le_bytes());
        block[212..216].copy_from_slice(&(embedded.len() as u32).to_le_bytes());
        block[216..216 + embedded.len()].copy_from_slice(embedded);
        stamp_tag(&mut block, TAG_EXTFE, (SIZE - 16) as u16, rel);
        block
    }

    /// Store with `blocks` laid from absolute block `first` on.
    fn store(blocks: &[Vec<u8>], first: u32) -> VecVolume {
        let total = u64::from(first + blocks.len() as u32) * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("the fixture fits in RAM");
        for (index, block) in blocks.iter().enumerate() {
            volume
                .write_all_at(u64::from(first + index as u32) * u64::from(SIZE), block)
                .expect("the block fits");
        }
        volume
    }

    #[test]
    fn fsd_parses_the_root_icb() {
        let volume = store(&[fsd_block(40, 8)], 40);
        let fsd = read_fsd(&volume, SIZE, 40, 8).expect("the file set parses");
        assert_eq!(fsd.root_icb.extent_length, SIZE);
        assert_eq!(fsd.root_icb.lbn, 8);
        assert_eq!(fsd.root_icb.partition_ref, 0);
    }

    #[test]
    fn fsd_wrong_tag_refuses() {
        let mut block = fsd_block(40, 8);
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 8);
        let volume = store(&[block], 40);
        let error = read_fsd(&volume, SIZE, 40, 8).expect_err("tag 261 is no file set");
        assert!(error.to_string().contains("261"), "{:?}", error);
    }

    #[test]
    fn fsd_location_mismatch_refuses() {
        let volume = store(&[fsd_block(40, 8)], 40);
        let error = read_fsd(&volume, SIZE, 40, 9).expect_err("relative 9 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('8'), "{text}");
    }

    #[test]
    fn ext_entry_collects_embedded_data() {
        let volume = store(&[ext_entry(41, 9, &[1, 2, 3, 4], 4, TYPE_DIRECTORY)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert!(entry.extended);
        assert_eq!(entry.file_type, TYPE_DIRECTORY);
        assert_eq!(entry.info_len, 4);
        assert!(entry.ads.is_empty());
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let (data, _) = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect("embedded data collects");
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn info_past_embedded_refuses() {
        let volume = store(&[ext_entry(41, 9, &[1, 2], 9, TYPE_FILE)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert_eq!(entry.file_type, TYPE_FILE);
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let error = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect_err("info 9 past 2 embedded refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('2'), "{text}");
    }

    #[test]
    fn extended_ad_type_refuses_naming_the_chain() {
        let mut block = ext_entry(41, 9, &[], 0, TYPE_FILE);
        block[16 + 18..16 + 20].copy_from_slice(&AD_EXTENDED.to_le_bytes());
        stamp_tag(&mut block, TAG_EXTFE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type 2 refuses");
        let text = error.to_string();
        assert!(text.contains('2'), "{text}");
        assert!(text.contains("258"), "{text}");
    }

    #[test]
    fn short_ad_extent_collects_through_home() {
        // Entry at 41 with one short extent (4 bytes at home-relative 2);
        // the data block sits at absolute 34.
        let mut block = vec![0u8; SIZE as usize];
        block[27] = TYPE_DIRECTORY;
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&4u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&8u32.to_le_bytes());
        block[176..180].copy_from_slice(&4u32.to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let mut data_block = vec![0u8; SIZE as usize];
        data_block[0..4].copy_from_slice(&[9, 8, 7, 6]);
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        // Store lays blocks 34..36: put the data block at absolute 34 by
        // padding entry/data order explicitly instead.
        let total = 64 * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("fits in RAM");
        volume
            .write_all_at(41 * u64::from(SIZE), &block)
            .expect("the entry fits");
        volume
            .write_all_at(34 * u64::from(SIZE), &data_block)
            .expect("the data fits");
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert!(!entry.extended);
        assert_eq!(entry.ads.len(), 1);
        let (data, segs) = collect_data(&volume, SIZE, &[0], &[home], &home, &entry, "test", 9)
            .expect("the extent collects");
        assert_eq!(data, vec![9, 8, 7, 6]);
        assert_eq!(segs, vec![DataSeg { start: 2, len: 4 }]);
    }

    #[test]
    fn unrecorded_extent_refuses_naming_type_and_index() {
        let mut block = vec![0u8; SIZE as usize];
        block[27] = TYPE_FILE;
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&4u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&8u32.to_le_bytes());
        block[176..180].copy_from_slice(&(1u32 << 30 | 4).to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type-1 extent refuses");
        let text = error.to_string();
        assert!(text.contains("descriptor 0"), "{text}");
        assert!(text.contains("type 1"), "{text}");
    }

    #[test]
    fn free_extent_refuses_naming_type_and_index() {
        // Two extents so the refusal names descriptor 1, not 0: the first
        // is recorded, the second is free (type 2).
        let mut block = vec![0u8; SIZE as usize];
        block[27] = TYPE_FILE;
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&8u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&16u32.to_le_bytes());
        block[176..180].copy_from_slice(&4u32.to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        block[184..188].copy_from_slice(&(2u32 << 30 | 4).to_le_bytes());
        block[188..192].copy_from_slice(&3u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type-2 extent refuses");
        let text = error.to_string();
        assert!(text.contains("descriptor 1"), "{text}");
        assert!(text.contains("type 2"), "{text}");
    }

    #[test]
    fn next_extent_refuses_as_an_unfollowed_chain() {
        let mut block = vec![0u8; SIZE as usize];
        block[27] = TYPE_FILE;
        block[16 + 18..16 + 20].copy_from_slice(&AD_SHORT.to_le_bytes());
        block[56..64].copy_from_slice(&4u64.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&8u32.to_le_bytes());
        block[176..180].copy_from_slice(&(3u32 << 30 | 8).to_le_bytes());
        block[180..184].copy_from_slice(&2u32.to_le_bytes());
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type-3 extent refuses");
        let text = error.to_string();
        assert!(text.contains("descriptor 0"), "{text}");
        assert!(text.contains("next-extent"), "{text}");
    }

    #[test]
    fn unknown_allocation_type_refuses() {
        let mut block = ext_entry(41, 9, &[], 0, TYPE_FILE);
        block[16 + 18..16 + 20].copy_from_slice(&7u16.to_le_bytes());
        stamp_tag(&mut block, TAG_EXTFE, (SIZE - 16) as u16, 9);
        let volume = store(&[block], 41);
        let error = read_file_entry(&volume, SIZE, 41, 9).expect_err("type 7 refuses");
        let text = error.to_string();
        assert!(text.contains('7'), "{text}");
    }

    /// Plain file entry at absolute `abs` (relative `rel`) with long
    /// allocation descriptors `ads` of (length, block, partition
    /// reference) and information length `info`.
    fn long_entry(abs: u32, rel: u32, ads: &[(u32, u32, u16)], info: u64, ftype: u8) -> Vec<u8> {
        let _ = abs;
        let mut block = vec![0u8; SIZE as usize];
        block[27] = ftype;
        block[16 + 18..16 + 20].copy_from_slice(&AD_LONG.to_le_bytes());
        block[56..64].copy_from_slice(&info.to_le_bytes());
        block[168..172].copy_from_slice(&0u32.to_le_bytes());
        block[172..176].copy_from_slice(&(ads.len() as u32 * 16).to_le_bytes());
        for (index, (len, lbn, part)) in ads.iter().enumerate() {
            let at = 176 + index * 16;
            block[at..at + 4].copy_from_slice(&len.to_le_bytes());
            block[at + 4..at + 8].copy_from_slice(&lbn.to_le_bytes());
            block[at + 8..at + 10].copy_from_slice(&part.to_le_bytes());
        }
        stamp_tag(&mut block, TAG_FE, (SIZE - 16) as u16, rel);
        block
    }

    fn home() -> PartitionDesc {
        PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        }
    }

    #[test]
    fn long_ad_extents_collect_through_the_mapped_partition() {
        // Two long extents: 4 bytes at home-relative 2 (reference 0 maps
        // to partition 0) and 2 bytes at relative 5 of a second partition
        // (reference 1), joined in order and cut to the information
        // length of 5.
        let other = PartitionDesc {
            number: 7,
            start: 200,
            length: 50,
        };
        let total = 300 * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("fits in RAM");
        let entry = long_entry(41, 9, &[(4, 2, 0), (4, 5, 1)], 5, TYPE_DIRECTORY);
        volume
            .write_all_at(41 * u64::from(SIZE), &entry)
            .expect("the entry fits");
        volume
            .write_all_at(34 * u64::from(SIZE), &[9, 8, 7, 6])
            .expect("the first extent fits");
        volume
            .write_all_at(205 * u64::from(SIZE), &[5, 4, 3, 2])
            .expect("the second extent fits");
        let parsed = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        assert_eq!(parsed.ads.len(), 2);
        let home = home();
        let (data, segs) = collect_data(
            &volume,
            SIZE,
            &[0, 7],
            &[home, other],
            &home,
            &parsed,
            "test",
            9,
        )
        .expect("both extents collect");
        assert_eq!(data, vec![9, 8, 7, 6, 5]);
        assert_eq!(
            segs,
            vec![DataSeg { start: 2, len: 4 }, DataSeg { start: 5, len: 4 }]
        );
    }

    #[test]
    fn extent_past_the_partition_end_refuses_naming_range() {
        // One long extent of a block plus one byte at the partition's last
        // block (relative 99 of 100): its second block escapes the
        // partition, so blocks 99..101 refuse against 100 blocks.
        let volume = store(
            &[long_entry(
                41,
                9,
                &[(SIZE + 1, 99, 0)],
                SIZE as u64,
                TYPE_FILE,
            )],
            41,
        );
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        let home = home();
        let error = resolve_extents(SIZE, &[0], &[home], &home, &entry.ads, "file `big`", 64)
            .expect_err("the escaping extent refuses");
        let text = error.to_string();
        assert!(text.contains("file `big`"), "{text}");
        assert!(text.contains("descriptor 0"), "{text}");
        assert!(text.contains("99..101"), "{text}");
        assert!(text.contains("100 blocks"), "{text}");
    }

    #[test]
    fn extent_starting_past_the_partition_refuses() {
        let volume = store(&[long_entry(41, 9, &[(4, 100, 0)], 4, TYPE_FILE)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        let home = home();
        let error = resolve_extents(SIZE, &[0], &[home], &home, &entry.ads, "file `far`", 64)
            .expect_err("relative 100 of 100 refuses");
        let text = error.to_string();
        assert!(text.contains("file `far`"), "{text}");
        assert!(text.contains("100"), "{text}");
    }

    #[test]
    fn empty_extent_past_the_partition_refuses() {
        // Zero bytes still name a block: relative 100 of 100 names none.
        let volume = store(&[long_entry(41, 9, &[(0, 100, 0)], 0, TYPE_FILE)], 41);
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        let home = home();
        let error = resolve_extents(SIZE, &[0], &[home], &home, &entry.ads, "file `nil`", 64)
            .expect_err("zero bytes at block 100 refuse");
        assert!(error.to_string().contains("100"), "{:?}", error);
    }

    #[test]
    fn extent_count_past_the_cap_refuses() {
        let volume = store(
            &[long_entry(41, 9, &[(4, 2, 0), (4, 3, 0)], 8, TYPE_FILE)],
            41,
        );
        let entry = read_file_entry(&volume, SIZE, 41, 9).expect("the entry parses");
        let home = home();
        let error = resolve_extents(SIZE, &[0], &[home], &home, &entry.ads, "file `many`", 1)
            .expect_err("2 past cap 1 refuses");
        let text = error.to_string();
        assert!(text.contains('2'), "{text}");
        assert!(text.contains('1'), "{text}");
    }

    #[test]
    fn file_bounds_refuse_a_short_sum_and_a_huge_sum() {
        let home = home();
        let windows = resolve_extents(
            SIZE,
            &[0],
            &[home],
            &home,
            &[AllocDesc::Short { len: 4, pos: 2 }],
            "file `short`",
            64,
        )
        .expect("one window resolves");
        let error =
            check_file_bounds(9, &windows, "file `short`").expect_err("info 9 past 4 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('4'), "{text}");
        check_file_bounds(4, &windows, "file `short`").expect("info 4 of 4 passes");
        check_file_bounds(2, &windows, "file `short`").expect("a short sum truncates");
        let huge = vec![ResolvedExtent {
            rel: 0,
            offset: 0,
            len: MAX_FILE_BYTES + 1,
        }];
        let error = check_file_bounds(MAX_FILE_BYTES + 1, &huge, "file `huge`")
            .expect_err("past-cap sum refuses");
        assert!(error.to_string().contains("byte cap"), "{:?}", error);
    }

    #[test]
    fn windows_read_whole_and_positional() {
        let total = 64 * u64::from(SIZE);
        let mut volume = VecVolume::new(total, 512).expect("fits in RAM");
        volume
            .write_all_at(34 * u64::from(SIZE), &[9, 8, 7, 6])
            .expect("the first extent fits");
        volume
            .write_all_at(35 * u64::from(SIZE), &[5, 4, 3, 2])
            .expect("the second extent fits");
        let windows = vec![
            ResolvedExtent {
                rel: 2,
                offset: 34 * u64::from(SIZE),
                len: 4,
            },
            ResolvedExtent {
                rel: 3,
                offset: 35 * u64::from(SIZE),
                len: 4,
            },
        ];
        let data = read_windows(&volume, &windows, 6, "file `w`").expect("6 of 8 read");
        assert_eq!(data, vec![9, 8, 7, 6, 5, 4]);
        let data = read_windows(&volume, &windows, 0, "file `w`").expect("empty reads");
        assert!(data.is_empty());
        let mut buf = [0u8; 5];
        let placed =
            read_windows_at(&volume, &windows, 8, 3, &mut buf, "file `w`").expect("3..8 reads");
        assert_eq!(placed, 5);
        assert_eq!(buf, [6, 5, 4, 3, 2]);
        let mut one = [0u8; 1];
        let placed = read_windows_at(&volume, &windows, 8, 8, &mut one, "file `w`")
            .expect("offset 8 is EOF");
        assert_eq!(placed, 0);
        assert_eq!(one, [0]);
        let error = read_windows_at(&volume, &windows, 8, 9, &mut one, "file `w`")
            .expect_err("offset 9 past 8 refuses");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('8'), "{text}");
    }

    #[test]
    fn file_type_names_stay_ascii() {
        assert_eq!(file_type_name(TYPE_DIRECTORY), "directory");
        assert_eq!(file_type_name(TYPE_FILE), "regular file");
        assert_eq!(file_type_name(TYPE_SYMLINK), "symbolic link");
        assert_eq!(file_type_name(TYPE_FIFO), "FIFO");
        assert_eq!(file_type_name(200), "unknown file type 200");
    }

    #[test]
    fn partition_ref_past_the_maps_refuses() {
        let home = PartitionDesc {
            number: 0,
            start: 32,
            length: 100,
        };
        let error = resolve_map(&[0], &[home], 3, "test").expect_err("ref 3 past 1 map refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains('1'), "{text}");
    }
}
