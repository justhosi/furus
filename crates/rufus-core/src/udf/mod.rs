//! UDF volume reader: anchor, descriptors, file set and the root
//! directory listing (S15, slice 1 of 4).
//!
//! Slice 1 reads the UDF descriptor chain and lists the root directory,
//! read-only, over any [`Volume`](crate::fs::Volume). The writer side
//! lives elsewhere ([`fs::udf`](crate::fs::udf) drives the external
//! `mkudffs` tool); this module never writes and never spawns anything.
//! It owns the store as `Box<dyn Volume>` for the same lifetime reason
//! [`IsoReader`](crate::iso::reader::IsoReader) does: a borrow would leak
//! the store's lifetime into every call site for no benefit.
//!
//! *Measured* — every on-disk fact below was read off real
//! `mkudffs --utf8 --media-type=hd --udfrev=0x0201 -b <512|2048> -l LABEL`
//! images from udftools 2.3 inside `archlinux:latest` (empty images at
//! both block sizes, plus a `-b 2048` image populated through a kernel
//! UDF mount with a subdirectory and four files volume-wide — three
//! beside it in the root, one inside it; see the slice report
//! for the container commands):
//!
//! * the anchor volume descriptor pointer (tag id 2) sits at logical
//!   sector 256 in units of the block size (byte `256 * 512` for `-b
//!   512`, `256 * 2048` for `-b 2048`), claims tag location 256, and
//!   carries a 16-block main extent at location 96 plus a second 16-block
//!   sequence extent 160 blocks before the volume end (block 32608
//!   of 32768 on the 64MiB `-b 2048` image, block 130912 of 131072 on
//!   the 64MiB `-b 512` image) carrying the same descriptors with their
//!   tags written for their own block numbers — so the reserve extent is
//!   not byte-identical with the main one: each reserve tag's location
//!   reads its own block, which is exactly what the fallback walk checks;
//! * every descriptor tag reads version 3 with a nonzero checksum byte
//!   (54 on the 64MiB `-b 2048` anchor and 235 on the 64MiB `-b 512`
//!   one — the ECMA-167 sum of the other tag bytes mod 256, 566 mod 256
//!   on the 2048 image; the anchor tag covers the two extents, so the
//!   value depends only on the layout — block size and extent positions —
//!   not on the volume UUID or timestamps, and repeats for a given image
//!   shape — 203 on the empty `-b 2048`
//!   verification image's file set descriptor and 192 on its root parent
//!   entry, both image-specific values that move with the volume UUID,
//!   timestamps and tag serials); the reader verifies the (id, location,
//!   CRC) triple and enforces neither the version nor the checksum byte,
//!   a deliberate scope choice, not a workaround: every corruption class
//!   the fixtures cover already refuses on the triple;
//!   the CRC is CRC-16/ITU-T (polynomial `0x1021`, init 0) over the
//!   `crc_len` bytes after the tag, verified on every descriptor of all
//!   three images;
//! * the main sequence runs primary (1), logical volume (6), partition
//!   (5), unallocated space (7), implementation use (4), terminator (8),
//!   then zero padding; every descriptor's tag location is its absolute
//!   block number;
//! * the logical volume descriptor carries the block size (equal to the
//!   probed one), the `*OSTA UDF Compliant` domain with suffix revision
//!   `0x0201` (reported as `2.01`, agreeing with `udfinfo`), one type-1
//!   partition map (volume sequence 1, partition 0), the file set
//!   descriptor's long address (length one block, partition reference 0),
//!   and the label as a d-string whose last byte is the significant
//!   length (compression id 8, `LABEL` reads back exactly);
//! * the partition descriptor carries partition 0 starting at block 257
//!   with contents identifier `+NSR03`;
//! * the file set descriptor (tag 256) carries the root directory ICB
//!   (length one block, partition reference 0); its tag location — like
//!   every file-structure tag — is the partition-relative block number;
//! * the root ICB points at an *extended* file entry (tag 266, not 261)
//!   with embedded directory data (ICB flags 3); the empty root holds one
//!   file identifier descriptor (tag 257, characteristics `0x0A` =
//!   directory + parent, empty name, pointing at the root itself), and the
//!   populated root holds that parent plus one `0x02` subdirectory entry
//!   and `0x00` file entries with compression-id-8 names; each FID's tag
//!   location is the partition-relative block holding it, and each FID's
//!   CRC covers its whole record including name and 4-byte padding.
//!
//! *Inferred* — spec text (ECMA-167) with no real-image sample behind it:
//! the long address implementation-use position (all measured addresses
//! have reference 0 and zero use bytes, so the offsets are unreadable off
//! the images), short/long/extended allocation descriptor shapes (all
//! measured directories are embedded), type-2 partition map identifier
//! strings, compression id 16 names, multi-block directory tag locations
//! (the measured single-block rule applied per containing block), and
//! extent-type bits on allocation extents (only recorded extents are
//! accepted).
//!
//! What this slice owns, file by file:
//!
//! * [`tag`] — the 16-byte descriptor tag: parse, CRC-16/ITU-T, window
//!   checks. The checksum byte and version are parsed nowhere on purpose
//!   (see above).
//! * [`anchor`] — the sector-256 anchor probe over the two supported
//!   block sizes, with the main and reserve extents.
//! * [`unicode`] — OSTA compressed Unicode (ids 8 and 16) and d-strings.
//! * [`descriptor`] — the volume descriptor sequence walk: primary,
//!   partition, logical volume (with its partition maps), and the
//!   skipped implementation-use, unallocated-space and terminator shapes.
//! * [`file`] — the file set descriptor, file/extended-file entries and
//!   allocation-descriptor resolution (embedded, short and long).
//! * [`fid`] — file identifier descriptor parsing over directory data.
//! * [`reader`] — [`UdfReader`](reader::UdfReader): open, label, revision,
//!   NSR, block size, partition, file set, root and `read_dir` listings.
//!
//! Deliberately left for later slices: file content reads (slice 2 owns
//! the entry ICBs exposed here), logical volume integrity descriptors,
//! extended attributes, and any write path.
//!
//! On sharing the ISO sector cache: it is not shared, on purpose. That
//! cache serves fixed 2048-byte sectors (`[u8; 2048]` sits in its type),
//! while the UDF block size is only known after the anchor probe runs —
//! sharing would mean either compile-time const generics (useless for a
//! runtime-detected size without enum dispatch) or churning every ISO
//! call site to a variable-size cache. Slice 1 also performs only a
//! bounded handful of block reads (two anchor probes at most, a 16-block
//! descriptor walk, then the file set, one file entry and the directory
//! extents), so a cache buys nothing yet. Every read instead goes
//! straight through [`Volume`](crate::fs::Volume) with the same
//! bounds-before-I/O discipline the ISO cache enforces. If slice 2's file
//! reads want amortisation, that is where a UDF block cache belongs.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::Volume;

pub mod anchor;
pub mod descriptor;
pub mod fid;
pub mod file;
pub mod reader;
pub mod tag;
pub mod unicode;

pub use anchor::Anchor;
pub use anchor::Extent;
pub use anchor::probe as probe_anchor;
pub use descriptor::LogicalVolume;
pub use descriptor::PartitionDesc;
pub use descriptor::VolumeDescriptors;
pub use fid::FileId;
pub use file::FileEntry;
pub use file::FileSetDescriptor;
pub use reader::Entry;
pub use reader::UdfReader;

/// Block sizes the anchor probe tries, in order: 2048 first (the mandated
/// image shape), then 512 (the only other size the writer side supports —
/// see [`BlockSize`](crate::fs::udf::BlockSize)).
pub const PROBE_BLOCK_SIZES: [u32; 2] = [2048, 512];

/// Hard ceiling on descriptors walked in one sequence: a real sequence is
/// six descriptors plus padding, so more than this without a terminator
/// means corruption, and the walk must not scan a huge extent. Mirrors
/// [`MAX_DESCRIPTORS`](crate::iso::MAX_DESCRIPTORS) for the same reason.
pub const MAX_DESCRIPTORS: usize = 64;

/// Hard ceiling on partition maps in one logical volume descriptor: one
/// map is normal, so anything past this is a hostile count, refused
/// rather than allocated.
pub const MAX_PARTITION_MAPS: usize = 64;

/// Hard ceiling on file identifier descriptors parsed from one
/// directory: bounds the work a hostile directory can demand.
pub const MAX_FIDS: usize = 65_536;

/// Hard ceiling on directory data bytes collected before parsing:
/// bounds the allocation a hostile file entry can demand. A refusal here
/// names both numbers; an allocation failure on a smaller request refuses
/// gracefully too, never panicking.
pub const MAX_DIR_BYTES: u64 = 8 * 1024 * 1024;

/// Hard ceiling on allocation extents joined for one directory: bounds
/// the I/O a hostile file entry can demand.
pub const MAX_DIR_EXTENTS: usize = 1024;

/// Little-endian `u16` at `at` of `bytes`: refuses with `what` and the
/// byte range when the window is not there. No indexing, no panics.
pub(crate) fn le_u16(bytes: &[u8], at: usize, what: &str) -> Result<u16> {
    bytes
        .get(at..at + 2)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} ends inside its two-byte field at bytes {at}..{}",
                at + 2
            ))
        })
        .and_then(|pair| {
            pair.try_into().map(u16::from_le_bytes).map_err(|_| {
                CoreError::invalid(format!("{what} bytes {at}..{} do not form a u16", at + 2))
            })
        })
}

/// Little-endian `u32` at `at` of `bytes`, same contract as [`le_u16`].
pub(crate) fn le_u32(bytes: &[u8], at: usize, what: &str) -> Result<u32> {
    bytes
        .get(at..at + 4)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} ends inside its four-byte field at bytes {at}..{}",
                at + 4
            ))
        })
        .and_then(|four| {
            four.try_into().map(u32::from_le_bytes).map_err(|_| {
                CoreError::invalid(format!("{what} bytes {at}..{} do not form a u32", at + 4))
            })
        })
}

/// Little-endian `u64` at `at` of `bytes`, same contract as [`le_u16`].
pub(crate) fn le_u64(bytes: &[u8], at: usize, what: &str) -> Result<u64> {
    bytes
        .get(at..at + 8)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "{what} ends inside its eight-byte field at bytes {at}..{}",
                at + 8
            ))
        })
        .and_then(|eight| {
            eight.try_into().map(u64::from_le_bytes).map_err(|_| {
                CoreError::invalid(format!("{what} bytes {at}..{} do not form a u64", at + 8))
            })
        })
}

/// Read the `size` byte block `lbn` from `volume`: the byte window is
/// bounds-checked against `total` before any I/O, and a block running
/// past the volume end is refused with the block number, the offset and
/// the extent — never zero-padded. Mirrors the ISO sector cache's
/// contract without the cache (see the module header for why).
pub(crate) fn read_block(
    volume: &dyn Volume,
    lbn: u32,
    size: u32,
    total: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let offset = u64::from(lbn).checked_mul(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} at block {lbn} of {size} bytes overflows the byte offset arithmetic"
        ))
    })?;
    let end = offset.checked_add(u64::from(size)).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} of {size} bytes at block {lbn} (offset {offset}) overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{what} of {size} bytes at block {lbn} (bytes {offset}..{end}) runs past \
             the {total} byte volume end"
        )));
    }
    let len = usize::try_from(size)
        .map_err(|_| CoreError::invalid(format!("{what} block size {size} is not addressable")))?;
    let mut out = vec![0u8; len];
    volume.read_exact_at(offset, &mut out)?;
    Ok(out)
}

/// Read `len` bytes at absolute `offset` from `volume`, bounds-checked
/// before any I/O like [`read_block`].
pub(crate) fn read_bytes(
    volume: &dyn Volume,
    offset: u64,
    len: u64,
    total: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let end = offset.checked_add(len).ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} of {len} bytes at offset {offset} overflows the byte offset arithmetic"
        ))
    })?;
    if end > total {
        return Err(CoreError::invalid(format!(
            "{what} of {len} bytes at offset {offset} (bytes {offset}..{end}) runs past \
             the {total} byte volume end"
        )));
    }
    let count = usize::try_from(len)
        .map_err(|_| CoreError::invalid(format!("{what} length {len} is not addressable")))?;
    let mut out = vec![0u8; count];
    volume.read_exact_at(offset, &mut out)?;
    Ok(out)
}

/// A long allocation descriptor: an extent length with the addressed
/// block and its partition reference. Carries the file set descriptor
/// location, every file identifier's ICB and every directory entry's ICB.
/// The implementation-use tail (6 bytes past the reference) is parsed
/// nowhere: every measured address has reference 0 with zero use bytes,
/// so the tail position is spec text, not a measured fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongAd {
    /// Extent length in bytes (for file entries: the entry length).
    pub extent_length: u32,
    /// Block number (partition-relative inside partitions, absolute in
    /// the descriptor sequence context where it never appears).
    pub lbn: u32,
    /// Index into the logical volume's partition map table.
    pub partition_ref: u16,
}

/// Parse a long allocation descriptor at `at` of `bytes`: length, block
/// number, then the partition reference right after it.
pub(crate) fn parse_long_ad(bytes: &[u8], at: usize, what: &str) -> Result<LongAd> {
    Ok(LongAd {
        extent_length: le_u32(bytes, at, what)?,
        lbn: le_u32(bytes, at + 4, what)?,
        partition_ref: le_u16(bytes, at + 8, what)?,
    })
}

/// Stamp a tag with `id`/`crc_len`/`location` onto the first 16 bytes of
/// `block` (test helper shared by every `udf` test module) and fix the
/// CRC over the covered window, mirroring what real images carry
/// (version 3; the checksum byte stays zero because production code
/// never checks it, so fixtures need no real checksum there).
/// Test-only: production code never writes tags.
#[cfg(test)]
pub(crate) use tag::stamp_tag;
