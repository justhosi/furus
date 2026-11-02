//! ISO9660 reader: volume descriptors, the chosen directory tree and
//! multi-extent files (S14, slices 1-2 of 4).
//!
//! PLAN's S14 asks for an ISO9660/Joliet/Rock Ridge reader over the image
//! with the volume descriptors "mmap"ed for amortised reads. Two facts
//! shape what this slice can honestly claim, split here the way the house
//! requires:
//!
//! * *Measured* — the ECMA-119 on-disk layout slices 1-2 parse:
//!   2048-byte sectors, the descriptor sequence at sector 16 (`CD001`
//!   at bytes 1..6, type byte at 0, version 1 at 6), the
//!   primary/supplementary/boot/terminator shapes, both-endian fields,
//!   and the packed directory records that never straddle a sector. The
//!   Joliet additions: the `%/@`, `%/C`, `%/E` escape openings marking
//!   levels 1-3 (highest level present wins, as libcdio selects),
//!   UCS-2BE identifiers with surrogate pairs combining per Unicode,
//!   `;1`/trailing-dot stripping on the decoded text, and adjacent
//!   same-name records joining into one multi-extent file in order.
//!   Every layout fact below is pinned by synthetic fixtures built byte
//!   by byte in the `#[cfg(test)]` modules, which claim nothing about
//!   real mastering tools.
//! * *Inferred* — that real `xorriso`/`genisoimage` output follows the
//!   same layout. Slices 1-2 cross-check directory listings and one
//!   Joliet tree against `xorriso` inside `archlinux:latest` where
//!   docker is available (see the slice reports); whatever could not be
//!   run is stated plainly there, never faked.
//!
//! The mmap half of the mandate is impossible here: the crate carries
//! `#![forbid(unsafe_code)]` and no new dependency is allowed, so there
//! is no way to map the image into memory. [`SectorCache`](cache::SectorCache)
//! sits on [`Volume`](crate::fs::Volume) instead and gives the same
//! amortised read pattern the mandate wants — whole 2048-byte sectors
//! through a 64 KiB (32-sector) LRU cache — while every access stays
//! bounds-checked against `total_bytes` before any I/O happens, exactly
//! like [`fs`](crate::fs) demands.
//!
//! What this slice owns, file by file:
//!
//! * [`cache`] — the sector cache over `Box<dyn Volume>` (owned, so the
//!   reader carries no lifetime; a borrow would leak the store's lifetime
//!   into every call site for no benefit).
//! * [`descriptor`] — the sector-16 descriptor sequence: primary (type 1),
//!   supplementary (type 2, with the Joliet level detected and the
//!   volume identifier UCS-2BE-decoded for Joliet), boot record
//!   (type 0) and terminator (type 255).
//! * [`joliet`] — UCS-2BE name and label decoding with surrogate-pair
//!   handling, plus `;1`/trailing-dot stripping on decoded text.
//! * [`record`] — directory-record parsing shared by both trees, and the
//!   `;1`/trailing-dot stripping for primary-tree (raw-byte) names.
//! * [`reader`] — [`IsoReader`](reader::IsoReader): the chosen tree
//!   ([`TreeKind`]), label, `root`, `lookup`, `read_dir`,
//!   `open_file`/`read_file` with multi-extent joining.
//!
//! Deliberately left for later slices: Rock Ridge system-use parsing,
//! path tables, El Torito boot handling, and recording-date decoding.
//! A directory whose data length is not a multiple of the sector size
//! reads its last partial sector the way ECMA-119 allows (only the
//! valid prefix carries records); anything cut mid-sector past the
//! volume end is refused as truncated.

/// ISO9660 logical sector size in bytes (ECMA-119 fixes it; the reader
/// addresses every extent in units of this).
pub const SECTOR_BYTES: usize = 2048;

/// [`SECTOR_BYTES`] as `u64` for the checked byte-offset arithmetic.
pub const SECTOR_BYTES_U64: u64 = 2048;

/// First sector of the volume-descriptor sequence (absolute byte 32768).
pub const FIRST_DESCRIPTOR_SECTOR: u32 = 16;

/// Hard ceiling on descriptors read before the terminator: a real set is
/// a handful of sectors, so more than this without a terminator means the
/// sequence is corrupt, and the loop must not walk a huge volume.
pub const MAX_DESCRIPTORS: usize = 64;

/// Hard ceiling on directory nesting while resolving a path: ISO paths
/// are at most 8 levels deep, so anything past this is a directory
/// looping on itself, refused rather than followed forever.
pub const MAX_DIR_DEPTH: usize = 32;

/// Hard ceiling on path components in one lookup: bounds the work a
/// hostile path string can demand.
pub const MAX_PATH_COMPONENTS: usize = 256;

pub mod cache;
pub mod descriptor;
pub mod joliet;
pub mod reader;
pub mod record;

pub use cache::SectorCache;
pub use descriptor::BootRecord;
pub use descriptor::DescriptorSet;
pub use descriptor::PrimaryDescriptor;
pub use descriptor::SupplementaryDescriptor;
pub use descriptor::read_descriptor_set;
pub use reader::Entry;
pub use reader::IsoReader;
pub use reader::OpenFile;
pub use reader::TreeKind;
pub use record::DirRecord;
pub use record::FLAG_ASSOCIATED;
pub use record::FLAG_DIRECTORY;
pub use record::FLAG_HIDDEN;
pub use record::FLAG_MULTI_EXTENT;
pub use record::parse_record;
pub use record::parse_records;
pub use record::strip_version;
