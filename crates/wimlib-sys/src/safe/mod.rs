//! Safe, configuration-independent facade over wimlib (S21).
//!
//! `cfg(wimlib_present)` is set only for the `wimlib-sys` crate: it does
//! not propagate to dependents, and `rufus-core` forbids `unsafe` code,
//! so it may never call a raw extern. This module is the seam that makes
//! that work: every public item here exists with an identical signature
//! in both configurations. When the library is linked (`bound`) the
//! items wrap the externs; when it is absent (`unbound`) the same items
//! exist but every operation returns [`WimlibError::NotLinked`].
//!
//! The types below are shared (written once, used by both sides); only
//! [`Wim`] itself has two implementations, selected below with `cfg`.
//! Raw pointers never appear in any public item here: handles stay
//! inside [`Wim`], and progress crosses the boundary as plain numbers.
//!
//! Not here yet: split-WIM assembly, capture/update flows, and a wired
//! integrity-check path — the [`OpenFlags::CHECK_INTEGRITY`] bit exists
//! for callers that want fail-fast opens, but the `rufus-core` layer
//! opens plain (see `windows::wim`) until a later slice wires
//! verification in.

#[cfg(wimlib_present)]
mod bound;
#[cfg(wimlib_present)]
pub use bound::Wim;

#[cfg(not(wimlib_present))]
mod unbound;
#[cfg(not(wimlib_present))]
pub use unbound::Wim;

use std::ops::BitOr;

/// `WIMLIB_ERR_ABORTED_BY_PROGRESS` (header `enum wimlib_error_code`,
/// `= 76`): returned when the progress callback aborts the operation.
///
/// The value lives in [`crate::consts`] (single source of truth); the
/// raw constant also exists as `ffi::WIMLIB_ERR_ABORTED_BY_PROGRESS`
/// when the library is linked, but `ffi` is compiled out otherwise, so
/// dependents (built without the gate) recognise cancellation through
/// this shared copy instead.
pub const ERR_ABORTED_BY_PROGRESS: i32 = crate::consts::WIMLIB_ERR_ABORTED_BY_PROGRESS;

/// General WIM information (the fields S21 extraction needs from
/// `struct wimlib_wim_info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimInfo {
    /// Number of images in the WIM.
    pub image_count: u32,
    /// 1-based bootable image index, or 0 when none is bootable.
    pub boot_index: u32,
    /// WIM format version.
    pub wim_version: u32,
    /// Default compression chunk size of resources, in bytes.
    pub chunk_size: u32,
    /// 1-based index of this part (split WIMs), else 1.
    pub part_number: u16,
    /// Total split parts, else 1.
    pub total_parts: u16,
    /// Default compression type of resources.
    pub compression: Compression,
    /// WIM size in bytes, excluding XML data and integrity table.
    pub total_bytes: u64,
    /// The WIM carries an integrity table.
    pub has_integrity_table: bool,
    /// The WIM is considered readonly for any reason (header flag,
    /// split part, or filesystem permissions).
    pub is_readonly: bool,
    /// The `readonly` flag is set in the WIM header.
    pub is_marked_readonly: bool,
    /// The reparse-point-fix flag is set in the WIM header.
    pub has_rpfix: bool,
    /// The `spanned` flag is set in the WIM header.
    pub spanned: bool,
    /// Only image metadata is present (no file resources).
    pub metadata_only: bool,
    /// Only file resources are present (no image metadata).
    pub resource_only: bool,
    /// The WIM is pipable (see `WIMLIB_WRITE_FLAG_PIPABLE`).
    pub is_pipable: bool,
}

/// Default compression type of resources in a WIM
/// (`wimlib_compression_type` values 0..3 per the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression (`0`).
    None,
    /// XPRESS compression (`1`).
    Xpress,
    /// LZX compression (`2`).
    Lzx,
    /// LZMS compression (`3`, ESD-style solid resources).
    Lzms,
    /// Any other header value, carried verbatim.
    Other(i32),
}

/// One extraction progress sample: the running totals after folding the
/// latest progress message into the accumulator (see `bound`).
///
/// Only fields whose values the header documents for the received
/// message are folded in: byte and stream counts arrive on every
/// `EXTRACT_*` message, `part_number`/`total_parts` only on
/// `EXTRACT_SPWM_PART_BEGIN`, and the file counts only on
/// `EXTRACT_FILE_STRUCTURE`/`EXTRACT_METADATA`. Fields no message has
/// touched yet read as their default (zero, or `None` for the name).
///
/// The file pair is per-phase, not monotonic: `current_file_count`
/// restarts when the metadata phase begins, and `end_file_count` is a
/// per-phase estimate that can differ between phases. Only the byte
/// pair climbs monotonically to the terminal `completed_bytes ==
/// total_bytes`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractProgress {
    /// 1-based index of the image being extracted.
    pub image: u32,
    /// Name of the image being extracted (`None` when wimlib hands
    /// back null or undecodable text).
    pub image_name: Option<String>,
    /// Bytes of file data to extract in total.
    pub total_bytes: u64,
    /// Bytes of file data extracted so far.
    pub completed_bytes: u64,
    /// File streams to extract in total.
    pub total_streams: u64,
    /// File streams extracted so far.
    pub completed_streams: u64,
    /// Split-part number (only meaningful around part boundaries).
    pub part_number: u32,
    /// Split-part total (only meaningful around part boundaries).
    pub total_parts: u32,
    /// Files to process in total in the structure/metadata phase.
    pub total_files: u64,
    /// Files processed so far in the structure/metadata phase.
    pub completed_files: u64,
}

/// Extraction flags (the `WIMLIB_EXTRACT_FLAG_` subset S21 uses).
///
/// Bitflags-free on purpose: four named values plus `BitOr` combining
/// is the whole surface, so no new crate is needed. Only flags present
/// in `/usr/include/wimlib.h` 1.14.5 exist here; nothing is invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractFlags {
    /// Raw flag word handed to `wimlib_extract_image`.
    bits: u32,
}

impl ExtractFlags {
    /// No flags.
    pub const NONE: Self = Self { bits: 0 };
    /// Extract directly to an unmounted NTFS volume (`0x1`, needs
    /// libntfs-3g at wimlib build time).
    pub const NTFS: Self = Self {
        bits: crate::consts::WIMLIB_EXTRACT_FLAG_NTFS as u32,
    };
    /// Do not extract security descriptors (`0x40`).
    pub const NO_ACLS: Self = Self {
        bits: crate::consts::WIMLIB_EXTRACT_FLAG_NO_ACLS as u32,
    };
    /// Do not extract Windows file attributes (`0x100000`).
    pub const NO_ATTRIBUTES: Self = Self {
        bits: crate::consts::WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES as u32,
    };

    /// No flags (same as [`ExtractFlags::NONE`]).
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// NTFS-volume extraction (same as [`ExtractFlags::NTFS`]).
    pub const fn ntfs() -> Self {
        Self::NTFS
    }

    /// The raw flag word for `wimlib_extract_image`.
    pub const fn bits(self) -> u32 {
        self.bits
    }
}

impl BitOr for ExtractFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

/// Open flags (the `WIMLIB_OPEN_FLAG_` subset S21 uses).
///
/// Only flags present in `/usr/include/wimlib.h` 1.14.5 exist here;
/// S21 opens plain (no flags); the rest are carried for callers that
/// want fail-fast checks at open time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags {
    /// Raw flag word handed to `wimlib_open_wim`.
    bits: u32,
}

impl OpenFlags {
    /// No flags: plain open.
    pub const EMPTY: Self = Self { bits: 0 };
    /// Verify the WIM against its integrity table while opening, when
    /// present (`0x1`).
    pub const CHECK_INTEGRITY: Self = Self {
        bits: crate::consts::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY as u32,
    };
    /// Fail with `WIMLIB_ERR_IS_SPLIT_WIM` on a split part (`0x2`).
    pub const ERROR_IF_SPLIT: Self = Self {
        bits: crate::consts::WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT as u32,
    };
    /// Check writability now instead of at overwrite time (`0x4`).
    pub const WRITE_ACCESS: Self = Self {
        bits: crate::consts::WIMLIB_OPEN_FLAG_WRITE_ACCESS as u32,
    };

    /// No flags (same as [`OpenFlags::EMPTY`]).
    pub const fn empty() -> Self {
        Self::EMPTY
    }

    /// The raw flag word for `wimlib_open_wim`.
    pub const fn bits(self) -> u32 {
        self.bits
    }
}

impl BitOr for OpenFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            bits: self.bits | rhs.bits,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WimlibError;

    use super::*;

    #[test]
    fn flag_words_match_header_1_14() {
        assert_eq!(ExtractFlags::NONE.bits(), 0);
        assert_eq!(ExtractFlags::NTFS.bits(), 0x1);
        assert_eq!(ExtractFlags::NO_ACLS.bits(), 0x40);
        assert_eq!(ExtractFlags::NO_ATTRIBUTES.bits(), 0x100000);
        assert_eq!(OpenFlags::EMPTY.bits(), 0);
        assert_eq!(OpenFlags::CHECK_INTEGRITY.bits(), 0x1);
        assert_eq!(OpenFlags::ERROR_IF_SPLIT.bits(), 0x2);
        assert_eq!(OpenFlags::WRITE_ACCESS.bits(), 0x4);
    }

    /// Every safe flag bit equals its linked `ffi` counterpart, so a
    /// future header drift fails here instead of compiling two truths.
    /// The values are already single-sourced through `crate::consts`;
    /// this test locks the re-export chain end to end.
    #[cfg(wimlib_present)]
    #[test]
    fn flag_bits_match_linked_ffi() {
        use core::ffi::c_int as Raw;

        assert_eq!(
            ExtractFlags::NTFS.bits() as Raw,
            crate::ffi::WIMLIB_EXTRACT_FLAG_NTFS
        );
        assert_eq!(
            ExtractFlags::NO_ACLS.bits() as Raw,
            crate::ffi::WIMLIB_EXTRACT_FLAG_NO_ACLS
        );
        assert_eq!(
            ExtractFlags::NO_ATTRIBUTES.bits() as Raw,
            crate::ffi::WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES
        );
        assert_eq!(
            OpenFlags::CHECK_INTEGRITY.bits() as Raw,
            crate::ffi::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY
        );
        assert_eq!(
            OpenFlags::ERROR_IF_SPLIT.bits() as Raw,
            crate::ffi::WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT
        );
        assert_eq!(
            OpenFlags::WRITE_ACCESS.bits() as Raw,
            crate::ffi::WIMLIB_OPEN_FLAG_WRITE_ACCESS
        );
    }

    #[test]
    fn flags_combine_with_bitor() {
        let combined = ExtractFlags::NTFS | ExtractFlags::NO_ACLS;
        assert_eq!(combined.bits(), 0x41);
        let opened = OpenFlags::CHECK_INTEGRITY | OpenFlags::WRITE_ACCESS;
        assert_eq!(opened.bits(), 0x5);
        assert_eq!(ExtractFlags::empty(), ExtractFlags::NONE);
        assert_eq!(ExtractFlags::ntfs(), ExtractFlags::NTFS);
        assert_eq!(OpenFlags::empty(), OpenFlags::EMPTY);
    }

    #[test]
    fn abort_code_matches_header_enum() {
        // `WIMLIB_ERR_ABORTED_BY_PROGRESS = 76` (`wimlib.h` enum
        // `wimlib_error_code`); the shared copy must agree with the
        // gated raw constant whenever it exists.
        assert_eq!(ERR_ABORTED_BY_PROGRESS, 76);
        #[cfg(wimlib_present)]
        assert_eq!(
            ERR_ABORTED_BY_PROGRESS,
            crate::ffi::WIMLIB_ERR_ABORTED_BY_PROGRESS
        );
        let _ = WimlibError::NotLinked;
    }
}
