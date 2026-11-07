//! Raw wimlib integer values shared across the link gate.
//!
//! `cfg(wimlib_present)` gates the `ffi` module, but the safe facade
//! (`safe`) is always compiled and needs the same numbers for its flag
//! types and the abort code. Defining each value once here — rather
//! than once per side — makes drift a compile-time non-event: `ffi`
//! re-exports them under their `WIMLIB_*` names when linked, and `safe`
//! builds its flag types from them in both configurations.
//!
//! Only the values both sides need live here (the flag bits S21 uses
//! plus the progress-abort code); every other `WIMLIB_*` constant stays
//! a plain declaration in `ffi`. Plain integers only: no unsafe, no
//! calls, nothing to review beyond the header mapping.
//!
//! Mapping: `/usr/include/wimlib.h` 1.14.5, `WIMLIB_EXTRACT_FLAG_*`
//! (`0x00000001`, `0x00000040`, `0x00100000`), `WIMLIB_OPEN_FLAG_*`
//! (`0x00000001`, `0x00000002`, `0x00000004`), and `enum
//! wimlib_error_code` (`WIMLIB_ERR_ABORTED_BY_PROGRESS = 76`).

use core::ffi::c_int;

/// Extract directly to an unmounted NTFS volume.
pub const WIMLIB_EXTRACT_FLAG_NTFS: c_int = 0x0000_0001;
/// Do not extract security descriptors.
pub const WIMLIB_EXTRACT_FLAG_NO_ACLS: c_int = 0x0000_0040;
/// Do not extract Windows file attributes.
pub const WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES: c_int = 0x0010_0000;

/// Verify the WIM against its integrity table while opening, if present.
pub const WIMLIB_OPEN_FLAG_CHECK_INTEGRITY: c_int = 0x0000_0001;
/// Fail with `WIMLIB_ERR_IS_SPLIT_WIM` when the WIM is a split part.
pub const WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT: c_int = 0x0000_0002;
/// Check writability now (fail fast instead of at overwrite time).
pub const WIMLIB_OPEN_FLAG_WRITE_ACCESS: c_int = 0x0000_0004;

/// Returned when the progress callback aborts the operation.
pub const WIMLIB_ERR_ABORTED_BY_PROGRESS: c_int = 76;
