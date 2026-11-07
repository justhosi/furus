//! Raw wimlib declarations for S21 (WIM apply, Windows To Go, BCD).
//!
//! # What is allowed here
//!
//! Exactly the C declarations below, mirroring `/usr/include/wimlib.h`
//! (wimlib 1.14.x) field for field, plus the two null-checked `CStr`
//! wrappers ([`version`], [`error_string`]). Nothing else may be added
//! without review: no safe logic, no allocation policy, no second
//! `#[allow(unsafe_code)]` site — the whole file lives inside the one
//! module-level allowance, and the S21 wrapper (a different crate) owns
//! every call.
//!
//! # Mapping notes
//!
//! * `wimlib_tchar` is `char` on Linux (UTF-8 paths, header section
//!   "Character encoding"), so it aliases [`c_char`] here. On Windows
//!   it would be `wchar_t`; this crate only targets Linux.
//! * `WIMStruct` is opaque: zero-sized and unconstructible, only ever
//!   touched behind a raw pointer handed back by `wimlib_open_wim`.
//! * `struct wimlib_wim_info` packs eleven one-bit fields plus a
//!   22-bit `reserved_flags` tail into one 32-bit word; that word is
//!   declared as a single [`WimlibWimInfo::flags`] `u32` with the bit
//!   positions documented there (reading bitfields from Rust would
//!   need layout guesses; a plain word does not).
//! * [`WimlibProgressInfo`] declares only the `extract` member: S21
//!   only registers progress for extraction, so that is the only
//!   member ever read, and only ever through a `*const` handed to the
//!   callback by C. Its size is never relied on as anything but a
//!   pointee.
//! * The 1.14.x header no longer defines `WIMLIB_EXTRACT_FLAG_HARDLINK`,
//!   `WIMLIB_EXTRACT_FLAG_SYMLINK`, `WIMLIB_EXTRACT_FLAG_VERBOSE`, or
//!   `WIMLIB_EXTRACT_FLAG_SEQUENTIAL` (verified by reading the header:
//!   no `EXTRACT_FLAG_` line carries those names), so they are
//!   deliberately absent here rather than guessed.
//! * `wimlib_get_error_string` takes an `enum wimlib_error_code` in C;
//!   the enum has C `int` representation, so the declaration uses
//!   [`c_int`] with no ABI difference.
//!
//! No other crate may declare wimlib symbols: everything `wimlib_*`
//! lives behind this module and the `wimlib_present` gate in
//! `src/lib.rs`.

// The single `#[allow(unsafe_code)]` site of this crate covers the
// whole FFI module: raw pointers, the `union`, the `extern` block, and
// the two wrappers that dereference C strings are all unsafe-capable,
// so scoping the allowance any tighter would only add noise.
#![allow(unsafe_code)]

use core::ffi::CStr;
use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_uint;
use core::ffi::c_void;

// ---------------------------------------------------------------------------
// Opaque handle and character type
// ---------------------------------------------------------------------------

/// Opaque WIM handle (`struct WIMStruct`).
///
/// Never constructed in Rust: `wimlib_open_wim` hands back a pointer,
/// `wimlib_free` reclaims it. The zero-sized private field keeps the
/// type uninhabited-by-construction while staying pointer-sized.
#[repr(C)]
pub struct WIMStruct {
    _private: [u8; 0],
}

/// Platform character type (`wimlib_tchar`).
///
/// `char` on Linux: paths are UTF-8 byte strings. The [`version`] and
/// [`error_string`] wrappers decode them with a plain UTF-8 conversion.
///
/// The name mirrors the header exactly, hence the casing allowance.
#[allow(non_camel_case_types)]
pub type wimlib_tchar = c_char;

// ---------------------------------------------------------------------------
// Progress reporting
// ---------------------------------------------------------------------------

/// Progress message codes (`enum wimlib_progress_msg`).
///
/// Only the messages S21 extraction can receive are listed; the values
/// are copied from the header.
pub const WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN: c_int = 0;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN: c_int = 1;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE: c_int = 3;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS: c_int = 4;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN: c_int = 5;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_METADATA: c_int = 6;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END: c_int = 7;
pub const WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END: c_int = 8;

/// Progress function return values (`enum wimlib_progress_status`).
pub const WIMLIB_PROGRESS_STATUS_CONTINUE: c_int = 0;
/// Aborts the in-progress operation with `WIMLIB_ERR_ABORTED_BY_PROGRESS`.
pub const WIMLIB_PROGRESS_STATUS_ABORT: c_int = 1;

/// Per-extraction progress payload (`struct wimlib_progress_info_extract`).
///
/// Field order and types mirror the header exactly. Sizes checked by
/// [`tests::extract_info_layout_matches_header_1_14`]: 112 bytes on
/// x86-64 (verified against the header with the C compiler).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WimlibProgressInfoExtract {
    /// 1-based index of the image being extracted.
    pub image: c_uint,
    /// Extraction flags in use.
    pub extract_flags: c_uint,
    /// Absolute path of the backing WIM file, or null.
    pub wimfile_name: *const wimlib_tchar,
    /// Name of the image being extracted (empty string if unnamed).
    pub image_name: *const wimlib_tchar,
    /// Target directory or NTFS volume path.
    pub target: *const wimlib_tchar,
    /// Reserved (always null in 1.14.x).
    pub reserved: *const wimlib_tchar,
    /// Bytes of file data to extract in total.
    pub total_bytes: u64,
    /// Bytes of file data extracted so far.
    pub completed_bytes: u64,
    /// File streams to extract in total.
    pub total_streams: u64,
    /// File streams extracted so far.
    pub completed_streams: u64,
    /// Split-part number (only for `EXTRACT_SPWM_PART_BEGIN`).
    pub part_number: c_uint,
    /// Split-part total (only for `EXTRACT_SPWM_PART_BEGIN`).
    pub total_parts: c_uint,
    /// Split-part GUID (only for `EXTRACT_SPWM_PART_BEGIN`).
    pub guid: [u8; 16],
    /// Files processed so far (structure/metadata phases).
    pub current_file_count: u64,
    /// Files to process in total (structure/metadata phases).
    pub end_file_count: u64,
}

/// Progress payload union (`union wimlib_progress_info`).
///
/// Only the `extract` member is declared: it is the only one S21 reads,
/// and only through a `*const` supplied by C to the progress callback.
/// The union is never constructed or written from Rust.
#[derive(Copy, Clone)]
#[repr(C)]
pub union WimlibProgressInfo {
    /// Valid for every `EXTRACT_*` message listed above.
    pub extract: WimlibProgressInfoExtract,
}

/// Progress callback type (`wimlib_progress_func_t`).
///
/// `None` unregisters (matches C `NULL`). The `info` pointer is
/// declared `*const` because the S21 callback only reads through it;
/// C declares it without `const`.
pub type WimlibProgressFunc = Option<
    unsafe extern "C" fn(
        msg: c_int,
        info: *const WimlibProgressInfo,
        progctx: *mut c_void,
    ) -> c_int,
>;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Verify the WIM against its integrity table while opening, if present.
pub const WIMLIB_OPEN_FLAG_CHECK_INTEGRITY: c_int = 0x0000_0001;
/// Fail with `WIMLIB_ERR_IS_SPLIT_WIM` when the WIM is a split part.
pub const WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT: c_int = 0x0000_0002;
/// Check writability now (fail fast instead of at overwrite time).
pub const WIMLIB_OPEN_FLAG_WRITE_ACCESS: c_int = 0x0000_0004;

/// Extract directly to an unmounted NTFS volume (needs libntfs-3g).
pub const WIMLIB_EXTRACT_FLAG_NTFS: c_int = 0x0000_0001;
/// Extract UNIX metadata captured with `WIMLIB_ADD_FLAG_UNIX_DATA`.
pub const WIMLIB_EXTRACT_FLAG_UNIX_DATA: c_int = 0x0000_0020;
/// Do not extract security descriptors (conflicts with `STRICT_ACLS`).
pub const WIMLIB_EXTRACT_FLAG_NO_ACLS: c_int = 0x0000_0040;
/// Fail instead of downgrading an unsettable security descriptor.
pub const WIMLIB_EXTRACT_FLAG_STRICT_ACLS: c_int = 0x0000_0080;
/// Do not extract Windows file attributes (readonly, hidden, ...).
pub const WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES: c_int = 0x0010_0000;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Every error code the S21 flows (open, info, extract, split, global
/// init, progress abort) can return, per the header's `enum
/// wimlib_error_code`. Values are copied from the header, not assigned.
/// Mount-, capture-, and compression-API-only codes are intentionally
/// omitted; add them when a wrapper needs them.
pub const WIMLIB_ERR_SUCCESS: c_int = 0;
pub const WIMLIB_ERR_DECOMPRESSION: c_int = 2;
pub const WIMLIB_ERR_IMAGE_COUNT: c_int = 10;
pub const WIMLIB_ERR_INSUFFICIENT_PRIVILEGES: c_int = 12;
pub const WIMLIB_ERR_INTEGRITY: c_int = 13;
pub const WIMLIB_ERR_INVALID_CHUNK_SIZE: c_int = 15;
pub const WIMLIB_ERR_INVALID_COMPRESSION_TYPE: c_int = 16;
pub const WIMLIB_ERR_INVALID_HEADER: c_int = 17;
pub const WIMLIB_ERR_INVALID_IMAGE: c_int = 18;
pub const WIMLIB_ERR_INVALID_INTEGRITY_TABLE: c_int = 19;
pub const WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY: c_int = 20;
pub const WIMLIB_ERR_INVALID_METADATA_RESOURCE: c_int = 21;
pub const WIMLIB_ERR_INVALID_PARAM: c_int = 24;
pub const WIMLIB_ERR_INVALID_RESOURCE_HASH: c_int = 28;
pub const WIMLIB_ERR_INVALID_UTF8_STRING: c_int = 31;
pub const WIMLIB_ERR_IS_SPLIT_WIM: c_int = 33;
pub const WIMLIB_ERR_LINK: c_int = 35;
pub const WIMLIB_ERR_METADATA_NOT_FOUND: c_int = 36;
pub const WIMLIB_ERR_MKDIR: c_int = 37;
pub const WIMLIB_ERR_NOMEM: c_int = 39;
pub const WIMLIB_ERR_NOT_A_WIM_FILE: c_int = 43;
pub const WIMLIB_ERR_NTFS_3G: c_int = 46;
pub const WIMLIB_ERR_OPEN: c_int = 47;
pub const WIMLIB_ERR_PATH_DOES_NOT_EXIST: c_int = 49;
pub const WIMLIB_ERR_READ: c_int = 50;
pub const WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED: c_int = 54;
pub const WIMLIB_ERR_RESOURCE_NOT_FOUND: c_int = 55;
pub const WIMLIB_ERR_SET_ATTRIBUTES: c_int = 57;
pub const WIMLIB_ERR_SET_REPARSE_DATA: c_int = 58;
pub const WIMLIB_ERR_SET_SECURITY: c_int = 59;
pub const WIMLIB_ERR_SET_SHORT_NAME: c_int = 60;
pub const WIMLIB_ERR_SET_TIMESTAMPS: c_int = 61;
pub const WIMLIB_ERR_SPLIT_INVALID: c_int = 62;
pub const WIMLIB_ERR_STAT: c_int = 63;
pub const WIMLIB_ERR_UNEXPECTED_END_OF_FILE: c_int = 65;
pub const WIMLIB_ERR_UNKNOWN_VERSION: c_int = 67;
pub const WIMLIB_ERR_UNSUPPORTED: c_int = 68;
pub const WIMLIB_ERR_WIM_IS_READONLY: c_int = 71;
pub const WIMLIB_ERR_WRITE: c_int = 72;
pub const WIMLIB_ERR_XML: c_int = 73;
pub const WIMLIB_ERR_WIM_IS_ENCRYPTED: c_int = 74;
pub const WIMLIB_ERR_WIMBOOT: c_int = 75;
pub const WIMLIB_ERR_ABORTED_BY_PROGRESS: c_int = 76;
pub const WIMLIB_ERR_WIM_IS_INCOMPLETE: c_int = 84;

// ---------------------------------------------------------------------------
// WIM info
// ---------------------------------------------------------------------------

/// General WIM information (`struct wimlib_wim_info`), mirrored exactly.
///
/// The eleven one-bit fields plus the 22-bit `reserved_flags` tail of
/// the header are one 32-bit word here; bit positions (header order,
/// least-significant first):
///
/// * 0 `has_integrity_table`, 1 `opened_from_file`, 2 `is_readonly`,
///   3 `has_rpfix`, 4 `is_marked_readonly`, 5 `spanned`,
///   6 `write_in_progress`, 7 `metadata_only`, 8 `resource_only`,
///   9 `pipable`, 10..=31 `reserved_flags`.
///
/// Sizes checked by [`tests::wim_info_layout_matches_header_1_14`]: 88
/// bytes on x86-64 (verified against the header with the C compiler).
#[repr(C)]
pub struct WimlibWimInfo {
    /// WIM GUID (all split parts share one).
    pub guid: [u8; 16],
    /// Number of images in the WIM.
    pub image_count: c_uint,
    /// 1-based bootable image index, or 0.
    pub boot_index: c_uint,
    /// WIM format version.
    pub wim_version: c_uint,
    /// Default compression chunk size of resources.
    pub chunk_size: c_uint,
    /// 1-based index of this part (split WIMs), else 1.
    pub part_number: u16,
    /// Total split parts, else 1.
    pub total_parts: u16,
    /// Default compression type (`wimlib_compression_type` value).
    pub compression_type: c_int,
    /// WIM size in bytes, excluding XML data and integrity table.
    pub total_bytes: u64,
    /// Bitfield word; positions documented on the struct.
    pub flags: c_uint,
    /// Reserved (zeroed).
    pub reserved: [c_uint; 9],
}

// ---------------------------------------------------------------------------
// Extern functions (prototypes copied from the header)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// Open a WIM file; writes the new handle to `wim_ret`.
    pub fn wimlib_open_wim(
        wim_file: *const wimlib_tchar,
        open_flags: c_int,
        wim_ret: *mut *mut WIMStruct,
    ) -> c_int;
    /// Fill `info` with basic information about an open WIM.
    pub fn wimlib_get_wim_info(wim: *mut WIMStruct, info: *mut WimlibWimInfo) -> c_int;
    /// Extract (`apply`) one image (or all with `WIMLIB_ALL_IMAGES`).
    pub fn wimlib_extract_image(
        wim: *mut WIMStruct,
        image: c_int,
        target: *const wimlib_tchar,
        extract_flags: c_int,
    ) -> c_int;
    /// Split a WIM into parts of at most `part_size` bytes.
    pub fn wimlib_split(
        wim: *mut WIMStruct,
        swm_name: *const wimlib_tchar,
        part_size: u64,
        write_flags: c_int,
    ) -> c_int;
    /// Register (or, with `None`, unregister) the progress function.
    pub fn wimlib_register_progress_function(
        wim: *mut WIMStruct,
        progfunc: WimlibProgressFunc,
        progctx: *mut c_void,
    );
    /// Describe an error code as a static string (never null in 1.14.x,
    /// but still null-checked by [`error_string`]).
    pub fn wimlib_get_error_string(code: c_int) -> *const wimlib_tchar;
    /// Library `PACKAGE_VERSION` string, e.g. `"1.14.5"`.
    pub fn wimlib_get_version_string() -> *const wimlib_tchar;
    /// Release a `WIMStruct` (null is a no-op).
    pub fn wimlib_free(wim: *mut WIMStruct);
    /// Library global init (auto-runs with flags 0 if skipped).
    pub fn wimlib_global_init(init_flags: c_int) -> c_int;
    /// Release library-global resources.
    pub fn wimlib_global_cleanup();
}

// ---------------------------------------------------------------------------
// Safe wrappers (the only place the externs are called)
// ---------------------------------------------------------------------------

/// Library version string, e.g. `"1.14.5"`.
///
/// Returns `None` when the static string is null (never observed) or
/// not valid UTF-8. Never panics.
pub fn version() -> Option<String> {
    // SAFETY: the callee returns a pointer to a static NUL-terminated
    // string it owns; no locking or teardown races it, and the pointer
    // is null-checked before any dereference.
    let raw = unsafe { wimlib_get_version_string() };
    if raw.is_null() {
        return None;
    }
    // SAFETY: non-null per the check above; the header guarantees a
    // NUL-terminated byte string on Linux, read here and not retained.
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Human-readable description of a wimlib error `code`.
///
/// Returns `None` for a null return (never observed) or non-UTF-8
/// text. Never panics.
pub fn error_string(code: c_int) -> Option<String> {
    // SAFETY: same contract as `version`: a static NUL-terminated
    // string owned by the library, null-checked before dereference.
    let raw = unsafe { wimlib_get_error_string(code) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: non-null per the check above; read, converted, and not
    // retained.
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn extract_info_layout_matches_header_1_14() {
        // u32 + u32 (8) + four pointers (32) + four u64 (32) + u32 +
        // u32 (8) + guid[16] + two u64 (16) = 112, alignment 8. Matches
        // `sizeof(struct wimlib_progress_info_extract)` from
        // /usr/include/wimlib.h 1.14.5, checked with the C compiler.
        assert_eq!(
            size_of::<WimlibProgressInfoExtract>(),
            112,
            "extract info size drifted from the 1.14.5 header"
        );
    }

    #[test]
    fn wim_info_layout_matches_header_1_14() {
        // guid[16] + four u32 (16) + u16 + u16 (4) + i32 (4) + u64 (8)
        // + flags u32 (4) + reserved[9] u32 (36) = 88, alignment 8.
        // Matches `sizeof(struct wimlib_wim_info)` from
        // /usr/include/wimlib.h 1.14.5, checked with the C compiler.
        assert_eq!(
            size_of::<WimlibWimInfo>(),
            88,
            "wim info size drifted from the 1.14.5 header"
        );
    }

    #[test]
    fn error_codes_match_header_1_14() {
        // Spot-pin the codes the S21 flows match on; the rest are
        // copied from the same header enum in declaration order.
        assert_eq!(WIMLIB_ERR_SUCCESS, 0, "SUCCESS must be zero");
        assert_eq!(
            WIMLIB_ERR_ABORTED_BY_PROGRESS, 76,
            "abort code must match the header"
        );
        assert_eq!(
            WIMLIB_ERR_RESOURCE_NOT_FOUND, 55,
            "resource code must match the header"
        );
        assert_eq!(
            WIMLIB_ERR_NOT_A_WIM_FILE, 43,
            "not-a-wim code must match the header"
        );
    }

    #[test]
    fn linked_matches_build_and_library_answers() {
        // Only compiled when the gate is on: the FFI module does not
        // exist otherwise, so there is nothing to call.
        assert!(crate::linked(), "linked must be true when present");
        let text = version().expect("version string must decode");
        assert!(
            text.starts_with("1."),
            "version must start with 1, got {text:?}"
        );
        let detail = error_string(WIMLIB_ERR_SUCCESS).expect("error 0 must decode");
        assert!(!detail.is_empty(), "error 0 must be non-empty");
    }
}
