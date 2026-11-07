//! Linked implementation of the safe facade: [`Wim`] wraps the raw
//! externs behind plain Rust types.
//!
//! The only `unsafe` in this file is calling wimlib and decoding what it
//! hands back; every public item takes and returns safe types only, so
//! dependents (notably `rufus-core`, which forbids `unsafe`) use the
//! facade without ever touching a raw pointer.
//!
//! Progress reporting: [`Wim::extract_image`] registers a trampoline
//! with `wimlib_register_progress_function` whose `progctx` points at a
//! stack [`Ctx`] holding the caller's callback and the running
//! [`ExtractProgress`](super::ExtractProgress) accumulator. The
//! trampoline folds each documented `EXTRACT_*` message into the
//! accumulator, invokes the callback, and returns continue/abort. A
//! callback panic is caught instead of unwinding into C (which would
//! be undefined behaviour): the trampoline records the payload and
//! aborts the operation, and the facade re-raises the panic with
//! `resume_unwind` after the wimlib call returns and the registration
//! is removed — so a panicking callback unwinds through
//! [`Wim::extract_image`], never across the FFI boundary and never
//! reported as a cancellation. The registration is removed (null
//! function) before `extract_image` returns, so the stack pointer
//! never outlives the borrow; the next call re-registers.
//!
//! `wimlib_global_init` runs exactly once per process (a `OnceLock`
//! caches the code, including failure); every constructor goes through
//! it, so a [`Wim`] can only exist after a successful init.

// The second (and last) `#[allow(unsafe_code)]` site of this crate:
// the FFI declarations in `src/ffi.rs` are the first. It covers only
// this module — calling the linked externs, decoding their C strings,
// and the progress trampoline C must call back into. No new site may
// be added without review.
#![allow(unsafe_code)]

use std::any::Any;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::os::unix::ffi::OsStrExt as _;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::path::Path;
use std::sync::OnceLock;

use crate::error::WimlibError;
use crate::ffi;

use super::Compression;
use super::ExtractFlags;
use super::ExtractProgress;
use super::OpenFlags;
use super::WimInfo;

/// An open WIM handle: owns the `WIMStruct` from `wimlib_open_wim` and
/// frees it on drop.
///
/// The raw pointer never escapes (all methods take safe types), the
/// type is not constructible outside this module, and it is neither
/// `Send` nor `Sync` (a raw pointer is neither by default, and wimlib
/// handles carry no thread-safety contract) — share the results, not
/// the handle.
pub struct Wim {
    /// Handle from `wimlib_open_wim`; never null after `open`.
    raw: *mut ffi::WIMStruct,
}

impl Drop for Wim {
    fn drop(&mut self) {
        // `wimlib_free` treats null as a no-op; `raw` is never null
        // here, but the call stays correct even so.
        unsafe {
            ffi::wimlib_free(self.raw);
        }
    }
}

/// Callback state living on the `extract_image` stack frame: the
/// caller's callback, the running progress accumulator the trampoline
/// folds each message into, and the payload of a callback panic (if
/// any) waiting to be re-raised after the wimlib call returns.
struct Ctx<'a> {
    /// Caller callback: `false` aborts the extraction.
    cb: &'a mut dyn FnMut(&ExtractProgress) -> bool,
    /// Running totals across the messages seen so far.
    msg: ExtractProgress,
    /// A caught callback panic, re-raised by the facade after the
    /// wimlib call returns (never across the FFI boundary).
    panic: Option<Box<dyn Any + Send>>,
}

impl Wim {
    /// Open the WIM at `path` with `flags`.
    ///
    /// Runs `wimlib_global_init` first (exactly once per process; a
    /// failure is returned as [`WimlibError::Code`]). Paths reach
    /// wimlib as UTF-8 bytes (`wimlib_tchar` is `char` on Linux); a
    /// path with an interior NUL byte fails with
    /// [`WimlibError::InvalidPath`] before any library call.
    pub fn open(path: &Path, flags: OpenFlags) -> Result<Wim, WimlibError> {
        ensure_init()?;
        let native = to_cstring(path)?;
        let mut raw: *mut ffi::WIMStruct = std::ptr::null_mut();
        let code =
            unsafe { ffi::wimlib_open_wim(native.as_ptr(), flags.bits() as c_int, &mut raw) };
        if code != ffi::WIMLIB_ERR_SUCCESS || raw.is_null() {
            return Err(code_error(code));
        }
        Ok(Wim { raw })
    }

    /// General information about the open WIM.
    ///
    /// Needs no init check: a [`Wim`] can only come from [`Wim::open`],
    /// which initialised the library already.
    pub fn info(&self) -> Result<WimInfo, WimlibError> {
        let mut slot = std::mem::MaybeUninit::<ffi::WimlibWimInfo>::uninit();
        let code = unsafe { ffi::wimlib_get_wim_info(self.raw, slot.as_mut_ptr()) };
        if code != ffi::WIMLIB_ERR_SUCCESS {
            return Err(code_error(code));
        }
        let raw = unsafe { slot.assume_init() };
        Ok(WimInfo {
            image_count: raw.image_count,
            boot_index: raw.boot_index,
            wim_version: raw.wim_version,
            chunk_size: raw.chunk_size,
            part_number: raw.part_number,
            total_parts: raw.total_parts,
            compression: match raw.compression_type {
                0 => Compression::None,
                1 => Compression::Xpress,
                2 => Compression::Lzx,
                3 => Compression::Lzms,
                other => Compression::Other(other),
            },
            total_bytes: raw.total_bytes,
            has_integrity_table: raw.flags & (1 << 0) != 0,
            is_readonly: raw.flags & (1 << 2) != 0,
            is_marked_readonly: raw.flags & (1 << 4) != 0,
            has_rpfix: raw.flags & (1 << 3) != 0,
            spanned: raw.flags & (1 << 5) != 0,
            metadata_only: raw.flags & (1 << 7) != 0,
            resource_only: raw.flags & (1 << 8) != 0,
            is_pipable: raw.flags & (1 << 9) != 0,
        })
    }

    /// Name of the 1-based `image` (`None` for an out-of-range index;
    /// empty string when the image is unnamed). Indices that cannot be
    /// a valid C `int` read as `None` without any library call.
    pub fn image_name(&self, image: u32) -> Result<Option<String>, WimlibError> {
        let Ok(index) = i32::try_from(image) else {
            return Ok(None);
        };
        let raw = unsafe { ffi::wimlib_get_image_name(self.raw, index) };
        Ok(decode_string(raw))
    }

    /// Description of the 1-based `image` (`None` when missing or the
    /// index is out of range). Indices that cannot be a valid C `int`
    /// read as `None` without any library call.
    pub fn image_description(&self, image: u32) -> Result<Option<String>, WimlibError> {
        let Ok(index) = i32::try_from(image) else {
            return Ok(None);
        };
        let raw = unsafe { ffi::wimlib_get_image_description(self.raw, index) };
        Ok(decode_string(raw))
    }

    /// Value of one per-image XML property (for example "TOTALBYTES").
    /// `None` when the index cannot be a C `int`, when `name` carries an
    /// interior NUL (reported as `InvalidPath`), when the image has no
    /// such property (null return), or when the value is not valid
    /// UTF-8 (never a lossy string that could parse as a wrong number).
    pub fn image_property(&self, image: u32, name: &str) -> Result<Option<String>, WimlibError> {
        let Ok(index) = i32::try_from(image) else {
            return Ok(None);
        };
        let native = CString::new(name).map_err(|_| WimlibError::InvalidPath {
            path: name
                .bytes()
                .map(|byte| {
                    if byte.is_ascii_graphic() || byte == b' ' {
                        byte as char
                    } else {
                        '?'
                    }
                })
                .collect(),
        })?;
        let raw = unsafe { ffi::wimlib_get_image_property(self.raw, index, native.as_ptr()) };
        Ok(decode_string(raw))
    }

    /// Extract (`apply`) the 1-based `image` into `target`.
    ///
    /// The `progress` callback receives the running
    /// [`ExtractProgress`](super::ExtractProgress) after every
    /// documented `EXTRACT_*` message and returns whether to continue:
    /// `false` aborts the extraction, which surfaces as
    /// [`WimlibError::Code`] with code
    /// [`ERR_ABORTED_BY_PROGRESS`](super::ERR_ABORTED_BY_PROGRESS).
    /// A panicking callback unwinds out of this function (re-raised
    /// after the wimlib call returns and the registration is removed):
    /// it is never reported as a cancellation and never unwinds into C.
    ///
    /// The progress registration lives only for the duration of this
    /// call (unregistered before returning), so the stack [`Ctx`]
    /// pointer never outlives the borrow.
    pub fn extract_image(
        &self,
        image: u32,
        target: &Path,
        flags: ExtractFlags,
        progress: &mut dyn FnMut(&ExtractProgress) -> bool,
    ) -> Result<(), WimlibError> {
        let native = to_cstring(target)?;
        let mut ctx = Ctx {
            cb: progress,
            msg: ExtractProgress::default(),
            panic: None,
        };
        let ctx_ptr = (&mut ctx as *mut Ctx<'_>) as *mut c_void;
        let code = unsafe {
            ffi::wimlib_register_progress_function(self.raw, Some(extract_trampoline), ctx_ptr);
            let code = ffi::wimlib_extract_image(
                self.raw,
                image as c_int,
                native.as_ptr(),
                flags.bits() as c_int,
            );
            ffi::wimlib_register_progress_function(self.raw, None, std::ptr::null_mut());
            code
        };
        if let Some(payload) = ctx.panic {
            resume_unwind(payload);
        }
        if code == ffi::WIMLIB_ERR_SUCCESS {
            Ok(())
        } else {
            Err(code_error(code))
        }
    }
}

/// Run `wimlib_global_init` exactly once per process, caching the
/// result (including failure) in a `OnceLock`.
fn ensure_init() -> Result<(), WimlibError> {
    static INIT: OnceLock<c_int> = OnceLock::new();
    let code = *INIT.get_or_init(|| unsafe { ffi::wimlib_global_init(0) });
    if code == ffi::WIMLIB_ERR_SUCCESS {
        Ok(())
    } else {
        Err(code_error(code))
    }
}

/// Build a [`WimlibError::Code`] for `code`, reading the message from
/// `wimlib_get_error_string` now (or a fixed fallback when the
/// library hands back null or undecodable text).
fn code_error(code: c_int) -> WimlibError {
    let message = decode_string(unsafe { ffi::wimlib_get_error_string(code) })
        .unwrap_or_else(|| "unknown wimlib error".to_string());
    WimlibError::Code { code, message }
}

/// Encode `path` for wimlib (UTF-8 bytes on Linux); an interior NUL
/// byte has no C representation and fails with `InvalidPath`.
fn to_cstring(path: &Path) -> Result<CString, WimlibError> {
    let bytes = path.as_os_str().as_bytes();
    CString::new(bytes).map_err(|_| WimlibError::InvalidPath {
        path: ascii_path(path),
    })
}

/// Log-safe rendering of a path: printable ASCII passes through, and
/// anything else (controls, NUL, non-ASCII) becomes `?`, so the
/// message stays one ASCII line.
fn ascii_path(path: &Path) -> String {
    path.as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '?'
            }
        })
        .collect()
}

/// Decode a wimlib string pointer: null or undecodable text reads as
/// `None` (never panics, never retains the pointer).
fn decode_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Fold one progress message into the accumulator.
///
/// The header documents which fields are valid per message (`struct
/// wimlib_progress_info_extract`): byte and stream counts arrive on
/// every `EXTRACT_*` message, part numbers only on
/// `EXTRACT_SPWM_PART_BEGIN`, and the file counts only on
/// `EXTRACT_FILE_STRUCTURE`/`EXTRACT_METADATA`. The image name is
/// decoded once (or again only when the image index changes, which a
/// single-image extraction never does); anything else stays at its
/// previous value.
fn fold_sample(msg: c_int, extract: &ffi::WimlibProgressInfoExtract, acc: &mut ExtractProgress) {
    if extract.image != acc.image || acc.image_name.is_none() {
        acc.image_name = decode_string(extract.image_name);
    }
    acc.image = extract.image;
    acc.total_bytes = extract.total_bytes;
    acc.completed_bytes = extract.completed_bytes;
    acc.total_streams = extract.total_streams;
    acc.completed_streams = extract.completed_streams;
    if msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN {
        acc.part_number = extract.part_number;
        acc.total_parts = extract.total_parts;
    }
    if msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA
    {
        acc.total_files = extract.end_file_count;
        acc.completed_files = extract.current_file_count;
    }
}

/// Progress trampoline handed to C: folds the message, runs the Rust
/// callback, and returns continue/abort.
///
/// A callback panic is caught and recorded (first payload wins); the
/// trampoline answers abort so the operation stops, and the facade
/// re-raises the panic after the wimlib call returns — never across
/// the FFI boundary.
///
/// Unknown messages and null pointers continue silently: extraction
/// only ever sends the documented `EXTRACT_*` set with valid info,
/// and refusing to guess keeps a future message from breaking apply.
unsafe extern "C" fn extract_trampoline(
    msg: c_int,
    info: *const ffi::WimlibProgressInfo,
    progctx: *mut c_void,
) -> c_int {
    let (extract, ctx) = unsafe {
        match (
            info.as_ref().map(|info| &info.extract),
            (progctx as *mut Ctx<'_>).as_mut(),
        ) {
            (Some(extract), Some(ctx)) => (extract, ctx),
            _ => return ffi::WIMLIB_PROGRESS_STATUS_CONTINUE,
        }
    };
    let known = msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END
        || msg == ffi::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END;
    if !known {
        return ffi::WIMLIB_PROGRESS_STATUS_CONTINUE;
    }
    fold_sample(msg, extract, &mut ctx.msg);
    match catch_unwind(AssertUnwindSafe(|| (ctx.cb)(&ctx.msg))) {
        Ok(true) => ffi::WIMLIB_PROGRESS_STATUS_CONTINUE,
        Ok(false) => ffi::WIMLIB_PROGRESS_STATUS_ABORT,
        Err(payload) => {
            if ctx.panic.is_none() {
                ctx.panic = Some(payload);
            }
            ffi::WIMLIB_PROGRESS_STATUS_ABORT
        }
    }
}
