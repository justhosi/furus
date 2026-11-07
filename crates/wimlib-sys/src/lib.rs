//! `wimlib-sys`: raw FFI bindings to wimlib for WIM/ESD apply.
//!
//! This crate exists for S21 (WIM apply, Windows To Go, BCD): it links
//! the system `libwim` and re-exports the exact C declarations the S21
//! wrapper needs — open/info/extract/split, the progress callback, and
//! the version/error-string helpers. Nothing else in the workspace
//! talks to wimlib directly.
//!
//! The declarations mirror the system header `/usr/include/wimlib.h`
//! (wimlib 1.14.x; see `src/ffi.rs` for the per-item mapping). On Linux
//! `wimlib_tchar` is `char`: paths are UTF-8 byte strings, so the safe
//! wrappers decode them with a plain UTF-8 conversion and never touch
//! wide strings.
//!
//! Linking is optional and decided at build time by `build.rs`, which
//! sets `cfg(wimlib_present)` when `libwim` is found. When the library
//! is absent the `ffi` module does not exist at all, so no wimlib
//! symbol can be called; [`linked`] reports the outcome as a
//! compile-time fact.
//!
//! No other crate may declare wimlib symbols: every `wimlib_*` name
//! lives here, behind this gate, and downstream crates use the
//! re-exported items (or the S21 safe wrapper built on top of them).

// Unsafe policy (S21, following `rufus-linux`): the workspace lint is
// `deny` and this crate inherits it. There is exactly one
// `#[allow(unsafe_code)]` site in this crate — the FFI module
// declaration in `src/ffi.rs`, whose header documents what it may
// contain (raw C declarations mirroring `/usr/include/wimlib.h` and
// the two null-checked CStr wrappers, nothing else). There must be no
// second unsafe use anywhere: no crate-level `#![allow(unsafe_code)]`,
// no other `#[allow(unsafe_code)]` attribute in this crate.

#[cfg(wimlib_present)]
mod ffi;
#[cfg(wimlib_present)]
pub use ffi::*;

/// Whether this build linked `libwim`.
///
/// This is a compile-time fact (`cfg!(wimlib_present)`), not a runtime
/// probe: when it is false the FFI module does not exist at all, so no
/// wimlib function can be called. The build script decides the value by
/// probing for the library; `WIMLIB_SYS_FORCE_UNLINKED=1` forces false.
pub fn linked() -> bool {
    cfg!(wimlib_present)
}

#[cfg(test)]
mod tests {
    #[cfg(not(wimlib_present))]
    #[test]
    fn unlinked_build_reports_false() {
        // Without libwim the gate is off and there is nothing to call.
        assert!(
            !super::linked(),
            "linked must be false when wimlib is absent"
        );
    }
}
