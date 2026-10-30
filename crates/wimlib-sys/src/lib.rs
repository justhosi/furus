//! `wimlib-sys`: raw FFI bindings to wimlib for WIM/ESD apply.
//!
//! Slice S01 only: an empty placeholder. Linking (build script probing for
//! `libwim`, `wimlib_open_wim`, progress callbacks, `wimlib_split`) arrives
//! in S21. The `links = "wim"` key is already declared so downstream crates
//! can depend on this crate name from day one.

#![forbid(unsafe_code)]

/// Returns `false` until S21 links the real library.
pub fn linked() -> bool {
    false
}
