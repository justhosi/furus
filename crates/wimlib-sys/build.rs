//! Build script for `wimlib-sys`.
//!
//! S01: no-op. S21 will probe for `libwim` here (pkg-config / static link)
//! and emit the `cargo:rustc-link-lib` lines.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
