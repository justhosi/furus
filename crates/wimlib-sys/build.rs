//! Build script for `wimlib-sys`.
//!
//! S21: probe for `libwim` and gate the FFI on `cfg(wimlib_present)`.
//! The rest of the workspace must build and test green when the library
//! is absent: this script never panics and never fails the build, it
//! only decides whether `wimlib_present` is set.
//!
//! Probe order (first hit wins):
//!
//! 1. `WIMLIB_SYS_FORCE_UNLINKED` set to any non-empty value except
//!    `0` — skip linking entirely (graceful-skip path for CI/hosts
//!    without wimlib).
//! 2. `WIMLIB_LIB_DIR` set to a non-empty directory — emit a
//!    `rustc-link-search` for it plus `rustc-link-lib=wim`.
//! 3. `pkg-config --exists wimlib` succeeds — emit one
//!    `rustc-link-search` per `-L` path from `pkg-config --libs-only-L
//!    wimlib`, plus `rustc-link-lib=wim`.
//! 4. Last resort: a well-known file (`/usr/lib/libwim.so`,
//!    `/usr/lib64/libwim.so`, plus static/MacOS variants) exists —
//!    emit `rustc-link-lib=wim` with no search path (on Linux the
//!    default search path already covers `/usr/lib`).
//!
//! Only `std::process::Command` is used: no new Cargo dependencies.

use std::path::Path;
use std::process::Command;

/// Emit the "not found" warning. This is the only warning this script
/// ever prints; the happy path stays silent.
fn declare_absent() {
    println!(
        "cargo:warning=wimlib not found; \
         wimlib-sys builds without FFI (linked() == false)"
    );
}

/// Emit the gate cfg. Callers print their own link lines first.
fn declare_present() {
    println!("cargo:rustc-cfg=wimlib_present");
}

/// True when `pkg-config --exists wimlib` succeeds. A missing
/// `pkg-config` binary (or any failure) is `false`, never an error.
fn pkg_config_exists() -> bool {
    Command::new("pkg-config")
        .args(["--exists", "wimlib"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The `-L...` tokens from `pkg-config --libs-only-L wimlib`, if any.
/// Failure (or unparsable output) yields an empty list, never an error.
fn pkg_config_lib_dirs() -> Vec<String> {
    let output = Command::new("pkg-config")
        .args(["--libs-only-L", "wimlib"])
        .output();
    match output {
        Ok(result) if result.status.success() => String::from_utf8_lossy(&result.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WIMLIB_SYS_FORCE_UNLINKED");
    println!("cargo:rerun-if-env-changed=WIMLIB_LIB_DIR");
    // Keep `unexpected_cfgs` quiet for the gate this script controls.
    println!("cargo:rustc-check-cfg=cfg(wimlib_present)");

    // 1. Forced unlink wins over everything (empty and "0" count as
    // unset, matching the usual truthiness convention).
    if let Ok(forced) = std::env::var("WIMLIB_SYS_FORCE_UNLINKED")
        && !forced.is_empty()
        && forced != "0"
    {
        declare_absent();
        return;
    }

    // 2. Explicit library directory.
    if let Ok(dir) = std::env::var("WIMLIB_LIB_DIR")
        && !dir.is_empty()
    {
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=wim");
        declare_present();
        return;
    }

    // 3. pkg-config probe.
    if pkg_config_exists() {
        for token in pkg_config_lib_dirs() {
            if let Some(dir) = token.strip_prefix("-L")
                && !dir.is_empty()
            {
                println!("cargo:rustc-link-search=native={dir}");
            }
        }
        println!("cargo:rustc-link-lib=wim");
        declare_present();
        return;
    }

    // 4. Last resort: well-known file locations. No search path is
    // emitted: on Linux the default library search path already covers
    // `/usr/lib`.
    const CANDIDATES: &[&str] = &[
        "/usr/lib/libwim.so",
        "/usr/lib64/libwim.so",
        "/usr/lib/libwim.a",
        "/usr/lib64/libwim.a",
        "/usr/lib/libwim.dylib",
        "/usr/lib64/libwim.dylib",
    ];
    if CANDIDATES
        .iter()
        .any(|candidate| Path::new(candidate).exists())
    {
        println!("cargo:rustc-link-lib=wim");
        declare_present();
        return;
    }

    declare_absent();
}
