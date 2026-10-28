//! Build script: bake the short git hash into `GIT_HASH`.
//!
//! `version.rs` reads it via `option_env!("GIT_HASH")` with an `"unknown"`
//! fallback, so every outcome here (including "no git available") keeps the
//! build working.

use std::path::Path;
use std::process::Command;

fn main() {
    // Re-run when the build script itself or the git HEAD changes, so the
    // hash cannot go stale across commits. The HEAD path is workspace
    // relative (this script runs with the package dir as cwd).
    println!("cargo:rerun-if-changed=build.rs");
    if Path::new("../../.git/HEAD").exists() {
        println!("cargo:rerun-if-changed=../../.git/HEAD");
    }

    let hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_string())
        .filter(|hash| !hash.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_HASH={hash}");
}
