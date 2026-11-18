//! Compile the Slint UI shell (`ui/main.slint`) ahead of the build.
//!
//! Slice S24-C C2 (S24-T1): the only job of this script is to hand the
//! declarative layout to `slint-build` at the same exact Slint version
//! pinned in `Cargo.toml`. All business rules stay in `src/state.rs`.

fn main() {
    println!("cargo:rerun-if-changed=ui/main.slint");
    slint_build::compile("ui/main.slint").expect("slint-build must compile ui/main.slint");
}
