//! `cargo xtask ci`: run every gate in order.

use std::path::Path;

use anyhow::Result;

use crate::assets::cmd_assets_check;
use crate::contract::cmd_contract;
use crate::parity::ParityMode;
use crate::parity::cmd_parity;
use crate::size::cmd_size;
use crate::util::run;
use crate::util::tool_present;

pub(crate) fn cmd_ci(root: &Path) -> Result<()> {
    println!("==> fmt");
    run("cargo", &["fmt", "--all", "--", "--check"], root)?;
    println!("==> clippy");
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        root,
    )?;
    println!("==> test");
    run("cargo", &["test", "--workspace"], root)?;
    println!("==> assets --check");
    cmd_assets_check(root)?;
    println!("==> parity --check");
    cmd_parity(root, ParityMode::Check)?;
    println!("==> contract --check");
    cmd_contract(root)?;
    println!("==> size");
    cmd_size(root, false)?;
    for tool in ["cargo-deny", "cargo-audit"] {
        if tool_present(tool) {
            println!("==> {tool}");
            let args: &[&str] = if tool == "cargo-deny" {
                &["deny", "check"]
            } else {
                &["audit"]
            };
            run("cargo", args, root)?;
        } else {
            println!("SKIP (not installed): {tool}");
        }
    }
    println!("ci: all gates passed");
    Ok(())
}
