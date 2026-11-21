//! `xtask`: repo maintenance tasks for the furus workspace (S01).
//!
//! No feature code lives here; only checks and reports:
//!
//! * `assets --check` — validate `assets/manifest.json` against files on disk
//! * `parity`          — validate `data/parity.csv` against `data/functions.csv`
//! * `parity --check`  — additionally prove `data/parity.csv` is freshly
//!   regenerated (CI gate; never dirties the tree)
//! * `size`            — release-build, enforce budgets, check growth
//!   against the committed baseline within allowance (never writes it)
//! * `size --write-baseline` — update the committed baseline (humans only)
//! * `ci`              — run every gate in order (fmt, clippy, test, ...)
//! * `dist`            — release-build, validate packaging/, emit a
//!   deterministic bundle (tar.gz + SHA256SUMS; .deb when dpkg-deb is
//!   available)
//! * `qa`              — end-to-end release gate. Tier 1 always runs,
//!   unprivileged, over sparse file targets: it orchestrates the existing
//!   formatter / partition / pipeline / BCD / SYSTEM-hive test suites.
//!   Tier 2 boots BIOS and UEFI images headlessly when QEMU + firmware are
//!   installed, with a hard per-invocation timeout and kill/reap on every
//!   path. `--require-qemu` makes a missing Tier 2 toolchain fatal;
//!   `--privileged` additionally enables loop-device suites (off by default).
//!
//! The xtask must work when invoked from the repo root
//! (`cargo xtask ...`); all paths are anchored at the workspace root derived
//! from `CARGO_MANIFEST_DIR`, never at the current directory.

#![forbid(unsafe_code)]

mod assets;
mod ci;
mod contract;
mod dist;
mod packaging;
mod parity;
mod qa;
mod size;
mod util;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use std::path::PathBuf;

use crate::assets::cmd_assets_check;
use crate::ci::cmd_ci;
use crate::dist::cmd_dist;
use crate::parity::ParityMode;
use crate::parity::cmd_parity;
use crate::qa::cmd_qa;
use crate::qa::parse_qa_options;
use crate::size::cmd_size;
use crate::util::repo_root;

fn print_usage() {
    println!(
        "\
usage: cargo xtask <task> [options]

tasks:
  assets --check   validate assets/manifest.json against assets/resources/
  parity [--regenerate | --check]
                   validate data/parity.csv (--regenerate rewrites it in
                   place; --check proves a rewrite would change nothing)
  size [--write-baseline]
                   release-build, enforce budgets, check growth against the
                   committed baseline within 4096-byte allowance
                   (--write-baseline updates it instead)
  ci               fmt + clippy + test + assets + parity --check + size (+ deny/audit)
  qa [--require-qemu] [--privileged]
                    two-tier end-to-end release gate:
                      tier 1 (always): unprivileged sparse-file suites — MBR/GPT,
                      FAT32/exFAT/NTFS/ext4/UDF, UEFI:NTFS structure, BCD +
                      SYSTEM hive, Windows boot files/bootloader
                      tier 2 (when QEMU + firmware exist): headless BIOS smoke,
                      real BIOS bootloader boots, OVMF/UEFI:NTFS boot — each
                      with a hard 30-120s timeout and kill/reap on every path
                      --require-qemu: fail instead of skipping when QEMU or the
                      UEFI firmware/toolchain is missing
                      --privileged: also run loop-device/mount suites (off by
                      default; unprivileged sparse-file mode is the default)
  dist [--target <triple>] [--out-dir <dir>]
                   release-build, validate packaging/, stage a deterministic
                   bundle (tar.gz + SHA256SUMS, .deb when dpkg-deb exists)
                   default target = rustc host triple; default out-dir =
                   target/dist/<triple>"
    );
}

fn main() -> Result<()> {
    let root = repo_root();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        bail!("no task given");
    }
    let task = args.remove(0);
    match task.as_str() {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "--version" => {
            println!("xtask {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "assets" => {
            if args.iter().any(|a| a == "--check") {
                cmd_assets_check(&root)
            } else {
                bail!("usage: cargo xtask assets --check");
            }
        }
        "parity" => {
            let regenerate = args.iter().any(|a| a == "--regenerate");
            let check = args.iter().any(|a| a == "--check");
            if regenerate && check {
                bail!("parity: --regenerate and --check are mutually exclusive");
            }
            if let Some(unknown) = args
                .iter()
                .find(|a| *a != "--regenerate" && *a != "--check")
            {
                bail!(
                    "parity: unknown option `{unknown}` (usage: cargo xtask parity [--regenerate | --check])"
                );
            }
            cmd_parity(
                &root,
                if regenerate {
                    ParityMode::Regenerate
                } else if check {
                    ParityMode::Check
                } else {
                    ParityMode::Validate
                },
            )
        }
        "size" => {
            let write_baseline = args.iter().any(|a| a == "--write-baseline");
            if let Some(unknown) = args.iter().find(|a| *a != "--write-baseline") {
                bail!(
                    "size: unknown option `{unknown}` (usage: cargo xtask size [--write-baseline])"
                );
            }
            cmd_size(&root, write_baseline)
        }
        "ci" => cmd_ci(&root),
        "qa" => cmd_qa(&root, parse_qa_options(&args)?),
        "dist" => {
            let mut target: Option<String> = None;
            let mut out_dir: Option<PathBuf> = None;
            let mut it = args.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--target" => {
                        target = Some(
                            it.next()
                                .context("dist: --target needs a target triple")?
                                .clone(),
                        );
                    }
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(
                            it.next().context("dist: --out-dir needs a directory")?,
                        ));
                    }
                    other => bail!(
                        "dist: unknown option `{other}` (usage: cargo xtask dist [--target <triple>] [--out-dir <dir>])"
                    ),
                }
            }
            cmd_dist(target, out_dir)
        }
        other => bail!("unknown task `{other}` (see `cargo xtask --help`)"),
    }
}
