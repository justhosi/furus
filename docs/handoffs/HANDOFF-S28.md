# S28 — CI dependency fix handoff (fontconfig / winit native build headers)

This file records S28, a workflow-only fix to make both CI gates green on
`ubuntu-latest`. The single code change is committed and pushed as
`dee5c9e ci: install fontconfig and winit dev headers for furus-gui`; it is the
only code change in this slice. This handoff (plus the README and TECHNICAL.md
updates) is the documentation-only publishing step for S28.

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`. cargo/rustc 1.99.0 live
in `~/.cargo/bin`; prefix cargo commands with `PATH="$HOME/.cargo/bin:$PATH"`.

## Objective

`cargo xtask ci` (specifically `cargo clippy --workspace --all-targets`, which
builds `furus-gui`) failed on GitHub Actions `ubuntu-latest` because the native
system libraries that Slint/winit link against were not installed. The goal was
to make both `Run xtask ci` and `Run xtask qa` pass on the runner **without**
changing shipped code, relaxing a gate, loosening a size budget or skipping a
QA suite.

## Root cause

CI run **44580541599** (head `74599d5`, push to `main`) failed at `Run xtask
ci` after 6m07s; `Run xtask qa` never started. The build script of
`yeslogic-fontconfig-sys v6.0.1` panicked because `fontconfig.pc` was not
installed:

```
error: failed to run custom build command for `yeslogic-fontconfig-sys v6.0.1`

Caused by:
  process didn't exit successfully:
  `/home/runner/work/furus/furus/target/debug/build/yeslogic-fontconfig-sys-a5fa9c772a45724d/build-script-build`
  (exit status: 101)
  --- stderr
  thread 'main' (14140) panicked at
  /home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/yeslogic-fontconfig-sys-6.0.1/build.rs:8:48:
  called `Result::unwrap()` on an `Err` value: "\npkg-config exited with status code 1\n>
  PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 pkg-config --libs --cflags
  fontconfig\n\npkg-config output:\n  Package fontconfig was not found in the pkg-config
  search path.\n  Perhaps you should add the directory containing `fontconfig.pc'\n  to the
  PKG_CONFIG_PATH environment variable\n  Package 'fontconfig' not found\n\nThe system
  library `fontconfig` required by crate `yeslogic-fontconfig-sys` was not found.\nThe file
  `fontconfig.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must
  contain its parent directory.\nThe PKG_CONFIG_PATH environment variable is not set.\n"
```

Slint 1.19.0 (`backend-winit` + `renderer-software`) additionally probes
`wayland-client.pc` and the x11 / x11-xcb pkg-config modules through winit, so
those dev packages are needed on the runner too. This was purely a missing
system-dependency problem on the CI host — the local Arch host already had the
headers and both gates were green there.

## The change (single file, `.github/workflows/ci.yml`, +6 / -1)

Only `.github/workflows/ci.yml` changed (commit `dee5c9e`, 1 file, 6 insertions,
1 deletion). The "Install QA system tools" `apt-get install` line gained these
packages, appended to the existing filesystem/QEMU/OVMF/GRUB list:

```
pkg-config libfontconfig1-dev libxkbcommon-dev libwayland-dev \
libxcb1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

The OVMF symlink block added in S27-T3 was left intact; it maps Ubuntu's
`/usr/share/OVMF/OVMF_{CODE,VARS}_4M.fd` to the Arch-style
`/usr/share/edk2/x64/OVMF_{CODE,VARS}.4m.fd` names the UEFI harness hard-codes,
so Tier 2 UEFI boots on `ubuntu-latest` instead of skipping.

**`libwim-dev` was deliberately NOT added.** `wimlib-sys` already builds
gracefully without the FFI library on this host, and installing it would change
the link behaviour of `furus` and disturb the committed size baseline. No
source, `Cargo.toml`, `xtask` or size-baseline file was touched.

## Constraints honoured

* **No gate relaxation.** No `#[ignore]`, no weakened assertion, no
  `allow(warnings)`, no `unsafe` and no `FONTCONFIG_NO_PKG_CONFIG` /
  `RUST_FONTCONFIG_DLOPEN` escape hatch was introduced. The missing libraries
  were installed instead of worked around.
* **No size-gate loosening.** `size-baseline.json` was not edited. The size gate
  checks growth only: the only delta larger than the 4 KiB allowance is a
  *shrink* (`furus`), and the handoff constraints forbid loosening size gates.
* **No skipped QA.** Every suite that ran on the host also ran on CI; the sole
  `SKIP` remains `tier1/pipeline-loop`, which needs `--privileged` by documented
  default and is not a regression from this change.
* **No Ubuntu-specific xtask fix was needed.** The root cause was the runner's
  missing packages, not `xtask`; `xtask/src/main.rs` is unchanged.

## Local verification (this host, `main` @ `dee5c9e`)

With `PATH="$HOME/.cargo/bin:$PATH"`:

* `env -u APPDIR cargo xtask ci` → exit 0, `ci: all gates passed` (assets 86/86,
  parity fresh, size within baseline allowance, `cargo-deny` ok; `cargo-audit`
  SKIP because it is not installed on this host).
* `env -u APPDIR cargo xtask qa` → exit 0, `qa: all suites passed`. All Tier 1
  suites PASS (`tier1/mbr-gpt-partitions`, `tier1/fat32`, `tier1/exfat`,
  `tier1/ntfs`, `tier1/ext4`, `tier1/udf`, `tier1/uefi-ntfs-structure`,
  `tier1/windows-bcd`, `tier1/windows-system-hive`, `tier1/windows-boot-files`,
  `tier1/windows-bootloader`); `tier1/pipeline-loop` SKIPs (needs
  `--privileged`); Tier 2 `tier2/bios-smoke`, `tier2/bios-bootloaders` and
  `tier2/uefi-ntfs-ovmf` all PASS.

## CI verification (run 44816900917, head `dee5c9e`)

GitHub Actions run **44816900917** is green: job `ci` passed in 11m57s, with
both `Run xtask ci` and `Run xtask qa` succeeding on `ubuntu-latest`. URL:
https://github.com/justhosi/furus/actions/runs/44816900917

* **QA gate:** `qa: all suites passed`. Tier 1 PASS for
  `mbr-gpt-partitions`, `fat32`, `exfat`, `ntfs`, `ext4`, `udf`,
  `uefi-ntfs-structure`, `windows-bcd`, `windows-system-hive`,
  `windows-boot-files`, `windows-bootloader`; `SKIP tier1/pipeline-loop:
  loop-device / throughput tests need --privileged`. Tier 2 PASS for
  `bios-smoke`, `bios-bootloaders` and `uefi-ntfs-ovmf` — the last one boots
  only because the OVMF shim made the 4M firmware visible at the Arch paths.
* **Size gate** (`cargo xtask ci`, `size: within committed baseline allowance,
  all budgets OK`):

  | Binary | CI bytes | Baseline bytes | Delta |
  |---|---|---|---|
  | `furus` | 1,805,736 | 1,810,152 | −4,416 (shrink) |
  | `furus-gui` | 12,774,672 | 12,774,280 | +392 |
  | `furus-helper` | 1,406,568 | 1,406,296 | +272 |

  All three are inside budget and inside the 4 KiB growth allowance. The only
  delta above that allowance is a shrink, so there is no reason to rewrite
  `size-baseline.json`; refreshing the baseline in a CI-dependency fix would
  weaken the very gate this slice set out to verify.

## Residual risks / gotchas

* The apt package names and OVMF install paths are Ubuntu-specific; a future
  runner image that renames them could reintroduce the failure or make Tier 2
  UEFI SKIP instead of boot. The workflow guards the OVMF shim with an
  existence check, so a missing firmware file degrades to a SKIP, never a
  false pass.
* `cargo-audit` is absent on the local host and is reported as SKIP, not pass;
  CI installs it and runs it as part of `xtask ci`.
* The live window and a real system bus remain unverified in this environment
  (no display / system bus); S28 changes nothing about that.

## Status

* S28 is complete: the code fix (`dee5c9e`) is on `main` and pushed, both CI
  gates are green on run 44816900917, and this handoff plus the README and
  TECHNICAL.md notes close out the documentation. No further action remains.
