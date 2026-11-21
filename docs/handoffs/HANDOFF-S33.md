# S33 — Post-release hygiene — SLICE 6 HANDOFF

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, current HEAD
`53a1a91` (S33.5 Part B CLI split committed). `cargo`/`rustc` live in `~/.cargo/bin`; prefix every cargo command
with `export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S33 handoff. It is updated as each slice lands.
Per-slice records may be added alongside it as historical notes.

## Status: Slices 1-6/9 complete and verified, committed locally; nothing pushed

All S33 work is committed locally on top of pushed `da44823`: `8c1ef69`
(S33.1), `6ce1a51` (S33.2), `cf10532` (S33.3), `191621a` (S33.4), `b06a3d3`
(handoff through slice 4), `48aaae5` (S33.5 Part A), `9e5361b` (handoff
through slice 5), `53a1a91` (S33.5 Part B CLI split), plus the two S32
documentation commits `e4fc6e6` and `3416f1c` which the user chose to keep
local. No reset/rebase/amend/push/tag was performed. `v0.1.1` already exists
as a published tag; S33 does not create or move tags. The user has not
authorized publishing any of these commits.

Guardrails still in force: preserve `unsafe_code = "deny"` in `Cargo.toml` and
all crate-level `#![forbid(unsafe_code)]`; no new `.unwrap()`/`.expect()` in
production code; do not rename `furus-linux`, `org.furuslinux.*`,
`/run/furus-linux`, or the `$XDG_*_HOME/furus-linux` paths.

## Overall S33 slice plan (1/9 .. 9/9)

The plan below is the authoritative scope owned by the parent session. Slices
5-8 are pure refactors and may be split further; the `N/M` tags are restated as
that happens.

| Slice | Scope | Status |
|---|---|---|
| 1/9 | Unify workspace/package version 0.1.0 → 0.1.1 (Cargo.toml, Cargo.lock, version tests, packaging defaults, CHANGELOG, README artifact names) | **Complete, verified** — `8c1ef69` |
| 2/9 | Standardize user-facing display/package metadata (`Furus` / `furus`): desktop `Name`, metainfo `<name>` + description, Arch `pkgname` + license dir, release verification path, packaging README, README Arch artifact examples | **Complete, verified** — `6ce1a51` |
| 3/9 | SIGINT via `sigaction` with explicit `SA_RESTART` | **Complete, verified** — `cf10532` |
| 4/9 | Portable paired OVMF firmware discovery with env overrides, xtask QA parity, removal of the Ubuntu CI symlink shims | **Complete, verified** — `191621a` |
| 5/9 | Part A: extract inline `#[cfg(test)] mod tests` from `pipeline/mod.rs`, `furus-helper/src/dbus.rs`, `furus-gui/src/main.rs` into sibling test files | **Complete, verified** — `48aaae5` |
| 6/9 | Part B: split `crates/furus-cli/src/main.rs` into `main`, `cli`, `output`, `commands` modules | **Complete, verified** — `53a1a91` |
| 7/9 | Part B: split `crates/furus-core/src/fs/exfat/volume.rs` into `volume/{mod,format,fat,io,tests}.rs` | Pending |
| 8/9 | Part B: split `xtask/src/main.rs` into `main`, `util`, `assets`, `parity`, `size`, `packaging`, `dist`, `contract`, `ci`, `qa` modules | Pending |
| 9/9 | Final full gate, README slice table row, `TECHNICAL.md` S33 section, final handoff | Pending |

## Slice 1/9 — what changed

Version unified from `0.1.0` to `0.1.1` everywhere it is a live default; version
assertions now derive from `env!("CARGO_PKG_VERSION")` so future bumps cannot
desync tests. Exact files:

- `Cargo.toml` — `[workspace.package] version = "0.1.1"`.
- `Cargo.lock` — all 8 workspace packages bumped to `0.1.1` by `cargo check --workspace`.
- `crates/furus-core/src/version.rs` — doc example `0.1.1`; both unit assertions use `CARGO_PKG_VERSION`.
- `crates/furus-core/src/lib.rs` — unit assertion uses `CARGO_PKG_VERSION`.
- `crates/furus-cli/tests/cli.rs` — `version_human_and_json` output and JSON assertions use `CARGO_PKG_VERSION`.
- `packaging/deb/control` — `Version: 0.1.1`.
- `packaging/rpm/furus.spec` — example command and `furus_version` default `0.1.1`; historical `%changelog` line 81 left at `0.1.0-1`.
- `packaging/arch/PKGBUILD` — example and `pkgver` default `0.1.1`.
- `CHANGELOG.md` — header workspace version `0.1.1`; new `## [0.1.1]` section with the moved dual-architecture bullet under `### Added` and four `### Changed` hygiene entries; `## [0.1.0]` kept as baseline with only that one misplaced bullet removed; `### Notes` unchanged.
- `README.md` — six artifact-name examples `0.1.1`; the `furus-linux-` Arch prefix intentionally kept for slice 2.
- `docs/handoffs/HANDOFF-S33.md` — this file (created).

`cargo fmt --all` was applied after the first CI fmt failure; it touched only
the two test files above.

## Verification (Slice 1/9 — exact commands, all run from repo root)

- `cargo check --workspace` → **pass**; all workspace packages compiled as `v0.1.1`.
- `cargo test -p furus-core version` → **pass** (3 version tests: 2 `version::tests::*`, 1 `tests::version_is_pinned_workspace_version`).
- `cargo test -p furus-cli --test cli version_human_and_json` → **pass** (1 passed, 55 filtered).
- `cargo test --workspace` → **pass**: 1881 passed, 0 failed, 29 ignored across 30 result lines = **1910 baseline tests**.
- `cargo xtask ci` → **pass** after rustfmt ("ci: all gates passed"); pre-existing `SKIP (not installed): cargo-audit` and duplicate-`zbus` warnings are not failures. First run failed only on the fmt gate and was fixed and re-run.
- `cargo xtask qa` → **pass** ("qa: all suites passed"); only the documented `tier1/pipeline-loop: loop-device / throughput tests need --privileged` skip.
- `git diff --check` → **clean**.
- `git grep '0\.1\.0' -- Cargo.toml packaging/ CHANGELOG.md` → only the allowed historical `## [0.1.0]` heading and the rpm `%changelog` `0.1.0-1` line; no stale live defaults.

### `0.1.0` audit of `crates/ xtask/`

- Changed: the 6 version assertions/doc examples in `furus-cli/tests/cli.rs`, `furus-core/src/lib.rs`, `furus-core/src/version.rs` — each asserted or documented the *current crate version*, so now use `CARGO_PKG_VERSION`.
- Kept: `crates/furus-proto/src/lib.rs:112` doc example `"furus-linux/0.1.0 (<git hash>)"` and `:493` fixture `created_by: "furus-linux/0.1.0 (test)"`. These deliberately test arbitrary opaque plan strings, not the live version; changing them would weaken fixture coverage.

## Slice 2/9 — what changed

User-facing display name standardized to `Furus` and the Arch package name to
`furus`, without touching any runtime identifier (`org.furuslinux.*`,
`/run/furus-linux`, `$XDG_*_HOME/furus-linux`) or the `furus-linux` crate name.
Exact files:

- `packaging/org.furuslinux.Furus.desktop` — line 4 `Name=furus-linux` → `Name=Furus`.
- `packaging/org.furuslinux.Furus.metainfo.xml` — `<name>` → `Furus` and the `<p>` description opener → `Furus creates bootable USB drives…`. `<id>`, `<launchable>`, `<icon>` and all other identifiers unchanged.
- `packaging/arch/PKGBUILD` — `pkgname=furus-linux` → `pkgname=furus`; license destination `${pkgdir}/usr/share/licenses/furus-linux/LICENSES.md` → `.../furus/LICENSES.md`.
- `.github/workflows/release.yml` — line 289 verification path `usr/share/licenses/furus-linux/LICENSES.md` → `usr/share/licenses/furus/LICENSES.md`. The `package-arch` and `publish` jobs use generic `*.pkg.tar.zst` globs; no hardcoded `furus-linux-` prefix existed, so none were changed.
- `packaging/README.md` — install-path table license path → `/usr/share/licenses/furus/LICENSES.md`.
- `README.md` — the two S33.1-deferred Arch artifact examples → `furus-0.1.1-1-x86_64.pkg.tar.zst` / `furus-0.1.1-1-aarch64.pkg.tar.zst`. Crate-description hits (lines 127/297/315–323/453–455) left untouched as explicit non-goals.
- `docs/handoffs/HANDOFF-S33.md` — this file.

No xtask edit was needed: `validate_metainfo`, `validate_desktop`,
`validate_arch_pkgbuild` and `cmd_contract` contain no hardcoded `furus-linux`
display/package-name expectation (the only xtask hits are `furus-linux` test
target names in `cmd_qa`, left alone). No check was weakened.

## Verification (Slice 2/9 — exact commands, all run from repo root)

- `cargo xtask ci` → **pass** ("ci: all gates passed", exit 0). Includes fmt, clippy, test, assets/parity checks, packaging validators, the contract and the size gate. Only pre-existing warnings (duplicate `zbus`/`thiserror`/`toml`/etc. lock entries, `SKIP (not installed): cargo-audit`) appear; none are failures.
- `cargo xtask dist --out-dir /tmp/opencode/s33-slice2-dist` → **pass** (exit 0). Wrote `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz` and `SHA256SUMS`. `dpkg-deb` is not installed in this environment, so the `.deb` step was skipped (`skip .deb: dpkg-deb not available`) — environmental, not a code failure. In that directory `sha256sum -c SHA256SUMS` → `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz: OK` (exit 0).
- Arch PKGBUILD naming: sourcing `packaging/arch/PKGBUILD` with no override yields `furus-0.1.1-1-<arch>.pkg.tar.zst`. A real `makepkg -f --noconfirm` build (tarball staged in `/tmp/opencode/s33-slice2-archbuild`) produced `furus-0.1.1-1-x86_64.pkg.tar.zst`; the package contains `usr/share/licenses/furus/LICENSES.md` and no `usr/share/licenses/furus-linux/...` entry, matching the new release.yml verification path.
- `cargo test --workspace` → **pass** (exit 0): 1881 passed, 0 failed, 29 ignored across 30 result lines = **1910 baseline tests**.
- `git diff --check` → **clean**.
- `grep -rn "furus-linux" packaging/ README.md .github/workflows/release.yml` → remaining hits are crate descriptions only (`README.md` lines 127/297/315–323/453–455); no display name, package name, license path or artifact example remains.

## Slice 3/9 — what changed

Portable SIGINT installation via `libc::sigaction` with an explicit
`SA_RESTART`, replacing the implementation-defined `libc::signal` call. Exactly
two files changed, both deliberately left uncommitted:

- `crates/furus-linux/src/signal.rs` —
  - Module charter (lines 3–5) now names the `libc::sigaction` call as the
    single unsafe operation, still under the one documented
    `#[allow(unsafe_code)]` (no new unsafe site; crate-level
    `#![forbid(unsafe_code)]` and workspace `unsafe_code = "deny"` unchanged).
  - Delivery doc (lines 23–25) now states `sigaction` + `SA_RESTART`
    guarantees a Ctrl-C during a blocked device write restarts the syscall
    instead of `EINTR` on both glibc and musl, no longer relying on
    implementation-defined `signal()` semantics.
  - `install_handler()`: inside ONE `unsafe` block, zero-init a
    `libc::sigaction`, set `sa_sigaction` to
    `on_sigint as *const () as libc::sighandler_t`, set `sa_flags` to
    `libc::SA_RESTART`, call `libc::sigemptyset(&mut sa.sa_mask)` and
    `libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut())`; return
    `CoreError::invalid("could not install the SIGINT handler")` if either
    call returns non-zero, else `Ok(())`. The expanded `// SAFETY:` comment
    covers struct zero-init validity, the `sighandler_t = size_t (usize)`
    pointer round-trip and `extern "C" fn(c_int)` ABI (verified against the
    locked libc 0.2.191 sources), the empty mask, `SA_RESTART` portability on
    glibc and musl, and that installing twice reinstalls the same handler.
  - Added one hermetic test `install_is_idempotent_and_starts_uncancelled`
    asserting two `install()` calls both return `Ok(())` and the flag is
    clear afterwards; no real SIGINT is raised. The three prior tests are
    byte-for-byte unchanged.

Verification of field/type claims against the locked libc 0.2.191 sources
(`~/.cargo/registry/src/index.crates.io-.../libc-0.2.191`):
`sighandler_t = size_t = usize` (unix/mod.rs:21); `sigaction` fields
`sa_sigaction: sighandler_t`, `sa_mask: sigset_t`, `sa_flags: c_int`,
`sa_restorer: Option<extern "C" fn()>` (new/glibc/.../bits/sigaction.rs:8,
unix/linux_like/linux/musl/mod.rs:91); `SA_RESTART: c_int = 0x10000000` on
both glibc and musl; `sigemptyset(*mut sigset_t) -> c_int` and
`sigaction(c_int, *const sigaction, *mut sigaction) -> c_int`.

## Verification (Slice 3/9 — exact commands, all run from repo root)

- `cargo test -p furus-linux signal` → **pass** (4 signal tests, including
  the new `install_is_idempotent_and_starts_uncancelled`; 0 failed).
- `cargo clippy -p furus-linux --all-targets -- -D warnings` → **pass**, zero
  warnings.
- `git grep 'allow(unsafe_code)' crates/` → confirmed no new unsafe sites:
  the only *attribute* in `signal.rs` is the single pre-existing one on
  `install_handler()` (all other hits are doc comments or other crates'
  already-documented sites).
- `cargo test --workspace` → **pass**: 1882 passed, 0 failed, 29 ignored
  across all result lines = **1911 tests** (baseline **1910** → **1911**, the
  +1 being the new install test).
- `cargo xtask ci` → **pass** ("ci: all gates passed", exit 0); only the
  documented `SKIP (not installed): cargo-audit` and pre-existing duplicate
  `zbus`/`zbus_macros` lock warnings appear; none are failures.
- `cargo xtask qa` → **pass** ("qa: all suites passed", exit 0); only the
  documented `tier1/pipeline-loop: loop-device / throughput tests need
  --privileged` skip.
- `git diff --check` → **clean**.

## Slice 4/9 — what changed (commit `191621a`)

Portable, paired OVMF discovery replaced hardcoded Arch paths and removed the
Ubuntu-only CI symlink workaround. Exactly four files:

- `crates/furus-core/tests/uefi_ntfs_boot.rs` — removed `OVMF_CODE`/`OVMF_VARS`
  constants; added ordered `OVMF_PAIRS` (Arch 4M, Arch legacy, Ubuntu 4M,
  Ubuntu legacy, Fedora/RHEL), a pure `first_existing_pair` helper, and
  `resolve_ovmf_pair()` that honours `FURUS_OVMF_CODE` / `FURUS_OVMF_VARS`
  (both-or-neither, both must be real files, descriptive errors) and otherwise
  returns the first pair where BOTH members exist. The resolved pair is threaded
  through `skip_reason(scratch, &ovmf)` and `boot(disk, work, deadline, &pair)`:
  the vars copy uses `ovmf.1` and QEMU's pflash code path uses `ovmf.0`.
  Added pure test `ovmf_pair_discovery_never_mixes_layouts` (no env mutation,
  parallel-safe).
- `xtask/src/main.rs` — the same five pairs in the same order, the same pure
  pair helper, and `ovmf_present()` with the same env-override rules, so QA can
  never disagree with the boot test. `first_existing_file` was removed; its old
  test was replaced by `firmware_discovery_only_accepts_real_pairs`, proving
  mixed code/vars across layouts are rejected. `cmd_qa` unchanged.
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` — removed the
  entire `sudo ln -sf` shim blocks and their comments (lines 45-54 and 96-105).

## Verification (Slice 4/9 — all run by coder and independently by reviewer)

- `cargo fmt --all -- --check` → **pass**.
- `cargo clippy --workspace --all-targets -- -D warnings` → **pass**, zero warnings.
- `cargo test -p furus-core --test uefi_ntfs_boot -- --nocapture` → **2 passed,
  0 skipped**: a real QEMU boot printed `UEFI-NTFS-OK` and the negative control
  showed no marker. The host has both Arch 4M and Ubuntu 4M firmware, so the
  first (Arch 4M) pair was selected.
- `cargo xtask ci` → **pass** ("ci: all gates passed"); size gate green with no
  baseline refresh (no shipped binary changed). Only pre-existing
  `cargo-audit` not-installed skip and duplicate-`zbus` lock warnings.
- `cargo xtask qa` → **pass** ("qa: all suites passed");
  `tier2/uefi-ntfs-ovmf` **PASS** (no longer skipped). Only the pre-existing
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged` skip.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (baseline 1910 → 1911 after S33.3 → 1912 after the new pure uefi
  test; the xtask test replaced the old one).
- `git diff --check` → **clean**; only the four in-scope files changed. No
  hardcoded `OVMF_CODE`/`OVMF_VARS` constants and no `ln -sf` shims remain.
- Not exercised locally: a host with ONLY Ubuntu's `/usr/share/OVMF/OVMF_*_4M.fd`
  (pair 3 in the list, covered by the pure selection test) — CI now exercises it.

## Slice 5/9 — what changed (commit `48aaae5`)

Pure mechanical move of three inline test modules into sibling files, with the
module declarations left as `#[cfg(test)] #[path = "…"] mod tests;`:

- `crates/furus-core/src/pipeline/mod.rs` → new `pipeline/tests.rs` (4456 lines).
- `crates/furus-helper/src/dbus.rs` → new `dbus_tests.rs` (1018 lines).
- `crates/furus-gui/src/main.rs` → new `main_tests.rs` (501 lines).

Each new file holds the former module body de-indented by four spaces (no new
`mod tests` wrapper). Production prefixes are byte-identical to `HEAD`; only
the declaration was added. No test, assertion, helper, import, attribute or
name changed — rustfmt reflowed five lines in `pipeline/tests.rs` after the
de-indent and removed one trailing comma where `fn image_file(...)` params
collapsed to a single line; both are whitespace/syntax-only. `super::` paths
still resolve to the same parent module (compilation is proof). No visibility
widening, no new unsafe or production `.unwrap()`, no behavior change.

Diff stat: 6 files, 5981 insertions / 5985 deletions. No docs/handoff touched
by the coder; this section was added by the parent afterwards.

## Verification (Slice 5/9 — coder and independent reviewer)

- `cargo fmt --all -- --check` → **clean** after formatting (the first check
  flagged five line reflows in the new `tests.rs`; `cargo fmt --all` touched
  only the six in-scope files).
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**, no warnings.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (unchanged baseline).
- `cargo test --workspace` → **1883 passed, 0 failed, 29 ignored**.
- `cargo xtask ci` → **pass**; size gate green with no baseline refresh (no
  shipped binary changed). Only pre-existing `cargo-audit` not-installed skip
  and duplicate-lock warnings.
- `cargo xtask qa` → **pass**; `tier2/uefi-ntfs-ovmf` PASS; only the
  pre-existing `tier1/pipeline-loop ... need --privileged` skip.
- `git diff --check` → **clean**. Reviewer re-ran every gate and independently
  compared each extracted body with `git show HEAD:<path>` modulo de-indent.
- The coder used `git add -N` (intent-to-add) while inspecting; the reviewer
  replaced it with a normal `git add -A`, and the commit contains all three new
  files with full content.

## Slice 6/9 — what changed (commit `53a1a91`)

Split the 2130-line `crates/furus-cli/src/main.rs` into eight files while
preserving every behavior:

- `src/main.rs` (452 lines) — crate docs, `#![forbid(unsafe_code)]`, module
  declarations, `Exit`/`Fail`/`fail_from_plan`/`to_pretty`/`json_error`,
  `HostPaths`, `dispatch`, `main`.
- NEW `src/cli.rs` (347) — `Cli`, `Command`, the four parsers.
- NEW `src/output.rs` (432) — all JSON structs, `report_summary`,
  `verdict_json`, both reporters, `print_human_plan`, `human_*`, `describe_step`.
- NEW `src/commands/mod.rs` (754) — all 13 command/helper functions.
- NEW `src/main_tests.rs` (74), `src/cli/tests.rs` (36),
  `src/commands/tests.rs` (110), `src/output/tests.rs` (19) — the original
  eight tests plus the `derivation_plan` helper, distributed to the module
  they exercise.

Visibility widened only to `pub(crate)` where a sibling module needs access;
no new plain `pub`, no new unsafe, no production `.unwrap()`, no dependency or
CLI/exit-code/JSON/error-message change. Three doc-only deviations (two
intra-doc link retargets plus `` `furus-core::hash` `` → `` `furus_core::hash` ``
in prose). Diff stat: 8 files, 1791 insertions / 1697 deletions.

## Verification (Slice 6/9 — coder and independent reviewer)

- `cargo fmt --all -- --check` → **clean** after one `cargo fmt --all`
  (which touched only the eight in-scope files).
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p furus-cli --no-deps` → **exit 0**.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (unchanged).
- `cargo test --workspace` → **1883 passed, 0 failed, 29 ignored**.
- `cargo xtask ci` / `cargo xtask qa` → **pass**; size gate green with no
  baseline refresh; only the documented `cargo-audit` and privileged-loop
  skips. `tier2/uefi-ntfs-ovmf` PASS.
- CLI behavior: `main --help` and all seven subcommand `--help` outputs
  byte-identical to the pre-change HEAD (reviewer built HEAD in a temporary
  worktree and compared); `version --json` matches apart from the build-time
  `git_hash` (`9e5361b` vs `3416f1c`).
- Reviewer independently compared 52 moved top-level items against `HEAD`
  (51/51 non-test items verbatim modulo imports/`pub(crate)`/reflow; the test
  module verified separately, all 8 tests identical).
- `git diff --check` clean; `git add -A` staged exactly eight files.

## What remains

Slices 7/9 through 9/9 per the plan table. Each must stay behaviour-preserving:
no public signature/CLI/JSON/error-message changes, no visibility widening, no
new unsafe or production `.unwrap()`, and the test count must not drop below
1912. Keep the no-push / no-tag rule until the user explicitly authorizes
publication. Slices 6/9 and earlier are committed locally (not pushed).
