# S33 — Post-release hygiene — FINAL HANDOFF (slice 9/9 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, current code/docs HEAD
`1760c08` (`docs: record S33 release hygiene and refactors`); this final handoff
is committed immediately after it. `cargo`/`rustc` live in `~/.cargo/bin`; prefix every cargo command
with `export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S33 handoff. It is updated as each slice lands.
Per-slice records may be added alongside it as historical notes.

## Status: ALL slices 1-9/9 complete and verified, committed locally; nothing pushed

All S33 work is committed locally on top of pushed `da44823`: `8c1ef69`
(S33.1), `6ce1a51` (S33.2), `cf10532` (S33.3), `191621a` (S33.4), `b06a3d3`
(handoff through slice 4), `48aaae5` (S33.5 Part A), `9e5361b` (handoff
through slice 5), `53a1a91` (S33.5 Part B CLI split), `86736cb` (handoff
through slice 6), `8e9ae92` (S33.5 Part B exfat volume split), `e020669`
(handoff through slice 7), `127bbc0` (S33.5 Part B xtask split), `d727a51`
(handoff through slice 8), `1760c08` (final full gate + README/TECHNICAL docs),
plus this final handoff commit, and the two S32 documentation commits
`e4fc6e6` and `3416f1c` which the user chose to keep local. No
reset/rebase/amend/push/tag was performed. The published tag `v0.1.1` exists as
tag object `4c6e4a6` pointing at commit `f763fdc`; S33 does not create or move
tags. **The user has not authorized publishing any of these commits — v0.1.1 is
ready for manual sign-off and Publisher tagging, but nothing may be pushed or
tagged until that explicit permission is given.**

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
| 7/9 | Part B: split `crates/furus-core/src/fs/exfat/volume.rs` into `volume/{mod,format,fat,io,tests}.rs` | **Complete, verified** — `8e9ae92` |
| 8/9 | Part B: split `xtask/src/main.rs` into `main`, `util`, `assets`, `parity`, `size`, `packaging`, `dist`, `contract`, `ci`, `qa` modules | **Complete, verified** — `127bbc0` |
| 9/9 | Final full gate, README slice table row, `TECHNICAL.md` S33 section, final handoff | **Complete, verified** — `1760c08` (docs/gates) + final handoff commit |

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

## Slice 7/9 — what changed (commit `8e9ae92`)

Split the 4344-line `crates/furus-core/src/fs/exfat/volume.rs` into a `volume/`
directory of five files:

- `mod.rs` (535 lines) — module docs, imports, `DirInfo` / private
  `DirContent` / `Level` / `FileTarget` / `GrowthPlan` / `Snapshot` /
  `Exfat<V>`, constants, `bitmap_entry_image`, `open` / `geometry` / `flush`,
  `mod format; mod fat; mod io;`, and
  `#[cfg(test)] #[path = "tests.rs"] mod tests;`.
- `format.rs` (35) — the `Exfat::format` entrypoint.
- `fat.rs` (198) — cluster allocation / free accounting and FAT-chain
  traversal: `allocate`, `release`, `free_bytes`, `fat_entry`,
  `set_fat_entry`, `set_fat_entry_ledgered`, `snapshot`, `restore`,
  `read_clusters`, `allocate_in_place`, `patch_percent_in_use`.
- `io.rs` (1613) — remaining `Exfat` methods plus the free helpers
  `read_whole`, `zero_cluster`, `slot_image`, `live_label_slot`,
  `fresh_label_slot`, `deleted_label_image`, `parent_text`.
- `tests.rs` (1979) — the former inline test body, de-indented one level, no
  wrapper.

`crates/furus-core/src/fs/exfat/mod.rs` is unchanged (`pub mod volume;` at
line 41, `pub use volume::DirInfo; pub use volume::Exfat;` at 49–50). Public
API unchanged; no new plain `pub`. Structural edits only: an alias
`use crate::fs::exfat::format as fmt;` in `mod.rs` (forced by the new
`mod format;` name collision) with three `format::ENTRY_BYTES` →
`fmt::ENTRY_BYTES` qualifications; narrow `use` additions; `pub(super)` on
fourteen cross-submodule items. No test, assertion, error message, disk bytes,
unsafe site or production `.unwrap()` changed. Diff stat: 6 files, 4360
insertions / 4344 deletions (net +16 structural lines).

## Verification (Slice 7/9 — coder and independent reviewer)

- `cargo fmt --all -- --check` → **clean** after one `cargo fmt --all`
  (only in-scope files touched).
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (unchanged); `cargo test --workspace` → **1883 passed, 0 failed,
  29 ignored**.
- `cargo xtask ci` → **all gates passed**; size gate green with no baseline
  refresh. Only the documented `cargo-audit` not-installed skip and
  pre-existing duplicate-lock warnings.
- `cargo xtask qa` → **all suites passed**; only the documented
  `tier1/pipeline-loop ... need --privileged` skip; `tier2/uefi-ntfs-ovmf`
  PASS.
- Preservation proof: reviewer extracted 52 production functions and 58 test
  items from both `git show HEAD:...volume.rs` and the new files; all bodies
  identical modulo visibility keywords, the `fmt::` alias, import/use lines
  and rustfmt reflow from de-indentation. All **39 tests** in identical
  order with unchanged names and assertions. Zero new `unsafe`, zero new
  production `.unwrap()`.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p furus-core --no-deps` → **exit 101**,
  but this is pre-existing: reviewer built a detached worktree at `86736cb`
  and both trees emit exactly **226 `error:` lines** with **identical error
  message multisets** (13 volume-related errors are the same messages,
  merely relocated). No new doc errors were introduced; fixing the 185
  crate-wide intra-doc link errors is out of scope for this pure refactor.
- `git diff --check` clean; `git add -A` staged exactly the six in-scope
  files. Working tree clean after commit.

## Slice 8/9 — what changed (commit `127bbc0`)

Split the 3181-line `xtask/src/main.rs` (2476 production / 705 test lines) into
task submodules. `main.rs` is now 177 lines and retains the crate docs,
`#![forbid(unsafe_code)]`, the `mod` declarations, `print_usage()` and the CLI
dispatch. New files: `assets.rs`, `ci.rs`, `contract.rs`, `dist.rs`,
`packaging.rs`, `parity.rs`, `size.rs`, `util.rs`, `qa.rs`, plus per-module
`tests.rs` siblings for assets, contract, dist, packaging, parity, qa and size.

The S33.4 OVMF work was preserved exactly: the five ordered `OVMF_PAIRS`,
`ovmf_present`, `parse_qa_options`, `cmd_qa`, `first_existing_pair`, both
`FURUS_OVMF_CODE` / `FURUS_OVMF_VARS` env overrides, and the
`firmware_discovery_only_accepts_real_pairs` test (now in `qa/tests.rs`).
No CLI flag, output string, exit code, JSON schema or error message changed.
Visibility widened only where cross-module access required `pub(crate)`; no new
plain `pub`, no new unsafe, no new production `.unwrap()`, no new dependency.
Diff stat: 17 files, 3162 insertions / 3024 deletions (net +138 structural
lines).

## Verification (Slice 8/9 — coder and independent reviewer)

- `cargo fmt --all -- --check` → **clean**.
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p xtask --no-deps` → **exit 0**.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (unchanged); `cargo test --workspace` → **1883 passed, 0 failed,
  29 ignored**. The 31 xtask leaf test names are an identical multiset (only
  the module-path prefix changed).
- `cargo xtask ci` → **all gates passed**; size gate green with no baseline
  refresh. Only the documented `cargo-audit` not-installed skip and
  pre-existing duplicate-lock warnings.
- `cargo xtask qa` → **all suites passed** with real QEMU boots
  (`PASS tier2/bios-bootloaders`, `PASS tier2/uefi-ntfs-ovmf`); only the
  documented `tier1/pipeline-loop ... need --privileged` skip.
- CLI byte-equality: reviewer built the pre-change HEAD (`e020669`) in a
  detached worktree and compared eight cases (`--help`, `bogus`, no args,
  `parity --regenerate --check`, `size --bogus`, `assets`, `--version`,
  `dist --target`) — **identical** in exit code, stdout and stderr.
  `print_usage()` and `main()` were byte-identical against
  `git show HEAD:xtask/src/main.rs`.
- Function multiset 104 = 104, zero added/removed; body-level normalized
  comparison found only two rustfmt whitespace diffs (`assert!( ` →
  `assert!(` and `temp_dir() .join` → `temp_dir().join`). `.unwrap()` count
  identical (91 = 91), all in test code or `#[cfg(test)]` helpers.
- `git diff --cached --check` clean; `git add -A` staged exactly the 17
  in-scope files; working tree clean after commit.

## Slice 9/9 — final gate and documentation (commit `1760c08`)

This slice changed documentation only; no production code, CLI, JSON schema,
exit code, test or dependency changed. Two files:

- `README.md` (`1 +`) — one S33 row added immediately after the S31 row in the
  `### Slice completion (S21–S29)` table. The heading and all existing rows are
  untouched. The row records version 0.1.1, the 1912-test floor, green
  `ci`/`qa`/`dist` gates and the fact that S33 creates no new tag and pushes
  nothing.
- `TECHNICAL.md` (`125 +`) — a new `## S33 — Release hygiene, portability and
  module split` section appended at EOF, documenting S33.1–S33.5 with all eight
  change commits (`8c1ef69`, `6ce1a51`, `cf10532`, `191621a`, `48aaae5`,
  `53a1a91`, `8e9ae92`, `127bbc0`), the invariants, test-count history, no size
  drift, full verification, and the post-release no-tag/no-push stance.

The reviewer corrected three factual errors in the draft before committing:
(1) the local host has only Arch-layout firmware — `/usr/share/OVMF/OVMF_*_4M.fd`
are compatibility symlinks back into `/usr/share/edk2/x64/`, not a second
install, so only the first (Arch 4M) pair is exercised end-to-end; (2) only 7
of the 9 xtask submodules have a sibling `tests.rs` (`util.rs` keeps tests
inline, `ci.rs` has none), not all nine; (3) `4c6e4a6` is the annotated tag
object for `v0.1.1`, which points at commit `f763fdc`, not the commit itself.

## Verification (Slice 9/9 — coder and independent reviewer)

- `cargo fmt --all -- --check` → **exit 0**.
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**.
- `cargo test --workspace` → **1883 passed, 0 failed, 29 ignored = 1912**.
  Full coder log at `/tmp/opencode/s33-test-full.log`.
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1912** (floor unchanged from S33.4 onward; baseline 1910 before S33,
  1911 after the S33.3 SIGINT test).
- `cargo xtask ci` → **`ci: all gates passed`**; only the pre-existing
  `cargo-audit` not-installed skip and duplicate-zbus lock warnings.
- `cargo xtask qa` → **`qa: all suites passed`**; only the documented
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged` skip;
  real `PASS tier2/bios-bootloaders` and `PASS tier2/uefi-ntfs-ovmf`.
- `cargo xtask dist --out-dir /tmp/opencode/s33-dist` (reviewer re-ran with
  `/tmp/opencode/s33-dist-review`) → **exit 0**. Artifact
  `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz`, **7,905,723 B**, SHA256
  `17e163783eceae1135ac77cf754165ebfdc83efac172c8457601ae24578e080b`;
  `sha256sum -c SHA256SUMS` → **OK** in both directories. `.deb` is skipped
  only because `dpkg-deb` is not installed (environmental).
- `size-baseline.json` unchanged: furus **1,810,504 B** (budget 3,000,000),
  furus-helper **1,406,392 B** (2,500,000), furus-gui **12,806,408 B**
  (14,000,000). No S33 size drift, so no `--write-baseline` was needed.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p furus-core --no-deps` still reports
  **226 pre-existing errors** (reviewer re-confirmed on the current tree);
  these are unchanged from the pre-refactor tree and explicitly out of scope.
  `cargo doc -p xtask --no-deps` is clean.
- `git diff --check` → **clean**; only `README.md` and `TECHNICAL.md` were
  staged in `1760c08`; working tree clean afterwards.

## Final state — ready for manual sign-off, NOT published

- S33 is complete: 1/9 version, 2/9 naming, 3/9 SIGINT, 4/9 OVMF portability,
  5/9 test extraction, 6/9 CLI split, 7/9 exfat volume split, 8/9 xtask split,
  9/9 final gate and docs. Every commit carries `Reviewed-by: reviewer`.
- All S33 commits are **local only**. `origin/main` is still `da44823`; local
  `main` also carries the two S32 doc commits `e4fc6e6` and `3416f1c` that the
  user explicitly chose to keep local. Do not include them in any publication
  without asking again.
- Tag `v0.1.1` already exists (tag object `4c6e4a6` → commit `f763fdc`) and is
  published. S33 must **not** create, move, or force-update any tag.
- **No push and no tag without explicit user permission.** The next step is a
  human maintainer review of this handoff; if approved, ask the user, then
  hand to `publisher` for the branch push only if they authorize it.
- Gotchas for the next context: the only test skips are `cargo-audit` not
  installed and `tier1/pipeline-loop` needing `--privileged`; the `.deb` skip
  is due to missing `dpkg-deb`; the 226 furus-core rustdoc errors are
  pre-existing; the Ubuntu-only firmware layout was never exercised locally
  (only the pure selection test covers it) — CI now does.
