# S33 — Post-release hygiene — SLICE 2 HANDOFF

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, current HEAD
`8c1ef69` (S33.1 committed). `cargo`/`rustc` live in `~/.cargo/bin`; prefix every cargo command
with `export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S33 handoff. It is updated as each slice lands.
Per-slice records may be added alongside it as historical notes.

## Status: Slices 1-2/9 complete and verified; nothing committed or pushed by this subagent

The three local commits `e4fc6e6`, `3416f1c` and `8c1ef69` (S33.1, on top of
pushed `da44823`) are untouched. No reset/rebase/amend/push/tag was performed.
`v0.1.1` already exists as a published tag; S33 does not create or move tags.

Guardrails still in force: preserve `unsafe_code = "deny"` in `Cargo.toml` and
all crate-level `#![forbid(unsafe_code)]`; no new `.unwrap()`/`.expect()` in
production code; do not rename `furus-linux`, `org.furuslinux.*`,
`/run/furus-linux`, or the `$XDG_*_HOME/furus-linux` paths.

## Overall S33 slice plan (1/9 .. 9/9)

The plan below combines the slice IDs handed to the coder with the release-hygiene
items enumerated in the S33 CHANGELOG entry. The parent session owns the
authoritative scope for slices whose exact file lists were not passed to this
subagent; those rows are marked *parent-defined* and must be confirmed before
work begins on them.

| Slice | Scope | Status |
|---|---|---|
| 1/9 | Unify workspace/package version 0.1.0 → 0.1.1 (Cargo.toml, Cargo.lock, version tests, packaging defaults, CHANGELOG, README artifact names) | **Complete, verified** |
| 2/9 | Standardize user-facing display/package metadata (`Furus` / `furus`): desktop `Name`, metainfo `<name>` + description, Arch `pkgname` + license dir, release verification path, packaging README, README Arch artifact examples (includes the prefix deferred out of slice 1, item 8) | **Complete, verified** |
| 3/9 | SIGINT via `sigaction` with explicit `SA_RESTART` | Pending — parent-defined |
| 4/9 | Portable OVMF firmware discovery | Pending — parent-defined |
| 5/9 | Module and test-layout refactor | Pending — parent-defined |
| 6/9 | Remaining S33 release hygiene | Pending — parent-defined |
| 7/9 | Remaining S33 release hygiene | Pending — parent-defined |
| 8/9 | Remaining S33 release hygiene | Pending — parent-defined |
| 9/9 | Remaining S33 release hygiene / final docs + handoff | Pending — parent-defined |

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

## What remains

Slices 3/9 through 9/9 per the plan table. Before starting any of them, get the
exact scope from the parent session (the plan rows for 3/9–9/9 were not supplied
to this subagent). Keep the no-commit / no-push / no-tag rule until the user
explicitly authorizes publication.
