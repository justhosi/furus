# S30 — Release workflow / A12 dormancy / v0.1.0 readiness — FINAL HANDOFF (4/4 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc 1.99.0 lives
in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the **final, authoritative** S30 handoff. It supersedes the slice
records `HANDOFF-S30-slice-1.md`, `HANDOFF-S30-slice-2.md` and
`HANDOFF-S30-slice-3.md`, which remain on disk as historical notes — their
"DONE (not committed, not pushed)" lines were accurate when written and are
stale now (see Gotchas). All four slices are complete and locally verified. S30
changes no runtime behaviour, no wire format, no dependency and no binary size.

## Status: all four slices complete

| Slice | Commit | Scope |
|---|---|---|
| 1/4 | `eff1b70` | NEW `.github/workflows/release.yml`: `v*` tag push or manual dispatch with required `tag` input; read-only `build` job mirrors `ci.yml` (pinned actions, Rust 1.99.0, rustfmt/clippy, cargo-deny 0.20.2, cargo-audit 0.22.2, full apt incl. S28 headers + OVMF shim, plus `dpkg`) and runs `ci` → `qa` → `dist`, uploading `target/dist/`; separate `release` job (the only `contents: write` job) flattens `*.tar.gz` / `*.deb` / `SHA256SUMS`, runs `sha256sum -c SHA256SUMS`, then `gh release create` with the built-in token. |
| 2/4 | `3d49f33` | `check_updates` / `update_channel` declared dormant schema-compatibility no-ops in `README.md` and `crates/rufus-core/src/config.rs` doc comments (behaviour, types, defaults, serde and tests untouched). Stale root `HANDOFF.md` archived to `docs/handoffs/HANDOFF-root-S27-archive.md`; `packaging/README.md` link repointed. A12 stays **proposed**; zero telemetry/network code. |
| 3/4 | `6aa51b5` | NEW `CHANGELOG.md` (v0.1.0) and NEW `docs/RELEASE-CHECKLIST.md` with pre-tag automated gates and physical USB / real-hardware acceptance as a **manual maintainer sign-off** (not CI-verified). |
| 4/4 | this documentation commit (HEAD at S30 close) | `TECHNICAL.md` S30 wrap-up (release workflow, dist/SHA256SUMS, conditional `.deb`, dormant A12, verification, unchanged sizes) and this final handoff. No source, `Cargo.toml`, CI, `size-baseline.json`, `DECISIONS.md`, `README.md`, `CHANGELOG.md`, release checklist or slice 1–3 file touched. |

Nothing is pushed. Reviewer and publisher own the commit and push; **no tag is
pushed as part of this slice**.

## What landed (detail lives in the per-slice handoffs)

* **Slice 1 — release automation.** Two-job workflow with least privilege:
  top-level `permissions: contents: read`; `build` reads only, runs all untrusted
  work (`cargo` builds/tests, tool installs, QA suites) and uploads
  `target/dist/` as one pinned artifact; `release` (`needs: build`) is the only
  job granted `contents: write`, and does only download → flatten → checksum →
  publish. A compromised build step or dependency therefore cannot mint a
  release. Triggers: `push` on tags `v*` and `workflow_dispatch` with a required
  string `tag` (on a manual run `github.ref_name` is a branch, so the operator
  names the tag). `gh release create <tag> --title <tag> --generate-notes` uses
  the preinstalled `gh` and `GH_TOKEN: ${{ github.token }}`, avoiding a
  third-party release action and extra secrets. Action pins are full SHAs
  (checkout/toolchain inherited from `ci.yml`; upload/download resolved via
  `gh api` on 2026-11-21).
* **Slice 2 — A12 documentation.** The two config fields are persisted and
  round-tripped for schema compatibility but never read: no update check, no
  HTTP client and no background network call exist in the tree. Decision A12
  ("telemetry: none; network only on explicit user action") remains **proposed**.
  `data/parity.csv`'s `net` row is a ledger assignment, not a live feature. The
  root S27 handoff was archived rather than deleted and its dangling
  `packaging/README.md` reference repointed; the different Windows-To-Go
  `docs/handoffs/HANDOFF.md` was not touched.
* **Slice 3 — release docs.** `CHANGELOG.md` records v0.1.0 capabilities (native
  FAT32/exFAT; NTFS/ext/UDF via external tools; MBR/GPT; UEFI + Legacy BIOS
  Windows To Go; Slint GUI; privileged helper over D-Bus with pkexec; CLI +
  proto; `xtask dist`/`qa`; tag-triggered release workflow), with no release
  date asserted. `docs/RELEASE-CHECKLIST.md` covers the pre-tag `ci`/`qa`/`dist`
  gates, `sha256sum -c` and tarball/`.deb` content inspection, then five manual
  hardware items (GUI + hotplug on a real desktop, Linux hybrid ISO boot,
  Windows 11 installer boot, Windows To Go boot with `SanPolicy=4`, failure
  recording). CI covers only virtual/synthetic suites.
* **Slice 4 — wrap-up.** `TECHNICAL.md` gained an S30 section written for a
  reader with no prior context, and this file is the single close-out record.

## Verification (exact commands and results)

Run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`. No privileged
host step, reboot, network action, tag push or release publish was used.

* `cargo xtask ci` → **exit 0, `ci: all gates passed`**. `==> fmt`, `==> clippy`
  clean; `==> test` all workspace suites green (0 failed, e.g. `1317 passed;
  0 failed; 6 ignored` in the core suite); `==> assets --check` `86 entries, 86
  files verified`; `==> parity --check` `2709 data rows`; `==> contract --check`
  green; `==> size` `within committed baseline allowance, all budgets OK`
  (`rufus: 1810152 / 3000000`, `rufus-helper: 1406296 / 2500000`, `rufus-gui:
  12774280 / 14000000`); `==> cargo-deny` `advisories ok, bans ok, licenses ok,
  sources ok`; `SKIP (not installed): cargo-audit`. Non-fatal
  `warning[duplicate]` lines from `Cargo.lock` appeared during the deny step.
* `cargo xtask qa` → **exit 0, `qa: all suites passed`**. Tier 1 PASS:
  `tier1/mbr-gpt-partitions`, `tier1/fat32`, `tier1/exfat`, `tier1/ntfs`,
  `tier1/ext4`, `tier1/udf`, `tier1/uefi-ntfs-structure`, `tier1/windows-bcd`,
  `tier1/windows-system-hive`, `tier1/windows-boot-files`,
  `tier1/windows-bootloader`; documented SKIP:
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged`.
  Tier 2 PASS: `tier2/bios-smoke`, `tier2/bios-bootloaders` (3 passed / 1 ignored
  GRUB4DOS, 29.61 s), `tier2/uefi-ntfs-ovmf` (1 passed, 17.76 s).
* `cargo xtask dist` → **exit 0**. Output directory:
  `target/dist/x86_64-unknown-linux-gnu/`. Tarball produced:
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz` (staging tree at
  `target/dist-staging/x86_64-unknown-linux-gnu/`). No `.deb` locally —
  `skip .deb: dpkg-deb not available`. `SHA256SUMS` contained one line,
  `<64-hex digest>  rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz` (two spaces,
  bare filename, no path component); run from the dist directory,
  `sha256sum -c SHA256SUMS` printed
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz: OK` (exit 0).
* `cargo fmt --all -- --check` → **exit 0**, clean.
* `git diff --check` → clean (no output, exit 0). After this docs edit,
  `git status --short` shows **only the two in-scope paths**:
  `M TECHNICAL.md` and `?? docs/handoffs/HANDOFF-S30.md`.

Binary sizes are byte-for-byte identical to `size-baseline.json`; S30 adds no
release binary. The release workflow was **not** executed locally — it needs a
GitHub runner and a real `v*` tag — and no hardware acceptance was performed.

## Acceptance criteria status

All met. Slice 1 has two least-privilege jobs, correct triggers/dispatch input,
the mirrored pinned toolchain and QA setup with `dpkg`, dist-only artifacts,
checksum verification before publish and `gh release create` with the built-in
token. Slice 2 leaves the A12 fields dormant with zero telemetry/network code
and no dangling handoff link. Slice 3 provides the v0.1.0 changelog and the
pre-tag/hardware checklist with manual sign-off. Slice 4 wraps up `TECHNICAL.md`
and this handoff. `ci`, `qa`, `dist`, `fmt` and whitespace/status checks all pass
as recorded above; only `TECHNICAL.md` and the new `HANDOFF-S30.md` are changed
by this slice.

## Gotchas

* **`.deb` skip is local-only.** `cargo xtask dist` emits a `.deb` only when
  `dpkg-deb` is on PATH; on this host it is absent, so the skip is expected and
  `dist` still exits 0. The release workflow installs `dpkg` so `ubuntu-latest`
  really builds the `.deb`. If that apt entry is removed, the release job's
  `*.deb` glob/publish would fail even though local `dist` keeps passing.
* **`cargo-audit` SKIP.** Not installed here; `cargo xtask ci` reports
  `SKIP (not installed)` rather than a pass. Pre-existing and expected, not a
  failure.
* **Duplicate-crate warnings.** `cargo-deny` prints non-fatal
  `warning[duplicate]` lines from `Cargo.lock` (zbus 5/6, thiserror 1/2, toml,
  windows-sys, …); unchanged from earlier slices, not introduced by S30.
* **QA `tier1/pipeline-loop` SKIP.** Loop-device/throughput suites need
  `--privileged`; their skip is the documented, accepted outcome on this host.
* **Release workflow not exercised locally.** No `v*` tag was pushed and no
  runner ran `release.yml`; `gh release create`, the checksum gate in the
  release job and the upload/download round trip are verified only by code
  review plus the local `sha256sum -c` proof, not by a live release.
* **Hardware validation is manual.** GUI/hotplug and UEFI/Legacy BIOS boots of
  Linux, Windows installer and Windows To Go are maintainer sign-off items in
  `docs/RELEASE-CHECKLIST.md`; no CI job performed them. Do not claim them as
  verified here.
* **Single default triple.** `cargo xtask dist` with no `--target` builds only
  the host triple, so there is one `SHA256SUMS` and flattening into `release/`
  is unambiguous. If multi-triple dist is added later, the flatten step must
  concatenate/merge the `SHA256SUMS` files instead of `cp`-ing colliding names.
* **Stale historical lines.** The three `HANDOFF-S30-slice-*.md` files still say
  "not committed, not pushed", accurate when written but stale now; they are
  left untouched as slice records. This file is the authoritative final state.
* **No out-of-scope edits.** `README.md`, `CHANGELOG.md`,
  `docs/RELEASE-CHECKLIST.md`, Rust sources, Cargo manifests,
  `.github/workflows/`, `size-baseline.json`, `DECISIONS.md` and the existing
  slice handoffs were not touched by slice 4.

## Remaining steps

1. Reviewer reviews this slice and commits it (fill the pending docs-commit hash
   in the status table if the project convention requires it). Do not push.
2. With the user's explicit permission, publisher pushes **`main` only — NO
   tag**. Pushing a `v*` tag here would trigger the release workflow prematurely.
3. Confirm the GitHub Actions run on that push is green (CI installs the native
   build headers and runs both `xtask ci` and `xtask qa`).
4. Only after the hardware acceptance in `docs/RELEASE-CHECKLIST.md` is signed
   off, the maintainer tags and pushes the tag, which triggers `release.yml`:

   ```
   git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0
   ```

   Then watch the `release` job finish and confirm the tarball, `.deb` and
   `SHA256SUMS` appear on the generated GitHub release.
5. No privileged host steps, reboots or network actions are required to verify
   S30 locally.
