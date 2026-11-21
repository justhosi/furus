# S30 — slice 3/4: CHANGELOG + release checklist

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, base HEAD `3d49f33`.
cargo/rustc 1.99.0 lives in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the handoff after **slice 3/4** of S30 (release automation). Slices are
gated one at a time (one command → reviewer → next command); do not batch them.
Slice 1 added `.github/workflows/release.yml`; slice 2 documented the dormant
A12 config fields. Both are at HEAD.

## Slice 3/4 — status: DONE (not committed, not pushed)

### Command executed

Add the user-facing v0.1.0 changelog and the pre-tag/hardware release checklist.
Documentation only — no source, workflow, dependency or size-baseline changes.

### Exact changes (only these three files, all new)

1. **NEW `CHANGELOG.md`** (repo root) — short Keep-a-Changelog-style file with
   one `## [0.1.0]` section. It summarizes the capabilities actually present in
   the tree (native FAT32/exFAT; NTFS/ext/UDF via external tools; MBR/GPT; UEFI
   + Legacy BIOS Windows To Go; Slint GUI; privileged `rufus-helper` over D-Bus
   with a pkexec transport; `rufus` CLI + `rufus-proto`; `cargo xtask dist`/`qa`)
   and the release-workflow readiness from slice 1. Notes record the dormant A12
   config fields and that hardware acceptance is a manual maintainer sign-off.
   No release date or future promise is asserted.
2. **NEW `docs/RELEASE-CHECKLIST.md`** — procedural pre-tag and hardware-acceptance
   checklist. Before tagging: export PATH, `cargo xtask ci`, `cargo xtask qa`,
   `cargo xtask dist`, `sha256sum -c SHA256SUMS`, and inspect tarball/`.deb`
   contents with the expected `/usr/bin`, `/usr/libexec` and `/usr/share` layout.
   Hardware acceptance: launch `rufus-gui` on a real X11/Wayland desktop and
   confirm the device list populates and USB plug/unplug hotplug is reflected;
   flash a 32 GB Linux hybrid ISO via pkexec/D-Bus `rufus-helper` and boot it on
   real hardware (UEFI and Legacy BIOS where applicable); flash a Windows 11
   installer and a Windows To Go image to 32 GB USB and verify UEFI + Legacy
   BIOS boot on real hardware. A lead note states plainly that these need
   physical hardware, are the maintainer's manual sign-off, and that automated
   CI covers only virtual/synthetic suites. Commands use flagged placeholders
   (`<triple>`, `<version>`) with replacement instructions.
3. **NEW `docs/handoffs/HANDOFF-S30-slice-3.md`** — this file.

No other file was created or edited. `README.md`, `TECHNICAL.md`, `Cargo.toml`,
all Rust sources, `.github/workflows/*`, `size-baseline.json`, `DECISIONS.md`,
and the slice-1/slice-2 artifacts are untouched. Nothing was committed and
nothing was pushed.

### Sources consulted (read before writing, to avoid overclaiming)

- `README.md` — Status section (filesystem/partition/boot/helper facts), the
  S21–S29 slice-completion matrix, the A12 "dormant fields" subsection, Layout,
  Build, `cargo xtask dist` and `cargo xtask qa` sections.
- `TECHNICAL.md` — §1 crate roles, §2 Windows To Go architecture (GPT layout,
  wimlib, BCD for UEFI and BIOS, `SanPolicy=4`), and the verification notes that
  explicitly say no fresh SeaBIOS/Windows hardware boot was run here. This is
  why the checklist asks for those boots rather than claiming they are verified.
- `Cargo.toml` — workspace `version = "0.1.0"`.
- `docs/handoffs/HANDOFF-S30-slice-1.md`, `HANDOFF-S30-slice-2.md` — prior slice
  scope and conventions.
- `.github/workflows/release.yml` — exact release triggers and steps, so the
  changelog/checklist describe the workflow accurately.

### Verification (exact commands and results)

Run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`.

1. `cargo xtask ci` → **exit 0; `ci: all gates passed`**. Every gate green:
   `fmt`, `clippy` (`-D warnings`), workspace `test`, `assets --check`,
   `parity --check`, `contract --check`, `size` (within committed baseline
   allowance, all budgets OK — sizes unchanged), `cargo-deny` (`advisories ok,
   bans ok, licenses ok, sources ok`). `cargo-audit` → `SKIP (not installed)`
   (pre-existing in this environment, not a failure). Cargo emitted duplicate-crate
   warnings from `Cargo.lock` during the deny step; no errors.
2. `cargo xtask qa` → **exit 0; `qa: all suites passed`**. Suites:
   `PASS tier1/mbr-gpt-partitions`, `tier1/fat32`, `tier1/exfat`, `tier1/ntfs`,
   `tier1/ext4`, `tier1/udf`, `tier1/uefi-ntfs-structure`, `tier1/windows-bcd`,
   `tier1/windows-system-hive`, `tier1/windows-boot-files`,
   `tier1/windows-bootloader`; `SKIP tier1/pipeline-loop: loop-device /
   throughput tests need --privileged` (expected/accepted); Tier 2 `PASS
   tier2/bios-smoke`, `tier2/bios-bootloaders`, `tier2/uefi-ntfs-ovmf`.
3. `git diff --check` → clean (no output, exit 0).
4. `git status --short` → only the three in-scope new files:

   ```
   ?? CHANGELOG.md
   ?? docs/RELEASE-CHECKLIST.md
   ?? docs/handoffs/HANDOFF-S30-slice-3.md
   ```

No privileged step, reboot, network action, tag push, release publish, commit
or push was used. The release workflow was not executed locally (it needs a
GitHub tag/runner). No hardware acceptance was performed — the checklist
documents it for the maintainer.

### Gotchas

- **Do not overclaim hardware verification.** The repo implements UEFI and
  Legacy BIOS Windows To Go, but no real BIOS/Windows boot has been run in this
  environment (TECHNICAL.md states this). The checklist asks for that sign-off;
  the changelog describes it as manual, not as passing CI.
- **`.deb` is conditional.** `cargo xtask dist` only emits a `.deb` where
  `dpkg-deb` is installed; the checklist flags the skip rather than assuming the
  artifact exists. The release workflow installs `dpkg` so the runner does build
  it.
- **Single default triple.** `cargo xtask dist` with no `--target` builds the
  host triple, so `<triple>` in the checklist is the host target triple printed
  by the command.
- **A12 stays proposed.** The changelog calls the config fields dormant no-ops
  and does not claim telemetry or an update-check feature (no HTTP client or
  background network code exists).
- **`cargo-audit` SKIP is pre-existing** and treated as a skip, not a failure,
  by `cargo xtask ci`.

### Remaining / next steps

1. Hand this slice to the reviewer; it is **not committed and not pushed**.
2. Slice 4/4 must be opened as its own gated command and reviewed separately —
   do not batch it with this slice. It is expected to finalize/publish S30
   (publisher sign-off and the real tagged-release verification on GitHub,
   including the hardware acceptance in `docs/RELEASE-CHECKLIST.md`).
3. If a later edit adds a release date or version, update `CHANGELOG.md` only
   with a real, verified date — none is asserted here.
