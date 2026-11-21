# Handoff — aarch64 / dual-architecture release (Slice 3/4 documentation)

## State

Repo: `furus`, branch `main`, HEAD `cc15dca`. Status: **workflow + test fix
committed and pushed; dry run green; documentation complete here, nothing
committed by this slice.**

- `.github/workflows/release.yml` and the exfat test normalization landed in
  `cc15dca` (commit message "test: normalize whitespace in exfat dump
  assertions"), already merged to `main` and pushed.
- `workflow_dispatch` dry run `44931040759` (`publish=false`) on `cc15dca`
  finished **success**: both native builds, all four package jobs (two per
  architecture), and `publish`'s download, flatten and checksum steps all
  passed. The final `gh release create` step was correctly skipped.
- The current public `v0.1.1` release still has the old five assets; it has
  **not** been replaced with the dual-arch assets. That is the final publishing
  step (below) and is out of scope here.

## Expected release assets (9)

Eight packages, two per architecture, plus one unified digest file:

| arch | artifacts |
| --- | --- |
| x86_64 | `furus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`, `furus-0.1.0-x86_64-unknown-linux-gnu.deb`, `furus-0.1.0-1.fc45.x86_64.rpm`, `furus-linux-0.1.0-1-x86_64.pkg.tar.zst` |
| aarch64 | `furus-0.1.0-aarch64-unknown-linux-gnu.tar.gz`, `furus-0.1.0-aarch64-unknown-linux-gnu.deb`, `furus-0.1.0-1.fc45.aarch64.rpm`, `furus-linux-0.1.0-1-aarch64.pkg.tar.zst` |

Plus `SHA256SUMS` with **eight lines** (one per package, bare filenames), all
verified OK by `sha256sum -c SHA256SUMS` in the publish job's dry run. The
release should therefore contain **9 assets**.

## Gotchas

- **Unofficial ARM Arch image**: official `archlinux:latest` is amd64-only, so
  the aarch64 `package-arch` lane uses
  `lfdevs/archlinux-ports:base-devel@sha256:a24c8b0151cdfcd678027eebba1d315f3c0d5433747c314b95e634a4492e280b`.
  It is a third-party port (publisher documents a drzee.net bootstrap signing
  key; packages target ARMv8.2-A+). The user explicitly accepted this. The
  **digest pin** is what bounds the trust — do not replace it with a tag.
- **x86-only size gate**: `xtask ci` (including the size-drift check against
  the host-specific `size-baseline.json`) runs only on the x86_64 lane. Both
  lanes run `xtask qa` and `xtask dist`; `dist` still enforces absolute release
  budgets on ARM.
- **QEMU skip**: the aarch64 lane skips the QEMU/OVMF Tier 2 boot tests; those
  remain covered only by the x86 lane. This is intentional, not a gap to fix.
- **exfat whitespace**: exfatprogs 1.2.2 pads `dump.exfat` fields with tabs on
  aarch64 vs spaces on x86_64; `cc15dca` normalizes whitespace before comparing
  so both pass without weakening the values checked.
- All action SHA pins are unchanged; no new dependency, no version bump.

## Remaining steps

1. Docs review of this slice (README release-assets section + S31 row,
   `TECHNICAL.md`, `DECISIONS.md` A3, `CHANGELOG.md`, this handoff). Reviewer
   checks structure and accuracy; no commit/push from this slice.
2. (Needs explicit user permission) Publisher replaces the `v0.1.1` release and
   tag so it carries the dual-arch artifacts, then verifies with
   `gh release view v0.1.1` that there are **9 assets** and that the downloaded
   `SHA256SUMS` (8 lines) matches all eight packages.
3. Keep the legacy handoffs under `docs/handoffs/` as historical records; they
   describe the earlier five-asset publication and are not edited here.
