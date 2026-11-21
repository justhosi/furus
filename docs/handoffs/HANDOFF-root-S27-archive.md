> **ARCHIVED S27 SNAPSHOT — superseded, do not follow as current state.**
> This is the historical root `HANDOFF.md` frozen at S27 (HEAD `fa4a0d7`); its
> "Nothing has been pushed" note is stale — S28/S29 and the release workflow
> are now on `main`. Current status lives in the README slice-completion matrix
> and the handoffs in `docs/handoffs/`. The body below is kept intact.

# HANDOFF — furus/ repo, S27 COMPLETE (final state)

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`, HEAD `fa4a0d7`
(`ci(qa): install QA tools and run xtask qa on push and PR`). All three S27
slices are implemented, reviewed and **committed locally — nothing has been
pushed**. This file is self-contained for a fresh context.

## Slice map (all complete)

| Slice | Content | State |
|---|---|---|
| S27-T1 | `cargo xtask qa` two-tier gate + 8 `xtask` tests | committed `75563b4` |
| S27-T2 | Completion markers + docs (README, TECHNICAL, handoffs) | committed `e483305` |
| S27-T3 | CI wiring in `.github/workflows/ci.yml` | committed `fa4a0d7` |
| Final | Bring handoffs to completed state (this update) | working tree only |

Local commit log (newest first):

* `fa4a0d7 ci(qa): install QA tools and run xtask qa on push and PR`
* `e483305 docs(qa): document S21-S27 completion and automated QA gate`
* `75563b4 feat(qa): implement S27-T1 xtask qa release gate`

## Final acceptance verification (this host; branch `main`, HEAD `fa4a0d7`)

All commands run with `PATH="$HOME/.cargo/bin:$PATH"`; cargo/rustc 1.99.0 live
in `~/.cargo/bin`, not the default PATH.

* `cargo xtask qa` → exit 0. **14 PASS**, **1 explicit SKIP**
  (`tier1/pipeline-loop` needs `--privileged`); all Tier 2 PASS including
  `tier2/uefi-ntfs-ovmf`. No orphan QEMU processes after the run.
* `cargo xtask parity --check` → exit 0; `data/parity.csv` fresh, **2,709 rows**.
* `cargo xtask dist` → exit 0; produced `tar.gz` + `SHA256SUMS`; `.deb` skipped
  (`dpkg-deb` absent).
* `cargo xtask ci` → exit 0; `cargo-audit` skipped (not installed).

All four gates are green. No heavy build is needed to re-verify documentation.

## CI wiring (S27-T3, committed at `fa4a0d7`)

`.github/workflows/ci.yml` now:

* triggers on **push** and **pull_request**;
* installs `dosfstools`, `ntfs-3g`, `e2fsprogs`, `udftools`, `exfatprogs`,
  `mtools`, `qemu-system-x86`, `ovmf`, `grub-common`, `grub-pc-bin`;
* shims Ubuntu OVMF `_4M.fd` firmware files to the Arch-style `.4m.fd` paths
  the UEFI Tier 2 test hard-codes (only when the Ubuntu files are present);
* runs `cargo xtask ci` and then `cargo xtask qa`.

See `docs/handoffs/HANDOFF-S27-slice-3.md` for slice-level detail, the full
verification record and residual risks.

## Gotchas (do not regress)

* **Stale `APPDIR` must be removed at child spawn** — `xtask` does this in both
  suite runners; a leftover AppImage variable breaks asset lookup.
* **Parity byte-stability.** `data/parity.csv` (2,709 rows) is generated from
  `data/functions.csv`. Do not change `BY_MODULE`, `OVERRIDES` or generator
  logic to "represent" S26/S27; `cargo xtask parity --check` must stay exit 0.
* **QEMU + OVMF are present on this host**, so Tier 2 genuinely ran. Absent
  tooling yields an explicit SKIP unless `--require-qemu` is passed.
* **`--privileged`** enables loop/mount extras; those were not exercised on
  this non-root host (the one `tier1/pipeline-loop` SKIP is expected).
* **BIOS smoke is SeaBIOS-specific** (`FURUS-QA-OK` on COM1); other firmware
  could fail the smoke without a product regression.
* **No real GitHub runner** was available to exercise the `apt-get install`
  step or the OVMF symlink shim; CI green-on-host is verified, runner behavior
  is not.
* **`cargo-audit` and `dpkg-deb` are absent locally**; audit and `.deb` build
  are reported as SKIP, never as passes.
* **No push without permission.** Nothing has been pushed. Do not invoke the
  `publisher` subagent, commit-to-remote or push without the user's explicit
  permission. `coder` never pushes.

## Remaining step / exact next steps

1. Ask the user for **explicit permission to publish/push** (via
   `notify-telegram` plus the `question` tool). Nothing has been pushed.
2. Only after that permission may the `publisher` push. Without it, stop here.

## Acceptance criteria status

* All S27 slices implemented, reviewed and committed locally — **met**.
* Final verification (`qa`, `parity --check`, `dist`, `ci`) exit 0 — **met**.
* No change to `BY_MODULE` / `OVERRIDES` / `data/parity.csv`, no `unsafe`, no
  new dependency — **met**.
* Push/publish — **not done; requires explicit user permission**.
