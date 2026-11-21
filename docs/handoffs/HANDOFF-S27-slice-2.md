# S27 — Slice 2/3 handoff (completion markers + documentation)

State at the end of this slice: the S21–S27 completion matrix, the `cargo xtask
qa` documentation, the S27 technical-decisions record and both handoff files
are written in the working tree, uncommitted. S27-T1 (the gate itself) is
already committed at `75563b4`; S27-T3 (CI wiring in `.github/workflows/ci.yml`)
is the remaining slice. The coder touched only the five in-scope files below;
`xtask/src/main.rs` and `.github/workflows/ci.yml` were deliberately untouched.

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`. `cargo`/`rustc` 1.99.0
live in `~/.cargo/bin`; prefix cargo commands with
`PATH="$HOME/.cargo/bin:$PATH"`. Nothing was committed or pushed — do neither
without explicit user permission.

## What was done

- `tools/parity.py`: docstring-only edit. Documents that the ledger covers only
  analysed functions/thunks, so S26 (packaging) and S27 (QA gate) are absent
  from it and are tracked in the README completion table; lists the S21–S27
  slice meanings. `BY_MODULE`, `OVERRIDES` and the generator logic are unchanged.
- `README.md`: new `### Slice completion (S21–S27)` matrix under Status (names,
  scope and state for each slice, with S27 showing T1 committed / T2 this slice
  / T3 pending); new `### Automated QA gate (\`cargo xtask qa\`)` under Tests
  (Tier 1 unprivileged sparse-file suites, Tier 2 BIOS COM1 smoke plus real
  Syslinux/FreeDOS/GRUB2 and OVMF/UEFI:NTFS serial-marker suites, 120 s / 30 s
  deadlines with kill+reap, explicit `SKIP` lines, `--require-qemu` /
  `--privileged`, `APPDIR` removal, CI to run it in T3); the `xtask` layout
  bullet now mentions `qa`.
- `TECHNICAL.md`: appended `## S27 — Automated QA gate (\`cargo xtask qa\`)`
  with T1–T3 scope, data flow, and every decision/trade-off: reuse of existing
  suites (root cause is automation, not missing functionality), no
  `furus-core` dependency in `xtask`, the hand-assembled 512-byte MBR with a
  COM1 marker versus VGA capture, OVMF delegation to the existing
  `uefi_ntfs_boot` harness, strict deadline + `ChildGuard` kill/reap against
  CI hangs, `APPDIR` removal at spawn, parity ledger intentionally unchanged,
  flag semantics, verification record and known limitations.
- `HANDOFF.md` (root): rewritten from the stale S26 state to the S27-T2 state
  (base `75563b4`, slice map, verification, gotchas, exact next steps,
  acceptance criteria).
- This file: slice-level handoff.

## Key decisions / gotchas

- **Parity byte-stability is the hard constraint.** `data/parity.csv` has
  2,709 rows generated from `data/functions.csv`. No `BY_MODULE` / `OVERRIDES`
  / logic change; only the docstring moved. `cargo xtask parity --check` must
  report the file fresh and exit 0. Non-function slices are tracked in the
  README matrix, not in the ledger.
- **Factual slice descriptions.** S25's label follows the parity module map
  (`net` = HTTP update check/download), but the README states the truth: only
  `check_updates` / `update_channel` config fields exist, not a live
  update-check feature. S22 is described by what its handoffs actually shipped
  (wimlib strict-link, NTFS overhead reserve, dynamic locale/GUID fallback,
  regf property tests). S27 is marked T1 committed / T2 uncommitted / T3
  pending rather than "complete".
- **`APPDIR` must be removed at spawn** in both `run_suite` and
  `qemu_bios_smoke`; a stale AppImage variable breaks asset lookup. This shell
  has it unset, but verification still uses `env -u APPDIR`.
- **QEMU + OVMF are installed here** (`qemu-system-x86_64`, `grub-mkimage`,
  `mkntfs`, `ntfscp`, `unshare`, `ntfs-3g`, OVMF 4m code+vars), so Tier 2 ran
  for real; do not describe it as skipped. `dpkg-deb` and `cargo-audit` are
  absent and are reported as skipped, never as passes.
- **Host-specific BIOS smoke.** The 512-byte real-mode sector prints
  `FURUS-QA-OK` to COM1 under this host's SeaBIOS; a differently configured
  firmware could fail the smoke without a product regression. No root/loop
  suites were run (`--privileged` not passed); no fresh Windows BIOS boot or
  physical-stick boot is claimed.
- **No commit, no push.** Hand to reviewer, then publish only on explicit
  user permission. `coder` never pushes.

## Verification (final)

- `cargo xtask parity --check` → exit 0, `2,709 data rows`, fresh regeneration.
- `cargo test -p xtask` → `29 passed; 0 failed; 0 ignored; 0 measured;
  0 filtered out`.
- `cargo fmt --all -- --check` → exit 0, clean.
- `env -u APPDIR PATH="$HOME/.cargo/bin:$PATH" cargo xtask qa` → exit 0,
  `qa: all suites passed`; 11 Tier 1 PASS, one `SKIP tier1/pipeline-loop
  (needs --privileged)`, Tier 2 `bios-smoke`, `bios-bootloaders` and
  `uefi-ntfs-ovmf` PASS; no scratch dir left in `/tmp`.

## Status and next action

- **NOT committed or pushed.** Only the five in-scope files are modified.
- **Next action:** hand this slice to `reviewer`; after sign-off implement
  S27-T3 (add `cargo xtask qa` to `.github/workflows/ci.yml`), then ask the
  user for explicit permission before any publish/commit/push.
