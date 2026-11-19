# HANDOFF — furus/ repo, S27-T2 (Slice 2/3)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. Base HEAD `75563b4`
(`feat(qa): implement S27-T1 xtask qa release gate`, Slice 1/3, committed).
S27-T1 is complete and committed; **S27-T2 (this slice) is uncommitted in the
working tree**; S27-T3 (CI wiring) is the remaining slice. This file is
self-contained for a fresh context. **Nothing was committed or pushed by this
slice; do neither without explicit user permission.** `coder` never pushes.

## Slice map

| Slice | Content | State |
|---|---|---|
| S27-T1 | `cargo xtask qa` two-tier gate + 8 new `xtask` tests | committed at `75563b4` |
| S27-T2 | Completion markers + docs (this slice) | uncommitted in working tree |
| S27-T3 | Add `cargo xtask qa` to `.github/workflows/ci.yml` | remaining (not started) |

## What S27-T2 changed (this slice, uncommitted)

Only in-scope files were touched (`git status --short` must show these and
nothing else):

* `tools/parity.py` — **docstring/comment only**. Extended the module docstring
  to explain that the ledger covers analysed functions/thunks only, that S26
  (packaging) and S27 (QA gate) are therefore absent from it and are tracked in
  the README completion table, and to list the S21–S27 slice meanings. No
  `BY_MODULE`, `OVERRIDES` or generated-row change; parity.csv stays byte-stable.
* `README.md` — added a `### Slice completion (S21–S27)` matrix under Status,
  added a `### Automated QA gate (\`cargo xtask qa\`)` subsection under Tests
  (two tiers, SeaBIOS COM1 smoke, real BIOS/UEFI suites, timeouts/kill-reap,
  `SKIP` lines, flags, CI-wiring note), and updated the `xtask` layout bullet
  to mention `qa`.
* `TECHNICAL.md` — appended `## S27 — Automated QA gate` recording all T1–T3
  decisions and trade-offs, verification and known limitations. All prior
  S21–S26 content untouched.
* `HANDOFF.md` (this file) — rewritten from the stale S26 state.
* `docs/handoffs/HANDOFF-S27-slice-2.md` — new slice-level handoff.

Out of scope and deliberately untouched: `xtask/src/main.rs` and
`.github/workflows/ci.yml` (T1 and T3 respectively).

## Verification actually run (final, all passed)

From `/home/hosi/dev/REA-Rufus/furus`, with
`PATH="$HOME/.cargo/bin:$PATH"`:

* `cargo xtask parity --check` → exit 0; `parity: data/parity.csv is fresh
  (regeneration changes nothing)`, `2709 data rows`, all disposition counts and
  address sets match.
* `cargo test -p xtask` → `test result: ok. 29 passed; 0 failed; 0 ignored;
  0 measured; 0 filtered out`.
* `cargo fmt --all -- --check` → exit 0, clean.
* `env -u APPDIR PATH="$HOME/.cargo/bin:$PATH" cargo xtask qa` → exit 0,
  `qa: all suites passed`. 11 Tier 1 suites PASS; one explicit
  `SKIP  tier1/pipeline-loop: loop-device / throughput tests need --privileged`;
  Tier 2 `bios-smoke`, `bios-bootloaders` (3 passed, 1 ignored GRUB4DOS,
  29.63 s) and `uefi-ntfs-ovmf` (1 passed, 17.55 s) PASS. No `/tmp/furus-qa-bios-*`
  scratch left behind.

## Gotchas (do not regress)

* **`APPDIR` must be removed at spawn.** A stale AppImage `APPDIR` breaks
  asset lookup in the suites; `qa` removes it in both `run_suite` and
  `qemu_bios_smoke`. This shell currently has `APPDIR` unset, but `env -u
  APPDIR` is used in verification anyway to be safe.
* **Parity is byte-stable.** `data/parity.csv` is generated from
  `data/functions.csv` (2,709 rows). Never change `BY_MODULE`, `OVERRIDES` or
  generator logic to "represent" S26/S27; `cargo xtask parity --check` must
  stay at exit 0. Only comments/docstrings may change in parity.py.
* **QEMU + OVMF are present here**, so Tier 2 genuinely ran: `qemu-system-x86_64`,
  `grub-mkimage`, `mkntfs`, `ntfscp`, `unshare`, `ntfs-3g` and
  `/usr/share/edk2/x64/OVMF_CODE.4m.fd` + `OVMF_VARS.4m.fd`. Do not claim a
  skip where none occurred.
* **`dpkg-deb` and `cargo-audit` are absent** on this host; `.deb` generation and
  the audit gate are skipped by design and reported as such, never as passes.
* **No push without permission.** Do not commit or push this slice. Hand it to
  the reviewer first; publish only after the user explicitly authorises it.
* `cargo`/`rustc` 1.99.0 live in `~/.cargo/bin`, not the default PATH — prefix
  cargo commands with `PATH="$HOME/.cargo/bin:$PATH"`.

## Remaining work / exact next steps (Slice 3/3)

1. Hand S27-T2 to the `reviewer` subagent for structure + security review. If
   blockers are reported, send them back to `coder` and repeat; do not push.
2. Only after review sign-off, implement S27-T3: add `cargo xtask qa` as a CI
   gate in `.github/workflows/ci.yml` (this file was out of scope for T2). Run
   the workflow YAML check available on this host and confirm the gate is
   ordered sensibly with the existing gates.
3. Ask the user for explicit permission to publish via `notify-telegram` plus
   the `question` tool. Only after that permission may the `publisher` commit
   and push. `coder` must never push.

## Acceptance criteria still open

* `git status --short` shows only the five in-scope files above (no commit).
* All four verification commands in the section above exit 0 (already met in
  this tree; re-run after any further edit).
* S27-T3: `.github/workflows/ci.yml` runs `cargo xtask qa` with `APPDIR`
  removed and a generous timeout, and CI is green with it — **not yet done**.
* No change to `BY_MODULE` / `OVERRIDES` / `data/parity.csv`, no `unsafe`, and
  no new dependency introduced by this slice (met).
