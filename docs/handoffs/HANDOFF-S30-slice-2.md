# S30 — slice 2/4: A12 config-field clarification + stale root handoff archive

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`, base HEAD `eff1b70`
(`ci(release): add tag-triggered release workflow`). cargo/rustc 1.99.0 lives
in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the handoff after **slice 2/4** of S30. Slices are gated one at a time
(one command → reviewer → next command); do not batch them. Slice 1 added the
tag-triggered release workflow (`.github/workflows/release.yml`, now at HEAD).

## Slice 2/4 — status: DONE (not committed, not pushed)

### Command executed

Clarify that the `check_updates` / `update_channel` config fields are dormant
schema-compatibility no-ops under Decision A12, and archive the stale S27 root
handoff so no live `HANDOFF.md` reference dangles after the move.

### Exact changes (only these files)

1. **`README.md`** — added a short `#### Update-check fields are dormant (A12)`
   subsection directly after the slice-completion matrix (below the S25 row).
   It states the two fields exist only for schema compatibility, are dormant
   no-ops that are persisted/round-tripped but never acted on, that **no HTTP
   client and no background network call** exist in the tree, and that Decision
   A12 stays **proposed**. No other README text changed (the S25 row is intact).
2. **`crates/furus-core/src/config.rs`** — DOC COMMENTS ONLY on the two fields
   in `pub struct Config`: both now say "Dormant schema-compatibility field
   (Decision A12, still proposed)" and that no update-check/network code reads
   them so no check or network call happens because of them. Types, defaults
   (`check_updates: true`, `update_channel: UpdateChannel::Stable`), serde
   attributes and all tests are untouched; no behaviour change, no network code.
3. **`HANDOFF.md` → `docs/handoffs/HANDOFF-root-S27-archive.md`** via `git mv`
   (preserved as a rename, R100 apart from the banner). Added a 2–4 line banner
   at the top marking it an archived S27 snapshot (HEAD `fa4a0d7`), noting its
   "Nothing has been pushed" line is stale (S28/S29 + release workflow are on
   `main`), and pointing current status at the README slice matrix and
   `docs/handoffs/`. Body kept intact. `docs/handoffs/HANDOFF.md` (the different
   Windows-To-Go handoff) was NOT touched.
4. **`packaging/README.md`** — one reference fix at line 21: the dangling
   `HANDOFF.md` now points to the archived
   `docs/handoffs/HANDOFF-root-S27-archive.md`.
5. **NEW `docs/handoffs/HANDOFF-S30-slice-2.md`** — this file.

No `Cargo.toml`, workflow, `DECISIONS.md`, `TECHNICAL.md`, `CHANGELOG`, source
behaviour, `size-baseline.json` or other file was changed. A12 remains
`proposed`; the fields were not deleted (schema compatibility preserved).

### Verification (exact commands and results)

All run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`.

1. `cargo test -p furus-core --lib config` → **ok. 22 passed; 0 failed**
   (1301 filtered out; ~29.7s).
2. `cargo xtask ci` → **exit 0; `ci: all gates passed`**. Every gate green:
   `fmt`, `clippy` (`-D warnings`), workspace `test` (all suites 0 failed),
   `assets --check`, `parity --check`, `contract --check`, `size` →
   `size: within committed baseline allowance, all budgets OK` (sizes
   unchanged), `cargo-deny` → `advisories ok, bans ok, licenses ok, sources ok`.
   `cargo-audit` → `SKIP (not installed)` (pre-existing, not a failure).
3. `git diff --check` and `git diff --cached --check` → clean (no output).
4. `git status --short` → only the five in-scope paths; the root move appears
   as a rename `R  HANDOFF.md -> docs/handoffs/HANDOFF-root-S27-archive.md`.
5. Grep for `HANDOFF.md` across tracked text files → the only remaining live
   reference was the one in `packaging/README.md`, now repointed. All other
   mentions are historical descriptions inside archived/slice handoffs
   (`HANDOFF-S21-*.md`, `HANDOFF-S27-slice-*.md`,
   `HANDOFF-boot-c0000001.md`, `HANDOFF-bcd-subkey-shrink.md`, `TECHNICAL.md`)
   and need no change. No live link dangles.

No privileged step, reboot, network action, commit or push was used.

### Gotchas

- **A12 is still `proposed`.** The clarification documents it as proposed; do
  not flip its status in `DECISIONS.md`, and do not claim telemetry policy is
  approved. The fields must stay for schema compatibility — removing them would
  break persisted configs that contain them.
- **No network code exists.** Re-adding any HTTP client or background update
  check would break the A12 statement now in the README; the `net` row in
  `data/parity.csv` is a ledger assignment, not an implemented feature.
- **Two different handoffs.** `docs/handoffs/HANDOFF.md` is the Windows-To-Go
  handoff and must not be confused with the archived root snapshot at
  `docs/handoffs/HANDOFF-root-S27-archive.md`.
- **Archived body is intentionally stale.** Its "nothing pushed", HEAD
  `fa4a0d7` and S27 slice map are historical; the banner flags this, do not
  "correct" the body to current state.
- **cargo-audit SKIP** is pre-existing in this environment (tool not installed);
  `cargo xtask ci` treats it as a skip, not a failure.

### Remaining / next steps

1. Hand this slice to the reviewer; it is **not committed and not pushed**.
2. Slice 3/4 must be opened as its own gated command and reviewed separately —
   do not batch it with this slice.
3. If a later slice touches `README.md` or `config.rs`, preserve the dormant
   A12 wording and keep the `packaging/README.md` archive link valid.
