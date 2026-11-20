# S29 — GUI / IPC verification — FINAL HANDOFF (4/4 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc 1.99.0 lives
in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the **final** S29 handoff. The earlier slice records remain as historical
notes in `HANDOFF-S29-slice-2.md` and `HANDOFF-S29-slice-3.md` (their
"not committed" status lines are stale — see Gotchas). All four slices are
complete and locally verified. S29 changes no runtime behaviour and no wire
format and adds no dependency.

## Status: all four slices complete

| Slice | Commit | Scope |
|---|---|---|
| 1/4 | `571ca4b` | Single-source D-Bus/polkit/packaging identifiers in `rufus-proto::service`; `xtask contract --check` scans packaging literals and is wired into `cmd_ci` between parity and size. |
| 2/4 | `c3fb0b2` | Offscreen Slint software-renderer smoke test (`crates/rufus-gui/tests/render_smoke.rs`). |
| 3/4 | `450c8fe` | Real compiled-helper JSONL / run-state wire test (`crates/rufus-gui/tests/helper_wire.rs`). |
| 4/4 | this documentation commit (HEAD at S29 close) | `README.md`, `TECHNICAL.md`, this handoff; no source, Cargo.toml, CI, `size-baseline.json` or slice 1–3 file touched. |

Nothing is pushed. Reviewer/publisher own commit and push.

## What landed (detail lives in the per-slice handoffs)

* **Slice 1.** Ten `pub const &str` identifiers (`BUS_NAME`, `OBJECT_PATH`,
  `INTERFACE_NAME`, `POLKIT_ACTION`, four `ERROR_*`, `HELPER_BIN_PATH`,
  `HELPER_DBUS_ARG`) in `crates/rufus-proto/src/service.rs`, re-exported from
  the crate root; GUI and helper import them (helper keeps thin aliases).
  `cmd_contract` reads this file directly — `xtask` has no `rufus-proto`
  dependency — validates packaging literals and the zbus interface macro, and
  rejects the legacy `org.rufus.` namespace and old helper path.
  `packaging/README.md` is skipped by the negative scan because it discusses
  that rejected namespace in prose. The const spelling
  `pub const NAME: &str = "...";` must stay stable for the scanner.
* **Slice 2.** `render_smoke.rs` installs a minimal platform with one shared
  `Rc<MinimalSoftwareWindow>` (320x240), instantiates `ui/main.slint`, turns on
  all four overlays at once plus four hash checkboxes and a four-element digest
  model, renders one non-blank frame and asserts a draw happened. It uses
  `#![deny(unsafe_code)]`, not `forbid`: `include_modules!()` generates vtables
  with a hardcoded `#[allow(unsafe_code)]` (E0453 under `forbid`). No
  `i-slint-backend-testing` dependency, no display server.
* **Slice 3.** `helper_wire.rs` builds a `GuiState` fixture, `Run::start` /
  `Run::confirm`, locates the compiled helper via `current_exe()` (one-shot
  `cargo build` fallback), probes `unshare -Ur`, then runs
  `PkexecTransport::with_command("/bin/sh", ["-c", script])`. Consumes the real
  `EventStream`, asserts exactly one `Done` with
  `Outcome::Refused { code: "not_a_block_device" }` (only the real validator
  emits it; a transport-synthesised `Done` uses `"exit"`), feeds it through
  `Run::apply` to `Finished(Refused(...))` with
  `configuration_locked() == false`. No device, write, pkexec, polkit, bus,
  async runtime, sleep or new dependency.

## Verification (exact commands and results)

Run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`.

* `cargo xtask ci` → **exit 0, `ci: all gates passed`**.
  `==> fmt`, `==> clippy` clean; `==> test` all workspace binaries green
  (including both new GUI tests); `==> assets --check` `86 entries, 86 files
  verified`; `==> parity --check` `2,709 data rows`, address sets match;
  `==> contract --check` `contract: all identifiers match the single source of
  truth`; `==> size` `rufus: 1810152 / 3000000`, `rufus-helper: 1406296 /
  2500000`, `rufus-gui: 12774280 / 14000000`, `size: within committed baseline
  allowance, all budgets OK`; `==> cargo-deny` `advisories ok, bans ok, licenses
  ok, sources ok`; `SKIP (not installed): cargo-audit`.
* `env -u APPDIR cargo xtask qa` → **exit 0, `qa: all suites passed`**.
  Tier 1 PASS: `tier1/mbr-gpt-partitions`, `tier1/fat32`, `tier1/exfat`,
  `tier1/ntfs`, `tier1/ext4`, `tier1/udf`, `tier1/uefi-ntfs-structure`,
  `tier1/windows-bcd`, `tier1/windows-system-hive`, `tier1/windows-boot-files`,
  `tier1/windows-bootloader`. Documented SKIP: `tier1/pipeline-loop: loop-device
  / throughput tests need --privileged`. Tier 2 PASS: `tier2/bios-smoke`,
  `tier2/bios-bootloaders` (3 passed / 1 ignored GRUB4DOS, 29.60 s),
  `tier2/uefi-ntfs-ovmf` (1 passed, 17.77 s).
* `cargo fmt --all -- --check` → **exit 0**, clean.
* `git status --short` → only the three in-scope documentation files modified
  (after this docs edit): `README.md`, `TECHNICAL.md`,
  `docs/handoffs/HANDOFF-S29.md`.

The binary sizes are byte-for-byte identical to `size-baseline.json`; the new
files are integration tests, not the release binaries the size gate measures.

## Acceptance criteria status

All met. Contract gate green in `ci`; offscreen render and real-helper wire
tests pass and run inside the workspace test gate; `qa` green with the
documented privileged-tier SKIP; sizes unchanged; docs (README status + GUI/IPC
verification section, TECHNICAL S29 section, this final handoff) complete;
only the three allowed files edited. No privileged host step, reboot or
network action was used.

## Gotchas

* **`shift` was deliberately removed.** The slice-3 prompt suggested
  `shift; exec unshare -Ur '<path>' "$@"`, but with `sh -c SCRIPT name arg...`
  POSIX puts `name` in `$0` and `$@` is already `--plan FILE --progress jsonl`;
  `shift` would drop `--plan`. The test uses no `shift` (reasoning recorded in
  the test). Point reviewers at the `sh -c` experiment in
  `HANDOFF-S29-slice-3.md`.
* **SKIP branch not exercised.** `unshare -Ur true` succeeds here, so the
  helper-wire test's SKIP path is untested; it skips cleanly where user
  namespaces are disabled.
* **`cargo build` fallback not exercised.** `target/debug/rufus-helper` was
  already present, so the one-shot build fallback did not run; it could be
  sensitive to the parent cargo's target-dir lock on a cold build — build the
  helper first if that ever bites, rather than changing the test.
* **`cargo-audit` SKIP.** Not installed on this host; xtask reports SKIP, never
  a pass. Pre-existing and expected.
* **Duplicate-crate warnings.** `cargo-deny` prints non-fatal
  `warning[duplicate]` lines (zbus 5/6, thiserror 1/2, toml, windows-sys, etc.);
  unchanged from S25 and not introduced by S29.
* **Const spelling is load-bearing** for the slice-1 scanner; keep
  `pub const NAME: &str = "...";` exact.
* **Stale historical lines.** `HANDOFF-S29-slice-2.md` and
  `HANDOFF-S29-slice-3.md` still say "DONE (not committed, not pushed)" —
  accurate when written, now stale. Left untouched intentionally as slice
  records; this file is the authoritative final state.
* No source, `Cargo.toml`, CI workflow, `size-baseline.json` or slice 1–3 file
  was edited in this slice.

## Remaining steps

1. Reviewer reviews this slice and commits it (fill the pending docs-commit
   hash in the table above). Do not push.
2. With the user's explicit permission, publisher pushes `main`.
3. Confirm the GitHub Actions run is green on push (CI installs the native
   build headers and runs both `xtask ci` and `xtask qa`).
4. No privileged host steps, reboots or network actions are required to verify
   S29 locally.
