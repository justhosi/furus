# S32 — Native XDG desktop portal file picker and UI polish — FINAL HANDOFF

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc live in
`~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S32 handoff. It supersedes the three per-slice
records (`HANDOFF-S32-slice-1.md`, `-slice-2.md`, `-slice-3.md`), which remain
on disk as historical notes.

## Status: implementation and verification complete; push pending permission

| Unit | Commit | Scope |
|---|---|---|
| Slice 1/4 | `fafb7a5` | New `crates/furus-gui/src/picker.rs` + `pub mod picker;` in lib.rs: portal `OpenFile`, zenity/kdialog fallback chain, pure helpers and 5 headless unit tests. |
| Slice 2/4 | `9f39890` | `main.rs`: guarded background-thread SELECT wiring via `slint::invoke_from_event_loop`, CLI positional image path with `args_os`, removal of the old synchronous picker. |
| Slice 3/4 | `780b27b` | `main.slint`: added `alignment: start;` to the parent `VerticalLayout` and removed `vertical-stretch: 1;` from the status `Text`. |
| fmt fix | `052aa4e` | `cargo fmt --all` applied to `picker.rs` (4 hunks), fixing the CI fmt gate missed in slice 1. |
| size baseline | `39e97ba` | `size-baseline.json` refreshed for the 32,128-byte `furus-gui` growth. |
| docs | this commit | `TECHNICAL.md` S32 section, this final handoff and the three per-slice handoffs. No source, manifest, workflow, fixture or baseline change. |

Nothing is pushed. Coder and reviewer never push; publication requires the
user's explicit permission and is owned by `publisher`.

## What landed

* **Picker module.** `picker.rs` owns image selection through
  `PickerOutcome { Selected, Cancelled, Unavailable }` and
  `pick_image_path() = resolve_chain(portal, fallbacks)`. The portal path
  subscribes to the `Response` signal before calling `OpenFile`, derives the
  request object path from the unique bus name, decodes `file://` URIs with
  strict `%XX`/UTF-8 handling, and uses `zbus::block_on` (zbus 6 has no
  `zbus::blocking`) on a background thread. Fallback happens only for
  `Unavailable`, never for `Cancelled`.
* **Main wiring.** SELECT dispatches to a named `furus-file-picker` thread
  guarded by an `AtomicBool`; results return through
  `slint::invoke_from_event_loop` and are rendered on the UI thread. The busy
  flag is released on every path. A positional CLI argument pre-selects and
  analyzes an image at startup, while `--version`/`--help`/`-h` remain
  genuinely headless fast paths.
* **UI polish.** The status `Text` no longer stretches into the blank gap
  above "Show log"; `alignment: start` parks spare height at the bottom of the
  layout without inflating buttons.

## Verification (exact commands and results)

Run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`.

* `cargo test -p furus-gui` → **pass** (91 lib + 14 bin + 1 helper_wire +
  1 offscreen `render_smoke`; 0 failures).
* `cargo clippy -p furus-gui --all-targets -- -D warnings` → **clean**.
* `cargo fmt --all -- --check` → **clean** (after `052aa4e`).
* `cargo xtask assets --check` → **pass** (86 entries, 86 files verified).
* `cargo xtask ci` → **all gates passed** (fmt, clippy, workspace test,
  assets, parity, contract, size). `SKIP (not installed): cargo-audit` is a
  pre-existing, reported skip, not a failure.
* `cargo xtask qa` → **all suites passed**. Only the documented
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged` skip.
* `size-baseline.json` → `furus` 1,810,504 B, `furus-helper` 1,406,392 B,
  `furus-gui` 12,806,408 B (budgets 3,000,000 / 2,500,000 / 14,000,000).
* Headless binary checks: `--version` → `furus-gui 0.1.0` exit 0; `--help` and
  `-h` exit 0; `--bogus` → unknown-option error + help exit 1; an `.iso` path
  reached `run_gui` (Winit reported no display), proving it was not misparsed.
* Reviewer verdicts: CLEAN for all five code/baseline commits, no blockers.

## Acceptance criteria status

All four S32 tasks are complete: portal primary with background-thread
dispatch (T1), pure unit tests for URI decoding/request path/fallback precedence
(T2), optional positional CLI path preserving headless flag fast paths (T3),
and the vertical-gap fix (T4). No `unsafe`, no async runtime, no heavy new
dependency, headless CI compatibility — all held.

## Gotchas

* **zbus 6 constraint.** The spec's `zbus::blocking` does not exist in the
  pinned zbus 6.2.0; `zbus::block_on` on a dedicated thread is the correct
  pattern and matches the existing D-Bus module.
* **Fmt gate.** Slice 1 was committed without rustfmt, so `cargo xtask ci`
  initially failed at `fmt`; fixed in `052aa4e`. Always run the CI gate after
  the final code commit, not just per-slice tests.
* **Size baseline drift.** The picker grew `furus-gui` by 32,128 bytes;
  `cargo xtask size --write-baseline` was required. The small `furus` (+352)
  and `furus-helper` (+96) changes are fresh-release-build variance, not S32
  source changes.
* **No visual confirmation on Hyprland.** The offscreen render smoke test
  proves the layout still compiles and renders; the actual absence of the gap
  on a tall tiling window is a manual maintainer check.
* **No end-to-end portal dialog in CI.** Only the pure logic, headless CLI and
  offscreen rendering were exercised. A real display session is needed to
  click SELECT against a live portal.
* **`cargo-audit` SKIP.** Not installed on this host; reported as a skip by
  `cargo xtask ci`, pre-existing and expected.

## Remaining steps

1. Ask the user for explicit permission to publish, using `notify-telegram`
   and the `question` tool (numbered options, one question).
2. Only with that permission, invoke `publisher` to push **`main` only — no
   tag**. Pushing a `v*` tag is a separate decision and would trigger the
   release workflow prematurely.
3. No privileged host steps, reboots or network actions are required to verify
   S32 locally.
