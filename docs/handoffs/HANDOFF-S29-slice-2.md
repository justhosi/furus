# S29 — slice 2/4: headless offscreen Slint render smoke test

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`, base HEAD `571ca4b`.
cargo/rustc 1.99.0 lives in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This file is the handoff after **slice 2/4**. Slices are gated one at a time
(one command → reviewer → next command); do not batch them. Slice 1/4 is in
`HANDOFF-S29.md`.

## Slice 2/4 — status: DONE (not committed, not pushed)

### Command executed

Implement an unprivileged, headless offscreen Slint software-renderer smoke
test that instantiates `crates/furus-gui/ui/main.slint`, sets representative
state, renders at least one frame, and asserts no panic / no missing bindings.

### What changed

1. **NEW `crates/furus-gui/tests/render_smoke.rs`** — one `#[test]` integration
   test binary (a single test keeps the platform-install per process race-free).
   - Installs a minimal `Platform` (`TestPlatform`) whose
     `create_window_adapter` hands out one shared
     `Rc<MinimalSoftwareWindow>` built with `RepaintBufferType::ReusedBuffer`;
     `slint::platform::set_platform(...).expect(...)` runs before any component
     is created, then the window is sized 320x240 physical pixels.
   - `slint::include_modules!()` generates `MainWindow` from the already
     compiled `ui/main.slint` (build.rs/shlint-build output in the shared
     package `OUT_DIR`); `MainWindow::new()` is expected to succeed.
   - Sets representative scalar state plus every combo-model property, then
     sets **all four conditional overlays true at once** (`advanced-visible`,
     `log-open`, `confirm-visible`, `checksum-visible`) with the four hash
     checkboxes checked and a four-element `checksum-digests` model — this
     forces the `checksum-digests[0..3]` bindings and every hidden branch in
     `main.slint` to evaluate, which is where a missing binding would surface.
   - `ui.show()`, `update_timers_and_animations()`, `ui.window().request_redraw()`.
   - Renders into a fixed `vec![DrawnPixel(false); WIDTH*HEIGHT]` via
     `window.draw_if_needed(|renderer| renderer.render(&mut buffer, WIDTH))`.
     `DrawnPixel` is a small `TargetPixel` that records whether anything was
     blended/drawn (a blank frame stays all-`false`). Asserts (a) the
     `draw_if_needed` callback ran and (b) at least one pixel was drawn.
   - Ends with `ui.hide()`.
   - No display server, no root, no real block devices, no async runtime, no
     new dependencies. Only `slint` (an existing regular dependency) is used.

2. **NEW `docs/handoffs/HANDOFF-S29-slice-2.md`** — this file.

No other files were modified. `Cargo.toml` (workspace and crate),
`.github/workflows/ci.yml`, `size-baseline.json`, slice-1 files, and all
`#![forbid(unsafe_code)]` crate roots are untouched.

### Decisions / gotchas

- **`deny`, not `forbid`.** The new test binary expands
  `slint::include_modules!()`, whose generated code hardcodes
  `#[allow(unsafe_code)]` (`vtable-macro`'s `ItemTreeVTable_static!`). Under a
  crate-level `#![forbid(unsafe_code)]` that is the hard error **E0453**,
  exactly as documented in `src/main.rs`. The test therefore opens with
  `#![deny(unsafe_code)]` plus the same explanatory comment — the workspace
  `[lints] unsafe_code = "deny"` and `[lints] workspace = true` remain
  untouched. No `#[allow(unsafe_code)]` appears in any hand-written line.
- **No `i-slint-backend-testing` dependency, no `configure_test_fonts()`.**
  Slint 1.19's own harness uses that crate only for deterministic text metrics;
  bundled fonts are sufficient for a smoke test that asserts only "something
  was drawn", not exact colours or metrics.
- **Bool target pixel over `Rgb8Pixel`.** A `DrawnPixel(bool)` keeps the
  non-blank assertion deterministic without depending on theme/background
  colours.
- **All overlays on simultaneously** is not a reachable user state, but it is
  intentional: the goal is to evaluate as many conditional bindings as possible
  in one deterministic frame. The four-element `checksum-digests` model keeps
  the `root.checksum-digests[0..3]` indexes in-bounds while the hash checkboxes
  are on.
- **`set_platform` uses `.expect`** rather than the harness's idempotent `.ok()`
  because this binary has a single test; a platform installation failure should
  fail loudly instead of silently falling back to winit (which would need a
  display server).
- Cargo-deny prints `warning[duplicate]` lines for several transitive crates;
  these are pre-existing and are warnings, not failures. `cargo-audit` is absent
  locally, so xtask prints `SKIP` — expected, not a failure. The new test did
  **not** cause a size-baseline drift (integration test binaries are not the
  release binaries the size gate measures).

### Verification (exact commands and results)

```
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/hosi/dev/REA-Furus/furus
cargo test -p furus-gui --test render_smoke
```

```
   Compiling furus-gui v0.1.0 (/home/hosi/dev/REA-Furus/furus/crates/furus-gui)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 5.93s
     Running tests/render_smoke.rs (target/debug/deps/render_smoke-b42c32859e639fcc)

running 1 test
test main_window_renders_offscreen_with_all_overlays ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
```

```
cargo xtask ci
```

Final line: `ci: all gates passed` (exit 0). Gate sections observed:

- `==> fmt` — clean (after applying `cargo fmt --all` to the new file; only
  `crates/furus-gui/tests/render_smoke.rs` changed).
- `==> clippy` — clean under `-D warnings` (no warnings).
- `==> test` — all workspace test binaries passed, including the new
  `render_smoke` test.
- `==> assets --check` — all `PASS … sha256 ok`.
- `==> parity --check` — `parity: data/parity.csv is fresh`, 2,709 rows,
  address sets match.
- `==> contract --check` — `contract: all identifiers match the single source
  of truth` (slice-1 gate still green).
- `==> size` — `size: within committed baseline allowance, all budgets OK`
  (no baseline change).
- `==> cargo-deny` — `advisories ok, bans ok, licenses ok, sources ok`;
  `SKIP (not installed): cargo-audit`.

### Remaining / next steps

- Slice 2/4 is complete and locally verified but **not committed and not
  pushed**. Hand this slice to the reviewer.
- Slice 3/4 (whatever the S29 plan defines next) must be opened as its own
  gated command and reviewed separately. Do not batch it with this slice.
