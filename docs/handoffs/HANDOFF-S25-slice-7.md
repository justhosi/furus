# S25 — Slice 7 handoff (localisation + GUI preferences — FINAL SLICE)

State at the end of this slice: the GUI's locale/i18n bridge and the GUI-only
preferences bridge are implemented, reviewed and committed. This closes S25.
The coder touched only the six code files; the scope expansion to `xtask` and
the size baseline was explicitly authorised by the user after the first review
round. The reviewer wrote `TECHNICAL.md` and this handoff.

## What was done
- New headless module `crates/furus-gui/src/i18n_bridge.rs` (`LocaleCatalog`),
  exported with one `pub mod i18n_bridge;` line in `lib.rs`.
- New headless module `crates/furus-gui/src/config_bridge.rs` (`GuiPrefs`),
  exported with one `pub mod config_bridge;` line in `lib.rs`.
- `main.rs` gained the locale/hash/advanced session state and marshalling
  callbacks only; `ui/main.slint` gained a locale combo, translated static
  captions, per-digest checkboxes and an advanced-options visibility toggle.
- `furus-core::config` gained a `[gui] GuiConfig` table with a test; the single
  existing `example()` literal was updated for the new field.
- `xtask/src/main.rs`: `furus-gui` release-size budget 12,000,000 → 14,000,000
  (spec at line 509 and the `size_drift_detection` fixture at line 934;
  other budgets unchanged). `size-baseline.json` refreshed via
  `cargo xtask size --write-baseline`.

## Key decisions / gotchas
- **Embedded `.loc` fallback, asset optional.** `LocaleCatalog::load` reads the
  first parseable system asset (`RCDATA_500.bin`, then the upstream `.loc`
  catalog name via `furus_core::paths::asset_path`, which takes one bare
  component) and otherwise
  falls back to the small `EMBEDDED_CATALOG` constant. In this environment
  `assets_dir()` points at a bogus `$APPDIR/...`, so tests exercise the embedded
  path; catalog loading is never required for a test and never touches an FHS
  install. Known caption ids fall back to Rust-owned English literals when the
  catalog has no translation; unknown ids pass through verbatim. Only
  `furus_core::i18n::{Catalog, Translator}` is used — no `.loc` grammar is
  reimplemented here (just `l`-header display names for the combo), no global
  mutable/lazy static, no network.
- **RTL is pure presentation.** `rtl: bool` is computed in Rust from the locale's
  primary subtag (`ar`/`he`/`fa`/`ur`). Slint 1.19 has **no native RTL layout
  engine**, so `.slint` uses the flag only for text alignment — never for a
  translation, preference, formatting or safety rule. All captions and
  preference values come from Rust properties; `.slint` holds no business rule.
- **`[gui] GuiConfig` in `furus-core::Config` (one TOML file, no new dep).** The
  active locale keeps its single owner `Config::locale`; the four hash-display
  toggles and `advanced_visible` live in `GuiConfig` with `#[serde(default)]` and
  sibling derives, so a file with no `[gui]` still loads. `GuiPrefs` only reads
  and writes fields on the whole `Config`; load never writes (a corrupt file is
  moved aside by core), save is the atomic `Config::save`, and every unrelated
  field (`show_all`, `check_updates`, `update_channel`, `last_device`,
  `ignore_devices`, `window`, `advanced`) survives a round trip. No dependency
  was added to either crate — notably no `toml` in `furus-gui` — and no
  network/`check_updates` behaviour was touched (A12).
- **Advanced-visible two-way binding fix (review round 2).** The first round
  declared `advanced-visible` as `in property` with `checked: root.advanced-visible;`.
  The generated Slint code showed a one-way `set_property_binding_erased` and no
  `link_two_way`, so a click never wrote the property the callback reads via
  `ui.get_advanced_visible()` — the section would not expand and the preference
  would not persist. Fixed by `in-out property <bool> advanced-visible;` plus
  `checked <=> root.advanced-visible;`. After `cargo clean -p furus-gui`, the
  generated `get/set_advanced_visible` alias `checkbox_33.accessible_checked`
  directly and the stale one-way binding is gone.
- **Size budget raise + baseline refresh (review round 2).** `cargo xtask size`
  failed with `furus-gui` 12,774,280 bytes over the old 12 MB budget; budgets are
  always enforced, so `--write-baseline` alone could not pass the gate. The user
  authorised raising the hardcoded budget to 14 MB and refreshing the baseline:
  the growth accumulated across all S25 slices (notably the two zbus versions —
  5.19 pulled transitively by Slint, 6.2 used directly), and the baseline had not
  been refreshed since `bbe054a`. Other binaries stayed within their drift
  allowance.

## Unverified / not covered
- **Headless vs live asset:** only the embedded `.loc` fallback and `from_bytes`
  fixtures were exercised. Real asset loading is unverified here because
  `assets_dir()` resolves to a bogus `$APPDIR/...`.
- **Rendered UI:** no display on the build host, so widget layout, locale combo
  round-trips and actual RTL text alignment are unverified; the RTL/binding
  behaviour was confirmed from the generated Slint code, not a live click.
- **cargo-deny duplicate-zbus warnings:** non-fatal, recorded as a nit only
  (two zbus versions are intentional). `cargo-audit` is not installed and is
  reported as SKIP, not a pass.

## Full S25 status
All seven slices are implemented, reviewed and committed:
1. Shared JSONL event/plan parser (`furus-proto`) and the headless CLI start.
2. pkexec helper transport over a sync seam.
3. D-Bus transport with one-shot fallback; startup root-refusal policy.
4. Headless run state machine with a confirmation gate.
5. Slint run wiring (confirm dialog, progress, cancel bridge, log drawer).
6. Four-algorithm checksum modal (headless engine + presentation-only overlay).
7. Localisation bridge, GUI preferences bridge, RTL flag and size budget raise
   (this slice).

## Verification (final)
- `env -u APPDIR cargo test -p furus-gui`: 86 + 14 + 0 passed, 0 failed.
- `env -u APPDIR cargo test --workspace`: green, 0 failed.
- `cargo fmt --all -- --check`: clean (exit 0).
- `env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings`: exit 0.
- `cargo xtask size`: furus 1,810,152 / helper 1,406,296 / gui 12,774,280 — all
  within budget; "within committed baseline allowance, all budgets OK".
- `env -u APPDIR cargo xtask ci`: exit 0 — "ci: all gates passed"
  (assets 86/86 verified, parity fresh at 2,709 rows, fmt/clippy/test/size/deny).

## Status and next action
- **NOT pushed.** The reviewer committed locally only; pushing is Publisher's job.
- **Next action: invoke Publisher ONLY on explicit user permission.** The
  publisher verifies the `Reviewed-by: reviewer` sign-off, updates the README
  and pushes. Do not push from this slice.
