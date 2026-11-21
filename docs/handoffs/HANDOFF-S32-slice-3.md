# S32 Slice 3/4 — Remove excess vertical gap above Show log

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo at
`~/.cargo/bin/cargo`.

Commit: `780b27b fix(gui): remove excess vertical gap above Show log`
(reviewer-approved, `Reviewed-by: reviewer` trailer). Nothing pushed.

## What landed

Only `crates/furus-gui/ui/main.slint` changed — exactly two edits:

1. `main.slint:125` — added `alignment: start;` to the parent `VerticalLayout`
   (which already had `padding: 12px;` and `spacing: 8px;`).
2. `main.slint:336` — removed `vertical-stretch: 1;` from the status `Text`
   (`text: root.status-text; wrap: word-wrap;`).

No other file was touched; no filler `Rectangle` was added and no window-size
constraint changed.

## Root cause and rationale

`MainWindow` has `preferred-height: 640px` and no max height, so a tall tiling
window (Omarchy/Hyprland) gives it spare vertical space. The parent
`VerticalLayout` (lines 122-373) had Slint's default `alignment: Stretch`, and
the status `Text` had `vertical-stretch: 1`, so that single text element grew to
absorb **all** spare height — rendering as a blank gap above the "Show log"
button.

Removing `vertical-stretch: 1` alone is not sufficient: under the default
`Stretch` alignment, when the sum of all stretch factors is 0 Slint distributes
spare height equally among every growable item. Slint buttons have no
`max-height`, so they are growable and would all become tall. Adding
`alignment: start;` takes the non-stretch layout branch: each item stays at its
preferred size and the spare height is parked at the bottom of the layout.

The confirm (line 377) and checksum (line 417) overlays are siblings **outside**
this `VerticalLayout`, so they are unaffected. The log `Rectangle` (line 343)
stays conditional on `root.log-open`.

## Verification

- `cargo test -p furus-gui` → pass, including the offscreen
  `main_window_renders_offscreen_with_all_overlays` render smoke test.
- `cargo clippy -p furus-gui --all-targets -- -D warnings` → clean.
- `cargo xtask assets --check` → pass (86/86 files verified; no asset hash
  change).
- Reviewer: CLEAN, no blockers. Committed; not pushed.

## Gotchas

- Actual visual confirmation on a tall Hyprland window is a manual maintainer
  sign-off; CI only proves the layout compiles and still renders offscreen.
