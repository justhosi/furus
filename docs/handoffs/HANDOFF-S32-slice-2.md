# S32 Slice 2/4 — Wire picker into SELECT and add CLI image path

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo at
`~/.cargo/bin/cargo`.

Commit: `9f39890 feat(gui): wire portal picker into SELECT and add CLI image path`
(reviewer-approved, `Reviewed-by: reviewer` trailer). Nothing pushed.

## What landed

Only `crates/furus-gui/src/main.rs` changed:

- Imports: `AtomicBool` added to `use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};`;
  `use furus_gui::picker::PickerOutcome;` added.
- `print_help()`: usage is now `furus-gui [OPTION] [IMAGE_PATH]` and documents
  that a positional image path pre-selects/analyzes the image at startup (the
  file-manager "Open With" case).
- `main()`: uses `std::env::args_os().nth(1)`.
  - `--version`, `--help`, `-h` → print and exit `SUCCESS` before any
    display/euid initialization (genuinely headless).
  - Any other argument starting with `-` → stderr
    `furus-gui: unknown option '<flag>'` + help + exit `FAILURE`, so a typo is
    not mistaken for a path.
  - Non-flag `OsString` → `PathBuf` startup path → `run_gui(startup_path)`.
    `args_os` ensures non-UTF-8 paths are accepted verbatim.
  - `startup_refusal(process::geteuid().as_raw())` still runs after flag parsing.
- The old local synchronous `pick_image_path()` (zenity/kdialog only) and its
  doc comment were deleted; the module-qualified
  `furus_gui::picker::pick_image_path()` is the sole picker entry point.
- `fn run_gui(startup_path: Option<PathBuf>)`.
- `on_select_clicked` now dispatches to a guarded background worker:
  - `let picker_busy = Arc::new(AtomicBool::new(false));` lives outside the
    callback; `picker_busy.swap(true, Ordering::AcqRel)` rejects a second click
    while a dialog is open.
  - A named `furus-file-picker` thread calls
    `furus_gui::picker::pick_image_path()` and marshals the result back with
    `slint::invoke_from_event_loop`.
  - Outcome handling on the UI thread: `Selected(path)` → `select_image(path, &sender)`;
    `Cancelled` → no-op (no note, no fallback); `Unavailable(msg)` → sets
    `note`. Then `render(...)`, then release the busy flag.
  - The busy flag is released on **every** path: inside the queued event-loop
    closure (via a dedicated `busy_for_loop` clone), on
    `invoke_from_event_loop` failure, and on thread-spawn failure.
  - No Slint widget or `Session` mutation happens off the UI thread; the
    `MutexGuard` is dropped in an inner block before `render` to avoid
    re-entrant borrows.
- Startup pre-selection just before the final `render(...)`:
  `if let Some(path) = startup_path { session.borrow_mut().select_image(path, &analyzer_sender); }`.
  `analyzer_sender` is created before both this call and the SELECT wiring, so
  the analyzer worker always exists.

## Technical decisions / rationale

- This follows the existing analysis/checksum/device dispatcher pattern: clone
  `SessionHandle` + `ui.as_weak()` into a worker thread, marshal back with
  `slint::invoke_from_event_loop`, render from the UI thread, join after
  `ui.run()`.
- `Cancelled` is intentionally a silent no-op. Fallback to zenity/kdialog is
  confined to the `Unavailable` case in slice 1's `resolve_chain`, exactly as
  the spec required (Cancel must NOT trigger zenity).
- `#![deny(unsafe_code)]` retained; no unsafe added.

## Verification

- `cargo test -p furus-gui` → pass (16 tests at review time; later full-suite
  runs: 91 lib + 14 bin + 1 helper_wire + 1 render_smoke).
- `cargo clippy -p furus-gui --all-targets -- -D warnings` → clean.
- Headless binary checks: `--version` → `furus-gui 0.1.0`, exit 0; `--help` and
  `-h` → exit 0; `--bogus` → unknown-option message + help, exit 1; a `/tmp/*.iso`
  path proceeded to `run_gui` (Winit reported no display), proving it was not
  misparsed as a flag.
- Reviewer: CLEAN, no blockers. Committed; not pushed.

## Gotchas

- No visual "pending" state is shown while the dialog is open — a second SELECT
  click is silently ignored by the busy guard. The spec asked for no note or
  fallback on `Cancelled`, so this is intentional.
- End-to-end dialog behavior needs a real display session; only the headless
  and argument-parsing paths were exercised in CI.
