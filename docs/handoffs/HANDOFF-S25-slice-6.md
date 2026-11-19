# S25 — Slice 6 handoff (checksum modal)

State at the end of this slice: the GUI's four-algorithm checksum dialog is
implemented, reviewed and committed. This slice adds no dependency, no Cargo
change and no doc change from the coder; the reviewer added the `TECHNICAL.md`
note and this handoff.

## What was done
- New headless engine `crates/rufus-gui/src/checksum.rs`, exported with one
  `pub mod checksum;` line in `lib.rs`. It owns the four streaming digests,
  incremental progress, one-shot cancellation and the stale-result guard.
- `main.rs` gained the checksum session state, an event-loop dispatcher, the
  three UI callbacks (compute / CANCEL / CLOSE), shutdown+join and pure display
  formatters. `ui/main.slint` gained a presentation-only modal overlay with
  four copyable read-only `LineEdit`s, a progress bar, a status line and
  CANCEL/CLOSE buttons.

## Key decisions / gotchas
- **Engine lives in `checksum.rs`, not `analyzer.rs`.** All state decisions
  (request ids, stale guard, outcome, progress, cancellation) are owned there;
  `main.rs` only marshals, stores and formats, and `main.slint` only displays.
- **`analyzer::checksum` remains but is unused by the GUI.** The old synchronous
  `checksum(&GuiState)` note path was removed from the GUI (no `show_checksum`,
  no import, no `self.note` write). The core function itself is untouched.
- **Real hashing only.** All four digests come from
  `rufus_core::hash::hash_reader` with `Algo::{Md5,Sha1,Sha256,Sha512}` (the
  same 1 MiB-chunk loop as the core). No hand-rolled hash, no new crate, no
  `unsafe`, no async, no network.
- **Progress is derived from `4 x file length`** (four passes over the file). A
  `Read` adapter counts bytes across passes and publishes a new whole percent
  per 1 MiB chunk, only when it increases; it is monotonic and capped at 100,
  and an empty file divides by zero nowhere (terminal result is 100).
- **Cancellation via a shared `Arc<AtomicBool>`** `CancelToken`. `cancel()` is
  idempotent; the `Read` adapter checks it at every chunk and returns an
  `Interrupted` error, so a large file stops promptly. A cancelled or failed
  run publishes a terminal result with no digests. `begin()` cancels the prior
  request; window close and modal CLOSE cancel the in-flight run, and window
  close shuts down and joins the single long-lived worker and its dispatcher.
- **Status NOT pushed into `GuiState`/the main status line.** The checksum
  status is displayed only in the modal's dedicated `checksum-status`
  property, not written to `self.note` or appended to the global status text.

## Verification
- Headless only: `env -u APPDIR cargo test -p rufus-gui` passes 81 library
  (incl. 7 new checksum tests) + 13 binary (incl. 1 formatter test), 0 failed.
  `cargo fmt --all -- --check` clean;
  `env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings` exit 0.
- No test opens a Slint window, device, pkexec, D-Bus or display; test fixtures
  are tiny temp files. **No rendered-window check** was possible (no display on
  the build host), so widget layout and copy/paste from the `LineEdit`s remain
  unverified.

## Next step
Slice 7 — i18n + config bridges.
