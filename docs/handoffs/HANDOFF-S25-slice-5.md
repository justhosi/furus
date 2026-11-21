# Handoff — S25 Slice 5/7: wire the run flow into the Slint UI

## Status
Coder complete, reviewed (`AUDIT: PASSED`) and committed as the slice-5
commit. **NOT pushed** — `publisher` runs after all seven slices on explicit
user permission. All three acceptance gates were re-run by the reviewer and
pass. The prior slice-3 fix round (D-Bus transport + fallback) was committed
separately as its own commit, immediately before this one.

## Scope (as landed — two source paths, plus docs)
| Path | Change |
|---|---|
| `crates/furus-gui/src/main.rs` | +~629 lines: `CancelBridge`, `RunView`/`run_view`, pure formatters, `Session` owns `Run` + bridge + `run_started`, worker/dispatcher threads, START/confirm/cancel/discard callbacks, terminal + log rendering, 5 new tests |
| `crates/furus-gui/ui/main.slint` | +~98 lines: `form-enabled` on every config control, `step-text`, log toggle + drawer, CANCEL, confirmation overlay (`confirm-facts`, `confirm-clicked`/`discard-clicked`) |

Docs in the same commit: `TECHNICAL.md` §3.8 (new slice-5 wiring paragraph,
"Accepted open decision — D-Bus mid-run death", transport-seam wording updated
to two shipped transports, slice-5 coverage + gates in §4), this file.

The separate commit immediately before this one carries exactly four paths —
`Cargo.lock`, `crates/furus-gui/Cargo.toml`,
`crates/furus-gui/src/ipc/mod.rs`, `crates/furus-gui/src/ipc/dbus.rs` — the
audited slice-3 D-Bus transport + fallback work. No other source, Cargo or doc
file was touched by the coder.

## What was done
- **Presentation-only boundary.** `.slint` holds no business rule: it renders
  Rust-provided properties and forwards callbacks. `main.rs` only marshals,
  formats and threads: every state transition goes through `Run`
  (`start`/`confirm`/`apply`/`cancel`) and every transport error / session fact
  through `ipc`. No plan building, confirmation-token logic, compatibility rule
  or device policy was reimplemented in the binary.
- **Confirmation gate verified against the code.** START calls
  `Run::start(&mut GuiState)` (plan only, no token, no transport) and opens the
  dialog; only `Run::confirm()` attaches the SHA-256 token. The worker starts
  the transport from the token-bearing plan **cloned from `Run::confirm()`**,
  never from `Run::plan()`. The provisional `run.plan()` in `Session::start()`
  is used only for the "Planned: …" status string.
- **Transport + threading.** A worker runs `open_helper(prefer_system_bus)` and
  `start_with_fallback(..., || Box::new(PkexecTransport::new()))`, installs the
  cancel sink, then pumps `EventStream` into an mpsc channel. A dispatcher
  applies each `RunMessage` to `Run` and re-renders on the UI thread via
  `slint::invoke_from_event_loop`; worker and dispatcher are joined after
  `ui.run()`.
- **Pure formatters.** `run_view(&Run)` derives progress/detail/lock/cancel/
  start/terminal values from `Run::state()` + `Run::configuration_locked()`;
  `confirmation_facts(&DeviceFacts)`, `log_line`/`log_lines` and `outcome_text`
  are pure. No Slint type, transport or device inside them.
- **Cancellation.** `CancelBridge` is a one-shot latch (Arc<Mutex<..>> with
  `requested`/`fired`/`sink`): a cancel issued before the worker installs its
  `CancelHandle` is latched and delivered exactly once at `install`.
  `Run::cancel()` asks through the injected `CancelRequest` whose action is
  `bridge.request()`; both that path and the explicit request in the callback
  converge on one `CancelHandle::cancel()` call.
- **Locking / lifecycle.** `configuration_locked()` drives one `form-enabled`
  flag applied to every configuration control. CANCEL is enabled only while
  `Running`, START re-enables only at `Finished`, the terminal `Outcome` is
  appended to the status line, and the log drawer renders buffered `Run::logs()`.

## Decisions
- The binary is only a composition root; transport selection is an injected
  probe (`prefer_system_bus`) and the fallback policy stays in `ipc`, so the UI
  never chooses a helper implicitly.
- The one-shot `CancelBridge` lives in the binary because only the binary joins
  the UI-thread action to the worker-thread `CancelHandle`; the state machine
  still only *asks* through `CancelRequest`.
- The log drawer's open/closed flag (`log-open`) is a local `.slint` property:
  it is pure UI state, not business state, so no Rust round-trip is needed.
- Early cancel is latched, not dropped, so a cancel during `start()`→worker
  install (including the polkit wait) is honoured.

## Gotchas
- `env -u APPDIR` is required for tests: this shell exports `APPDIR` at a
  missing AppImage asset dir, which breaks 7 unrelated `furus-core` tests.
  Do not edit `paths.rs`. Prefix cargo with `PATH=/home/hosi/.cargo/bin:$PATH`.
- **Unsendable / live-bus unverified.** The D-Bus path is exercised only with
  in-process signal-conversion tests and injected fakes; no system bus, polkit
  prompt or real helper was contacted, and no real window was rendered (no
  display on this host). The `CancelHandle` sink fires the D-Bus cancel on the
  calling thread via a spawned-and-joined thread; an unresponsive bus could
  stall that caller, but no live-bus case was run here.
- **D-Bus mid-run death (accepted, not fixed).** If the helper dies without a
  `Done`, `EventStream` does not end (no `NameOwnerChanged` watch), so the
  worker `join` after `ui.run()` can block. This is the accepted wait from
  slice 3; no name-owner watch was added in slice 5. Decide in a later slice
  whether to watch name ownership.
- `apply()` is a no-op outside `Running`; events before `confirm()` are ignored.
- The pkexec path ends cleanly at shutdown: cancel fires SIGKILL, stdout EOF
  synthesises a terminal `Done`, the stream ends and the worker returns.

## Verification (re-run by the reviewer, in this tree)
```
env -u APPDIR cargo test -p furus-gui
  -> lib 74 passed; bin 12 passed; doc 0 passed; 0 failed
cargo fmt --all -- --check
  -> exit 0, clean
env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings
  -> exit 0, clean
```
All 5 new binary tests pass. No test opens a device, a display, a helper,
pkexec, polkit or a bus; no new dependency, no `unsafe` beyond Slint macro
expansion, no async and no network in the slice-5 files.

## Next steps — Slice 6/7
1. Decide whether to add a `NameOwnerChanged` watch to the D-Bus client so a
   helper that dies without `Done` ends `EventStream` and unblocks the worker
   `join`; if yes, implement with headless tests and update §3.8 and this
   gotcha. If not, reaffirm the accepted wait in the handoff.
2. Add end-to-end coverage of the run wiring with a mock transport (the current
   binary tests cover the pure formatters and `Run` directly, not the
   worker/dispatcher path end to end).
3. Verify the live system-bus path and the actual window rendering on a host
   with a bus and a display; both are unverified here.
4. Keep `TECHNICAL.md` §3.8 in step as later slices land. Push only on explicit
   user permission, via `publisher`, after slice 7/7.
