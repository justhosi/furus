# Handoff — S25 Slice 4/7: the run state machine

## Status
Coder complete, reviewed (`AUDIT: PASSED`) and committed as the slice-4 commit.
**NOT pushed** — `publisher` runs after all seven slices on explicit user
permission. All three acceptance gates re-run by the reviewer pass.

## Scope (as landed — two source paths, plus docs)
| Path | Change |
|---|---|
| `crates/rufus-gui/src/run.rs` | **new**, 952 lines: `Run` state machine, `StepLabel`, `CancelRequest`, `RunError`, helpers and 8 tests |
| `crates/rufus-gui/src/lib.rs` | one line: `pub mod run;` |

Docs in the same commit: `TECHNICAL.md` §3.8 (new slice-4 paragraph, narrowed
"What S25 still owes", slice-4 coverage + gates), this file.

**Out of scope / untouched:** the uncommitted slice-3 work in `Cargo.lock`,
`crates/rufus-gui/Cargo.toml`, `crates/rufus-gui/src/ipc/mod.rs` and
`crates/rufus-gui/src/ipc/dbus.rs`. Do not commit or revert it here.

## What was done
- `Run` owns one plan's lifecycle: `Idle --start()--> Confirming --confirm()-->
  Running{step, percent, rate, eta} --Done/cancel()--> Finished(Outcome)`.
- **The confirmation gate.** `start()` builds through `GuiState::build_plan`
  (S23 planner is still the only builder), captures `DeviceFacts`, then clears
  the planner's provisional `sha256:` token. `Plan::confirm` hashes the plan's
  *other* fields and ignores the stored token, so `confirm()` recomputes the
  identical hash — only the moment the token exists changes. `confirmed_plan()`
  returns `ConfirmationRequired` in `Idle`/`Confirming`, so START alone can
  never yield a runnable plan.
- **Wire op labels.** `StepLabel::from_op` accepts exactly the seven
  `rufus-helper` `op_tag` values `wipe/mklabel/mkpart/mkfs/write/bootloader/
  finalize` and renders `wipe/table/partition/format/write/bootloader/finalise`;
  an unknown tag keeps the last known label.
- **Rate/ETA from an explicit clock.** `apply(&Event, Duration)` is the only
  input; no `Instant`, `SystemTime` or wall clock in the crate. Rate is `done`
  over the time since the step's first sample; ETA is remaining units at that
  rate, both via `rufus_core::units`. `total: None`, zero elapsed and zero rate
  all yield `None`.
- **Monotonic display.** Earlier-step and fewer-units samples are ignored;
  percent never decreases within a step (a step advance legitimately restarts
  it). `Event::Done` is terminal — later events are ignored. `cancel()` is
  one-shot through an injected `CancelRequest` and yields exactly one
  `Finished(Cancelled)`. Logs are bounded at `LOG_LIMIT = 500`.
  `configuration_locked()` is true in `Confirming`/`Running`.

## Decisions
- The planner's `sha256:` token is an **integrity hash**, not user approval;
  clearing and recomputing keeps the exact token while making its existence the
  confirmation boundary. Verified against `planner::build` and `Plan::confirm`.
- Cancellation is an *ask*, injected as `FnOnce() + Send + 'static`; the state
  machine keeps no dependency on any transport.
- The UI owns the clock; the machine only consumes an injected `Duration`, so
  tests are deterministic.

## Gotchas
- `env -u APPDIR` is required for tests: this shell exports `APPDIR` at a
  nonexistent AppImage asset dir, which breaks 7 unrelated `rufus-core` tests.
  Do not edit `paths.rs`. `cargo` needs `PATH=/home/hosi/.cargo/bin:$PATH`.
- `apply()` is a no-op unless the state is `Running`; do not try to feed events
  before `confirm()`.
- `confirmed_plan()` still returns the (token-bearing) plan after `Finished`;
  that is intentional — the transport must not be restarted from a finished
  `Run`.

## Verification (run in this tree)
```
env -u APPDIR cargo test -p rufus-gui              # 74 + 7 + 0 passed, 0 failed
cargo fmt --all -- --check                         # exit 0, clean
env -u APPDIR cargo clippy -p rufus-gui --all-targets -- -D warnings  # exit 0, clean
```
All 8 `run::tests` pass. No test opens a device, a display, a helper, pkexec,
polkit or a bus; no `unsafe`, no async, no threads and no new dependency.

## Next steps — Slice 5/7 (wire transport + machine into the UI)
1. START stays the gate: call `run.start(&mut gui)`, show the provisional plan
   from `run.plan()` and the captured `run.device()`, keep controls locked via
   `run.configuration_locked()`. Only the user's confirm action calls
   `run.confirm()`.
2. Start the transport from `run.confirmed_plan()` (never from `run.plan()`),
   then record `let started = Instant::now();` — the UI owns the clock.
3. Drive the machine from the stream: for each `Event` from `Started.events`,
   call `run.apply(&event, started.elapsed())` and render from `run.state()`
   (`RunState::Running { step, percent, rate, eta }`) and `run.logs()`.
4. Adapt the transport cancel handle to the injected seam: build
   `CancelRequest::new(move || { let _ = handle.cancel(); })` with a clone of
   `Started.cancel` (its `FnOnce` must be `Send + 'static`; drop the
   `Result<(), IpcError>` because the machine only needs to *ask*), pass it via
   `Run::with_cancel`, and have the UI cancel button call `run.cancel()`.
5. Treat `RunState::Finished(outcome)` as terminal: unlock the form, stop
   reading the stream (the `EventStream` is already terminal at the first
   `Done`).
6. Keep `TECHNICAL.md` §3.8 in step as the wiring lands. Push only on explicit
   user permission, via `publisher`, after slice 7/7.
