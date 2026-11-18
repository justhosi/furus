# Handoff — S25 Slice 1/7: the IPC seam and the JSONL event parser

## Status
Coder complete, reviewed (`AUDIT: PASSED` in round 2), committed as
`feat(gui): add the IPC seam and the JSONL event parser`. **NOT pushed** —
`publisher` runs phase 3 after all seven slices.

Round 1 failed on three clippy blockers plus five minors; the round-2 review
re-read every site and re-ran the gate (`clippy --workspace --all-targets --
-D warnings` exit 0). No `#[allow]`, no `unsafe`, no new dependency, no
thread/spawn/network code was added by the fix round.

## Scope (as landed — four paths)
| Path | Change |
|---|---|
| `crates/rufus-proto/src/events.rs` | `LineError`, `Completion::check_version`, `from_jsonl_line`, 4 new tests (+175 lines) |
| `crates/rufus-proto/src/lib.rs` | crate-root re-export of `LineError` and `from_jsonl_line` |
| `crates/rufus-gui/src/ipc.rs` | **new**, 333 lines: `IpcError`, `CancelHandle`, `Started`, `EventStream`, `HelperTransport`, `MockTransport`, 6 tests |
| `crates/rufus-gui/src/lib.rs` | one line: `pub mod ipc;` |

Docs in the same commit: `TECHNICAL.md` (§3.8 and the S25 coverage block),
`DECISIONS.md` (dated S25 amendment, A9/A8), this file.

## What was done
### The parser (shared, in `rufus-proto`)
- `from_jsonl_line(&str) -> Result<Event, LineError>` strips a trailing `\r`
  and surrounding ASCII whitespace, rejects the empty line, parses to
  `serde_json::Value`, names an unknown `kind` tag (`progress`, `log`, `done`
  only) *before* the enum deserialiser, and applies the version rule to every
  `Done` line.
- `LineError` is `Empty` / `Json(String)` / `UnknownKind(String)` /
  `VersionTooHigh { found, supported }`, with pinned `Display` strings. The tag
  is producer-controlled and reaches the UI through
  `IpcError::Protocol`, so its `Display` arm uses `escape_debug` — a tag with
  ESC or a newline renders escaped (a test fails if that is removed).
- `Completion::check_version` is the **only** version comparison in the tree
  (grep-verified: the helper only *writes* `EVENT_STREAM_VERSION`); newer
  streams are refused, equal/older parse.
- Tests cover the four variants concretely, the hostile inputs (two-line blob,
  `"\u{0}"`, 8 MiB message → `Ok`, 4,096 nested `[` → `Json`, no panic or stack
  overflow) and one serialise→parse round trip per `Event` variant.

### The seam (client, in `rufus-gui::ipc`)
- `HelperTransport::start(&mut self, &Plan) -> Result<Started, IpcError>`;
  `Started { session, events, cancel }`; `events: EventStream` is a **blocking
  `Iterator<Item = Result<Event, IpcError>>`** (`impl Iterator`, not an inherent
  `next`), and `cancel: CancelHandle`.
- `EventStream` discards foreign-session lines, surfaces the first `Done` and
  then returns `None` for ever, forwards transport errors, and turns a bad line
  into `IpcError::Protocol(LineError)`.
- `CancelHandle` is one-shot **across clones** and sticky: the first result
  (`Ok` or `Err`) is cached and returned by every later call, so a retry cannot
  report success for a failed cancel. Poisoned locks become
  `IpcError::Transport`, not panics. `type CancelAction = Box<dyn FnOnce() ->
  Result<(), IpcError> + Send + 'static>` keeps the action `Send + 'static`.
- `MockTransport` replays JSONL through the production parser, so tests never
  need a helper, a bus, a process or a display. `assert_send::<CancelHandle>()`
  and `assert_send::<EventStream>()` are pinned in a test.

## The two intended transports (not implemented yet)
1. **pkexec reader thread** — `rufus-helper --plan <file> --progress jsonl`
   spawned under `pkexec`; the child's stdout is read line by line on a plain
   `std::thread` and pushed through `from_jsonl_line`. `IpcError::Spawn`/
   `Unavailable` belong here.
2. **zbus 6 client** — `org.rufuslinux.Helper1` on the system bus:
   `Execute(plan_json) -> session_id`, `Cancel(session_id)`, signals
   `progress`/`log`/`done`. zbus 6 has **no blocking API**, so the client must
   drive its proxy with `zbus::block_on` on its **own** thread (never on a
   runtime task — `zbus::block_on` panics if called from a task the runtime
   drives; see the measured note in `crates/rufus-helper/src/dbus.rs`), then
   feed events to the same `Iterator`. Adding `zbus` to `rufus-gui` is a
   dependency decision for that slice, not taken here.

## What remains (slices 2–7)
- The real transports above; nothing spawns or connects today.
- A decision the D-Bus signal set does not answer: `done(session,
  outcome_json)` carries **no stream version**, so the client must supply
  `Completion.version` (i.e. `EVENT_STREAM_VERSION`) or the helper signal must
  grow a version argument — otherwise the single version rule cannot be applied
  on the D-Bus path. `progress` also sends `total: i64`/`percent: i16`
  (`None`/`-1` conventions) where the JSONL form uses `Option<u64>`/`Option<u8>`,
  so that mapping needs to be written down when the client lands.
- START still only *describes* a plan: no polkit-gated execute, no cancellation
  button, no `Event`-driven progress/log rendering, no size-baseline refresh for
  the GUI binary.

## Verification (run in this tree)
```
cargo clippy --workspace --all-targets -- -D warnings   # exit 0, clean  (the round-1 blocker)
cargo fmt --all -- --check                              # exit 0, clean
cargo build -p rufus-gui                                # exit 0
env -u APPDIR cargo test -p rufus-proto -p rufus-gui    # 21 + 36 + 7 passed, 0 failed
git status --porcelain                                  # only the four slice paths (+ docs)
```

## Gotchas
- **`APPDIR` trap**: this shell exports `APPDIR=/tmp/.mount_DeepAIHbAgCA`, and
  `rufus-core`'s `paths.rs` prefers `$APPDIR/usr/share/rufus-linux/assets`,
  which does not exist. That causes **7 pre-existing, environmental
  `rufus-core` test failures** under `cargo test --workspace`. They are not
  slice regressions and `paths.rs` must not be touched: always run
  `env -u APPDIR cargo test …`.
- `cargo` needs `PATH="$HOME/.cargo/bin:$PATH"` in this shell.
- `from_jsonl_line` is the only client parser; do not grow a second one in the
  transport. The accepted tag list lives beside the enum on purpose — adding an
  `Event` variant means bumping `EVENT_STREAM_VERSION`, updating that list, and
  adding an arm to `ipc.rs`'s exhaustive session `match` (which is what makes a
  forgotten variant a compile error, not a silent drop).
- The round-trip test lists the variants by hand; nothing *forces* it to grow
  with the enum. Treat "new variant" as "touch the tag list and the test".
- `CancelHandle::cancel` holds the result lock while the action runs, so an
  action that calls `cancel()` on a clone of its own handle would deadlock.
  Keep transport cancel actions free of handle re-entry.

## Next steps
1. Slice 2/7: pick the transport order (pkexec first is the smaller surface),
   then add it behind `HelperTransport` without touching the parser.
2. Keep the contract doc (`TECHNICAL.md` §3.8) in step if the seam changes, and
   record any new dependency as a `DECISIONS.md` amendment.
3. Push only on explicit user permission, via `publisher`, after slice 7/7.
