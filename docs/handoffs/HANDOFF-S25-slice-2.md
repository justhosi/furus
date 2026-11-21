# Handoff — S25 Slice 2/7: the pkexec transport

## Status
Coder complete, reviewed (`AUDIT: PASSED` in round 2), committed as
`feat(gui): add the pkexec transport for the privileged helper`. **NOT
pushed** — `publisher` runs phase 3 after all seven slices.

Round 1 failed on one major (an uncancellable blocking `start()`) plus five
minors; the round-2 review re-read every site and re-ran the gate. No `#[allow]`,
no `unsafe`, no async, no network and no `Cargo.toml`/`Cargo.lock` change was
introduced by the fix round.

## Scope (as landed — four source paths)
| Path | Change |
|---|---|
| `crates/furus-gui/src/ipc.rs` | **deleted** (333 lines) — split into the module below, byte-identical outside the two added lines |
| `crates/furus-gui/src/ipc/mod.rs` | **new**, 341 lines: the slice-1 seam verbatim, plus `pub mod pkexec`, the `PkexecTransport` re-export and the blocking-`start` contract on the trait |
| `crates/furus-gui/src/ipc/pkexec.rs` | **new**, 1,042 lines: `PkexecTransport` (spawn, readers, timeout, cancel, terminal synthesis, temp-plan sweep) and 13 tests |
| `crates/furus-proto/src/lib.rs` | `Plan::to_json` (writes `confirm` verbatim) + 2 tests |

Docs in the same commit: `TECHNICAL.md` (§3.8, including the sentence that
wrongly claimed no transport ships), `DECISIONS.md` (two S25 slice-2
amendments), this file.

## What was done
### The transport
- `PkexecTransport::new()` / `Default` spawn
  `<program> <prefix…> furus-helper --plan <file> --progress jsonl` with only
  stdout and stderr piped; the production prefix is empty, so the real command
  is `pkexec furus-helper …`.
- stdout is read line by line on a `furus-helper-stdout` thread through the
  shared `from_jsonl_line`; stderr on a `furus-helper-stderr` thread; both feed
  the existing `EventStream`, so session demultiplexing, the exactly-one-`Done`
  rule and `IpcError::Protocol` are unchanged.
- **Blocking `start()`**: `first_message` applies one `recv_timeout` over a
  120 s default budget (`DEFAULT_AUTHORIZATION_TIMEOUT`) while skipping blank
  lines. On expiry it kills the child, `wait()`s (reaps) it, joins the reader,
  drops the plan file and returns
  `IpcError::Transport("no helper event within Ns; authorization not completed")`.
  Reads **after** `start()` are plain blocking `recv()` — no per-line timeout,
  so long `wipe`/`verify` steps cannot be cut off.
- **Terminal synthesis**: a run with no `Done` gets exactly one, with
  `EVENT_STREAM_VERSION`: `0`→`ok`, `3`→`refused` (`code: "exit"`),
  `4`→`failed` (`code: "exit"`), `6`→`cancelled`, anything else→`failed`
  (`code: "exit"`); a cancelled run synthesises `cancelled` whatever its
  status. A real `Done` for the session suppresses synthesis.
- **Cancel**: SIGKILL only if the child is still running, and a sticky
  `cancelled` flag so the EOF that follows reports `Cancelled`.
- **stderr**: capped at the **last** 8 KiB (`STDERR_LIMIT`), `from_utf8_lossy`
  + `escape_debug`, tail-truncated at a `char` boundary, appended to the
  synthesised message — control bytes never reach the UI raw.
- **Temp plan**: `Plan::to_json` → `$TMPDIR/furus-plan-<gui-pid>-<counter>-
  <nanos>.json` via `create_new(true)` + mode `0600`; removed before the
  terminal event, on reader error, on timeout, on spawn failure and on `Drop`.
- **Sweep**: every constructor removes only *canonical-name, regular-file,
  current-user, mode-0600* plans whose `/proc/<pid>/stat` proves the pid gone or
  a zombie. Symlinks, other users, other modes, unparsable names and every I/O
  error are ignored. A live pid is never touched, so pid reuse leaks a file
  rather than deleting a live run's plan.

## Round-1 findings and how each was closed
| # | Finding | Fix |
|---|---|---|
| 1 | **MAJOR** — uncancellable blocking `start()` | one `recv_timeout` over the authorization budget; timeout kills **and reaps** (test asserts `/proc/<pid>` gone), removes the plan and returns the pinned `Transport` error. The budget is a single wait, not a per-read timeout. |
| 2 | contract change unwritten | documented on `HelperTransport::start` **and** the `PkexecTransport` impl; §3.8 now carries the full contract and no longer says no transport ships |
| 3 | reader-error arm skipped teardown | the `ReaderMessage::Error` arm cancels, sets `ended`, takes the plan and joins the reader; `invalid_utf8_reader_error_ends_without_done_and_removes_plan` asserts `Err` then `None`, no synthesised `Done`. `Drop` still works when `ended` is already set (it skips the kill and the reader is already joined). |
| 4 | exit-status table untested | `exit_statuses_synthesize_expected_single_completion` over `{0, 3, 4, 6, 7, 126}`; changing any mapping makes it panic on the expected/actual pair. |
| 5 | stderr bound unpinned and truncated from the wrong end | keeps the **tail**, capped at 8 KiB; the test writes 64 KiB then `TAIL_MARKER` and asserts the bound, the marker and no control characters. |
| 6 | temp plans survive abnormal death | the constructor sweep above, with a test proving a dead-pid file is removed and a live-pid file is preserved. |

## What slices 3–7 still owe
- **The D-Bus client** (`org.furuslinux.Helper1`): zbus 6 has no blocking API, so
  it must drive its proxy with `zbus::block_on` on its **own** thread. Two
  mappings are still unwritten: `done` carries no stream version (supply
  `Completion.version` from `EVENT_STREAM_VERSION`, or grow the signal), and
  `progress` sends `total: i64`/`percent: i16` (`None`/`-1` conventions) where
  JSONL uses `Option<u64>`/`Option<u8>`. Adding `zbus` to `furus-gui` is a
  dependency decision for that slice.
- **Wiring**: nothing in the UI calls a transport yet — START still only
  *describes* a plan. A polkit-gated start, a real cancel button and
  `Event`-driven progress/log rendering are all still open.
- **`IpcError::Unavailable`** is still unexercised in production code: the
  pkexec transport returns `Spawn`/`Transport`, so the "no transport available"
  arm belongs to transport selection (probing pkexec vs D-Bus).
- **Size baseline**: once the transport is linked into the START path, refresh
  `size-baseline.json` with measured values, as previous slices did.

## Verification (run in this tree)
```
cargo clippy --workspace --all-targets -- -D warnings   # exit 0, clean
cargo fmt --all -- --check                              # exit 0, clean
cargo build -p furus-gui                                # exit 0
env -u APPDIR cargo test -p furus-proto -p furus-gui    # 23 + 49 + 7 passed, 0 failed
ls /tmp/furus-plan-*                                    # prints nothing
git status --porcelain --untracked-files=all            # only the four slice paths (+ docs)
```
The 13 transport tests spawn `/bin/sh -c` stubs only; none invokes pkexec,
polkit, the bus, a display or a device.

## Gotchas
- **`APPDIR` trap**: this shell exports `APPDIR=/tmp/.mount_DeepAIHbAgCA`, and
  `furus-core`'s `paths.rs` prefers `$APPDIR/usr/share/furus-linux/assets`,
  which does not exist. That causes **7 pre-existing, environmental
  `furus-core` test failures** under `cargo test --workspace`. They are not
  slice regressions and `paths.rs` must not be touched: always run
  `env -u APPDIR cargo test …`.
- `cargo` needs `PATH="$HOME/.cargo/bin:$PATH"` in this shell.
- **`start()` blocks by contract.** Do not "fix" that with a per-read timeout:
  the 120 s budget covers the polkit authorization wait only, and a timeout on
  the event loop would kill a legitimate long `wipe`/`verify`. The injected
  budget is a test seam; production construction must stay `new()`/`Default`.
- **The sweep is a delete loop in a world-writable directory.** Do not widen it:
  the canonical-name parse, the regular-file (no-symlink) check, the
  owner + mode `0600` check and the `/proc/<pid>/stat` gone-or-zombie proof are
  each load-bearing. Never remove "any `furus-plan-*`".
- The transport tests share one process temp dir and assert on
  `prefixed_plan_files()`, so they all take a `TEST_LOCK`; new tests must take
  it too or they will flake against each other.
- Teardown lives in `ProcessLines` (`plan_file`, `reader`, `ended`), not in
  `Started`: dropping the stream must still kill the child, join both readers
  and remove the plan. `finish_after_done` is what makes a real `Done` terminal
  without a second synthesised one.
- stderr keeps its **tail**, not its head — a switch back to the first 8 KiB
  loses the useful failure text (`large_stderr_keeps_bounded_escaped_tail`
  fails).

## Next steps
1. Slice 3/7: pick up the D-Bus client behind the same `HelperTransport`
   (record the `zbus` dependency decision first), or wire `PkexecTransport`
   behind START if the coordinator prefers the end-to-end path first.
2. Keep `TECHNICAL.md` §3.8 in step whenever the seam or the transport contract
   moves, and record any new dependency as a `DECISIONS.md` amendment.
3. Push only on explicit user permission, via `publisher`, after slice 7/7.
