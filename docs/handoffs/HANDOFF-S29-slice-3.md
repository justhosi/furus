# S29 — slice 3/4: compiled-helper JSONL / run-state wire test

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`, base HEAD `c3fb0b2`
(after slice 2). cargo/rustc 1.99.0 lives in `~/.cargo/bin`; every cargo
command below was prefixed with `export PATH="$HOME/.cargo/bin:$PATH"`.

This file is the handoff after **slice 3/4**. Slices are gated one at a time
(one command → reviewer → next command); do not batch them. Slice 1/4 is in
`HANDOFF-S29.md`, slice 2/4 in `HANDOFF-S29-slice-2.md`.

## Slice 3/4 — status: DONE (not committed, not pushed)

### Command executed

Add one real subprocess integration test that launches the **compiled**
`furus-helper`, drives it through the GUI's production JSONL parser and run
state machine against an unprivileged, nonexistent `/dev` node, and proves a
`not_a_block_device` refusal with zero writes and no root outside a user
namespace.

### What changed (only the two in-scope files)

1. **NEW `crates/furus-gui/tests/helper_wire.rs`** — one `#[test]` binary,
   `compiled_helper_refusal_drives_the_gui_parser_and_run_state_machine`,
   following the required flow verbatim:
   1. Build a fixture `GuiState::default()` and assign its public `device` /
      `image` fields: device path `/dev/furus-qa-missing-<pid>-<case>`, size
      32,010,928,128 B, sector size 512, plausible model/serial/sysfs/
      identity, `mount_summary: "not mounted"`; image `ImageRef` with a temp
      `.iso` path, size 1 MiB, sha256 `"0"`×64, `ImageKind::Iso`,
      `is_windows: false`, `ImageReport::default()`. No image file is read or
      written — the planner only sniffs the path/kind, and the helper refuses
      at rule 4 (device node) before it would hash the image at rule 6.
   2. `Run::start(&mut gui)` → assert `Confirming`.
   3. `Run::confirm()` → assert the all-`None` `Running` state and clone the
      confirmed `Plan`.
   4. `locate_helper()` derives `<target>/<profile>/furus-helper` from
      `current_exe().parent().parent()` (works for debug/release/custom
      target dirs); if missing, runs `cargo build -p furus-helper` once from
      the workspace root (`CARGO_MANIFEST_DIR`'s parent's parent) and retries,
      with an explicit panic message if still absent.
   5. Probe `unshare -Ur true`; on any failure `eprintln!` a SKIP reason and
      `return` (no fallback to a stub). The probe passed here.
   6. `PkexecTransport::with_command("/bin/sh", ["-c", script])` with
      `script = "exec unshare -Ur '<abs-helper-path>' \"$@\""` (path shell-quoted
      with the usual `'` → `'\''` substitution).
   7. `transport.start(&plan)`; consume `started.events` to exhaustion.
   8. Every event is asserted to be exactly one `Event::Done` carrying
      `Outcome::Refused { code: "not_a_block_device", .. }`; any other kind,
      any other outcome, a second `Done`, or a parser error fails the test.
      A transport-synthesised `Done` would carry `code: "exit"`, so this code
      proves the real helper validator ran.
   9. Feed every parsed `Event` to `run.apply(&event, Duration::from_secs(0))`.
   10. Assert `RunState::Finished(Outcome::Refused { code: "not_a_block_device", .. })`
       and `run.configuration_locked() == false`.
   No new dependencies, no `unsafe`, no async runtime, no sleeps, no added
   timeouts, no pkexec/polkit/D-Bus, no real block device, no disk writes.

2. **NEW `docs/handoffs/HANDOFF-S29-slice-3.md`** — this file.

No other files changed. `Cargo.toml` (workspace and crate), CI workflow,
`size-baseline.json`, `run.rs`, `state.rs`, `pkexec.rs`, helper sources and all
slice-1/slice-2 files are untouched. `git status --short` showed only the two
new files.

### Seams chosen (all pre-existing and public)

- `furus_gui::ipc::PkexecTransport::with_command(program, args_prefix)` — the
  documented test seam. It spawns
  `<program> <args_prefix> furus-helper --plan <FILE> --progress jsonl`.
- `HelperTransport::start(&Plan)` / `Started.events: EventStream` — the EventStream
  parses every stdout line with `furus_proto::from_jsonl_line` and filters by
  session, so consuming it exercises the production GUI parser.
- `furus_gui::run::{Run, RunState}` and `furus_gui::state::{GuiState,
  DeviceSelection, BootSelection}` public fields — a fixture can be built
  without any real image inspection; `ImageReport::default()` exists.
- `furus_proto::{Event, Completion, Outcome}` — pattern-matched directly.
- Helper `validate::device_node_checks` (validate.rs:317): `symlink_metadata`
  on the nonexistent `/dev/...` path returns `not_a_block_device` before
  `collect_candidates`, `check_image` or any executor step. Helper `main.rs`
  does the root check first (line 290), then load → validate → the single
  terminal `Done` (line 374).
- `current_exe()`-based binary discovery, with a one-shot `cargo build`
  fallback, because `CARGO_BIN_EXE_furus-helper` is not set for a furus-gui
  integration test.

### Gotchas / decisions

- **The suggested `shift` in the wrapper script was corrected.** The task
  text proposed `shift; exec unshare -Ur '<path>' "$@"` on the premise that
  `shift` drops the literal `furus-helper`. This is not how `sh -c` works:
  with `sh -c SCRIPT name arg...`, POSIX puts `name` in `$0` (not `$1`) and
  `$@` is already `arg...`. Verified locally:
  ```
  $ /bin/sh -c 'echo "zero=[$0]"; echo "at=[$@]"; shift; echo "after=[$@]"' \
      furus-helper --plan /tmp/x.json --progress jsonl
  zero=[furus-helper]
  at=[--plan /tmp/x.json --progress jsonl]
  after=[/tmp/x.json --progress jsonl]
  ```
  Keeping `shift` would have dropped `--plan` and made the helper fail with a
  usage error instead of the intended refusal. The test therefore uses
  `exec unshare -Ur '<path>' "$@"` with **no `shift`**, and the reasoning is
  recorded as a comment in the test. This is a correction inside the new
  test file only — no out-of-scope file was touched.
- The helper's pre-session refusal has an empty `session`, which
  `PkexecTransport.start()` picks up from the first line; `EventStream`'s
  session filter therefore lets the single `Done` through and `ProcessLines`
  ends the stream after it rather than synthesising a second `Done` from the
  non-zero exit.
- `unshare -Ur` maps the caller to uid 0 **inside the namespace only**; that
  is enough for the helper's `geteuid() == 0` check and creates no host root.
  The test still skips cleanly where user namespaces are disabled.
- Unverified branches: the SKIP branch (not taken — `unshare -Ur true`
  returns 0 here) and the `cargo build -p furus-helper` fallback (not taken —
  `target/debug/furus-helper` was present). The fallback may be susceptible
  to the parent cargo's target-dir lock in a cold build; if that ever bites,
  build the helper before running this test rather than changing the test.

### Verification (exact commands and results)

Run from `/home/hosi/dev/REA-Furus/furus` with
`export PATH="$HOME/.cargo/bin:$PATH"`.

```
cargo test -p furus-gui --test helper_wire
```
```
   Compiling furus-gui v0.1.0 (/home/hosi/dev/REA-Furus/furus/crates/furus-gui)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.77s
     Running tests/helper_wire.rs (target/debug/deps/helper_wire-92f093d71506c7ea)

running 1 test
test compiled_helper_refusal_drives_the_gui_parser_and_run_state_machine ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```
(First attempt failed to compile because `["-c", script]` mixed `&str` and
`String`; fixed to `["-c", script.as_str()]`. No other code change.)

```
cargo test -p furus-helper
```
```
test result: ok. 111 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 4.19s   (unit tests)
test result: ok.  11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s   (tests/cli.rs)
```
The 3 ignored tests are the pre-existing root/loop-device tests.

```
cargo xtask ci
```
Final line: `ci: all gates passed` (exit 0). Gates observed:
- `==> fmt` / `==> clippy` — clean (after `cargo fmt --all`; only the new test
  file changed).
- `==> test` — all workspace test binaries passed, including `helper_wire`.
- `==> assets --check` — `assets: 86 entries, 86 files verified`.
- `==> parity --check` — `parity: 2,709 data rows`, address sets match.
- `==> contract --check` — `contract: all identifiers match the single source
  of truth` (slice-1 gate still green).
- `==> size` — `furus: 1810152 / 3000000`, `furus-helper: 1406296 / 2500000`,
  `furus-gui: 12774280 / 14000000`, total 15990728;
  `size: within committed baseline allowance, all budgets OK`. These bytes
  are identical to `size-baseline.json` — **no size change**.
- `==> cargo-deny` — `advisories ok, bans ok, licenses ok, sources ok`;
  `SKIP (not installed): cargo-audit` (pre-existing, not a failure). The
  `warning[duplicate]` lines are pre-existing transitive-crate warnings.

### Remaining / next steps

- Slice 3/4 is complete and locally verified but **not committed and not
  pushed**. Hand this slice to the reviewer (one command, one review).
- Slice 4/4 (whatever the S29 plan defines next) must be opened as its own
  gated command and reviewed separately. Do not batch it with this slice.
- If a reviewer asks for the literal `shift`, point them at the `sh -c`
  experiment above: it would drop `--plan` and break the very end-to-end
  flow this slice exists to prove.
