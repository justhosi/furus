# S36 — Volume-label safety and log UX — FINAL HANDOFF (slice 5/5 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, code HEAD `78b8f07`
(`fix(gui): guard window close during active writes (S36.4)`); the four code
commits are `b1316ea`, `b09b3d7`, `cadf9bf`, `78b8f07`. `cargo`/`rustc` live in
`~/.cargo/bin`; prefix every cargo command with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S36 handoff. It records the four code slices and the
final documentation/acceptance slice. S36 prevents `mkfs` from failing *after*
a disk was wiped by validating volume labels up front against one shared,
on-disk-grounded rule; auto-sanitizes ISO labels in the GUI per filesystem;
adds a one-click **Copy log** button; and blocks window close while a write is
in flight. Working rule throughout: one slice at a time, coder then
independent reviewer.

## Status: ALL slices 1-5/5 complete and verified — local only, nothing pushed or tagged

All S36 code work is committed locally on top of the post-S35 tip `6c4d926`
(the lockfile-only `url` 2.5.9 bump):

| Commit | Slice | Subject |
|---|---|---|
| `b1316ea` | S36.1 | `fix(core,helper): validate volume labels before destructive steps` |
| `b09b3d7` | S36.2 | `fix(gui): sanitize volume labels for each filesystem` |
| `cadf9bf` | S36.3 | `feat(gui): add Copy log to clipboard` |
| `78b8f07` | S36.4 | `fix(gui): guard window close during active writes` |

Every one of the four commits carries `Reviewed-by: reviewer`. This final
slice (5/5) changes exactly three documentation files — `README.md`,
`TECHNICAL.md` and this handoff — and is left **uncommitted for the reviewer**;
the final docs commit is pending review. No source file, Cargo file, packaging
file or `size-baseline.json` was touched in this final slice. No
reset/rebase/amend/push/tag was performed. The published tag `v0.1.1` already
exists from an earlier release; S36 creates or moves no tags.

**The user has not authorized publishing any of this — S36 is ready for manual
sign-off but nothing may be pushed or tagged until that explicit permission is
given. Publication/tagging is left entirely to the manual maintainer /
`Publisher`; this work never pushes and never tags.**

Guardrails still in force: preserve workspace `unsafe_code = "deny"` and
crate-level `#![forbid(unsafe_code)]`; zero new `.unwrap()`/`.expect()` in
production code; zero new crates (the clipboard module shells out to existing
system helpers); one shared source of truth for label rules. The untracked,
user-owned `./build/` directory was never staged, deleted, read into docs or
otherwise touched; `dist` used only its default `target/dist/<triple>`
out-dir.

## Overall S36 slice plan (1/5 .. 5/5)

| Slice | Scope | Status |
|---|---|---|
| 1/5 | S36.1 — shared `furus_core::fs::label` `validate_label` / `sanitize_label` matching the real on-disk encoders; planner pre-flight of built Mkfs steps (`PlanError::Usage`, including the Windows→NTFS override); helper `check_steps` calls the shared validator and refuses with `invalid_label`, deleting private `label_ok` | **Complete, verified** — `b1316ea` |
| 2/5 | S36.2 — `GuiState` tracks `label_is_auto` + `raw_image_label`, sanitizes the ISO volume ID for the selected filesystem on analysis, re-clamps on filesystem change, clears auto on manual edit, and surfaces planner refusals before START | **Complete, verified** — `b09b3d7` |
| 3/5 | S36.3 — `clipboard.rs` with `ClipboardOutcome` + testable backend chain (Wayland: wl-copy/xclip/xsel; otherwise xclip/xsel/wl-copy), daemon-safe pipe hygiene, Copy log button beside Show log, async status via `invoke_from_event_loop` | **Complete, verified** — `cadf9bf` |
| 4/5 | S36.4 — `close-enabled` property, `RunView.close_enabled` conservative default, gated CLOSE click, and `on_close_requested` guard with the exact refusal note | **Complete, verified** — `78b8f07` |
| 5/5 | Final full gate, README S36 row, `TECHNICAL.md` S36 section, this handoff | **Complete; docs left uncommitted for reviewer** |

## Slice 1/5 — S36.1, what changed (commit `b1316ea`, `Reviewed-by: reviewer`)

`crates/furus-core/src/fs/label.rs` (new, 421 lines), `fs/mod.rs`,
`planner/mod.rs`, `furus-helper/src/validate.rs` and `size-baseline.json`.

- **One shared rule.** `validate_label(label, fs)` and
  `sanitize_label(raw, fs)` live in `furus_core::fs::label`, re-exported from
  `furus_core::fs`. Limits come from the repo's real encoders, not the PLAN:
  FAT32 11 ASCII bytes (controls incl. DEL, non-ASCII and
  `"*/:<>?\|` refused), exFAT 11 UTF-16 units (same forbidden set, DEL
  rejected here too), ext2/3/4 **16 ASCII bytes** (the PLAN's "UTF-8" is
  stricter in reality because `Options::with_label` checks `is_ascii()`),
  NTFS 32 UTF-16 units with no NUL, UDF **126 UTF-8 bytes** (the PLAN's "30"
  is stale). Empty is always "no label"; refusals are
  `CoreError::InvalidInput` naming the ceiling or offending character.
- **Sanitizer invariant.** Drop unstorable characters, trim, uppercase for
  FAT32, and truncate on a UTF-8 character boundary (FAT32/ext/UDF) or whole
  UTF-16 unit boundary (exFAT/NTFS, never splitting a surrogate pair).
  `validate_label(&sanitize_label(raw, fs), fs).is_ok()` holds for any input,
  including all-rejected text (result = empty). `Fedora-KDE-Live-45` →
  `FEDORA-KDE-` on FAT32.
- **Planner.** `planner::build` iterates the *built* `Step::Mkfs` list and
  maps a refusal to `PlanError::Usage` before sealing a `Plan`. Using built
  steps covers the Windows To Go → NTFS override (a 40-byte label legal on
  UDF is refused at NTFS's 32 units).
- **Helper.** `validate::check_steps` calls the shared validator and rejects
  with the distinct code `invalid_label` before touching or unmounting the
  device; the old private `label_ok` (32 printable ASCII chars) was deleted.
  The validator's exact message is carried into the rejection.
- **Baseline** — the only S36 write: helper 2,140,384 → 2,145,712 B.

### Verification — Slice 1/5

Workspace listing count 1957 (final S35) → **1970** (+13: 11 label unit tests
and 2 planner tests). `cargo test -p furus-core` and `-p furus-helper` pass.

## Slice 2/5 — S36.2, what changed (commit `b09b3d7`, `Reviewed-by: reviewer`)

`crates/furus-gui/src/state.rs`, `main.rs` and `main_tests.rs`.

- `GuiState` gains `label_is_auto` and `raw_image_label`; analysis start clears
  them, and `apply_image_analysis` stores the raw ISO volume ID and derives
  the displayed label with `sanitize_label` against the filesystem analysis
  just selected (NTFS for Windows, FAT32 otherwise).
- `set_volume_label` maps empty input to "no label" and ends auto tracking;
  `select_filesystem` re-derives an auto label from the raw ISO ID for the new
  filesystem, and re-sanitizes a manual label in place only if it is invalid
  there (without restoring auto tracking).
- A manual overlong label is refused by `planner::build` as
  `PlanError::Usage`, shown in `status_text()`, and START stays disabled —
  before any confirmation dialog or destructive action.

### Verification — Slice 2/5

Workspace listing count 1970 → **1976** (+6). Tests pin FAT32 clamping, the
NTFS→FAT32 switch, manual-label clamping, 20-byte manual refusal, and
re-analysis restoring auto tracking.

## Slice 3/5 — S36.3, what changed (commit `cadf9bf`, `Reviewed-by: reviewer`)

New `crates/furus-gui/src/clipboard.rs` (341 lines), `lib.rs`, `main.rs`,
`ui/main.slint` and `tests/render_smoke.rs`.

- `ClipboardOutcome { Copied, Unavailable, Failed(String) }` plus a private
  `ClipboardBackend` trait make the chain testable with fakes. Wayland
  (`WAYLAND_DISPLAY` set): `wl-copy` → `xclip -selection clipboard` →
  `xsel --clipboard --input`; otherwise `xclip` → `xsel` → `wl-copy`.
  `NotFound` → `Unavailable` (next backend), success short-circuits, a real
  `Failed` stops the chain, empty text returns `Failed("no text to copy")`
  without spawning. Failure strings are short ASCII (≤120 chars).
- **Pipe hygiene:** spawn with stdin piped, stdout `Stdio::null()`, stderr
  piped but never drained; write text, drop stdin for EOF, await only the
  spawned process's exit status on a background thread. This avoids the
  daemonized-clipboard-owner hang that `wait_with_output` would cause.
- Slint: Copy log sits beside Show log / Hide log in an 8px-spaced
  `HorizontalLayout`, enabled only when `log-text != ""`. `on_copy_log_clicked`
  copies the rendered `log_lines(...)`, runs on a `"furus-clipboard"` thread
  and publishes the exact note strings via `slint::invoke_from_event_loop`,
  then re-renders; thread-spawn failure has its own note.

### Verification — Slice 3/5

Workspace listing count 1976 → **1988** (+12). Tests cover chain order for
both sessions, Unavailable fallback, Copied short-circuit, Failed reporting,
exhausted chain, missing binary, exit-status mapping, empty text, failure
sanitization, and offscreen rendering of the new button.

## Slice 4/5 — S36.4, what changed (commit `78b8f07`, `Reviewed-by: reviewer`)

`crates/furus-gui/src/main.rs`, `main_tests.rs`, `tests/render_smoke.rs` and
`ui/main.slint`.

- `close-enabled` property drives the footer CLOSE button. `RunView.close_enabled`
  defaults to `false` and is `true` only at Idle and Finished(any outcome);
  Confirming and Running stay blocked from CONFIRM AND WRITE until the helper
  reaches a terminal state. `render` pushes it via `set_close_enabled`;
  `on_close_clicked` re-reads it under a short borrow before quitting.
- `ui.window().on_close_requested(...)` handles the window-manager `X`:
  blocked close sets `session.note` to exactly **"Write in progress — click
  CANCEL first or wait for it to finish before closing."**, re-renders and
  returns `KeepWindowShown`; otherwise `HideWindow`.
- The checksum modal's CLOSE (`on_checksum_close_clicked` → `close_checksum()`)
  is intentionally separate and not gated by this flag.

### Verification — Slice 4/5

Workspace listing count 1988 → **1990** (+2). Tests cover `run_view` close
state across Idle, Confirming, Running and every Finished outcome, plus
`set_close_enabled(false/true)` render smoke.

## Final acceptance gate — exact results (all run from repo root)

All commands run with `export PATH="$HOME/.cargo/bin:$PATH"`; full logs are in
`/tmp/opencode/s36/<gate>.log` (`list_count.txt`, `diff_check.log` alongside).

- `cargo fmt --all -- --check` → **exit 0**, clean.
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**, no
  warnings.
- `cargo test -p furus-helper` → **exit 0**: unit target **142 passed / 0
  failed / 3 ignored** + integration target **11 passed / 0 failed**.
- `cargo test -p furus-gui` → **exit 0**: **112 lib + 17 bin + 1 helper_wire +
  5 render_smoke = 135**, 0 failed (doc-tests 0).
- `cargo test --workspace` → **exit 0**: **1961 passed / 0 failed / 29 ignored
  = 1990** across 30 result lines.
- `cargo test --workspace -- --list | grep -cE ': test$'` → **1990**.
- `cargo xtask qa` → **exit 0, "qa: all suites passed"**. All tier1 suites plus
  `tier2/bios-smoke`, `tier2/bios-bootloaders`, `tier2/uefi-ntfs-ovmf` pass.
  Documented pre-existing skips: `tier1/pipeline-loop` (loop-device /
  throughput needs `--privileged`) and one caller-supplied-`grldr` QEMU ignore
  (`grub4dos_boots_to_its_prompt_in_qemu`).
- `cargo xtask dist` (default out-dir only — **not** `./build`) → **exit 0**.
  Artifact `target/dist/x86_64-unknown-linux-gnu/furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz`,
  **8,247,623 B**, SHA256
  `4522d3d13431a3fa000348df6d6aeef84f1a0556cfc3ba72bf49dc30617d551c` (from
  `SHA256SUMS`); `sha256sum -c SHA256SUMS` → **OK**. `.deb` skipped only
  because `dpkg-deb` is not installed (environmental).
- `cargo xtask size` → **exit 0, "within committed baseline allowance, all
  budgets OK"**: furus **1,813,160** / 3,000,000, furus-helper **2,145,712** /
  2,500,000, furus-gui **12,808,072** / 14,000,000, total **16,766,944 B**.
  No baseline write in this slice.
- `cargo xtask ci` → **exit 0, "ci: all gates passed"**: fmt, clippy, test,
  assets `--check`, parity `--check`, contract `--check` and size all pass;
  cargo-deny reports `advisories ok, bans ok, licenses ok, sources ok`.
  `SKIP (not installed): cargo-audit` — pre-existing environmental skip.
- `git diff --check` → **exit 0**, clean.

### Test counts — progression

Workspace listing count / total: **1957** (final S35) → **1970** (S36.1, +13)
→ **1976** (S36.2, +6) → **1988** (S36.3, +12) → **1990** (S36.4, +2).
Final `cargo test --workspace`: 1928 passed / 29 ignored (S35) → 1961 passed /
29 ignored (S36); the ignored count stayed at 29.

### Size-baseline delta — S36.1 only

`size-baseline.json` was written exactly once in S36, in S36.1:
`furus-helper` **2,140,384 → 2,145,712 B** (shared label code). No later S36
slice wrote it, and this final slice makes no baseline write. The committed
baseline still records furus **1,810,504 B** and furus-gui **12,806,408 B**;
current furus (**1,813,160 B**) and furus-gui (**12,808,072 B**) drift within
the committed allowance. Do NOT run `--write-baseline`.

## Non-blocking reviewer notes (accepted, not fixed)

- **stderr is never drained.** `CommandBackend` pipes stderr for the design
  but deliberately never reads it to EOF, because a daemonized clipboard
  owner inherits the descriptor and would hang a drain. Failure causes come
  from exit status and sanitised spawn/write errors, not helper output.
- **`Failed` short-circuits the clipboard chain.** Only `Unavailable`
  (binary missing) tries the next helper; a helper that exists but fails
  stops the chain. This is intentional — a real failure should be reported,
  not hidden by trying a different backend.
- **`session.note` refusal text persists until the next action.** The close
  guard's "Write in progress…" note is surfaced through
  `status_with_device_warning` and is cleared by the next user action that
  resets the note; it does not auto-expire on a timer.
- **Checksum-modal CLOSE is intentionally separate.** Its own close callback
  dismisses the checksum overlay and is not governed by
  `RunView.close_enabled`; only the window/footer close is write-gated.

## Unchanged / pre-existing (not S36 regressions)

- `cargo-audit` not installed → `ci` prints `SKIP (not installed)`.
- `qa` privileged `tier1/pipeline-loop` skip and one QEMU `grldr` ignore —
  environmental / caller-supplied resource.
- `.deb` packaging skipped because `dpkg-deb` is absent.
- Duplicate `zbus` / `zbus_macros` lock warnings — pre-existing.
- Rustdoc was not re-run in this final gate (pre-existing S33 situation); out
  of scope for S36.

## Manual live-desktop sign-off checklist — maintainer BEFORE Publisher sign-off

Unchecked on purpose; these need a real display, a real removable USB and a
Polkit session and cannot be proven by CI. Check each box after testing on the
target desktop:

- [ ] ISO analysis with `Fedora-KDE-Live-45` while FAT32 is selected shows
      `FEDORA-KDE-` (≤11 bytes) and START is enabled.
- [ ] Switching File system NTFS → FAT32 re-clamps the auto label to a valid
      FAT32 value; a manual overlong label on FAT32 refuses with a clear
      status message and START disabled, before any confirmation/disk write.
- [ ] Labels remain storable and correctly truncated for exFAT, ext2/3/4,
      NTFS and UDF, including non-ASCII / forbidden-character input.
- [ ] **Copy log** is disabled with an empty log, enabled after activity;
      clicking it copies the full formatted log with no GUI hang, with
      `wl-copy` on Wayland and `xclip`/`xsel` on X11, and with no clipboard
      helper installed (status note names the missing tools).
- [ ] Pasting the copied text into an editor/terminal shows clean, complete
      log lines.
- [ ] Starting a write greys out footer **CLOSE** and the window `X` refuses
      to close with the "Write in progress — click CANCEL first or wait for it
      to finish before closing." note.
- [ ] After CANCEL or a finished run, **CLOSE** re-enables and the window
      closes cleanly.
- [ ] The checksum modal's own CLOSE still dismisses the overlay independently.
- [ ] The log drawer and the new two-button row render legibly in both dark
      and light themes.

## Publication stance

No push and no tag. S36 is complete and locally reviewed, but leaves all
publication and tagging to manual maintainer / `Publisher` sign-off. Do not
create, move or force-update `v0.1.1`, and do not push any local commits, until
the user explicitly authorizes it. The final documentation commit is still
pending reviewer. The manual checklist above is the last gate before Publisher
may act. The untracked `./build/` directory is user-owned and must not be
staged, deleted or treated as a repo release artifact.
