# S34 — Live-desktop fixes after S33 — FINAL HANDOFF (slice 3/3 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, code HEAD `d241942`
(`fix(gui): theme the log drawer with Palette colors (S34.2)`); the two code
commits are `6aaefd4` and `d241942`. `cargo`/`rustc` live in `~/.cargo/bin`;
prefix every cargo command with `export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S34 handoff. It records the two code slices and the
final documentation/acceptance slice. S34 fixes two live-desktop bugs observed
after S33: the `pkexec` helper path failure on an installed system (S34.1) and
the invisible `Show log` drawer text (S34.2). Working rule throughout: one
slice at a time, coder then independent reviewer.

## Status: ALL slices 1-3/3 complete and verified — local only, nothing pushed or tagged

All S34 work is committed locally on top of the S33 tip `fffec73`:
`6aaefd4` (S34.1, pkexec installed-helper path) and `d241942` (S34.2, themed log
drawer), both carrying `Reviewed-by: reviewer`. This final slice changes only
three documentation files (`README.md`, `TECHNICAL.md` and this handoff) and
is left uncommitted for the reviewer. No reset/rebase/amend/push/tag was
performed. The published tag `v0.1.1` (tag object `4c6e4a6` → commit
`f763fdc`) already exists and is published; S34 creates or moves no tags.

**The user has not authorized publishing any of this — S34 is ready for manual
sign-off but nothing may be pushed or tagged until that explicit permission is
given. Publication is left to manual maintainer / `Publisher` sign-off only.**

Guardrails still in force: preserve `unsafe_code = "deny"` and crate-level
`#![forbid(unsafe_code)]`; no new `.unwrap()`/`.expect()` in production code;
do not rename `furus-linux`, `org.furuslinux.*`, `/run/furus-linux` or the
`$XDG_*_HOME/furus-linux` paths. Do not touch `size-baseline.json`, the D-Bus
service file, or the untracked `./build/` directory — `build/` is user-owned
and was left completely untouched (not staged, not deleted, not written into).
The `dist` gate used only its default `target/dist/<triple>` out-dir.

## Overall S34 slice plan (1/3 .. 3/3)

| Slice | Scope | Status |
|---|---|---|
| 1/3 | S34.1 — resolve the installed `furus-helper` path for `pkexec` using the single-source `furus_proto::HELPER_BIN_PATH` and a pure 3-step resolver; 3 hermetic unit tests; no duplicated path literal; no packaging change | **Complete, verified** — `6aaefd4` |
| 2/3 | S34.2 — theme the `Show log` drawer with `Palette` colors and `Flickable` sizing; add the `log_drawer_renders_with_contrast` RGB render-smoke test | **Complete, verified** — `d241942` |
| 3/3 | Final full gate, README slice-table row, `TECHNICAL.md` S34 section, this handoff | **Complete; docs left uncommitted for reviewer** |

## Slice 1/3 — S34.1, what changed (commit `6aaefd4`)

Exactly one file changed: `crates/furus-gui/src/ipc/pkexec.rs`
(93 insertions / 4 deletions).

- **Root cause.** `PkexecTransport::start` passed the bare name
  `"furus-helper"` to `pkexec`. `pkexec` sanitizes `PATH` and the sanitized
  search path does not contain `/usr/libexec`, so on an installed system the
  helper was not found and the spawn failed with exit 127
  (`Cannot run program furus-helper: No such file or directory`). Local
  `target/release` / `cargo run` builds masked the bug, so it only surfaced on
  a real installed desktop.
- **Single-source path, no duplicate literal.** The workspace already defines
  `furus_proto::HELPER_BIN_PATH` = `/usr/libexec/furus-helper` in
  `crates/furus-proto/src/service.rs`, re-exported from `furus_proto`. The GUI
  now imports that constant instead of hard-coding the path anywhere. The
  D-Bus service file `packaging/dbus/org.furuslinux.Helper1.service` already
  carried the matching `Exec=/usr/libexec/furus-helper --dbus`, so no packaging
  change was needed.
- **Resolver.** `PkexecTransport` gained a `helper_program: PathBuf` field.
  `new()` calls the pure `resolve_helper_program(current_exe,
  Path::new(HELPER_BIN_PATH))`, which returns (1) the installed
  `HELPER_BIN_PATH` when it is a file; (2) a `furus-helper` sibling next to
  `current_exe` when present (local builds); else (3) the bare
  `"furus-helper"`. `start()` now passes `.arg(&self.helper_program)`, so
  installed systems launch the absolute path that survives pkexec's PATH
  sanitization. Taking inputs as arguments keeps the resolver pure and
  root-free to test.
- **Test seam kept bare.** `with_command` and
  `with_command_and_authorization_timeout` still set bare `"furus-helper"` as
  `helper_program`. They drive the existing argv/wire protocol tests through a
  command stub, not a real pkexec; keeping the bare name leaves every existing
  argv assertion and the helper JSONL/run-state wire test unchanged, isolating
  the fix to the production launch path.
- **Tests.** Three new hermetic tests with unique `temp_dir()` fixtures:
  installed-file-wins even with a sibling present, sibling fallback, and bare
  fallback both with and without `current_exe`. They never create files under
  `/usr/libexec`.

### Verification — Slice 1/3

- `cargo test -p furus-gui pkexec` → **16 passed**.
- `cargo test -p furus-gui` → **113 passed** at this point (before the S34.2
  render-smoke test).
- D-Bus sanity: `packaging/dbus/org.furuslinux.Helper1.service` already had
  `Exec=/usr/libexec/furus-helper --dbus`; no packaging change. `cargo xtask
  ci` contract check passed.

## Slice 2/3 — S34.2, what changed (commit `d241942`)

Exactly two files changed: `crates/furus-gui/ui/main.slint` (16 insertions /
3 deletions) and `crates/furus-gui/tests/render_smoke.rs` (140 insertions).

- **Root cause.** The `Show log` drawer hard-coded `background: #f6f6f6` while
  the log text inherited the dark theme's light foreground, producing
  light-on-white, effectively invisible text.
- **Themed drawer.** It is now an outer `Rectangle` with `min-height: 120px`,
  `background: Palette.alternate-background`, `border-width: 1px`,
  `border-color: Palette.border`, `border-radius: 4px`, `clip: true`; an inner
  `Flickable` with `width/height: 100%` and
  `content-height: log-text.preferred-height + 16px` so long logs scroll; and
  `log-text` at `x/y: 8px`, `width: parent.width - 16px`,
  `color: Palette.foreground`, `wrap: word-wrap`, with an empty-state fallback
  `"No log entries yet."`. `Palette` was already imported. Color audit: the
  only remaining `#` colors in `main.slint` are `#000000aa` on the two
  intentional modal scrims.
- **Render-smoke test.** `log_drawer_renders_with_contrast` renders a
  closed-log baseline into an `RgbPixel` buffer, opens the drawer with two log
  lines (both modals closed), re-renders into the same `ReusedBuffer`, diffs to
  locate the changed band, and asserts the frame changed, the band is ≥100 px
  tall and the band has ≥3 distinct colors. Slint 1.19's platform context is
  thread-local, so the test installs the software adapter once per test thread
  with a thread-local `Once` and serializes rendering with a global `Mutex`.
  Reviewer mutation testing in a throwaway worktree confirmed the guard:
  removing the drawer collapses the band to a 12 px button-label region
  (fails ≥100 px); a constant-fill drawer yields 2 colors (fails ≥3).

### Verification — Slice 2/3

- `cargo test -p furus-gui --test render_smoke` → **3 passed**.
- `cargo test -p furus-gui` → **114 passed** (96 lib + 14 bin + 1 helper_wire +
  3 render_smoke).
- Two extra `--test-threads=1` runs of the render smoke passed.

## Reviewer nit (non-blocking) — record for the next context

The new test guards the *outcome* (visible contrast, not a constant fill),
not the specific theme choice. Its ≥3 distinct colors are dominated by
antialiasing grays and the assertion would also pass against the old
`#f6f6f6` drawer, because text still renders over it. Dark/light theme
readability is therefore **not** proven by automation and remains a manual
desktop check (see checklist below). This did not block review.

## Final acceptance gate — exact results (all run from repo root)

All commands run with `export PATH="$HOME/.cargo/bin:$PATH"`.

- `cargo fmt --all -- --check` → **exit 0** (clean).
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**, no
  warnings.
- `cargo test --workspace` → **exit 0**: **1892 passed / 0 failed / 29 ignored
  = 1921** across 29 result lines (full log `/tmp/opencode/s34-final-test.log`).
- `cargo test --workspace --all-targets -- --list | grep -cE ': test$'` →
  **1921**.
- `cargo xtask ci` → **exit 0, "ci: all gates passed"**
  (log `/tmp/opencode/s34-final-ci.log`); contract check green. Only the
  pre-existing duplicate-`zbus`/`zbus_macros` lock warnings and
  `SKIP (not installed): cargo-audit` appear.
- `cargo xtask qa` → **exit 0, "qa: all suites passed"**
  (log `/tmp/opencode/s34-final-qa.log`); real `PASS tier2/bios-bootloaders`
  and `PASS tier2/uefi-ntfs-ovmf`; only the documented
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged`
  skip.
- `cargo xtask dist` (default out-dir only — **not** `./build`) → **exit 0**
  (log `/tmp/opencode/s34-final-dist.log`). Artifact
  `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz`, **7,902,790 B**, SHA256
  `f83cbf60ecf51d1e4227ba9203c01725f7e818d897ff8692a9bea51c3a216dde`
  (from `SHA256SUMS`); `sha256sum -c SHA256SUMS` → **OK**. Default out-dir is
  `target/dist/x86_64-unknown-linux-gnu`. `.deb` skipped only because
  `dpkg-deb` is not installed (environmental). This size/hash differs from
  S33.8's 7,902,205 B / `76e3bc6d…` because S34.1/S34.2 changed shipped
  source.
- `cargo xtask size` → **exit 0, "within committed baseline allowance, all
  budgets OK"**: furus 1,810,264 / 3,000,000, furus-helper 1,406,296 /
  2,500,000, furus-gui 12,790,408 / 14,000,000, total 16,006,968 B.
- `git diff --check` → **exit 0**, clean.

### Test counts — before and after

- Workspace listing count / total: **1917** (final S33) → **1921** (S34),
  delta **+4** = 3 resolver tests (S34.1) + 1 log-drawer test (S34.2).
- `cargo test --workspace`: 1888 passed / 0 failed / 29 ignored (1917) at
  S33 → 1892 passed / 0 failed / 29 ignored (1921) at S34.
- `furus-gui`: 113 passed after S34.1 → 114 passed after S34.2
  (96 lib + 14 bin + 1 helper_wire + 3 render_smoke); `pkexec` filter 16
  passed; `render_smoke` target 3 passed.

### Size-baseline delta — none needed

`size-baseline.json` is **unchanged** (do NOT run `--write-baseline`). It
still records furus **1,810,504 B**, furus-helper **1,406,392 B**, furus-gui
**12,806,408 B**. Current release binaries are furus **1,810,264 B**,
furus-helper **1,406,296 B**, furus-gui **12,790,408 B** (furus-gui grew 768 B
from the S34.1 launch-path code); all are within budget and within the
committed allowance, so no baseline refresh is required.

### Pre-existing, unrelated skips / warnings (not S34 regressions)

- `cargo-audit` — `SKIP (not installed): cargo-audit` in `xtask ci`.
- `tier1/pipeline-loop` — loop-device / throughput tests need `--privileged`
  in `xtask qa`.
- `.deb` — skipped because `dpkg-deb` is not installed (environmental).
- duplicate `zbus`/`zbus_macros` lock warnings.
- rustdoc: this final gate did **not** re-run `cargo doc`. The pre-existing
  S33 situation is carried forward: `RUSTDOCFLAGS="-D warnings" cargo doc -p
  furus-core --no-deps` reports 226 pre-existing errors on both pre- and
  post-refactor trees (relocated by the S33 module split, not introduced);
  `cargo doc -p xtask --no-deps` is clean. Not re-verified here and out of
  scope for S34.

## Manual desktop sign-off checklist — maintainer BEFORE Publisher sign-off

Unchecked on purpose; these need a real display and Polkit session and cannot
be proven by CI. Check each box after testing on the target desktop:

- [ ] With a package-installed helper, launching a write via `pkexec` succeeds
  without exit 127 — Polkit launches `/usr/libexec/furus-helper` from the
  resolved absolute path (S34.1).
- [ ] A local build (`target/release` / `cargo run`) still finds the sibling
  `furus-helper` next to the GUI binary (resolver rule 2).
- [ ] The D-Bus activation path still works — the service file's
  `Exec=/usr/libexec/furus-helper --dbus` is unaffected.
- [ ] The `Show log` drawer text is readable in **both** dark and light themes
  (the render-smoke test cannot prove theme readability — see reviewer nit).
- [ ] With no log entries, the drawer shows the `"No log entries yet."`
  fallback.
- [ ] A long log scrolls inside the drawer via the `Flickable` instead of
  overflowing the window.
- [ ] The confirm and checksum modals from S33.8 are unchanged and still
  readable/themed (only `#000000aa` scrims remain).

## Publication stance

No push and no tag. S34 is complete and locally reviewed, but leaves all
publication to manual maintainer / `Publisher` sign-off. Do not create, move
or force-update `v0.1.1`, and do not push any local commits, until the user
explicitly authorizes it. The manual checklist above is the last gate before
Publisher may act. The untracked `./build/` directory is user-owned and must
not be staged, deleted or treated as a repo release artifact.
