# S35 — Real helper write pipeline, safe auto-unmount, streamed verification — FINAL HANDOFF (slice 5/5 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, code HEAD `0fc6f08`
(`fix(helper,gui): stream image verification with immediate feedback (S35.3)`);
the four code commits are `94728b2`, `d7765f`, `8c3038d`, `0fc6f08`.
`cargo`/`rustc` live in `~/.cargo/bin`; prefix every cargo command with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the authoritative S35 handoff. It records the four code slices and the
final documentation/acceptance slice. S35 makes the privileged helper run the
real verified write pipeline, safely auto-unmount non-system removable media in
the host namespace with a strict post-unmount re-check, and stream cancellable
SHA-256 image verification with immediate GUI feedback. Working rule
throughout: one slice at a time, coder then independent reviewer.

## Status: ALL slices 1-5/5 complete and verified — local only, nothing pushed or tagged

All S35 code work is committed locally on top of the S34 tip `f720f24`:

| Commit | Slice | Subject |
|---|---|---|
| `94728b2` | S35.1 | `feat(helper): run the real verified write pipeline` |
| `d7765f` | S35.2a | `fix(core,helper,gui): allow safe auto-unmount of removable media` |
| `8c3038d` | S35.2b | `fix(helper): unmount removable media in the host namespace` |
| `0fc6f08` | S35.3 | `fix(helper,gui): stream image verification with immediate feedback` |

All four carry `Reviewed-by: reviewer`. This final slice (5/5) changes only
three documentation files — `README.md`, `TECHNICAL.md` and this handoff — and
is left uncommitted for the reviewer. No source file, `size-baseline.json`,
Cargo file or packaging file was touched in this final slice. No
reset/rebase/amend/push/tag was performed. The published tag `v0.1.1` already
exists from an earlier release; S35 creates or moves no tags.

**The user has not authorized publishing any of this — S35 is ready for manual
sign-off but nothing may be pushed or tagged until that explicit permission is
given. Publication/tagging is left entirely to the manual maintainer /
`Publisher`; this work never pushes and never tags.**

Guardrails still in force: preserve `unsafe_code = "deny"` and crate-level
`#![forbid(unsafe_code)]`; no new `.unwrap()`/`.expect()` in production code;
no dependency / `Cargo.lock` / `Cargo.toml` change (the user explicitly deferred
`RUSTSEC-2026-0592`); do not rename `furus-linux`, `org.furuslinux.*`,
`/run/furus-linux` or the `$XDG_*_HOME/furus-linux` paths. The untracked
`./build/` directory is user-owned and was left completely untouched (not
staged, not deleted, not written into). The `dist` gate used only its default
`target/dist/<triple>` out-dir.

## Overall S35 slice plan (1/5 .. 5/5)

| Slice | Scope | Status |
|---|---|---|
| 1/5 | S35.1 — real verified write pipeline in `furus-helper`: `HelperReporter` (all five core `Event` variants → proto log/progress, session tag + `device_text`), `outcome_from_core_error`, `PlanRunner`/`RealRunner` reusing CLI opener derivation and `RunOptions{verify,badblocks,retries:3,retry_delay:5s,reset_usb:false}`, cancel probe `|| cancel.is_set()`; wired into argv + D-Bus via `Registry::with_runner`; `CurrentExecutor` now test-only, fixtures use `StubRunner` | **Complete, verified** — `94728b2` |
| 2/5 | S35.2a — safe auto-unmount policy: `furus_core::safety::is_protected_mountpoint` (boundary-aware protected list) and `judge_with_policy(target, allow_auto_unmount)`; strict `judge` delegates with false; sole `Reason::Mounted` exception for non-system removable non-protected; helper fast validation uses true; GUI annotation is display-only | **Complete, verified** — `d7765f` |
| 3/5 | S35.2b — host-namespace unmount: `crates/furus-helper/src/unmount.rs` `Unmounter`/`LiveUnmounter`, devnum for disk + every partition, scan/dedupe/sort deepest-first, protected paths fail closed before any unmount, `MountOps::unmount(path,false)` (never `MNT_DETACH`), EBUSY guided message, Info log per unmount, then `validate::recheck_strict` with plain `judge`; fixtures use `NoopUnmounter`/`FailingUnmounter`; helper-only baseline refresh | **Complete, verified** — `8c3038d` |
| 4/5 | S35.3 — streamed verification: `check_image` reduced to four fast metadata checks; `verify_image_digest` reuses `hash_file_cancellable` (1 MiB chunks, cancel between reads), immediate Info log + throttled Progress (`verify_image`, step 0, terminal 100%), cancel→CANCELLED_CODE / mismatch→`image_changed` / I/O→`image_unreadable` before unmount/write; `Cancel::flag()` exposes the `AtomicBool`; GUI sets "Authenticating and starting helper…" after render, before worker spawn | **Complete, verified** — `0fc6f08` |
| 5/5 | Final full gate, README S35 row, `TECHNICAL.md` S35 section, this handoff | **Complete; docs left uncommitted for reviewer** |

## Slice 1/5 — S35.1, what changed (commit `94728b2`)

New `crates/furus-helper/src/pipeline.rs` (717 lines). Previously the helper's
run step was a stub (`exec::CurrentExecutor`, now `#[cfg(test)]` test-only) that
emitted canned events. S35 makes production actually execute the CLI-equivalent
core pipeline.

- **`HelperReporter`** implements `furus_core::pipeline::Reporter` over a
  `&mut dyn ProgressSink`, a session id and a mutable step index. It maps all
  five core events to proto `Event::Log` / `Event::Progress`, each tagged with
  the session and sanitized via `furus_core::text::device_text` (trim + control/
  non-ASCII mapping) before reaching the transport: `StepStarted` sets the step
  index and logs `step i/total: …`; `StepFinished` logs elapsed ms; `Progress`
  becomes `Progress::new(session, step, device_text(step), done, total)`;
  `Message` becomes a log with parsed level (fallback `Info`); `Finished` logs
  total ms.
- **`outcome_from_core_error`** classifies any `CoreError` (recursing through
  `CoreError::Step`) and mirrors the CLI exit mapping with two softened cases:
  `Cancelled` → `Outcome::Cancelled`; `NotImplemented` / `InvalidInput` →
  `Refused` (`not_implemented` / `invalid_plan`); `Io`, `Verify` and all others
  → `Failed` (`io` / `verify` / `other`). The message is the full outer
  `Display`, so a step name is never lost.
- **`PlanRunner` / `RealRunner`**: `PlanRunner: Send + Sync` is the seam both
  entry points call. `RealRunner` reuses the CLI's `opener_table_kind` /
  `table_kind` / `layout_kind` (a cross-step disagreement refuses with
  `invalid_plan` rather than guessing), reuses the validation env's sysfs root
  for `DeviceOpener`, and calls `furus_core::pipeline::run` with
  `RunOptions{verify: plan.options.verify, badblocks: plan.options.bad_blocks,
  retries: 3, retry_delay: 5s, reset_usb: false}` and a cooperative cancel
  probe `&|| cancel.is_set()` (never a forced thread kill).
- **Wiring**: production argv and D-Bus paths inject `RealRunner` via
  `Registry::with_runner`; D-Bus fixtures inject a `StubRunner` and never touch
  a real device. `CurrentExecutor` is now test-only. The helper's `Done`
  outcome now reflects a real wipe/partition/format/write/bootloader run.

### Verification — Slice 1/5

Workspace listing count 1921 (S34) → **1935** (14 new helper pipeline tests).
The helper crate's pipeline tests cover reporter event mapping, `device_text`
sanitization, the full error→outcome matrix, opener derivation and cancel
probing.

## Slice 2/5 — S35.2a, what changed (commit `d7765f`)

`crates/furus-core/src/safety.rs` (+263), `crates/furus-helper/src/validate.rs`,
`crates/furus-gui/src/main.rs` and `main_tests.rs`.

- **`is_protected_mountpoint(path)`** is the shared, root-free definition of a
  system path auto-unmount must never touch, kept in `furus-core` so the pure
  crate does not depend on `furus-linux`. Boundary-aware list: `/`, `/boot`,
  `/boot/efi`, `/home`, `/usr`, `/var`, `/etc`, `/opt`, `/srv`, `/root`,
  matched via `strip_prefix` with exact-or-`/`-boundary, so `/bootable` and
  `/homebrew` do not match and `/` is the exact root only.
- **`judge_with_policy(target, allow_auto_unmount)`**: plain `judge` now
  delegates with `false` (strict/fail-closed, also the post-unmount re-check).
  The one relaxation is at rule 6 (`Reason::Mounted`): skip only when
  `allow_auto_unmount` is true and the target is removable, not a system disk,
  and mounted at a non-protected path. Every other refusal stays unchanged and
  in order; a system disk is refused before mount state is considered. Helper
  fast validation passes `true`; the GUI's `" (will be unmounted automatically)"`
  suffix is a display-only annotation that changes no verdict. Callers must
  re-check with plain `judge` after unmounting (S35.2b does).

### Verification — Slice 2/5

Workspace listing count 1935 → **1941** (+6). Pairwise safety tests pin every
refusal's precedence and confirm `judge_with_policy(..., true)` relaxes only
the mounted-removable case and nothing else.

## Slice 3/5 — S35.2b, what changed (commit `8c3038d`)

New `crates/furus-helper/src/unmount.rs` (661 lines) plus `dbus.rs`,
`dbus_tests.rs`, `main.rs`, `validate.rs` and a helper-only baseline refresh.

- **`Unmounter` / `LiveUnmounter`**: given the validated device and env, derive
  the device number via `furus_linux::mounts::dev_number` for the disk and every
  partition, scan all matching mount entries, dedupe by path, sort deepest-first
  (depth then length descending) so nested mounts release before parents.
- **Fail-closed protection**: before any unmount call, every candidate path is
  checked with `is_protected_mountpoint`; a protected path aborts the whole step
  with code `protected_mount` and an ASCII guided message ("…unmount it
  manually and rebuild the plan") — nothing is unmounted.
- **Unmount mechanics**: `MountOps::unmount(path, false)` — `detach = false`
  always, never `MNT_DETACH`. `EBUSY` becomes an ASCII guided message naming the
  busy mount; each success emits a session-tagged `Info` log. Hermetic fixtures
  use `NoopUnmounter` and `FailingUnmounter` (injectable via
  `Registry::with_unmounter`); `FailingUnmounter` can fail by kind or raw errno
  or succeed.
- **Strict re-check**: `validate::recheck_strict` re-reads `mountinfo` and
  applies plain `judge`, so any surviving/new mount is refused after unmount.
- **Pinned ordering in both entry points** (argv `run`, D-Bus `WorkerRun::run`):
  fast validate → [digest slot from S35.3] → host unmount → strict recheck →
  mount namespace → runner. Ordering tests in both paths assert this sequence.
- **Baseline**: `size-baseline.json` refreshed for the helper only,
  2,126,752 → 2,140,384 B; no change to furus or furus-gui. This was the
  **last** baseline write in S35; S35.1 had already refreshed the helper
  baseline earlier in the slice (1,406,392 → 2,126,752 B).

### Verification — Slice 3/5

Workspace listing count 1941 → **1952** (+11). Unmount tests cover deepest-first
sorting, dedupe, never-`MNT_DETACH`, protected-path fail-closed (including a
protected path listed second), EBUSY messaging and strict re-check behaviour.

## Slice 4/5 — S35.3, what changed (commit `0fc6f08`)

`crates/furus-helper/src/validate.rs` (+219), `dbus.rs`, `dbus_tests.rs`,
`exec.rs`, `main.rs`, plus the GUI `main.rs`.

- **`check_image`** is now only the four fast metadata checks (metadata read,
  regular file, world-writable bit clear, recorded size). It never reads image
  bytes, keeping fast validation off the multi-gigabyte path.
- **`verify_image_digest(plan, sink, session, cancel)`** reuses
  `furus_core::hash::hash_file_cancellable` (1 MiB chunks, cancel probed between
  reads). It emits an immediate `Info` log `Verifying image SHA-256...` before
  the first read, throttles progress to percent changes (op `verify_image`,
  step 0) plus a guaranteed terminal 100%, and maps cancel→`CANCELLED_CODE`,
  mismatch→`image_changed`, I/O→`image_unreadable`. Both entry points run it
  before unmount/write; `CANCELLED_CODE` maps to `Outcome::Cancelled`, other
  rejects to `Failed`, and the run still ends on exactly one terminal `Done`.
- **`exec::Cancel::flag()`** exposes the shared `&AtomicBool` inside the
  `Arc<AtomicBool>` so the hash helper shares the cancellation object the
  runner probes with `cancel.is_set()`.
- **GUI**: `ui.on_confirm_clicked` calls `render(...)` first, then sets both
  `step_text` and `status_text` to `"Authenticating and starting helper…"`
  before spawning the worker thread — feedback while pkexec authenticates and
  the digest streams.

### Verification — Slice 4/5

Workspace listing count 1952 → **1957** (+5). Tests cover immediate-log,
throttled-progress ending at 100%, cancel/mismatch/unreadable codes, and the
fast-check codes for unreadable/changed images.

## Reviewer nit and known residual (both non-blocking)

- **Reviewer nit (comment-only).** The `dbus.rs` module header and `WorkerRun`
  field comments from S35.2b still describe only unmount + strict re-check
  before the namespace, without naming the inserted digest phase. The
  implementation-site comments in `main.rs`/`dbus.rs` and the ordering tests do
  pin digest-before-unmount, so behaviour is correct; the mismatch did not
  block review.
- **Known TOCTOU residual (unchanged).** Image and device node are reopened by
  path when S17 streams the write, so bytes can change between digest
  verification and the write; PLAN §6's "image passed as an open fd" is not
  implemented. The fast checks + streamed digest narrow but do not close the
  window; closing it is an S17 obligation and out of scope here.

## Final acceptance gate — exact results (all run from repo root)

All commands run with `export PATH="$HOME/.cargo/bin:$PATH"`; full logs are in
`/tmp/opencode/s35/<gate>.log` and `.summary`.

- `cargo fmt --all -- --check` → **exit 0**, clean.
- `cargo clippy --workspace --all-targets -- -D warnings` → **exit 0**, no
  warnings.
- `cargo test --workspace` → **exit 0**: **1928 passed / 0 failed / 29 ignored
  = 1957** (30 result lines).
- `cargo test --workspace -- --list | grep -cE ': test$'` → **1957**.
- `cargo test -p furus-helper` → **exit 0**: unit target **142 passed / 3
  ignored** (145 tests) + integration target **11 passed**.
- `cargo xtask qa` → **exit 0, "qa: all suites passed"**. All tier1 suites plus
  `tier2/bios-smoke`, `tier2/bios-bootloaders`, `tier2/uefi-ntfs-ovmf` pass;
  documented skips: `tier1/pipeline-loop` (loop-device / throughput needs
  `--privileged`) and one QEMU ignore
  (`grub4dos_boots_to_its_prompt_in_qemu`, needs a caller-supplied `grldr`).
- `cargo xtask dist` (default out-dir only — **not** `./build`) → **exit 0**.
  Artifact `target/dist/x86_64-unknown-linux-gnu/furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz`,
  **8,238,850 B**, SHA256
  `03fe9a6907d8beb08ad99e62b279939677a2d88d26c89941c2fc27c565dad00a` (from
  `SHA256SUMS`); `sha256sum -c SHA256SUMS` → **OK**. `.deb` skipped only because
  `dpkg-deb` is not installed (environmental).
- `cargo xtask size` → **exit 0, "within committed baseline allowance, all
  budgets OK"**: furus **1,810,488** / 3,000,000, furus-helper **2,143,520** /
  2,500,000, furus-gui **12,790,920** / 14,000,000, total **16,744,928 B**.
  No baseline write in this slice.
- `cargo xtask ci` → **exit 1 at the final `cargo deny` gate only** — this is
  the user-deferred advisory, not a regression. Every earlier ci gate passed:
  `fmt`, `clippy`, `test`, `assets --check`, `parity --check`, `contract --check`
  ("contract: all identifiers match the single source of truth") and `size`.
  `cargo deny check` reports **advisories FAILED, bans ok, licenses ok, sources
  ok** on `RUSTSEC-2026-0592` (`url` 2.5.8 via pinned Slint 1.19 / i-slint-
  compiler 1.19 and webbrowser 1.2.7). Per the user's explicit decision this
  advisory is deferred; no dependency/`Cargo.lock`/`Cargo.toml` change was made.
- `git diff --check` → **exit 0**, clean.

### Test counts — progression

Workspace listing count / total: **1921** (final S34) → **1935** (S35.1) →
**1941** (S35.2a) → **1952** (S35.2b) → **1957** (S35.3), delta **+36** across
S35. Final `cargo test --workspace`: 1892 passed / 29 ignored (S34) →
1928 passed / 29 ignored (S35); the ignored count stayed at 29.

### Size-baseline delta — helper only (S35.1 and S35.2b)

`size-baseline.json` was refreshed **twice** in S35, both times for
`furus-helper` only: S35.1 (1,406,392 → 2,126,752 B) and S35.2b
(2,126,752 → 2,140,384 B — the last write, for `unmount.rs`). This final slice
makes **no** baseline write. It still records furus **1,810,504 B**, furus-helper
**2,140,384 B**, furus-gui **12,806,408 B**. Current release binaries — furus
**1,810,488 B**, furus-helper **2,143,520 B**, furus-gui **12,790,920 B** — are
all within budget and within the committed allowance. Do NOT run
`--write-baseline` again.

### Unchanged / advisory notes (not S35 regressions)

- `RUSTSEC-2026-0592` — cargo-deny advisories failure, **deferred by the user**;
  the one known failing gate. No dependency change was made.
- `qa` privileged `tier1/pipeline-loop` skip and one QEMU `grldr` ignore —
  environmental / caller-supplied-resource, pre-existing.
- `.deb` — skipped because `dpkg-deb` is not installed (environmental).
- duplicate `zbus`/`zbus_macros` lock warnings — pre-existing.
- rustdoc was not re-run in this final gate, carrying forward the pre-existing
  S33 situation; out of scope for S35.

## Manual live-hardware sign-off checklist — maintainer BEFORE Publisher sign-off

Unchecked on purpose; these need a real display, a real removable USB and a
Polkit session and cannot be proven by CI. Check each box after testing on the
target desktop:

- [ ] Insert a genuine auto-mounted USB device; confirm it appears under
      `/run/media/...` and the GUI lists it as a removable target.
- [ ] Use a multi-GB ISO image so the SHA-256 digest phase is visible; build a
      plan normally.
- [ ] On **START**, the confirmation screen notes that the mounted removable
      target **will be unmounted automatically** (display-only annotation), and
      no protected system path is ever listed for auto-unmount.
- [ ] On **CONFIRM**, the step/status text immediately shows
      `"Authenticating and starting helper…"` before any silent wait (pkexec
      prompt / helper startup).
- [ ] Live progress appears during verification: an immediate
      `Verifying image SHA-256...` log line followed by advancing
      `verify_image` progress up to a terminal 100%, then a host-unmount `Info`
      log line naming the unmounted path.
- [ ] The run proceeds through the full real pipeline — wipe, mklabel, mkpart,
      mkfs, write, bootloader, finalize — ending in `Outcome::Ok` with a
      complete, readable log (no stub/canned progress).
- [ ] After unmount, the strict re-check would refuse any mount that survived;
      confirm no auto-unmount target reappears mid-run and a still-mounted
      target is refused rather than written.
- [ ] Cancel mid-digest ends as `Outcome::Cancelled` with no unmount and no
      device bytes touched.
- [ ] A busy mount (file open on the USB) produces the ASCII guided EBUSY
      message rather than a raw errno; a protected system mount is refused
      before anything is unmounted.
- [ ] The `Show log` drawer (S34.2) remains readable and scrolls the longer
      S35 event stream in both dark and light themes.

## Publication stance

No push and no tag. S35 is complete and locally reviewed, but leaves all
publication and tagging to manual maintainer / `Publisher` sign-off. Do not
create, move or force-update `v0.1.1`, and do not push any local commits, until
the user explicitly authorizes it. The manual checklist above is the last gate
before Publisher may act. The untracked `./build/` directory is user-owned and
must not be staged, deleted or treated as a repo release artifact.
