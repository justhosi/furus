# DECISIONS.md — furus for Linux (Rust rewrite), slice S00

Status of the plan: **approved in principle. Decision A4 is settled (approved
2026-10-27): external tools are allowed.** Sections 1–3 are the S00 record as
written then: in particular "no implementation has started" was true at S00
and is **not current** — implementation has proceeded slice by slice since S01,
and each slice's amendments are recorded in section 4.

## 1. Decisions A1–A12

These are the defaults the plan assumes (`PLAN.md` section 1). A1, A3, A4 and
A5 are **approved** (ratified 2026-11-19 for A1/A3/A5, 2026-10-27 for A4);
the rest are recorded here as **proposed**: they are plan defaults awaiting the
user's confirmation. Each one changes the schedule if changed. If any of
A1–A12 is rejected, stop and revise the plan before S01.

| ID | Decision | Value | Status | Rationale |
|----|----------|-------|--------|-----------|
| A1 | Licence | **GPL-3.0-or-later** | approved 2026-11-19 | The original Windows utility is GPLv3; a derivative must stay GPLv3. |
| A2 | Public name | **new name** (working name `furus-linux`) | proposed | GPL covers code, not the original utility's trademark. Keep attribution, avoid confusion. |
| A3 | Targets | x86_64 + aarch64, glibc ≥ 2.31; static musl for CLI/helper | approved 2026-11-19 | Covers Debian 11+, Ubuntu 20.04+, Fedora, Arch, Raspberry Pi. |
| A4 | External tools | **allowed** (approved 2026-10-27): `mke2fs`, `mkntfs`, `mkudffs`, behind a runtime check. FAT32/exFAT are written natively. | **approved 2026-10-27** | Pure-Rust ext4/NTFS/UDF writers are multi-year projects. |
| A5 | C libraries | **wimlib** (LGPL-3.0-or-later) linked for WIM/ESD; optional `libext2fs` feature | approved 2026-11-19 | Only sane way to apply Windows images correctly. |
| A6 | Assets | reuse the original utility's GPLv3 embedded assets, with provenance + licence audit (this slice's `LICENSES.md` and `assets/manifest.json`) | proposed | FreeDOS, Syslinux, GRUB4DOS, UEFI:NTFS, the upstream `.loc` database, icons. |
| A7 | GUI | **Slint** (GPLv3), software renderer, no GPU, no webview, no GTK | proposed | Smallest native toolkit with this widget set; ~4–6 MB. |
| A8 | Concurrency | threads + channels, **no async runtime** | proposed | Async buys nothing here; saves ~1 MB and startup time. |
| A9 | Privilege | GUI never runs as root; a small helper does device writes | proposed | Matches Linux expectations and is testable. |
| A10 | Config | TOML under `$XDG_CONFIG_HOME/furus-linux/`, portable mode `./furus.toml` | proposed | Replaces the Windows registry; no root needed. |
| A11 | Locales | reuse the upstream `.loc` database (pollock format), English fallback | proposed | Keeps the 50+ existing translations. |
| A12 | Telemetry | none; network only on explicit user action | proposed | Matches the original utility's behaviour. |

Note on A4: the runtime check behind A4 covers `mke2fs`, `mkntfs`, `mkudffs`
with a clear package hint when absent. Wimlib linkage is recorded under **A5**,
not A4, and follows A5's status (approved 2026-11-19).

## 2. Trademark and naming

The code is **GPLv3, so GPLv3 applies to this rewrite, but the original
Windows utility's name is a trademark of its author (Pete Batard / Akeo
Consulting)**. Public distribution must therefore use a **different name**;
attribution is kept and no name is chosen that suggests an official product
of the original utility. The **working name is `furus-linux`** (decision A2)
until the user picks one. The GPLv3
corresponding-source duty is honoured by keeping this repository public; the
repository itself is the source offer.

Suggested source-of-truth for the future decision: A2's value becomes a real
product name **only** when the user confirms it, and the change ripples through
config paths (`A10`), the helper D-Bus name, the asset directory and the
desktop file — that is why it is frozen here, in S00, and not later.

## 3. Go/no-go

*(S00 record, kept as written; superseded — implementation began at S01 and
continues under the per-slice contracts recorded in section 4.)*

**No implementation starts beyond S00 until the user gives an explicit
go-ahead.** S00 delivers only this file, `LICENSES.md` and
`assets/manifest.json`; it contains no Rust, no build system and no CI. The
next slice (S01 — workspace, CI, size gates, parity tool) is gated on:

1. the user's explicit go-ahead, and
2. the status of the decisions still proposed here (A2 and A6–A12): A1, A3, A4
   and A5 are now approved and no longer block, but a rejection of any
   still-proposed decision means stop and revise the plan before S01.

## 4. Amendments after S00

### 2026-11-01 - A4 tool inventory

The S00 text above records A4 as settled with three formatters. The shipped
code now probes and runs more tools; each is behind a runtime presence
check with a package hint. Measured against the tree at `618821c`:

| Tool | Used for | Where |
|---|---|---|
| `mke2fs`, `mkfs.ext2`, `mkfs.ext3`, `mkfs.ext4` | ext2/3/4 format | `crates/furus-core/src/fs/ext.rs` |
| `e2fsck` | ext verification (`-f -n`) | same |
| `debugfs` | ext persistence file write (`-w -R`) and read-back (`-R`) | same |
| `mkntfs`, `mkfs.ntfs` | NTFS format | `crates/furus-core/src/fs/ntfs.rs` |
| `mkudffs`, `mkfs.udf` | UDF format | `crates/furus-core/src/fs/udf.rs` |

The runtime tools above are also driven directly by the suites. The other
external programs (`fsck.fat`, `fsck.exfat`, `dump.exfat`, `exfatlabel`,
`mdir`, `mcopy`, `dumpe2fs`, `e2label`, `blkid`, `ntfslabel`, `ntfsfix`,
`udfinfo`, plus `mount`, `losetup` and `sfdisk` in the device suites) are
driven only by tests under `crates/*/tests`, so they are test
prerequisites, not runtime dependencies.

The header's "No implementation has started" sentence describes S00 at the
time it was written; slices S01 onward are implemented and are described in
`README.md`.

### 2026-11-18 - S22 amendments (no A1–A12 value changes)

These clarify implementation details of existing decisions; none of the A1–A12
values above is changed.

* **A5 (C libraries)**: `wimlib-sys` gains an opt-in `strict-link` Cargo feature
  that turns a missing system `libwim` (or `WIMLIB_SYS_FORCE_UNLINKED`) from a
  silent unbound stub into a compile error. It is default-off: default builds
  are unchanged and no dependency is added.
* **A11 (Locales) — BCD only**: BCD store locale handling is now dynamic — a
  locale supplied from the applied tree (`.mui` detection) → the BCD-Template's
  `12000005` → `en-us`, written verbatim to all four locale sites. This is a BCD
  implementation detail; the A11 GUI locale policy (upstream `.loc` database,
  English fallback) is unchanged.
* **A5/WIM apply**: the apply pre-flight reserves NTFS overhead —
  `required + max(64 MiB, required / 50)` — on both free-space checks before any
  write, because exact NTFS metadata/compression overhead cannot be predicted
  from the WIM.
* **Testing**: a deterministic regf mutation property test (500 sequences × 20
  ops, reparse + checksum + `check_bins` after every step) was added with no new
  dependency.

### 2026-11-18 - S23 amendments (no A1–A12 value changes)

These record where S23 put existing logic; none of the A1–A12 values above is
changed and no dependency is added.

* **Layering (A9/A7 support)**: provisional plan construction lives in
  `furus-core::planner`, not in a front end, so the CLI and the S24 Slint GUI
  build the same `furus_proto::Plan` from the same rules. `furus-core` keeps its
  hard boundary: it never depends on `furus-linux` and never reads `/sys`.
  Platform facts cross the boundary as pure data — a `planner::DeviceProbe`
  filled by `furus-linux::probe_device` (or `plan_device_ref` for a selected
  `Device`), graded in core. `clap` stays a CLI-only concern: the CLI keeps a
  `ValueEnum` twin of the selector and converts at the call site.
* **Wire contract (A8 support)**: `PLAN_VERSION` stays 6 and the plan JSON,
  the CLI flags and exit codes 0–7 are unchanged by the move; the builder's
  refusals are classified as `planner::PlanError` (`Device` → exit 2, `Safety` →
  3, `Usage` → 1, `Confirm` → 4/`json`) and mapped back in `furus-cli`.
* **Module layout**: `pipeline::bootloader` is a directory of private arm
  submodules (`syslinux`, `grub2`, `grub4dos`, `dos_kolibri`, `uefi_ntfs`,
  `windows`) behind an unchanged `pub(crate)` surface (`Installed`,
  `install_tree`, `run`); no on-disk behaviour changed, and the release binary's
  +1,184-byte reshuffle is recorded in the refreshed size baseline.
* **Bad blocks**: there is no separate bad-block step and no plan field beyond
  the existing one — the surface scan is the wipe's opt-in `"badblocks"`
  pseudo-step (`RunOptions::badblocks`), independent of full format
  (`quick == false`, which only zeroes). Documentation now matches that; the
  previous "arrives in slice 9" note was stale.

### 2026-11-18 - S24 amendments (no A1–A12 value changes)

These record how the S24 GUI enforces the contract's hard constraints; none of
the A1–A12 values above is changed and no new front-end dependency beyond the
A7-mandated toolkit is added.

* **A7 realized as an exact pin**: `slint` and `slint-build` are pinned to
  `=1.19.0` with `default-features = false` and only `std`, `compat-1-2`,
  `backend-winit`, `renderer-software`; `rustix` is pinned to `=1.1.6`
  (`std`, `process`) purely to read the effective uid for A9, because `std`
  cannot do it without `unsafe`. Consequence accepted with the pin: the lock
  grows 102 → 567 packages and duplicates crates that cannot unify across
  majors (`zbus` 5.19.0 for Slint next to `zbus` 6.2.0 for `furus-helper`,
  `rustix` 0.38.44/1.1.6, `thiserror` 1/2, `toml` 0.8/1.x), and the winit
  backend drags in async plumbing (`zbus`'s `async-io`) that no `furus-gui`
  code calls — there is still no `tokio`, no `async-std` and no `async` code in
  the crate, so A8 stands for our own code. The A7 planning estimate in
  section 1 (~4–6 MB) proved low: with the mandated feature set the release
  binary measures 11,602,240 bytes, inside the unchanged 12,000,000 budget.
  A7's status column is left as `proposed` in section 1 — recording a user
  confirmation that never happened is not this slice's to make.
* **Licence (A1 direction)**: Slint crates are tri-licensed; `deny.toml`
  accepts **only** the `GPL-3.0-only` branch, through per-crate
  `[[licenses.exceptions]]` pinned to `@=1.19.0` so a Slint bump forces a
  re-review. The `LicenseRef-Slint-*` proprietary branches are never accepted.
  `BSL-1.0` is allowed only for `clipboard-win`/`error-code`, which are
  Windows-only and provably absent from the Linux graph. Six RUSTSEC
  advisories are scoped-ignored; all six are `informational = "unmaintained"`
  with `patched = []`, so no ignore hides a fixable vulnerability.
* **No unsafe (contract 0.4.4), clarified**: `crates/furus-gui/src/lib.rs`
  keeps `#![forbid(unsafe_code)]`; the binary target uses
  `#![deny(unsafe_code)]` because `slint::include_modules!()` emits
  `#[allow(unsafe_code)]` inside generated vtables and an `allow` under a
  crate-level `forbid` is a hard error (E0453). This is a narrowing of how the
  constraint is spelled, not of what it guarantees: there is no `unsafe` block
  and no `#[allow(unsafe_code)]` in hand-written `furus-gui` source, and the
  workspace `unsafe_code = "deny"` still rejects any that appears. Isolating
  `include_modules!()` in a second internal crate was rejected — it relocates
  the generated unsafe outside the audited crate and adds a workspace member
  without deleting any unsafe code.
* **GUI never root (A9)**: `startup_refusal(euid)` is a pure function, unit
  tested through the euid, naming the unprivileged-GUI / privileged-helper
  split; there is no override flag or environment variable. `--version`,
  `--help`/`-h` short-circuit before both the Slint and the euid check, so they
  still work with no display (contract 0.4.6).
* **Size (contract 0.4.8)**: no budget changed. Measured `furus-gui` 284,008 →
  11,541,312 bytes (budget 12,000,000) and `furus-helper` 1,385,080 →
  1,405,992. The helper delta is cargo feature unification, established by
  measurement rather than assumed: the same tree built with
  `-p furus-helper` alone is 1,384,904 bytes, under `--workspace` 1,405,992,
  because `rustix` 1.1.6 is one package instance shared with the Slint/winit
  tree and gains `mm`, `shm`, `system` there. `size-baseline.json` was
  refreshed with the measured values only; C3 and C4 then took `furus-gui` to
  11,566,272 (+24,960) and 11,602,240 (+35,968), the value at the S24 tip,
  leaving 397,760 bytes of headroom, and `furus` moved 1,810,200 → 1,809,576
  (−624) against the same lock refresh. `BINARY_BUDGETS` (3,000,000 /
  2,500,000 / 12,000,000) is unchanged.

### 2026-11-19 - S25 amendments (no A1–A12 value changes)

These record where the client half of the helper wire contract lives; none of
the A1–A12 values above is changed and no dependency is added.

* **A9 (privilege split) — client-side wire parsing lives in `furus-proto`**:
  the helper emits one JSONL `Event` per line (`--plan … --progress jsonl`) and
  the same three events as D-Bus signals (`org.furuslinux.Helper1`:
  `Execute`/`Cancel` plus `progress`/`log`/`done`), so *reading* that stream is
  a client concern while its *contract* is shared by both halves of the split.
  `events::from_jsonl_line` and `events::LineError` therefore live in
  `furus-proto` next to the types they parse, re-exported from its crate root
  (`furus_proto::{from_jsonl_line, LineError}`), instead of being re-implemented
  in `furus-gui` or owned by the privileged helper: the client keeps no tag list
  of its own, so the two halves cannot disagree about what a valid line is.
  Adding an `Event` variant remains a schema change that bumps
  `EVENT_STREAM_VERSION`, and `Completion::check_version` is the single home of
  that rule (the shared parser applies it to every `Done` line; only newer
  streams are refused).
* **A8 (threads + channels, no async runtime), restated for the seam**:
  `furus-gui::ipc` exposes a sync `HelperTransport::start` returning a blocking
  `Iterator` of events plus a `CancelHandle`, so both intended transports fit
  with no executor — the pkexec child's stdout is read on a plain
  `std::thread`, and a zbus 6 client (async-only, no blocking API) drives its
  proxy with `zbus::block_on` on its own thread and feeds the same iterator.
  No crate names a runtime; zbus still brings the one it needs.
* **Cancel is one-shot and sticky**: `CancelHandle` runs its action at most once
  across clones and caches the first result, so repeating a cancel can never
  turn a failed cancel into a reported success.
* **Not renumbered**: no new A-number is introduced. An `A13` would extend the
  S00 plan-decision set whose values still await user confirmation (sections 1
  and 3); this slice settles placement *inside* the A9 split rather than adding
  a plan default, which is how the S22–S24 amendments were recorded as well.

### 2026-11-19 - S25 slice-2 amendments (no A1–A12 value changes)

These record the two contracts the shipped pkexec transport introduces; no
A1–A12 value changes and no dependency is added.

* **A8/A9 — the authorization wait is bounded, the run is not**: `pkexec` is
  silent while polkit authenticates, so `HelperTransport::start` is documented
  as blocking and carries one default budget of **120 s**
  (`DEFAULT_AUTHORIZATION_TIMEOUT`). On expiry the transport kills **and reaps**
  the child, removes the plan file and returns
  `IpcError::Transport("no helper event within Ns; authorization not completed")`
  instead of blocking for ever; a longer budget only delays a hung prompt, and a
  shorter one cuts off a legitimate password entry. The budget covers the
  authorization wait only — reads after `start()` are un-timed blocking reads,
  so a long `wipe`/`verify` step is unaffected. Tests inject their own budget
  through `with_command_and_authorization_timeout`; production construction
  (`new()`/`Default`) always uses the constant.
* **A9 — the plan file is user-private and swept narrowly**: the plan handed to
  the privileged helper is written to `std::env::temp_dir()` as
  `furus-plan-<gui-pid>-<counter>-<nanos>.json`, created with `create_new(true)`
  and mode `0600`, and removed on every exit path. Because it lives in a
  world-writable directory, the constructor sweep deletes a file only when it
  (a) parses as that canonical name, (b) is a regular file, not a symlink,
  (c) is owned by the current user with mode exactly `0600`, and (d) names a pid
  that `/proc/<pid>/stat` proves is gone or a zombie. Every other entry and
  every error is ignored, so a pid reused by a live process leaks its stale file
  instead of deleting a live run's plan, and another user's file is never a
  candidate.
* **Not renumbered**: for the same reason as the slice-1 entry above — these
  settle contracts *inside* the A8/A9 decisions rather than adding a plan
  default whose value would still await user confirmation.

### 2026-11-19 - S26 amendments (A1, A3, A5 ratified)

S26 ratifies three of the S00 plan defaults — A1, A3 and A5 — against what the
tree already ships. Only these three status cells change; their values and
rationales in section 1 are unchanged, and no other A-number is touched.

* **A1 (Licence) — GPL-3.0-or-later, approved**: the rewrite is GPL-3.0-or-later,
  as the original Windows utility is GPLv3 and a derivative must stay GPLv3. This is not a new
  commitment: `LICENSES.md`'s audit of all 86 embedded assets already records
  that baseline, and `deny.toml` already accepts only the `GPL-3.0-only`
  copyleft branch of the tri-licensed Slint crates (pinned to `=1.19.0`), never
  the proprietary `LicenseRef-Slint-*` branches. In user-facing terms: the
  program and its assets stay free and open under GPLv3, and because this
  repository is public it is itself the corresponding-source offer required by
  the GPL — anyone who receives a binary can get the source that built it.

* **A3 (Targets) — approved**: the two target families are x86_64 and aarch64,
  each on glibc ≥ 2.31 (Debian 11+, Ubuntu 20.04+, Fedora, Arch, Raspberry Pi),
  with a static-musl option for the CLI and the helper. The mechanism that will
  exercise these is `xtask dist --target <triple>`. Honest scope note: only the
  host triple is verified in this environment; cross-building requires the
  target toolchains to be installed, so no aarch64 binary is claimed to have
  been built here. **Dual-arch realization (2026-11-21):** the value of A3 is
  now exercised by the release workflow, which builds native x86_64 and
  aarch64 artifacts on a two-runner matrix (see `TECHNICAL.md`), so aarch64
  binaries are produced in CI. This realizes the decision without changing
  it, and does not alter the local-scope note above — this development host
  still only builds the host triple.

* **A5 (C libraries) — approved**: wimlib remains LGPL-3.0-or-later and is
  linked for WIM/ESD through `wimlib-sys`, with the opt-in `strict-link` feature
  added in S22 turning a missing system `libwim` into a compile error. The LGPL
  relink and source obligations are met by shipping wimlib as a separate
  package (so a recipient can relink against a modified library) and by
  including the licence texts in the distribution bundle. The optional
  `libext2fs` feature is unchanged.

* **A2 and A6–A12 remain proposed and are outside S26's authorization.**
  Ratifying them would require user decisions that were never given — the
  public name (A2) specifically still awaits the user, because the original
  utility's name is a trademark and only the user can pick the release name. Consequently the
  specification's broad phrase "no unratified S00 architecture items
  remaining" is not literally achievable without fabricating those decisions;
  after S26 the accurate statement is that A1, A3, A4 and A5 are approved and
  A2 and A6–A12 remain proposed.
