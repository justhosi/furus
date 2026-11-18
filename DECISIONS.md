# DECISIONS.md — Rufus for Linux (Rust rewrite), slice S00

Status of the plan: **approved in principle. Decision A4 is settled (approved
2026-10-27): external tools are allowed.** Sections 1–3 are the S00 record as
written then: in particular "no implementation has started" was true at S00
and is **not current** — implementation has proceeded slice by slice since S01,
and each slice's amendments are recorded in section 4.

## 1. Decisions A1–A12

These are the defaults the plan assumes (`PLAN.md` section 1). A4 is settled;
the rest are recorded here as **proposed**: they are plan defaults awaiting the
user's confirmation. Each one changes the schedule if changed. If any of
A1–A12 is rejected, stop and revise the plan before S01.

| ID | Decision | Value | Status | Rationale |
|----|----------|-------|--------|-----------|
| A1 | Licence | **GPL-3.0-or-later** | proposed | Rufus is GPLv3; a derivative must stay GPLv3. |
| A2 | Public name | **new name** (working name `rufus-linux`) | proposed | GPL covers code, not the "Rufus" trademark. Keep attribution, avoid confusion. |
| A3 | Targets | x86_64 + aarch64, glibc ≥ 2.31; static musl for CLI/helper | proposed | Covers Debian 11+, Ubuntu 20.04+, Fedora, Arch, Raspberry Pi. |
| A4 | External tools | **allowed** (approved 2026-10-27): `mke2fs`, `mkntfs`, `mkudffs`, behind a runtime check. FAT32/exFAT are written natively. | **approved 2026-10-27** | Pure-Rust ext4/NTFS/UDF writers are multi-year projects. |
| A5 | C libraries | **wimlib** (LGPL-3.0-or-later) linked for WIM/ESD; optional `libext2fs` feature | proposed | Only sane way to apply Windows images correctly. |
| A6 | Assets | reuse Rufus's GPLv3 embedded assets, with provenance + licence audit (this slice's `LICENSES.md` and `assets/manifest.json`) | proposed | FreeDOS, Syslinux, GRUB4DOS, UEFI:NTFS, `rufus.loc`, icons. |
| A7 | GUI | **Slint** (GPLv3), software renderer, no GPU, no webview, no GTK | proposed | Smallest native toolkit with this widget set; ~4–6 MB. |
| A8 | Concurrency | threads + channels, **no async runtime** | proposed | Async buys nothing here; saves ~1 MB and startup time. |
| A9 | Privilege | GUI never runs as root; a small helper does device writes | proposed | Matches Linux expectations and is testable. |
| A10 | Config | TOML under `$XDG_CONFIG_HOME/rufus-linux/`, portable mode `./rufus.toml` | proposed | Replaces the Windows registry; no root needed. |
| A11 | Locales | reuse `rufus.loc` (pollock format), English fallback | proposed | Keeps the 50+ existing translations. |
| A12 | Telemetry | none; network only on explicit user action | proposed | Matches Rufus behaviour. |

Note on A4: the runtime check behind A4 covers `mke2fs`, `mkntfs`, `mkudffs`
with a clear package hint when absent. Wimlib linkage is recorded under **A5**,
not A4, and follows A5's status (still proposed).

## 2. Trademark and naming

The code is **GPLv3, so GPLv3 applies to this rewrite, but "Rufus" is a
trademark of its author (Pete Batard / Akeo Consulting)**. Public distribution
must therefore use a **different name**; attribution is kept and no name is
chosen that suggests an official Rufus product. The **working name is
`rufus-linux`** (decision A2) until the user picks one. The GPLv3
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
2. the status of A1–A3 and A5–A12 (proposed here; a rejection of any of them
   means stop and revise the plan before S01).

## 4. Amendments after S00

### 2026-11-01 - A4 tool inventory

The S00 text above records A4 as settled with three formatters. The shipped
code now probes and runs more tools; each is behind a runtime presence
check with a package hint. Measured against the tree at `618821c`:

| Tool | Used for | Where |
|---|---|---|
| `mke2fs`, `mkfs.ext2`, `mkfs.ext3`, `mkfs.ext4` | ext2/3/4 format | `crates/rufus-core/src/fs/ext.rs` |
| `e2fsck` | ext verification (`-f -n`) | same |
| `debugfs` | ext persistence file write (`-w -R`) and read-back (`-R`) | same |
| `mkntfs`, `mkfs.ntfs` | NTFS format | `crates/rufus-core/src/fs/ntfs.rs` |
| `mkudffs`, `mkfs.udf` | UDF format | `crates/rufus-core/src/fs/udf.rs` |

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
  implementation detail; the A11 GUI locale policy (`rufus.loc`, English
  fallback) is unchanged.
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
  `rufus-core::planner`, not in a front end, so the CLI and the S24 Slint GUI
  build the same `rufus_proto::Plan` from the same rules. `rufus-core` keeps its
  hard boundary: it never depends on `rufus-linux` and never reads `/sys`.
  Platform facts cross the boundary as pure data — a `planner::DeviceProbe`
  filled by `rufus-linux::probe_device` (or `plan_device_ref` for a selected
  `Device`), graded in core. `clap` stays a CLI-only concern: the CLI keeps a
  `ValueEnum` twin of the selector and converts at the call site.
* **Wire contract (A8 support)**: `PLAN_VERSION` stays 6 and the plan JSON,
  the CLI flags and exit codes 0–7 are unchanged by the move; the builder's
  refusals are classified as `planner::PlanError` (`Device` → exit 2, `Safety` →
  3, `Usage` → 1, `Confirm` → 4/`json`) and mapped back in `rufus-cli`.
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
  majors (`zbus` 5.19.0 for Slint next to `zbus` 6.2.0 for `rufus-helper`,
  `rustix` 0.38.44/1.1.6, `thiserror` 1/2, `toml` 0.8/1.x), and the winit
  backend drags in async plumbing (`zbus`'s `async-io`) that no `rufus-gui`
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
* **No unsafe (contract 0.4.4), clarified**: `crates/rufus-gui/src/lib.rs`
  keeps `#![forbid(unsafe_code)]`; the binary target uses
  `#![deny(unsafe_code)]` because `slint::include_modules!()` emits
  `#[allow(unsafe_code)]` inside generated vtables and an `allow` under a
  crate-level `forbid` is a hard error (E0453). This is a narrowing of how the
  constraint is spelled, not of what it guarantees: there is no `unsafe` block
  and no `#[allow(unsafe_code)]` in hand-written `rufus-gui` source, and the
  workspace `unsafe_code = "deny"` still rejects any that appears. Isolating
  `include_modules!()` in a second internal crate was rejected — it relocates
  the generated unsafe outside the audited crate and adds a workspace member
  without deleting any unsafe code.
* **GUI never root (A9)**: `startup_refusal(euid)` is a pure function, unit
  tested through the euid, naming the unprivileged-GUI / privileged-helper
  split; there is no override flag or environment variable. `--version`,
  `--help`/`-h` short-circuit before both the Slint and the euid check, so they
  still work with no display (contract 0.4.6).
* **Size (contract 0.4.8)**: no budget changed. Measured `rufus-gui` 284,008 →
  11,541,312 bytes (budget 12,000,000) and `rufus-helper` 1,385,080 →
  1,405,992. The helper delta is cargo feature unification, established by
  measurement rather than assumed: the same tree built with
  `-p rufus-helper` alone is 1,384,904 bytes, under `--workspace` 1,405,992,
  because `rustix` 1.1.6 is one package instance shared with the Slint/winit
  tree and gains `mm`, `shm`, `system` there. `size-baseline.json` was
  refreshed with the measured values only; C3 and C4 then took `rufus-gui` to
  11,566,272 (+24,960) and 11,602,240 (+35,968), the value at the S24 tip,
  leaving 397,760 bytes of headroom, and `rufus` moved 1,810,200 → 1,809,576
  (−624) against the same lock refresh. `BINARY_BUDGETS` (3,000,000 /
  2,500,000 / 12,000,000) is unchanged.
