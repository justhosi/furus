# DECISIONS.md — Rufus for Linux (Rust rewrite), slice S00

Status of the plan: **approved in principle. Decision A4 is settled (approved
2026-10-27): external tools are allowed. No implementation has started —
anything beyond S00 waits for an explicit go-ahead.**

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
