# furus

A Rust rewrite of Rufus, the Windows utility for making bootable USB
drives, targeting Linux. `furus` is the workspace name used in the code
(see `xtask`); it is a from-scratch implementation that keeps Rufus's
on-disk formats and behaviour but none of its code.

The work is organised as a slice plan. The plan document itself lives
outside this repository (module docs cite it as `rust-rewrite/PLAN.md`
by line number); it is not checked in here. What is in-repo is
`DECISIONS.md`, the frozen S00 planning-decisions record: the twelve
plan defaults (licence, public name, targets, external-tool policy, GUI
toolkit, privilege model, ...) and their S00 status. Its "no
implementation has started" line is an S00 snapshot - implementation has
advanced well past it - and its public-name and licence decisions (A1,
A2) remain marked "proposed".

## Status

The rewrite is in progress, one slice at a time. The filesystem write
side is the most complete part:

* FAT32 and exFAT are formatted natively by `rufus-core` - no mount, no
  external tool - with a file API (create, write, read, list,
  timestamps, labels) verified byte-for-byte against the on-disk
  layouts.
* NTFS is written by detecting and driving the external `mkntfs` /
  `mkfs.ntfs` tool (the `ntfs-3g` package on Debian/Ubuntu, the
  separate `ntfsprogs` package on Arch), then verifying the VBR and
  reading the volume label back from `$MFT` record 3. A native NTFS
  writer is out of scope, and the S21 post-format VBR-fix hook is
  explicitly deferred - no hook code ships (see
  `crates/rufus-core/src/fs/ntfs.rs`).
* ext2, ext3 and ext4 are written by detecting and driving the external
  `mke2fs` / `mkfs.ext*` tool (the `e2fsprogs` package); the flavour
  decides the journal bit and the fixed 4096-byte block / 256-byte inode
  geometry, labels are read back from the superblock, and `e2fsck -f -n`
  verifies. Persistence mode labels the volume `persistence` and writes
  `/persistence.conf` through `debugfs`. The QEMU persistence-boot
  acceptance is not measurable on the build host, so it is documented in
  the test module docs rather than claimed.
* NTFS and ext share one external-tool probe (PATH scan, executable
  check, version probe, busy-exec retry) in
  `crates/rufus-core/src/fs/tool.rs`; the version flag stays per family
  (`-V` for ext, `--version` for NTFS), passed at each call site.
* Device discovery, introspection, the safety verdict, partition-table
  writers (MBR + GPT) and the privileged helper are implemented. The
  helper runs each external tool in its own process group and, on
  cancel, SIGKILLs the whole group rather than just the child, so a
  shell that forks (dash's `sh -c` leaves a `sleep` grandchild) cannot
  keep the output pipes open and stall the cancel.
* The end-to-end write path is the least complete part: the CLI's
  `write` command validates its arguments and then honestly reports
  "not implemented" (exit 7), pending the later executor slices.
* The GUI is still a stub: it prints version/help and otherwise reports
  "GUI arrives in S24".

There is no production-readiness claim here. Open acceptance items (for
example a real 32 GB Windows installer boot) are documented as such in
the test module docs rather than faked.

## Layout

A Cargo workspace (edition 2024, `resolver = "3"`):

* `rufus-proto` - versioned plan/progress types shared by the CLI, GUI
  and helper: the `Plan` contract and its `Plan::confirm` hash, plus the
  helper event stream.
* `rufus-core` - the safe, non-privileged foundation and the filesystem
  write side: error/config/paths/i18n/hash/units, MBR + GPT table
  readers and writers, the FAT32/exFAT/NTFS/ext2/3/4 formatters,
  superblock probing and the safety verdict.
* `wimlib-sys` - FFI bindings to wimlib, for applying WIM/ESD images.
* `rufus-linux` - the only crate that touches `/sys` and `/run/udev`:
  device discovery, mount/swap/holder introspection, and the
  block-ioctl shim.
* `rufus-helper` - the privileged write helper: validates a plan and
  runs it, exposed over D-Bus behind polkit; it runs as root, the GUI
  never does.
* `rufus-cli` - the `rufus` command-line front end: version, checksum,
  analyze, plan, list, write.
* `rufus-gui` - the Slint desktop front end (currently the S01 stub).
* `xtask` - repo maintenance: asset-manifest check, parity check, the
  per-binary size gate, CI ordering.

The crate layering keeps privileged I/O in `rufus-linux` /
`rufus-helper` and the formatter logic in `rufus-core`, which never
depends on `rufus-linux` (see `crates/rufus-core/src/fs/mod.rs`).

Safety and dependencies: every crate root carries
`#![forbid(unsafe_code)]`, and the workspace denies unsafe code, with
exactly one allowance - the four block ioctls
(BLKZEROOUT/BLKDISCARD/BLKRRPART/BLKFLSBUF) in
`crates/rufus-linux/src/ioctl.rs` that rustix does not wrap.
`rufus-core` is dependency-light by design: no async runtime, no logging
framework, no regex.

## Build

A Rust toolchain pinned by `rust-toolchain.toml` is required; on this
development host cargo lives under `~/.cargo/bin`:

    export PATH="$HOME/.cargo/bin:$PATH"
    cargo build --offline
    cargo test --offline --workspace

The size gate builds the release binaries, enforces their per-binary
budgets and compares them against `size-baseline.json` (it never
rewrites the baseline):

    CARGO_NET_OFFLINE=true cargo xtask size

## Tests

The formatters are verified against real external tools, which the
suites use when present and skip (with an explicit `skip:` line, never a
silent pass) when absent:

* `crates/rufus-core/tests/fat32_format.rs` - `fsck.fat -n` must accept
  the written image at 64 MiB, 2 GiB, 32 GiB and the 2 TiB limit.
* `crates/rufus-core/tests/exfat_format.rs` - `fsck.exfat`,
  `dump.exfat` and `exfatlabel` (exfatprogs) must call the image clean
  and read back the geometry and label.
* `crates/rufus-core/tests/ntfs_format.rs` - `mkntfs`, `ntfsfix -n` and
  `ntfslabel` must agree with the written volume; the VBR-declared
  bounds and the `$MFT` record-3 label read are pinned.

The kernel-mount tests are `#[ignore]`d: they need root and a loop
device, run on demand with `sudo -E $(which cargo) test --offline
-p rufus-core --test <suite> -- --ignored --nocapture`, or inside the
documented privileged container (an `archlinux` image; the NTFS suite's
module doc records the `pacman -Sy --noconfirm ntfs-3g ntfsprogs`
package split).

## Docs

* `DECISIONS.md` - frozen S00 planning decisions; implementation has
  since advanced.
* `LICENSES.md` - asset licence audit for the Rufus 4.15 resources the
  rewrite reuses; the code licence is GPL-3.0-or-later (decision A1,
  still proposed).
* `assets/`, `data/`, `packaging/` and the `tests/` fixtures carry their
  own READMEs.
