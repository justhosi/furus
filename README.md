# furus

A clean implementation of Rufus in Rust, targeting Linux. Rufus is the
Windows utility for making bootable USB drives. `furus` is the workspace
name used in the code (see `xtask`); it is a from-scratch implementation
that keeps Rufus's on-disk formats and behaviour but none of its code.

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

The implementation is in progress, one slice at a time. The filesystem
write side is the most complete part:

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
* UDF is written by detecting and driving the external `mkudffs` /
  `mkfs.udf` tool (the `udftools` package), pinning `--udfrev=0x0201`,
  then verifying the volume recognition sequence (BEA01, one NSR
  descriptor, TEA01) at byte 32768 of the image; the label is read back
  with `udfinfo`. A native UDF writer is out of scope (see
  `crates/rufus-core/src/fs/udf.rs`).
* A read-only UDF reader (S15) in `crates/rufus-core/src/udf/` reads a
  UDF volume back through the same `Volume` abstraction the writer
  produces: the anchor pointer at logical sector 256 (probed at block
  size 2048, then 512), the descriptor sequence (primary, partition,
  logical volume with its type-1 partition maps, the file set
  descriptor), the root file entry and every file identifier descriptor,
  then any regular file's bytes through its extents and allocation
  descriptors, and the whole tree through a depth-bounded `walk`.
  Type-2 partition maps, extended allocation descriptors, compression
  ids other than 8 and 16, and every non-file ICB type (symlinks,
  FIFOs, sockets, devices, VAT/metadata entries) refuse by name, never
  by fabricating bytes; file reads are capped at 64 MiB and 4096
  extents so a hostile entry cannot demand unbounded work, and the
  reader never writes.
* NTFS, ext and UDF share one external-tool probe (PATH scan,
  executable check, version probe, busy-exec retry) in
  `crates/rufus-core/src/fs/tool.rs`; the version flag stays per family
  (`-V` for ext, `--version` for NTFS), UDF is probed by its usage
  banner instead, and each is passed at its call site.
* An ISO9660 image reader (S14) in `crates/rufus-core/src/iso/` reads
  the volume-descriptor sequence, the primary directory tree, Joliet
  supplementary trees (preferred when present; the highest escape level
  wins), multi-extent files joined in order, and — on the primary tree
  alone — Rock Ridge/SUSP names, symlink targets, attributes and
  `CL`/`PL`/`RE` relocated directories, plus the El Torito boot catalog.
  `walk` lists a tree depth-first with absolute paths and never follows
  symlinks. Images are read through the crate's `Volume` abstraction
  with a 64 KiB sector cache rather than mmap — mmap needs `unsafe` or a
  new dependency, both forbidden by the crate — so every access stays
  bounds-checked against the store before any I/O.
* An image container layer (S15) in `crates/rufus-core/src/image/`
  detects the container family by magic over any `Volume`
  (`ImageKind`), opens a regular file read-only and validates its header
  (`open_image`), then presents the *logical* disk as a read-only
  `Volume` whose size is the container's virtual size rather than the
  file length. Fixed and dynamic VHD, VHDX, FFU and qcow2 all get a
  reader: fixed VHD presents file bytes `0..current_size` without the
  footer, dynamic VHD walks the BAT, VHDX resolves the BAT with its
  state machine, qcow2 resolves L1→L2 over 64 KiB clusters, and FFU
  maps store blocks to payload windows. FFU has no real sample on the
  host, so its layout is inferred rather than measured. Writes are
  refused — the containers are read-only — and the payload acceptance
  suite (`tests/image_readers.rs`) is `#[ignore]`d because it installs
  `qemu-img` inside `archlinux:latest`, which needs docker and network;
  CI runs with `--network none`, so the suite must not depend on Arch
  mirrors.
* Device discovery, introspection, the safety verdict, partition-table
  writers (MBR + GPT) and the privileged helper are implemented. The
  helper runs each external tool in its own process group and, on
  cancel, SIGKILLs the whole group rather than just the child, so a
  shell that forks (dash's `sh -c` leaves a `sleep` grandchild) cannot
  keep the output pipes open and stall the cancel.
* The end-to-end write path runs: the CLI's `write` command validates
  its plan file (schema version + confirm hash) and executes it through
  the pipeline — wipe, table, partition, format, write (a byte-for-byte
  `Dd` or a file-tree `Copy`), bootloader, finalize — with per-event
  JSON (`--json`) or a throttled progress line, Ctrl-C cancellation
  (exit 6), and typed refusals (exit 7 only for the image kinds with
  no tree reader — WIM, VHD, VHDX, FFU, qcow2, PE — and a `Copy` plan
  run over the `--device-file` seam, which has no partition node to
  mount). `--device-file` runs the same plan
  against a regular file for tests. `rufus plan --verify` records a
  read-back of the whole image against the plan digest, doubling the
  I/O; `rufus plan --badblocks` records a surface scan that runs in
  the wipe step. A chunk write that fails with `EIO`/`ENOSPC` is
  retried three times, five seconds apart (the failing chunk only,
  with the device size re-read before each attempt);
  `write --reset-usb` additionally resets the USB device once the
  retries are spent and retries the chunk one last time — best
  effort, off by default. The plan records `bad_blocks` (and
  `verify`); the retry/reset knobs are runtime recoveries, not plan
  content. The `--json` stream (one `Event` object per stdout line) is
  documented in `crates/rufus-cli/src/main.rs` and on
  `rufus_core::pipeline::Event`.
* The copy engine (S18) is wired into the write path. `rufus plan
  --iso-mode` selects `WriteMode::Copy` for ISO and Raw images (the
  recommended mode for bootable sticks); a `Copy` write walks the
  ISO9660 or UDF tree onto the mounted data partition through a mount
  seam (`Opener::mount_partition`, guarded by `rufus-linux`'s `Mounted`
  helper with vfat/exfat/ntfs3, `NOSUID|NODEV` and a detach fallback). The
  walk is cancellable, pre-flights free space, enforces the FAT32
  file-size limit, and throttles its progress through the pipeline's
  shared 100 ms cadence. The `Raw` UDF path (a pure-UDF image carries no
  `CD001`, so it detects as `Raw`) is driven end to end by a positive
  and a negative test: the copy arm lands a UDF tree byte for byte and
  refuses a volume whose structure is corrupt. The fixture is
  hand-encoded against our own reader, so it proves the arm consumes
  what the reader accepts, not that the reader matches a real `mkudffs`
  volume; a real `mkudffs`-built volume through the copy arm remains a
  declared follow-up.
* Bootloader installation (S19/S20) is wired as the `bootloader`
  pipeline step. `rufus plan --bootloader <mode>` selects the installer
  explicitly (`auto`, `syslinux`, `grub2`, `grub4dos`, `uefi-ntfs`,
  `freedos`, `kolibri`, `msdos` or `none`); `auto` keeps the write-mode
  pairing (a `Dd` write already laid the image's own boot code, so
  `none`; a `Copy` write needs one, so `auto`), and every other mode is
  emitted verbatim. `auto` probes Syslinux, then GRUB2, then GRUB4DOS
  in the image's own tree: Syslinux installs from the image's payloads
  (family choice 4.07/6.04, a VBR graft, a contiguous stage file with
  sector map and ADV, companions kept when the copy already placed
  identical bytes, and a `syslinux.cfg` wrapper); GRUB2 BIOS writes its
  record into the MBR with `core.img` bounded by the post-MBR gap and
  places a UEFI GRUB payload at `/EFI/boot/bootx64.efi` when absent;
  GRUB4DOS writes its MBR/SBR and refuses before writing anything
  unless a root `/grldr` already exists (the image's own or a
  caller-supplied one), because resource 451 is GRUB2's `core.img`, not
  a `grldr` (Rufus downloads the real loader `grub4dos-0.4.6a/grldr`
  and bundles none). `uefi-ntfs` forces `Copy`
  and the two-partition `uefi_ntfs` layout, writing the embedded 1 MiB
  shim image at the ESP offset, and needs an NTFS or exFAT data
  partition. `freedos` and `kolibri` need a FAT32 data partition:
  FreeDOS installs the embedded payloads (kernel, shell, `DISPLAY`,
  `KEYB`, `MODE`, the keyboard-layout libraries and the EGA codepage
  fonts) plus a `CONFIG.SYS`/`AUTOEXEC.BAT` pair and the transcribed
  ms-sys FAT32 boot record; KolibriOS places the `MTLD_F32` loader and
  its record. `msdos` needs FAT32 plus `--msdos-dir` naming the user's
  `IO.SYS`, `MSDOS.SYS` and `COMMAND.COM`, and plans no write step (the
  files must be the first entries of the fresh volume). Three loaders
  now boot in QEMU from full six-step plans (Syslinux 4.07 to its
  `boot:` prompt, FreeDOS to a `C:\>` prompt, and GRUB2 BIOS to a
  `grub>` shell running a config that prints `GRUB2-OK`), and the
  UEFI:NTFS shim boots a real NTFS payload under OVMF
  (`UEFI-NTFS-OK`). No stick has been booted on hardware, and the
  GRUB4DOS boot test is `#[ignore]`d behind `RUFUS_TEST_GRLDR` because
  the payload is not bundled; each suite prints one `skip:` line when
  qemu, grub-mkimage, mkntfs, OVMF or another tool is absent.
* The GUI is still a stub: it prints version/help and otherwise reports
  "GUI arrives in S24".

There is no production-readiness claim here. Open acceptance items (for
example a real 32 GB Windows installer boot) are documented as such in
the test module docs rather than faked.

### `analyze` report

`rufus analyze [--json] <image>` reports the S16 image analysis in a
`report` object next to the four long-standing image keys (`path`,
`size_bytes`, `sha256`, `kind`), which keep their names, order and
values. The human output summarises the report as one `report:` line
after `sha256:` (kind, label, Windows version/build, distro and boot
mode only); `--json` carries the whole object. With `--device`, the
same `report` object is filled from the image file alongside the device
report.

The object holds the image family (`kind`, `is_iso`, `is_udf`), the
Windows payload (`is_windows`, `windows_version`, `build`,
`is_windows_to_go`, `wim_images`), the Linux distro and persistence
family (`distro`, `persistence` — `distro` also carries the DOS-family
markers `KolibriOS`, `ReactOS`, `FreeDOS` and `MS-DOS`), the bootloader
capabilities (`has_efi`, `has_bios`, `has_grub`, `grub_version`,
`has_syslinux`, `syslinux_version`), the label candidates and a
`truncated` flag for capped tree walks. A `null` report means the report
could not be produced — the volume probed positive but its reader
refused it (a corrupt or truncated image), or reading the image failed:
a broken ISO never turns `analyze` into an error.

## Layout

A Cargo workspace (edition 2024, `resolver = "3"`):

* `rufus-proto` - versioned plan/progress types shared by the CLI, GUI
  and helper: the `Plan` contract and its `Plan::confirm` hash, plus the
  helper event stream.
* `rufus-core` - the safe, non-privileged foundation and the filesystem
  write side: error/config/paths/i18n/hash/units, MBR + GPT table
  readers and writers, the FAT32/exFAT/NTFS/ext2/3/4/UDF formatters,
  the ISO9660/Joliet/Rock Ridge image reader (`iso/`), the read-only
  UDF reader (`udf/`) and the image container layer (`image/`),
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
exactly two allowances - the four block ioctls
(BLKZEROOUT/BLKDISCARD/BLKRRPART/BLKFLSBUF) in
`crates/rufus-linux/src/ioctl.rs` that rustix does not wrap, and the one
SIGINT handler install in `crates/rufus-linux/src/signal.rs` (one atomic
store, nothing else).
`rufus-core` is dependency-light by design: no async runtime, no logging
framework, no regex.

## Build

A Rust toolchain pinned by `rust-toolchain.toml` is required; on this
development host cargo lives under `~/.cargo/bin`:

    export PATH="$HOME/.cargo/bin:$PATH"
    cargo build --offline
    cargo test --offline --workspace

The size gate builds the release binaries, enforces their per-binary
budgets and checks growth against `size-baseline.json` within a 4096-byte
allowance (the same compiler emits slightly different bytes on different
system linkers; it never rewrites the baseline):

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
* `crates/rufus-core/tests/udf_format.rs` - `mkudffs`, `udfinfo` and a
  kernel mount must agree with the written volume across the block-size
  matrix (512/2048), the label shapes (short, 126-byte ceiling,
  default) and the pinned `--udfrev=0x0201` revision.

The kernel-mount tests are `#[ignore]`d: they need root and a loop
device, run on demand with `sudo -E $(which cargo) test --offline
-p rufus-core --test <suite> -- --ignored --nocapture`, or inside the
documented privileged container (an `archlinux` image; the NTFS suite's
module doc records the `pacman -Sy --noconfirm ntfs-3g ntfsprogs`
package split). Two further suites exercise the mount and boot seams:
`crates/rufus-linux/tests/mount_seam.rs` mounts FAT32, exFAT and NTFS
through the real kernel (`#[ignore]`d, root + loop devices, run with
`-p rufus-linux --test mount_seam`), and
`crates/rufus-core/tests/uefi_ntfs_boot.rs` boots the UEFI:NTFS shim
against a real NTFS volume in OVMF (unprivileged; it runs in the normal
suite and skips with one `skip:` line when qemu, grub-mkimage, mkntfs,
ntfscp, unshare, ntfs-3g or the OVMF images are absent).

## Docs

* `DECISIONS.md` - frozen S00 planning decisions; implementation has
  since advanced (its section 4 records the post-S00 tool amendment).
* `LICENSES.md` - asset licence audit for the Rufus 4.15 resources the
  implementation reuses; the code licence is GPL-3.0-or-later (decision
  A1, still proposed).
* `assets/`, `data/`, `packaging/` and the `tests/` fixtures carry their
  own READMEs.
