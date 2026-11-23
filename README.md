# furus

A clean implementation of rufus in Rust, targeting Linux. `furus` is a
from-scratch rewrite that keeps the on-disk formats and behaviour of the
original Windows utility, but none of its code. The workspace name used in
the code (see `xtask`) is `furus`, as are the crate, binary and package names.

The work is organised as a slice plan. The plan document itself lives
outside this repository (module docs cite it as `rust-rewrite/PLAN.md`
by line number); it is not checked in here. What is in-repo is
`DECISIONS.md`, the frozen S00 planning-decisions record: the twelve
plan defaults (licence, public name, targets, external-tool policy, GUI
toolkit, privilege model, ...) and their S00 status. Its "no
implementation has started" line is an S00 snapshot - implementation has
advanced well past it - and, of the decisions called out
here, the public name (A2) is still proposed while the licence (A1) was
ratified 2026-11-19 as GPL-3.0-or-later (A3 and A5 were ratified the same day).

## Status

The implementation is in progress, one slice at a time. The filesystem
write side is the most complete part:

* FAT32 and exFAT are formatted natively by `furus-core` - no mount, no
  external tool - with a file API (create, write, read, list,
  timestamps, labels) verified byte-for-byte against the on-disk
  layouts.
* NTFS is written by detecting and driving the external `mkntfs` /
  `mkfs.ntfs` tool (the `ntfs-3g` package on Debian/Ubuntu, the
  separate `ntfsprogs` package on Arch), then verifying the VBR and
  reading the volume label back from `$MFT` record 3. A native NTFS
  writer is out of scope. The post-format VBR `HiddenSectors` field is
  now guaranteed by `patch_hidden_sectors` in
  `crates/furus-core/src/fs/ntfs.rs`.
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
  `crates/furus-core/src/fs/udf.rs`).
* A read-only UDF reader (S15) in `crates/furus-core/src/udf/` reads a
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
  `crates/furus-core/src/fs/tool.rs`; the version flag stays per family
  (`-V` for ext, `--version` for NTFS), UDF is probed by its usage
  banner instead, and each is passed at its call site.
* An ISO9660 image reader (S14) in `crates/furus-core/src/iso/` reads
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
* An image container layer (S15) in `crates/furus-core/src/image/`
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
  against a regular file for tests. `furus plan --verify` records a
  read-back of the whole image against the plan digest, doubling the
  I/O; `furus plan --badblocks` records a surface scan that runs in
  the wipe step. A chunk write that fails with `EIO`/`ENOSPC` is
  retried three times, five seconds apart (the failing chunk only,
  with the device size re-read before each attempt);
  `write --reset-usb` additionally resets the USB device once the
  retries are spent and retries the chunk one last time — best
  effort, off by default. The plan records `bad_blocks` (and
  `verify`); the retry/reset knobs are runtime recoveries, not plan
  content. The `--json` stream (one `Event` object per stdout line) is
  documented in `crates/furus-cli/src/main.rs` and on
  `furus_core::pipeline::Event`.
* The copy engine (S18) is wired into the write path. `furus plan
  --iso-mode` selects `WriteMode::Copy` for ISO and Raw images (the
  recommended mode for bootable sticks); a `Copy` write walks the
  ISO9660 or UDF tree onto the mounted data partition through a mount
  seam (`Opener::mount_partition`, guarded by `furus-linux`'s `Mounted`
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
  pipeline step. `furus plan --bootloader <mode>` selects the installer
  explicitly (`auto`, `syslinux`, `grub2`, `grub4dos`, `uefi-ntfs`,
  `freedos`, `kolibri`, `msdos`, `windows` or `none`); `auto` keeps the write-mode
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
  a `grldr` (the original Windows utility downloads the real loader
  `grub4dos-0.4.6a/grldr`
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
  GRUB4DOS boot test is `#[ignore]`d behind `FURUS_TEST_GRLDR` because
  the payload is not bundled; each suite prints one `skip:` line when
  qemu, grub-mkimage, mkntfs, OVMF or another tool is absent.
  `windows` plans a GPT Windows To Go layout (100 MiB ESP, MSR, NTFS
  data partition) with no write step because the bootloader step
  applies the image's WIM via wimlib, formats the ESP FAT32,
  builds the UEFI/BIOS BCD stores from the image's own `BCD-Template` (no
  Windows tools or Wine on the host), places boot manager, store, fonts, sets
  offline SAN policy 4, disables WinRE recovery and refuses any non-Windows
  image. The write path is verified end to end on real USB hardware;
  UEFI Windows To Go boot is verified in QEMU/OVMF as of commit
  `3adee7c` (the `0xc0000001` BCD boot-store bug is resolved; see
  `TECHNICAL.md` and `docs/handoffs/HANDOFF-windows-verification.md`).
  Legacy BIOS coverage is at BCD-parity unit-test level only: a dedicated
  test compares the BIOS (Boot/BCD) store's required elements and loader
  description with the UEFI store. No fresh SeaBIOS Windows boot was run
  in this environment, so no Legacy BIOS boot is claimed as verified.
* The GUI arrived in S24 and is no longer a stub: `furus-gui` opens a
  Slint window over the headless `GuiState` (device, boot selection, image
  option, partition scheme, target system, file system, cluster size, labels,
  quick format, bad blocks), refuses to run as root, and stays unprivileged —
  writes run in the separate privileged helper, never in the GUI process. Live
  hotplug watching keeps the device list current (S24 C3: a watcher thread
  whose snapshots are published to the event loop, with the selection held by
  stable device identity); selecting an image analyses it off the UI thread
  (S24 C4: size/SHA-256/kind plus the Windows-ness, boot-mode, distro and WIM
  facts, with a monotonic request id so a superseded result can never
  overwrite a newer selection), and START stays disabled until the shared
  planner accepts the current state. S25 wired the confirmed write path:
  START still only builds a plan, but it now opens a "CONFIRM DESTRUCTIVE
  WRITE" dialog carrying the captured device facts and an irreversibility
  warning; only "CONFIRM AND WRITE" attaches the plan's SHA-256 confirm token
  and hands it to a worker that starts the helper transport and streams its
  events into a run state machine. "GO BACK" discards the plan, CANCEL is
  enabled while a run is in flight, a form-wide lock freezes every
  configuration control during the run, and a show/hide log drawer renders
  the buffered events and the terminal outcome. The helper is reached through
  a pkexec reader thread or a D-Bus client on `org.furuslinux.Helper1`, with
  one fallback to pkexec when the preferred transport is unavailable. The
  CHECKSUM button now opens a cancellable modal that streams MD5, SHA-1,
  SHA-256 and SHA-512 digests at once through the core hasher with bounded
  progress, rather than echoing the single digest analysis already computed.
  A Language combo selects the display locale (from the system `.loc` asset
  or a small embedded fallback, with translation through `furus_core::i18n`),
  and Arabic, Hebrew, Persian and Urdu get RTL text alignment; the locale,
  advanced-section visibility and which of the four digests the modal shows
  are persisted as GUI preferences in a `[gui]` table of the core-owned TOML
  config. The window has not been rendered on a real display, and the
  privileged transports have not been exercised against a live system bus
  here — see `TECHNICAL.md` sections 3.7 and 3.8 for exactly what is and is
  not verified.

There is no production-readiness claim here. Open acceptance items (for
example a real 32 GB Windows installer boot) are documented as such in
the test module docs rather than faked.

### Slice completion (S21–S29)

This matrix is the authoritative completion marker for the later slices. It
also records the automation/release slices (S26, S27), which have **no rows in
the function-parity ledger** (`data/parity.csv`) because they ported no
analysed upstream function — the ledger only covers functions and thunks from
`data/functions.csv`. Those slices are tracked here instead.

| Slice | Scope | State |
|---|---|---|
| S21 | Windows To Go / FFU-WIM — GPT Windows To Go layout, WIM apply via wimlib, UEFI/BIOS BCD stores built without Windows tools, offline `SanPolicy=4` | complete (on `main`) |
| S22 | Windows User Experience — wimlib strict-link feature, NTFS overhead pre-flight reserve, dynamic locale/template-GUID fallback, regf property tests | complete (on `main`) |
| S23 | Hashing / SBAT / EFI fixup — MD5/SHA1/SHA256/SHA512 hashing, shared plan builder, bootloader submodules and bad-blocks reconciliation; the ledger also assigns the `hash-efi` (SBAT + EFI boot-file fixup) module here | complete (on `main`) |
| S24 | Slint GUI — unprivileged window over `GuiState`, hotplug device watch, background image analysis | complete (on `main`) |
| S25 | Update check + confirmed write flow — confirmation-gated GUI run and helper IPC transports, four-digest checksum modal, locale/preferences; the parity ledger assigns the `net` (HTTP update check/download) module here, but only the `check_updates`/`update_channel` config fields exist, not a live update-check feature | complete (on `main`) |
| S26 | Release bundles / packaging — finalized `packaging/` metadata and the deterministic `cargo xtask dist` bundle | complete (on `main`) |
| S27 | Automated QA gate — the two-tier `cargo xtask qa` release gate | complete (on `main`) |
| S28 | CI dependency fix — install fontconfig/winit native build headers on ubuntu-latest so `xtask ci` (clippy) and `xtask qa` both run green | complete (on `main`) |
| S29 | GUI / IPC verification — single-source D-Bus/polkit/packaging contract with a CI drift check, offscreen Slint render smoke, and a real compiled-helper JSONL/run-state wire test | complete (on `main`) |
| S31 | Native packages in CI — parameterized RPM/Arch recipes and a dual-architecture release workflow that builds `.rpm` and `.pkg.tar.zst` natively for x86_64 and aarch64 under one unified `SHA256SUMS` (8 packages + digest = 9 assets) | complete (on `main`); workflow validated end-to-end for both architectures — dry run `44931040759` (publish=false) green; release v0.1.1 published 2026-11-21 via tag-push run `44933721775` with 9 assets (8 packages + unified `SHA256SUMS`), verified against GitHub asset digests |
| S33 | Release hygiene, portability, module split and live GUI fixes — unified version 0.1.1, standardized `Furus`/`furus` naming, portable glibc/musl SIGINT via `libc::sigaction`, distro-portable paired OVMF discovery with CI shims removed, pure-refactor module splits across `furus-cli`, `furus-core::fs::exfat::volume`, `xtask` and test extraction, plus the portal-first non-blocking picker (S32/S33.6), fast two-phase ISO analysis with background cancellable SHA-256, and themed/bounded confirm and checksum modals | complete (local `main`, reviewed); v0.1.1 tagged/published earlier, no new tag or push from S33; 1917 tests, full `ci`/`qa`/`dist` gate green |
| S34 | Live-desktop fixes after S33 — resolve the installed `furus-helper` path for `pkexec` (reuse single-source `HELPER_BIN_PATH` via a three-step resolver, no duplicated literal) and theme the `Show log` drawer with `Palette` colors plus an RGB render-smoke contrast test | complete (local `main`, reviewed); `6aaefd4` (pkexec helper path) + `d241942` (themed log drawer); 1921 tests, full `ci`/`qa`/`dist` gate green; no new tag or push from S34; publication left to manual maintainer / Publisher |
| S35 | Real verified write pipeline in `furus-helper` with immediate GUI feedback — run the CLI-equivalent core write pipeline from the helper (all five core `Event` variants mapped to proto log/progress, CLI-equivalent failure→outcome mapping, single-source opener derivation) over a `PlanRunner` seam; allow safe host-namespace auto-unmount of non-system removable media with a strict post-unmount re-check and protected-path fail-closed guard; stream cancellable SHA-256 image verification with immediate log + percent progress before any unmount/write; set step/status to "Authenticating and starting helper…" on confirm | complete (local `main`, reviewed); `94728b2` (real pipeline) + `d7765f` (safe auto-unmount policy) + `8c3038d` (host-namespace unmount + strict recheck) + `0fc6f08` (streamed digest verification); 1957 tests (1928 passed / 29 ignored); full `ci`/`qa`/`dist` gate green; the user-deferred `RUSTSEC-2026-0592` cargo-deny advisory (`url` 2.5.8 via pinned Slint 1.19) was resolved after S35 by a lockfile-only `url` bump to 2.5.9 and CI is now fully green; no new tag or push from S35; publication left to manual maintainer / Publisher sign-off |

| S36 | Volume-label safety and log UX — one shared per-filesystem `furus_core::fs::label` validator/sanitizer (FAT32 11 ASCII bytes, exFAT 11 UTF-16 units, ext 16 ASCII bytes, NTFS 32 UTF-16 units, UDF 126 UTF-8 bytes) enforced by the planner and helper before any destructive step; GUI auto-sanitizes ISO labels and re-clamps on filesystem change; one-click **Copy log** with a Wayland/X11 clipboard-helper chain; footer **CLOSE** and the window-manager close blocked while a write is in flight | complete (local `main`, reviewed); `b1316ea` (core/helper label validation) + `b09b3d7` (GUI label sanitizing) + `cadf9bf` (Copy log clipboard) + `78b8f07` (write-in-progress close guard); new test floor **1990** (1961 passed / 0 failed / 29 ignored); full `ci`/`qa`/`dist` gate green; no new tag or push from S36; publication left to manual maintainer / Publisher sign-off |

#### Update-check fields are dormant (A12)

The `check_updates` and `update_channel` config fields from the S25 row above
exist only for schema compatibility. They are **dormant no-ops**: persisted and
round-tripped, but never acted on. No code performs an update check, and there
is **no HTTP client and no background network call** anywhere in the tree —
nothing connects to the network because of these fields. This keeps Decision A12
("telemetry: none; network only on explicit user action", still **proposed**)
intact; do not read S25's `net` ledger row as a live update-check feature.

### `analyze` report

`furus analyze [--json] <image>` reports the S16 image analysis in a
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

* `furus-proto` - versioned plan/progress types shared by the CLI, GUI
  and helper: the `Plan` contract and its `Plan::confirm` hash, plus the
  helper event stream.
* `furus-core` - the safe, non-privileged foundation and the filesystem
  write side: error/config/paths/i18n/hash/units, MBR + GPT table
  readers and writers, the FAT32/exFAT/NTFS/ext2/3/4/UDF formatters,
  the ISO9660/Joliet/Rock Ridge image reader (`iso/`), the read-only
  UDF reader (`udf/`) and the image container layer (`image/`),
  superblock probing and the safety verdict.
* `wimlib-sys` - FFI bindings to wimlib, for applying WIM/ESD images.
* `furus-linux` - the only crate that touches `/sys` and `/run/udev`:
  device discovery, mount/swap/holder introspection, and the
  block-ioctl shim.
* `furus-helper` - the privileged write helper: validates a plan and
  runs it, exposed over D-Bus behind polkit; it runs as root, the GUI
  never does.
* `furus-cli` - the `furus` command-line front end: version, checksum,
  analyze, plan, list, write.
* `furus-gui` - the Slint desktop front end (S24: the window, the headless
  `GuiState` it renders, the `std::thread` device watch and the background
  image analyzer; S25: the confirmation-gated run flow, the cancellable
  four-algorithm checksum modal, the locale and GUI-preference bridges, and
  the pkexec/D-Bus helper transports. It still owns no privilege: confirmed
  writes run in the helper).
* `xtask` - repo maintenance: asset-manifest check, parity check, the
  per-binary size gate, CI ordering, `dist` (release bundles - see Build
  below), and `qa` (the two-tier end-to-end release gate - see Tests below).

The crate layering keeps privileged I/O in `furus-linux` /
`furus-helper` and the formatter logic in `furus-core`, which never
depends on `furus-linux` (see `crates/furus-core/src/fs/mod.rs`).

Safety and dependencies: the workspace denies unsafe code; `furus-linux`
carries two documented allowances - the four block ioctls
(BLKZEROOUT/BLKDISCARD/BLKRRPART/BLKFLSBUF) in
`crates/furus-linux/src/ioctl.rs` that rustix does not wrap, and the
SIGINT handler install in `crates/furus-linux/src/signal.rs` (one atomic
store, nothing else) - and `wimlib-sys` carries two more (the raw FFI
declarations in `src/ffi.rs` and the safe facade in `src/safe/bound.rs`
with its C calls, trampolines and string decoding). Every other crate
root keeps `#![forbid(unsafe_code)]`. The one exception in spelling is
the `furus-gui` binary target, which uses `#![deny(unsafe_code)]`:
`slint::include_modules!()` expands to vtables that hardcode
`#[allow(unsafe_code)]`, and an `allow` under a crate-level `forbid` is a
hard error (E0453). The `furus-gui` library root keeps the `forbid`, no
hand-written `furus-gui` line contains `unsafe` or `#[allow(unsafe_code)]`,
and the workspace lint would reject one (see `TECHNICAL.md` section 3.7).
`furus-core` is dependency-light by design: no async runtime, no logging
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

At the S25 tip it reports `furus` 1,810,152 bytes (budget 3,000,000),
`furus-helper` 1,406,296 (2,500,000) and `furus-gui` 12,774,280
(14,000,000 — raised from 12 MB in S25 to absorb the two zbus versions and
the rest of the S25 GUI growth), `size: within committed baseline allowance,
all budgets OK`.

### Release bundles (`cargo xtask dist`)

Building is not the same as shipping: `cargo xtask dist [--target <triple>]
[--out-dir <dir>]` release-builds the workspace, enforces the same size
budgets, validates the eleven finalized `packaging/` files (XML via quick-xml,
INI via a hand-written parser, plus distro-token checks), stages an exact
twelve-file FHS tree, and writes a deterministic
`furus-<version>-<triple>.tar.gz` alongside a `SHA256SUMS`. The default target
is the rustc host triple and the default output directory is
`target/dist/<triple>`; `sha256sum -c SHA256SUMS` verifies a bundle. Entries
are sorted and uid/gid/mtime and the gzip mtime are zeroed so the tarball is
byte-for-byte reproducible; stored mtimes of zero may display as `1970-01-01`
in `tar -tv`, shifted by the local timezone, which is display only.

A `.deb` is built only where `dpkg-deb` is installed (`dpkg-deb
--root-owner-group`); elsewhere the command prints `skip .deb: dpkg-deb not
available` and still succeeds with the tarball and digest file - this host has
no `dpkg-deb`, so `.deb` generation is not verified here. The staged tree puts
the CLI and GUI at `/usr/bin/furus` and `/usr/bin/furus-gui` and the privileged
helper at `/usr/libexec/furus-helper` (root-owned, 0755): the GUI never runs as
root, so writes happen only in the helper, gated by the polkit action, and the
D-Bus system.d configuration restricts who may own the well-known name. The
polkit policy, D-Bus files, desktop entry, AppStream metainfo, icon and licence
texts install under `/usr/share`; only the `.deb` uses `DEBIAN/control` and
`DEBIAN/postinst`.

The Arch `PKGBUILD` and RPM `furus.spec` consume that same single tarball and
its staged `usr/` tree, so the artifact name and layout are a contract - no
second tarball, no flattened archive. The packaging files keep the
`org.furuslinux.*` namespace because the GUI and helper hardcode those bus and
polkit identifiers, and the external formatters (`ntfs-3g`, `e2fsprogs`,
`udftools`, wimlib) are recommendations or optional dependencies rather than
hard ones, since decision A4 makes them runtime-checked. `packaging/README.md`
has the full install-path table and service-verification commands.

### Release assets / install

Every `v*` tag is built automatically by `.github/workflows/release.yml` from
**two native builds** — one on `ubuntu-latest` (x86_64) and one on
`ubuntu-24.04-arm` (aarch64). Each architecture produces the same four artifact
kinds from its own `cargo xtask dist --target <triple>` build: a generic
`.tar.gz` tarball, a `.deb`, an `.rpm` and a `.pkg.tar.zst`. The architecture is
part of every filename, so the two sets cannot collide. The release publishes
all eight packages plus one unified `SHA256SUMS` covering every artifact.

Both an x86_64 and an aarch64 file of each kind exist; pick the one matching
your machine. Install the native package for your distro from the directory
holding the downloaded files (the `./` makes your package manager use the local
file, and the glob matches whichever architecture you downloaded):

* Ubuntu/Debian: `sudo apt install ./furus-*.deb`
  (e.g. `furus-0.1.1-x86_64-unknown-linux-gnu.deb` or
  `furus-0.1.1-aarch64-unknown-linux-gnu.deb`)
* Fedora: `sudo dnf install ./furus-*.rpm`
  (e.g. `furus-0.1.1-1.fc45.x86_64.rpm` or `furus-0.1.1-1.fc45.aarch64.rpm`)
* Arch Linux: `sudo pacman -U ./furus-*.pkg.tar.zst`
  (e.g. `furus-0.1.1-1-x86_64.pkg.tar.zst` or
  `furus-0.1.1-1-aarch64.pkg.tar.zst`)

The single `SHA256SUMS` has one line per package (eight in total). Verify your
downloads against it from the same directory:

```
sha256sum -c SHA256SUMS
```

`packaging/README.md` has the full install-path table and service-verification
commands.

## Tests

The formatters are verified against real external tools, which the
suites use when present and skip (with an explicit `skip:` line, never a
silent pass) when absent:

* `crates/furus-core/tests/fat32_format.rs` - `fsck.fat -n` must accept
  the written image at 64 MiB, 2 GiB, 32 GiB and the 2 TiB limit.
* `crates/furus-core/tests/exfat_format.rs` - `fsck.exfat`,
  `dump.exfat` and `exfatlabel` (exfatprogs) must call the image clean
  and read back the geometry and label.
* `crates/furus-core/tests/ntfs_format.rs` - `mkntfs`, `ntfsfix -n` and
  `ntfslabel` must agree with the written volume; the VBR-declared
  bounds and the `$MFT` record-3 label read are pinned.
* `crates/furus-core/tests/udf_format.rs` - `mkudffs`, `udfinfo` and a
  kernel mount must agree with the written volume across the block-size
  matrix (512/2048), the label shapes (short, 126-byte ceiling,
  default) and the pinned `--udfrev=0x0201` revision.

The kernel-mount tests are `#[ignore]`d: they need root and a loop
device, run on demand with `sudo -E $(which cargo) test --offline
-p furus-core --test <suite> -- --ignored --nocapture`, or inside the
documented privileged container (an `archlinux` image; the NTFS suite's
module doc records the `pacman -Sy --noconfirm ntfs-3g ntfsprogs`
package split). Two further suites exercise the mount and boot seams:
`crates/furus-linux/tests/mount_seam.rs` mounts FAT32, exFAT and NTFS
through the real kernel (`#[ignore]`d, root + loop devices, run with
`-p furus-linux --test mount_seam`), and
`crates/furus-core/tests/uefi_ntfs_boot.rs` boots the UEFI:NTFS shim
against a real NTFS volume in OVMF (unprivileged; it runs in the normal
suite and skips with one `skip:` line when qemu, grub-mkimage, mkntfs,
ntfscp, unshare, ntfs-3g or the OVMF images are absent).

### Automated QA gate (`cargo xtask qa`)

`cargo xtask qa` is the S27 end-to-end release gate: one command that
orchestrates the suites above and reports one `PASS`, `FAIL` or `SKIP` line
per stage, ending in `qa: all suites passed` (or a list of failures). It is
unprivileged by default and safe to run on a plain CI runner. From this host:

    env -u APPDIR PATH="$HOME/.cargo/bin:$PATH" cargo xtask qa

* **Tier 1 — always on, unprivileged, sparse-file targets only.** It runs the
  MBR/GPT partition-table suite, the FAT32/exFAT/NTFS/ext4/UDF formatter
  suites, the UEFI:NTFS structural tests, and the Windows BCD / SYSTEM hive
  suites (the BCD element set, the `0xc0000001` regression guard, and
  `SanPolicy=4` in the SYSTEM hive). No root and no loop devices are needed:
  these are file-backed images and structural tests.
* **Tier 2 — headless QEMU boot checks, when QEMU + firmware are installed.**
  BIOS is checked twice: a self-contained smoke test boots a hand-assembled
  512-byte MBR (real-mode loop printing `FURUS-QA-OK` to COM1, asserted over
  `-serial stdio` under SeaBIOS), then the real Syslinux 4.07, FreeDOS and
  GRUB2 BIOS boot suites run. UEFI delegation reuses the existing
  OVMF/UEFI:NTFS `uefi_ntfs_boot` harness, which asserts its own
  `UEFI-NTFS-OK` serial marker instead of crafting an EFI binary in xtask.
* **Strict deadlines and kill/reap.** Every suite has a 120-second backstop
  deadline (the BIOS smoke boot gets 30 seconds), and the spawned child is
  killed and reaped on timeout, failure or early return (`ChildGuard`), so a
  hung machine can never hang CI. Missing tools or firmware produce an
  explicit `SKIP` line, never a silent pass.
* **Flags.** `--require-qemu` makes a missing QEMU/OVMF toolchain fatal
  instead of skipping; `--privileged` additionally enables the
  loop-device/mount and pipeline end-to-end suites, which are `#[ignore]`d
  and off by default. `APPDIR` is removed at spawn so a stale AppImage
  variable cannot break asset lookup.

CI runs `cargo xtask qa` as a gate on pushes and pull requests, after
installing the filesystem, QEMU/OVMF and GRUB tools the suites need
(`.github/workflows/ci.yml`). On `ubuntu-latest` the workflow also installs
the native build headers Slint/winit need (`pkg-config` plus the fontconfig,
xkbcommon, wayland and xcb dev packages) and shims Ubuntu's `OVMF_*_4M.fd`
firmware into the Arch-style `/usr/share/edk2/x64/*.4m.fd` paths the harness
expects, so Tier 2 UEFI boots on CI instead of skipping.

### GUI / IPC verification (S29)

Three automated gates cover the GUI/helper split; none needs root, a display
server, a real block device or a new dependency:

* **Contract identifiers** — `cargo xtask contract --check`, wired into
  `cargo xtask ci` between parity and size, reads the D-Bus / polkit / packaging
  identifiers single-sourced in `furus-proto::service` and fails on any drift
  in the GUI, helper or packaging copies.
* **Offscreen render smoke** — `cargo test -p furus-gui --test render_smoke`
  instantiates the Slint window through the software renderer with every
  overlay visible, renders a non-blank frame and needs no window system.
* **Real helper wire** — `cargo test -p furus-gui --test helper_wire` launches
  the compiled helper under `unshare -Ur`, drives its real JSONL event stream
  through the GUI's parser and run state machine, and asserts a
  `not_a_block_device` refusal with no device I/O or writes (root exists only
  inside the user namespace).

`cargo-audit` remains a documented `SKIP` here (not installed on this host),
and the non-fatal duplicate-crate warnings from `cargo-deny` are pre-existing.

## Docs

* `DECISIONS.md` - frozen S00 planning decisions; implementation has
  since advanced (its section 4 records the post-S00 tool amendment).
* `TECHNICAL.md` - technical notes and architectural decisions (including
  the S21 Windows To Go design, registry tweaks, and UEFI boot verification).
* `docs/handoffs/` - archived handoff notes from earlier slices, including
  `HANDOFF-windows-verification.md` (QEMU/OVMF UEFI boot acceptance) and
  `HANDOFF-boot-c0000001.md` (the resolved `0xc0000001` BCD boot-store bug).
* `LICENSES.md` - asset licence audit for the 4.15 resources of the original
  Windows utility that the implementation reuses; the code licence is
  GPL-3.0-or-later (decision A1, approved 2026-11-19).
* `assets/`, `data/`, `packaging/` and the `tests/` fixtures carry their
  own READMEs.
