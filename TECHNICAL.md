# Technical Notes: furus

This document explains the architecture, design choices, data flow, dependencies, and trade-offs of the `furus` codebase, with a specific focus on the S21 Windows To Go implementation.

---

## 1. Overall System Architecture & Principles

`furus` is a clean, from-scratch implementation of Rufus written in Rust for Linux. It reproduces Rufus's on-disk layouts, bootloader installation logic, and partition schemes without copying code from the upstream C codebase.

### Workspace Crate Architecture

The repository is organised as a Cargo workspace with strict privilege and responsibility separation:

* **`rufus-proto`**: Shared wire contract between the CLI, GUI, and the privileged daemon. Defines versioned `Plan`, `Confirm`, and structured event streaming schemas. Serialises deterministically to JSON.
* **`rufus-core`**: Unprivileged foundational library. Contains:
  * In-memory filesystem writers (native FAT32, native exFAT) and external tool drivers (NTFS, ext2/3/4, UDF).
  * Partition table parsers and generators (MBR, GPT).
  * Read-only image decoders: ISO9660 with Joliet/Rock Ridge, UDF reader, and container readers (VHD, VHDX, qcow2, FFU).
  * Superblock probing, safety checks, and target classification.
  * Dependency-light by design: `#![forbid(unsafe_code)]`, no async runtimes, no logging frameworks.
* **`wimlib-sys`**: Minimal, safe FFI bindings over `libwim` for inspecting and extracting WIM/ESD/SWM archives without dragging Windows binaries or Wine into the Linux environment.
* **`rufus-linux`**: Linux-specific platform adapter. Interacts with `/sys`, `/proc`, `/run/udev`, and block device nodes. Handles mounting, disk discovery, partition enumeration, and block ioctls.
* **`rufus-helper`**: Privileged daemon executed via Polkit/D-Bus or run directly as root. Confirms plan cryptographic digests and executes pipeline steps within isolated namespaces where needed.
* **`rufus-cli`**: CLI binary (`rufus`) exposing inspection, analysis, planning, and writing capabilities.
* **`rufus-gui`**: Slint-based graphical user interface front-end (S24): an unprivileged Slint 1.19.0 window over a headless `GuiState`; it never runs as root and never writes to a device.
* **`xtask`**: Repository maintenance automation (binary size enforcement, parity ledger validation against upstream Rufus 4.15, asset integrity verification).

---

## 2. S21: Windows To Go Architecture & Design

Slice 21 (S21) implements full support for Windows images, focusing on the Windows To Go deployment flow: converting a Windows installation ISO (or raw WIM) into a bootable Windows environment on a removable target.

### 2.1 Partition Layout (`LayoutKind::WindowsToGo`)

Windows To Go requires a multi-partition layout on a GPT disk:
1. **Partition 1: EFI System Partition (ESP)**
   * Size: 100 MiB (204,800 sectors at 512-byte LBA).
   * Filesystem: FAT32.
   * Type GUID: `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`.
   * Label: `EFI System Partition` / `ESP`.
2. **Partition 2: Microsoft Reserved Partition (MSR)**
   * Size: 16 MiB (32,768 sectors).
   * Filesystem: Unformatted raw space.
   * Type GUID: `e3c9e310-0b45-43a6-a86b-e8e642d14f00`.
3. **Partition 3: Windows OS Data Partition**
   * Size: Remaining capacity of the disk.
   * Filesystem: NTFS.
   * Type GUID: `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7` (Basic Data).
   * Label: `Windows`.

### 2.2 Execution Pipeline

A Windows To Go installation runs through the standard pipeline steps with a critical distinction: **no separate `Write` step is executed**.
- Standard ISO writes copy or stream the raw image directly onto a volume.
- In contrast, `--bootloader windows` handles image extraction and system provisioning directly inside the `bootloader` step:
  1. `Wipe`: Clears partition signatures and initial/trailing sectors.
  2. `Mklabel`: Writes the GPT table.
  3. `Mkpart`: Creates ESP, MSR, and Data partitions according to the WindowsToGo layout.
  4. `Mkfs`: Formats the Data partition as NTFS using the system's `mkntfs` tool.
  5. `Bootloader` (`BootloaderMode::Windows`):
     - Formats the 100 MiB ESP partition as FAT32 natively via `rufus-core` (without mounting or invoking external utilities).
     - Applies the selected image index from `install.wim` (or `install.esd`) onto the mounted NTFS partition via `wimlib-sys`.
     - Builds the Boot Configuration Data (BCD) stores for both UEFI and BIOS firmwares.
     - Places boot managers (`bootmgfw.efi`, `bootmgr`), font support files, and memory diagnostics.
     - Edits the target's offline registry hives to configure SAN policy and disable WinRE recovery.
  6. `Finalize`: Flushes filesystem caches, syncs block devices, and clears temporary mounts.

---

## 3. Key Technical Decisions & Innovations

### 3.1 BCD Store Generation (Registry Hive Manipulation in Pure Rust)

Windows requires binary BCD stores formatted as Windows Registry hives (`regf` format). Historically, creating BCD on Linux required invoking `bcdboot.exe` under Wine or pulling in complex dependencies.

**Decision**: Implement a pure-Rust BCD engine using `BCD-Template` extraction.
- Windows installation media carries a template hive at `\Windows\System32\config\BCD-Template` inside `install.wim`.
- `rufus-core` parses this `regf` hive and, the way Microsoft `bcdboot` does, CLONES fresh OS-loader and resume objects from `BCD-Template` rather than patching the template objects in place. On UEFI the fresh loader is `{3796cdc8-e33b-11f1-b950-525400123456}` and its resume object is `{3796cdc7-e33b-11f1-b950-525400123456}` (BIOS variants end in `...123457`). The template objects to clone are resolved by fixed GUID first; for custom templates where that GUID is absent, a bounded scan of `Objects/*` matches the `Description\Type` REG_DWORD bitmask (`0x10200003` OS loader, `0x10200004` resume), with an `accept` predicate that skips unusable candidates so one malformed or unsuitable object cannot break store construction. It then:
  - repoints `{bootmgr}` at the fresh loader (`23000003`, `24000001`) and resume object (`23000006`), and gives `{bootmgr}` its own `11000001` device pointing at the ESP (system/data partition on BIOS);
  - writes the loader's `12000004` description derived from the applied WIM image name (for the eval image: `Windows 11 Enterprise Evaluation`). **This element is REQUIRED**: without a non-empty loader `12000004`, bootmgr rejects the store and the boot lands in Recovery with `0xc0000001`. The caller (`run_windows`) therefore always supplies a non-empty description (WIM image name, then description, then a `Windows` fallback), guarded by a regression test that reads the on-disk BCD.
  - writes the resolved locale to `12000005` and the 8-byte `REG_BINARY` encodings that `bcdboot` uses (`25000020`, `250000c2`, `25000008`) at all four locale sites, and sets `{memdiag}`'s device to the ESP. Locale precedence is: a locale supplied from the applied tree → the BCD-Template's own `12000005` → `en-us`. `to_go::install()` discovers the locale via `boot_files::locale_from_tree()` (case-insensitive `.mui` entries under `Windows/Boot/EFI/<locale>/`, symlinks skipped), falling back to `bcd::locale_in_template()`. A supplied locale is validated before any parse/mutation and is written verbatim (e.g. `de-DE` stays `de-DE`; there is no normalization), with `en-us` when the template carries no valid locale.
- **Verification**: A known-good reference BCD was regenerated by running real `bcdboot` inside WinPE on the written image, then A/B boot-tested. Our output has 18 objects (the 16 template objects plus the fresh loader/resume; the two superseded template loaders are retained but inactive). Every ACTIVE object matches the `bcdboot` reference element-for-element (modulo per-disk GUIDs), with valid header checksums. The A/B test proved the loader `12000004` description is load-bearing: a known-good BCD with that single element removed fails with `0xc0000001`, while ours with it added boots past bootmgr.

### 3.2 Registry Tweaks for Portable USB Operation

Running Windows from a USB drive requires modifying target offline registry settings before first boot:
1. **SAN Policy 4 (Offline Internal Disks)**:
   - Sets `Storage\Policies\SanPolicy = 4` in `SYSTEM\ControlSet001\Services\partmgr\Parameters`.
   - Prevents Windows To Go from mounting or altering internal hard drives of host machines it boots on.
2. **WinRE Disabled**:
   - Removes or disables recovery redirects to avoid boot failure loops if recovery partitions are absent on portable media.

### 3.3 Hardware Concurrency and Kernel Mount Races

During real hardware validation against real USB devices and loop images, several subtle Linux kernel block-layer and automount interactions were diagnosed and resolved:

1. **Partition Node Naming by Kernel Rule (`3dab9ff`)**:
   - The Linux kernel appends `p` to partition numbers only when the parent disk node ends in an ASCII digit (`/dev/loop1` -> `/dev/loop1p3`, `/dev/nvme0n1` -> `/dev/nvme0n1p3`), but appends directly for letter-ending devices (`/dev/sdb` -> `/dev/sdb3`). `furus` now strictly models this kernel rule, ensuring synthetic and unpopulated disks resolve partition paths correctly.
2. **Pre-mount Release of Existing Mounts (`0171dcb`)**:
   - Desktop environments run automounters (such as `udisks2` / `udiskie`) that automatically mount partitions when `mkfs` finishes. The Linux `ntfs3` driver refuses secondary mounts with differing mount flags (`EBUSY`). The mounting logic explicitly inspects `/proc/self/mountinfo` and releases existing claims on the target partition node before issuing `mount(2)`.
3. **Releasing Whole-Disk Handle Before Partition Mount (`7cc42d4`)**:
   - The whole disk was held open with `O_RDWR | O_EXCL` for raw partition table and BCD identity inspection. The Linux kernel rejects mounting any individual partition (`Can't open blockdev`, `EBUSY`) while an exclusive handle on the parent disk is alive. `run_windows` explicitly releases the disk handle after reading geometry and raw identifiers, prior to mounting ESP and data partitions.
   - Nothing on the post-release path may reopen the disk either. `DeviceOpener::partition()` re-opens the parent disk `O_RDWR | O_EXCL` and caches that handle, so reading the data partition's capacity through it (as `run_windows` once did, to pass `apply_ntfs` its pre-flight `capacity`) re-created the very claim the release had dropped, and the following data mount failed with `EBUSY`. The capacity now comes from the stamped plan geometry (`data_window(LayoutKind::WindowsToGo, TableKind::Gpt, sector_size, size)`), the same window the BCD identity and the opener's partition window use, so the released disk stays closed until a mount needs it. Opening the partition volume is the only such reopen on this path; `partition_path()` just names the node.
4. **Stale Mount Eviction for Exclusive Open (`4bfa5b0`)**:
   - Reopening the disk exclusively when automounters immediately claim new partitions failed with `EBUSY`. `DeviceOpener::open` checks the mount table on busy errors, tears down any stale automounts matching the disk or its partitions, and executes a controlled retry.

### 3.4 NTFS Post-Format VBR `HiddenSectors` Guarantee

Windows recognises an NTFS partition as the system volume only when the VBR's `HiddenSectors` field (u32 LE at byte offset `0x1C`) holds the partition's start LBA. The NTFS formatter passes that geometry to the external `mkntfs` as `-p <start> -H 255 -S 63` (hidden sectors, heads, sectors per track) alongside `-f [-L <label>] -c <cluster>`, using the same large-disk CHS values the FAT32 side's BPB carries.

Older `mkntfs` builds and cross-distro packages may silently ignore `-p` and leave `HiddenSectors` as zero, so the geometry flags alone are not trusted. After `mkntfs` completes and the VBR has been verified, `fs::ntfs::patch_hidden_sectors` reads the four-byte field, writes the requested partition start LBA when it differs, and re-reads it to confirm the write persisted. The operation is a single 4-byte `write_all_at` on a read+write handle the function opens itself, so it cannot corrupt the rest of the VBR; it is a no-op when geometry was not requested or the field is already correct. Unit tests cover the patch directly and pin its call site inside `format_with` (after a format through a stub formatter, the field equals the partition start LBA).

The backup / alternate boot sector is intentionally out of scope: this guarantee covers the primary VBR only, which is the one Windows reads for the boot path.

### 3.5 WIM Apply Pre-Flight and Optional Strict Linking

**NTFS overhead reserve.** WIM apply refuses a target whose free space cannot cover the decoded payload *plus* a conservative NTFS overhead reserve. `required_with_ntfs_overhead(required)` computes `required + max(64 MiB, required / 50)` with saturating arithmetic (a 64 MiB floor or 2% slack, whichever is larger). Both pre-flight paths enforce it: `apply()` against `mounted.free_bytes()` and `apply_ntfs()` against `capacity`, each rejecting with `CoreError::InvalidInput` before any write begins. The reserve is deliberately generous — exact NTFS metadata/compression overhead cannot be predicted from the WIM alone — so a target that would technically fit can be rejected.

**Opt-in strict linking (`wimlib-sys`).** By default `wimlib-sys` builds gracefully without a system `libwim`: `build.rs` probes for the library and, when absent, still compiles an unbound stub (`linked() == false`) rather than failing the build. The opt-in `strict-link` Cargo feature turns a missing library into a compile-time `compile_error!` (it also trips under `WIMLIB_SYS_FORCE_UNLINKED=1`). Default builds are unchanged and the feature adds no dependency.

**Deterministic regf mutation property test.** `regf.rs` carries a test-only, seeded (xorshift64*, no dependency, fixed seed) property test that runs 500 sequences × 20 randomized mutation operations — 10,000 verified steps — against a `BTreeSet`/`BTreeMap` shadow model. After every step it re-serializes the hive, re-parses it, recomputes/validates the header checksum and calls `check_bins()`, then compares `find_child` / `find_value` / `read_value` / `element_value` and the exact child/value sets on the reparsed hive against the shadow, catching silent corruption. Operations cover root and nested key adds (with and without a model), element/value writes and overwrites, removals, explicit `append_hbin()`, and churn drain/refill. Documented deviation: this editor's `alloc()` caps a single cell at `HBIN_USABLE` (4064 B) and cells cannot span `hbin` pages (there is no `db` big-data path), so the test uses 4–4056 B payloads and forces cross-bin growth through many near-page-size values plus `append_hbin()`, rather than a single 16 KiB value. No production fix was required; four alternate seeds also passed.

### 3.6 S23: Shared Plan Builder, Bootloader Submodules & Bad-Blocks Reconciliation

**Shared provisional plan builder (`crates/rufus-core/src/planner/`).** The plan construction that lived in `crates/rufus-cli/src/plan.rs` (1,162 lines) moved into `rufus-core` so the CLI and the S24 Slint GUI call the same rules instead of a copy. The module exports:

* `BootloaderOpt` — the `--bootloader` selector with `mode()` (plan's `rufus_proto::BootloaderMode`) and `layout()` (`Single`, `UefiNtfs` or `WindowsToGo`). `crates/rufus-cli/src/plan.rs` keeps only a `clap::ValueEnum` twin of the same shape plus a `From` conversion (85 lines), so the flag spelling stays part of the CLI contract and `clap` never enters `rufus-core`.
* `Options` — `scheme`, `target`, `filesystem`, `label`, `cluster_bytes`, `quick_format`, `iso_mode`, `bootloader`, `msdos_dir`, `bad_blocks`, `verify`, `persistence`, `show_all`, `confirmed_serial` (the same fields the CLI flags filled before).
* `write_mode()` — the transfer mode: content wins over the extension (`Iso`/`Raw` and the compressed kinds stream by `Dd`, containers by `Copy`), the extension is only a tiebreaker for `Unknown` content, and `iso_mode` flips tree-walkable images to `Copy`.
* `steps()` — `Wipe` → `Mklabel` → `Mkpart` → `Mkfs` → [`Write`] → `Bootloader` → `Finalize`. `msdos` and `windows` plan no `Write` step (the former must place `IO.SYS` first on the fresh volume, the latter applies the WIM in the bootloader step); `windows` also overrides `--filesystem` to NTFS in both the options and the mkfs step; `uefi-ntfs` forces `Copy`.
* `build()` — refuses the mode/filesystem pairings (`uefi-ntfs` needs NTFS or exFAT, `freedos`/`kolibri`/`msdos` need FAT32, `msdos` needs a non-empty `msdos_dir` and `--msdos-dir` is refused with any other mode), then seals the `Plan` and recomputes its confirm SHA-256.
* `DeviceProbe` / `DeviceFacts` — the platform boundary. `rufus-core` only *grades* the facts: without `--dry-run` a missing path is a device refusal and an existing non-block path a safety refusal, with `--dry-run` both are planned with `block_device: false`; when `facts` is present the mapper fields (`size_bytes`, `serial`, `model`, `sysfs`) ride into the plan and `block_device` is forced true, because a discoverable device is a block device on its root. The refusal messages are the pre-extraction ones, verbatim. `rufus-linux` fills the probe: `probe_device(path, sysfs)` (`std::fs::metadata` + sysfs discovery) and `plan_device_ref(&Device)` for an already-selected device model. `crates/rufus-core/Cargo.toml` still lists no `rufus-linux`, so the S23 hard constraint holds.
* `PlanError { Device, Safety, Usage, Confirm }` replaces `rufus_cli::Fail` inside the builder; `main.rs::fail_from_plan` maps it back to exit 2 (`device`), 3 (`safety`), 1 (`usage`) and 4 (`json`, the confirm-hash case). CLI flags, `PLAN_VERSION` 6 JSON, and exit codes 0–7 are unchanged.
* The image inspection preamble moved to `rufus_core::image::{inspect, file_size, detect_file}` (`ImageInfo`: path, size, SHA-256, magic-only kind — field for field `rufus_proto::ImageRef`). `crates/rufus-cli/src/image.rs` is a 9-line re-export surface that keeps the historical `image_size` spelling for `checksum`.

**Bootloader submodules (`crates/rufus-core/src/pipeline/bootloader/`).** The 7,602-line `bootloader.rs` became:

| File | Lines | Contents |
|---|---|---|
| `mod.rs` | 735 | shared dispatch (`install_tree`, `run`), the `Installed` report vocabulary, `DiskView`/`gap_end` and the post-MBR-gap bound the BIOS arms share |
| `syslinux.rs` | 94 | Syslinux 4.07/6.04 (VBR graft, stage file, companions, `syslinux.cfg`) |
| `grub2.rs` | 94 | GRUB2 BIOS record + `core.img` + UEFI payload |
| `grub4dos.rs` | 72 | GRUB4DOS record + `grldr` |
| `dos_kolibri.rs` | 243 | FreeDOS, KolibriOS, MS-DOS and their `run_msdos` arm |
| `uefi_ntfs.rs` | 129 | UEFI:NTFS shim + ESP window |
| `windows.rs` | 561 | Windows To Go arm: identity, BCD, apply, boot files |
| `tests/` (`mod`, `dos`, `grub`, `run`, `syslinux`, `uefi`, `windows`) | 3,553 | the 52 unit tests, fixtures and test doubles |
| `end_to_end/` (`mod`, `qemu`, `qemu_boot`) | 2,225 | the 9 end-to-end tests, the QEMU VGA capture harness and the 4 QEMU boot tests |

No public item changed: the arms and the submodules stay private (`pub(super)`), `Installed`, `install_tree` and `run` keep their `pub(crate)` signatures, and `end_to_end` stays a `#[cfg(test)] pub(crate) mod` with `seed_exe_assets` still reachable as `pipeline::bootloader::end_to_end::seed_exe_assets`. Every file is under 1,800 lines (largest: `end_to_end/mod.rs`, 1,646).

One observable side effect: the four QEMU boot tests are now at `pipeline::bootloader::end_to_end::qemu_boot::*` instead of `...::end_to_end::*`. That is a module-path rename only — the test bodies are unchanged (their token stream is identical to the pre-split file), all 61 `#[test]`s still exist, three of the QEMU tests execute (they gate on `qemu-system-x86_64 --version`) and `grub4dos_boots_to_its_prompt_in_qemu` keeps its pre-existing `#[ignore]` behind `RUFUS_TEST_GRLDR`. Nothing in the tree, docs or CI filtered those names. The release binary grew 1,184 bytes from the reshuffle, so `size-baseline.json` was refreshed to 1,810,200 (budget 3 MB, measured by `cargo xtask size`).

**Bad-blocks reconciliation.** `mkfs.rs` still claimed the surface scan "arrives in slice 9", but `pipeline::badblocks` has ridden in the wipe since S09. The module docs now say what the code does: a full format (`quick == false`) only zeroes the partition (one `Message`, no `Progress` samples, framed by `StepStarted`/`StepFinished`), and the destructive surface scan is a separate opt-in pass — `pipeline::badblocks`, invoked at the end of `wipe::run` when `RunOptions::badblocks` is set — that reports through the event-level `"badblocks"` pseudo-step (its own `Progress` samples plus pass/summary `Message` lines) and finishes before `Mklabel`/`Mkpart`/`Mkfs` start. The two knobs are independent; with both on, the scan comes first and the format's zero pass overwrites the pattern writes. No behaviour changed — only the documentation and the test that pins the order.

---

### 3.7 S24: Slint shell, dependency pin and the GUI-never-root split

**Shape of the crate.** `rufus-gui` is one library (`src/lib.rs` → `state.rs`) plus one binary (`src/main.rs`). `GuiState` (C1) is the whole form as pure data: selected device, boot image, image option, scheme, target, filesystem, cluster size, labels, quick format, bad-blocks passes, plus `image_option_enabled()` / `filesystem_enabled()` / `status_text()` / `build_plan()`. It owns no UI types and is tested headless. `ui/main.slint` (243 lines) is presentation only: every model, selection, enabled and `visible` flag is an `in`/`in-out` property and every interaction is a `callback`, so the `.slint` file contains no lists, no defaults and no scheme/target/filesystem rule.

**Data flow.** One direction only. A callback mutates `GuiState`, then `render()` pushes the whole state back out (combo models are `ModelRc<SharedString>` built in Rust from the label tables in `main.rs`; selections are the wire enum reformatted as text). Nothing is read back out of the UI except the two `checked` toggles, which are read from the two-way-bound property the click already updated. START only *describes* a plan (`describe_plan`); no write path exists in this crate. Because C2 has no worker threads yet, every state change already happens on the event loop; `slint::invoke_from_event_loop` becomes mandatory — and testable — when C3/C4 add the device watcher and the image analyzer.

**Dependency pin (A7).** `slint = "=1.19.0"` with `default-features = false` and exactly `std`, `compat-1-2`, `backend-winit`, `renderer-software`; `slint-build = "=1.19.0"` compiles `ui/main.slint` from `build.rs`; `rustix = "=1.1.6"` (`std` + `process`) supplies `geteuid` because `std` cannot report the effective uid without `unsafe`. Verified feature set at build time: `slint v1.19.0 backend-winit,compat-1-18,compat-1-2,renderer-software,std` — no femtovg/skia renderer, no Qt, no GTK, no webview. Cost of that pin, all of it transitively forced: the lock grows 102 → 567 packages and duplicates a few crates that cannot be unified across majors (`zbus` 5.19.0 for Slint's portal support next to `zbus` 6.2.0 for `rufus-helper`; `rustix` 0.38.44/1.1.6, `thiserror` 1/2, `toml` 0.8/1.x), and the winit backend pulls async plumbing (`zbus`'s `async-io`) that this crate never calls — there is no `tokio`, no `async-std` and no `async` code in `rufus-gui`.

**Licence policy.** Dependencies are `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`. `deny.toml` accepts **only** the GPL-3.0-only branch, as per-crate `[[licenses.exceptions]]` pinned to `@=1.19.0`, so a Slint bump re-opens the list for review; the proprietary branches are never accepted. `BSL-1.0` (MIT-equivalent) is allowed for `clipboard-win`/`error-code`, which are Windows-only and verified absent from the Linux graph (`cargo tree -i` finds no path). Six RUSTSEC advisories are scoped-ignored; all six are `informational = "unmaintained"` with `patched = []` (chrono, ttf-parser, zvariant, zbus_names, zvariant_derive, pin-utils), so none masks a vulnerability and none has an available fix.

**Unsafe enforcement (contract 0.4.4).** `src/lib.rs` keeps `#![forbid(unsafe_code)]`, so every business-rule line in the crate is under the hard lint. The binary target uses `#![deny(unsafe_code)]` instead: `slint::include_modules!()` expands to vtables that hardcode `#[allow(unsafe_code)]`, and an `allow` under a crate-level `forbid` is a hard error (E0453, 24 occurrences — try it). There is no `unsafe` block and no `#[allow(unsafe_code)]` anywhere in hand-written `rufus-gui` source, and the workspace `[workspace.lints.rust] unsafe_code = "deny"` would reject one, so hand-written code is still gated. Isolating `include_modules!()` in a second internal crate would restore the literal `forbid` on `rufus-gui` without removing one line of generated unsafe — it moves the exception out of the audited crate and adds a workspace member — so it was rejected as bookkeeping.

**Startup policy (A9, contract 0.4.6).** `--version`, `--help` and `-h` are matched on `argv[1]` and return from `main` before any Slint call, before the display is touched and before the euid check, which is why they work with both `DISPLAY` and `WAYLAND_DISPLAY` unset. Otherwise `startup_refusal(process::geteuid().as_raw())` decides: a pure `fn(u32) -> Option<String>` that returns the refusal text for euid 0 and `None` for anything else, so the rule is unit-testable on a normal desktop. The text names both halves of the split (unprivileged GUI, `rufus-helper` for privileged work) and states there is no override flag; no environment variable or argument can bypass it.

**Device access (contract 0.4.5).** Reads only: `sysfs::enumerate`/`sysfs::filter` for the startup device list, `/proc/self/mounts` for the mount summary, and `rufus_core::image::inspect` plus `rufus_core::report::analyze_file` on the selected image. There is no `open(..., O_RDWR)`, no `OpenOptions::write`, no `mkfs` and no `ioctl` in the crate (the only `OpenOptions`/`fs::write` calls are test fixtures under `std::env::temp_dir()`). The image picker spawns `zenity` or `kdialog` with `std::process::Command` and no shell, which keeps the dependency budget closed until C4 replaces the seam with the analyzer worker.

**Size (contract 0.4.8).** `rufus-gui` went 284,008 → 11,541,312 bytes against the unchanged 12,000,000 budget (≈458 KB headroom). `rufus-helper` moved 1,385,080 → 1,405,992, which is *not* a source or dependency change: the same tree built alone with its own `CARGO_TARGET_DIR` gives 1,384,904 bytes (`cargo build --release -p rufus-helper`) and 1,405,992 under `--workspace` (+21,088). `rustix` 1.1.6 is a single package instance shared by `rufus-helper` (direct) and the Slint/winit tree, so `--workspace` unifies features and adds `mm`, `shm` and `system` to the shared build. The A7 pin cannot remove that; the baseline was refreshed with the measured values by `cargo xtask size --write-baseline` and `BINARY_BUDGETS` is untouched.

---

## 4. Current Verification Status & Known Limitations

### Verified:
* **End-to-End Write Pipeline**: Tested and verified on physical USB 3.0/2.0 hardware (`/dev/sdb`, 32 GB flash drive). Successfully applied 111,760 entries (19,215,065,696 bytes), formatted ESP, written BCD stores, and finalized cleanly. A later quick-format run applied 152,980 entries (10,404,700,292 bytes) from `install.wim` in 39 boot files and finalized cleanly.
* **Firmware Hand-off**: Firmware successfully loads `EFI/Boot/BOOTX64.EFI` from the ESP, passes execution to `bootmgfw.efi`, and invokes `winload.efi`.
* **QEMU/OVMF Boot Verification**: A freshly written image boots under QEMU/OVMF, passes bootmgr with **no `0xc0000001`**, and proceeds into the Windows Setup ("Install Windows") screen across 20 consecutive screendumps. The written BCD was also verified byte-for-byte (fresh loader carries `12000004 = Windows 11 Enterprise Evaluation` and device GUIDs matching the stamped GPT layout).
* **Legacy BIOS BCD parity (unit-test level)**: A dedicated unit test (`bios_bcd_has_parity_with_uefi_bcd`) builds a BIOS (Boot/BCD) store and compares it with a UEFI store built from an otherwise identical request: both loaders carry the required `11000001`/`21000001` devices and the `12000004` description with the same value, class-0x4 setup elements are stripped on both, and the BIOS variants use the distinct `...123457` loader/resume GUIDs. This is BCD-store parity only; no fresh SeaBIOS Windows boot was run in this environment, so no Legacy BIOS boot is claimed as verified.

### S22 automated coverage (added after the S21 hardware validation above)
* **Dynamic BCD locale**: unit tests cover `locale_in_template` (valid/invalid tags, all-four-site write, `build()` default/template behaviour, invalid-locale refusal), `locale_from_tree` (de-DE discovery, bytewise-smallest determinism, missing/non-`.mui`/malformed/symlink rejection), custom-GUID template resolution via `Description\Type` (fresh output GUIDs unchanged), and a to_go e2e test in which a de-DE `.mui` tree yields de-DE in all four locale elements of the ESP store. The detected tag is written verbatim; no GUI locale policy changes.
* **WIM pre-flight**: 9 unit tests pin `required_with_ntfs_overhead` at the 64 MiB floor (incl. just below the 2% crossover), its 2% branch/crossover and `u64::MAX` saturation, plus exact-fit / under-margin (`need - 1`) / ample-space cases for both `apply` and `apply_ntfs` (the passing cases assert `Cancelled` from pre-flight, so extraction is never reached).
* **regf property test**: the 500 × 20 mutation test above passes deterministically (fixed seed, 10,000 verified steps, 8 `hbin` bins), four alternate seeds also passed, and sabotage checks confirmed it detects silent data loss.
* **strict-link negative check**: `WIMLIB_SYS_FORCE_UNLINKED=1 cargo check -p wimlib-sys --features strict-link` fails with the intended `compile_error!`, while the same unlinked build without the feature still checks clean.

### S23 automated coverage (planner extraction, bootloader split, bad-blocks)
* **Planner**: `rufus_core::planner` carries 15 tests — the 13 tests that used to live in `rufus-cli::plan` (write-mode pairing, explicit-mode layouts, the `uefi-ntfs`/`freedos`/`kolibri`/`msdos` refusals, the Windows To Go plan, the MS-DOS no-write plan) plus two new ones that pin the moved grading rules: `device_ref_grades_missing_and_non_block_paths` (dry-run relaxation, the device refusal naming `--dry-run`, the non-block safety refusal) and `device_ref_enriches_from_discovery_facts` (all mapper fields from the probe). `rufus-cli` keeps one test, `every_cli_selector_maps_to_its_core_twin`, so a variant added to only one of the two enums fails a test.
* **Bootloader split**: 61 `#[test]`s before the split and 61 after — 52 unit tests under `bootloader/tests/` plus 9 under `bootloader/end_to_end/` — and all 61 are listed by `cargo test -p rufus-core --lib -- --list` and run by the same harness. The three QEMU tests that can run on the build host pass for real (`qemu-system-x86_64` present); the fourth is `#[ignore]`d exactly as before.
* **Bad-blocks**: one new pipeline test, `full_format_zeroes_without_scanning_and_scan_rides_in_wipe`, checks both directions: a full format with `badblocks` off zeroes the partition and emits no `"badblocks"` progress or pass messages, and the same plan with the flag on emits scan `Progress` before `StepStarted { step: "mkfs" }` and still zeroes afterwards.
* **Gates at the S23 tip**: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (1,747 passed / 0 failed / 29 ignored; `rufus-core` lib 1,316 passed / 6 ignored), `cargo xtask parity --check` (2,709 rows, S23 = 42) and `cargo xtask ci` (`ci: all gates passed`, assets 86/86, size 1,810,200 / 1,385,080 / 284,008 against the refreshed baseline; `cargo-deny` and `cargo-audit` SKIPped because they are not installed).

### S24 automated coverage (Slint shell, dependency pin, startup policy)
* **Startup policy**: two unit tests on the pure check — `root_is_refused_with_the_unprivileged_gui_privileged_helper_split` (euid 0 must return a refusal that names the unprivileged GUI, `rufus-helper` and the absence of an override flag) and `unprivileged_euids_start_normally` (1, 60,000 and 65,534 must return `None`). Both fail if the rule regresses in either direction.
* **Headless CLI**: `env -u DISPLAY -u WAYLAND_DISPLAY cargo run -q -p rufus-gui -- --version`, `-- --help` and `-- -h` each exit 0 and print the expected text, proving the fast paths precede any Slint/display initialization.
* **Dependency policy**: `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`; `cargo metadata --locked` accepts the lock as consistent; `cargo tree -f "{p} {f}"` shows `slint` with exactly `backend-winit,compat-1-18,compat-1-2,renderer-software,std`.
* **No business logic in `.slint`**: the file is 243 lines of layout plus property/callback declarations; grepping it for scheme/target/filesystem vocabulary returns only property names, callback names and the static captions "Partition scheme", "Target system" and "passes".
* **Size**: `cargo xtask size` reports `rufus 1,809,576 / rufus-helper 1,405,992 / rufus-gui 11,541,312`, all within budget, against the refreshed baseline.
* **Not covered**: the window has never been rendered (no display on the build host), so widget layout, combo selection round-trips and the zenity/kdialog picker are unverified; hotplug and image analysis arrive in C3/C4.

### Resolved (`0xc0000001`):
* **Windows First-Boot `0xc0000001`**: This was NOT a WIM-specialization limitation — it was a BCD bug. The generated UEFI store omitted the loader's `12000004` description element, which bootmgr requires; any store without it lands in Recovery with `0xc0000001`. An earlier note claiming "an identical `bcdboot` deployment fails identically" was wrong: a WinPE-regenerated `bcdboot` BCD on the same image boots past bootmgr, and a controlled A/B test isolated `12000004` as the deciding element. Fixed in `4d22a12` (caller always supplies a non-empty description), with the surrounding bcdboot-parity work in `44e8062`, `a3c2154`, `8e01ab0` and `296261b`.
* **Remaining Setup screen (out of S21 scope)**: Because the image applies an unspecialized deployment `install.wim`, boot currently stops at the "Install Windows / Windows installation error" Setup screen — the same screen the known-good `bcdboot` BCD reaches. Reaching a full desktop requires Windows Setup's specialize pass (a generalized/specialized WIM), which is a separate concern from S21's BCD correctness. The S21 acceptance criterion — no `0xc0000001`, no manual `bcdedit`/`chkdsk`/`bcdboot` repair — is MET.
