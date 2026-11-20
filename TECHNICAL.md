# Technical Notes: furus

This document explains the architecture, design choices, data flow, dependencies, and trade-offs of the `furus` codebase, with a specific focus on the S21 Windows To Go implementation.

---

## 1. Overall System Architecture & Principles

`furus` is a clean, from-scratch implementation of Rufus written in Rust for Linux. It reproduces Rufus's on-disk layouts, bootloader installation logic, and partition schemes without copying code from the upstream C codebase.

### Workspace Crate Architecture

The repository is organised as a Cargo workspace with strict privilege and responsibility separation:

* **`rufus-proto`**: Shared wire contract between the CLI, GUI, and the privileged daemon. Defines versioned `Plan`, `Confirm`, and structured event streaming schemas, plus the reader for the helper's JSONL event wire (`events::from_jsonl_line`, `LineError`). Serialises deterministically to JSON.
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
* **`rufus-gui`**: Slint-based graphical user interface front-end (S24): an unprivileged Slint 1.19.0 window over a headless `GuiState`, plus the client half of the helper IPC seam (`ipc`: transport trait, pkexec transport, session-scoped event stream, sticky cancel); it never runs as root and never writes to a device.
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

**Shape of the crate.** `rufus-gui` is one library (`src/lib.rs` → `state.rs`, plus the Slint-free `devices.rs` and `analyzer.rs` added in C3 and C4) plus one binary (`src/main.rs`). `GuiState` (C1) is the whole form as pure data: selected device, boot image, image option, scheme, target, filesystem, cluster size, labels, quick format, bad-blocks passes, plus `image_option_enabled()` / `filesystem_enabled()` / `status_text()` / `start_enabled()` / `build_plan()`. It owns no UI types and is tested headless. `ui/main.slint` (250 lines) is presentation only: every model, selection, enabled and `visible` flag is an `in`/`in-out` property and every interaction is a `callback`, so the `.slint` file contains no lists, no defaults and no scheme/target/filesystem rule.

**Data flow.** One direction only. A callback mutates `GuiState`, then `render()` pushes the whole state back out (combo models are `ModelRc<SharedString>` built in Rust from the label tables in `main.rs`; selections are the wire enum reformatted as text). Nothing is read back out of the UI except the two `checked` toggles, which are read from the two-way-bound property the click already updated. START only *describes* a plan (`describe_plan`); no write path exists in this crate. Because C2 had no worker threads, every state change happened on the event loop; C3 and C4 add the two worker paths (below), where `slint::invoke_from_event_loop` is the only legal way in.

**Hotplug path (C3).** `devices.rs` owns discovery (`sysfs::enumerate` + `sysfs::filter`, with the internal-disk warning), a `DeviceWatcher` worker on a `std::thread`, an injectable publish seam and the `DeviceListState` reducer; it has no Slint import, so it is tested headless against fake snapshots. `main.rs` keeps everything Slint: the worker sends `DeviceUpdate` snapshots over `std::sync::mpsc` to a dispatcher thread whose only job is `slint::invoke_from_event_loop`, so every `GuiState` and model mutation, and every `render()`, runs on the event loop — the session is an `Arc<Mutex<…>>` whose lock exists only to make the handle `Send`/`Sync`. The watcher is bounded by a 100 ms wait, so a CLOSE (or the window manager closing the only window) ends `ui.run()` and is followed by a joined worker and a joined dispatcher (the closed channel ends the dispatcher). Selection stability is by stable identity (`Device::identity`), never by index: an accepted snapshot keeps the selected device while it is still present and clears it — through `GuiState::clear_device`, so the plan and START follow — when it is gone. A snapshot is discarded when its epoch differs from the current selection epoch or its sequence is not newer than the last accepted; the worker tags a snapshot with the epoch it reads when the wait completes, so work that began before a user choice but finished after it still lands (with the choice preserved), while a publication already queued before the choice cannot overwrite it. A *rejected* snapshot is dropped rather than requeued, so the list can lag until the next real device change; the window is one epoch load wide and the watcher only publishes changes.

**Image analyzer (C4).** `analyzer.rs` is Slint-free: `AnalyzerWorker` is a `std::thread` fed by `std::sync::mpsc`, and the production seam (`spawn_production`) is `rufus_core::image::inspect` — size, SHA-256 and container kind — followed by `rufus_core::report::analyze_file` for the Windows-ness, BIOS/UEFI boot paths, distro, labels and WIM editions. The worker drains queued selections and analyses only the newest one, so a burst of clicks cannot queue unbounded work behind a long hash. `AnalysisCoordinator` owns a monotonically increasing request id that is assigned at selection, *before* the selection reaches the worker, together with the selected path; a published `AnalysisResult` is applied only when both the id and the path still match the latest pending request, and is otherwise discarded without mutating anything at all — not the facts, status text, progress, enabled flags or the provisional plan (a re-selection of the same file is told apart by the id alone, a mis-routed result by the path alone). An accepted result clears the pending request and then either applies the facts through `GuiState::apply_image_analysis` or a named failure through `GuiState::fail_image_analysis`, so a later selection always starts from a clean pending slot. The analyzer supplies facts only: `GuiState` still owns every default and enabled flag and `planner::build` still owns every compatibility rule. CHECKSUM displays the digest the analysis already computed — it never re-reads the file and touches no network. `main.rs` keeps the Slint half: the worker publishes into a channel drained by a dispatcher thread that only calls `slint::invoke_from_event_loop`; START is gated by `GuiState::start_enabled()` and pressing it reports the plan or the planner's refusal (it writes nothing). `AnalyzerWorker::shutdown` sends `Stop` and joins after a 2 s bounded wait, so a worker still inside one analysis is detached rather than joined unbounded, and a closed publish channel ends the worker without a panic.

**Dependency pin (A7).** `slint = "=1.19.0"` with `default-features = false` and exactly `std`, `compat-1-2`, `backend-winit`, `renderer-software`; `slint-build = "=1.19.0"` compiles `ui/main.slint` from `build.rs`; `rustix = "=1.1.6"` (`std` + `process`) supplies `geteuid` because `std` cannot report the effective uid without `unsafe`. Verified feature set at build time: `slint v1.19.0 backend-winit,compat-1-18,compat-1-2,renderer-software,std` — no femtovg/skia renderer, no Qt, no GTK, no webview. Cost of that pin, all of it transitively forced: the lock grows 102 → 567 packages and duplicates a few crates that cannot be unified across majors (`zbus` 5.19.0 for Slint's portal support next to `zbus` 6.2.0 for `rufus-helper`; `rustix` 0.38.44/1.1.6, `thiserror` 1/2, `toml` 0.8/1.x), and the winit backend pulls async plumbing (`zbus`'s `async-io`) that this crate never calls — there is no `tokio`, no `async-std` and no `async` code in `rufus-gui`.

**Licence policy.** Dependencies are `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`. `deny.toml` accepts **only** the GPL-3.0-only branch, as per-crate `[[licenses.exceptions]]` pinned to `@=1.19.0`, so a Slint bump re-opens the list for review; the proprietary branches are never accepted. `BSL-1.0` (MIT-equivalent) is allowed for `clipboard-win`/`error-code`, which are Windows-only and verified absent from the Linux graph (`cargo tree -i` finds no path). Six RUSTSEC advisories are scoped-ignored; all six are `informational = "unmaintained"` with `patched = []` (chrono, ttf-parser, zvariant, zbus_names, zvariant_derive, pin-utils), so none masks a vulnerability and none has an available fix.

**Unsafe enforcement (contract 0.4.4).** `src/lib.rs` keeps `#![forbid(unsafe_code)]`, so every business-rule line in the crate is under the hard lint. The binary target uses `#![deny(unsafe_code)]` instead: `slint::include_modules!()` expands to vtables that hardcode `#[allow(unsafe_code)]`, and an `allow` under a crate-level `forbid` is a hard error (E0453, 24 occurrences — try it). There is no `unsafe` block and no `#[allow(unsafe_code)]` anywhere in hand-written `rufus-gui` source, and the workspace `[workspace.lints.rust] unsafe_code = "deny"` would reject one, so hand-written code is still gated. Isolating `include_modules!()` in a second internal crate would restore the literal `forbid` on `rufus-gui` without removing one line of generated unsafe — it moves the exception out of the audited crate and adds a workspace member — so it was rejected as bookkeeping.

**Startup policy (A9, contract 0.4.6).** `--version`, `--help` and `-h` are matched on `argv[1]` and return from `main` before any Slint call, before the display is touched and before the euid check, which is why they work with both `DISPLAY` and `WAYLAND_DISPLAY` unset. Otherwise `startup_refusal(process::geteuid().as_raw())` decides: a pure `fn(u32) -> Option<String>` that returns the refusal text for euid 0 and `None` for anything else, so the rule is unit-testable on a normal desktop. The text names both halves of the split (unprivileged GUI, `rufus-helper` for privileged work) and states there is no override flag; no environment variable or argument can bypass it.

**Device access (contract 0.4.5).** Reads only: `sysfs::enumerate`/`sysfs::filter` for the startup device list and a read-only `inotify`/poll watch on `/sys/class/block` through `rufus_linux::DeviceWatcher` (C3; the crate's only `/sys` literal is `SysfsRoot::new("/sys")` in `start_live_watcher`), `/proc/self/mounts` for the mount summary, and `rufus_core::image::inspect` plus `rufus_core::report::analyze_file` on the selected image, both on the analyzer worker thread (C4). There is no `open(..., O_RDWR)`, no `OpenOptions::write`, no `mkfs` and no `ioctl` in the crate (the only `OpenOptions`/`fs::write` calls are test fixtures under `std::env::temp_dir()`). The image picker still spawns `zenity` or `kdialog` with `std::process::Command` and no shell — C4 replaced the synchronous *analysis* of the picked path, not the picker — so the dependency budget stays closed.

**Size (contract 0.4.8).** `rufus-gui` went 284,008 → 11,541,312 bytes against the unchanged 12,000,000 budget (≈458 KB headroom), and 11,541,312 → 11,566,272 (+24,960) once C3 added the device list and watcher, leaving ≈434 KB headroom, and 11,566,272 → 11,602,240 (+35,968) once C4 added the analyzer worker and its wiring, leaving 397,760 bytes of headroom. `rufus-helper` moved 1,385,080 → 1,405,992, which is *not* a source or dependency change: the same tree built alone with its own `CARGO_TARGET_DIR` gives 1,384,904 bytes (`cargo build --release -p rufus-helper`) and 1,405,992 under `--workspace` (+21,088). `rustix` 1.1.6 is a single package instance shared by `rufus-helper` (direct) and the Slint/winit tree, so `--workspace` unifies features and adds `mm`, `shm` and `system` to the shared build. The A7 pin cannot remove that. `rufus` also moved 1,810,200 → 1,809,576 (−624) against the same lock refresh; no CLI source changed. `BINARY_BUDGETS` is untouched and every baseline value came from `cargo xtask size --write-baseline` on the reviewed tree.

---

### 3.8 S25: the client-side IPC seam and the shared JSONL reader

**Where the wire parsing lives (A9).** The helper already streams one `Event` per JSONL line (`rufus-helper --plan <file> --progress jsonl`) and exports the same three events as D-Bus signals on `org.rufuslinux.Helper1` (`Execute` → session id, `Cancel(session)`, and the `progress`/`log`/`done` signals). Reading that stream is a *client* concern, but the wire contract is shared by both halves of the privilege split, so the reader lives in `rufus-proto` next to the types it parses rather than in `rufus-gui`: `events::from_jsonl_line` and `events::LineError` are defined there and re-exported from the crate root (`rufus_proto::{from_jsonl_line, LineError}`). `rufus-gui` therefore keeps no parser and no tag list of its own, and neither crate gains a dependency.

**Error taxonomy.** `from_jsonl_line` reports exactly four failures, each named instead of folded into serde's generic enum error:

| Variant | When |
|---|---|
| `LineError::Empty` | the line is empty once a trailing `\r` and the surrounding ASCII whitespace are removed |
| `LineError::Json(String)` | not JSON, not an `Event` shape, trailing data on the line, or input past serde_json's 128-deep recursion limit |
| `LineError::UnknownKind(String)` | the `kind` tag is not `progress`, `log` or `done` — checked before the enum deserialiser, so the report names the offending value |
| `LineError::VersionTooHigh { found, supported }` | a `Done` line whose `version` exceeds `EVENT_STREAM_VERSION` |

The accepted tag list is kept in step with the `Event` enum's serde `kind` tags on purpose: unknown kinds fail closed (PLAN §2), and adding a variant is a schema change that bumps `EVENT_STREAM_VERSION`. A round-trip test serialises every `Event` variant and asserts the parser accepts it back, and `ipc::EventStream`'s session match is exhaustive (no wildcard), so a new variant is a compile error rather than a silently discarded event.

**The version rule has one home.** `Completion::check_version` is the only place that compares a stream version against `EVENT_STREAM_VERSION`, and `from_jsonl_line` applies it to every `Done` line. Only *newer* streams are refused; an equal or older version parses. `Completion.version` is the stream version and never `PLAN_VERSION`, and tests pin both (`EVENT_STREAM_VERSION == 1`, plan schema `== 6`).

**Trust boundary in `Display`.** `LineError` reaches the UI through `IpcError::Protocol`, whose `Display` is what the GUI renders as status text. The unknown tag is producer-controlled, so the `Display` impl passes it through `escape_debug`: a tag carrying ESC or a newline renders as an escape, not as a raw byte the UI would interpret. `LineError::Json` needs no such treatment — serde's own messages render string values with `{:?}`, so they are escaped already.

**Transport seam.** `rufus-gui::ipc` exposes one trait, `HelperTransport::start(&mut self, &Plan) -> Result<Started, IpcError>`, with `Started { session, events, cancel }`: `events` is a blocking `Iterator<Item = Result<Event, IpcError>>` and `cancel` is a `CancelHandle`. `IpcError` has four arms — `Unavailable`, `Spawn`, `Protocol(LineError)` and `Transport` — so a missing helper, a failed spawn/channel and a bad line stay distinguishable. Two transports ship (the pkexec reader thread, S25 slice 2, and the D-Bus client, slice 3); both fit only because the seam is sync (A8). Selection is composition-root policy, not transport logic: `open_helper(prefer_dbus)` picks a client on an injected probe and `start_with_fallback` retries once through a freshly built pkexec transport only when the preferred `start` returns `Unavailable` — an `AccessDenied`/`Transport` failure is returned unchanged and never re-prompts a user who already refused:

* **pkexec reader thread (shipped)** — `ipc::pkexec::PkexecTransport` runs `rufus-helper --plan <file> --progress jsonl` under `pkexec`, reads the child's stdout line by line on a plain `std::thread` and feeds the iterator through the same `from_jsonl_line` as above. No bus and no second authorisation prompt; the temp-file, argv, timeout and terminal-synthesis contracts are spelled out in "The pkexec transport" below.
* **D-Bus client (implemented)** — `org.rufuslinux.Helper1` on the system bus: `Execute(plan_json) -> session_id`, `Cancel(session_id)`, and the `progress`/`log`/`done` signals. zbus 6 is async-only (the blocking API is gone), so the client drives its proxy with `zbus::block_on` on **its own** `std::thread` — never on a runtime task — and hands the resulting events to the same blocking iterator. That thread is also why the seam is an `Iterator` and not a callback. Signals are converted in `rufus-gui` and serialised to JSONL so the shared `from_jsonl_line` parser stays the only reader; the signal's lossy `percent` is ignored and percent derivation is delegated to `Progress::new`. `Done` carries no version, so the client stamps `EVENT_STREAM_VERSION`.

`EventStream` demultiplexes by session: a line whose `session` is not the started run's is discarded, the first `Done` is surfaced and makes the stream terminal (`None` from then on, even if the transport keeps producing), and a transport error is forwarded as `Err(IpcError::Transport(..))`. `MockTransport` is the test double: it replays JSONL through the production parser instead of faking events, so the parser stays on the tested path with no helper present.

**Sticky cancel.** `CancelHandle` is a `Clone` over two `Arc<Mutex<…>>` slots, and its one-shot action runs at most once *across clones*: the first result — success or failure — is cached and returned by every later `cancel()`, so a retry can never report success for a cancel that failed. A poisoned lock becomes `IpcError::Transport` rather than a panic.

**The pkexec transport (S25 slice 2).** `ipc::pkexec::PkexecTransport` implements the seam by spawning the helper through `pkexec` and reading its stdout on a plain `std::thread`. It adds no dependency, no async runtime and no network.

*Temp plan file.* `start()` serialises the plan with `Plan::to_json` (which writes the stored `confirm` verbatim) into a fresh file in `std::env::temp_dir()`, created with `create_new(true)` and mode `0600`, named `rufus-plan-<pid>-<counter>-<nanos>.json` — `<pid>` is the **GUI** process's pid, `<counter>` a process-wide atomic and `<nanos>` the wall clock at creation. The file is removed before the terminal event is surfaced and on every other exit path (spawn failure, reader error, timeout, `Drop`). Every constructor first sweeps the temp directory, and the sweep is deliberately narrow: a name must parse as that canonical form (leading zeros and extra fields are rejected), the entry must be a **regular file** (symlinks are skipped — `DirEntry::file_type()` does not follow them), it must be owned by the current user with mode exactly `0600`, and its pid is removed only when `/proc/<pid>/stat` proves the process gone (`NotFound`) or a zombie (`state == 'Z'`). Everything else — another user's file, another mode, an unparsable or non-UTF-8 name, a `hidepid` read failure, any I/O error — is ignored. A live pid is never touched, so pid reuse can only leak a stale file, never delete a live run's plan.

*argv shape.* `start()` runs `<program> <prefix…> rufus-helper --plan <file> --progress jsonl` with only stdout and stderr piped (stdin is left alone). The production constructor passes an empty prefix, i.e. `pkexec rufus-helper …`; `with_command`/`with_command_and_authorization_timeout` are the documented test seams that let the suite drive `/bin/sh -c <script>` with no pkexec, root or polkit.

*Terminal synthesis.* A run that never emits a `Done` still ends with exactly one, built in `synthesized_done` with `EVENT_STREAM_VERSION`:

| Exit status | Synthesised outcome |
|---|---|
| `0` | `ok` |
| `3` | `refused`, `code: "exit"` |
| `4` | `failed`, `code: "exit"` |
| `6` | `cancelled` |
| anything else (`7`, `126`, signal death, …) | `failed`, `code: "exit"` |

A run that was cancelled synthesises `cancelled` whatever its status. A real `Done` for the run's session suppresses synthesis: the stream becomes terminal there and the queued exit message is never read. A read/UTF-8 error on stdout is different — it surfaces `Err(IpcError::Transport(..))` and then `None`, with **no** synthesised `Done`, so the UI reports a transport failure instead of inventing a completion.

*Blocking `start()` and its authorization budget.* `start()` blocks until the helper's first non-blank event, which under pkexec is delayed by the polkit prompt. The wait is one `recv_timeout` over a **120 s** default budget (`DEFAULT_AUTHORIZATION_TIMEOUT`); on expiry the child is killed **and reaped**, the plan file is dropped, and `start()` returns `IpcError::Transport("no helper event within 120s; authorization not completed")`. The budget covers the authorization wait only: once `start()` has returned, reads are plain blocking `recv()` with no timeout, so a long `wipe`/`verify` step cannot be killed by a per-line deadline. An injected budget is reachable only through the documented test constructors; production construction (`new()`/`Default`) always uses the 120 s constant.

*stderr tail.* stderr is drained on its own thread and capped at the **last** 8 KiB (`STDERR_LIMIT`), so a chatty failure keeps its end rather than its start. The captured bytes go through `from_utf8_lossy` and `escape_debug` before being appended to the synthesised message, and the escaped text is truncated to its tail at a `char` boundary — an ESC or newline in helper output never reaches the UI as a raw control byte.

*Cancel and teardown.* `cancel()` sends SIGKILL only if the child is still running and flags the run as cancelled; the stdout EOF then carries the synthesised `cancelled` completion, and repeating the cancel returns the cached first result. Dropping the stream without draining it kills the child, joins both reader threads and removes the plan file, so an abandoned run leaks neither a process nor a file.

**The run state machine (S25 slice 4).** `rufus-gui::run::Run` is a display-independent lifecycle — `Idle -> Confirming -> Running { step, percent, rate, eta } -> Finished(Outcome)` — that turns the transport's `Event` stream into the progress state the drawer will show. START still goes through `GuiState::build_plan`, so the S23 planner stays the only place a plan is built, but `Run::start` then deliberately **clears** the planner's provisional `sha256:` token: `Plan::confirm` hashes the plan's other fields and ignores the stored token, so `Run::confirm` recomputes the identical hash — only the moment the token exists changes. `confirmed_plan()` refuses with `ConfirmationRequired` until that recompute, so START alone can never hand a runnable plan to a transport. Rate and ETA come from the wire `done`/`total` plus an **explicit** elapsed `Duration` the caller passes to `Run::apply(event, elapsed)`, formatted with `rufus_core::units` — no wall clock in this crate, so tests stay deterministic. Stale samples (an earlier step, or fewer units within a step) are ignored, percent never regresses within a step, `Done` is terminal, cancel is one-shot through an injected `CancelRequest`, logs are bounded at `LOG_LIMIT = 500`, and configuration stays locked through Confirming and Running. The module adds no dependency, no async, no threads and no transport/device/pkexec/bus/polkit in it or its tests.

**The Slint run wiring (S25 slice 5).** `main.rs` is the composition root and owns no business rule. START calls `Run::start(&mut GuiState)` (plan only — no token, no transport) and opens a destructive-write confirmation dialog built from the captured `DeviceFacts` plus an explicit irreversibility warning; the dialog is pure presentation (`confirm-facts` is Rust-provided, `confirm-clicked`/`discard-clicked` are callbacks) and only `Run::confirm()` attaches the SHA-256 token. The token-bearing plan is cloned from `Run::confirm()` and handed to a worker thread that starts the transport through `open_helper(prefer_system_bus)` + `start_with_fallback` — never from `Run::plan()`. The UI owns the clock (`run_started: Instant` set at confirm); the worker pumps `EventStream` into an mpsc channel and a dispatcher applies every message to `Run` on the event loop via `slint::invoke_from_event_loop`, then re-renders. Every state transition still goes through `Run` (`start`/`confirm`/`apply`/`cancel`) and every transport error or session fact through `ipc`. A pure `run_view(&Run)` formatter derives progress, detail, lock, cancel/start flags and terminal `Outcome` text; `confirmation_facts`, `log_line`/`log_lines` and `outcome_text` are pure formatters. `Run::configuration_locked()` drives one `form-enabled` flag that gates every configuration control, CANCEL is enabled only while `Running`, START re-enables only at `Finished`, the terminal `Outcome` is shown in the status line, and the log drawer renders the buffered `Run::logs()`. A one-shot `CancelBridge` latches a cancel issued before the worker installed its `CancelHandle` and delivers it exactly once at install; `Run::cancel()` and the bridge path together reach the transport's `CancelHandle` exactly once.

**The checksum modal (S25 slice 6).** `rufus-gui::checksum` is the headless owner of the four-algorithm checksum dialog; it deliberately does **not** live in `analyzer.rs`. Streaming digests come only from `rufus_core::hash::hash_reader` with `Algo::{Md5,Sha1,Sha256,Sha512}` over its 1 MiB chunks — no reimplementation, no hex/crypto crate, no `unsafe`, no async or network. A `Read` adapter counts bytes across all four passes (`total = 4 x file length`) and publishes a new whole percent per chunk, monotonic and capped at 100; an empty file has no division by zero. Cancellation is a shared `Arc<AtomicBool>` `CancelToken` checked at every read chunk, so a large file stops promptly; `cancel()` is one-shot across clones, and a cancelled/failed run publishes a terminal result with **no** digests so a partial set can never look complete. A monotonic `(request_id, path)` guard discards stale publications exactly as `analyzer.rs` does, and `begin()` cancels the superseded request. `main.rs` holds only the view state, a worker thread plus an event-loop dispatcher, three callbacks (compute / CANCEL / CLOSE) and pure display formatters; on window close it cancels, shuts down and joins the worker and its dispatcher. Modal CLOSE cancels but keeps the single long-lived worker for the session. The old synchronous `analyzer::checksum(&GuiState)` note path is gone from the GUI — the core function remains untouched but is now unused by it — and the checksum status is shown only in the modal's own property, never pushed into `GuiState` or the main status line. `main.slint` is pure presentation: values flow in as properties, clicks flow out as callbacks.

**Localisation and GUI preferences (S25 slice 7).** Two headless bridges in `rufus-gui` own every locale and display-preference decision; `main.rs` only marshals strings and flags into Slint properties, and `main.slint` carries no business, translation or preference rule. `i18n_bridge::LocaleCatalog` loads the first parseable `.loc` catalog — the `RCDATA_500.bin`/`rufus.loc` system asset via `rufus_core::paths::asset_path`, else the small `EMBEDDED_CATALOG` constant — so catalog loading never depends on `$APPDIR` or an FHS install and tests stay deterministic and offline. Translation goes only through `rufus_core::i18n::{Catalog, Translator}` (full tag → primary subtag → English); a known caption id whose catalog text is still the msgid falls back to a Rust-owned English literal from `CAPTIONS`, and an unknown id is returned verbatim. No `.loc` grammar is reimplemented here (only `l`-header display names are read for the locale combo) and there is no global/lazy static or network. `rtl` is computed in Rust from the locale's primary subtag (`ar`/`he`/`fa`/`ur`) as pure presentation only — Slint 1.19 has no RTL layout engine, so `main.slint` uses it solely for text alignment; it never changes a formatting or safety rule. `config_bridge::GuiPrefs` is a thin wrapper over the single core-owned TOML `Config`: the active locale tag stays the one `Config::locale`, while the four hash-display toggles and advanced-section visibility live in a new `[gui] GuiConfig` table added to `rufus_core::Config` with `#[serde(default)]` and sibling derives. Loading never writes (a corrupt file follows core's backup-aside policy); saving goes through the atomic `Config::save`, preserving every unrelated field (`show_all`, `check_updates`, `update_channel`, `last_device`, `ignore_devices`, `window`, `advanced`) and touching no network/update behaviour. No dependency was added to either crate (notably no `toml` in `rufus-gui`). The `advanced-visible` checkbox is a two-way binding (`in-out property` + `checked <=> root.advanced-visible`) so a click updates the exact property the callback reads; the first review round caught a one-way binding that left the section unexpandable and the preference stale. The slice also raised the hardcoded `rufus-gui` release-size budget in `xtask` from 12 MB to 14 MB and refreshed `size-baseline.json`; growth accumulated across all S25 slices (notably the two zbus versions), and the baseline had not been refreshed since `bbe054a`.

**Accepted open decision — D-Bus mid-run death (do not fix here).** If the helper exits mid-run without emitting `Done`, the D-Bus signal stream does not end, so `EventStream` stays open and the worker's `join` at shutdown can block. This transport deliberately has no `NameOwnerChanged` watch; slice 5 records the accepted wait rather than adding one (see the slice-5 handoff). The live system-bus path and real window rendering remain unverified in this environment (no system bus, no display).

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
* **No business logic in `.slint`**: the file is 250 lines of layout plus property/callback declarations; grepping it for scheme/target/filesystem vocabulary returns only property names, callback names and the static captions "Partition scheme", "Target system" and "passes". The C4 CHECKSUM button adds one `bool` property and one `callback`, and its enabled state is the Rust-provided `checksum-enabled`.
* **Device list and hotplug (C3)**: 13 headless tests in `devices.rs` — initial list plus a non-advancing auto-select, device added, removal clearing the selection, unrelated hotplug preserving it, an older-epoch snapshot rejected, a fresh post-selection snapshot accepted with the choice kept (and the guard not latched shut by a rejection), out-of-order sequence rejected, the injected fake-snapshot channel driving the real worker (initial publish at epoch 0 / sequence 1), the worker tagging a completed snapshot with the epoch read at completion, `show_all` surfacing the internal-disk warning, the filter dropping builtin/loop/virtual/zero-size devices (the builtin names now keep `usb`/`removable` set, so only the name rule can drop them), a quiet worker joined well under 1 s and a closed publish channel stopping without a panic. Two binary tests cover the session glue in `main.rs` — `unplugging_the_selected_device_clears_the_planning_state` (identity *and* `GuiState`, down to `build_plan() == Err(NoDevice)`) and `a_snapshot_that_still_carries_the_selected_device_keeps_it_selected` — plus one that pins the internal-disk warning surviving into the rendered status. Both binary tests were mutation-checked (removing the `clear_device` call, and clearing on every accepted snapshot, each fail them). No test opens `/sys`, a display, or a device.
* **Image analyzer (C4)**: 9 headless tests in `analyzer.rs` drive the real `AnalysisCoordinator` and the real `AnalysisResult` type with a fake analysis seam — a Windows ISO yielding the image-option selector, the NTFS/GPT/UEFI defaults and a Windows-bootloader plan; a Linux hybrid ISO hiding the selector and planning both `dd` and copy; a raw image keeping the user's MBR/ext4 choice with `BootloaderMode::None`; a named failure producing an error status and no plan; the newer result applied and the older one discarded in both arrival orders; the guard's two halves pinned separately (an older id on an identical path, and the current id on a different path, both discarded with the pending request intact); the worker analysing only on its own thread and surviving a closed publish channel; CHECKSUM showing the inspected digest without touching the file; and START disabled until the current selection plans. One binary test runs the production seam end to end minus the picker and the dispatcher — a real `AnalyzerWorker`, `AnalyzerSender`, `Session::select_image` and `Session::apply_analysis` — and pins that the request id exists before the worker can publish and that a superseded result is discarded; a second pins that START reports the planner refusal and performs no write. Mutation-checked: comparing only the id or only the path in the staleness guard fails the new test, and submitting under an id that was not the pending one fails the session test.
* **Size**: `cargo xtask size` reports `rufus 1,809,576 / rufus-helper 1,405,992 / rufus-gui 11,602,240`, all within budget, against the refreshed baseline. On C3's (+24,960) and C4's (+35,968) growth see §3.7.
* **Gates at the S24 tip (C5 closure)**: `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo test -p rufus-gui` passes 30 library and 7 binary tests; `cargo test --workspace` reaches the `rufus-core` library target and reports `1309 passed; 7 failed; 6 ignored`, the 7 being exactly the contract §0.3 environment baseline — `boot::uefi_ntfs::tests::embedded_install_returns_the_pinned_one_mib`, `pipeline::bootloader::tests::dos::freedos_installs_payloads_locale_and_record`, `pipeline::bootloader::tests::run::run_uefi_ntfs_writes_the_image_and_reports_both_lines`, `pipeline::bootloader::end_to_end::full_plan_installs_syslinux_end_to_end`, `pipeline::bootloader::end_to_end::every_wired_mode_installs_its_fingerprint_end_to_end`, `pipeline::bootloader::end_to_end::qemu_boot::freedos_boots_to_its_shell_in_qemu`, `pipeline::bootloader::end_to_end::qemu_boot::syslinux_407_boots_to_its_prompt_in_qemu` — every one an embedded-asset resolution failure (`not found under '/…/usr/share/rufus-linux/assets'`), with none renamed, added, deleted or `#[ignore]`d by S24; `cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`; `cargo xtask assets --check` 86/86 and `cargo xtask parity --check` 2,709 rows agree with the manifest and the address sets; `cargo xtask size` reports `rufus` 1,809,576 / `rufus-helper` 1,405,992 / `rufus-gui` 11,602,240 bytes, `within committed baseline allowance, all budgets OK`. `cargo xtask ci` runs fmt and clippy and then stops at `==> test`: the 7 baseline failures make `cargo test --workspace` exit 101, so the assets, parity, size and dependency stages were each run standalone in the same tree instead of being reported as covered by `ci`. `cargo-audit` is not installed on this host, so that gate is skipped and reported as skipped, never as a pass.
* **Not covered**: the window has never been rendered (no display on the build host), so widget layout, combo selection round-trips and the zenity/kdialog picker are unverified; hotplug transitions are covered by injected snapshots only — no USB stick has been plugged into or pulled out of a running window, and its `inotify` path is exercised only by `rufus-linux`'s own fixtures — and the analyzer is proven with injected fakes and tiny synthetic fixtures only: no real multi-hundred-MB ISO, no real WIM edition table and no analyzer run on a real display have been exercised.

### S25 automated coverage (client-side IPC seam)
* **Shared parser (`rufus-proto`)**: 23 library tests (17 before slice 1, 21 at the slice-1 tip): the 4 slice-1 ones are `jsonl_line_parser_trims_and_parses_an_event` (surrounding whitespace and a trailing `\r` are ignored), `jsonl_line_parser_names_empty_invalid_unknown_and_future_versions` (each of the four `LineError` variants asserted concretely — `Empty`, `Json(_)`, `UnknownKind("future")`, `VersionTooHigh { found: 2, supported: EVENT_STREAM_VERSION }` — plus the hostile inputs: a two-line blob and `"\u{0}"` must be `Json`, an 8 MiB message must parse `Ok`, and 4,096 nested `[` must fail as `Json` with no panic and no stack overflow), `jsonl_parser_accepts_every_serialized_event_variant` (serialise → `from_jsonl_line` → compare, one entry per `Event` variant) and `line_errors_have_pinned_display_strings` (all four `Display` strings pinned, and an `UnknownKind` tag carrying ESC and a newline must render with no control character left in it); the 2 slice-2 ones are `plan_to_json_round_trips_through_the_wire_type` (serialise → parse → equal) and `plan_to_json_preserves_the_confirm_value_verbatim` (a `confirm` carrying a space and a newline survives byte-for-byte).
* **Seam (`rufus-gui::ipc`)**: 6 headless tests — `mock_transport_demultiplexes_and_stops_after_one_done` (a foreign-session line is skipped, the matching progress arrives, `Done` is surfaced exactly once and the next two `next()` calls are `None`), `mock_transport_uses_the_proto_parser_and_surfaces_protocol_errors` (a bad line becomes `IpcError::Protocol(LineError::Json(_))`), `event_stream_forwards_transport_errors_and_ignores_mismatched_sessions`, `cancel_runs_its_action_once_across_clones` (also asserting `CancelHandle: Send` and `EventStream: Send`, with the action counted through an `AtomicUsize`), `cancel_repeats_the_first_error_across_clones` (an `Err` stays that same `Err` on the clone's call, action still run once) and `ipc_errors_have_pinned_display_strings`. `rufus-gui` library tests go 30 → 36 in slice 1 and 36 → 49 in slice 2 (13 transport tests), and the binary stays at 7; no test opens a device, a display or a helper.
* **Transport (`rufus-gui::ipc::pkexec`, slice 2)**: 13 headless tests driving `/bin/sh -c` stubs — no pkexec, root, polkit, bus or device. `normal_run_surfaces_progress_in_order_and_only_one_done`; `run_uses_the_helper_argv_and_plan_file_is_private_until_stream_end` (argv is exactly `rufus-helper --plan <file> --progress jsonl`, the plan is mode `0600` while live and gone at the terminal event); `cancelling_a_live_run_kills_it_and_is_idempotent`; `missing_program_is_a_spawn_error_and_leaves_no_temp_plan`; `exit_four_without_done_synthesizes_a_failed_completion` (version, `code == "exit"`, stderr text carried into the message); `exit_statuses_synthesize_expected_single_completion`, the `{0, 3, 4, 6, 7, 126}` table asserting the outcome per status, `code == "exit"` where applicable, `version == EVENT_STREAM_VERSION` and exactly one `Done`; `authorization_timeout_kills_and_reaps_silent_helper_and_removes_plan` (a 500 ms injected budget, the pinned error string, `/proc/<pid>` gone — killed *and* reaped — and no leftover plan); `invalid_utf8_reader_error_ends_without_done_and_removes_plan` (`Err` then `None`, no synthesised `Done`, plan removed); `large_stderr_keeps_bounded_escaped_tail` (8 KiB plus message overhead, the *tail* marker retained, no control characters); `stderr_control_characters_are_escaped_in_synthesized_failure_text` (ESC renders as `\u{1b}`); `constructor_sweeps_only_stale_exact_scheme_plan_files` (a dead-pid file is removed, a file naming this process's live pid is preserved); `blank_lines_between_events_are_skipped`; `dropping_a_live_stream_removes_its_plan_file_and_kills_child`.
* **Gates at the S25 slice-1 tip**: `cargo clippy --workspace --all-targets -- -D warnings` clean (the gate that failed the first review round), `cargo fmt --all -- --check` clean, `cargo build -p rufus-gui` clean, and `env -u APPDIR cargo test -p rufus-proto -p rufus-gui` green — 21 + 36 + 7 passed, 0 failed. `env -u APPDIR` is required: with this shell's `APPDIR` exported, `rufus-core`'s asset lookup resolves to the (absent) AppImage directory and 7 unrelated `rufus-core` tests fail; no test in this slice touches that path.
* **Gates at the S25 slice-2 tip**: `cargo clippy --workspace --all-targets -- -D warnings` exit 0 and clean; `cargo fmt --all -- --check` clean; `cargo build -p rufus-gui` clean; `env -u APPDIR cargo test -p rufus-proto -p rufus-gui` green — 23 + 49 + 7 passed, 0 failed; `ls /tmp/rufus-plan-*` prints nothing after the suite, so no run leaked its plan file.
* **State machine (`rufus-gui::run`, slice 4)**: 8 headless tests — `start_never_yields_a_runnable_plan_before_the_confirmation_gate` (START leaves `confirm == ""` and `confirmed_plan()` refuses), `confirm_attaches_exactly_the_recomputed_sha256_token` (the attached token is `Plan::confirm`'s own hash), `progress_maps_every_wire_op_and_never_regresses` (all seven `op` tags, stale samples ignored, percent monotonic), `rate_and_eta_use_the_injected_elapsed_and_stay_unknown_without_data`, `cancel_mid_write_yields_exactly_one_cancelled_terminal_state`, `configuration_is_locked_while_confirming_and_running_and_after_finish_unlocked`, `log_lines_are_buffered_in_order_and_bounded` and `run_errors_have_pinned_display_strings` — no device, pkexec, bus, polkit or wall clock.
* **Gates at the S25 slice-4 tip**: `cargo fmt --all -- --check` clean; `env -u APPDIR cargo clippy -p rufus-gui --all-targets -- -D warnings` exit 0 and clean; `env -u APPDIR cargo test -p rufus-gui` green — 74 + 7 passed, 0 failed.
* **Slint wiring (S25 slice 5)**: 5 new binary tests — `start_requires_confirmation_before_a_transport_can_start` (START leaves `confirm == ""`, `confirmed_plan()` refuses, only `confirm()` opens the gate), `run_state_drives_progress_and_locked_controls` (lock/start/cancel flags, 50% progress, rate, ETA, terminal text), `cancel_bridge_is_one_shot_and_survives_early_cancel`, `confirmation_facts_include_every_destructive_warning` and `log_lines_keep_level_and_order` — while the two C3 session tests are retained. Library stays at 74; binary 7 → 12. No test opens a device, a display, a helper, pkexec, polkit or a bus.
* **Gates at the S25 slice-5 tip**: `cargo fmt --all -- --check` clean; `env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings` exit 0 and clean; `env -u APPDIR cargo test -p rufus-gui` green — 74 + 12 + 0 passed, 0 failed. `cargo` needs `PATH=/home/hosi/.cargo/bin:$PATH`.
* **Checksum modal (S25 slice 6)**: 7 new headless tests in `checksum.rs` (known vectors for all four digests, empty file, monotonic/bounded incremental progress, mid-run cancellation with no partial digests, repeated/pre-cancel, stale `(id, path)` discard, named failure for an unreadable source) plus 1 binary formatter test; library 74 -> 81, binary 12 -> 13. No test opens a Slint window, device, pkexec, D-Bus or display; fixtures are tiny temp files with pid+counter names removed on `Drop`. The old synchronous `analyzer::checksum` note path is gone from the GUI but the core function still has its own test.
* **Gates at the S25 slice-6 tip**: `cargo fmt --all -- --check` clean; `env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings` exit 0 and clean; `env -u APPDIR cargo test -p rufus-gui` green — 81 + 13 + 0 passed, 0 failed. Rendered-window layout and copy/paste from the read-only `LineEdit`s remain unverified (no display on the build host).
* **Localisation and GUI preferences (S25 slice 7)**: 4 new headless tests in `i18n_bridge.rs` (embedded fallback with no asset, stable locale order + RTL flags for ar/he/fa/ur, full-tag → primary → English fallback chain) and 2 in `config_bridge.rs` (atomic GUI-pref round trip preserving every unrelated field with no temp-file leak, missing/corrupt file yielding defaults without a destructive write), plus 1 core `config.rs` test (`gui_table_loads_defaults_and_round_trips`) and 1 binary caption test. Library 81 -> 86, binary 13 -> 14. No test opens a display, device, helper, bus or network; fixtures are temp files cleaned on `Drop`.
* **Gates at the S25 slice-7 tip (final)**: `cargo fmt --all -- --check` clean; `env -u APPDIR cargo clippy --workspace --all-targets -- -D warnings` exit 0; `env -u APPDIR cargo test -p rufus-gui` green — 86 + 14 + 0 passed, 0 failed; `env -u APPDIR cargo test --workspace` green (0 failed); `cargo xtask size` within budget (`rufus-gui` 12,774,280 / 14,000,000); `env -u APPDIR cargo xtask ci` exit 0 (`ci: all gates passed`, assets 86/86, parity fresh at 2,709 rows). Non-fatal `cargo-deny` duplicate-zbus warnings remain (zbus 5.19 pulled by Slint, 6.2 by the GUI/helper); `cargo-audit` is not installed and is reported as SKIP, not a pass. Headless/live-asset catalog loading and rendered-UI text alignment remain unverified (no display on the build host; `assets_dir()` resolves to a bogus `$APPDIR` here).

### Resolved (`0xc0000001`):
* **Windows First-Boot `0xc0000001`**: This was NOT a WIM-specialization limitation — it was a BCD bug. The generated UEFI store omitted the loader's `12000004` description element, which bootmgr requires; any store without it lands in Recovery with `0xc0000001`. An earlier note claiming "an identical `bcdboot` deployment fails identically" was wrong: a WinPE-regenerated `bcdboot` BCD on the same image boots past bootmgr, and a controlled A/B test isolated `12000004` as the deciding element. Fixed in `4d22a12` (caller always supplies a non-empty description), with the surrounding bcdboot-parity work in `44e8062`, `a3c2154`, `8e01ab0` and `296261b`.
* **Remaining Setup screen (out of S21 scope)**: Because the image applies an unspecialized deployment `install.wim`, boot currently stops at the "Install Windows / Windows installation error" Setup screen — the same screen the known-good `bcdboot` BCD reaches. Reaching a full desktop requires Windows Setup's specialize pass (a generalized/specialized WIM), which is a separate concern from S21's BCD correctness. The S21 acceptance criterion — no `0xc0000001`, no manual `bcdedit`/`chkdsk`/`bcdboot` repair — is MET.

## S26 — Distribution packaging & release bundles

This section explains how furus turns a validated workspace and a set of
packaging metadata files into installable release bundles. It is written for an
engineer seeing the project for the first time; everything here lives under
`xtask/src/main.rs` (the `dist` pipeline and its unit tests) and `packaging/`
(the metadata that gets validated and staged). No feature code in the shipped
binaries was changed by this work.

### What changed and why (T1–T5)

S26 is the distribution slice. It makes releases reproducible and installable
on Debian/Ubuntu, Arch and RPM systems. The five tasks map as follows:

* **T1 — ratification (commit `9cd7d38`)**: three open S00 plan defaults were
  ratified against what the code already does — A1 (licence GPL-3.0-or-later),
  A3 (targets x86_64 + aarch64, glibc ≥ 2.31) and A5 (wimlib for WIM/ESD),
  recorded in `DECISIONS.md` §4. **A2 and A6–A12 deliberately remain proposed**;
  ratifying them is outside S26's authorization, so the broad S00 phrase "no
  unratified architecture items" stays formally unmet by design.
* **T2 — packaging files (commit `2ba0ff4`)**: finalized the 11 files under
  `packaging/` — the D-Bus service + `system.d` conf, the polkit policy, the
  desktop entry, AppStream metainfo, SVG icon, Debian `control`/`postinst`, Arch
  `PKGBUILD`, RPM spec, and `packaging/README.md`.
* **T3 — dist pipeline (commit `d0b9d42`)**: implemented
  `cargo xtask dist` end to end and aligned the Arch/RPM specs with the archive
  it actually emits.
* **T4 — tests (this final slice)**: expanded the `xtask` unit tests from 15 to
  21, covering the staged layout and modes, positive/negative XML and INI
  validation, and SHA-256 generation/corruption detection. One small,
  behavior-preserving refactor extracted `write_sha256sums` from `cmd_dist` so
  the exact digest format can be tested without a release build.
* **T5 — verification (this final slice)**: ran the full gate set (`fmt`,
  `cargo test -p xtask`, `cargo xtask dist`, `cargo xtask ci`, and `sha256sum -c`
  on the produced bundle); all passed. Tail results are recorded below.

### Architecture and data flow

`cargo xtask dist [--target <triple>] [--out-dir <dir>]` runs this pipeline in
`cmd_dist`, anchored at the workspace root derived from `CARGO_MANIFEST_DIR`
(never the current directory):

1. **Root + triple resolution.** `repo_root()` is the directory containing
   `xtask/`. `host_triple()` reads the `host:` line of `rustc -vV`. The effective
   triple is `--target` if given, else the host. `debian_arch()` maps the triple
   to a Debian architecture and fails fast on anything else.
2. **Release build + size gates.** It runs `cargo build --release --workspace`
   (adding `--target <triple>` when one was supplied), then stats the three
   binaries and enforces the committed budgets: `rufus` 3,000,000 bytes,
   `rufus-helper` 2,500,000, `rufus-gui` 14,000,000. `cmd_size` additionally
   checks drift against `size-baseline.json` with a 4,096-byte allowance; the
   `dist` path itself only enforces the hard budgets.
3. **Manifest validation.** `validate_packaging()` reads all 11 `PACKAGING_FILES`
   and validates the semantic ones: XML files (polkit policy, D-Bus `system.d`
   conf, AppStream metainfo) are parsed with **quick-xml** into a small element
   tree (`xml_tree`) and checked for required attributes/text; INI-shaped files
   (D-Bus service, desktop entry) go through a **hand-written `parse_ini`** that
   fails closed on duplicates, stray keys and malformed lines; the distro files
   are checked for required tokens (`require_tokens`). Validated texts are
   returned in a `Packaging` struct so staging never re-reads them.
4. **Staging tree.** `stage_tree()` wipes and rebuilds `target/dist-staging/<triple>`
   with exactly 12 files: `usr/bin/rufus`, `usr/bin/rufus-gui`,
   `usr/libexec/rufus-helper`, the polkit/service/bus-conf/desktop/metainfo/SVG
   data files, `usr/share/doc/rufus/LICENSES.md`, `DEBIAN/control` and
   `DEBIAN/postinst`. Binaries, the helper and `postinst` are mode **0755**; all
   metadata and the control file are **0644**. The literal `Architecture: any`
   in `deb/control` is rewritten once to the concrete `amd64`/`arm64` value.
5. **Deterministic tarball.** `write_dist_archive()` emits a `.tar.gz` straight
   into the output file: **flate2 `GzBuilder` with `mtime(0)`** and best
   compression wraps a `tar::Builder`. Entries are collected by
   `collect_staged()`, sorted by path (directories before files), and each
   header is built with `Header::new_gnu()` with **mtime = uid = gid = 0**, empty
   uname/gname, and the staged mode. Non-regular staged entries fail closed.
   `verify_archive()` reads the finished archive back and checks every entry's
   path, mtime and uid/gid against the staging tree.
6. **Conditional .deb.** If `dpkg-deb` is on `PATH`, `cmd_dist` runs
   `dpkg-deb --root-owner-group --build <staging> <out>/<stem>.deb` so the helper
   is installed root-owned. Here `dpkg-deb` is absent, so it prints
   `skip .deb: dpkg-deb not available` and continues — the tar.gz and SHA256SUMS
   are still a successful release.
7. **SHA256SUMS.** `write_sha256sums(out_dir, artifacts)` writes one
   `<64-hex-digest>  <name>\n` line per produced artifact in stable order. In
   this environment the only artifact is
   `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`.

The artifact name is `rufus-<CARGO_PKG_VERSION>-<triple>.tar.gz`. The default
output directory is `target/dist/<triple>`; `--out-dir <dir>` is honored and
resolved relative to the repo root. The staging directory is always
`target/dist-staging/<triple>` and is wiped on every run.

### Security invariants

* **Privileged helper.** `usr/libexec/rufus-helper` is staged mode 0755 and,
  in the `.deb`, built with `dpkg-deb --root-owner-group` so it lands
  root-owned; `DEBIAN/postinst` re-asserts `chown root:root` and `chmod 0755`
  idempotently. The GUI never runs as root (S24 split).
* **Polkit authorization gate.** The action `org.rufuslinux.write-device` uses
  `allow_any=no`, `allow_inactive=no` and `allow_active=auth_admin_keep`, so an
  administrator authenticates once per session for a write, not once per
  sector. The helper checks this action for the caller before reading a plan.
* **D-Bus ownership confinement.** `org.rufuslinux.Helper1.conf` uses a
  `<policy user="root">` that allows only `own` of `org.rufuslinux.Helper1`, and
  a `<policy context="default">` that **denies `own` but allows
  `send_destination`**. This restricts *who can claim* the well-known name
  (defence in depth against an impostor) without blocking the unprivileged GUI
  from calling `Execute`/`Cancel`. A group-restricted send policy was rejected:
  it would duplicate the method-authorization decision that already belongs to
  the polkit action, and the two could drift apart. Method authorization is the
  helper's job, not the bus policy's.

### Naming deviation: `org.rufuslinux.*`, not `org.rufus.*`

The S26 specification literally writes the IDs/filenames as `org.rufus.*`. The
shipped code hardcodes the D-Bus name and interface `org.rufuslinux.Helper1`,
the object path `/org/rufuslinux/Helper1`, the polkit action
`org.rufuslinux.write-device`, and the desktop id `org.rufuslinux.Rufus.desktop`
(the `--dbus` CLI switch on the helper is also fixed). The GUI and helper
compile against these exact strings; changing them would break the running
system. Every filename and identifier therefore keeps the `org.rufuslinux.*`
namespace. **This is an accepted, documented deviation from the spec's literal
names**, recorded in `packaging/README.md` and the decision records. The
required *properties* (auth_admin_keep, root-only name ownership, the install
locations) are all met; only the literal spelling differs.

### External-tool dependency rationale

Following decision A4, formatters are runtime-checked and declared as
*recommendations*, not hard dependencies, so images that need no external
formatter still work. FAT32 and exFAT are written natively. The rest:

| Format | Tool | Debian / Ubuntu | Arch |
|---|---|---|---|
| NTFS | `mkntfs`/`mkfs.ntfs` | `ntfs-3g` | `ntfs-3g` **and** `ntfsprogs` |
| ext2/3/4 | `mke2fs`/`e2fsck` | `e2fsprogs` | `e2fsprogs` |
| UDF | `mkudffs` | `udftools` | `udftools` |
| WIM/ESD | wimlib | `libwim15` | `wimlib` |

These are declared as `Recommends: ntfs-3g, e2fsprogs, udftools, libwim15` in
`deb/control`, as `optdepends=('ntfs-3g' 'ntfsprogs' 'e2fsprogs' 'udftools'
'wimlib')` in the Arch `PKGBUILD`, and as `Recommends: ...` in the RPM spec.
**There is no `rufus doctor` subcommand** — none was added. Validation of these
dependencies lives entirely in the packaging metadata and the runtime checks in
the writer code; do not claim a CLI command was introduced.

### Target / architecture mapping and the `--target` fix

`debian_arch()` maps `x86_64-*` → `amd64` and `aarch64-*`/`arm64*` → `arm64`;
anything else fails early with a clear message before a build is attempted.
Only the host triple `x86_64-unknown-linux-gnu` is installed here, so no
aarch64 cross-build was produced or verified.

A bug was found and fixed in T3: an explicit `--target` always makes Cargo build
into `target/<triple>/release`, even when the triple equals the host, whereas a
host build without `--target` lands in `target/release`. `cmd_dist` keys its
`bin_dir` off `target.is_some()` (not `triple == host`) so it reads binaries
from the right place in both cases.

### Packaging ↔ dist contract (the T3 blocker and its resolution)

The reviewer of T3 found a mismatch: `dist` emits **one** triple-named archive
whose top level is the staged FHS tree (`usr/` and `DEBIAN/`), while the Arch
`PKGBUILD` and RPM spec claimed different tarball names and read loose files
from the extraction root. The decision was to **fix the packaging, not dist** —
the archive name and layout are now the authoritative contract:

* `packaging/arch/PKGBUILD` sets `_target=${_target:-x86_64-unknown-linux-gnu}`
  and `source=("rufus-${pkgver}-${_target}.tar.gz")`, matching the real artifact
  exactly. Every `package()` source path now points into the staged tree
  (`${srcdir}/usr/bin/rufus`, `${srcdir}/usr/libexec/rufus-helper`,
  `${srcdir}/usr/share/...`). A real `makepkg`-style `package()` run under
  `fakeroot` passed in review.
* `packaging/rpm/rufus.spec` sets `%global dist_target
  x86_64-unknown-linux-gnu`, `Source0: rufus-%{version}-%{dist_target}.tar.gz`
  and `BuildArch: x86_64`, with `%setup -q -c -n rufus-%{version}` (the archive
  has no leading directory) and every `%install` source taken from the staged
  tree.

A future engineer must not reintroduce a second tarball or flatten the archive:
both distro specs consume this exact `usr/` + `DEBIAN/` layout.

### Decisions and trade-offs

* **In-process tar/flate2 vs. shelling out to GNU tar.** The archive is built
  with the `tar` and `flate2` crates directly. This avoids depending on a host
  `tar` binary and gives precise control over header fields (uid/gid/mtime 0,
  GNU headers, sorted order), which is what makes the output deterministic.
* **Deterministic gzip vs. apparent mtime.** The gzip header mtime and every
  tar-entry mtime are stored as **0**. GNU `tar -tv` may *display* the epoch as
  `1970-01-01 02:00` because it applies the local (UTC+2 here) timezone to that
  stored zero; nothing is actually timestamped. No timestamp other than zero is
  written anywhere.
* **Conditional .deb.** `.deb` generation is attempted only when `dpkg-deb`
  exists. Here it does not, so `.deb` output is untested in this environment and
  skipped by design while the rest of the release still succeeds.
* **No `unsafe` in xtask.** The crate declares `#![forbid(unsafe_code)]`; all of
  this is safe Rust, with std plus the already-present `anyhow`, `flate2`, `tar`,
  `quick-xml`, `serde`/`serde_json` dependencies. No new dependency was added
  for tests (a pid + atomic-counter `TempDir` replaces a tempfile crate).
* **Coverage limits.** No aarch64 cross-build, real `dpkg-deb`, `rpmspec` or
  `rpmlint` check was possible here; those surfaces remain unverified.

### Verification record (final S26-T4 run)

All commands were run from `/home/hosi/dev/REA-Rufus/furus` with
`PATH="$HOME/.cargo/bin:$PATH"`:

* `cargo fmt --all -- --check` → clean (exit 0).
* `cargo test -p xtask` → `test result: ok. 21 passed; 0 failed; 0 ignored;
  0 measured; 0 filtered out` (was 15 before T4).
* `cargo xtask dist` → exit 0; sizes `rufus` 1,810,152 / `rufus-helper`
  1,406,296 / `rufus-gui` 12,774,280 bytes, all `[OK]`; `11 packaging files`
  validated; `skip .deb: dpkg-deb not available`; artifact
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`.
* `sha256sum -c SHA256SUMS` in
  `target/dist/x86_64-unknown-linux-gnu/` →
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz: OK`.
* `cargo xtask ci` → `ci: all gates passed` (fmt, clippy, workspace test,
  assets 86/86, parity 2,709 rows, size, `cargo deny check` = advisories/bans/
  licences/sources ok; `cargo-audit` reported `SKIP (not installed)`).
* `git diff --check` → clean.

The non-fatal `cargo deny` duplicate-crate warnings (zbus, thiserror, toml,
windows-sys, etc.) remain unchanged from S25 and are not introduced by S26.

## S27 — Automated QA gate (`cargo xtask qa`)

This section records the technical decisions behind the S27 release gate. It
is written for an engineer seeing the project for the first time. The gate
lives entirely in `xtask/src/main.rs` (`cmd_qa` and its helpers); no feature
code in the shipped binaries was changed, and `data/parity.csv` was deliberately
left untouched.

### What changed and why (T1–T3)

S27 is an **automation** slice, not a functionality slice. The formatters,
partition writers, BCD/SYSTEM-hive logic and the BIOS/UEFI boot suites already
existed and were verified individually; what was missing was one deterministic,
unprivileged command that runs them all and fails CI if any of them fails. The
three tasks map as follows:

* **T1 — the gate (commit `75563b4`)**: implemented `cargo xtask qa` with two
  tiers, strict timeouts, kill/reap, explicit `SKIP` lines and the
  `--require-qemu` / `--privileged` flags, plus the `xtask` unit tests
  (the suite total went from 21 to **29**).
* **T2 — completion markers and documentation (this slice)**: extended the
  `tools/parity.py` docstring, added the S21–S27 slice-completion matrix and
  the `cargo xtask qa` section to `README.md`, appended this `## S27` section,
  and rewrote the root `HANDOFF.md` plus a new slice handoff. No `BY_MODULE` /
  `OVERRIDES` entry and no generated row changed.
* **T3 — CI wiring (remaining, Slice 3/3)**: add `cargo xtask qa` as a gate in
  `.github/workflows/ci.yml`. That file is out of this slice's scope; until it
  lands, the command is green locally but CI does not yet call it.

**CI native build dependencies (S28, workflow-only).** On `ubuntu-latest` the
workflow installs Slint's native dev headers (`pkg-config`, fontconfig,
xkbcommon, wayland and xcb) because `yeslogic-fontconfig-sys` needs
`fontconfig.pc` and Slint 1.19 (`backend-winit` + `renderer-software`) probes
`wayland-client.pc` and x11/x11-xcb via pkg-config, and it shims Ubuntu's
`OVMF_*_4M.fd` firmware into the Arch-expected `/usr/share/edk2/x64/*.4m.fd`
names so Tier 2 UEFI boots instead of skipping — no architecture changed, and
`libwim-dev` was deliberately left out because `wimlib-sys` builds without it.

### Architecture and data flow

`cmd_qa(root, options)` builds a `QaSummary` that collects failed stage labels
so the gate reports **every** failure instead of stopping at the first.

1. **Options.** `parse_qa_options` accepts only `--require-qemu` and
   `--privileged`; anything else is a named error. Parsing is a pure,
   unit-tested value (`QaOptions`), so no process is spawned to test it.
2. **Tier 1 (always on).** Eleven unprivileged suites are orchestrated as
   `cargo test` subprocesses with inherited stdio (each suite's own `skip:`
   lines stay visible): the `rufus-linux` `partition_table` suite (MBR/GPT),
   the `rufus-core` `fat32_format`, `exfat_format`, `ntfs_format`,
   `ext_format` and `udf_format` suites, the `uefi_ntfs::` structural library
   tests, and the Windows suites (`windows::bcd::`, `windows::to_go::`,
   `windows::boot_files::`, `pipeline::bootloader::tests::windows::`). The BCD
   element shapes, the stripped class-0x4 elements, the `0xc0000001`
   regression guard and the SYSTEM hive `SanPolicy=4` assertion all live in
   those pre-existing tests. All targets are regular/sparse files — no root,
   no loop device, no mount.
3. **Privileged opt-in.** The `pipeline_end_to_end`, `loop_device` and
   `mount_seam` suites are `#[ignore]`d by default and need real loop devices.
   Without `--privileged`, `tier1/pipeline-loop` prints an explicit
   `SKIP  ... need --privileged` line; with it, the ignored tests are run
   (`loop` filters out the 4 GiB throughput benchmark on this host).
4. **Tier 2 (conditional).** If `qemu-system-x86_64` is absent, the three boot
   stages print `SKIP` lines and the gate still finishes successfully — unless
   `--require-qemu` was set, in which case the missing toolchain is fatal
   (`bail!`). When QEMU is present:
   * `tier2/bios-smoke` writes a 512-byte MBR boot sector into a scratch
     directory under `std::env::temp_dir()` and boots it with
     `-display none -serial stdio -monitor none -no-reboot -drive ...,format=raw,if=ide`.
     `boot_sector_bytes` assembles a real-mode loop (`cli`, `cld`, then per
     character poll the COM1 line-status register at `0x3FD` for the
     transmit-holding-register-empty bit, write the data port `0x3F8`, finish
     with `hlt` and a `jmp $` park) and ends with the `0x55AA` signature at
     offsets 510/511 that makes SeaBIOS execute the sector at `0x7C00`. The
     marker is `FURUS-QA-OK`; the assertion is a case-insensitive ASCII search
     over the captured raw serial bytes. The scratch directory is removed on
     every path.
   * `tier2/bios-bootloaders` runs the existing
     `pipeline::bootloader::end_to_end::qemu_boot::` suites (Syslinux 4.07,
     FreeDOS, GRUB2 BIOS). Each already has a 10–12 second capture deadline;
     the gate's outer deadline is only a backstop for a hung `cargo` process.
   * `tier2/uefi-ntfs-ovmf` first probes `qemu-system-x86_64`, `grub-mkimage`,
     `mkntfs`, `ntfscp`, `unshare`, `ntfs-3g` and a complete OVMF code+vars
     pair (checked across the common `/usr/share/edk2/...` and
     `/usr/share/OVMF/...` layouts). If anything is missing it prints one
     `SKIP` (or fails under `--require-qemu`); otherwise it runs the existing
     `uefi_ntfs_boot` integration test, which asserts its own `UEFI-NTFS-OK`
     serial marker from the shim's GRUB payload.
5. **Reporting.** Each stage logs `PASS  <label>` or `FAIL  <label>: <reason>`;
   `QaSummary::finish` ends with `qa: all suites passed` or a named list of
   failures and a non-zero exit.

### Decisions and trade-offs

* **Orchestrate existing suites, never reimplement.** The root cause of S27
  was missing automation, not missing functionality. Formatting, MBR/GPT
  writing, BCD parsing and boot capture already have their own tests; `qa`
  only sequences them. Reimplementing any of them inside `xtask` would create
  a second source of truth that could pass while the real code regressed.
* **No `rufus-core` dependency in `xtask`.** The gate drives the suites as
  `cargo test` subprocesses and inspects only their exit status and (for the
  smoke test) QEMU's stdout. Linking `rufus-core` into `xtask` would drag the
  formatter/tool chain and its dependencies into the maintenance crate,
  duplicate the tests' tool probes, and couple the gate to crate internals.
  Keeping the boundary at the process level means the gate stays small, uses
  only `std` plus the dependencies already present, and exercises exactly the
  code the shipped binaries use.
* **Hand-assembled 512-byte MBR + COM1, not VGA capture.** A deterministic
  byte-coded boot sector that prints `FURUS-QA-OK` to COM1 is the smallest
  possible proof that a BIOS actually executed sector 0 from our image: it is
  file-backed (no loop device or root), needs no framebuffer, terminal or
  graphical console, and makes the assertion a plain byte-substring search.
  Reusing a VGA/framebuffer capture would tie the gate to host graphics and a
  font/rendering path that has nothing to do with boot correctness; the real
  bootloaders are still covered by the existing VGA-tolerant QEMU suites in
  the next stage.
* **Delegate UEFI to the existing OVMF harness.** The `uefi_ntfs_boot` suite
  already builds a shim, boots it under OVMF, and checks both the positive
  (marker present) and negative (marker must be absent without the shim)
  cases. Hand-crafting an EFI binary in `xtask` would duplicate that work and
  lose the negative control.
* **Strict deadlines + `ChildGuard`.** `QA_SUITE_TIMEOUT` is a 120-second
  backstop for each `cargo test` and `QA_QEMU_TIMEOUT` is 30 seconds for the
  smoke boot (well inside the promised 30–60 s window; the 162-byte loop
  prints in well under a second). Every spawn is wrapped so `Drop` kills and
  **reaps** the child, and the QEMU stdout reader runs on a thread while
  stderr is drained, so neither a full pipe nor a surviving `hlt`ed machine
  can hang CI. This is defence in depth: the suites' own 10–12 s capture
  guards handle the normal case, the gate's deadline handles a hung process.
* **`APPDIR` is removed at spawn.** Both `run_suite` and `qemu_bios_smoke`
  call `.env_remove("APPDIR")`. A stale AppImage variable makes
  `rufus_core::paths::asset_path` resolve to a non-existent AppImage tree,
  which fails unrelated asset tests (the reason S25 handoffs require
  `env -u APPDIR`); the gate removes it so callers need not remember.
* **Parity ledger intentionally unchanged.** `tools/parity.py` maps analysed
  functions by module/address. S26 and S27 ported no function, so giving them
  rows would be fiction and would break the byte-stable 2,709-row
  `data/parity.csv`. Only the docstring was extended; the completion matrix
  in `README.md` is the authoritative marker for these slices.
* **Flags semantics.** `--require-qemu` changes *missing toolchain* from a
  `SKIP` into a hard failure (it does not force an installed toolchain to
  pass); `--privileged` is the only way to opt into root/loop suites, so the
  default gate remains runnable by an unprivileged CI user. Unknown flags are
  rejected rather than ignored.
* **No `unsafe`, no new dependency.** `xtask` keeps `#![forbid(unsafe_code)]`;
  the real-mode bytes are assembled by pushing `u8` literals into a `Vec`, and
  the tests use the existing pid+atomic-counter `TempDir` pattern.

### Verification record (S27-T2)

All commands were run from `/home/hosi/dev/REA-Rufus/furus` with
`PATH="$HOME/.cargo/bin:$PATH"` (and `env -u APPDIR` for the QA gate):

* `cargo xtask parity --check` → exit 0; `parity: data/parity.csv is fresh
  (regeneration changes nothing)`, `2,709 data rows`, all per-disposition
  counts and address sets match. The parity.py docstring edit did not change a
  generated byte.
* `cargo test -p xtask` → `test result: ok. 29 passed; 0 failed; 0 ignored;
  0 measured; 0 filtered out` (21 before T1).
* `cargo fmt --all -- --check` → exit 0, clean.
* `env -u APPDIR PATH="$HOME/.cargo/bin:$PATH" cargo xtask qa` → exit 0,
  `qa: all suites passed`. Eleven Tier 1 suites `PASS`; `SKIP
  tier1/pipeline-loop: loop-device / throughput tests need --privileged`;
  Tier 2 `tier2/bios-smoke`, `tier2/bios-bootloaders` (3 passed / 1 ignored
  GRUB4DOS, 29.63 s) and `tier2/uefi-ntfs-ovmf` (1 passed, 17.55 s) all
  `PASS`. No scratch directory was left in `/tmp`.
* Tool context: `qemu-system-x86_64`, `grub-mkimage`, `mkntfs`, `ntfscp`,
  `unshare`, `ntfs-3g` and an OVMF code+vars pair are installed here, so Tier 2
  genuinely ran rather than skipping. `dpkg-deb` and `cargo-audit` are absent.

### Known limitations

* **No real root/loop test on this host.** `--privileged` was not used; the
  loop-device, mount-seam and ignored pipeline suites are skipped by design.
  Their behaviour is only covered where they are individually documented.
* **Host-specific SeaBIOS.** The BIOS smoke test asserts a COM1 marker under
  this host's SeaBIOS via `-display none`; a different firmware that does not
  map COM1 the same way could fail without indicating a product regression.
  The marker assertion tolerates case, not a different console device.
* **No fresh Windows BIOS boot.** Windows coverage in Tier 1 is BCD
  element-parity and SYSTEM-hive structural tests, not a booted SeaBIOS
  Windows To Go image; no legacy BIOS Windows boot is claimed as verified.
* **GRUB4DOS and real hardware remain out of scope.** The GRUB4DOS boot test
  is `#[ignore]`d pending a caller-supplied `grldr`, and no physical USB stick
  was booted in this environment.
* **CI wiring is not yet done.** T3 (`.github/workflows/ci.yml`) is a separate
  slice; until then the gate is local-only.
