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
* **`rufus-gui`**: Slint-based graphical user interface front-end.
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
- `rufus-core` parses this `regf` hive, inspects the existing elements, and dynamically constructs objects for:
  - `{bootmgr}` (Windows Boot Manager): firmware boot settings, display order, timeout.
  - `{default}` (Windows OS Loader): pointers to `\Windows\system32\winload.efi` (UEFI) or `winload.exe` (BIOS), referencing the data partition device signature.
  - `{memdiag}` (Memory Diagnostics).
- **Verification**: Comparing our output BCD against Microsoft `bcdboot` output via `bcddiff.py` proved **16 vs 16 objects identical** with zero element discrepancies and valid header checksums.

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

---

## 4. Current Verification Status & Known Limitations

### Verified:
* **End-to-End Write Pipeline**: Tested and verified on physical USB 3.0/2.0 hardware (`/dev/sdb`, 32 GB flash drive). Successfully applied 111,760 entries (19,215,065,696 bytes), formatted ESP, written BCD stores, and finalized cleanly.
* **Firmware Hand-off**: Firmware successfully loads `EFI/Boot/BOOTX64.EFI` from the ESP, passes execution to `bootmgfw.efi`, and invokes `winload.efi`.

### Pending / Known Limitation:
* **Windows First-Boot Specialize (`0xc0000001`)**:
  - Booting an un-specialized Windows 11 24H2 `install.wim` image on both QEMU/OVMF and physical hardware halts at Microsoft's Recovery screen with error `0xc0000001`.
  - Thorough testing showed that an identical deployment created via raw `wimlib-imagex apply` with official Microsoft `bcdboot` generation fails identically. Stock deployment WIM images require Windows Setup's specialize pass to populate system-specific driver states, `MountedDevices`, and service startup flags before they can boot to the desktop as a portable OS.
  - UEFI boot acceptance remains parked until a generalized reference image or post-apply registry specialization mechanism is evaluated.
