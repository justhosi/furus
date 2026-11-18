# Handoff — Windows To Go build (`wintogo.img`) — AI context recovery

> Written 2026-11-16. This document is the single source of truth for a fresh session.
> Read this fully before doing anything. The original conversation adds nothing beyond it.

## 1. Objective (user's task, verbatim intent)

Rebuild `~/.cache/rscratch/wintogo.img` from `win11e-eval.iso` (the existing one predates the fix).
Confirm genuine NTFS descriptors with `ntfssecaudit`. Boot QEMU/OVMF (ideally also a real stick)
past error `0xc0000001`. Update `furus/TECHNICAL.md`. Push ONLY on the user's explicit go-ahead,
via the `publisher` subagent (coder/reviewer never push).

Acceptance = genuine NTFS descriptors (TrustedInstaller etc., not the 3-descriptor simplified state)
AND boot past 0xc0000001. Fixes found during testing still go through coder → reviewer slices.

## 2. Repository & commit state (CLEAN, do not re-do)

- Repo: `/home/hosi/dev/REA-Rufus/furus`. `origin/main` = `083dffe`.
- HEAD = `b7ca5a9` — "fix: compute the Windows To Go apply capacity from the plan, not the volume"
  (Reviewed-by trailer, NOT pushed). Working tree CLEAN.
- 5 UNPUSHED commits: `a417a83`, `f566798`, `74fb14d`, `de990c5`, `b7ca5a9`.
- Gates (all passed at last check): build, fmt, clippy `-D warnings`, 1261 tests (6 ignored).
- **The fix is correct and committed**: NTFS-volume mode apply via wimlib (preserves security
  descriptors) runs BEFORE any mount; capacity comes from `data_window(LayoutKind::WindowsToGo,
  TableKind::Gpt, sector_size, size)` in `run_windows` (bootloader.rs ~1432), NOT from
  `ctx.opener.partition()?.total_bytes()` (which re-cached the `O_EXCL` handle → mount EBUSY).
- `TECHNICAL.md` has ONE bullet from the EBUSY fix; it still needs the full decision/result record.

## 3. Current image state

`/home/hosi/.cache/rscratch/wintogo.img` = 32 GiB GPT, fully written (`WRITE_EXIT=0`):
- p1 ESP 100M FAT32 (`972a3aff-d2cb-4240-92f8-4ed8585652dc`), starts sector 2048
- p2 MSR 16M (`e3c9e316` type, GUID `4d6b9d19-80f7-4017-b31d-52f92f94ef14`)
- p3 data 31.9G NTFS (`ebd0a0a2` type, GUID `796dfc6f-d7b7-443b-82d2-6a5dba19687c`), start sector
  239616, 66869214 sectors
- Disk GUID `aab49039-87ff-4fd1-836f-c3d42b90cac9`
- Written with `sudo -n systemd-inhibit --what=sleep:idle --mode=block ./target/release/rufus write --plan /tmp/opencode/wtg-plan.json --yes`
  (the inhibit is REQUIRED — host suspend killed an earlier mid-mkfs write).

**Image has been mutated during debugging** (all reversible; originals saved):
- ESP BCD was overwritten with a debug variant `/tmp/opencode/BCD-debug.bin` (36864 B, adds
  bootdebug=1/debugtype=Serial/debugport=COM1/baudrate=115200 to the default loader). Original
  saved at `/tmp/opencode/BCD-orig.bin` (32768 B).
- p3 VBR patched: hidden sectors = 239616, sec/track = 63, heads = 255. ntfsfix was run (fixed the
  alternate boot sector + cleared the dirty flag).
- None of these changes fixed the boot. For a clean re-test, restore BCD-orig.bin and re-run ntfsfix
  if desired; but ultimately the IMAGE SHOULD BE REBUILT from the plan after the real code fix.

Current device state: loop1 DETACHED, no loop1 mounts, no QEMU running. ISO at `/mnt/winiso` on loop0.

## 4. Verification results (all PASSED — strong evidence)

- **ntfssecaudit**: 886 valid descriptors / 450 distinct keys (old tree = 3). Per-file: `Windows`,
  `System32`, `Program Files`, `bootmgr`, root → owner `S-1-5-80-956008885-3418522649-1831038044-
  1853292631-2271478464` (TrustedInstaller); registry hive → `S-1-5-18` (SYSTEM). Genuine.
- Boot files: all ESP + data boot files present; `winload.efi`, `ntoskrnl.exe`, `hal.dll`, `ci.dll`,
  `kdcom.dll` are byte-identical (sha256) to install.wim. 39 boot files placed.
- BCD fully parsed with a custom regf reader: device/osdevice encode correct disk GUID + partition
  GUID; path `\windows\system32\winload.efi`; systemroot `\windows`; bootmgr default = the UEFI
  loader `{b012b84d-c47c-4ed5-b722-c0c42163e569}`. All correct.
- GPT type GUIDs correct (ESP/MSR/Basic Data). MFT record size 1024 is normal. RAM 4 GB tested.
- Dirty flag + bad alternate boot sector found via ntfsfix and fixed — no boot change.

## 5. THE BLOCKER — boot still fails `0xc0000001` (UNSOLVED)

QEMU/OVMF boots to the Windows recovery screen: "Recovery / Your PC/Device needs to be repaired /
An unexpected error has occurred. / Error code: 0xc0000001 / Press Esc for UEFI Firmware Settings".
Same failure in old and new image → second root cause, independent of the NTFS descriptor fix.
Everything statically checkable is correct (see §4). The failure is EARLY (bootmgr loaded winload,
winload returned STATUS_UNSUCCESSFUL, no filename in the error).

Ruled OUT as the cause: NTFS descriptors, boot files, SYSTEM hive, BCD structure/GUIDs/path,
GPT type GUIDs, hidden sectors, MFT record size, RAM, dirty flag, alternate boot sector, CHS geometry.

Note: "QEMU exited" = the recovery screen auto-reboots after ~60s (with `-no-reboot`, QEMU exits on
that reset). It is NOT a crash. Screendumps at 25/35/45/55s are identical static recovery screens.

**Serial debug is a DEAD END without a KD debugger**: even with bootdebug=1/Serial/COM1/115200 in
the BCD, `-serial file:` captures ONLY OVMF BdsDxe messages; Windows emits no plain text (KD protocol
needs a host debugger). Do not sink more time here.

### Prime remaining hypothesis (ACTIVE — this is where the previous session stopped)

The BCD **device element binary format** written by `partition_device()` in
`crates/rufus-core/src/windows/bcd.rs` (line 477) may be WRONG. If bootmgr cannot parse the
partition device element, it can't locate the partition → 0xc0000001. Inspect:
- `partition_device()` writes an 88-byte REG_BINARY: 16 zero bytes, **type 6** u32@0x10, zero@0x14,
  len 0x48 u32@0x18, zero@0x1C, then GPT: partition_guid 16B@0x20 + 8 zeros + disk_guid 16B@0x38.
- `boot_device()` writes type **5**@0x10 (this matches a real Windows BCD from the ISO: memdiag's
  11000001 = `...\x05\x00\x00\x00`).
- Ground truth from the ISO's own BCD (`/mnt/winiso/efi/microsoft/boot/bcd`, dumped with
  `bcd_dump.py`): ramdisk device = type **4**, **176 bytes**, starts with the ramdisk object GUID;
  boot device = type **5**, 88 bytes. The ISO BCD has NO partition device, so type 6 is UNVERIFIED.
- Need to determine the correct partition-device type/byte layout. Microsoft's BCD device types are
  believed to be: 1=Locate, 2=Partition, 3=File, 4=Ramdisk, 5=Boot — so **type 6 may be invalid**.
  The repo's tests merely assert what the code writes (6), so they don't prove correctness.
- Just extracted Microsoft's own template: `/tmp/opencode/tmpl/BCD-Template` (28672 B) from
  `install.wim`; `bcd_dump.py` shows it has loader objects with `\windows` / winload paths but the
  device elements are added by the repo's build (not in template). A web search for the exact BCD
  device-element binary format was INTERRUPTED — resume it.

**Next steps (in order):**
1. Determine the correct BCD partition device element format. Web search "BCD device element binary
   format partition GPT type field" or find a real GPT Windows BCD on the web / generate one. Compare
   byte-for-byte with `partition_device()` output. Check whether the GUID ORDER (partition@0x20,
   disk@0x38) and type value (6) are right.
2. If wrong, fix `bcd.rs::partition_device` via a coder slice → reviewer (one command at a time).
3. If the device element is correct, the next suspect is NTFS metadata Windows' boot-time reader
   rejects (compare MFT records of $MFT/$Boot/$Volume/$Bitmap/$LogFile, $I30 indices, $Secure
   $SII/$SDH against a Windows-formatted NTFS reference).
4. Rebuild the image from plan after the code fix; re-run all §4 verifications + boot test.
5. Update `TECHNICAL.md` with both the EBUSY fix and the second-root-cause fix/results.
6. Ask user for push permission; only then invoke `publisher`.

## 6. Tools, scripts & environment facts

- `cargo` needs `export PATH="$HOME/.cargo/bin:$PATH"` first. Passwordless `sudo -n`.
- **Run Python from `/home/hosi`** — a stray `/tmp/opencode/struct.py` shadows stdlib `struct`.
- Model CANNOT view images — use `tesseract <png> stdout` OCR + `magick <png> -resize 1x1 txt:-` for
  dominant color (recovery screen = `#2268B3`).
- `pkill -f '[q]emu-system'` to stop QEMU (the `[q]` avoids self-match). `pkill -x` fails (>15 chars).
- `sudo -n losetup --find --show --partscan <img>` to re-attach; udisks2 auto-mounts p3 at
  `/run/media/hosi/4AC1BC2C357EF894` — umount before raw access.
- Scripts in `/home/hosi/`: `bcd_dump.py` (working regf/BCD reader — offsets relative to 0x1000),
  `bcd_edit.py`, `gpt_dump.py`, `inspect_loader.py`, `dump_sublist.py`.
- Boot binaries: `/tmp/opencode/boot-wintogo.sh` (2.5G), `boot-wintogo-4g.sh` (4G + `-serial
  file:/tmp/opencode/serial.log`), `qemu-shot.sh <name>` (screendump via monitor socket → PNG).
- OVMF: `/usr/share/edk2/x64/OVMF_CODE.4m.fd` (RELEASE, no debug), VARS `/tmp/opencode/OVMF_VARS.fd`.
- mkntfs v2026.9.28 (libntfs-3g). wimlib 1.15.27 (too new for the old 1.8.x bootloader bug).
- BCD parse facts: cell = 4-byte size + record; nk name_len@+0x48, name@+0x4C; vk data_size@cell+8,
  data_off@cell+12; all cell offsets relative to 0x1000; 'lf' subkey entry = (offset u32, hint u32).

## 7. Working rules reminder (from ~/.config/opencode/AGENTS.md)

- Diagnose before coding. Slice work: one command to coder → reviewer → next command. Tag slices
  `Slice N/M`. Never let coder/reviewer push. Publisher only with explicit user permission.
- Handoff doc (this file) at end of every slice. Keep `TECHNICAL.md` updated with all decisions.
- Subagent models: coder = Hy4 flash Free (high); reviewer = Qwen 3.8 Flash (high);
  publisher = Qwen 3.8 Flash (medium). Don't change without explicit permission.
