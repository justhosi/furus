# Handoff: Windows To Go boot failure `0xc0000001` — BCD is the root cause

> Purpose: continue this investigation in a **fresh session** with zero prior context.
> Everything needed is here. When done, delete/rename the stale `HANDOFF.md` (it is
> outdated — it still treats the BCD hypothesis as "ACTIVE").

---

## 1. Objective and acceptance criteria

- **Goal:** the rebuilt Windows To Go image must boot past the `0xc0000001` recovery
  screen under QEMU/OVMF **without any manual Microsoft-side repair** (no WinPE
  `bcdedit`/`chkdsk`/`bcdboot`).
- **Acceptance:** `./target/release/furus write --plan ...` produces an image that boots
  into Windows OOBE ("Getting ready") in the standard QEMU harness, with no `0xc0000001`.
- Secondary acceptance: all code fixes go through `coder` → `reviewer` slices, one
  command at a time, tagged `Slice N/M`; `TECHNICAL.md` and handoff docs stay current;
  **push only on explicit user permission via `publisher`** (coder/reviewer never push).

---

## 2. The single most important finding

**The failure is in the BCD store our pipeline writes, specifically in the *objects*
it creates — NOT the VBR, GPT, filesystem, content, or hives.**

Proof (decisive experiment, already run):
1. Boot the ISO to WinPE, `mountvol s: /s`, run
   `bcdboot c:\windows /s s: /f uefi /v` — Microsoft regenerates the ESP boot files + BCD.
2. Boot the WTG image in the same QEMU harness → screen goes to **"Starting services"**
   then **"Getting ready"** (Windows OOBE). `0xc0000001` is GONE.
3. The ESP **file set did not change** (no new locale dirs / boot.stl / resources). Only
   the BCD store changed. Therefore the defect is **inside our BCD store**.

Two isolation experiments FAILED to fix boot on our store:
- adding only `{bootmgr}` `11000001` = ESP GPT device (via `bcdedit /set {bootmgr} device
  partition=s:`) → still `0xc0000001`;
- additionally adding the resume object `{0c334284}` device → still `0xc0000001`.

So the differentiator is the **new OS+resume object pair** bcdboot creates, and/or the
repointed `{bootmgr}` `23000003`/`24000001`/`23000006` + `en-us` casing + `GuidCache`.

---

## 3. Git / slice state

- Repo: `/home/hosi/dev/REA-Furus/furus` (the top-level `REA-Furus` dir is NOT a git repo).
- HEAD = **`c9832de`**. Commits made this campaign:
  - `3921d51` `feat: pass the partition geometry to mkntfs so it writes a bootable VBR`
  - `c9832de` `feat: hand the planned partition start to the ntfs mkfs arm`
- 5 older unpushed commits: `a417a83`, `f566798`, `74fb14d`, `de990c5`, `b7ca5a9`.
  `origin/main` = `083dffe`. **Nothing has been pushed.**
- Untracked: `furus/HANDOFF.md` (stale, do not stage) and this handoff file.
- Slice numbering used so far = `1/3`, `2/3`. For the BCD fix + docs, **restate the count**
  (e.g. `Slice 3/4` BCD fix, `Slice 4/4` docs) and say the tag when handing to coder/reviewer.

---

## 4. What is already FIXED and verified (do not re-investigate)

- **NTFS descriptors, boot files, SYSTEM hive, BCD device GUIDs, GPT type GUIDs, MFT record
  size, RAM, dirty flag, alternate boot sector, ESP label** — all ruled out by earlier work.
- `mft2_clst` theory is DEAD: on-disk `mft2_clst` (4,179,325) exactly equals the real
  `$MFTMirr` LCN reported by `ntfsinfo -m`. Primary VBR is structurally valid.
- **mkntfs geometry (our slices 1/3 + 2/3):** the pipeline used to call
  `mkntfs -f -L <label> -c 4096 <dev>` with no geometry; mkntfs warned
  "Windows will not be able to boot from this device". Fixed by adding
  `-p <start> -H 255 -S 63`. Verified: rebuild log has no warning; VBR now has CHS
  63 @0x18, 255 heads @0x1A, hidden 239616 @0x1C. This was a real defect but **not** the
  boot blocker (boot still failed with geometry correct).
- **GPT / PMBR are correct** (two earlier alarms were my own parse bugs): entry field at
  offset 40 is `last_lba` (inclusive), not a sector count; p1 = 2048..206847 (100 MiB ESP),
  p2 = 206848..239615 (16 MiB MSR), p3 = 239616..67108830, ends exactly at `last_usable`.
  Primary + backup GPT headers mirrored. Protective MBR `0xEE` at 0x1BE, start LBA 1,
  sectors 0x03FFFFFF. `mkpart` writes all this correctly end-to-end.
- **Volume content complete:** 111,779 files, 25,358 dirs, 11 GB used. All key system files
  present (winload.efi, ntoskrnl.exe, config hives, 98 boot-start drivers all present,
  MZ/regf headers valid). Hives pass regf checksum + full hbin-chain validation.
  `chkdsk c: /f` in PE ran 17.85 s, said "Windows has made corrections to the file system"
  but reboot still failed — so whatever it fixed was not the blocker.
- **BCD parses cleanly in Windows' own `bcdedit`** — the store is not malformed.

---

## 5. BCD stores on disk (key facts)

- ESP BCD: `/EFI/Microsoft/Boot/BCD` — 32,768 B, UEFI store, default = `{b012b84d}`
  (`winload.efi`, device elements p3). This is the one firmware uses.
- Volume `\boot\bcd` — 28,672 B, **BIOS/legacy** variant (default `{a1943bbc}`,
  `winload.exe`). By design (dual UEFI+BIOS layout). Not the UEFI boot store.
- Live GPT GUIDs: disk `9be7c3e4-272e-453b-821d-d3e74adc55b6`;
  ESP part `1d093a82-8126-4811-a3cf-cadc390db127`;
  p3 part `8b431eb6-3dc0-4246-964c-44ec7b228e6b`.
- BCE element `11000001`/`21000001` device value = 88-byte BINARY:
  `[16 zero][u32 type=6][4 zero][u32 len=0x48][4 zero][part GUID 16][8 zero][disk GUID 16]`.
  `partition_device()` in `windows/bcd.rs` already builds exactly this shape (its doc says
  "88-byte REG_BINARY"). The code comment at `bcd.rs:69-74` wrongly claims `{bootmgr}` needs
  no `11000001` — that assumption is **disproven as the sole fix** but may still be part of
  the full answer.

---

## 6. Saved artifacts and current image state

| Path | What |
|---|---|
| `/tmp/opencode/bcd_new` | **Known-good** bcdboot store (boots). Diff this against ours. |
| `/tmp/opencode/bcd_ours2` | Our failing store + two bcdedit experiments (ESP device + resume device). |
| `/tmp/opencode/esp_orig/EFI/Microsoft/Boot/BCD` | Our original pre-bcdboot store. |
| `/tmp/opencode/bcd_new_dump.txt` | `bcd_dump2.py` dump of the good store (16 objects, 113 lines) — **now dumpable after the regf_dump2 patch**. |
| `/tmp/opencode/esp_orig/` | Full original ESP tree copy. |
| `/home/hosi/.cache/rscratch/wintogo.img` | 32 GiB test image; currently mid-OOBE from the bcdboot success run. **Rebuild before the final acceptance test.** |
| `/tmp/opencode/wtg-plan.json` | Rebuild plan (GPT, dual, ntfs, windows_to_go layout, ISO `/mnt/winiso/sources/install.wim`). |
| `/tmp/opencode/wtg-write4.log` | Clean rebuild log (after geometry fix). |

Current loop/mount state: `/dev/loop0` = ISO (ro, `/mnt/winiso`); `/dev/loop1` = wintogo.img
(rw, re-attached with `losetup -P`); `/dev/loop1p1` = ESP (`/mnt/esp2` vfat ro, mounted);
`/dev/loop1p3` = p3. No QEMU processes running. ESP `EFI/Microsoft/` now has both `Boot`
and `Recovery`.

---

## 7. Tooling gotchas (learned the hard way)

- `export PATH="$HOME/.cargo/bin:$PATH"`; binary is built with `cargo build --release -p
  furus-cli` (binary `target/release/furus`); **`-p furus` does not exist**.
- No `xxd` — use `od -A x -t x1z`. `convert`, `tesseract` available. `hivexsh`/`chntpw` not.
- Python scripts must run from `/home/hosi` (stray `/tmp/opencode/struct.py` shadows stdlib
  when a script lives in `/tmp/opencode`). A stray model-pricing banner may print — ignore.
- `losetup -f` fails as user. **`losetup -P` is mandatory** or the pipeline fails with
  "kernel cannot re-read the partition table". Stale udisks2 mounts on loop1 must be
  unmounted (`udisksctl unmount -b /dev/loop1`) before detach.
- Never `pkill -f` a pattern that also appears in your own shell command line (kills self).
  Use `pkill -x qemu-system-x86` (name truncated to 15 chars) or monitor `quit`.
- Detached QEMU needs `setsid nohup`; otherwise harness kills it with signal 15.
- Boot harness: `/tmp/opencode/boot-wintogo-4g.sh` (q35/KVM, `-cpu host`, OVMF_CODE.4m.fd +
  `/tmp/opencode/OVMF_VARS.fd`, ich9-ahci + ide-hd sata.0, 4 GB, vnc :5, monitor sock,
  `-no-reboot` exits itself ≈60 s after the recovery screen — sample screenshots at ≈40-55 s).
  Screenshot: `printf 'screendump /tmp/opencode/X.ppm\n' | socat - UNIX-CONNECT:/tmp/opencode/qemu-mon.sock`
  then `convert X.ppm X.png` then `tesseract X.png stdout --psm 6`.
- PE harness: `/tmp/opencode/pe-start.sh` boots ISO (`boot-pe.sh`, DVD bootindex=0, disk
  bootindex=1, vnc :6), polls serial, sends 4× `ret`; ~45-50 s to Setup language screen.
  `sendkey shift-f10` opens cmd (`X:\sources>`). Type with `python3 /home/hosi/sendtype.py
  '<text>'` (not executable directly; 0.05 s/key pacing; braces supported via
  `shift-bracket_left`/`shift-bracket_right`). `mountvol s: /s` mounts ESP as S:.
- FAT32 ESP gets dirty after a hard QEMU `quit` → Linux vfat `Input/output error`. Fix:
  `umount /mnt/esp2`, `fsck.vfat -n /dev/loop1p1`, remount ro.
- Rebuild command:
  `sudo -n systemd-inhibit --what=sleep:idle --mode=block ./target/release/furus write --plan /tmp/opencode/wtg-plan.json --yes`
  (inhibit is REQUIRED — host suspend once killed a mid-mkfs run).

---

## 8. Exact next steps (in order)

1. **Finish the object-level BCD diff.** `bcd_dump2.py` now works on the good store
   (`regf_dump2.py` was patched: `subkeys()` guards out-of-range list offsets and recurses
   into `ri` with `{'nsub':1,'sublist':sub}`). Dump our store too and diff:
   ```
   cd /home/hosi
   sudo -n python3 -u bcd_dump2.py /tmp/opencode/bcd_ours2 > /tmp/opencode/bcd_ours2_dump.txt
   diff /tmp/opencode/bcd_ours2_dump.txt /tmp/opencode/bcd_new_dump.txt
   ```
   Focus on: `23000003`/`24000001` (default/displayorder), `23000006`, `12000005`
   (`en-us` vs `en-US`), the `{d1e88705…}` OS object, `{d1e88704…}` resume object,
   `{6efb52bf}`→`{1afa9c49}` inheritance change, `GuidCache`.
   (Fallback if the dumper misbehaves: `/home/hosi/bcdtree.py` was written but has wrong
   `nk` field offsets — the authoritative ones are in `regf_dump2.py`: `nk` nsub@0x14,
   sublist@0x1C, nval@0x24, vallist@0x28, name-len@0x48, name@0x4C; root cell from base
   block 0x24; `vk` namelen@2, rawsize@4, dataoff@8, type@0xC, flags@0x10, name@0x14.)
2. **Identify the minimal change** to `windows/bcd.rs` that makes our store behave like
   bcdboot's. Likely: create a fresh OS loader object + resume object (with device
   elements) and repoint `{bootmgr}`'s `23000003`/`24000001`/`23000006`, instead of reusing
   the BCD-Template's `{b012b84d}`/`{0c334284}` objects. Read `crates/furus-core/src/windows/bcd.rs`
   (1897 lines): `build_store` (~line 575+), `StoreRequest`, `partition_device`, and the
   module doc (~lines 41-75, 192-205). Call site: `windows/to_go.rs` (~294-299) —
   `Request.identity` comes from `pipeline/bootloader/windows.rs::windows_identity`, using
   `esp_window`/`data_window` from `part/plan.rs`; the ESP GUID is available there.
3. **Open the fix as `Slice 3/4`** (restate tag): give coder the exact diagnosis and scope
   (one command, `coder`→`reviewer`, no push, acceptance = green fmt/clippy/tests). Then
   `Slice 4/4` = docs (`furus/TECHNICAL.md` root-cause record; rewrite stale `furus/HANDOFF.md`).
4. **Rebuild** (clean): detach/unmount as needed, `losetup -P /dev/loop1 <image>`, run the
   systemd-inhibit write command above; confirm mkntfs emits no geometry warning; dump VBR
   (expect CHS 63/255/239616, spv = device sectors − 1, valid backup boot sector);
   `ntfsfix -n /dev/loop1p3` must report the alternate boot sector OK.
5. **Boot test** with `boot-wintogo-4g.sh`; screenshot at ≈50 s. **Boot passes** when you see
   "Starting services" / "Getting ready" instead of `0xc0000001`.
6. Write an end-of-slice handoff, then **ask the user for push permission**; only then invoke
   `publisher` (which updates README, commits docs, pushes).

---

## 9. Standing rules to respect in the new session

- Diagnose before coding; one command per slice, `coder` → `reviewer`, one review at a time.
- `coder` never commits/pushes; `reviewer` commits but never pushes; `publisher` only with
  explicit user permission.
- If a subagent/model fails, follow the fallback rule in `~/.config/opencode/AGENTS.md`
  (one reconnect, then switch that agent's model line to the fallback, tell the user).
- Questions to the user go to Telegram via `notify-telegram` **and** the `question` tool.
- Keep `furus/TECHNICAL.md` updated with technical decisions; end each slice with a handoff.
