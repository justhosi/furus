# Handoff — BCD subkey-list shrink bug (blocks Windows To Go bootloader step)

Created: 2026-11-17. This is the authoritative handoff for the current blocker.
Older handoffs: `HANDOFF-boot-c0000001.md` (original investigation), `HANDOFF.md` (stale).

## Objective

The Windows To Go (W2G) image built by this tool must boot past `0xc0000001`
under QEMU/OVMF to OOBE ("Starting services"/"Getting ready") with **no manual
Microsoft-side repair**. Acceptance is:

```
./target/release/rufus write --plan /tmp/opencode/wtg-plan.json --yes
```

produces an image that boots under QEMU/OVMF without `0xc0000001`.

## Current state (read this first)

### Git state
- Working dir: `/home/hosi/dev/REA-Rufus/furus`
- HEAD = `a3c2154`, **9 commits ahead of `origin/main`, nothing pushed**.
- Commit chain (newest first):
  - `a3c2154` `fix: strip setup-template elements from the boot store`
  - `44e8062` `fix: wire the resume object like bcdboot so the store boots`
  - `c9832de` `feat: hand the planned partition start to the ntfs mkfs arm`
  - `3921d51` `feat: pass the partition geometry to mkntfs so it writes a bootable VBR`
- `git status --short` shows only untracked `?? HANDOFF-boot-c0000001.md` and
  `?? HANDOFF.md` (plus this new handoff). Do NOT stage/commit handoff files.

### The blocker — NEW BUG introduced by the strip fix
The most recent `rufus write` **failed at the bootloader step** (it was not merely
cancelled by a server restart). Exact error from `/tmp/opencode/write4.log`:

```
info: applied 152980 entries (10404700292 bytes)
rufus: step 'bootloader': invalid input: bcd subkey list at file offset 0x6d80 cannot shrink
```

The `remove_child` primitive added in `a3c2154` (in
`crates/rufus-core/src/windows/regf.rs`, around line 1836) refuses to shrink an
lf/lh subkey-list cell at file offset `0x6d80`. This blocks the whole write. The
image is currently in a **partial state**: NTFS applied 100%, but the
bootloader/BCD step failed — it is NOT a valid bootable image and must be rebuilt
from scratch after the fix.

### Environment / loop state (verify before acting)
- `loop0` = ISO `/home/hosi/.cache/rscratch/isos/win11e-eval.iso`, mounted ro at `/mnt/winiso`.
- `loop1` = `/home/hosi/.cache/rscratch/wintogo.img`, attached with `-P`.
- `/dev/loop1p3` is **auto-mounted rw at `/run/media/hosi/05E8320825D489D2`** by
  udisks2 — unmount it before detaching loop1. `/dev/loop1p1` (ESP) may also be
  mounted at `/mnt/esp2`.
- Image mtime ~Nov 17 11:01 (partial write). No rufus/qemu processes running.
- Passwordless `sudo -n` works — use it for all root ops.

## What has been established (do not re-derive)

### Root-cause chain for `0xc0000001`
The tool patches the applied image's `Windows/System32/config/BCD-Template`
regf hive in place. A store built by real `bcdboot` boots; ours produced
`0xc0000001`. Verified byte-for-byte against bcdboot's good store
(`/tmp/opencode/bcd_new` / dump `/tmp/opencode/bcd_new.txt`):
- Device-blob format and GUID patching are **correct** (`type=6@0x10`, `len=0x48@0x18`,
  partition GUID@`0x20`, disk GUID@`0x38`); our store is byte-identical to bcdboot's
  for the target GUIDs.
- The missing piece was object STRUCTURE, fixed in two committed slices:
  1. `44e8062`: resume object wiring — resume device (`11000001` = data partition),
     full winresume path (`12000002` = `\windows\system32\winresume.efi`/.exe),
     and bootmgr `23000006` = resume GUID.
  2. `a3c2154`: strip class-0x4 setup-template elements (see below) from the
     active boot-path objects.

### Why template elements must be stripped
Per the authoritative BCD element reference
(https://geoffchappell.com/notes/windows/boot/bcd/elements.htm), BCD element
datatype class = `id & 0xF0000000`; class `0x4` = "template" = SETUP-time
directives, not runtime boot elements. These are the cruft our in-place template
patching leaves, and which bcdboot strips from every object it recreates:
- `0x42000002` = BcdSetupString_ApplicationRelativePath
- `0x45000001` = BcdSetupInteger_DeviceType
- `0x46000004` = BcdSetupBoolean_OmitOsLoaderElements (`0x46000010` = RecoveryOs)
- `0x47000005` = unknown 16-byte binary
- `0x47000006` = BCDE_TEMPLATE_TYPE_ELEMENTS_TO_MIGRATE_LIST
bcdboot strips these from `{bootmgr}`, the UEFI loader `{b012b84d}`, the resume
object, and `{memdiag}`, while leaving them on inactive BIOS/PE objects. Prime
suspect for `0xc0000001` was `45000001` DeviceType confusing bootmgfw.

### Deferred (not done, lower confidence)
- `{bootmgr}` ESP device (`11000001` = ESP partition `1d093a82...`) — bcdboot adds
  it, we omit it. Needs the ESP GUID threaded into `StoreRequest` (currently only
  the data-partition `identity` is available). An earlier bcdedit experiment adding
  it alone still failed, so it is probably necessary-but-not-sufficient. Consider
  only if the strip fix still fails to boot.
- `en-US`→`en-us` locale casing (cosmetic) and `16000009` autorecovery (harmless).

### Deterministic GUIDs
- ESP partition: `1d093a82-8126-4811-a3cf-cadc390db127`
- Data partition: `8b431eb6-3dc0-4246-964c-44ec7b228e6b`
- Disk: `9be7c3e4-272e-453b-821d-d3e74adc55b6`

## Exact next steps

1. **Diagnose the shrink bug** (this is a "when something is broken" situation —
   inspect + reproduce, state root cause, THEN change code):
   - Read `remove_child` (~line 1836) and `write_subkey_list` in
     `crates/rufus-core/src/windows/regf.rs`, plus `list_insert` (~1679) which it
     mirrors. Find where the "cannot shrink" error is raised and why the compacted
     lf/lh list at file offset `0x6d80` is rejected.
   - Likely cause: `write_subkey_list` computes a new cell size from
     `LIST_ENTRIES + entries.len()*entry_size` and refuses when that is smaller
     than some minimum or smaller than the old allocated cell (an in-place shrink
     guard). A real BCD template has an lf list whose compacted size falls below
     that guard after removing template elements.
   - Reproduce against the real captured template:
     `/tmp/opencode/tmpl/BCD-Template` (the ignored test
     `real_template_builds_both_variants` / `RUFUS_TEST_BCD_TEMPLATE` exercises it,
     but note: the unit-test path passed while the real write failed — so the
     reproduction must use the real template, not `template_fixture()`).

2. **Fix via coder → reviewer**, one slice at a time, tagged `Slice N/M`:
   - Hand coder the exact diagnosis, scope (regf.rs `remove_child` / shrink path),
     and acceptance: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
     `cargo test -p rufus-core` green, AND a real-template reproduction that no
     longer errors at 0x6d80. Coder does NOT commit/push.
   - Hand the result to reviewer (review structure + security, commit only, never push).
   - If reviewer reports blockers, send back to coder; only proceed when clean.

3. **Rebuild the image** after the fix:
   - Unmount `/dev/loop1p3` (`sudo umount /run/media/hosi/05E8320825D489D2`) and any
     `/mnt/esp2`, then `sudo -n losetup -d /dev/loop1`.
   - Re-attach: `sudo -n losetup -P /dev/loop1 /home/hosi/.cache/rscratch/wintogo.img`.
   - Rebuild release binary: `export PATH="$HOME/.cargo/bin:$PATH" && cd /home/hosi/dev/REA-Rufus/furus && cargo build --release -p rufus-cli`.
   - Write: `cd /home/hosi/dev/REA-Rufus/furus && sudo -n systemd-inhibit --what=sleep:idle --mode=block ./target/release/rufus write --plan /tmp/opencode/wtg-plan.json --yes > /tmp/opencode/write5.log 2>&1`
     — **run this with NO tool timeout** (background, no `timeout` field); the full
     non-quick surface zero takes ~12 min. Confirm "bootloader" step completes with
     no "cannot shrink" error.

4. **Detach loop1** before boot test: unmount p3 + esp2, `sudo -n losetup -d /dev/loop1`.

5. **Boot test** with `/tmp/opencode/boot-wintogo-4g.sh`:
   - `cp /usr/share/edk2/x64/OVMF_VARS.4m.fd /tmp/opencode/OVMF_VARS.fd`
   - `pkill -x qemu-system-x86_64` (only that exact name)
   - `setsid nohup /tmp/opencode/boot-wintogo-4g.sh > /tmp/opencode/qemu5.log 2>&1 &`
   - after ~55 s: `printf 'screendump /tmp/opencode/screen5.ppm\n' | socat -t 3 - UNIX-CONNECT:/tmp/opencode/qemu-mon.sock`
   - `convert /tmp/opencode/screen5.ppm -resize 200% /tmp/opencode/screen5.png`
   - `tesseract /tmp/opencode/screen5.png stdout` — PASS = "Starting services"/"Getting ready" (OOBE); FAIL = `0xc0000001`.
   - Note: QEMU exits on its own with `-no-reboot` after a guest reboot; take the
     screenshot while it is still running. This model cannot view images directly
     (no image input) — rely on `tesseract` OCR and `magick`/`convert` color histogram.

6. **Slice 4/4 (docs)** once boot passes: update `furus/TECHNICAL.md` with the full
   root-cause record and the corrected statement (TECHNICAL.md:84 currently wrongly
   claims "16 vs 16 objects identical with zero element discrepancies" vs bcdboot —
   contradicted by the resume + strip fixes). Rewrite/remove stale `furus/HANDOFF.md`
   and this handoff when done.

7. **Ask the user for push permission** (via `notify-telegram` AND the `question` tool)
   before invoking `publisher`. Only after explicit permission may `publisher` commit
   docs and push. Nothing has been pushed.

## Standing rules (binding)
- All code changes go through `coder` then `reviewer`, one command/slice at a time,
  tagged `Slice N/M` (restate the tag if the plan changes).
- `coder` never commits/pushes; `reviewer` commits but never pushes; `publisher`
  only with explicit user permission.
- Diagnose before coding. A "X doesn't work" report means: inspect + reproduce,
  state root cause, plan, then implement.
- Questions to the user go via `notify-telegram` AND the `question` tool.
- Model fallback: one retry, then switch the failing subagent's model line in
  `~/.config/opencode/agents/<agent>.md` to `opencode/deepseek-v4.1-flash-free#high`
  and tell the user.

## Tooling gotchas
- `export PATH="$HOME/.cargo/bin:$PATH"`; build with `cargo build --release -p rufus-cli`
  (not `-p rufus`); crate is `furus/crates/rufus-core`.
- No `xxd` — use `od -A x -t x1z`.
- Python must run from `/home/hosi` (stray `/tmp/opencode/struct.py` shadows stdlib).
- `losetup -P` mandatory; unmount all loop1 partitions before detach.
- Use `sudo -n systemd-inhibit --what=sleep:idle --mode=block` around rufus write.
- QEMU screenshot: HMP monitor socket `/tmp/opencode/qemu-mon.sock` via socat.
- PE tooling if needed: `/tmp/opencode/pe-start.sh`, `/home/hosi/sendtype.py` (sendkey
  shift-f10, type with `python3 /home/hosi/sendtype.py '<text>'`).

## Key artifacts
- `furus/crates/rufus-core/src/windows/regf.rs` — `remove_child` (~1836), `write_subkey_list`, `list_insert` (~1679), `free_cell` (~1181). **Fix target.**
- `furus/crates/rufus-core/src/windows/bcd.rs` — `build_store`, strip step, resume wiring.
- `/tmp/opencode/write4.log` — the failing write log ("cannot shrink" at 0x6d80).
- `/tmp/opencode/tmpl/BCD-Template` — real captured template for reproduction.
- `/tmp/opencode/bcd_new` + `/tmp/opencode/bcd_new.txt` — known-good bcdboot store/dump.
- `/tmp/opencode/wtg-plan.json` — acceptance write plan.
- `/tmp/opencode/boot-wintogo-4g.sh`, OVMF files, `/tmp/opencode/qemu-mon.sock`.
