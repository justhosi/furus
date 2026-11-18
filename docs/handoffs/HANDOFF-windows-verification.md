# Handoff — Windows To Go (S21) verification — COMPLETE

Status: **COMPLETE and verified**. All code/diagnosis work is finished. This file
records the final state for a fresh context; there is no active task except the
final documentation commit and push (Slice 4/4), which the user authorized to
run autonomously ("make all the decisions yourself and at the end push the repo").

Working dir: `/home/hosi/dev/REA-Rufus/furus` (git repo, branch `main`,
origin `https://github.com/justhosi/furus`). At the time of writing, HEAD is
`4d22a12` and the repo is ~14 commits ahead of `origin/main`, NOT yet pushed.
Release binary `target/release/rufus` is built from `4d22a12` (mtime 07:20:26).

## Goal / acceptance

`./target/release/rufus write --plan /tmp/opencode/wtg-plan.json --yes` must
produce an image that boots under QEMU/OVMF past the boot manager with **no
`0xc0000001`** and no manual `bcdedit` / `chkdsk` / `bcdboot` repair.

**Acceptance MET.** The freshly written image's BCD was verified both at the
byte level and at runtime. See "Verification" below.

## Root cause (finally proven)

The generated UEFI BCD's fresh OS-loader object `{3796cdc8-e33b-11f1-b950-525400123456}`
was missing element **`12000004` (the loader description)**. `bcd::build_store`
only writes `12000004` when `request.description` is `Some`, but the sole
production caller in `pipeline/bootloader/windows.rs` hardcoded `description: None`.
A real `bcdboot`-generated store always carries a non-empty `12000004`.

Decisive A/B experiment: taking our own written BCD and adding only `12000004`
made it boot past bootmgr (into a Windows setup screen); taking the known-good
`bcdboot` BCD and removing only `12000004` reproduced the exact `0xc0000001`
failure. Removing the extra `16000009` did NOT help. So `12000004` is the
load-bearing difference, and it was missing from day one.

## Fix commits (in order, all on top of the original `8375c07`)

- `8375c07` — allow subkey lists to retain capacity and reuse in place (regf).
- `44e8062` — wire the resume object like `bcdboot` so the store boots.
- `a3c2154` — strip setup-template elements from the boot store.
- `8e01ab0` — point `{bootmgr}` at the ESP so the UEFI store boots
  (the `{bootmgr}\11000001` ESP device element).
- `296261b` — clone the UEFI BCD loader objects the way `bcdboot` does
  (fresh loader + resume objects with byte-exact bcdboot element sets).
- `4d22a12` — **emit a loader description in the To Go BCD** (the final root-cause
  fix). `pipeline/bootloader/windows.rs` derives the description from the WIM image name
  via `loader_description()` (name → description → `"Windows"` fallback); the
  real image yields `"Windows 11 Enterprise Evaluation"`, so `12000004` is now
  always emitted. A regression test reads the on-disk BCD and asserts the
  loader carries `12000004`; reverting the fix makes it fail.

NOTE: `296261b`'s brief said to remove `{memdiag}\1600000B`, which the reviewer
found contradicts the known-good reference (it HAS that element). Harmless to
boot (`memdiag` only launches from the boot menu); left as-is, not worth a round trip.

## Verification (all passed)

1. **Build/test**: `cargo fmt --all -- --check`, `cargo clippy -p rufus-core
   --all-targets -- -D warnings`, `cargo test -p rufus-core` (1271 lib passed, 0
   failed, 6 ignored; all integration binaries green), `cargo build --release`.
2. **Clean write** (`write11`, quick-format plan
   `/tmp/opencode/wtg-plan.json`, confirm
   `sha256:ef6abda90a0dc578ad26919fa9b3e87477226eb830e65e890629be3d923b03cd`):
   ran to 100%, 152980 entries / 10404700292 bytes, 39 boot files, finalized.
   Quick format was used because full-surface zeroing (~18 min) kept being
   killed by environment restarts; it does not affect BCD correctness.
3. **BCD byte-level**: dumped `/tmp/opencode/bcd_write11` — fresh loader carries
   `12000004 = Windows 11 Enterprise Evaluation`, `12000005 = en-us`, device
   elements match the new GPT layout (disk `DA9ACA5E-875B-4A3A-BF92-91493E6E4EF4`,
   ESP `49778BC8-2344-4F54-996F-164155CCB71D`, data `53A1C805-414A-47F0-80D1-4E7746B52FEA`).
4. **Runtime boot** (`qemu12b`, 20×5 s poll loop in a single tool call): NO
   `0xc0000001` in any poll; boot proceeds past bootmgr into the Windows Setup
   screen — identical to the known-good `bcdboot` BCD control. The remaining
   "Install Windows / installation error" screen is the expected artifact of
   applying an unspecialized `install.wim` (setup-state), NOT a BCD failure, and
   occurs with the known-good control too; out of scope.

## Environment notes / gotchas for any future run

- `/tmp/opencode` was wiped by an 08:00 environment reset; all current artifacts
  there (plan, boot script, OVMF_VARS, logs, BCD copies) were recreated after it.
  The known-good reference BCD survived at `/home/hosi/.cache/rscratch/bcd_good_bcdboot`;
  helper `.py` scripts survive in `/home/hosi`.
- QEMU dies between tool calls, so launch AND poll/screendump in ONE tool call;
  use `printf "screendump /tmp/opencode/sN_%d.ppm\n" "$i"` (double quotes) so
  `$i` expands — single quotes send a literal `$i` to the monitor.
- `pgrep -x qemu-system-x86_64` truncates the 18-char name → false "EXITED";
  use `pgrep -af 'qemu-system-x86_64 -machine q35' | grep -v 'bash -c'`.
  A stale QEMU can hold the image write-lock ("Failed to get write lock").
- `kill -0` on a root-owned PID returns EPERM (looks like "exited"); use `pgrep -f`.
  `losetup -d` reports success but udisks re-attaches `loop1`.
- FAT32 ESP can get dirty after a hard QEMU quit → `fsck.vfat -n` before rw mount.

## Slice 4/4 — remaining (docs + push, do not ask)

1. Rewrite this handoff (done) and update `TECHNICAL.md`: fix stale §2.2/3.1/4
   and the false §84 "16 vs 16 objects identical" claim (store now has 18
   objects including the two retained inactive template loaders and the fresh
   loader/resume pair); reconcile the §4 contradiction with
   `HANDOFF-boot-c0000001.md` §4 (bcdboot-regenerated BCD boots past bootmgr).
2. Clean up any stray `BOOTX64.EFI.hidden` on the ESP, if present.
3. Stage all 4 `HANDOFF*.md` files + `TECHNICAL.md`; commit docs.
4. `git push origin main` (~14 commits). Verify with `git status` / `git log`.
