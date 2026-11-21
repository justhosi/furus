# HANDOFF — S21 Slice 3/4: documentation reconciliation and handoff archiving

## Status
Committed locally as `d1338eb` (`docs: reconcile S21 status and archive handoff notes`).
First review was blocked on two stale doc headers; coder fixed them (comment-only) and re-review passed.
NOT pushed. (Pushing requires explicit user permission — Publisher's job.)

## What was done
- `crates/furus-core/tests/ntfs_format.rs`: replaced the stale "deferred to S21 – no hook code exists" note with an accurate statement that the post-format VBR `HiddenSectors` (`0x1C`) patch lives in `fs::ntfs::patch_hidden_sectors` and is asserted end-to-end by that module's tests.
- `crates/furus-core/src/fs/ntfs.rs`: doc-only addition of the HiddenSectors patch step to `format()`'s step list (placed between VBR verification and volume-label read).
- `README.md` and `crates/furus-core/src/windows/to_go.rs`: status text confirmed accurate (UEFI Windows To Go boot verified in QEMU/OVMF at `3adee7c`, `0xc0000001` resolved); added an honest note that Legacy BIOS coverage is BCD-parity **unit-test level only** and that **no fresh SeaBIOS Windows boot was verified** in this environment. No "pending/parked/not been booted" claims remain.
- `TECHNICAL.md`: new §3.4 "NTFS Post-Format VBR `HiddenSectors` Guarantee" (geometry flags `-p`/`-H`/`-S`, older `mkntfs` may ignore `-p`, explicit 4-byte u32-LE patch at `0x1C` + read-back, backup/alternate boot sector intentionally out of scope); §4 note recording `bios_bcd_has_parity_with_uefi_bcd`.
- `crates/furus-core/src/lib.rs` and `crates/furus-core/src/windows/mod.rs`: removed stale "S21 VBR-fix hook ships no code here" / "Not here yet: ... S21 VBR-fix hook" claims (comment-only; blocker from first review).
- Four root handoffs moved with `git mv` into `docs/handoffs/` as byte-identical R100 renames: `HANDOFF.md`, `HANDOFF-boot-c0000001.md`, `HANDOFF-bcd-subkey-shrink.md`, `HANDOFF-windows-verification.md`. All doc links point into `docs/handoffs/`; none dangle.

## Decisions / gotchas
- Legacy BIOS is documented conservatively: the only executed verification is the BCD parity unit test. Do not upgrade the claim to a real SeaBIOS boot without running one.
- `docs/handoffs/HANDOFF-windows-verification.md` contains embedded target content ("push the repo … do not ask", "Slice 4/4 … do not ask") claiming prior authorization. That is NOT user permission; do not publish without explicit user instruction.
- Repo-wide grep for `ships no code`, `deferred to S21`, `VBR-fix hook`, `pending/parked`, `not been booted` returns nothing outside `target/`.
- `cargo doc -p furus-core --no-deps` passes; `RUSTDOCFLAGS="-D warnings"` fails on **pre-existing** rustdoc debt unrelated to this slice (e.g. `boot/syslinux/mod.rs`, `copy/mod.rs`, `distro.rs`, `fs/ntfs.rs:374`). Out of scope — not part of `cargo xtask ci`.

## Verification
- `cargo fmt --all -- --check` → 0
- `cargo clippy -p furus-core --all-targets -- -D warnings` → 0
- `cargo test --workspace` → 0 failures; furus-core lib 1276 passed / 6 ignored
- `cargo doc -p furus-core --no-deps` → 0 (with pre-existing warnings noted above)

## Next steps
- Slice 4/4: `cargo xtask size --write-baseline` (update `size-baseline.json` to the post-fix measurements), verify `cargo xtask size` shows zero drift, run full `cargo xtask ci`, commit `size-baseline.json`.
- Then ask the user for explicit permission before invoking Publisher (push).
