# Handoff — S21 Slice 1/4 (NTFS post-format VBR `HiddenSectors`) — DONE

Status: **committed** as `aa8faf1` (`feat: patch the NTFS VBR HiddenSectors field after mkntfs`). Not pushed.

## What was done

`crates/furus-core/src/fs/ntfs.rs` now guarantees the primary NTFS VBR's BPB `HiddenSectors` field (u32 LE at offset `0x1C..0x20`) equals the planned partition start LBA, even when `mkntfs` silently ignores its `-p` geometry flag:

- Public `patch_hidden_sectors(target, start_lba)` reads the 4-byte field, writes `start_lba` only when it differs, and reads back to confirm. No-ops for `None` or an already-correct value. Opens its own read+write handle; all I/O errors name `target`.
- Called from `format_with()` **after** `boot_sector(&read_vbr(target)?)?`, so only a VBR already verified as NTFS is patched.
- Module-header "deferred S21 VBR hook" note removed and replaced with the new guarantee.
- Tests (4): patch-from-zero on a synthetic 512-byte VBR (whole-file "only 0x1C..0x20 changed" check), no-op when already correct, no-op when `None`, short-target I/O failure, plus an end-to-end assertion in `format_passes_partition_geometry` that the call site actually patches `239616`.

## Decisions / gotchas

- Backup/alternate boot sector is **intentionally not patched** (out of scope; `HANDOFF.md` recorded `ntfsfix` rewriting it). Windows reads the primary only, so the boot guarantee holds. Revisit only if a recovery-from-backup case appears.
- Optional nit left: `format()`'s doc step list (near `:364-374`) still omits the patch step; module header documents it. Fold into the docs slice if convenient.

## Verification

- `cargo fmt --all -- --check` → 0
- `cargo clippy -p furus-core --all-targets -- -D warnings` → 0
- `cargo test -p furus-core --lib` → 1276 passed, 0 failed, 6 ignored

## Next

Slice 2/4: BIOS BCD parity unit test in `crates/furus-core/src/windows/bcd.rs` (uncommitted change already in tree). Then Slice 3/4 docs, Slice 4/4 baseline + full CI. Do not push without the user's explicit permission.
