# HANDOFF — S21 Slice 2/4: Legacy BIOS BCD parity unit test

## Status
Committed locally as `5b9e585` (`test: assert BIOS BCD parity with the UEFI store`).
Only `crates/rufus-core/src/windows/bcd.rs` changed (+141 lines, test module only).
NOT pushed. (Pushing requires explicit user permission — Publisher's job.)

## What was done
- Extended the pre-existing `bios_bcd_has_parity_with_uefi_bcd` test.
- Added the missing `ELEMENT_OS_DEVICE` (`0x21000001`) assertion on the BIOS loader; device checks now loop over `[ELEMENT_DEVICE, ELEMENT_OS_DEVICE]` against `partition_device(data)`.
- Built a genuine UEFI comparison store from `StoreRequest { firmware: Firmware::Uefi, ..request }` — identical `identity`, `esp_identity`, `description`; only `firmware` differs. `StoreRequest` is `Copy`.
- Asserts the three spec-required loader elements (`11000001`, `21000001`, `12000004`) and the decoded description value agree between BIOS and UEFI.
- Kept distinct-GUID assertions (`OS_LOADER_BIOS`/`RESUME_BIOS` vs UEFI `...123456` variants), `{bootmgr}` `11000001` + `23000003`, class-0x4 stripping, and resume-device checks.
- No production code changed; no new dependencies; no `unsafe`.

## Decisions / gotchas
- "Required element parity" is deliberately limited to the three loader elements the spec names (`11000001`, `21000001`, `12000004`). A full element-ID-set comparison would be wrong: the BIOS and UEFI template loaders inherit different elements (e.g. `16000060` only on the UEFI-derived loader). That is existing, correct builder behaviour, not a bug.
- Reviewer proof of non-tautology (temporary mutations, file restored byte-exact afterwards, sha1 verified): changing the expected description or zeroing the disk signature in `expected_device` makes the test fail.
- Two review nits left as-is on purpose: constant-level distinct-GUID assertions duplicate other tests but document which GUID the hive reads use; the "Class-0x4 stripped on both" doc comment overstates what this test inspects (the fresh key has no class-0x4 element to strip; the in-place strip is covered by `template_class_elements_are_stripped_from_boot_path`). Both are harmless.

## Verification
- `cargo fmt --all -- --check` → 0
- `cargo clippy -p rufus-core --all-targets -- -D warnings` → 0
- `cargo test -p rufus-core --lib` → 1276 passed, 0 failed, 6 ignored
- `cargo test ... windows::bcd::tests::bios_bcd_has_parity_with_uefi_bcd --exact` → 1 passed

## Next steps
- Slice 3/4: documentation reconciliation and handoff archiving (committed as `d1338eb`).
- Slice 4/4: `cargo xtask size --write-baseline`, then full `cargo xtask ci`, commit `size-baseline.json`.
