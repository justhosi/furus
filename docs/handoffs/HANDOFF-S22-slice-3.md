# Handoff — S22 Slice 3/5 (S22-T1: dynamic BCD locale + template object-type fallback)

## Status
Committed as `2eeb142` — `feat: resolve the BCD locale dynamically and find template objects by type` (3 files: `windows/{bcd,boot_files,to_go}.rs`). NOT pushed.

Review round 1 found a BLOCKER (unbounded loop over unvalidated hive subkey count in `find_template_object`) plus several should-fixes; sent back to coder on the same slice. Coder applied all fixes but hit its step limit before verification. Main session then fixed three unverified test bugs (see below) and verified all gates green. Re-review passed: the forged-count guard, decoy-skip predicate, symlink checks, stale-doc refresh and non-tautological precedence tests were all confirmed; sabotage-style checks proved the tests detect regressions.

Reviewer's should-fixes also include: stale module docs still claiming hardcoded `en-us`; type-scan picking the byte-wise smallest candidate without checking whether it can pass build validation; `boot_files` symlink invariant stated more broadly than enforced; missing tests for resume fallback, preserved error strings, BIOS store parsing in the to_go e2e test, and "tree beats template" precedence. All fixed and verified in re-review. Reviewer decided verbatim locale (e.g. `de-DE`, `en-US`) is acceptable — recorded in slice 5 docs; do not normalize.

Non-blocking reviewer nits: `.mui` detection is name-only (doc wording slightly overstates); `TECHNICAL.md:83` stale `en-us` line fixed in slice 5; filler assertion in the dangling-resume test; forged-count test pins only `InvalidInput`, not the specific message.

## Scope
Only three source files:
- `crates/furus-core/src/windows/bcd.rs`
- `crates/furus-core/src/windows/boot_files.rs`
- `crates/furus-core/src/windows/to_go.rs`

The untracked handoff docs for slices 1–2 are NOT part of this slice's commit.

## What was implemented
### bcd.rs
- `use std::borrow::Cow`; new constants `OBJECT_TYPE_OS_LOADER = 0x10200003`, `OBJECT_TYPE_RESUME = 0x10200004`.
- `pub(crate) fn is_valid_locale_tag(&str) -> bool` — 2–3 ASCII letters, then zero or more groups of `-` + 2–8 ASCII alphanumerics; no regex, no new dependency. Shared with `boot_files`.
- `find_template_object(hive, objects, fixed_guid, object_type)` — tries the fixed template GUID first, then scans `Objects/*` for a matching `Description\Type` REG_DWORD (`0x10200003` OS loader, `0x10200004` resume). Byte-wise smallest matching key name wins; malformed siblings are skipped non-fatally; original missing-object error strings preserved. Used for both loader and resume (resume keyed off loader's `23000003` value).
- `locale_from_elements`, `locale_from_hive` (bootmgr → UEFI loader → BIOS loader), public `locale_in_template(&[u8]) -> Option<String>` (best effort, never errors).
- `build_with_locale(template, request, locale)`; `build()` now delegates with `None`. Supplied locale validated before any parse/mutation (invalid → `InvalidInput` naming the value). Effective locale = supplied → template → `"en-us"`, carried in a `Cow` and written to all four `ELEMENT_LOCALE` sites.
- Four new tests: valid/invalid `locale_in_template`; all-four write plus `build()` default/template behaviour; invalid-locale refusal; custom-GUID template resolved by type fallback (fresh default GUIDs still carry `12000004`, `11000001`, `21000001`). Fresh output GUID literals unchanged.

### boot_files.rs
- Imports `is_valid_locale_tag`.
- `pub fn locale_from_tree(&Path) -> Option<String>` — scans `Windows/Boot/EFI/<locale>/*` for case-insensitive `.mui` entries, skips symlinks via `symlink_metadata`, validates tags, returns byte-wise smallest, `None` for missing/unreadable trees. Module docs plus four tests (de-DE; ja-JP+de-DE determinism with uppercase `.mui`; no-mui/malformed/missing; symlinked dir/entry).

### to_go.rs
- `install()` detects `locale = boot_files::locale_from_tree(&data_root).or_else(|| bcd::locale_in_template(&template))` after reading the template, and passes it to `bcd::build_with_locale` for both UEFI and BIOS stores. Docs updated. Added one e2e test reusing `template_fixture` / `system_fixture_with_sanpolicy` / `FakeMount`: a de-DE `.mui` tree yields de-DE in all four locale elements of the ESP store.

## Decisions / gotchas
- The locale is written verbatim: a template carrying `"en-US"` now writes `"en-US"` rather than the old lowercase `"en-us"`. Absent or invalid template locale still yields `"en-us"`. Spec says write the detected locale with `en-us` fallback, so this is expected to be acceptable; confirm in review.
- Fallback uses the `Description\Type` REG_DWORD bitmask, not GUID string matching; malformed sibling objects are ignored so one bad object cannot break store construction.
- No unsafe code, no async, no new dependencies, no change to fresh output GUIDs.

## Round-2 fixes (coder, then main session)
Coder (edits unverified): guarded `find_template_object` with a one-time `list_head`/`count == nsub` check and `break` on list errors; added an `accept` predicate so the type-scan keeps only candidates passing the build's `22000002`/`42000002`/`Elements` checks; refreshed stale `en-us` docs and comments; added provenance comments for the type constants plus a real-template check in the ignored test; added the `{memdiag}` locale comment; `locale_from_tree` now `symlink_metadata`-checks `Windows`/`Windows/Boot`/`EFI`; extended tests (decoy skip, dangling-resume fallback, pinned error strings, forged count, symlinked components, to_go both stores with fr-FR template).

Main session fixed three unverified test bugs:
- `bcd.rs` test used `assert_eq!` on `find_template_object`'s `Result<Option<usize>, CoreError>` (CoreError lacks `PartialEq`) → changed to `matches!(.., Ok(None))`.
- `type_fallback_skips_unusable_loader_candidates` asserted the fresh loader carries `ELEMENT_LOADER_PATH` (0x42000002), but the fresh loader only carries `ELEMENT_PATH` (0x12000002) → assert `ELEMENT_PATH` and its `winload_full_path(Uefi)` value.
- `build_pins_missing_loader_and_resume_messages` expected error strings lacked the `invalid input: ` prefix added by `CoreError`'s thiserror Display → added the prefix.
- `to_go.rs` BIOS store path was `data/boot/bcd` (lowercase), not `data/boot/BCD` → fixed.

## Verification (main session; reviewer to re-run)
- `cargo fmt --all -- --check` → 0
- `cargo clippy -p furus-core --all-targets -- -D warnings` → 0
- `cargo test -p furus-core --lib windows::` → 106 passed, 0 failed, 5 ignored
- `cargo test -p furus-core windows::` (all targets) → 0 failures
- targeted `objects_count_mismatch_refuses_promptly` → 1 passed in 0.00s (no hang)

## Next steps
1. Reviewer verifies non-tautology, preserved error strings, unchanged fresh GUIDs, no unsafe/deps, and commits only the three source files.
2. Slice 4/5: S22-T4 deterministic 500+ sequence randomized regf hive mutation property test in `crates/furus-core/src/windows/regf.rs` (reparse + header checksum + `check_bins` after every step), fix any real bugs found.
3. Slice 5/5: TECHNICAL.md/DECISIONS.md updates, commit all handoff docs, `cargo xtask size --write-baseline`, full `cargo xtask ci`, then request explicit user permission before any publish.
