# Handoff — S22 Slice 2/5 (S22-T2): WIM pre-flight NTFS overhead reserve

## Status
Committed as `2f7889a` (`feat: reserve NTFS overhead in the WIM apply pre-flight`).
One file: `crates/rufus-core/src/windows/apply.rs` (+279/−10). NOT pushed.

## What was done
- Added private `required_with_ntfs_overhead(required: u64) -> u64` = `required.saturating_add(max(64 * 1024 * 1024, required / 50))` — 64 MiB floor or 2% slack, whichever is larger, plus the payload total; saturating, no panic path.
- Applied to both pre-flight sites: `apply()` against `mounted.free_bytes()`, `apply_ntfs()` against `capacity`. Refuse when `available < need`.
- `CoreError::InvalidInput` preserved; error text still contains the raw uncompressed total, the available bytes, and `"refusing before any write"`, and now also reports `need` and the reserve.
- Module doc step c and both function docs explain the formula and that it is deliberately conservative.
- Added 9 unit tests: helper at the 64 MiB floor (incl. just below crossover), 2% branch at/above the 3.2 GiB crossover, saturation at `u64::MAX`; path-level exact-fit / under-margin (`need - 1`) / ample-space for both `apply` and `apply_ntfs`. Exact-fit and ample tests use a pre-set cancellation probe so they assert `CoreError::Cancelled` from pre-flight, never extraction.

## Decisions / gotchas
- The reserve is intentionally conservative (spec-mandated) and can reject a target that would technically fit.
- `apply_ntfs`'s capacity comes from `data_window` (whole remaining disk), so this does not reject genuine installs.
- Reviewer nits, not fixed: `reserve = need.saturating_sub(want)` understates the true reserve only near `u64::MAX` where nothing can pass anyway; `saturating_div(50)` is equivalent to `/ 50`.
- Pre-existing untracked `docs/handoffs/HANDOFF-S22-slice-1.md` deliberately left out of this commit.

## Verification (all passed)
- `cargo fmt --all -- --check` → 0 (no other files reformatted)
- `cargo clippy -p rufus-core --all-targets -- -D warnings` → 0
- `cargo test -p rufus-core --lib windows::apply` → 19 passed, 0 failed
- `cargo test --workspace` → green (rufus-core lib 1285 passed / 6 ignored; all other suites green)

## Remaining / exact next steps
1. Slice 3/5 (S22-T1): dynamic locale discovery in `bcd.rs`/`boot_files.rs`, template `Description\Type` fallback resolver, `to_go.rs` wiring, de-DE/custom-GUID tests.
2. Slice 4/5 (S22-T4): deterministic 500+ sequence regf property tests.
3. Slice 5/5: docs, size baseline, full CI gate, then ask before publishing.

## Acceptance criteria still open
- `cargo test -p rufus-core windows::`, `cargo test -p wimlib-sys`, `cargo xtask size --write-baseline`, `cargo xtask ci` all exit 0.
- No unsafe in core, no new dependencies, no async runtime.
