# Handoff — S22 Slice 1/5 (S22-T3): `wimlib-sys` strict-link feature

## Status
Committed as `d2eb819` (`feat: gate wimlib-sys linking with an opt-in strict-link feature`).
NOT pushed (Publisher step, requires explicit user permission).

## What was done
- `crates/wimlib-sys/Cargo.toml`: added `[features] strict-link = []`, no dependencies and no `default` key, so default builds are unchanged.
- `crates/wimlib-sys/src/lib.rs`: added module-doc paragraph for the feature and a module-scope guard:
  `#[cfg(all(feature = "strict-link", not(wimlib_present)))] compile_error!(...)`.
  The message tells the user to install `libwim-dev`, set `WIMLIB_LIB_DIR`, or disable `strict-link`, and notes that `WIMLIB_SYS_FORCE_UNLINKED` also trips the guard.
- `build.rs` untouched: graceful probe still never fails the build and still declares `cfg(wimlib_present)`.

## Decisions / gotchas
- Opt-in, default-off is deliberate: the workspace must keep building on hosts without `libwim-dev`.
- `WIMLIB_SYS_FORCE_UNLINKED=1` is treated as an absent library, so under `strict-link` it correctly fails compilation.
- Exactly two `#[allow(unsafe_code)]` sites remain (`src/ffi.rs`, `src/safe/bound.rs`); no unsafe added.
- `TECHNICAL.md` was NOT updated in this slice (out of commit scope); it is queued for the final docs slice.

## Verification (all passed)
- `cargo fmt --all -- --check` → 0
- `cargo clippy -p wimlib-sys --all-targets -- -D warnings` → 0 (also with `--features strict-link`)
- `cargo test -p wimlib-sys` → 0, 21 tests
- `cargo check -p wimlib-sys --features strict-link` → 0 (host has libwim)
- Negative: `WIMLIB_SYS_FORCE_UNLINKED=1 cargo check -p wimlib-sys --features strict-link` → 101 with the expected `compile_error!` text (expected failure)
- `WIMLIB_SYS_FORCE_UNLINKED=1 cargo check -p wimlib-sys` → 0 (graceful path preserved)
- `cargo check --workspace` → 0

## Remaining / exact next steps
1. Slice 2/5 (S22-T2): add `max(64 MiB, required/50)` NTFS overhead reserve to both pre-flight paths in `crates/furus-core/src/windows/apply.rs`, with exact-fit / under-margin / ample-space unit tests. One command to coder, then reviewer.
2. Slice 3/5 (S22-T1): dynamic locale + template GUID fallback.
3. Slice 4/5 (S22-T4): regf property tests.
4. Slice 5/5: docs, size baseline, full `cargo xtask ci`, then ask the user before publishing.

## Acceptance criteria still open
- All S22 verification commands must exit 0: `cargo test -p furus-core windows::`, `cargo test -p wimlib-sys`, `cargo xtask size --write-baseline`, `cargo xtask ci`.
- No unsafe in `furus-core`, no new dependencies, no async runtime.
