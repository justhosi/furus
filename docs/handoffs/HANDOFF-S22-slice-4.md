# Handoff — S22 Slice 4/5 (S22-T4: deterministic regf mutation property test)

## Status
Committed as `2279698` — `test: check 10k randomized regf mutations against a shadow model`. Pushed: no (Publisher step, requires explicit user permission).

## Scope
Only `crates/furus-core/src/windows/regf.rs` — the `#[cfg(test)] mod tests` block (1 import line + ~479 new lines). Zero production-code changes. The untracked handoff docs for slices 1–3 are NOT part of this slice's commit.

## What was implemented
- `Rng`: local xorshift64* PRNG with a fixed seed `0x243F_6A88_85A3_08D3` — no dependencies, no entropy, identical sequence every run.
- `two_bin_hive()`: synthetic 2-bin `ROOT` hive fixture (same shape as the existing tests) so cross-bin allocation is exercised from the start.
- `Shadow` model (`BTreeSet`/`BTreeMap`) plus `verify()`: after every mutation step it does `update_checksum()` → `to_bytes()` → `Hive::parse()` → explicit `check_bins()` → stored-vs-computed header checksum assert → idempotent re-parse. It then checks `find_child`, `find_value`, `read_value`, `element_value` and the exact child/value sets on the **reparsed** hive against the shadow, so silent corruption is caught.
- `prop_hive_mutations()`: 500 sequences × 20 randomized ops = **10 000 verified steps** (plus setup and churn drain/refill). Operations: root and nested `add_child_key` (with `Some(model)` and `None`), `set_element` with payloads 4 B–4056 B, `set_value` overwrites, `remove_child` on element subkeys and real keys (correct bool asserts, absent-key no-ops), explicit `append_hbin()`, and a deterministic shrink-to-zero-then-reinsert on a churn subkey list.
- No production fix was needed; four alternate seeds also passed. No focused regression test required.

## Decision / gotcha — 16 KiB payload deviation
The spec asked for payload sizes 4 B – 16 KiB. This regf editor's `alloc()` (regf.rs:921-935) refuses any cell larger than `HBIN_USABLE` (4064 B), and cells cannot span `hbin` pages; appending bins does not lift the per-cell cap. A single 16 KiB value would require implementing registry big-data (`db`) cells — out of scope for a property test. The test therefore uses the allocator's real range 4 B – 4056 B (biased toward near-page-size payloads) and forces cross-bin growth with many large values plus `append_hbin()`: the fixed seed reaches 8 `hbin` bins (10 with an alternate seed). Reviewer must confirm this is an acceptable documented deviation.

## Verification (coder; reviewer to re-run)
- `cargo fmt --all -- --check` → 0
- `cargo clippy -p furus-core --all-targets -- -D warnings` → 0
- `cargo test -p furus-core --lib windows::regf` → 3 passed, 0 failed (`prop_hive_mutations` 1.2–1.6 s; ~6.1 s including compile)
- Determinism: two identical runs both reported `500 sequences, 10000 verified steps, max 8 hbin bins`.

## Reviewer decision on the 16 KiB deviation
Accepted as an acceptable, documented deviation — not a blocker, no escalation. Verified against `alloc()` (regf.rs:921-935): `cell_total(body) = round8(body + 4)`, refuses any `total > HBIN_USABLE` (4064); `take_free` stays within one bin and `check_bins` rejects cell overruns, so cells cannot span pages. There is no `db` big-data path, so a 16 KiB single value would require new production parser+writer support — out of scope for a test-only slice. The spec's intent (stress allocation across hbin boundaries) is met by 4–4056 B payloads biased near page size, explicit `append_hbin()`, and 8 bins reached on the fixed seed.

## Non-blocking reviewer nits (not fixed)
- regf.rs:2321-2326 comment says 4056 B is the largest payload; the true ceiling is 4060 (`round8(4060+4) = 4064`). `MAX_PAYLOAD = HBIN_USABLE - 8` is a conservative 4-byte margin; wording is off by one granule.
- regf.rs:2770-2774: `max_bins` is only `eprintln!`-ed, not asserted; an `assert!(max_bins > 2, ...)` would pin cross-bin coverage.
- regf.rs:2477: "idempotent round-trip" re-parses but does not compare the second `to_bytes()` to the first.
- regf.rs:2651-2665: op 5 hand-rolls a 4–8 B payload instead of calling `payload()`.
- Pre-existing, out of scope: `remove_child` frees only the child `nk` cell, not its `vk`/data cells; the test correctly does not assert leak-freedom.

## Reviewer verification
Sabotage test: removing one `shadow.values.insert` line made the test fail on the first sequence (silent data loss detected); file restored and `sha256sum -c` OK before commit. Determinism: two runs both `500 sequences, 10000 verified steps, max 8 hbin bins` (3 passed, ~1.25 s). Zero `unsafe`, zero new deps, zero production changes (diff 480/0, test module only).

## Next steps
1. Reviewer decides on the 16 KiB deviation, verifies determinism/non-tautology, and commits only `regf.rs`.
2. Slice 5/5: update `TECHNICAL.md` (incl. the stale `en-us` line at :83) and `DECISIONS.md` for strict-link, locale discovery, apply reserve and property tests; commit all handoff docs; `cargo xtask size --write-baseline`; full `cargo xtask ci`; then request explicit user permission before any publish.
