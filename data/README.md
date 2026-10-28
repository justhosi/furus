# data/

Function-parity ledger for the rewrite (2,709 analysed functions, one row each).

* `functions.csv` — copied from `example/functions.csv`: the raw RE output
  (`address,name,size,kind,module,calls_out,calls_in,strings`).
* `parity.csv` — copied from `rust-rewrite/parity.csv`: every function with
  exactly one disposition (`port`, `c-ffi`, `crate`, `system-tool`,
  `replace`, `thunk`) plus the owning slice. Regenerate with
  `cargo xtask parity --regenerate` (runs `tools/parity.py`, which reads
  `data/functions.csv` and writes `data/parity.csv`); row counts and the
  address-set match are enforced by `cargo xtask parity`.
