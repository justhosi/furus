# S29 — single-source the D-Bus / polkit / packaging contract (slice 1/4)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc 1.99.0 lives
in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

S29 has four slices. This file is the handoff after **slice 1/4**. Slices are
gated one at a time (one command → reviewer → next command); do not batch them.

## Diagnosis (established before this slice)

The D-Bus / polkit / packaging identifiers already MATCH. The bug class is that
the literal strings were duplicated in the GUI, the helper and packaging with
no automated enforcement, so they could drift silently. Slice 1 removes the
duplication and adds a CI gate that fails on drift. No runtime behaviour or
wire format changes.

## Slice 1/4 — status: DONE (not committed, not pushed)

### What changed

1. **NEW `crates/rufus-proto/src/service.rs`** — the single source of truth.
   Ten `pub const &str` values with doc comments: `BUS_NAME`, `OBJECT_PATH`,
   `INTERFACE_NAME`, `POLKIT_ACTION`, `ERROR_NOT_AUTHORIZED`, `ERROR_BUSY`,
   `ERROR_INVALID_PLAN`, `ERROR_UNKNOWN_SESSION`, `HELPER_BIN_PATH`
   (`/usr/libexec/rufus-helper`), `HELPER_DBUS_ARG` (`--dbus`). Values are
   byte-identical to the old literals. Declarations keep the exact spelling
   `pub const NAME: &str = "...";` because xtask scans for it.
2. **`crates/rufus-proto/src/lib.rs`** — `pub mod service;` plus
   `pub use service::{...}` re-exporting all ten constants so Rust consumers
   write `rufus_proto::BUS_NAME` etc.
3. **`crates/rufus-gui/src/ipc/dbus.rs`** — the seven private `const` literals
   are gone; the values are imported from `rufus_proto`. Local `UNKNOWN_TOTAL`
   and all behaviour/tests are unchanged.
4. **`crates/rufus-helper/src/dbus.rs`** — the existing `pub const` API
   (`BUS_NAME`, `OBJECT_PATH`, `POLKIT_ACTION`, `ERROR_*`, `INTERFACE_NAME`) is
   preserved as thin aliases (`pub const X: &str = service::X;`), so `main.rs`
   and the tests need no edits. The
   `#[zbus::interface(name = "org.rufuslinux.Helper1")]` literal was
   deliberately NOT changed (the macro needs a literal); the gate reads it
   from source and compares it to `INTERFACE_NAME`.
5. **`xtask/src/main.rs`** — new `cmd_contract(root: &Path) -> Result<()>` and
   small scanning helpers, wired into `cmd_ci` as `==> contract --check`
   between `parity --check` and `size`. Prints `PASS`/file:line errors. Also
   adds two unit tests (`contract_check_passes_for_the_repository`,
   `contract_const_reads_the_single_source_declarations`).
6. **NEW `docs/handoffs/HANDOFF-S29.md`** — this file.

No new dependencies, no async runtime, no root-requiring tests. The existing
xtask `dist` validators (lines ~692-693) still hardcode `BUS_NAME` /
`POLKIT_ACTION`; they were left alone as out of scope. The new gate parses the
single-source file directly, so it does not share those duplicates.

### Decisions / gotchas

- **xtask has no `rufus-proto` dependency**, and `xtask/Cargo.toml` is NOT in
  this slice's allowed-file list. Rather than add a dependency, `cmd_contract`
  reads the literal values out of `crates/rufus-proto/src/service.rs` with
  simple string scanning. This keeps the gate dependency-free and still
  validates packaging against the one definition. Keep the const declaration
  spelling stable.
- **Negative-scan exception:** `packaging/README.md` deliberately discusses the
  rejected `org.rufus.*` namespace in prose (lines 8/10/15). The literal
  `"org.rufus."` scan would false-positive there, so the gate skips exactly
  `README.md` while scanning every other file under `packaging/` plus the two
  D-Bus source files. Do not put a real `org.rufus.` identifier in a package
  data file.
- The scan also rejects `/usr/lib/rufus/rufus-helper` everywhere it looks.

### Verification (run this slice)

```
export PATH="$HOME/.cargo/bin:$PATH"
cargo xtask ci
```
Expected exit 0; `cargo-audit` is absent locally so xtask prints SKIP. The gate
prints `==> contract --check` followed by PASS lines and the final
`contract: all identifiers match the single source of truth`. If it fails, fix
the checker (not the data) unless a real mismatch exists.

## Slice 2/4 — exact next steps (offscreen Slint render test)

NOT STARTED. This slice must be opened as its own gated command and reviewed
separately. Goal: prove the GUI renders offscreen (no display server) without
root. Before editing, inspect `crates/rufus-gui/src` (the Slint `.slint` files,
the `main`/window setup, and how the backend/renderer is selected) and the
existing GUI tests. Confirm the Slint backend/renderer used in tests and what
`cargo xtask ci` runs, then design a test that loads the component with the
software renderer and no window system, asserting only what is deterministic
offscreen (component instantiates, initial text/state, no panic). Keep the
test unprivileged and headless; do not relax lints or change CI workflow. Scope
files to whatever that slice's command names; write a fresh
`HANDOFF-S29-slice-2.md` (or update this file) at its end, and report the exact
verification command/output. Do not commit or push.
