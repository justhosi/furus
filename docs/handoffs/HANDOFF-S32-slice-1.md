# S32 Slice 1/4 — Native XDG desktop portal file picker (module)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc live in
`~/.cargo/bin`; prefix cargo commands with `export PATH="$HOME/.cargo/bin:$PATH"`.

Commit: `fafb7a5 feat(gui): add native XDG desktop portal file picker`
(reviewer-approved, `Reviewed-by: reviewer` trailer). Nothing pushed.

## What landed

- New `crates/furus-gui/src/picker.rs`; `pub mod picker;` added to
  `crates/furus-gui/src/lib.rs`.
- Public API:
  - `enum PickerOutcome { Selected(PathBuf), Cancelled, Unavailable(String) }`
    (`Debug, Clone, PartialEq, Eq`) with `falls_through()`.
  - `pub fn pick_image_path() -> PickerOutcome` =
    `resolve_chain(pick_via_xdg_portal(), pick_via_fallbacks)`.
- `pick_via_xdg_portal()` performs a single `zbus::block_on(portal_open())`.
  `portal_open()` connects with `zbus::blocking`-style semantics expressed via
  `Connection::session()` (see decision below), builds the handle token
  `furus_open_<pid>_<AtomicU64 counter>`, computes the request object path,
  creates a `Request` proxy and subscribes to `Response` **before** calling
  `org.freedesktop.portal.FileChooser.OpenFile`, then awaits the signal with
  `poll_fn(Stream::poll_next)` and decodes `(u32, HashMap<String, OwnedVariant>)`.
  Response 0 decodes the first `uris` entry via `decode_file_uri` → `Selected`;
  any other response → `Cancelled`. Errors → `Unavailable`.
- Pure helpers with headless unit tests: `request_object_path` (`:1.42` →
  `1_42`), `decode_file_uri` (`file://` + optional `localhost` authority,
  `%XX` decoding, UTF-8 validation, malformed-`%` rejection, no `+`→space
  translation), `hex_value`, `resolve_chain` (falls through **only** on
  `Unavailable`, never on `Cancelled`), `pick_via_fallbacks` (zenity then
  kdialog; clear message naming xdg-desktop-portal and the
  `furus-gui /path/to/image.iso` escape hatch).
- 5 pure unit tests passed; `cargo clippy -p furus-gui --all-targets -- -D warnings`
  was clean at the time.

## Technical decisions

- **zbus 6 has no `zbus::blocking`.** The handoff spec assumed an older zbus, but
  the workspace pins zbus 6.2.0. The crate's established pattern
  (`crates/furus-gui/src/ipc/dbus.rs`) is `zbus::block_on(async { … })` on a
  dedicated thread; `picker.rs` follows that. No async runtime was added.
- Canonical zbus 6 re-exports `Variant`, `OwnedVariant`, `OwnedObjectPath` live
  under `zbus::wire`; `zbus::zvariant` is deprecated since 6.0 and is not used.
- Portal `OpenFile` signature is `(s, s, a{sv}) -> o`; an empty `parent_window`
  (`""` as `&str`) is valid. Request path =
  `/org/freedesktop/portal/desktop/request/<sender without leading ':' and with '.'→'_'>/<token>`.
- The portal call is synchronous from the caller's point of view but is always
  invoked from a background thread (wired in slice 2), so it never blocks the
  Slint event loop.

## Verification

- `cargo test -p furus-gui` → passed (5 new pure tests among them).
- `cargo clippy -p furus-gui --all-targets -- -D warnings` → clean.
- Reviewer: CLEAN, no blockers. Committed; not pushed.

## Gotchas / follow-up captured in later slices

- **rustfmt was not run before this commit.** `cargo xtask ci` later failed its
  `fmt` gate with 4 diff hunks in `picker.rs` (lines 56, 78, 86, 109). Fixed by
  `cargo fmt --all` and committed as `052aa4e` during slice 4.
- The 32,128-byte growth of the `furus-gui` release binary came from this module
  plus slice 2's wiring; the size baseline was refreshed during slice 4.
