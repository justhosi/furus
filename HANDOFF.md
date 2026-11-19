# HANDOFF — furus/ repo, S26 final (Slice 4/4 complete)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, base HEAD `d0b9d42`.
This file is self-contained for a fresh context. **S26 (Distribution packaging
& release bundles) is fully complete.** Nothing has been committed or pushed by
this slice; do neither without explicit user permission. `coder` never pushes.

## Commits so far (all already on `main`)

* `9cd7d38` — docs: ratify A1, A3, A5 in S26-T1 decision records.
* `2ba0ff4` — feat(packaging): complete S26-T2 distribution definitions.
* `d0b9d42` — feat(dist): implement S26-T3 distribution bundles and align distro specs.

S26-T4 (this slice) is intentionally **uncommitted** in the working tree so a
reviewer can inspect it; the only changed files are:
`xtask/src/main.rs` (tests + one behavior-preserving helper extraction),
`TECHNICAL.md` (appended S26 section) and this `HANDOFF.md` (overwritten).

`cargo`/`rustc` 1.99.0 live in `~/.cargo/bin`, not on the default PATH. Prefix
cargo commands with `PATH="$HOME/.cargo/bin:$PATH"`.

## What S26 built

`cargo xtask dist [--target <triple>] [--out-dir <dir>]` release-builds the
workspace, enforces size budgets (rufus 3M / helper 2.5M / GUI 14M), validates
the 11 finalized `packaging/` files (XML via quick-xml, INI via a hand-written
parser, distro-token checks), stages a 12-file FHS tree into
`target/dist-staging/<triple>`, writes a deterministic
`rufus-<version>-<triple>.tar.gz` (gzip mtime 0, sorted tar entries, uid/gid/
mtime 0), conditionally builds a `.deb` with `dpkg-deb --root-owner-group`, and
writes `SHA256SUMS`. Full architecture, security invariants, the `org.rufuslinux`
naming deviation, the external-tool rationale, the packaging↔dist contract and
the decision record are in the new `## S26` section of `TECHNICAL.md`.

## S26-T4 changes in detail

* `xtask/src/main.rs`:
  * Extracted `write_sha256sums(out_dir, artifacts)` from `cmd_dist` (identical
    output; CLI behavior unchanged) and added a test-only `verify_sha256sums`
    helper plus a `TempDir` (pid + atomic counter, cleanup on `Drop`).
  * Grew the `#[cfg(test)] mod tests` from **15 to 21** tests: `staged_layout_has_exact_paths_and_modes`, `staged_control_architecture_follows_target_mapping`, `real_packaging_xml_and_ini_files_validate`, `malformed_xml_is_rejected`, `malformed_ini_is_rejected_by_validators`, `sha256sums_match_artifact_bytes_and_detect_corruption`, and a strengthened `dist_archive_is_byte_identical` (mtime/uid/gid/mode pinned). No new dependency.
* `TECHNICAL.md`: appended `## S26 — Distribution packaging & release bundles`,
  leaving all prior S21–S25 content untouched.
* `HANDOFF.md`: this final handoff (stale T3-blocker wording removed).

## Verification actually run (final run, all passed)

From `/home/hosi/dev/REA-Rufus/furus`, with `PATH="$HOME/.cargo/bin:$PATH"`:

* `cargo fmt --all -- --check` → exit 0, clean.
* `cargo test -p xtask` → `21 passed; 0 failed; 0 ignored; 0 measured;
  0 filtered out` (was 15 before T4).
* `cargo xtask dist` → exit 0; sizes `rufus` 1,810,152 / `rufus-helper`
  1,406,296 / `rufus-gui` 12,774,280 bytes, all `[OK]`; `11 packaging files`
  validated; `skip .deb: dpkg-deb not available`; artifact
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz` in
  `target/dist/x86_64-unknown-linux-gnu/`.
* `sha256sum -c SHA256SUMS` in that out-dir →
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz: OK`.
* `cargo xtask ci` → `ci: all gates passed` (fmt, clippy, workspace test,
  assets 86/86, parity 2,709 rows, size, `cargo deny check` ok;
  `cargo-audit` reported `SKIP (not installed)`).
* `git diff --check` → exit 0, clean.

During T4 one clippy `useless_format` in a new test was caught by `cargo xtask
ci` and fixed; the final CI re-run is clean.

## Caveats / unverified

* No `dpkg-deb` here: `.deb` generation is skipped by design and untested.
  `rpmspec` and `rpmlint` are also absent, so the spec was never parsed/linted
  by a real tool (the Arch `package()` was run for real under `fakeroot` in T3
  review and passed).
* Only the host triple `x86_64-unknown-linux-gnu` is installed; no aarch64
  cross-build was produced or verified.
* T1's "no unratified S00 architecture items remaining" stays formally unmet
  **by design**: A1, A3, A4 and A5 are approved, but **A2 and A6–A12 remain
  proposed** in `DECISIONS.md` §4. Do not ratify them to satisfy that phrase.
* Non-fatal `cargo deny` duplicate-crate warnings (zbus, thiserror, toml,
  windows-sys, …) remain unchanged from S25. `cargo-audit` is not installed.

## Gotchas (do not regress)

* Keep `org.rufuslinux.*` identifiers and filenames exactly as shipped; the
  GUI/helper hardcode the bus name, object path, interface and polkit action.
* Dist's single artifact name and `usr/` + `DEBIAN/` layout are the authoritative
  packaging contract consumed by PKGBUILD `source=` and RPM `Source0`. Do not
  add a second tarball or flatten the archive.
* Stored mtimes are always 0; GNU `tar -tv` may display `1970-01-01 02:00` due
  to the local UTC+2 display timezone — this is not a real timestamp.
* Default out-dir is `target/dist/<triple>`; `target/dist-staging/<triple>` is
  wiped and rebuilt on every dist run. Explicit `--out-dir` is honored.
* Explicit `--target <host>` makes Cargo build into `target/<triple>/release`;
  code keys `bin_dir` off `target.is_some()`, not `triple == host` (a T3 fix).

## Remaining work / exact next steps

1. Hand this slice to the `reviewer` subagent for structure + security review.
   If blockers are reported, send them back to `coder` and repeat; do not push.
2. Once the reviewer signs off, **ask the user for explicit permission to
   publish** using `notify-telegram` plus the `question` tool.
3. Only after that explicit permission, invoke the `publisher` subagent: verify
   review sign-off, update `README.md` if needed, commit the docs, and push.
   `coder` must never push.
4. Thereafter the earlier S21 boot-acceptance item (separate from S26) remains
   unverified on this host; see `/home/hosi/dev/REA-Rufus/HANDOFF.md`.
