# HANDOFF — furus/ repo, S26-T1 (Slice 1/4)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`.
This file is written for a fresh context that must resume with no prior history.

## Current state

- S26-T1 is **complete**. Working tree has uncommitted documentation-only
  changes in exactly two files: `DECISIONS.md` and `LICENSES.md`.
- **Nothing was committed and nothing was pushed** — do not do either without
  explicit user permission (publisher step).
- No Rust source or packaging file was touched.
- Verification run and passed:
  - `git diff --check` → no output, exit 0.
  - Row grep confirmed A1/A3/A5 status cells read `approved 2026-11-19`.
- `cargo` is at `~/.cargo/bin/cargo` (not on the mise PATH); use
  `PATH="$HOME/.cargo/bin:$PATH"` if a later task needs it. T1 needed no cargo.

## What this slice (S26-T1) completed

Ratified three S00 architectural records from `proposed` to `approved
2026-11-19`, with rationale matching the shipped tree:

- `DECISIONS.md`:
  - Section 1 intro now says A1/A3/A4/A5 are approved, the rest proposed.
  - Table rows A1, A3, A5: only the **Status** cell changed to `approved
    2026-11-19`. Value and Rationale text preserved verbatim. A4 stays
    `approved 2026-10-27`; A2 and A6–A12 stay `proposed` (untouched).
  - A4/wimlib note (Section 1, after the table): "follows A5's status" now
    reads `(approved 2026-11-19)`.
  - Section 3 go/no-go note: A1/A3/A4/A5 no longer block; A2 and A6–A12 still
    await the user.
  - New Subsection at end of Section 4:
    `### 2026-11-19 - S26 amendments (A1, A3, A5 ratified)` covering:
      * A1 — GPL-3.0-or-later baseline already enforced by `LICENSES.md`'s
        86-asset audit and `deny.toml`'s `GPL-3.0-only` Slint branch; public
        repo is the GPL source offer.
      * A3 — x86_64 + aarch64 glibc ≥ 2.31 (Debian 11+, Ubuntu 20.04+, Fedora,
        Arch, Raspberry Pi), static-musl option for CLI/helper; `xtask dist
        --target <triple>` is the mechanism; only the host triple is verified
        here, no aarch64 build claimed.
      * A5 — wimlib LGPL-3.0-or-later linked via `wimlib-sys`, opt-in
        `strict-link` feature from S22; LGPL relink/source duties met by a
        separate library package and licence texts in the bundle.
      * Neutral statement that A2 and A6–A12 remain proposed and outside
        S26's authorization.
- `LICENSES.md` line 11: A1 parenthetical changed to `(approved 2026-11-19,
  decision A1)`. A6 stays `(proposed decision A6)`. The rest of the 219-line
  audit is untouched.

## Gotchas (read before continuing)

- **Naming discrepancy**: the S26 spec calls the repo `furus` and links to
  `justhosi/furus`; DECISIONS.md A2 uses the working name `rufus-linux`. The
  release name is **not decided** — "Rufus" is a trademark (Pete Batard /
  Akeo Consulting), so A2 must not be ratified or renamed without the user.
  Do not let spec naming imply a settled product name.
- **Ratification discrepancy**: the spec's acceptance criterion says
  "`DECISIONS.md` has no unratified S00 architecture items remaining." That is
  **not literally achievable** — prior slices refused to fabricate user
  confirmation. After T1 the accurate state is A1/A3/A4/A5 approved,
  **A2 and A6–A12 still proposed**. Do not ratify them to satisfy that phrase.
- The spec's `org.rufus.*` / `rufus-helper` / `/usr/libexec/rufus-helper`
  naming in T2/T3 is the spec's own choice; reconcile with A2's frozen working
  name before finalizing packaging, and flag it rather than silently renaming.

## What remains in S26 (slices 2–4)

- **S26-T2** — `packaging/`: complete/validate Polkit action
  (`org.rufus.helper.policy`), D-Bus system service + bus policy
  (`org.rufus.Helper1.service`, `org.rufus.Helper1.conf`), Freedesktop
  `.desktop` + AppStream metainfo, and distro specs (Debian `control`/
  `postinst` recommending `ntfs-3g`, `e2fsprogs`, `udftools`, `libwim15`;
  Arch `PKGBUILD` / RPM `.spec`). Helper must install root-owned `0755`.
- **S26-T3** — `xtask/src/main.rs`: implement `cargo xtask dist
  [--target <triple>] [--out-dir <dir>]`: release builds + size gates, stage
  binaries/policy/manifests/icons/`LICENSES.md`, deterministic `.tar.gz`
  (`.deb` when `dpkg-deb` present), and `SHA256SUMS`.
- **S26-T4** — `xtask/src/main.rs`: unit/integration tests for `xtask dist`
  verifying staged layout, valid XML/INI in the manifests, and SHA-256 digests.

## Exact next steps

1. Resume at **Slice 2/4 (S26-T2)**: inspect `packaging/` and its README, then
   edit only the packaging files. Keep one-command/one-review slicing.
2. Then **S26-T3**, then **S26-T4** in `xtask/src/main.rs`.
3. Run the spec's verification: `cargo xtask dist`, `cargo test -p xtask`,
   `cargo xtask ci` (with `PATH="$HOME/.cargo/bin:$PATH"`).
4. Review, then ask the user before any commit/push.

## Acceptance criteria still open

- From T1: the spec's "no unratified S00 architecture items remaining"
  criterion stays formally unmet by design — A2/A6–A12 remain proposed pending
  user decisions; this is recorded in DECISIONS.md Section 4.
- `cargo xtask dist` builds release binaries, verifies size gates, validates
  `packaging/` manifests, and emits a complete bundle + `SHA256SUMS`, exit 0.
- `cargo test -p xtask` and `cargo xtask ci` pass cleanly.
- Boot acceptance from the prior S21 work is still unverified (separate from
  S26); see the workspace-level handoff at `/home/hosi/dev/REA-Rufus/HANDOFF.md`.
