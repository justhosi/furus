# Handoff — furus rebrand, Slice 2/4: documentation rebrand

## State

Work in `/home/hosi/dev/REA-Furus/furus`, branch `main`, starting HEAD
`89578f3` (Slice 1, the code-and-packaging rebrand commit). This slice is **not committed and not pushed**.

Slice 1 already renamed the code, crate directories, binaries, D-Bus/polkit
identifiers, packaging files and CI. This slice rewrote the human-facing
documentation only. No code, build file, packaging file, CI YAML, `assets/`
file, `data/*.csv` or `tools/parity.py` was touched.

Files rewritten (case-preserving replacement of the old project name with
`furus`/`Furus`/`FURUS`, including crate paths, commands, D-Bus/polkit IDs,
package filenames and the repository name):

* `README.md`, `CHANGELOG.md`, `TECHNICAL.md`, `DECISIONS.md`, `LICENSES.md`,
  `packaging/README.md`, `docs/RELEASE-CHECKLIST.md`
* `assets/README.md`, `crates/furus-cli/tests/golden/README.md`,
  `tests/fixtures/README.md`
* every `docs/handoffs/*.md` that mentioned the old name, including the
  previously untracked `docs/handoffs/HANDOFF-S31-publish-release.md`

Special cases applied on top of the mechanical rename:

1. `README.md` opening paragraph now carries the **single intentional**
   lowercase mention of the original name in its opening sentence; all other
   references there are `furus` or "the original Windows utility". This is
   the only line in any tracked
   `.md`/`.txt`/`.adoc` file that spells the original name.
2. `README.md` S31 matrix row now records the workflow as validated end-to-end
   and release `v0.1.1` as published on 2026-11-21 with 5 assets and matching
   `SHA256SUMS`. The stale caveat in `TECHNICAL.md`'s S31 close-out was
   corrected the same way.
3. Provenance citations in `LICENSES.md`, `DECISIONS.md`, `assets/README.md`,
   `README.md`, `CHANGELOG.md` and `TECHNICAL.md` were rephrased with generic
   "the original Windows utility" wording where they describe the upstream
   project. No URL or upstream asset filename was fabricated: the installer
   filename, version string, `.loc`/console-launcher asset names, resource
   script and FAT12 volume label are described generically while preserving
   version numbers, hashes, dates and decision IDs.
4. `TECHNICAL.md` gained a "Rebrand to `furus` (2026-11-21)" section recording
   the crate/binary/D-Bus/polkit/package-output renames and the deliberate
   data-integrity exceptions (protected `assets/` payloads and manifest kept
   byte-identical; the upstream `.loc` asset-name literal kept in
   `crates/furus-gui/src/i18n_bridge.rs`; raw RE evidence in `data/*.csv` and
   the `BY_MODULE` key in `tools/parity.py` kept for `xtask parity --check`).
5. New handoff: this file.

## Verification done in this slice

* A case-insensitive grep of all tracked `.md`/`.txt`/`.adoc` files for the
  old name → no matches; the mechanical rename covered all 46 in-scope files.
* The same grep over the working tree returns only the intentional README
  opening line plus stale matches under the gitignored
  `target/dist-staging/…/LICENSES.md`
  build artifact (a stale staged copy); that file is not a source document
  and was deliberately left untouched.
* Referenced identifiers in docs were checked against the rebranded tree:
  crates are `crates/furus-*`, binaries are `furus`/`furus-gui`/`furus-helper`,
  D-Bus/polkit IDs are `org.furuslinux.*`, files are
  `packaging/rpm/furus.spec` and `org.furuslinux.Furus.*`, env vars are
  `FURUS_*`, and the dist license path is `usr/share/doc/furus/LICENSES.md`.
  The docs do not reference any old path that no longer exists.

## What remains

* **Slice 3 — verification.** Re-run the real gates on the rebranded tree
  (fmt, clippy, tests, `cargo xtask ci`, `cargo xtask qa`, `cargo xtask
  assets --check`, `cargo xtask parity --check`, `cargo xtask contract
  --check`, `cargo xtask dist`) and confirm the emitted artifact names and
  staged paths match the documentation. Confirm `git status --short` contains
  only the intended documentation paths before the reviewer commits.
* **Slice 4 — publication.** Replace the already-published `v0.1.1` release
  and its tag: the current public release (2026-11-21, 5 assets, 0 downloads)
  still carries the pre-rebrand asset-name prefix. Only after the user
  explicitly approves publishing may the publisher delete/replace that
  release and tag with rebranded `furus-*` artifacts. The docs already state
  `v0.1.1` was validated end-to-end, so keep that fact true when updating the
  release.

## Acceptance criteria still open

* No documentation path, command, identifier or filename in the tree refers to
  a pre-rebrand artifact that no longer exists.
* The one-match invariant holds for tracked docs after the reviewer commit.
* Slice 3's gate output is recorded in a follow-up handoff.
* Slice 4 is gated on explicit user permission; do not publish without it.

## Gotchas

* `target/dist-staging/…/usr/share/doc/furus/LICENSES.md` is a stale build
  artifact with old text. It is gitignored and outside the documentation
  scope; a clean rebuild will refresh it. Do not hand-edit it.
* The untracked `HANDOFF-S31-publish-release.md` is part of this slice's
  changes and must be added in the same commit as the rewritten docs.
* Commit message convention in this repo: lowercase imperative, e.g.
  `docs: rebrand documentation to furus`. Do not commit from this handoff.
