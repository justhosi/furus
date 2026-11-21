# S31 — Native RPM/Arch packages in the release workflow — FINAL HANDOFF (3/4 complete; slice 4 dispatch/push pending)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. cargo/rustc 1.99.0 lives
in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the **final, authoritative** S31 handoff. It supersedes the slice
records `HANDOFF-S31-slice-1.md` and `HANDOFF-S31-slice-2.md`, which remain on
disk as historical notes — their "not committed, not pushed" lines were
accurate when written and are stale now (see Gotchas). The first three slices
are complete and locally verified; slice 4 (dispatch/push) is pending. S31
changes no runtime behaviour, no wire format, no dependency and no binary size:
the release binaries are byte-for-byte
the ones measured by the S29/S30 size gate, and the dormant A12 config fields
are untouched (decision A12 stays **proposed**).

## Status: 3/4 complete; slice 4 (dispatch/push) pending

| Slice | Commit | Scope |
|---|---|---|
| 1/4 | `dd891b4` | Parameterized `packaging/rpm/rufus.spec` (`rpmbuild --define 'rufus_version …' --define 'rufus_target …'`, defaults `0.1.0` / `x86_64-unknown-linux-gnu`; Fedora-correct deps `wimlib`, `polkit`, `fontconfig`, `ntfs-3g`, `e2fsprogs`, `udftools`, no Debian-only `libwim15`; `%global debug_package %{nil}`) and `packaging/arch/PKGBUILD` (env `rufus_version` / `_target`, **not** `pkgver`, which makepkg unsets; `sha256sums=('SKIP')`; `options=(!strip)`; polkit/fontconfig `optdepends`). All ten install paths preserved. xtask RPM validator now requires `wimlib`; the deb validator keeps `libwim15` (correct for Debian) and the Arch validator is unchanged. |
| 2/4 | `467559a` | `.github/workflows/release.yml` refactored from 2 jobs into a 4-job DAG: `build` (ubuntu-latest, `contents: read`, `xtask ci`→`qa`→`dist`, uploads `target/dist/`, emits `version`/`target` outputs) → parallel `package-rpm` (fedora:latest, `contents: read`, `rpmbuild` with the two defines, `rpm -qlp`/`rpm -qpR` ten-path checks, uploads `*.rpm`) and `package-arch` (archlinux:latest, `contents: read`, non-root builder, env `rufus_version`/`_target` `makepkg`, `tar --zstd -tf` ten-path checks, uploads `*.pkg.tar.zst`) → `publish` (needs all three, sole `contents: write`, downloads `pattern: '*'` + `merge-multiple: true`, regenerates ONE unified `SHA256SUMS` over `.tar.gz`/`.deb`/`.rpm`/`.pkg.tar.zst`, `sha256sum -c` gate, then `gh release create "$TAG" --title "$TAG" --generate-notes --repo "${{ github.repository }}"` … with `GH_TOKEN`, guarded by `if: github.event_name == 'push' \|\| inputs.publish`). New `workflow_dispatch` boolean input `publish` (default `false`) so manual dry runs do not publish. The exact `--repo "${{ github.repository }}"` is the user-mandated fix for the prior v0.1.0 `fatal: not a git repository` failure. No checkout in `publish`; no Rust compiled in the container jobs. |
| 3/4 | this documentation commit (HEAD at S31 close) | `README.md` (release-assets/install subsection with the three exact one-line commands, plus a complete S31 slice-matrix row that notes the workflow has not run end-to-end), `packaging/README.md` (same three commands; RPM metadata corrected from `libwim15` to `wimlib`; note that RPM/Arch packages are now CI-built from the dist tarball), `TECHNICAL.md` (S31 design section), and this final handoff. No source, Cargo manifest, `.github/workflows/`, `size-baseline.json`, `DECISIONS.md`, spec/PKGBUILD or slice-1/slice-2 handoff was touched. |
| 4/4 | pending (slice 4) | Reviewer commits slice 3; publisher pushes **`main` only — NO tag**; slice 4 runs a `workflow_dispatch` dry run (`publish: false`) and reports the exact artifact filenames. This row is not yet complete. |

Nothing is pushed by this slice. Reviewer and publisher own the commit and
push; **no tag is pushed as part of S31**.

## What landed (detail lives in the per-slice handoffs)

* **Slice 1 — offline/native recipes.** Both recipes build a ready-to-install
  binary package entirely from the pre-built `target/dist/<triple>/rufus-<version>-<triple>.tar.gz`,
  with no Rust recompilation and no rpmbuild/makepkg warnings or errors. RPM is
  parameterized with `--define` macros (with safe defaults, so a plain
  `rpmbuild -bb` still works); Arch is parameterized with `rufus_version` and
  `_target` environment variables because makepkg unsets `pkgver` before
  sourcing the PKGBUILD. `sha256sums=('SKIP')` is intentional (the workflow
  verifies the tarball first), and `options=(!strip)` / `%global debug_package
  %{nil}` are load-bearing for a pre-built, stripped payload.
* **Slice 2 — the four-job release workflow.** Least privilege is a security
  boundary: only `publish` holds `contents: write`, and it has no checkout and
  no compilation; the `build` and two packaging jobs are all `contents: read`.
  VERSION/TARGET for the recipes are derived from the build job's one dist
  tarball, not the tag, so they match the artifact names exactly for any `v*`
  tag. The unified `SHA256SUMS` is regenerated and verified in `publish` before
  `gh release create`, so corrupted uploads fail before publication. The
  `publish` input makes manual runs dry by default.
* **Slice 3 — documentation.** `README.md`, `packaging/README.md` and
  `TECHNICAL.md` now describe the release assets, the three install commands,
  the corrected Fedora dependency names, the single-dist-build/four-job design,
  the parameterization interfaces, the per-format smoke checks, the unified
  checksum gate, dry-run mode and the `--repo` rationale.

## Verification (exact commands and results)

Run from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"`. No privileged
host step, reboot, network action, tag push or release publish was used in this
slice.

* `cargo xtask ci` → **exit 0, `ci: all gates passed`**. Sizes unchanged and
  within the committed baseline allowance (`rufus` 1,810,152 B,
  `rufus-helper` 1,406,296 B, `rufus-gui` 12,774,280 B). The packaging contract
  still passes with the new `wimlib` token in the RPM validator; the deb
  validator still requires `libwim15` (correct for Debian). `SKIP (not
  installed): cargo-audit` is pre-existing and reported as a skip, not a
  failure.
* `cargo xtask qa` → **exit 0, `qa: all suites passed`**. Only the documented
  `tier1/pipeline-loop: loop-device / throughput tests need --privileged` skip.
* `git diff --check` → clean (no output, exit 0).
* `git status --short` → only the in-scope documentation paths are modified/new.
* Grep confirms the three install commands appear verbatim in both `README.md`
  and `packaging/README.md`, and that the RPM section of `packaging/README.md`
  no longer mentions `libwim15` (the deb section correctly keeps it).

Slice 1 additionally ran real `makepkg` and `rpmbuild` builds (in
`fedora:latest`) that produced all ten install paths; slice 2 parsed and
statically asserted the workflow YAML. Those results are recorded in the
per-slice handoffs and are not re-run here. No release binary was rebuilt by
this slice, so sizes are byte-identical to `size-baseline.json`.

## Acceptance criteria status

All documentation requirements are met:

* `README.md` has a release-assets/install subsection with the three exact
  commands, states the artifacts come from one `cargo xtask dist` build on each
  `v*` tag, mentions the generic tarball and unified `SHA256SUMS`, and keeps the
  existing voice and slice matrix (S31 row complete on `main`, with the
  not-run-end-to-end caveat).
* `packaging/README.md` has the same three commands, has the RPM `libwim15`
  metadata corrected to Fedora-correct `wimlib`, keeps the deb `libwim15`
  where correct, and notes CI builds the RPM/Arch packages from the dist
  tarball rather than shipping only metadata.
* `TECHNICAL.md` has an S31 section covering the single dist build, four-job DAG
  and least privilege, the `--define` vs Arch-env parameterization and the
  `pkgver` reason, the `rpm -qlp`/`rpm -qpR`, `tar --zstd -tf` and `dpkg-deb -c`
  smoke checks, the unified `SHA256SUMS` generation/verification, dry-run mode
  and the `--repo` fix, and notes that sizes remain byte-identical and A12 is
  untouched.
* This final handoff records three commits (with a stable reference, not a
  transient hash) for the documentation commit, acceptance status, verification,
  gotchas and remaining steps.

Slice 4 (live dry run, exact filenames) is **not** complete and remains a
tracked step below.

## Gotchas

* **Workflow not executed locally.** The 4-job DAG, container jobs, checksum
  gate and `gh release create` were parsed and statically asserted only. No
  GitHub runner ran `release.yml`; slice 4 will do the dry dispatch.
* **`actionlint` unavailable.** It is not installed here, so the workflow was
  validated with PyYAML plus explicit assertions in slice 2 instead. Slice 4
  should still confirm on the live run.
* **`cargo-audit` SKIP.** Not installed on this host; `cargo xtask ci` reports
  `SKIP (not installed)` rather than a pass. Pre-existing and expected.
* **`dpkg-deb` skip locally.** `cargo xtask dist` emits a `.deb` only when
  `dpkg-deb` is on PATH; it is absent here, so this host produces no `.deb`.
  The workflow installs `dpkg` so `ubuntu-latest` really builds it; removing
  that apt entry would break publication at the `*.deb` glob.
* **Manual-dispatch checkout follows the dispatch branch, not `inputs.tag`.**
  The build likewise runs from that branch, so on a dry run the branch must
  already contain the intended recipe and tarball-producing code. This is
  pre-existing workflow design, unchanged by S31.
* **Hardware validation is manual.** GUI/hotplug and UEFI/Legacy BIOS boots of
  Linux, Windows installer and Windows To Go are maintainer sign-off items in
  `docs/RELEASE-CHECKLIST.md`; CI does not perform them. Do not claim them as
  verified here.
* **Arch/RPM version-target overrides differ.** RPM takes `--define` macros;
  Arch takes `rufus_version`/`_target` env vars, never `pkgver`. `_target`
  selects the tarball, not the package architecture, and RPM `BuildArch` is
  still hardcoded to `x86_64` (aarch64 is a separate, out-of-scope change).
* **License paths differ.** RPM uses `usr/share/licenses/rufus/LICENSES.md`,
  Arch uses `usr/share/licenses/rufus-linux/LICENSES.md`; the smoke-check loops
  account for this.
* **Stale historical lines.** `HANDOFF-S31-slice-1.md` and
  `HANDOFF-S31-slice-2.md` still say "not committed, not pushed" and "not run",
  accurate when written but stale now. They are left untouched as slice
  records; this file is the authoritative final state.

## Remaining steps

1. Reviewer reviews this slice and commits it (do not push).
2. With the user's explicit permission, publisher pushes **`main` only — NO
   tag**. Pushing a `v*` tag now would trigger the release workflow prematurely.
3. Slice 4 runs a `workflow_dispatch` dry run with `publish: false`, confirms
   all four jobs build and verify their artifacts and that **no** GitHub release
   is created.
4. Slice 4 reports the exact artifact filenames produced (for example
   `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`, the `.deb`, the `.rpm` and the
   `.pkg.tar.zst`), and confirms the unified `SHA256SUMS` lists all of them.
5. Only after explicit user permission does a real publish happen; a real tag
   push is a separate, explicit decision and is **not** part of S31.
6. No privileged host steps, reboots or network actions are required to verify
   S31 locally.
