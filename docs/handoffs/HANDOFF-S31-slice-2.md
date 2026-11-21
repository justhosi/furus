# S31 — slice 2/4: four-job release workflow (RPM + Arch + guarded publish)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, base HEAD
`dd891b4f55278c86b970d21bf2ef93d246b794c2`. cargo/rustc 1.99.0 live in
`~/.cargo/bin`; prefix cargo commands with `export PATH="$HOME/.cargo/bin:$PATH"`.

This is the handoff after **slice 2/4** of S31. Slices are gated one at a time
(one command → reviewer → next command); do not batch them. **Nothing was
committed, pushed, tagged, and no workflow was dispatched/run.** The workflow
has only been parsed and statically validated — it has NOT been executed.

## Slice 2/4 — status: DONE (not committed, not pushed, not run)

### Command executed

Refactor `.github/workflows/release.yml` from the old 2-job (`build` → `release`)
shape into the required 4-job DAG that produces and verifies an RPM and an Arch
package from the build job's dist tarball, and publishes all four artifact kinds
under one unified `SHA256SUMS`. Add the `publish` dry-run input. Record this
handoff.

### Exact changes (only the two in-scope paths)

1. **`.github/workflows/release.yml`** (refactored)
   - Triggers unchanged except `workflow_dispatch` gains a boolean input
     `publish` (`default: false`); `tag` (required string) is kept.
   - Top-level `permissions: contents: read` kept; only `publish` overrides to
     `contents: write`.
   - `build` job body kept verbatim (pinned checkout
     `11d5960a…`, pinned rust-toolchain `b725eda…` @ 1.99.0 + rustfmt/clippy,
     cargo-deny 0.20.2 + cargo-audit 0.22.2, full apt list incl S28
     fontconfig/winit headers + OVMF 4M symlink shim + `dpkg`, `cargo xtask ci`,
     `cargo xtask qa`, `cargo xtask dist`, upload-artifact
     `ea165f8d…` with `if-no-files-found: error`). Added `outputs.version` /
     `outputs.target` from a new `id: dist-info` step that reads the one dist
     tarball: `target` = `rustc -vV` host triple (what `xtask dist` used),
     `version` = tarball stem minus `rufus-` and `-<target>`. Fails if the
     tarball count is not exactly one or either value cannot be derived.
   - New `package-rpm` (`container: fedora:latest`, `needs: build`,
     `contents: read`): `dnf install rpm-build tar gzip git`, checkout, download
     `dist`, copy tarball to `~/rpmbuild/SOURCES/`, run
     `rpmbuild -bb --define "rufus_version $RUFUS_VERSION" --define
     "rufus_target $RUFUS_TARGET" packaging/rpm/rufus.spec`, assert all ten RPM
     paths via `rpm -qlp`, print `rpm -qpR` and `rpm -qp --recommends`, upload
     only `out/*.rpm` with `if-no-files-found: error`.
   - New `package-arch` (`container: archlinux:latest`, `needs: build`,
     `contents: read`): `pacman -Syu` + `base-devel zstd tar git`, checkout,
     download `dist`, create non-root `builder`, copy `PKGBUILD` + tarball into
     `/work` and chown it, run as builder
     `rufus_version=… _target=… makepkg -f --noconfirm --skipchecksums`, assert
     the ten Arch paths via `tar --zstd -tf`, upload only `out/*.pkg.tar.zst`
     with `if-no-files-found: error`.
   - `release` → `publish`: `needs: [build, package-rpm, package-arch]`,
     `contents: write`, downloads all three artifacts with `pattern: '*'` +
     `merge-multiple: true` into one `release/` dir, `rm` the dist job's narrow
     `SHA256SUMS` and regenerate a unified one covering
     `*.tar.gz *.deb *.rpm *.pkg.tar.zst`, runs `sha256sum -c SHA256SUMS`
     (fails the job on mismatch), then `gh release create` with `GH_TOKEN:
     ${{ github.token }}`.
   - **No checkout in `publish`.** The exact required argument
     `--repo "${{ github.repository }}"` is on the `gh release create` command.
   - No Rust is compiled in either container job; both consume only the dist
     tarball.
2. **NEW `docs/handoffs/HANDOFF-S31-slice-2.md`** — this file.

No other file was created or edited. In particular the README files,
`TECHNICAL.md`, Cargo manifests, Rust sources, `size-baseline.json` and the
slice-1 packaging recipes were left untouched.

### Four-job DAG

```
build  (ubuntu-latest, contents: read)
  ├─ outputs: version, target   (derived from the one dist tarball)
  ├─ uploads artifact "dist"    (target/dist/ contents)
  │
  ├─> package-rpm   (fedora:latest, needs: build, contents: read)
  │      uploads artifact "rpm"   (*.rpm only)
  │
  ├─> package-arch  (archlinux:latest, needs: build, contents: read)
  │      uploads artifact "arch"  (*.pkg.tar.zst only)
  │
  └─> publish       (ubuntu-latest, needs: all three, contents: write)
         downloads pattern '*', merge-multiple:true
         unified SHA256SUMS -> sha256sum -c -> gh release create
```

Only `publish` holds the write token. The two packaging jobs run in parallel
and depend only on `build`, not on each other.

### Interface details used from slice 1

- **RPM overrides are `--define` macros**, passed on the `rpmbuild` command:
  `--define "rufus_version <VERSION>" --define "rufus_target <TARGET>"`. The
  spec has safe defaults (`0.1.0` / `x86_64-unknown-linux-gnu`) when absent.
  `Source0` = `rufus-%{version}-%{dist_target}.tar.gz`, resolved from
  `~/rpmbuild/SOURCES/`. Fedora names are used (no Debian-only `libwim15`).
- **Arch overrides are ENV vars** `rufus_version=<VERSION>` and
  `_target=<TARGET>` passed to `makepkg`. Crucially **not `pkgver`** — makepkg
  unsets `pkgver` at `/usr/bin/makepkg:1252` before sourcing the PKGBUILD.
  `sha256sums=('SKIP')` and `options=(!strip)` are left as slice 1 set them;
  `--skipchecksums` is used because the tarball is already verified by the
  workflow.
- Dist artifact names: `rufus-<VERSION>-<TARGET>.tar.gz`,
  `rufus-<VERSION>-<TARGET>.deb`, and `SHA256SUMS` (lines `<digest>  <name>`).
  VERSION/TARGET for the recipes come from the build job's tarball, so they
  match the artifact name exactly for any `v*` tag (Cargo's package version can
  differ from the tag; deriving from the tag would be wrong).
- Ten asserted paths differ only in the license location:
  RPM `usr/share/licenses/rufus/LICENSES.md`; Arch
  `usr/share/licenses/rufus-linux/LICENSES.md`.

### The `--repo` fix

The previous release run failed with `gh: fatal: not a git repository` because
the old `release` job had no checkout and `gh` could not infer the repository
from a Git remote. Per the explicit requirement, the fix is the exact argument
`--repo "${{ github.repository }}"` on the `gh release create` command, with a
comment explaining why it is needed. **No checkout step was added to `publish`**;
the minimal fix is on the command itself.

### Dry-run behaviour

- `workflow_dispatch` with `publish: false` (the default): `build`,
  `package-rpm` and `package-arch` all run and fully verify their packages, but
  the `Publish GitHub release` step is skipped. Nothing is published.
- `workflow_dispatch` with `publish: true`: same, then `gh release create` runs
  against `TAG = inputs.tag`.
- `push` of a `v*` tag: publishing always happens (`TAG = github.ref_name`).

Expressed on the step as:
`if: github.event_name == 'push' || inputs.publish`

### Verification (exact results)

All static; **the workflow was not executed** (slice 4 will run the dry dispatch).

1. `python3` + `yaml.safe_load('.github/workflows/release.yml')` → parsed OK.
   Assertions all passed:
   - 4 jobs in order `build, package-rpm, package-arch, publish`.
   - `needs`: build none, both package jobs `build`, publish
     `[build, package-rpm, package-arch]`.
   - `permissions`: top-level and the three non-publish jobs `contents: read`;
     publish `contents: write` (no other write grant).
   - Triggers: `push.tags == ['v*']`; `workflow_dispatch` has required string
     `tag` and boolean `publish` default `false`.
   - `build.outputs.version/target` wired to `steps.dist-info.outputs.*`, and a
     step with `id: dist-info` exists.
   - All four third-party actions pinned to the exact full SHAs required, and
     **every** `uses:` matches `@[0-9a-f]{40}` (no unpinned action).
   - The literal string `--repo "${{ github.repository }}"` is present, on the
     `gh release create` step; that step also carries `GH_TOKEN:
     ${{ github.token }}`, `--title "$TAG"`, `--generate-notes`, and all five
     file globs (`./*.tar.gz`, `./*.deb`, `./*.rpm`, `./*.pkg.tar.zst`,
     `./SHA256SUMS`).
   - Publish step `if` equals `github.event_name == 'push' || inputs.publish`,
     and `publish` contains no checkout step.
   - Unified checksum step regenerates over `*.tar.gz *.deb *.rpm *.pkg.tar.zst`
     and runs `sha256sum -c SHA256SUMS`.
   - Neither container job contains `cargo build` or `cargo xtask dist`.
   - In `build`, `Run xtask ci` → `Run xtask qa` → `Build release artifacts` →
     `Upload dist artifacts` in that order; every upload-artifact step has
     `if-no-files-found: error`.
2. `actionlint` → not installed in this environment, so it was skipped;
   `yaml.safe_load` was used as the parser/validator instead.
3. `git diff --check` → clean (no output, exit 0).
4. `git status --short` → only ` M .github/workflows/release.yml` at validation
   time (the handoff file is new and untracked, i.e. the final expected status
   is that plus `?? docs/handoffs/HANDOFF-S31-slice-2.md`).

### Gotchas

- **Container jobs have no checkout by default.** We added `actions/checkout`
  to both package jobs (after installing `git`, which the base images lack)
  solely to obtain `packaging/rpm/rufus.spec` / `packaging/arch/PKGBUILD`. The
  alternative would have been to pass the recipes through an extra artifact;
  checkout is simpler and guarantees the recipe matches the same commit the
  build job used. No cargo command is added to either job.
- **Checkout ref on manual dispatch** is the dispatch branch, not `inputs.tag`;
  the build likewise runs from that branch, so the recipes and the tarball stay
  consistent. This is pre-existing workflow design, unchanged here.
- **License path differs** between the two packages (`licenses/rufus` vs
  `licenses/rufus-linux`); the assertion loops account for that.
- **`sha256sum` uses bare filenames** (no `./`) so `sha256sum -c` resolves in
  `release/`; the `gh release create` file arguments use `./` as specified.
- **All four artifact globs must match.** `build` installs `dpkg` so the `.deb`
  exists, and both package jobs use `if-no-files-found: error`, so a missing
  artifact fails before publish rather than leaving an unexpanded glob.
- **RPM version/target are `--define`s; Arch are env vars**, not `pkgver`.
- `actionlint` could not run here (not installed); validation was via PyYAML
  plus explicit assertions. Slice 4 should still confirm on the live run.
- This is a static-only verification. Container behaviour (`dnf`/`pacman`
  availability, `su builder`, `rpmbuild`/`makepkg` success) was exercised in
  slice 1 outside GitHub Actions, but the workflow itself has not run.

### Remaining / next steps

1. Hand this slice to the reviewer; it is **not committed and not pushed**.
2. Slice 3/4 (separate gated command) is expected to update documentation,
   including `packaging/README.md` (still mentions `libwim15` for RPM) — not
   touched here because it is out of scope.
3. Slice 4/4 is expected to push the branch and execute a dry
   `workflow_dispatch` run (`publish: false`), confirm all four jobs/builds and
   that no release is created, then — with explicit user permission — do the
   real publish. Do NOT run `workflow_dispatch` from this slice.
4. If the dry run fails, fix only within the owning slice's scope and re-gate
   through coder → reviewer.
