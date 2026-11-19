# HANDOFF — furus/ repo, S26-T3 blocker remediation (still Slice 3/4)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`. Base HEAD `2ba0ff4`
(S26-T2). The reviewer did **not** commit T3; its blocker is now fixed in the
working tree. This file is self-contained for a fresh context.

## Current state

- S26-T3 is complete **and its one review blocker is resolved**. Nothing has
  been committed or pushed; do neither without explicit user permission.
  `coder` never pushes.
- Working-tree changes (uncommitted): `xtask/src/main.rs`, `xtask/Cargo.toml`,
  `Cargo.lock`, `packaging/arch/PKGBUILD`, `packaging/rpm/rufus.spec`,
  `HANDOFF.md`.
- `packaging/README.md` was deliberately left unchanged: it contains no
  source-tarball name or flat-layout claim that became wrong.
- `cargo`/`rustc` 1.99.0 are at `~/.cargo/bin`, not on the default PATH.
  Prefix every cargo command with `PATH="$HOME/.cargo/bin:$PATH"`.

## Resolved blocker: dist bundle vs. packaging contract

The reviewer found that `cargo xtask dist` emits a single triple-named tarball
whose root is the staged FHS tree (`usr/`, `DEBIAN/`), while PKGBUILD and the
RPM spec claimed different tarball names and read loose files from the
extraction root. Planner decision: **fix the packaging, not dist**.

- Dist logic, archive name and archive layout are unchanged. The only xtask
  edit in this remediation was the module doc comment at `main.rs:13` (it no
  longer calls `dist` a stub).
- `packaging/arch/PKGBUILD` now declares
  `_target=${_target:-x86_64-unknown-linux-gnu}` (packagers override for
  `aarch64-unknown-linux-gnu`) and
  `source=("rufus-${pkgver}-${_target}.tar.gz")`, exactly matching the dist
  artifact `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`. Every `package()`
  source path now points into the staged tree (`${srcdir}/usr/bin/rufus`,
  `${srcdir}/usr/libexec/rufus-helper`, `${srcdir}/usr/share/...`,
  `${srcdir}/usr/share/doc/rufus/LICENSES.md`). Destinations, root ownership
  of the helper and all optdepends tokens (`ntfs-3g`, `ntfsprogs`,
  `e2fsprogs`, `udftools`, `wimlib`) are unchanged.
- `packaging/rpm/rufus.spec` now has `%global dist_target
  x86_64-unknown-linux-gnu`, `Source0:
  rufus-%{version}-%{dist_target}.tar.gz` and `BuildArch: x86_64`, with a
  comment explaining the aarch64 overrides. The false claim that dist edits
  BuildArch into the spec was removed. `%prep` uses
  `%setup -q -c -n rufus-%{version}` (the archive has no leading directory).
  All `%install` sources now use the staged layout; destinations, `%files`
  and `Recommends: ntfs-3g, e2fsprogs, udftools, libwim15` are unchanged.

## Verification actually run (all passed)

From `/home/hosi/dev/REA-Rufus/furus`:

- `PATH="$HOME/.cargo/bin:$PATH" cargo xtask dist` → exit 0, same output as
  T3 (three budgets OK, 11 packaging files validated,
  `skip .deb: dpkg-deb not available`, artifact
  `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`).
- Extracted the tarball to a temp dir: all 12 expected files present. Derived
  every `${srcdir}/...` path from PKGBUILD `package()` and every `usr/...`
  source from the spec `%install` (after joining `\` continuations) and
  checked existence — 10/10 OK for each.
- `bash -n packaging/arch/PKGBUILD` → exit 0.
- PKGBUILD simulation: extracted the bundle into a temp `srcdir`, ran the
  **real** `package()` under `fakeroot bash -c 'srcdir=… pkgdir=…; source
  packaging/arch/PKGBUILD; package'` → exit 0; installed tree showed 755
  binaries/helper and 644 metadata at the expected pkgdir paths.
- RPM simulation: extracted the `%install` lines, joined continuations,
  substituted `%{buildroot}`, `%{_bindir}`, `%{_datadir}` with temp paths,
  and ran them from the extraction dir → exit 0; installed tree matched the
  `%files` destinations.
- Filename line-up: printed `rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`
  and grepped the `source=("rufus-${pkgver}-${_target}.tar.gz")` and
  `Source0: rufus-%{version}-%{dist_target}.tar.gz` templates in the two
  specs — both matched.
- `rpmspec` and `rpmlint` are **absent**, so no real spec parse/lint was run.
- `git diff --check`, `cargo fmt --all -- --check`, `cargo test -p xtask`
  → all clean (`15 passed; 0 failed`); `cargo xtask ci` → `ci: all gates passed`.
  An initial doc-comment indent triggered clippy
  `doc_overindented_list_items`; it was fixed to the existing 2-space
  continuation style and CI re-ran clean.

## Gotchas

- Naming invariant: keep `org.rufuslinux.*` identifiers and filenames exactly
  as shipped; the GUI/helper hardcode the bus name and polkit action.
- Dist's single artifact name/layout is now the authoritative packaging
  contract. Do not add second tarballs or flatten the archive.
- `dpkg-deb` is absent: `.deb` generation is untested here and skipped by
  design. Only `x86_64-unknown-linux-gnu` is installed; no target was added.
- Default out-dir is `target/dist/<triple>`; `target/dist-staging/<triple>`
  is wiped and rebuilt on every dist run.
- Explicit `--target <host>` makes Cargo build into `target/<triple>/release`;
  the code keys `bin_dir` off `target.is_some()`, not `triple == host`.
- Architecture mapping: `x86_64*` → `amd64`, `aarch64*`/`arm64*` → `arm64`,
  otherwise an early clear error before the build.
- GNU tar displays mtime as `1970-01-01 02:00` due to the local UTC+2 display
  timezone; stored mtime is 0 and verified by `verify_archive`.

## Remaining work: S26-T4 (Slice 4/4)

1. Expand tests in `xtask/src/main.rs`: negative cases for malformed XML/INI
   and each distro dependency assertion, staging layout/mode checks including
   the `Architecture:` rewrite, SHA256SUMS format and CLI parsing.
2. Update `TECHNICAL.md` with the dist pipeline, determinism strategy, the
   exact bundle-name/staged-tree contract consumed by PKGBUILD and the RPM
   spec, and the `.deb` skip condition.
3. Final verification: `cargo fmt --all -- --check`, `cargo test -p xtask`,
   `cargo xtask ci`, `cargo xtask dist`; then hand to the reviewer subagent
   (structure + security) and ask the user for publish permission only after
   review sign-off. Never push from `coder`.

## Open acceptance criteria

- T1's "no unratified S00 architecture items remaining" stays formally unmet
  by design — A2 and A6–A12 remain proposed in `DECISIONS.md` Section 4. Do
  not ratify them to satisfy it.
- Boot acceptance from the earlier S21 work is still unverified (separate
  from S26); see `/home/hosi/dev/REA-Rufus/HANDOFF.md`.
