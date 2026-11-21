# S31 — slice 1/4: offline/local RPM + Arch recipes from the dist tarball

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, base HEAD `aab6f79`
(`aab6f7965776e84e8ec5242012d2617bbe72370f`).
cargo/rustc 1.99.0 lives in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the handoff after **slice 1/4** of S31. Slices are gated one at a time
(one command → reviewer → next command); do not batch them. Slice 1 only
prepares the two native package recipes and the validating contract so a later
slice can wire them into offline/local CI. **Nothing was committed or pushed.**

## Slice 1/4 — status: DONE (not committed, not pushed)

### Command executed

Make `packaging/rpm/rufus.spec` and `packaging/arch/PKGBUILD` build a
ready-to-install binary package entirely from the pre-built
`target/dist/<triple>/rufus-<version>-<triple>.tar.gz` emitted by
`cargo xtask dist`, with no Rust recompilation and no rpmbuild/makepkg
warnings or errors. Update the one xtask validator whose token contract has to
change. Record this handoff.

### Exact changes (only these four files)

1. **`packaging/rpm/rufus.spec`** (modified)
   - Added overridable macros with safe defaults:
     `%{!?rufus_version:%global rufus_version 0.1.0}` and
     `%{!?rufus_target:%global rufus_target x86_64-unknown-linux-gnu}`.
     Both are set *before* spec parsing by
     `rpmbuild --define 'rufus_version X' --define 'rufus_target T'`, so the
     defaults fire only when the define is absent.
   - `Version: %{rufus_version}`; `%global dist_target %{rufus_target}`;
     `Source0: rufus-%{version}-%{dist_target}.tar.gz` still names the exact
     dist tarball. `%setup -q -c -n rufus-%{version}` and all ten `install -D`
     lines and all ten `%files` entries are unchanged.
   - `Recommends:` now reads
     `ntfs-3g, e2fsprogs, udftools, wimlib, polkit, fontconfig` — Fedora-correct
     names; Debian-only `libwim15` is gone (also updated in `%description`).
     The three originally required tokens stay on the `Recommends:` line.
   - Added `%global debug_package %{nil}`. Without it Fedora 45 / RPM 6.1
     auto-generates a `rufus-debugsource` subpackage whose `debugsourcefiles.list`
     is empty (the dist binaries carry no debuginfo), which is a **fatal**
     `error: Empty %files file`. Disabling it is correct here: nothing is
     recompiled, so there is no debuginfo to split out.
   - `BuildArch: x86_64` is unchanged (see Gotchas).
2. **`packaging/arch/PKGBUILD`** (modified)
   - `pkgver=${rufus_version:-0.1.0}`. It deliberately does **not** read the
     `pkgver` environment variable: `/usr/bin/makepkg:1252` unsets `pkgver`
     (a `pkgbuild_schema_strings` name) before sourcing PKGBUILD, so
     `pkgver=${pkgver:-...}` silently falls back to the default. `rufus_version`
     is a non-schema name and also matches the RPM recipe's override name.
   - `_target=${_target:-x86_64-unknown-linux-gnu}` (already present) keeps
     selecting the dist tarball; `_target` is not unset by makepkg and its
     override was verified.
   - Added `sha256sums=('SKIP')` with an inline comment: the dist tarball is
     already verified against `SHA256SUMS` by the release workflow before it
     reaches this recipe, so `SKIP` is deliberate, not a missing entry.
   - Added `'polkit'` and `'fontconfig'` to `optdepends`; the five required
     tokens (`ntfs-3g`, `ntfsprogs`, `e2fsprogs`, `udftools`, `wimlib`) remain.
   - Added `options=(!strip)`. The binaries arrive stripped from
     `cargo xtask dist`; makepkg's tidy step otherwise re-strips them and runs
     `gdb-add-index`, which printed misleading `No debugging symbols` /
     `No index was created` error lines. No install path or mode changed.
3. **`xtask/src/main.rs`** (modified — one validator only)
   - `validate_rpm_spec` now requires `wimlib` instead of `libwim15` on the
     `Recommends:` line (with a comment explaining the split).
     `validate_deb_control` still requires `libwim15` (correct for Debian), and
     `validate_arch_pkgbuild` still requires all five original tokens. No other
     xtask behaviour, no test changes: `real_packaging_xml_and_ini_files_validate`
     already reads the real spec and now passes with the new token.
4. **NEW `docs/handoffs/HANDOFF-S31-slice-1.md`** — this file.

No other file was created or edited. In particular `.github/workflows/release.yml`,
`README.md`, `packaging/README.md`, `TECHNICAL.md`, `Cargo.toml`, other Rust
sources, size baselines and prior handoffs were left untouched. No commit, no
push, no tag, no GitHub Actions workflow was run.

### Verification (exact commands and results)

All from the repo root with `export PATH="$HOME/.cargo/bin:$PATH"` unless noted.

1. `cargo xtask ci` → **exit 0; `ci: all gates passed`**. Notable lines:
   `contract: all identifiers match the single source of truth` (including
   `PASS packaging/arch/PKGBUILD` and `PASS packaging/rpm/rufus.spec` for
   `/usr/libexec/rufus-helper`), `size: within committed baseline allowance,
   all budgets OK`, `advisories ok, bans ok, licenses ok, sources ok`.
   `SKIP (not installed): cargo-audit` is pre-existing in this environment and
   treated as a skip, not a failure. Size numbers unchanged: rufus 1,810,152 B,
   rufus-helper 1,406,296 B, rufus-gui 12,774,280 B.
2. `cargo xtask dist` → **exit 0**. Output includes
   `dist: validated 11 packaging files` (so the updated RPM validator passes
   against the real spec), and
   `dist: wrote .../target/dist/x86_64-unknown-linux-gnu/rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz`.
   `skip .deb: dpkg-deb not available` locally (pre-existing; the release
   workflow installs `dpkg`). Tarball SHA256 before and after a second dist run
   was identical: `835947d600402c060fbcde8e3eae0d27e0f2c67132c6f5d41e3ed213f23fcc7d`
   — the artifact is deterministic and unaffected by these recipe edits.
3. Native Arch test, as non-root (`uid=1000(hosi)`), from a clean temp dir
   outside the repo containing only `PKGBUILD` + the tarball:

   ```
   T=/tmp/opencode/s31-arch-test
   rm -rf "$T"; mkdir -p "$T"
   cp packaging/arch/PKGBUILD "$T/"
   cp target/dist/x86_64-unknown-linux-gnu/rufus-0.1.0-x86_64-unknown-linux-gnu.tar.gz "$T/"
   cd "$T"
   makepkg -f --noconfirm --skipchecksums
   ```

   → **exit 0**, `Making package: rufus-linux 0.1.0-1`,
   `Finished making: rufus-linux 0.1.0-1`, produced
   `rufus-linux-0.1.0-1-x86_64.pkg.tar.zst`. No gdb-add-index errors. The single
   `WARNING: Skipping verification of source file checksums` comes only from the
   explicit `--skipchecksums` flag; a separate run with plain
   `makepkg -f --noconfirm` also exited 0 with **no warnings at all**, because
   `sha256sums=('SKIP')` is present. `tar --zstd -tf` confirmed all ten paths:
   `usr/bin/rufus`, `usr/bin/rufus-gui`, `usr/libexec/rufus-helper`,
   `usr/share/polkit-1/actions/org.rufuslinux.policy`,
   `usr/share/dbus-1/system-services/org.rufuslinux.Helper1.service`,
   `usr/share/dbus-1/system.d/org.rufuslinux.Helper1.conf`,
   `usr/share/applications/org.rufuslinux.Rufus.desktop`,
   `usr/share/metainfo/org.rufuslinux.Rufus.metainfo.xml`,
   `usr/share/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg`,
   `usr/share/licenses/rufus-linux/LICENSES.md`.
   `.PKGINFO` confirms `pkgver = 0.1.0-1` and all seven `optdepend` entries.
   Override checks: `rufus_version=9.9.9 _target=x86_64-unknown-linux-gnu
   makepkg -f --noconfirm --skipchecksums` produced `rufus-linux-9.9.9-1-x86_64.pkg.tar.zst`;
   `_target=aarch64-unknown-linux-gnu` successfully consumed a tarball renamed
   to that target (see Gotchas for the produced package arch).
4. Fedora RPM test in Docker (daemon 29.9.2, `fedora:latest` pulled —
   Fedora release 45, RPM 6.1.0):

   ```
   docker run -d --name s31-fedora fedora:latest sleep 3600
   docker exec s31-fedora dnf install -y rpm-build tar gzip
   mkdir -p /work/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
   # docker cp packaging/rpm/rufus.spec -> /work/SPECS/rufus.spec
   # docker cp the dist .tar.gz          -> /work/SOURCES/
   docker exec s31-fedora rpmbuild -bb --define '_topdir /work' \
     --define 'rufus_version 0.1.0' \
     --define 'rufus_target x86_64-unknown-linux-gnu' /work/SPECS/rufus.spec
   ```

   → **exit 0**, `Wrote: /work/RPMS/x86_64/rufus-0.1.0-1.fc45.x86_64.rpm`.
   A grep for genuine `warning:` / `error:` / `RPM build errors` lines returned
   `(none)`; `check-files` reported no unpackaged files. No `cargo`/`rustc`/
   `Compiling` line appears anywhere in the build log — the `%build` section is
   only comments, so there is zero Rust recompilation.
   `rpm -qlp` listed exactly the same ten paths as the Arch package (with the
   RPM license path `usr/share/licenses/rufus/LICENSES.md`).
   `rpm -qpR` shows `glibc >= 2.31` plus ELF-derived needs including
   `libfontconfig.so.1` and `libwim.so.15`; `rpm -qp --recommends` shows exactly
   `e2fsprogs fontconfig ntfs-3g polkit udftools wimlib` — no `libwim15`.
   Re-running with no `--define` produced the same default
   `rufus-0.1.0-1.fc45.x86_64.rpm`; re-running with
   `--define 'rufus_version 9.9.9'` produced `rufus-9.9.9-1.fc45.x86_64.rpm`,
   confirming both override paths.
5. `git diff --check` → clean (no output, exit 0).

### Gotchas

- **Arch override variable is `rufus_version`, not `pkgver`.** makepkg unsets
  `pkgver` before sourcing the PKGBUILD, so `pkgver=... makepkg ...` is silently
  ignored. Slice 2 must set `rufus_version` and `_target` in the environment.
- **RPM overrides are `--define`, not env vars.** Use
  `--define 'rufus_version <v>' --define 'rufus_target <triple>'`; plain
  `rpmbuild -bb` still works via the safe defaults.
- **`BuildArch` is still hardcoded to `x86_64`.** Version and target are
  parameterized, but architecture is not. An aarch64 RPM still needs the spec
  edited to `BuildArch: aarch64` (the comment in the spec says so). Raising this
  to a third define is a separate, deliberately out-of-scope change.
- **`_target` selects the tarball, not the package arch.** makepkg derives the
  package architecture from the host `CARCH`/`arch` array. The aarch64 override
  test ran on x86_64 and therefore produced an `x86_64`-labelled package; a real
  aarch64 package must be built on an aarch64 runner.
- **`sha256sums=('SKIP')` is intentional.** Do not replace it with a real hash
  computed at recipe-build time: the release workflow already verifies the
  tarball against `SHA256SUMS`, and adding a second hash would couple the recipe
  to a specific artifact build. Plain `makepkg` is clean with `SKIP`.
- **`options=(!strip)` and `%global debug_package %{nil}` are load-bearing.**
  Removing either reintroduces the gdb-add-index "No debugging symbols" errors
  (Arch) or the fatal empty-debugsource error (Fedora). Keep both while the
  payload is a pre-built, stripped dist tarball.
- **`cargo-audit` SKIP and `dpkg-deb` skip are pre-existing** environment facts,
  not regressions from this slice. No .deb was produced locally.
- **Weak vs strong deps.** `polkit`/`fontconfig` are on `Recommends:`/`optdepends`
  as requested. rpmbuild additionally derives strong Requires from the ELF
  binaries (`libfontconfig.so.1`, `libwim.so.15`, glibc symbols); those are
  automatic and expected, not hand-authored metadata.

### Remaining / next steps

1. Hand this slice to the reviewer; it is **not committed and not pushed**.
2. Slice 2/4 (separate gated command) is expected to wire these recipes into
   `.github/workflows/release.yml`: build RPM with the two `rpmbuild --define`
   flags and Arch with the two environment overrides, from the already-uploaded
   `dist` artifact, with no Rust rebuild. Do not batch with slice 1.
3. Slice 3/4 is expected to update the documentation (including
   `packaging/README.md`, which still says `libwim15` for RPM — not touched here
   because it is out of scope). Slice 4/4 handles publication.
4. If a later change adds a `rufus_arch` define, revisit `BuildArch` and the
   aarch64 path; nothing in this slice assumed cross-compilation.
