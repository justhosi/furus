# Handoff — S31 Slice 2/2: publish release v0.1.1

## State

VERIFIED COMPLETE. The user explicitly approved publishing (chose "Yes — fresh
v0.1.1 tag (Recommended)") in chat and via Telegram.

- Publisher committed docs as `77ec8cf` (`docs: record S31 release publish fix
  and handoff`) on top of reviewer's `e9a5c43` (flatten fix).
- Pushed `main` to `origin` (https://github.com/justhosi/furus).
- Created annotated tag `v0.1.1` (tag object `ce10bc0`, target `77ec8cf`) and
  pushed only that tag. `v0.1.0` was not moved.
- Tag push triggered release workflow run `44917081484`. All four jobs passed:
  `build` (16m8s), `package-rpm` (41s), `package-arch` (32s), `publish` (9s).
  The new `Flatten artifacts into release/` step worked in CI.

## Verified release

`gh release view v0.1.1 --repo justhosi/furus` → published, not draft/prerelease.
URL: https://github.com/justhosi/furus/releases/tag/v0.1.1

Five assets, all `state: uploaded`, download count 0:

| Asset | GitHub SHA-256 digest |
| --- | --- |
| `furus-0.1.0-x86_64-unknown-linux-gnu.tar.gz` | `5e76e96fabc10be0c2d561af5a0100be0dc2afbc1ffa6c7b22e897816a3403d0` |
| `furus-0.1.0-x86_64-unknown-linux-gnu.deb` | `1b6b2563dc48ad69e58cbc9ca05fd5b4a75c5154c6116e68fbb7d16e9efaf685` |
| `furus-0.1.0-1.fc45.x86_64.rpm` | `f4d8c6f918e47d5be09bde0c9de18e081d5f4e0dc5a30e13778798bf886423ec` |
| `furus-linux-0.1.0-1-x86_64.pkg.tar.zst` | `6ad9838dfdcad6abaa5ca1b17475b13969ab45a6f792171f888e27156fc08d21` |
| `SHA256SUMS` | (4 lines, digests above) |

`SHA256SUMS` downloaded from the release matches all four asset digests
exactly. The original Slice 2 acceptance criteria are met.

## Gotchas / stale docs

- HANDOFF-S31-publish-flatten.md says remote `v0.1.0` points at `aab6f79`;
  the actual tag object is `e5a73cd` (commit `aab6f79`). Harmless but stale.
- README.md line 247 still says the workflow "has not yet been executed
  end-to-end". It has now been executed successfully.
- README.md lines 393-404 and packaging/README.md lines 13-15 use `furus-*`
  install wildcards, which match the actual v0.1.1 asset names.

## New work: full rebrand (user decision, 2026-11-21)

User pointed out package names should be `furus-*.deb`, `furus-*.rpm`,
`furus-*.pkg.tar.zst` and chose **Full rebrand** when asked about scope:
rename binaries, D-Bus names and service files too, not only artifact
filenames. Investigation so far:

- `xtask/src/main.rs:1465` builds the dist stem as
  `furus-{version}-{triple}` (also used for `.deb` at line 1478).
- `packaging/rpm/furus.spec`: `Name: furus`, `Source0: furus-%{version}-...`,
  `%setup -n furus-%{version}`, installs `furus-gui`/`furus-helper`.
- `packaging/arch/PKGBUILD`: `pkgname=furus-linux`,
  `source=("furus-${pkgver}-${_target}.tar.gz")`.
- Binaries, D-Bus interface/service names, desktop/metainfo/polkit files and
  install paths consistently use `furus` / `org.furuslinux.*`.

Unresolved decisions requiring user input before implementation:
1. Whether to keep, replace or delete the already-published v0.1.1 release
   (public URL above; 0 downloads) and how to version the rebranded release.
2. Exact rebrand boundary: crate names (`furus-core`, `furus-gui`, ...) and
   D-Bus/polkit namespace vs only user-visible names and install paths.

No rebrand code has been written. Follow global AGENTS.md slicing rules:
diagnose → plan → coder → reviewer → permissions before publisher/publication.
