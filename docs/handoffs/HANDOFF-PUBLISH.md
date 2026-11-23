# Handoff — v0.1.2-rc1 pre-release publication

## Authorization and decisions

- The user explicitly authorized publication on 2026-11-23 (conveyed to the
  publisher subagent by the launching session). No further permission is
  needed.
- Tag name: `v0.1.2-rc1` (user choice).
- GitHub Release: **prerelease** (user choice), title `v0.1.2-rc1 (pre-release)`,
  not marked latest. Existing tags `v0.1.0` and `v0.1.1` are untouched.
- No code changes are part of this slice. The S33–S36 implementation, the docs
  artifact-table update (`950f4d4`), and the workflow idempotency fix
  (`1edcbcf`) are already on `main`, each carrying `Reviewed-by: reviewer`.
  This is a docs-only record of the final, verified publication state.
- Later user decision (2026-11-23): extend the existing `v0.1.2-rc1`
  prerelease with dual-architecture deb/rpm packages and CI-built archives.
  The earlier publisher release had eight assets and a six-line `SHA256SUMS`.
  The final, verified release has ten assets: x86_64 and aarch64 `.tar.gz`,
  `.deb`, `.rpm` and Arch `.pkg.tar.zst` packages, the regenerated
  `SHA256SUMS`, and the untouched convenience `.zip`. The aarch64 `.tar.gz`
  and aarch64 Arch package are now attached, reversing the earlier decision
  to exclude them. `SHA256SUMS` is regenerated over exactly the eight CI
  packages (the `.zip` is excluded). This final slice creates no new tag, push,
  or code changes.

## Source

- Source commit (code + final gates): `b9600b8d37f25a33fdf3bcfc31261e0b5ca088d1`
  (`docs: finalize S36 label validation and log UX (final acceptance gate)`).
- The `v0.1.2-rc1` annotated tag object
  (`3059336d3e5d200dfde2af2e5bbe43345a629010` → `9d8e1e8…`) is unchanged;
  no tag was created or moved during publication.
- `main` has since advanced to `1edcbcf` (workflow idempotency fix), with
  `950f4d4` (docs artifact-table update) immediately before it; both carry
  `Reviewed-by: reviewer` and both are pushed to `origin/main`.
- Remote: `origin` = https://github.com/justhosi/furus, branch `main`. Before
  publication `main` was 17 commits ahead of `origin/main` and no remote
  `v0.1.2-rc1` tag existed.

## Final gate state (recorded, not re-run here)

S36 final gate green: fmt, clippy, workspace 1961 passed / 0 failed / 29
ignored (1990 total), helper 142/3 + 11, GUI 135, qa, size, `xtask ci` all
gates. `cargo-audit` skipped only because it is not installed. Manual live-hardware
sign-off remains open and is called out in the release notes.

## Artifacts (SHA-256 verified before upload)

| Asset | Origin | Size (bytes) | SHA-256 |
| --- | --- | --- | --- |
| `furus-0.1.1-aarch64-unknown-linux-gnu.tar.gz` | CI build (attached) | 8,075,590 | `4b474948fac7aeaf8064aec988d45cb1102801b4e59429955e44c6e3d3c0ef58` |
| `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz` | CI rebuild (replaced) | 8,245,670 | `13d4315855d2eb47595ae625b977a75cb41a06ade54539c40547ee9bd07cca92` |
| `furus-0.1.1-aarch64-unknown-linux-gnu.deb` | CI build (new) | 6,792,112 | `4de68c20d783f9992d747e7eb8e51f2e9df645501c3d21bd033fe9f56afae9b5` |
| `furus-0.1.1-x86_64-unknown-linux-gnu.deb` | CI build (new) | 6,483,916 | `21a26c9cdc570e756f543296ee3fbc1bb6b2c654af14f0b1260da5a5f7542922` |
| `furus-0.1.1-1.fc45.aarch64.rpm` | CI build (new) | 6,771,710 | `9e755107a27ab12cc9494fbfcfde0ece6897eb74e9545cac6bfa4ac8a413d3aa` |
| `furus-0.1.1-1.fc45.x86_64.rpm` | CI build (new) | 6,493,339 | `2cc9789844790f39539a3c8b5972570632f74584b71a1f1ee03d5db827e91483` |
| `furus-0.1.1-1-aarch64.pkg.tar.zst` | CI build (attached) | 8,506,201 | `15e8d292d6eea3b778a5939f07032d62f3c49b09059d6a8e3e1326cef0e9d630` |
| `furus-0.1.1-1-x86_64.pkg.tar.zst` | CI rebuild (replaced) | 8,237,634 | `f78b08fd9d4c2206375164b8441dbb2ddd42efcb5cb240c52ae4fcdf1f1fc0c4` |
| `SHA256SUMS` | regenerated (replaced, 8 bare-filename lines) | 828 | `9f67b7dacedf8ec8346c203f3f7f746ebd107fb028474eb1f7453aa39763c8ed` |
| `furus-0.1.1-x86_64-unknown-linux-gnu.zip` | initial local build (untouched) | 8,276,771 | `ad3034622ccfab21ad0bcddad6e0d07a8701473d087ffbfb47035026801a8676` |

Filenames retain `0.1.1` from `Cargo.toml`; `v0.1.2-rc1` is the prerelease
label, not a filename component. All CI-built assets come from the release
workflow. The x86_64 `.tar.gz` and Arch package were rebuilt by CI and replaced
the earlier locally built ones (whose binaries differed slightly). The aarch64
`.tar.gz` and aarch64 Arch package are now attached, reversing the earlier
decision to exclude them. The convenience `.zip` was untouched throughout and
its digest never changed. `SHA256SUMS` was regenerated with eight bare-filename
lines covering exactly the eight CI packages above (the `.zip` is excluded);
`sha256sum -c` reports all eight OK. The untracked `./build/` stays untracked
and untouched, and the tag and source commit are unchanged.

The earlier publisher release had eight assets and a six-line `SHA256SUMS`.
Workflow rerun `45183071221` attempt 2 still failed at `gh release create`
because reruns reuse the OLD workflow definition from the original tag ref
`9d8e1e8` — the idempotency fix exists only on `main`. A fresh
`workflow_dispatch` on the fixed `main` (run `45194237749`,
`gh workflow run release.yml --ref main -f tag=v0.1.2-rc1 -f publish=true`)
took the idempotent branch and refreshed all assets with
`gh release upload --clobber`, producing the ten-asset final state.

Final release state: https://github.com/justhosi/furus/releases/tag/v0.1.2-rc1
— prerelease `true`, draft `false`, `latest` remains `v0.1.1`.

## Scope / no pending publish action

The complete authorized publication is: the annotated `v0.1.2-rc1` tag, the
push of `main` and that tag to `origin`, and one prerelease on GitHub with the
ten assets listed above. The follow-up docs artifact-table update (`950f4d4`)
and workflow idempotency fix (`1edcbcf`) are already on `origin/main`. Nothing
beyond this is authorized or pending. `./build/` stays untracked; no force-push,
tag rewrite, deletion, or "latest" release change is in scope. This final docs
slice created no local commits, and no push, tag, or gate run is performed here.
