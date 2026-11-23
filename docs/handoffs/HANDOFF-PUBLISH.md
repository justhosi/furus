# Handoff — v0.1.2-rc1 pre-release publication

## Authorization and decisions

- The user explicitly authorized publication on 2026-11-23 (conveyed to the
  publisher subagent by the launching session). No further permission is
  needed.
- Tag name: `v0.1.2-rc1` (user choice).
- GitHub Release: **prerelease** (user choice), title `v0.1.2-rc1 (pre-release)`,
  not marked latest. Existing tags `v0.1.0` and `v0.1.1` are untouched.
- No code changes are part of this slice. The S33–S36 implementation and docs
  commits are already on `main`, each carrying `Reviewed-by: reviewer`. This is
  a docs-only record of the publication.

## Source

- Source commit (code + final gates): `b9600b8d37f25a33fdf3bcfc31261e0b5ca088d1`
  (`docs: finalize S36 label validation and log UX (final acceptance gate)`).
- The `v0.1.2-rc1` annotated tag points at the tip of `main` — the docs-only
  commit adding this handoff record on top of `b9600b8`.
- Remote: `origin` = https://github.com/justhosi/furus, branch `main`. Before
  publication `main` was 17 commits ahead of `origin/main` and no remote
  `v0.1.2-rc1` tag existed.

## Final gate state (recorded, not re-run here)

S36 final gate green: fmt, clippy, workspace 1961 passed / 0 failed / 29
ignored (1990 total), helper 142/3 + 11, GUI 135, qa, size, `xtask ci` all
gates. `cargo-audit` skipped only because it is not installed. Manual live-hardware
sign-off remains open and is called out in the release notes.

## Artifacts (SHA-256 verified before upload)

| Artifact | Size (bytes) | SHA-256 |
| --- | --- | --- |
| `target/dist/x86_64-unknown-linux-gnu/furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz` | 8,247,623 | `4522d3d13431a3fa000348df6d6aeef84f1a0556cfc3ba72bf49dc30617d551c` |
| `target/dist/x86_64-unknown-linux-gnu/SHA256SUMS` | 110 | (one line; matches the `.tar.gz` digest above) |
| `./build/furus-0.1.1-1-x86_64.pkg.tar.zst` | 8,247,948 | `12ace52428dead975c995719213970958378bcfd3f2be54d93503af9c3ee9d54` |
| `./build/furus-0.1.1-x86_64-unknown-linux-gnu.zip` | 8,276,771 | `ad3034622ccfab21ad0bcddad6e0d07a8701473d087ffbfb47035026801a8676` |

Filenames retain `0.1.1` from `Cargo.toml`; the `v0.1.2-rc1` tag is the
pre-release label. The untracked `./build/` directory is user-owned: it is read
only for these two artifacts and is never staged or deleted.

## Scope / no pending publish action

The complete authorized publication is: this docs-only handoff commit, the
annotated `v0.1.2-rc1` tag, pushing `main` and that tag to `origin`, and one
prerelease on GitHub with the four artifacts above. Nothing beyond this is
authorized or pending. `./build/` stays untracked; no force-push, tag rewrite,
deletion, or "latest" release change is in scope.
