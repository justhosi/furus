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
- Later user decision (2026-11-23): extend the existing `v0.1.2-rc1`
  prerelease with dual-architecture deb/rpm packages. Replace the previously
  attached locally built x86_64 `.tar.gz` and Arch `.pkg.tar.zst` with the
  CI-built versions, add x86_64 and aarch64 `.deb` and `.rpm`, and keep the
  convenience `.zip` untouched. Regenerate `SHA256SUMS` over exactly the six
  chosen packages (the `.zip` is excluded); do not attach an aarch64 `.tar.gz`
  or `.pkg.tar.zst`. No new tag, push, or code changes.

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

| Asset | Origin | Size (bytes) | SHA-256 |
| --- | --- | --- | --- |
| `furus-0.1.1-x86_64-unknown-linux-gnu.tar.gz` | CI rebuild (replaced) | 8,245,673 | `13f0f63ce758ee613a6052260d9f3795b65ddf326da9342788602491dcd0757e` |
| `furus-0.1.1-x86_64-unknown-linux-gnu.deb` | CI build (new) | 6,484,040 | `cb5eebc7b514be18abe3709163152780e3de86433265c366061e4126666c57b1` |
| `furus-0.1.1-1.fc45.x86_64.rpm` | CI build (new) | 6,493,349 | `d83d2b49d4fc0e3adc233ae41aec3dcfb34d5214c74ac051db37a749395978f1` |
| `furus-0.1.1-1-x86_64.pkg.tar.zst` | CI rebuild (replaced) | 8,237,635 | `075b7c8776cc90ba9786e77c69b8a539482615394de7f4f340cd5c9e45ec8f59` |
| `furus-0.1.1-aarch64-unknown-linux-gnu.deb` | CI build (new) | 6,792,006 | `869bcac3c7a77e1a50283b4b31eac72211a2d1418007da6149897e2b048696e3` |
| `furus-0.1.1-1.fc45.aarch64.rpm` | CI build (new) | 6,771,713 | `a224409b2d4cc5df35dab1c11dc0d9ff8141d41bab6c71005bfe5b925dc91abe` |
| `furus-0.1.1-x86_64-unknown-linux-gnu.zip` | initial local build (untouched) | 8,276,771 | `ad3034622ccfab21ad0bcddad6e0d07a8701473d087ffbfb47035026801a8676` |
| `SHA256SUMS` | regenerated (replaced, 6 bare-filename lines) | 617 | `1c660aaae03c8bf0fddc6d40a25fda5bbce035d2cd434860491168cb65601361` |

Filenames retain `0.1.1` from `Cargo.toml`; `v0.1.2-rc1` is the prerelease
label, not a filename component. All CI-built assets come from tag-push run
`45183071221`, whose publish step failed only because the release already
existed. The CI x86_64 `.tar.gz` and Arch package replaced the earlier locally
built ones because their binaries differ slightly from CI's. `SHA256SUMS`
covers exactly the six packages above (x86_64 `.tar.gz`/`.deb`/`.rpm`/Arch plus
aarch64 `.deb`/`.rpm`) and deliberately excludes the convenience `.zip`. No
aarch64 `.tar.gz` or `.pkg.tar.zst` is attached. The untracked `./build/` stays
untracked and untouched, and the tag and source commit are unchanged.

## Scope / no pending publish action

The complete authorized publication is: this docs-only handoff commit, the
annotated `v0.1.2-rc1` tag, pushing `main` and that tag to `origin`, and one
prerelease on GitHub with the eight assets listed above. Nothing beyond this
is authorized or pending. `./build/` stays untracked; no force-push, tag
rewrite, deletion, or "latest" release change is in scope.
