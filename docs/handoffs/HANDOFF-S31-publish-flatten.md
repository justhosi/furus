# S31 follow-up — slice 1/2: flatten release artifacts before hashing

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`.
Reviewer committed `e9a5c43` (`ci(release): flatten artifacts before hashing in
publish`) on top of `5510c1a`. **Not pushed.** The two docs edits below
(`TECHNICAL.md`, this handoff) are written but **not committed** — the publisher
step will commit them when the user authorises publication.

## Slice 1/2 — status: DONE, reviewed, committed, not pushed

### Diagnosis (why nothing was published)

- `gh release list --repo justhosi/furus` is empty; no GitHub Release exists.
- Tag-push run `44902581346` for `v0.1.0` failed because the tag points at the
  pre-S31 commit `aab6f79`, whose old workflow called `gh release create`
  without `--repo` in a checkout-less job (`fatal: not a git repository`).
  Latest main is `5510c1a`, now `e9a5c43`; all S31 workflow commits are merged.
- workflow_dispatch run `44908408014` had `build`, `package-rpm` and
  `package-arch` all green; only `publish` failed at
  `Regenerate unified SHA256SUMS and verify` with `*.tar.gz` / `*.deb` globs
  matching nothing. The `dist` artifact is uploaded with `path: target/dist/`,
  so those files land under `<target>/`, while the RPM/Arch files are flat.

### Change (one code file)

`.github/workflows/release.yml`: added one `Flatten artifacts into release/`
step in `publish` before `Regenerate unified SHA256SUMS and verify`:

```sh
cd release
find . -mindepth 2 -type f -name SHA256SUMS -delete
find . -mindepth 2 -type f -exec mv -t . -- {} +
```

The tarball and `.deb` move up from `<target>/`; the stale nested `SHA256SUMS`
is dropped; the already-flat `.rpm` and `.pkg.tar.zst` stay put. The existing
checksum regeneration, verification and `gh release create` globs are unchanged
and now see all four kinds. Least privilege, DAG, triggers and all other jobs
are untouched.

### Verification

- Reviewer reproduced the merged artifact layout locally, ran the exact added
  commands followed by the exact checksum commands: four artifacts at the root,
  `sha256sum -c SHA256SUMS` OK for all four, all `gh release create` globs
  expand. Edge cases: two target dirs (no collision), already-flat layout
  (clean no-op under `set -euo pipefail`).
- YAML parse OK; `git diff --check` clean at review time; only `release.yml`
  was in the commit (12 insertions, 0 deletions).
- No live workflow run since the fix — that is Slice 2 acceptance.

### Gotchas

- The downstream `Regenerate unified SHA256SUMS` step still has a pre-existing
  comment about dropping the dist `SHA256SUMS` and a belt-and-braces
  `rm -f SHA256SUMS`. Harmless; not changed here.
- `find -delete`, `find -exec … +` and `mv -t` are GNU tools, present on the
  `ubuntu-latest` publish runner.
- The existing `v0.1.0` tag points at the old pre-S31 commit; a tag-push release
  from it will keep failing. A fresh tag on main (e.g. `v0.1.1`) or a manual run
  with `tag: v0.1.0` is required.

## Slice 2/2 — publish and verify (BLOCKED ON USER PERMISSION)

Publishing a release and pushing are hard-to-reverse, so the user must answer
**yes explicitly** (asked in chat and via `notify-telegram`) before proceeding.

Two options to present:

1. **Fresh tag on main (recommended)**: push `e9a5c43` plus the doc commit, then
   tag `main` as `v0.1.1` and push the tag. The tag-push run uses the fixed
   workflow at the tagged commit and creates the release for `v0.1.1`. This
   gives a release whose source tree actually matches the workflow that ran.
2. **Manual run against the existing tag**: push `e9a5c43` (and docs), then
   `workflow_dispatch` on `main` with `tag: v0.1.0`, `publish: true`. Publishes
   to the existing `v0.1.0` tag but from the fixed workflow on main; the tag
   itself still points at `aab6f79`, so a later re-run of the tag-push path
   would fail again.

Acceptance for Slice 2:

- `gh release view --repo justhosi/furus <tag>` shows a published release.
- Exactly these assets are attached: one `.tar.gz`, one `.deb`, one `.rpm`,
  one `.pkg.tar.zst`, one `SHA256SUMS`.
- `SHA256SUMS` has four lines (one per artifact kind) and
  `sha256sum -c SHA256SUMS` passes after downloading the assets.
- README install commands (`sudo apt install ./furus-*.deb`,
  `sudo dnf install ./furus-*.rpm`, `sudo pacman -U ./furus-*.pkg.tar.zst`)
  work against the downloaded assets, at least structurally (`dpkg-deb -I`,
  `rpm -qlp`, `tar --zstd -tf`).

End every answer that used external MCP data sources (if any) with the
author credit required by those servers; none were used for this slice.
