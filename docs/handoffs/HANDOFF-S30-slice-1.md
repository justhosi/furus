# S30 — slice 1/4: tag-triggered release workflow

Repo: `/home/hosi/dev/REA-Furus/furus`, branch `main`, base HEAD `a00a537`.
cargo/rustc 1.99.0 lives in `~/.cargo/bin`; prefix cargo commands with
`export PATH="$HOME/.cargo/bin:$PATH"`.

This is the handoff after **slice 1/4** of S30 (release automation). Slices are
gated one at a time (one command → reviewer → next command); do not batch them.
There is no prior S30 slice.

## Slice 1/4 — status: DONE (not committed, not pushed)

### Command executed

Add a `v*`-tag-triggered GitHub Actions workflow that builds and verifies the
release artifacts in a read-only job, then publishes them in a separate
write-scoped job using the built-in token.

### What changed

1. **NEW `.github/workflows/release.yml`** — a two-job workflow.
   - **Triggers.** `push` on tags `['v*']`, plus `workflow_dispatch` with one
     required string input `tag` (description "Existing tag to release, e.g.
     v0.1.0"). On a tag push we release `github.ref_name`; on a manual run
     `github.ref_name` is a branch, so the operator must name the tag.
   - **Top level `permissions: contents: read`.** Only the `release` job is
     granted `contents: write`.
   - **`build` job** (`permissions: contents: read`, `ubuntu-latest`): mirrors
     `ci.yml` exactly — pinned checkout, pinned `dtolnay/rust-toolchain`
     (1.99.0 + rustfmt/clippy), pinned cargo-deny 0.20.2 / cargo-audit 0.22.2
     installs, the full QA apt list, and the OVMF 4M symlink shim. Adds `dpkg`
     to the apt list (one short comment) so `dpkg-deb` exists and
     `cargo xtask dist` genuinely produces the `.deb` on the runner. Steps:
     `cargo xtask ci`, `cargo xtask qa`, `cargo xtask dist`, then upload
     `target/dist/` with pinned `actions/upload-artifact` (`name: dist`,
     `if-no-files-found: error`).
   - **`release` job** (`needs: build`, `permissions: contents: write`,
     `ubuntu-latest`): downloads the `dist` artifact with pinned
     `actions/download-artifact` to `dist/`, flattens `*.tar.gz`, `*.deb` and
     `SHA256SUMS` into `release/`, runs `sha256sum -c SHA256SUMS` there (fails
     on any mismatch), then publishes with `gh release create` using
     `GH_TOKEN: ${{ github.token }}`, tag/title from
     `github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name`,
     `--generate-notes`, and the three flattened asset files.

2. **NEW `docs/handoffs/HANDOFF-S30-slice-1.md`** — this file.

No other files were modified. `ci.yml`, all Rust sources, `Cargo.toml`,
`size-baseline.json`, `README.md`, `DECISIONS.md`, `TECHNICAL.md` and all other
docs are untouched. Nothing was committed and nothing was pushed.

### Design decisions

- **Two jobs for least privilege.** The build job runs unretrusted work
  (`cargo` builds/tests, `cargo install`, the QA suites) and therefore holds
  only a read token. Only the compact `release` job — download, checksum,
  publish — gets `contents: write`. A compromised build step or dependency
  cannot mint a release. Top-level permissions stay `contents: read`.
- **Artifacts come only from `cargo xtask dist`.** That command runs the
  release workspace build, packaging validation and size gates, stages the
  tree, writes a deterministic `tar.gz` (verified by reading it back), adds a
  `.deb` when `dpkg-deb` exists, and emits `SHA256SUMS` with one `<digest>  <name>`
  line per artifact using bare filenames. Nothing else in the tree is uploaded.
  `dpkg` is in the apt list specifically so the `.deb` is real, not skipped.
- **Flatten + re-verify before publishing.** `dist/` mirrors
  `target/dist/<triple>/`; flattening puts all files beside `SHA256SUMS`, whose
  bare filenames then resolve, and `sha256sum -c` makes any corruption between
  the two jobs a hard failure (the reproducibility invariant).
- **`gh` CLI over a third-party release action.** `gh` is preinstalled on
  `ubuntu-latest`; `gh release create` handles tag creation for the named tag
  and notes generation, so the workflow needs no extra dependency and no secret
  beyond the built-in `github.token`. `gh --title <tag>` keeps the title equal
  to the released tag.
- **Pin sources.** checkout `11d5960a…` and rust-toolchain `b725eda5…` are
  inherited verbatim from `ci.yml` (resolved there 2026-10-28). upload-artifact
  `ea165f8d…` and download-artifact `d3f86a10…` were resolved via `gh api` on
  2026-11-21. All carry a `# v4` / `# stable` comment per the repo convention;
  an in-file comment records the dates and the "re-resolve deliberately" rule.
- **No tag creation by the workflow** beyond what `gh release create <tag>`
  necessarily does for the supplied tag; no `unsafe`, no Rust changes.

### Verification (exact commands and results)

Run from the repo root. No build was necessary for this docs/workflow-only
slice; the release workflow itself was NOT executed locally (it needs a GitHub
tag and runner) and no `gh release create` was attempted.

1. YAML syntax — result: `YAML OK`.

   ```
   python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/release.yml")); print("YAML OK")'
   ```

2. Whitespace / patch hygiene — result: no output, exit 0.

   ```
   git diff --check
   ```

   Additional check for the new (untracked) file — output empty (no whitespace
   errors; exit 1 only means "files differ"):

   ```
   git diff --no-index --check /dev/null .github/workflows/release.yml
   ```

3. Working tree — result: exactly the two in-scope new files, nothing else.

   ```
   git status --short
   ?? .github/workflows/release.yml
   ?? docs/handoffs/HANDOFF-S30-slice-1.md
   ```

4. Structural sanity (extra, read-only) confirmed the parsed `on` block has
   `push` + `workflow_dispatch` (required string `tag`), top-level
   `permissions: contents: read`, and jobs `build` (needs none, read, 8 steps)
   and `release` (needs build, write, 3 steps).

No privileged step, reboot, network call, tag push or release publish was used.

### Acceptance criteria status

Met: two jobs with least-privilege permissions, correct triggers and dispatch
tag input, mirrored pinned toolchain/QA setup with `dpkg` added, dist-only
artifacts uploaded, checksum verification before publish, `gh release create`
with built-in token, explanatory comments, and only the two allowed files
created. YAML parses; `git diff --check` clean; `git status --short` shows only
the two new files.

### Gotchas

- **PyYAML reads `on:` as the boolean key `True`** (YAML 1.1). This is only a
  local-parsing quirk; GitHub Actions uses YAML 1.2 where `on` is a string. The
  structural check accounted for it. No change to the workflow is needed.
- **Single default triple.** `cargo xtask dist` with no `--target` builds the
  host triple only, so there is exactly one `SHA256SUMS` in the uploaded tree
  and flattening it into `release/` is unambiguous. If a later slice adds
  multi-triple dist output, the flatten step must concatenate/merge the
  `SHA256SUMS` files instead of `cp`-ing them (they would otherwise collide).
- **`.deb` presence depends on `dpkg-deb`.** The `dpkg` apt package is what
  makes the `.deb` real on the runner; if that install is ever removed the
  `release/*.deb` glob would fail to match and publication would break.
- **`sha256sum -c` is the correctness gate, not a formality** — it is what
  makes the upload/download round-trip trustworthy, so it must run before
  `gh release create` (it does, in a separate step).
- No CI/source/size-baseline/docs files outside this slice were touched.

### Remaining / next steps

1. Hand this slice to the reviewer; it is **not committed and not pushed**.
2. Slice 2/4 must be opened as its own gated command and reviewed separately —
   do not batch it with this slice.
3. The workflow's real behaviour (checksum gate, `gh release create`, asset
   upload) can only be verified on GitHub with an actual `v*` tag or a manual
   dispatch against an existing tag; that verification belongs to the final
   S30 slice / after publisher pushes, not to this local slice.
4. Confirm the pinned action SHAs still resolve before merging if significant
   time passes; re-resolve deliberately rather than bumping blindly.
