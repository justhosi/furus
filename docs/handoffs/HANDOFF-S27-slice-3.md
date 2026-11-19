# S27 — Slice 3/4 handoff (CI wiring, final verification, residual risks)

This file records the S27-T3 CI-wiring slice and the final S27 verification.
S27-T3 is implemented, reviewed and committed locally at `fa4a0d7`; all three
S27 slices are complete. The final slice (4/4, documentation only) brought the
root `HANDOFF.md` to the completed state. **Nothing has been pushed.**

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, HEAD `fa4a0d7`.
cargo/rustc 1.99.0 live in `~/.cargo/bin`; prefix cargo commands with
`PATH="$HOME/.cargo/bin:$PATH"`. Do not commit or push without explicit user
permission; `coder` never pushes.

## Local commits (all S27 work)

* `75563b4 feat(qa): implement S27-T1 xtask qa release gate`
* `e483305 docs(qa): document S21-S27 completion and automated QA gate`
* `fa4a0d7 ci(qa): install QA tools and run xtask qa on push and PR`

## CI wiring (S27-T3)

Only `.github/workflows/ci.yml` changed in this slice. It now:

* triggers on `push` and `pull_request` (previously it did not run on PRs);
* adds an "Install QA system tools" step: `sudo apt-get update` then
  `sudo apt-get install -y --no-install-recommends dosfstools ntfs-3g
  e2fsprogs udftools exfatprogs mtools qemu-system-x86 ovmf grub-common
  grub-pc-bin` — filesystem tools for the Tier 1 sparse-image suites, QEMU +
  OVMF for headless Tier 2 BIOS/UEFI boots, and `grub-mkimage`/`grub-pc-bin`
  for bootable GRUB2 BIOS images;
* shims Ubuntu's OVMF firmware names to the Arch-style paths the UEFI Tier 2
  harness hard-codes: only when `/usr/share/OVMF/OVMF_CODE_4M.fd` and
  `OVMF_VARS_4M.fd` exist, symlinks them to
  `/usr/share/edk2/x64/OVMF_CODE.4m.fd` and `OVMF_VARS.4m.fd`, so the UEFI
  check actually boots on `ubuntu-latest` instead of skipping;
* runs `cargo xtask ci` and then `cargo xtask qa` as the final gates.

Gate order and YAML were checked locally; no real GitHub runner was available
to exercise the `apt` install or the OVMF shim end to end.

## Final verification record (this host; `main` @ `fa4a0d7`)

With `PATH="$HOME/.cargo/bin:$PATH"`:

* `cargo xtask qa` → exit 0. **14 PASS**, **1 explicit SKIP**
  (`tier1/pipeline-loop` needs `--privileged`); all Tier 2 suites PASS,
  including `tier2/uefi-ntfs-ovmf`. No orphan QEMU processes after the run.
* `cargo xtask parity --check` → exit 0; `data/parity.csv` fresh, **2,709 rows**.
* `cargo xtask dist` → exit 0; produced `tar.gz` + `SHA256SUMS`; `.deb` skipped
  (`dpkg-deb` absent).
* `cargo xtask ci` → exit 0; `cargo-audit` skipped (not installed).

## Residual risks / gotchas

* **Unverified on a real runner.** The apt install list and OVMF symlink shim
  were inspected but not executed on `ubuntu-latest`; a package rename or a
  different OVMF install path there could make Tier 2 SKIP rather than run.
* **SeaBIOS-specific smoke.** The BIOS COM1 marker (`FURUS-QA-OK`) assumes this
  host's SeaBIOS; a different firmware may fail the smoke without a real
  regression.
* **`--privileged` extras unexercised.** Loop/mount suites are skipped on this
  non-root host; one `tier1/pipeline-loop` SKIP is expected and correct.
* **Absent local tools are SKIPs, not passes.** `cargo-audit` (audit gate) and
  `dpkg-deb` (`.deb` bundle) are not installed here. CI installs `cargo-audit`;
  it does not install `dpkg-deb`, so `.deb` is not produced in CI.
* **Parity byte-stability.** Do not touch `BY_MODULE`, `OVERRIDES` or generator
  logic; `parity --check` must stay exit 0 with 2,709 rows.
* **Stale `APPDIR`** must be removed at child spawn (handled by `xtask`).
* QEMU + OVMF are present here, so Tier 2 genuinely ran; absent tooling gives
  an explicit SKIP unless `--require-qemu`.

## Status and next action

* All S27 work is **committed locally and green**; **nothing pushed**.
* **Only remaining step:** ask the user for explicit permission to
  publish/push (via `notify-telegram` plus the `question` tool). Push only
  after that permission; do not invoke `publisher` without it.
