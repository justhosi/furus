# HANDOFF — furus/ repo, S26-T2 (Slice 2/4)

Repo: `/home/hosi/dev/REA-Rufus/furus`, branch `main`, base HEAD `9cd7d38`
(from the ratified-docs slice, S26-T1).
This file is written for a fresh context that must resume with no prior history.

## Current state

- S26-T2 is **complete**. Working tree has uncommitted changes confined to
  `packaging/` (plus this `HANDOFF.md`). The T1 documentation changes in
  `DECISIONS.md` and `LICENSES.md` are still present and uncommitted.
- **Nothing was committed and nothing was pushed.** Do not do either without
  explicit user permission (publisher step).
- No Rust or Cargo file was touched in T2. Do not touch Rust/Cargo,
  `DECISIONS.md`, `LICENSES.md` or `README.md` while finishing S26.

## What this slice (S26-T2) completed

Distribution packaging definitions are now complete and self-consistent so the
next slice's `xtask dist` can stage and validate them.

Modified:
- `packaging/dbus/org.rufuslinux.Helper1.service` — `Exec=` changed to
  `/usr/libexec/rufus-helper --dbus` (was
  `/usr/libexec/rufus-linux/rufus-helper --dbus`). `Name=`, `User=root`,
  `[D-Bus Service]` preserved.
- `packaging/polkit/org.rufuslinux.policy` — only `vendor_url` changed from the
  nonexistent `https://github.com/rufus-linux` to
  `https://github.com/justhosi/furus`. Action id
  `org.rufuslinux.write-device`, `allow_any=no`, `allow_inactive=no` and
  `allow_active=auth_admin_keep` verified unchanged.
- `packaging/README.md` — rewritten: naming-deviation section, complete
  "What installs where" table (helper now `/usr/libexec/rufus-helper`),
  D-Bus ownership-vs-authorization explanation, distro dependency paragraph,
  dist note, and the verification-commands section (ids were already correct).

Created:
- `packaging/dbus/org.rufuslinux.Helper1.conf` — system.d busconfig, well-formed
  XML with the freedesktop DOCTYPE, `root` may own the name, default policy
  denies `own` but allows `send_destination`; comments explain that polkit is
  the method gate.
- `packaging/org.rufuslinux.Rufus.desktop` — `[Desktop Entry]` with all required
  keys including `Keywords=`.
- `packaging/org.rufuslinux.Rufus.metainfo.xml` — AppStream component, CC0-1.0 /
  GPL-3.0-or-later, launchable, scalable icon, homepage, binary provides.
- `packaging/org.rufuslinux.Rufus.svg` — original 128x128 viewBox USB-stick
  with a write-arrow icon; no upstream artwork reused.
- `packaging/deb/control` — `Architecture: any` kept literally (dist rewrites),
  `Depends: libc6 (>= 2.31)`,
  `Recommends: ntfs-3g, e2fsprogs, udftools, libwim15`, no in-stanza comments.
- `packaging/deb/postinst` — mode **0755**, `#!/bin/sh` + `set -e`, guarded
  `chown root:root` / `chmod 0755` on `/usr/libexec/rufus-helper`, `exit 0`,
  no service-manager calls (container/chroot safe).
- `packaging/arch/PKGBUILD` — `rufus-linux` 0.1.0-1, both arches, GPL-3.0-or-later,
  `glibc>=2.31`, optdepends `ntfs-3g`/`ntfsprogs`/`e2fsprogs`/`udftools`/`wimlib`,
  plain `install` commands, no network in `package()`.
- `packaging/rpm/rufus.spec` — parseable spec with Requires/Recommends, install
  directives, `%files` with `%attr(0755,root,root) /usr/libexec/rufus-helper`
  and an aarch64 `BuildArch` note.

## Verification actually run (all passed)

From `/home/hosi/dev/REA-Rufus/furus`:

- `python3 -c 'import xml.etree.ElementTree as E,sys; [E.parse(p) for p in sys.argv[1:]]' <4 xml files>`
  → `XML OK: 4 files`, exit 0. (One early failure was an illegal `--` inside a
  busconfig XML comment; fixed by rewording to a semicolon.)
- `python3 -c 'import configparser,sys; [configparser.ConfigParser().read(p) for p in sys.argv[1:]]' <service> <desktop>`
  → `INI OK: 2 files`, exit 0.
- `git diff --check` → no output, exit 0. Extra Python scan found no trailing
  whitespace in any `packaging/` file.
- A 75-assertion content check (`/tmp/opencode/verify_invariants.py`) →
  `75/75 passed`, exit 0. It verifies every required token listed above,
  including that the old vendor URL is gone and `systemctl` is absent from
  postinst.
- `stat -c '%a %n' packaging/deb/postinst` → `755 packaging/deb/postinst`.
- `command -v dpkg-deb` → absent.

## Gotchas (read before continuing)

- **`org.rufuslinux.*` vs the spec's `org.rufus.*`**: the spec names the files
  and IDs `org.rufus.*`, but the shipped GUI/helper hardcode
  `org.rufuslinux.Helper1` (bus name + interface), `/org/rufuslinux/Helper1`,
  `org.rufuslinux.write-device` and `--dbus` (see `crates/rufus-helper/src/dbus.rs:130-151`
  and `crates/rufus-gui/src/ipc/dbus.rs:33-39`). Literally using `org.rufus.*`
  would break the runtime. Keep the `org.rufuslinux.*` namespace everywhere.
  The deviation is documented in `packaging/README.md` and here.
- **Helper path changed**: service `Exec=` and all distro metadata now use
  `/usr/libexec/rufus-helper` (root-owned 0755), not the old
  `/usr/libexec/rufus-linux/rufus-helper`. `xtask dist` must stage the helper
  binary to that path in its layouts.
- **`Architecture: any` is literal**: `xtask dist` must rewrite that single
  line in the staged `DEBIAN/control` to `amd64` or `arm64` per target. Do not
  change the source file to a concrete arch.
- **`dpkg-deb` is absent** in this environment: `xtask dist` must still produce
  the `.tar.gz` + `SHA256SUMS`, and only emit a `.deb` when `dpkg-deb` is found.
- Package name split: Debian/RPM package is `rufus`; Arch PKGBUILD / AppStream
  id / desktop name use `rufus-linux` / `org.rufuslinux.Rufus.desktop`. This is
  intentional and mirrors the existing identifiers.
- `cargo` is at `~/.cargo/bin/cargo`, not on the mise PATH; prefix
  `PATH="$HOME/.cargo/bin:$PATH"` for cargo commands.

## What remains in S26 (slices 3–4)

- **S26-T3** — `xtask/src/main.rs`: implement `cargo xtask dist
  [--target <triple>] [--out-dir <dir>]` — release builds + size gates, stage
  binaries (`rufus`, `rufus-gui` to `/usr/bin`; `rufus-helper` to
  `/usr/libexec`), all `packaging/` manifests/icons to the paths in the README
  table, rewrite `Architecture: any`, deterministic `.tar.gz`, a `.deb` when
  `dpkg-deb` exists, and `SHA256SUMS`.
- **S26-T4** — `xtask/src/main.rs`: unit/integration tests for `xtask dist`
  verifying staged layout, well-formed XML/INI in the manifests, and SHA-256
  digests.

## Exact next steps

1. Resume at **Slice 3/4 (S26-T3)** in `xtask/src/main.rs` only. Reuse the
   `packaging/` paths and tokens above as the validation contract; do not edit
   `packaging/` again unless a concrete mismatch is found.
2. Then **S26-T4**, then review.
3. Run the spec's verification with `PATH="$HOME/.cargo/bin:$PATH"`:
   `cargo xtask dist`, `cargo test -p xtask`, `cargo xtask ci`.
4. Ask the user before any commit/push. Never push from `coder`.

## Acceptance criteria still open

- From T1: "no unratified S00 architecture items remaining" stays formally
  unmet by design — A2 and A6–A12 remain proposed pending user decisions;
  recorded in `DECISIONS.md` Section 4. Do not ratify them to satisfy it.
- `cargo xtask dist` builds release binaries, verifies size gates, validates
  these `packaging/` files, and emits a complete bundle + `SHA256SUMS`, exit 0.
- `cargo test -p xtask` and `cargo xtask ci` pass cleanly.
- Boot acceptance from the prior S21 work is still unverified (separate from
  S26); see the workspace-level handoff at `/home/hosi/dev/REA-Rufus/HANDOFF.md`.
