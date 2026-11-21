# packaging/

Distribution artefacts for furus: Debian, Arch and RPM metadata, plus the
polkit policy, D-Bus service and bus configuration, desktop entry, AppStream
metainfo and icon. Slice S26-T2 completes these definitions. `xtask dist`
(S26-T3) validates these files and stages them into the release bundle.

## Install

Install the native package for your distro from the directory holding the
downloaded files (the `./` makes your package manager use the local file):

* Ubuntu/Debian: `sudo apt install ./furus-*.deb`
* Fedora: `sudo dnf install ./furus-*.rpm`
* Arch Linux: `sudo pacman -U ./furus-*.pkg.tar.zst`

The `.rpm` and `.pkg.tar.zst` are no longer just metadata recipes: they are
built in CI by `.github/workflows/release.yml` from the single `cargo xtask
dist` tarball, with no Rust recompilation, and published alongside the tarball,
the `.deb` and a unified `SHA256SUMS` on every `v*` tag. "Verifying the service"
below covers the post-install D-Bus/polkit checks.

## Naming: why the files are `org.furuslinux.*`, not `org.furus.*`

The S26 specification writes the filenames and IDs as `org.furus.*`. That
namespace cannot be used: the shipped GUI and helper hardcode the bus name and
interface `org.furuslinux.Helper1`, the object path `/org/furuslinux/Helper1`,
the polkit action `org.furuslinux.write-device`, and the helper's `--dbus` CLI
switch (see `crates/furus-helper/src/dbus.rs` and
`crates/furus-gui/src/ipc/dbus.rs`). Using literal `org.furus.*` filenames or
action IDs would break the running system, so every file and ID here keeps the
`org.furuslinux.*` namespace. The required **properties** are still met: the
polkit action uses `auth_admin_keep`, and a D-Bus system.d configuration
restricts ownership of the well-known name to root. This is a deliberate,
documented deviation from the spec's literal names, also recorded in the
archived `docs/handoffs/HANDOFF-root-S27-archive.md`.

## What installs where

| Source file | Install path |
|---|---|
| `polkit/org.furuslinux.policy` | `/usr/share/polkit-1/actions/org.furuslinux.policy` |
| `dbus/org.furuslinux.Helper1.service` | `/usr/share/dbus-1/system-services/org.furuslinux.Helper1.service` |
| `dbus/org.furuslinux.Helper1.conf` | `/usr/share/dbus-1/system.d/org.furuslinux.Helper1.conf` |
| `org.furuslinux.Furus.desktop` | `/usr/share/applications/org.furuslinux.Furus.desktop` |
| `org.furuslinux.Furus.metainfo.xml` | `/usr/share/metainfo/org.furuslinux.Furus.metainfo.xml` |
| `org.furuslinux.Furus.svg` | `/usr/share/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg` |
| `deb/control` | `DEBIAN/control` inside the deb (`Architecture: any` is rewritten to `amd64`/`arm64` by dist per target) |
| `deb/postinst` | `DEBIAN/postinst` inside the deb (mode 0755) |
| `arch/PKGBUILD` | release-bundle metadata for Arch source builds |
| `rpm/furus.spec` | release-bundle metadata for RPM builds |
| `LICENSES.md` (repository root) | `/usr/share/licenses/furus-linux/LICENSES.md` |

Binaries, built and installed by `xtask dist` from the release build:

| Binary | Install path |
|---|---|
| `furus` (CLI) | `/usr/bin/furus` |
| `furus-gui` | `/usr/bin/furus-gui` |
| `furus-helper` | `/usr/libexec/furus-helper` (root-owned, 0755) |

## D-Bus ownership vs. authorization

The new `system.d` configuration (`dbus/org.furuslinux.Helper1.conf`)
restricts who may **own** the well-known name `org.furuslinux.Helper1` to the
root-run service. This is defence in depth: only the real helper can claim the
name on the system bus. It deliberately does **not** restrict who may **send**
messages to that name — the GUI runs as the ordinary user and must be able to
call `Execute` and `Cancel`. Method authorization is the helper's job: it
checks the `org.furuslinux.write-device` polkit action for the caller before
it reads a plan. A group-restricted bus policy would duplicate that decision
and could drift away from the polkit action, so it is not used. In the polkit
action, `auth_admin_keep` means an administrator's password is asked for once
and remembered for the rest of the session — a write is one deliberate act,
not one per sector.

## External tool dependencies

Following the runtime-check semantics of decision A4 (see the repository
`README.md` and `DECISIONS.md`): NTFS writing drives `mkntfs`/`mkfs.ntfs`
(`ntfs-3g` on Debian/Ubuntu; on Arch the privileged-container note installs
**both** `ntfs-3g` and `ntfsprogs`), ext2/3/4 writing drives `mke2fs`/
`e2fsck` (`e2fsprogs`), UDF writing drives `mkudffs` (`udftools`), and WIM/ESD
uses wimlib (`libwim15` on Debian, `wimlib` on Arch). FAT32 and exFAT are
written natively. These are declared as
`Recommends: ntfs-3g, e2fsprogs, udftools, libwim15` in `deb/control`, as
`optdepends` (`ntfs-3g`, `ntfsprogs`, `e2fsprogs`, `udftools`, `wimlib`) in
`arch/PKGBUILD`, and as `Recommends: ntfs-3g, e2fsprogs, udftools, wimlib,
polkit, fontconfig` in `rpm/furus.spec` (Fedora-correct names; the Debian-only
wimlib package name does not exist on Fedora). They are recommendations, not
hard dependencies, because A4 makes them runtime-checked: images that need no
external formatter work without them.

## Verifying the service

One-time, as root, on a machine with the files above installed:

```
systemctl reload dbus
pkaction --action-id org.furuslinux.write-device --verbose
```

Then, as a normal user (the plan file is one `furus plan` produced):

```
busctl --system call org.furuslinux.Helper1 /org/furuslinux/Helper1 \
  org.furuslinux.Helper1 Execute s "$(cat plan.json)"
busctl --system monitor org.furuslinux.Helper1
```

`Execute` answers with the session id (`s`) after polkit authentication and
plan validation; `Progress`, `Log` and `Done` arrive as signals. Cancel with:

```
busctl --system call org.furuslinux.Helper1 /org/furuslinux/Helper1 \
  org.furuslinux.Helper1 Cancel s "<session id>"
```

`Cancel` is scoped to the connection that started the run: the helper records
the caller's unique bus name at `Execute` time and answers `Cancel` from any
other connection (including a fresh `busctl` invocation) exactly as it answers
an unknown id, so it neither aborts the run nor confirms that the session
exists. A client that owns the run must keep its single connection open (the
desktop application does; a shell cannot, so use `pkexec` with the MVP
`--plan/--progress` interface when you need to interrupt a run by hand).

A caller polkit denies gets `org.freedesktop.DBus.Error.AccessDenied`; every
other refusal is `org.freedesktop.DBus.Error.Failed` prefixed with the
stable error name (`org.furuslinux.Error.Busy: …`,
`org.furuslinux.Error.InvalidPlan: <validator code>: …`).
