# packaging/

Distribution artefacts for furus: Debian, Arch and RPM metadata, plus the
polkit policy, D-Bus service and bus configuration, desktop entry, AppStream
metainfo and icon. Slice S26-T2 completes these definitions. `xtask dist`
(S26-T3) validates these files and stages them into the release bundle.

## Naming: why the files are `org.rufuslinux.*`, not `org.rufus.*`

The S26 specification writes the filenames and IDs as `org.rufus.*`. That
namespace cannot be used: the shipped GUI and helper hardcode the bus name and
interface `org.rufuslinux.Helper1`, the object path `/org/rufuslinux/Helper1`,
the polkit action `org.rufuslinux.write-device`, and the helper's `--dbus` CLI
switch (see `crates/rufus-helper/src/dbus.rs` and
`crates/rufus-gui/src/ipc/dbus.rs`). Using literal `org.rufus.*` filenames or
action IDs would break the running system, so every file and ID here keeps the
`org.rufuslinux.*` namespace. The required **properties** are still met: the
polkit action uses `auth_admin_keep`, and a D-Bus system.d configuration
restricts ownership of the well-known name to root. This is a deliberate,
documented deviation from the spec's literal names, also recorded in the
archived `docs/handoffs/HANDOFF-root-S27-archive.md`.

## What installs where

| Source file | Install path |
|---|---|
| `polkit/org.rufuslinux.policy` | `/usr/share/polkit-1/actions/org.rufuslinux.policy` |
| `dbus/org.rufuslinux.Helper1.service` | `/usr/share/dbus-1/system-services/org.rufuslinux.Helper1.service` |
| `dbus/org.rufuslinux.Helper1.conf` | `/usr/share/dbus-1/system.d/org.rufuslinux.Helper1.conf` |
| `org.rufuslinux.Rufus.desktop` | `/usr/share/applications/org.rufuslinux.Rufus.desktop` |
| `org.rufuslinux.Rufus.metainfo.xml` | `/usr/share/metainfo/org.rufuslinux.Rufus.metainfo.xml` |
| `org.rufuslinux.Rufus.svg` | `/usr/share/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg` |
| `deb/control` | `DEBIAN/control` inside the deb (`Architecture: any` is rewritten to `amd64`/`arm64` by dist per target) |
| `deb/postinst` | `DEBIAN/postinst` inside the deb (mode 0755) |
| `arch/PKGBUILD` | release-bundle metadata for Arch source builds |
| `rpm/rufus.spec` | release-bundle metadata for RPM builds |
| `LICENSES.md` (repository root) | `/usr/share/licenses/rufus-linux/LICENSES.md` |

Binaries, built and installed by `xtask dist` from the release build:

| Binary | Install path |
|---|---|
| `rufus` (CLI) | `/usr/bin/rufus` |
| `rufus-gui` | `/usr/bin/rufus-gui` |
| `rufus-helper` | `/usr/libexec/rufus-helper` (root-owned, 0755) |

## D-Bus ownership vs. authorization

The new `system.d` configuration (`dbus/org.rufuslinux.Helper1.conf`)
restricts who may **own** the well-known name `org.rufuslinux.Helper1` to the
root-run service. This is defence in depth: only the real helper can claim the
name on the system bus. It deliberately does **not** restrict who may **send**
messages to that name — the GUI runs as the ordinary user and must be able to
call `Execute` and `Cancel`. Method authorization is the helper's job: it
checks the `org.rufuslinux.write-device` polkit action for the caller before
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
`arch/PKGBUILD`, and as `Recommends: ntfs-3g, e2fsprogs, udftools, libwim15`
in `rpm/rufus.spec`. They are recommendations, not hard dependencies, because
A4 makes them runtime-checked: images that need no external formatter work
without them.

## Verifying the service

One-time, as root, on a machine with the files above installed:

```
systemctl reload dbus
pkaction --action-id org.rufuslinux.write-device --verbose
```

Then, as a normal user (the plan file is one `rufus plan` produced):

```
busctl --system call org.rufuslinux.Helper1 /org/rufuslinux/Helper1 \
  org.rufuslinux.Helper1 Execute s "$(cat plan.json)"
busctl --system monitor org.rufuslinux.Helper1
```

`Execute` answers with the session id (`s`) after polkit authentication and
plan validation; `Progress`, `Log` and `Done` arrive as signals. Cancel with:

```
busctl --system call org.rufuslinux.Helper1 /org/rufuslinux/Helper1 \
  org.rufuslinux.Helper1 Cancel s "<session id>"
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
stable error name (`org.rufuslinux.Error.Busy: …`,
`org.rufuslinux.Error.InvalidPlan: <validator code>: …`).
