# packaging/

Distribution artefacts (deb, rpm, AppImage, polkit policy, D-Bus service,
desktop file, AppStream metainfo, man page).

Slice S01 reserved the directory; S26 adds `xtask dist` for the rest. The
two files below are the S06 privileged-service pieces and are install-ready
today.

## What installs where

| File | Install path |
|---|---|
| `polkit/org.rufuslinux.policy` | `/usr/share/polkit-1/actions/org.rufuslinux.policy` |
| `dbus/org.rufuslinux.Helper1.service` | `/usr/share/dbus-1/system-services/org.rufuslinux.Helper1.service` |
| the helper binary | `/usr/libexec/rufus-linux/rufus-helper` (the `Exec=` path) |

No `/usr/share/dbus-1/system.d/` file is needed: the bus lets any user send
a message to `org.rufuslinux.Helper1`, and **polkit** is the gate — the
helper checks `org.rufuslinux.write-device` for the caller before it reads
a plan. Do not add a bus policy that allows only a group unless that group
is also the one the policy action names.

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

A caller polkit denies gets `org.freedesktop.DBus.Error.AccessDenied`; every
other refusal is `org.freedesktop.DBus.Error.Failed` prefixed with the
stable code (`busy: …`, `invalid_plan: …`).
