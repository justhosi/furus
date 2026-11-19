Name:           rufus
Version:        0.1.0
Release:        1%{?dist}
Summary:        Native USB image writer for Linux
License:        GPL-3.0-or-later
URL:            https://github.com/justhosi/furus
# `cargo xtask dist` emits one exact-name bundle, rufus-<version>-<triple>.tar.gz,
# whose root is the staged FHS tree (usr/, DEBIAN/), not loose files.
%global dist_target x86_64-unknown-linux-gnu
Source0:        rufus-%{version}-%{dist_target}.tar.gz
# For an aarch64 rebuild set dist_target=aarch64-unknown-linux-gnu and BuildArch: aarch64.
BuildArch:      x86_64

Requires:       glibc >= 2.31
Recommends:     ntfs-3g, e2fsprogs, udftools, libwim15

%description
rufus is a native utility for writing disk images to USB devices, with a
root-owned D-Bus helper mediating device access. FAT32 and exFAT are written
natively; NTFS, ext2/3/4, UDF and WIM/ESD images need the recommended external
tools (ntfs-3g, e2fsprogs, udftools, libwim15) available at write time.

%prep
# The archive has no leading directory; -c creates it and cds into it.
%setup -q -c -n rufus-%{version}

%build
# Release binaries are built by `cargo xtask dist` and shipped in Source0.

%install
# Sources are the paths inside the dist bundle's staged tree.
install -D -m 0755 usr/bin/rufus        %{buildroot}%{_bindir}/rufus
install -D -m 0755 usr/bin/rufus-gui    %{buildroot}%{_bindir}/rufus-gui
install -D -m 0755 usr/libexec/rufus-helper %{buildroot}/usr/libexec/rufus-helper
install -D -m 0644 usr/share/polkit-1/actions/org.rufuslinux.policy \
  %{buildroot}%{_datadir}/polkit-1/actions/org.rufuslinux.policy
install -D -m 0644 usr/share/dbus-1/system-services/org.rufuslinux.Helper1.service \
  %{buildroot}%{_datadir}/dbus-1/system-services/org.rufuslinux.Helper1.service
install -D -m 0644 usr/share/dbus-1/system.d/org.rufuslinux.Helper1.conf \
  %{buildroot}%{_datadir}/dbus-1/system.d/org.rufuslinux.Helper1.conf
install -D -m 0644 usr/share/applications/org.rufuslinux.Rufus.desktop \
  %{buildroot}%{_datadir}/applications/org.rufuslinux.Rufus.desktop
install -D -m 0644 usr/share/metainfo/org.rufuslinux.Rufus.metainfo.xml \
  %{buildroot}%{_datadir}/metainfo/org.rufuslinux.Rufus.metainfo.xml
install -D -m 0644 usr/share/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg \
  %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg
install -D -m 0644 usr/share/doc/rufus/LICENSES.md \
  %{buildroot}%{_datadir}/licenses/rufus/LICENSES.md

%files
%{_bindir}/rufus
%{_bindir}/rufus-gui
%attr(0755,root,root) /usr/libexec/rufus-helper
%{_datadir}/polkit-1/actions/org.rufuslinux.policy
%{_datadir}/dbus-1/system-services/org.rufuslinux.Helper1.service
%{_datadir}/dbus-1/system.d/org.rufuslinux.Helper1.conf
%{_datadir}/applications/org.rufuslinux.Rufus.desktop
%{_datadir}/metainfo/org.rufuslinux.Rufus.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg
%{_datadir}/licenses/rufus/LICENSES.md

%changelog
* Thu Nov 19 2026 furus maintainers <mohamadzadeh@outlook.com> - 0.1.0-1
- Initial packaging.
