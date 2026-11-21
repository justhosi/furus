Name:           rufus
# Version and target are overridable by the offline/local CI recipe build:
#   rpmbuild --define 'rufus_version 0.1.0' \
#            --define 'rufus_target x86_64-unknown-linux-gnu' -bb rufus.spec
# With no --define the defaults below keep a plain `rpmbuild -bb` working.
%{!?rufus_version:%global rufus_version 0.1.0}
%{!?rufus_target:%global rufus_target x86_64-unknown-linux-gnu}
# The dist binaries are pre-built release binaries with no debuginfo. Fedora's
# automatic debuginfo/debugsource subpackages would otherwise fail on an empty
# debugsourcefiles.list; disable them instead of recompiling anything here.
%global debug_package %{nil}
Version:        %{rufus_version}
Release:        1%{?dist}
Summary:        Native USB image writer for Linux
License:        GPL-3.0-or-later
URL:            https://github.com/justhosi/furus
# `cargo xtask dist` emits one exact-name bundle, rufus-<version>-<triple>.tar.gz,
# whose root is the staged FHS tree (usr/, DEBIAN/), not loose files. dist_target
# follows rufus_target, so Source0 always names the exact pre-built dist bundle.
%global dist_target %{rufus_target}
Source0:        rufus-%{version}-%{dist_target}.tar.gz
# For an aarch64 rebuild pass --define 'rufus_target aarch64-unknown-linux-gnu'
# and set BuildArch: aarch64.
BuildArch:      x86_64

Requires:       glibc >= 2.31
# Fedora names: wimlib (not Debian's libwim15); polkit/fontconfig are needed by
# the D-Bus helper and the Slint GUI at runtime. No Rust is rebuilt here.
Recommends:     ntfs-3g, e2fsprogs, udftools, wimlib, polkit, fontconfig

%description
rufus is a native utility for writing disk images to USB devices, with a
root-owned D-Bus helper mediating device access. FAT32 and exFAT are written
natively; NTFS, ext2/3/4, UDF and WIM/ESD images need the recommended external
tools (ntfs-3g, e2fsprogs, udftools, wimlib) available at write time.

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
