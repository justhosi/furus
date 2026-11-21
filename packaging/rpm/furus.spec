Name:           furus
# Version and target are overridable by the offline/local CI recipe build:
#   rpmbuild --define 'furus_version 0.1.1' \
#            --define 'furus_target x86_64-unknown-linux-gnu' -bb furus.spec
# With no --define the defaults below keep a plain `rpmbuild -bb` working.
%{!?furus_version:%global furus_version 0.1.1}
%{!?furus_target:%global furus_target x86_64-unknown-linux-gnu}
# BuildArch is overridable so the aarch64 lane can tag its RPM aarch64; the
# default keeps a plain `rpmbuild -bb` working as before.
%{!?furus_build_arch:%global furus_build_arch x86_64}
# The dist binaries are pre-built release binaries with no debuginfo. Fedora's
# automatic debuginfo/debugsource subpackages would otherwise fail on an empty
# debugsourcefiles.list; disable them instead of recompiling anything here.
%global debug_package %{nil}
Version:        %{furus_version}
Release:        1%{?dist}
Summary:        Native USB image writer for Linux
License:        GPL-3.0-or-later
URL:            https://github.com/justhosi/furus
# `cargo xtask dist` emits one exact-name bundle, furus-<version>-<triple>.tar.gz,
# whose root is the staged FHS tree (usr/, DEBIAN/), not loose files. dist_target
# follows furus_target, so Source0 always names the exact pre-built dist bundle.
%global dist_target %{furus_target}
Source0:        furus-%{version}-%{dist_target}.tar.gz
# For an aarch64 rebuild pass --define 'furus_target aarch64-unknown-linux-gnu'
# and override BuildArch with --define 'furus_build_arch aarch64', so the RPM
# is tagged aarch64.
BuildArch:      %{furus_build_arch}

Requires:       glibc >= 2.31
# Fedora names: wimlib (not Debian's libwim15); polkit/fontconfig are needed by
# the D-Bus helper and the Slint GUI at runtime. No Rust is rebuilt here.
Recommends:     ntfs-3g, e2fsprogs, udftools, wimlib, polkit, fontconfig

%description
furus is a native utility for writing disk images to USB devices, with a
root-owned D-Bus helper mediating device access. FAT32 and exFAT are written
natively; NTFS, ext2/3/4, UDF and WIM/ESD images need the recommended external
tools (ntfs-3g, e2fsprogs, udftools, wimlib) available at write time.

%prep
# The archive has no leading directory; -c creates it and cds into it.
%setup -q -c -n furus-%{version}

%build
# Release binaries are built by `cargo xtask dist` and shipped in Source0.

%install
# Sources are the paths inside the dist bundle's staged tree.
install -D -m 0755 usr/bin/furus        %{buildroot}%{_bindir}/furus
install -D -m 0755 usr/bin/furus-gui    %{buildroot}%{_bindir}/furus-gui
install -D -m 0755 usr/libexec/furus-helper %{buildroot}/usr/libexec/furus-helper
install -D -m 0644 usr/share/polkit-1/actions/org.furuslinux.policy \
  %{buildroot}%{_datadir}/polkit-1/actions/org.furuslinux.policy
install -D -m 0644 usr/share/dbus-1/system-services/org.furuslinux.Helper1.service \
  %{buildroot}%{_datadir}/dbus-1/system-services/org.furuslinux.Helper1.service
install -D -m 0644 usr/share/dbus-1/system.d/org.furuslinux.Helper1.conf \
  %{buildroot}%{_datadir}/dbus-1/system.d/org.furuslinux.Helper1.conf
install -D -m 0644 usr/share/applications/org.furuslinux.Furus.desktop \
  %{buildroot}%{_datadir}/applications/org.furuslinux.Furus.desktop
install -D -m 0644 usr/share/metainfo/org.furuslinux.Furus.metainfo.xml \
  %{buildroot}%{_datadir}/metainfo/org.furuslinux.Furus.metainfo.xml
install -D -m 0644 usr/share/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg \
  %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg
install -D -m 0644 usr/share/doc/furus/LICENSES.md \
  %{buildroot}%{_datadir}/licenses/furus/LICENSES.md

%files
%{_bindir}/furus
%{_bindir}/furus-gui
%attr(0755,root,root) /usr/libexec/furus-helper
%{_datadir}/polkit-1/actions/org.furuslinux.policy
%{_datadir}/dbus-1/system-services/org.furuslinux.Helper1.service
%{_datadir}/dbus-1/system.d/org.furuslinux.Helper1.conf
%{_datadir}/applications/org.furuslinux.Furus.desktop
%{_datadir}/metainfo/org.furuslinux.Furus.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg
%{_datadir}/licenses/furus/LICENSES.md

%changelog
* Thu Nov 19 2026 furus maintainers <mohamadzadeh@outlook.com> - 0.1.0-1
- Initial packaging.
