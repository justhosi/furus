Name:           rufus
Version:        0.1.0
Release:        1%{?dist}
Summary:        Native USB image writer for Linux
License:        GPL-3.0-or-later
URL:            https://github.com/justhosi/furus
Source0:        rufus-%{version}.tar.gz

# For aarch64 builds the dist target sets BuildArch: aarch64 in this spec.

Requires:       glibc >= 2.31
Recommends:     ntfs-3g, e2fsprogs, udftools, libwim15

%description
rufus is a native utility for writing disk images to USB devices, with a
root-owned D-Bus helper mediating device access. FAT32 and exFAT are written
natively; NTFS, ext2/3/4, UDF and WIM/ESD images need the recommended external
tools (ntfs-3g, e2fsprogs, udftools, libwim15) available at write time.

%prep
%setup -q

%build
# Release binaries are built by `cargo xtask dist` and shipped in Source0.

%install
install -D -m 0755 rufus        %{buildroot}%{_bindir}/rufus
install -D -m 0755 rufus-gui    %{buildroot}%{_bindir}/rufus-gui
install -D -m 0755 rufus-helper %{buildroot}/usr/libexec/rufus-helper
install -D -m 0644 org.rufuslinux.policy \
  %{buildroot}%{_datadir}/polkit-1/actions/org.rufuslinux.policy
install -D -m 0644 org.rufuslinux.Helper1.service \
  %{buildroot}%{_datadir}/dbus-1/system-services/org.rufuslinux.Helper1.service
install -D -m 0644 org.rufuslinux.Helper1.conf \
  %{buildroot}%{_datadir}/dbus-1/system.d/org.rufuslinux.Helper1.conf
install -D -m 0644 org.rufuslinux.Rufus.desktop \
  %{buildroot}%{_datadir}/applications/org.rufuslinux.Rufus.desktop
install -D -m 0644 org.rufuslinux.Rufus.metainfo.xml \
  %{buildroot}%{_datadir}/metainfo/org.rufuslinux.Rufus.metainfo.xml
install -D -m 0644 org.rufuslinux.Rufus.svg \
  %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.rufuslinux.Rufus.svg
install -D -m 0644 LICENSES.md \
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
