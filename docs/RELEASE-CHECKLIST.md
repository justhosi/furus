# Release checklist

Use this before tagging a `v*` release. The tag triggers
`.github/workflows/release.yml`, which builds with `cargo xtask dist`,
re-verifies `SHA256SUMS`, and publishes the tarball, `.deb` and digest file as a
GitHub release.

> **Manual sign-off — read first.** Every step under "Hardware acceptance"
> below needs physical hardware and a real desktop session. Automated CI covers
> only the virtual/synthetic suites (`cargo xtask ci`, `cargo xtask qa`):
> file-backed images, headless QEMU/SeaBIOS/OVMF boots and helper wire tests. No
> CI job has ever rendered the window, plugged or unplugged a USB stick, or
> booted real hardware. A maintainer must perform those steps by hand and sign
> off before the tag is pushed.

## Before tagging — automated gates and artifacts

1. Export the cargo path. On this host cargo is not on PATH by default:

   ```
   export PATH="$HOME/.cargo/bin:$PATH"
   ```

2. Run the full CI gate and confirm it ends in `ci: all gates passed`:

   ```
   cargo xtask ci
   ```

   `cargo-audit` prints `SKIP (not installed)` on hosts without it; that is
   expected here and is not a failure.

3. Run the QA gate and confirm it ends in `qa: all suites passed`. The
   `tier1/pipeline-loop` `SKIP` line is expected unless `--privileged` is used;
   it is not a failure.

   ```
   cargo xtask qa
   ```

4. Build the release artifacts from the repo root:

   ```
   cargo xtask dist
   ```

   It prints the output directory. Expect one `rufus-*.tar.gz`, one `rufus-*.deb`
   (only where `dpkg-deb` is installed), and `SHA256SUMS` under
   `target/dist/<triple>/`. `<triple>` is a placeholder — replace it with the
   host Rust target triple the command reports, for example
   `x86_64-unknown-linux-gnu`.

5. Verify the digest file in that output directory. Replace `<triple>` as above:

   ```
   cd target/dist/<triple>
   sha256sum -c SHA256SUMS
   ```

   Every listed file must print `OK`.

6. Inspect the artifact contents. Replace `<version>` with `0.1.0` and
   `<triple>` as above:

   ```
   tar -tzf rufus-<version>-<triple>.tar.gz
   dpkg-deb -c rufus-<version>-<triple>.deb
   ```

   Confirm the staged layout: the CLI and GUI at `/usr/bin/rufus` and
   `/usr/bin/rufus-gui`, the privileged helper at `/usr/libexec/rufus-helper`,
   and the polkit policy, D-Bus files, desktop entry, AppStream metainfo, icon
   and licence texts under `/usr/share`. If `dpkg-deb` is unavailable, the
   `.deb` step is skipped — note that on the sign-off rather than assuming it
   was checked.

## Hardware acceptance — maintainer manual sign-off

These need a real machine and a real USB drive. Record the hardware, firmware
mode and result for each item. Where a mode does not apply to the machine or
image, mark it N/A with the reason.

1. **GUI on a real desktop.** Launch `rufus-gui` on a real X11 or Wayland
   desktop. Confirm the window renders and the device list populates. Insert a
   USB stick while the window is open — it must appear in the list — then remove
   it — it must disappear. That confirms plug/unplug hotplug is reflected.
2. **Linux hybrid ISO → boot.** Flash a 32 GB USB drive with a Linux hybrid ISO
   through `rufus-gui`, which runs the privileged `rufus-helper` via
   pkexec/D-Bus (approve the polkit prompt). Boot the stick on real hardware in
   UEFI mode, and in Legacy BIOS mode where the machine supports it. Confirm it
   reaches the distro's boot menu in each mode.
3. **Windows 11 installer → boot.** Flash a Windows 11 installer to a 32 GB USB
   drive and boot it on real hardware in UEFI mode and, where applicable, Legacy
   BIOS mode. Confirm the installer starts.
4. **Windows To Go → boot.** Flash a Windows To Go image to a 32 GB USB drive
   and boot it on real hardware in UEFI mode and, where applicable, Legacy BIOS
   mode. Confirm Windows reaches the desktop and that the host's internal disks
   are not mounted or altered (the offline `SanPolicy=4` behaviour).
5. Record any failure with the exact firmware mode, hardware and image used. Do
   not tag until every applicable item passes.

## Tag

Only after all of the above pass, push the `v*` tag that triggers the workflow.
Watch the release job finish and confirm the tarball, `.deb` and `SHA256SUMS`
appear on the generated GitHub release.
