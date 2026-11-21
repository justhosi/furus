# Changelog

All notable changes to this project are recorded here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The workspace version
is `0.1.0` (see `Cargo.toml`); no release date is recorded here.

## [0.1.0]

Initial, in-progress implementation of `furus`, a clean Rust rewrite of the
original Windows utility for Linux. Capabilities present in this version:

### Added

- Native FAT32 and exFAT formatting with a file API; NTFS, ext2/3/4 and UDF
  formatted through runtime-checked external tools, with read-back verification.
- MBR and GPT partition-table readers and writers.
- UEFI and Legacy BIOS Windows To Go: GPT layout, WIM apply via wimlib, BCD
  stores for both firmware types built without Windows tools, and offline
  `SanPolicy=4`.
- `furus-gui`, an unprivileged Slint desktop front end with device discovery
  and hotplug, image analysis, a confirmation-gated write flow and progress UI.
- `furus-helper`, the privileged write helper exposed over D-Bus with a pkexec
  transport, so the GUI never runs as root; polkit and D-Bus policy files live
  under `packaging/`.
- The `furus` CLI (version, checksum, analyze, plan, list, write) and the shared
  `furus-proto` plan/progress contract.
- `cargo xtask dist` (deterministic tarball, a `.deb` where `dpkg-deb` exists,
  and `SHA256SUMS`) and `cargo xtask qa` (the two-tier automated QA gate).
- Tag-triggered `.github/workflows/release.yml`: on a `v*` tag it builds via
  `cargo xtask dist`, re-verifies `SHA256SUMS`, and publishes the tarball, `.deb`
  and digest file as a GitHub release. The workflow itself is only exercised on
  GitHub with a real tag; `docs/RELEASE-CHECKLIST.md` records the manual hardware
  sign-off that must precede tagging.

### Notes

- The `check_updates` and `update_channel` config fields are dormant
  schema-compatibility no-ops (Decision A12, still proposed): there is no
  telemetry, HTTP client or background network call.
- Real USB/hardware acceptance (GUI on a desktop, hotplug, and UEFI/Legacy BIOS
  boots of Linux, Windows installer and Windows To Go media) is a manual
  maintainer sign-off and is not covered by automated CI.
