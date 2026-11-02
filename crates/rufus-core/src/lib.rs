//! `rufus-core`: safe, non-privileged foundation of the rewrite.
//!
//! Slice S02 (core runtime) delivers the pieces every later slice builds
//! on — error handling, logging, configuration, paths, localisation,
//! checked arithmetic and version reporting:
//!
//! * [`error`] — [`CoreError`](error::CoreError), the single error type
//!   (I/O with path, config/serialise failures, `.loc` parse errors,
//!   invalid input, asset resolution). [`Result`](error::Result) is the
//!   crate-wide result alias.
//! * [`fs`] — the filesystem write side (S09, S10): the
//!   [`Volume`](fs::Volume) byte-store surface (total extent, exact
//!   positional I/O, sector size, flush) that keeps the formatters
//!   independent of `rufus-linux`, the no-mount, no-external-tool FAT32
//!   formatter under [`fs::fat32`] — [`geometry`](fs::fat32::geometry)
//!   (large FAT32 included), the [`bpb`](fs::fat32::bpb) byte images and
//!   [`format`](fs::fat32::format) (superblocks, both FATs, root
//!   directory) — and the exFAT formatter under [`fs::exfat`]
//!   (boot region and its backup, checksum sector, FAT, allocation
//!   bitmap, up-case table, root directory). The NTFS integration under
//!   [`fs::ntfs`] (S11) probes and drives the external `mkntfs`/`mkfs.ntfs`
//!   tool and verifies the VBR — a native writer is out of scope, and the
//!   S21 VBR-fix hook of PLAN lines 948-949 ships no code here. The
//!   ext2/3/4 integration under [`fs::ext`] (S12) probes and drives the
//!   external `mke2fs`/`mkfs.ext*` tool under the same A4 rule and
//!   verifies the superblock fields the mandate pins (4096-byte blocks,
//!   the label field read up to the first NUL or the full 16 bytes, the
//!   journal bit), the `e2fsck -f -n` check, and the persistence mode
//!   (label `persistence` plus `/persistence.conf` holding `/ union`);
//!   the mount-and-write, 2 TB sparse-image and QEMU persistence-boot
//!   acceptance tests are the next slice.
//! * [`log`] — [`Logger`](log::Logger): an `Arc`-shared in-memory ring
//!   (10,000 records) with level filtering and an optional append-only
//!   file sink; UTC timestamps without a date/time dependency.
//! * [`config`] — [`Config`](config::Config): serde/TOML settings with
//!   forward-compatible parsing, atomic save, and corrupt-file recovery
//!   ([`LoadedConfig`](config::LoadedConfig)).
//! * [`paths`] — XDG directories without the `dirs` crate, asset-dir
//!   resolution (`$RUFUS_ASSETS`, AppImage `$APPDIR`, FHS install), and
//!   portable-mode (`./rufus.toml`) discovery.
//! * [`i18n`] — [`Catalog`](i18n::Catalog): the Rufus `.loc`
//!   (pollock-format) catalog, parsed eagerly from disk, with locale
//!   normalisation, an English fallback chain and a [`Translator`](i18n::Translator).
//! * [`iso`] — the ISO9660 reader (S14, slices 1-3 of 4): a 64 KiB sector
//!   cache over [`Volume`](fs::Volume), the sector-16 volume-descriptor
//!   sequence (primary, supplementary with Joliet tree selection,
//!   boot record, terminator), UCS-2BE Joliet name decoding, the
//!   shared directory records with multi-extent joining, SUSP/Rock
//!   Ridge names, symlinks, attributes and relocation on the primary
//!   tree, and path lookup with listings and file reads.
//! * [`hash`] — [`Algo`](hash::Algo) selection plus streaming
//!   [`hash_reader`](hash::hash_reader) / [`hash_file`](hash::hash_file)
//!   digests (MD5/SHA-1/SHA-256/SHA-512) over a 1 MiB buffer.
//! * [`part`] — write-side MBR and GPT table builders (S08): the
//!   sector-0 MBR image and the full protective-MBR/primary/backup GPT
//!   image, next to their parsers (which moved here from
//!   `partition.rs`).
//! * [`partition`] — read-side MBR and GPT table parsing
//!   ([`Layout`](partition::Layout), [`TablePartition`](partition::TablePartition)):
//!   the authoritative table behind a device, with CRC-32 implemented
//!   in-crate and rotted metadata reported as warnings rather than
//!   errors. Since S08 this module name is a thin facade over [`part`].
//! * [`fsprobe`] — [`FsKind`](fsprobe::FsKind) superblock recognition
//!   from raw byte windows ([`probe`](fsprobe::probe)); four kinds
//!   (lvm2, btrfs, xfs, zfs) exist only so the write path can refuse to
//!   erase them.
//! * [`safety`] — the PLAN §6 verdict ([`judge`](safety::judge),
//!   [`SafetyVerdict`](safety::SafetyVerdict) / [`Reason`](safety::Reason)):
//!   one fail-closed rule chain, enforced identically at preview and
//!   helper, with the builtin-name list shared with discovery.
//! * [`text`] — [`device_text`](text::device_text), the one sanitiser
//!   for untrusted device text (trim, then control/non-ASCII → `?`).
//! * [`units`] — checked sector math, human-readable sizes, durations.
//! * [`version`] — crate version, compile-time git hash, user-agent string.
//!
//! The crate is dependency-light by design (serde, toml, thiserror, the
//! S03 RustCrypto digests, plus tempfile for tests): no async runtime, no
//! logging framework, no regex — see PLAN.md §5. The S05 modules push
//! that further: CRC-32, GUID formatting, table parsing and superblock
//! recognition are implemented in-crate rather than pulled from crates.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod fs;
pub mod fsprobe;
pub mod hash;
pub mod i18n;
pub mod iso;
pub mod log;
pub mod part;
pub mod partition;
pub mod paths;
pub mod safety;
pub mod text;
pub mod units;
pub mod version;

pub use config::AdvancedConfig;
pub use config::Config;
pub use config::LoadedConfig;
pub use config::UpdateChannel;
pub use config::WindowConfig;
pub use error::CoreError;
pub use error::Result;
pub use fsprobe::FsKind;
pub use hash::Algo;
pub use hash::hash_file;
pub use hash::hash_file_with;
pub use hash::hash_reader;
pub use i18n::Catalog;
pub use i18n::Translator;
pub use log::Level;
pub use log::Logger;
pub use log::Record;
pub use partition::Layout;
pub use partition::TableKind;
pub use partition::TablePartition;
pub use paths::asset_path;
pub use paths::assets_dir;
pub use paths::cache_dir;
pub use paths::config_dir;
pub use paths::default_config_path;
pub use paths::portable_config_path;
pub use paths::state_dir;
pub use safety::Reason;
pub use safety::SafetyVerdict;
pub use safety::Target;
pub use safety::judge;
pub use text::device_text;
pub use units::bytes_to_sectors_ceil;
pub use units::format_duration;
pub use units::human_bytes;
pub use units::sectors_to_bytes;
pub use version::git_hash;
pub use version::user_agent;
pub use version::version;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_pinned_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }
}
