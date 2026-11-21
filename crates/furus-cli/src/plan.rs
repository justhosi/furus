//! CLI-facing `--bootloader` selector (S23).
//!
//! The selection rules live in [`furus_core::planner::BootloaderOpt`], so
//! the GUI and the CLI cannot drift. This module keeps only the
//! `clap::ValueEnum` surface (the flag spelling is part of the CLI
//! contract) and converts to the core enum at the boundary.

use clap::ValueEnum;
use furus_core::planner::BootloaderOpt as CoreBootloaderOpt;

/// The `--bootloader` selector as parsed by clap.
///
/// Every variant maps one-to-one onto [`CoreBootloaderOpt`]; see that
/// type for the partition/filesystem pairing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BootloaderOpt {
    /// Pair with the write mode (`Dd` → none, `Copy` → auto).
    Auto,
    /// Syslinux 4.x/6.x.
    Syslinux,
    /// GNU GRUB 2.
    Grub2,
    /// GRUB4DOS.
    Grub4dos,
    /// UEFI:NTFS helper partition (NTFS or exFAT data partition, copy mode).
    UefiNtfs,
    /// FreeDOS.
    Freedos,
    /// KolibriOS.
    Kolibri,
    /// MS-DOS from the user's own system files (`--msdos-dir`): no
    /// write step is planned, since `IO.SYS` must be the first root
    /// entry of the fresh volume.
    #[value(name = "msdos")]
    MsDos,
    /// Windows To Go: the GPT `WindowsToGo` layout and an NTFS data
    /// partition with no write step (`--filesystem` is overridden; a
    /// `--scheme mbr` plan is refused later by the layout, which is
    /// GPT-only). The bootloader step applies the WIM itself.
    #[value(name = "windows")]
    Windows,
    /// No bootloader (plain data media).
    None,
}

impl From<BootloaderOpt> for CoreBootloaderOpt {
    fn from(opt: BootloaderOpt) -> Self {
        match opt {
            BootloaderOpt::Auto => CoreBootloaderOpt::Auto,
            BootloaderOpt::Syslinux => CoreBootloaderOpt::Syslinux,
            BootloaderOpt::Grub2 => CoreBootloaderOpt::Grub2,
            BootloaderOpt::Grub4dos => CoreBootloaderOpt::Grub4dos,
            BootloaderOpt::UefiNtfs => CoreBootloaderOpt::UefiNtfs,
            BootloaderOpt::Freedos => CoreBootloaderOpt::Freedos,
            BootloaderOpt::Kolibri => CoreBootloaderOpt::Kolibri,
            BootloaderOpt::MsDos => CoreBootloaderOpt::MsDos,
            BootloaderOpt::Windows => CoreBootloaderOpt::Windows,
            BootloaderOpt::None => CoreBootloaderOpt::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BootloaderOpt;
    use furus_core::planner::BootloaderOpt as CoreBootloaderOpt;

    #[test]
    fn every_cli_selector_maps_to_its_core_twin() {
        for (cli, core) in [
            (BootloaderOpt::Auto, CoreBootloaderOpt::Auto),
            (BootloaderOpt::Syslinux, CoreBootloaderOpt::Syslinux),
            (BootloaderOpt::Grub2, CoreBootloaderOpt::Grub2),
            (BootloaderOpt::Grub4dos, CoreBootloaderOpt::Grub4dos),
            (BootloaderOpt::UefiNtfs, CoreBootloaderOpt::UefiNtfs),
            (BootloaderOpt::Freedos, CoreBootloaderOpt::Freedos),
            (BootloaderOpt::Kolibri, CoreBootloaderOpt::Kolibri),
            (BootloaderOpt::MsDos, CoreBootloaderOpt::MsDos),
            (BootloaderOpt::Windows, CoreBootloaderOpt::Windows),
            (BootloaderOpt::None, CoreBootloaderOpt::None),
        ] {
            assert_eq!(CoreBootloaderOpt::from(cli), core);
        }
    }
}
