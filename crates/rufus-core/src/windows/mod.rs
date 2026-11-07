//! Windows image handling (S21, slice 6 of 12): WIM apply and split, and the BCD store builder.
//!
//! A Windows USB needs the installer image from `install.wim` (or
//! `install.esd`) laid onto the target filesystem — the equivalent of
//! what Rufus does with wimlib's apply step — and, when that image
//! outgrows what FAT32 can hold, split into `.swm` parts first. This
//! module owns both sides: [`wim`] opens a WIM through the safe
//! `wimlib-sys` facade, lists its images, and extracts one into an
//! existing directory with byte/file progress and cancellation, while
//! [`split`] turns an oversized `install.wim` into FAT32-sized parts
//! with the same progress and cancellation shape. [`bcd`] builds the
//! UEFI and BIOS stores by patching the applied image's own
//! `BCD-Template` with a small in-crate `regf` editor.
//!
//! The reader side stays where it is: [`crate::wim`] (S16) parses the
//! header and XML for inspection without the library. Anything that
//! needs the bytes out of an image comes here instead.
//!
//! Not here yet: ESD solid resources, integrity-checked opens, the
//! NTFS-volume extraction mode, pipeline wiring for the BCD stores,
//! and the S21 VBR-fix hook of PLAN lines 948-949.

/// Apply one WIM image onto the mounted data partition.
pub mod apply;
/// BCD store builder: patches the applied image's `BCD-Template` host-side.
pub mod bcd;
pub mod split;
pub mod wim;
