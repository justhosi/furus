//! Windows image handling (S21, slice 2 of 12): apply WIM images.
//!
//! A Windows USB needs the installer image from `install.wim` (or
//! `install.esd`) laid onto the target filesystem — the equivalent of
//! what Rufus does with wimlib's apply step. This module owns that
//! side: [`wim`] opens a WIM through the safe `wimlib-sys` facade,
//! lists its images, and extracts one into an existing directory with
//! byte/file progress and cancellation.
//!
//! The reader side stays where it is: [`crate::wim`] (S16) parses the
//! header and XML for inspection without the library. Anything that
//! needs the bytes out of an image comes here instead.
//!
//! Not here yet: split-WIM (`.swm`) assembly, ESD solid resources,
//! integrity-checked opens, the NTFS-volume extraction mode, BCD
//! store editing, and the S21 VBR-fix hook of PLAN lines 948-949.

pub mod wim;
