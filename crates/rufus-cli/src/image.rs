//! CLI image helpers (S23 extraction).
//!
//! The real work lives in [`rufus_core::image`] so `rufus-cli`, `rufus-gui`
//! and later front ends share one inspection preamble. This module stays
//! as the CLI's import surface (and keeps the historical `image_size`
//! spelling for the `checksum` command) with no rules of its own.

pub use rufus_core::image::file_size as image_size;
pub use rufus_core::image::inspect;
