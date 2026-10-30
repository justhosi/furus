//! Thin compatibility facade over the `part` module tree.
//!
//! Slice S08 split the former monolithic `partition.rs` into
//! [`crate::part::{mbr, gpt}`] (the read side plus the new writers);
//! `plan` — the layout builder that fills a disk image — lands there
//! later. Every public path under `partition` keeps working through the
//! re-exports below, so `rufus-cli`, `rufus-linux::inspect`,
//! `rufus-helper::validate` and `fsprobe` compile unchanged.

// The shared types live directly in `part`; the parse helpers live in
// the two submodule files, so the glob cannot carry them — re-export
// each one explicitly to keep the pre-S08 paths working.
pub use crate::part::gpt::{crc32_ieee, gpt_entry_range, guid_to_string, parse_gpt};
pub use crate::part::mbr::parse_mbr;
pub use crate::part::*;
