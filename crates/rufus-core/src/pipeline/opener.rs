//! Who supplies the stores the pipeline drives.
//!
//! [`Opener`] has two jobs because the run touches two shapes of
//! storage: [`device`](Opener::device) is the whole disk (wipe, table
//! and raw writes go through [`Target`]), while
//! [`partition`](Opener::partition) is the data partition as the
//! filesystem formatters' [`Volume`] (Mkfs, CopyTree
//! in later slices). The CLI implements this over `BlockDevice` plus
//! the partition node path once `Mkpart` has created it; a test opener
//! hands out fixtures instead.

use crate::error::Result;
use crate::fs::Volume;
use crate::pipeline::target::Target;

/// Supplies the stores for one pipeline run.
pub trait Opener {
    /// The whole disk as a [`Target`]: wipe, table and raw writes.
    fn device(&self) -> Result<Box<dyn Target>>;

    /// The data partition as the filesystem formatters'
    /// [`Volume`].
    fn partition(&self) -> Result<Box<dyn Volume>>;
}
