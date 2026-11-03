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

    /// The node path the external-tool formatters (`mke2fs`, `mkntfs`,
    /// `mkudffs`) run against. Core never invents the name: the CLI
    /// resolves the partition node (say `/dev/sdb1`) once `Mkpart` has
    /// created it, and a test hands out a scratch file. `Result`
    /// because the partition may not be openable yet.
    fn partition_path(&self) -> Result<std::path::PathBuf>;

    /// Give up the whole-disk handle opened so far, if any: flush it,
    /// close it, and forget it so the next [`device`](Opener::device)
    /// reopens from scratch. The tool-based `Mkfs` arms call this
    /// through
    /// [`RunContext::release_device`](super::steps::RunContext::release_device)
    /// immediately before [`partition_path`](Opener::partition_path):
    /// the external formatters want their own exclusive claim on the
    /// partition node, and on a real device that claim conflicts with
    /// the pipeline's open whole-disk handle. Test openers keep the
    /// default no-op; forgetting is observable through a reordered
    /// open, never through lost bytes (everything is flushed first).
    fn release(&self) -> Result<()> {
        Ok(())
    }
}
