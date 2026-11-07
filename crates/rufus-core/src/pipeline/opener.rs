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

use rufus_proto::Filesystem;

use crate::error::Result;
use crate::fs::Volume;
use crate::pipeline::target::Target;

/// A mounted data partition: the directory the copy step works through,
/// plus the pre-flight and teardown it needs.
///
/// The guard owns the mount: dropping it unmounts best-effort (errors
/// ignored, never panicking), while
/// [`release`](MountedPartition::release) is the explicit path so an
/// unmount failure can be reported to the caller instead of swallowed.
/// [`free_bytes`](MountedPartition::free_bytes) is what the copy
/// pre-flight checks the payload against: the adapter answers it with
/// `statvfs` on the mount point, core never asks the filesystem itself.
/// A test opener that already has a directory (no kernel mount
/// involved) returns a plain directory guard over it.
pub trait MountedPartition {
    /// The directory the copy step reads and writes through.
    fn path(&self) -> &std::path::Path;

    /// Free bytes available to unprivileged writers on the mount, for
    /// the copy pre-flight.
    fn free_bytes(&self) -> Result<u64>;

    /// Unmount (and forget the mount point) explicitly, so a failure
    /// surfaces instead of being swallowed by the best-effort drop.
    fn release(&mut self) -> Result<()>;
}

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

    /// Reset the underlying USB device once the write retry budget is
    /// spent: `Ok(true)` means a reset was issued and the failed chunk
    /// deserves one more attempt; `Ok(false)` means not supported by
    /// this opener (a file seam has no bus to reset, a non-USB disk has
    /// no reset node). Test openers keep the default no-op.
    fn reset_device(&self) -> Result<bool> {
        Ok(false)
    }

    /// Data ranges of the image file at `path`: `(offset, len)` windows
    /// in ascending order, non-overlapping, exactly covering the file's
    /// data, so the write step can stream data and zero holes instead
    /// of copying every byte. `Ok(None)` means the platform or the
    /// filesystem cannot answer — never an error for a file that
    /// simply has no holes — and the caller then treats the whole file
    /// as data. Errors are reserved for a genuine I/O failure (an
    /// unreadable file, a failed query).
    fn data_ranges(&self, _path: &std::path::Path) -> Result<Option<Vec<(u64, u64)>>> {
        Ok(None)
    }

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

    /// Mount the freshly formatted data partition for the copy step:
    /// `Ok` owns the mount until
    /// [`release`](MountedPartition::release) (or the guard's
    /// best-effort drop). The default refuses: only an opener with a
    /// partition node to mount (the device opener) overrides it; a
    /// file seam keeps the refusal (it has no node), and a test opener
    /// without a mount returns `NotImplemented` the same way.
    fn mount_partition(&self, _filesystem: &Filesystem) -> Result<Box<dyn MountedPartition>> {
        Err(crate::error::CoreError::NotImplemented {
            what: "mounting the data partition",
        })
    }

    /// The node path of the EFI System Partition, when the layout has
    /// one. The default refuses: only the device opener (which knows
    /// the disk name and the sysfs root to wait on) overrides it; a
    /// file seam keeps the refusal (it has no partition nodes), and a
    /// test opener without one returns `NotImplemented` the same way.
    fn esp_path(&self) -> Result<std::path::PathBuf> {
        Err(crate::error::CoreError::NotImplemented {
            what: "an EFI System Partition on this target",
        })
    }

    /// Mount the ESP (FAT32) so the Windows boot files can land on it.
    /// `Ok` owns the mount until
    /// [`release`](MountedPartition::release) (or the guard's
    /// best-effort drop), like
    /// [`mount_partition`](Opener::mount_partition). The default
    /// refuses for the same reason: mounting needs a partition node,
    /// which only the device opener has.
    fn mount_esp(&self) -> Result<Box<dyn MountedPartition>> {
        Err(crate::error::CoreError::NotImplemented {
            what: "mounting the EFI System Partition",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;

    /// A minimal opener that overrides nothing optional: it pins the
    /// default `mount_partition` refusal.
    struct PlainOpener;

    impl Opener for PlainOpener {
        fn device(&self) -> Result<Box<dyn Target>> {
            Err(CoreError::invalid("test opener has no device"))
        }

        fn partition(&self) -> Result<Box<dyn Volume>> {
            Err(CoreError::invalid("test opener has no partition"))
        }

        fn partition_path(&self) -> Result<std::path::PathBuf> {
            Err(CoreError::invalid("test opener has no partition node"))
        }
    }

    #[test]
    fn mount_partition_defaults_to_a_named_refusal() {
        let opener = PlainOpener;
        let Err(error) = opener.mount_partition(&Filesystem::Fat32) else {
            panic!("an opener without a mount refuses");
        };
        assert!(
            matches!(
                error,
                CoreError::NotImplemented {
                    what: "mounting the data partition"
                }
            ),
            "the refusal names mounting: {error:?}"
        );
        let text = error.to_string();
        assert!(text.contains("mounting"), "{text}");
        assert!(text.contains("not implemented"), "{text}");
        assert!(text.is_ascii(), "{text}");
    }

    #[test]
    fn esp_seam_defaults_to_named_refusals() {
        let opener = PlainOpener;
        let Err(error) = opener.esp_path() else {
            panic!("an opener without an ESP refuses");
        };
        assert!(
            matches!(
                error,
                CoreError::NotImplemented {
                    what: "an EFI System Partition on this target"
                }
            ),
            "the refusal names the ESP: {error:?}"
        );
        assert!(error.to_string().is_ascii(), "{error}");
        let Err(error) = opener.mount_esp() else {
            panic!("an opener without an ESP mount refuses");
        };
        assert!(
            matches!(
                error,
                CoreError::NotImplemented {
                    what: "mounting the EFI System Partition"
                }
            ),
            "the refusal names mounting: {error:?}"
        );
        assert!(error.to_string().is_ascii(), "{error}");
    }
}
