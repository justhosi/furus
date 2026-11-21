use super::*;
use crate::fs::exfat::format;

impl<V: Volume> Exfat<V> {
    /// Format a whole exFAT volume onto `volume` and hand its live API
    /// back.
    ///
    /// The volume content is built by part A's
    /// [`format::format`](format::format) writer (boot regions, FAT,
    /// allocation bitmap, up-case table, root directory, label) — this
    /// type takes over the bitmap bookkeeping: the bitmap bytes are
    /// loaded back from the just-formatted image and the free count is
    /// counted from the bits, so the two views agree by construction
    /// (and the count matches what `mkfs.exfat` reports for the same
    /// layout — measured 15,868 free of 15,872 clusters on 64 MiB).
    pub fn format(mut volume: V, options: &format::FormatOptions) -> Result<Self> {
        let geometry = format::format(&mut volume, options)?;
        let base_offset = geometry.cluster_offset(geometry.bitmap_cluster)?;
        let bitmap = Bitmap::load(
            &volume,
            geometry.bitmap_cluster,
            geometry.bitmap_clusters,
            geometry.cluster_bytes,
            geometry.cluster_count,
            base_offset,
        )?;
        Ok(Self {
            volume,
            geometry,
            free_clusters: bitmap.free_clusters(),
            bitmap,
            bitmap_dirty: false,
        })
    }
}
