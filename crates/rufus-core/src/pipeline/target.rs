//! The write surface core is allowed to name.
//!
//! [`Target`] mirrors `rufus_linux::block::Sink` deliberately:
//! `rufus-core` cannot name that crate (core never depends on
//! `rufus-linux`), so `rufus-linux` will provide a delegating adapter in
//! a later slice and the two contracts must stay in step. Every method is
//! positional and bounds-checked before any I/O happens; a window
//! running past [`size`](Target::size) refuses naming offset, length and
//! size.
//!
//! [`write_all_at_cancellable`](Target::write_all_at_cancellable) writes
//! in `chunk`-sized pieces and returns the bytes written so far at a
//! whole-chunk boundary on cancellation — never a torn piece. (The name
//! `Target` collides with `rufus-proto`'s firmware-target enum on
//! purpose: this is the store, that is the boot goal; the paths keep
//! them apart.)

#[cfg(test)]
use crate::error::CoreError;
use crate::error::Result;
#[cfg(test)]
use crate::fs::Volume;

/// The whole-disk write surface the pipeline drives: wipe, table and
/// raw writes go here, while the data partition's filesystem work goes
/// through [`Volume`](crate::fs::Volume) from
/// [`Opener::partition`](super::opener::Opener::partition).
pub trait Target {
    /// Total writable extent in bytes.
    fn size(&self) -> u64;

    /// Sector size in bytes (512 unless the backend reports otherwise).
    fn sector_size(&self) -> u32 {
        512
    }

    /// Fill `buf` completely from `offset`, or report why not.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Write all of `buf` at `offset`, or report why not.
    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()>;

    /// Write `buf` at `offset` in `chunk`-sized pieces, giving the
    /// caller the chance to abort between pieces: cancellation returns
    /// `Ok` with the bytes written so far — a whole number of pieces,
    /// nothing torn. A zero `chunk` is invalid.
    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64>;

    /// Zero out `[offset, offset + len)`. A zero `len` is invalid.
    fn zero_range(&self, offset: u64, len: u64) -> Result<()>;

    /// Suggest that `[offset, offset + len)` be deallocated. Best effort
    /// by contract: no support means the data stays and the call still
    /// reports `Ok`. Wipe uses it as a hint before zeroing.
    fn discard(&self, _offset: u64, _len: u64) -> Result<()> {
        Ok(())
    }

    /// Push buffered state down.
    fn flush(&self) -> Result<()>;

    /// Ask for a fresh partition table view (no-op where there is no
    /// kernel table to re-read).
    fn reread_partitions(&self) -> Result<()> {
        Ok(())
    }
}

/// Shared bounds rule for the test target below: `[offset, offset +
/// len)` must lie inside `size`, naming offset, length and size like
/// the volume implementations do.
#[cfg(test)]
fn check_window(size: u64, offset: u64, len: u64, verb: &str) -> Result<()> {
    match offset.checked_add(len) {
        Some(end) if end <= size => Ok(()),
        Some(end) => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, {end}) does not fit the target size {size}"
        ))),
        None => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, ...) overflows past the target size {size}"
        ))),
    }
}

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::rc::Rc;

/// In-memory [`Target`] for unit tests: one shared byte store plus
/// flush/reread counters, so a test opener can hand out handles and
/// still observe what the run did. Backed by
/// [`VecVolume`](crate::fs::VecVolume) internally rather than a second
/// byte store; `Rc`-shared so every handle sees the same bytes.
/// Single-threaded only, like every test double here.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct VecTarget {
    inner: Rc<VecTargetInner>,
}

/// Shared state behind [`VecTarget`].
#[cfg(test)]
#[derive(Debug)]
struct VecTargetInner {
    /// The bytes; behind a cell because [`Target`] takes `&self` while
    /// [`VecVolume`](crate::fs::VecVolume) writes take `&mut self`.
    volume: RefCell<crate::fs::VecVolume>,
    /// Extent in bytes, recorded so [`size`](Target::size) stays
    /// infallible without borrowing.
    size: u64,
    /// Sector size in bytes, recorded for the same reason.
    sector_size: u32,
    /// Completed [`flush`](Target::flush) calls.
    flushes: Cell<u64>,
    /// Completed [`reread_partitions`](Target::reread_partitions) calls.
    rereads: Cell<u64>,
    /// Offered [`discard`](Target::discard) windows, in call order.
    discards: RefCell<Vec<(u64, u64)>>,
}

#[cfg(test)]
impl VecTarget {
    /// A zeroed target of `len` bytes with `sector_size`-byte sectors.
    pub(crate) fn new(len: u64, sector_size: u32) -> Result<Self> {
        Ok(Self {
            inner: Rc::new(VecTargetInner {
                volume: RefCell::new(crate::fs::VecVolume::new(len, sector_size)?),
                size: len,
                sector_size,
                flushes: Cell::new(0),
                rereads: Cell::new(0),
                discards: RefCell::new(Vec::new()),
            }),
        })
    }

    /// Completed flush calls across all handles sharing this store.
    pub(crate) fn flushes(&self) -> u64 {
        self.inner.flushes.get()
    }

    /// Completed partition re-reads across all handles.
    pub(crate) fn rereads(&self) -> u64 {
        self.inner.rereads.get()
    }

    /// Offered discard windows across all handles, in call order.
    pub(crate) fn discards(&self) -> Vec<(u64, u64)> {
        match self.inner.discards.try_borrow() {
            Ok(windows) => windows.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// A copy of the current bytes, for content assertions.
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        let volume = self
            .inner
            .volume
            .try_borrow()
            .map_err(|_| CoreError::invalid("test target is already borrowed"))?;
        Ok(volume.bytes().to_vec())
    }
}

#[cfg(test)]
impl Target for VecTarget {
    fn size(&self) -> u64 {
        self.inner.size
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let volume = self
            .inner
            .volume
            .try_borrow()
            .map_err(|_| CoreError::invalid("test target is already borrowed"))?;
        volume.read_exact_at(offset, buf)
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        // One shared body with the cancellable form below (which the
        // Sink side does the same way): the whole buffer, never
        // cancelled, in a single conceptual piece.
        self.write_all_at_cancellable(offset, buf, usize::MAX, &|| false)?;
        Ok(())
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        if chunk == 0 {
            return Err(CoreError::invalid("write chunk size must be non-zero"));
        }
        // Whole-buffer bounds first, so even an immediate cancellation
        // reports validation errors, never a silent skip.
        check_window(self.inner.size, offset, buf.len() as u64, "write")?;
        let mut volume = self
            .inner
            .volume
            .try_borrow_mut()
            .map_err(|_| CoreError::invalid("test target is already borrowed"))?;
        let mut done = 0usize;
        while done < buf.len() {
            if cancelled() {
                return Ok(done as u64);
            }
            let piece = (buf.len() - done).min(chunk);
            volume.write_all_at(offset + done as u64, &buf[done..done + piece])?;
            done += piece;
        }
        Ok(done as u64)
    }

    fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
        check_window(self.inner.size, offset, len, "zero")?;
        if len == 0 {
            return Err(CoreError::invalid("cannot zero a zero-length window"));
        }
        // Plain zero writes in bounded pieces (a test double has no
        // kernel primitive to prefer).
        const PIECE: u64 = 64 * 1024;
        let zeros = vec![0u8; PIECE as usize];
        let mut volume = self
            .inner
            .volume
            .try_borrow_mut()
            .map_err(|_| CoreError::invalid("test target is already borrowed"))?;
        let mut pos = offset;
        let mut remaining = len;
        while remaining > 0 {
            let piece = remaining.min(PIECE);
            volume.write_all_at(pos, &zeros[..piece as usize])?;
            pos += piece;
            remaining -= piece;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut volume = self
            .inner
            .volume
            .try_borrow_mut()
            .map_err(|_| CoreError::invalid("test target is already borrowed"))?;
        volume.flush()?;
        self.inner.flushes.set(self.inner.flushes.get() + 1);
        Ok(())
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        if self
            .inner
            .discards
            .try_borrow_mut()
            .map(|mut windows| windows.push((offset, len)))
            .is_err()
        {
            return Err(CoreError::invalid("test target is already borrowed"));
        }
        Ok(())
    }

    fn reread_partitions(&self) -> Result<()> {
        self.inner.rereads.set(self.inner.rereads.get() + 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_violations_name_offset_length_and_size() {
        let target = VecTarget::new(1024, 512).expect("fixture target fits");
        let error = target
            .write_all_at(1020, &[0u8; 8])
            .expect_err("a past-the-end write refuses");
        let text = error.to_string();
        assert!(text.contains("1020"), "{text}");
        assert!(text.contains("1028"), "{text}");
        assert!(text.contains("1024"), "{text}");
        let error = target
            .zero_range(0, 0)
            .expect_err("a zero-length zero refuses");
        assert!(error.to_string().contains("zero-length"), "{error:?}");
        let error = target
            .write_all_at_cancellable(0, &[0u8; 1], 0, &|| false)
            .expect_err("a zero chunk refuses");
        assert!(error.to_string().contains("non-zero"), "{error:?}");
    }

    #[test]
    fn cancellable_write_stops_on_whole_chunks() {
        let target = VecTarget::new(1024, 512).expect("fixture target fits");
        let data = vec![7u8; 100];
        // Cancel after two 32-byte pieces: 64 bytes land, nothing torn.
        let calls = Cell::new(0u32);
        let done = target
            .write_all_at_cancellable(0, &data, 32, &|| {
                let seen = calls.get();
                calls.set(seen + 1);
                seen >= 2
            })
            .expect("cancellation still reports Ok");
        assert_eq!(done, 64);
        let bytes = target.bytes().expect("bytes read back");
        assert!(bytes[..64].iter().all(|&byte| byte == 7));
        assert!(bytes[64..].iter().all(|&byte| byte == 0));
        // Immediate cancellation still validates the window first.
        let error = target
            .write_all_at_cancellable(2000, &data, 32, &|| true)
            .expect_err("an out-of-range write refuses even when cancelled");
        assert!(error.to_string().contains("2000"), "{error:?}");
    }

    #[test]
    fn zero_range_and_defaults_behave() {
        let target = VecTarget::new(1024, 512).expect("fixture target fits");
        target.write_all_at(0, &[9u8; 100]).expect("seed writes");
        target.zero_range(10, 20).expect("zeroing works");
        let bytes = target.bytes().expect("bytes read back");
        assert!(bytes[..10].iter().all(|&byte| byte == 9));
        assert!(bytes[10..30].iter().all(|&byte| byte == 0));
        assert!(bytes[30..100].iter().all(|&byte| byte == 9));
        assert_eq!(target.size(), 1024);
        assert_eq!(target.sector_size(), 512);
        assert_eq!(target.flushes(), 0);
        assert_eq!(target.rereads(), 0);
    }
}
