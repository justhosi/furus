//! The S17 write adapters: core [`Target`](rufus_core::pipeline::Target)
//! and [`Opener`](rufus_core::pipeline::Opener) over the block
//! [`Sink`](crate::block::Sink)s.
//!
//! Two openers share one cached-handle core:
//!
//! * [`DeviceOpener`] — a real device node plus its partition geometry;
//! * [`FileOpener`] — the `--device-file` test seam: a regular file,
//!   created when absent, sized from its own length.
//!
//! The sharing is load-bearing, not convenience. [`BlockDevice`] opens
//! `O_RDWR|O_EXCL`, and on Linux the exclusive claim is per-disk: while
//! the whole-disk handle is open, opening `/dev/sdb1` (or running a
//! formatter that wants its own claim) fails with `EBUSY`. So
//! [`Opener::partition`](rufus_core::pipeline::Opener::partition)
//! never opens a second handle — it returns a [`SinkVolume`] window
//! over the same open device — and the tool-based `Mkfs` arms release
//! the handle first (see
//! [`RunContext::release_device`](rufus_core::pipeline::steps::RunContext::release_device)
//! and [`Opener::release`](rufus_core::pipeline::Opener::release)):
//! flush, close, forget, and reopen lazily on the next use. The
//! partition node wait lives here too: only the adapter knows the
//! sysfs root, the disk name and the node spelling, so
//! [`DeviceOpener::partition_path`](DeviceOpener::partition_path)
//! polls [`wait_for_partitions`](crate::wipe::wait_for_partitions)
//! before handing the node to an external formatter. Core stays
//! platform-free throughout.
//!
//! Agreement with [`Mkpart`](rufus_core::pipeline::mkpart): the
//! partition window is not recomputed here — both sides feed the same
//! `(table, sector size, byte size)` triple, read off the same opened
//! handle, into the same
//! [`single_data_window`](rufus_core::part::plan::single_data_window)
//! planner call, so the formatted window is the stamped partition by
//! construction.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::fs::Volume;
use rufus_core::part::TableKind;
use rufus_core::part::plan::single_data_window;
use rufus_core::pipeline::MountedPartition;
use rufus_core::pipeline::Opener;
use rufus_core::pipeline::Target;
use rufus_proto::Filesystem;

use crate::block::BlockDevice;
use crate::block::Sink;
use crate::inspect::partition_name;
use crate::model::Device;
use crate::sysfs::SysfsRoot;
use crate::wipe::PARTITION_POLL_INTERVAL;
use crate::wipe::PARTITION_POLL_TIMEOUT;
use crate::wipe::wait_for_partitions;

/// A core [`Target`] over any block [`Sink`]: every call delegates to
/// the sink unchanged. The sector size is stored, not probed — a
/// [`Sink`] has no sector concept (alignment is a direct-I/O property,
/// not geometry), so the opener supplies the discovery value the
/// device was opened with.
#[derive(Debug)]
pub struct SinkTarget<S: Sink> {
    sink: Arc<S>,
    sector_size: u32,
}

impl<S: Sink> SinkTarget<S> {
    /// Share `sink` (never re-open it) with `sector_size`-byte sectors.
    pub fn new(sink: Arc<S>, sector_size: u32) -> Self {
        Self { sink, sector_size }
    }
}

impl<S: Sink> Target for SinkTarget<S> {
    fn size(&self) -> u64 {
        self.sink.size()
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.sink.read_at(offset, buf)
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.sink.write_all_at(offset, buf)
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        self.sink
            .write_all_at_cancellable(offset, buf, chunk, cancelled)
    }

    fn zero_range(&self, offset: u64, len: u64, _cancelled: &dyn Fn() -> bool) -> Result<()> {
        // Dropped deliberately: zeroing is one fast `BLKZEROOUT`
        // ioctl (or the sink's own fallback), so there is no chunk
        // loop to consult the probe in — run-level cancellation
        // happens between windows at the call sites instead.
        self.sink.zero_range(offset, len)
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        self.sink.discard(offset, len)
    }

    fn flush(&self) -> Result<()> {
        self.sink.flush()
    }

    fn reread_partitions(&self) -> Result<()> {
        self.sink.reread_partitions()
    }
}

/// A core [`Volume`] window over a shared [`Sink`] at
/// `[base, base + len)`: the partition view that never opens a second
/// handle (see the module docs for why a second `O_EXCL` claim fails).
/// Construction pins the alignment the planner guarantees (base and
/// length on whole sectors); every I/O is bounds-checked against the
/// window before touching the sink, naming base, offset and length.
#[derive(Debug)]
pub struct SinkVolume<S: Sink> {
    sink: Arc<S>,
    base: u64,
    len: u64,
    sector: u32,
}

impl<S: Sink> SinkVolume<S> {
    /// A `len`-byte view at `base` over `sink` with `sector`-byte
    /// sectors. Refuses a zero sector size, unaligned base or length,
    /// and any window running past the sink's size.
    pub fn new(sink: Arc<S>, base: u64, len: u64, sector: u32) -> Result<Self> {
        if sector == 0 {
            return Err(CoreError::invalid(
                "partition window sector size is zero".to_string(),
            ));
        }
        if !base.is_multiple_of(u64::from(sector)) {
            return Err(CoreError::invalid(format!(
                "partition window base {base} is not on a {sector} byte sector boundary"
            )));
        }
        if !len.is_multiple_of(u64::from(sector)) {
            return Err(CoreError::invalid(format!(
                "partition window length {len} is not a whole number of {sector} byte sectors"
            )));
        }
        let size = sink.size();
        match base.checked_add(len) {
            Some(end) if end <= size => Ok(Self {
                sink,
                base,
                len,
                sector,
            }),
            Some(end) => Err(CoreError::invalid(format!(
                "partition window [{base}, {end}) does not fit the {size} byte device"
            ))),
            None => Err(CoreError::invalid(format!(
                "partition window [{base}, ...) overflows past the {size} byte device"
            ))),
        }
    }
}

impl<S: Sink> Volume for SinkVolume<S> {
    fn total_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "partition read of {} bytes at offset {offset} overflows",
                buf.len()
            ))
        })?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "partition read of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.sink.read_at(self.base + offset, buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let end = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            CoreError::invalid(format!(
                "partition write of {} bytes at offset {offset} overflows",
                buf.len()
            ))
        })?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "partition write of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.sink.write_all_at(self.base + offset, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.sink.flush()
    }

    fn sector_size(&self) -> u32 {
        self.sector
    }
}

/// The file seam's whole-disk target: a [`SinkTarget`] over the opened
/// [`BlockDevice`] (regular files open buffered — see
/// [`BlockDevice::open`]).
pub type FileTarget = SinkTarget<BlockDevice>;

/// What backs a shared opener: a real node (with everything the
/// partition wait needs) or the file seam.
#[derive(Debug)]
enum Backend {
    /// A real device node: open exclusively with discovery geometry,
    /// wait for `part_name` under `disk_name` in `sysfs` before handing
    /// the node path to an external formatter. `usb` records whether
    /// the discovered transport is USB (reset nodes only exist for
    /// those).
    Device {
        path: PathBuf,
        disk_name: String,
        part_name: String,
        size: u64,
        logical: u32,
        physical: u32,
        sysfs: SysfsRoot,
        usb: bool,
    },
    /// The `--device-file` seam: a regular file, no kernel table, no
    /// node to wait for.
    File { path: PathBuf },
}

impl Backend {
    /// Open the backing store. Real nodes go through
    /// [`BlockDevice::open_with`] (exclusive, discovery geometry);
    /// files through [`BlockDevice::open`] (buffered, own length).
    fn open(&self) -> Result<BlockDevice> {
        match self {
            Backend::Device {
                path,
                size,
                logical,
                physical,
                ..
            } => BlockDevice::open_with(path, *size, *logical, *physical),
            Backend::File { path } => BlockDevice::open(path),
        }
    }
}

/// The cached-handle core both openers share: one lazily opened
/// [`BlockDevice`], reused by every `device()` and `partition()` call
/// until [`release`](Opener::release) forgets it. The `opens` counter
/// is the no-second-handle proof the unit tests read.
#[derive(Debug)]
struct Shared {
    /// The table [`Mkpart`](rufus_core::pipeline::mkpart) stamps, so
    /// the window planner runs with the same kind.
    table: TableKind,
    backend: Backend,
    state: Mutex<Option<Arc<BlockDevice>>>,
    opens: AtomicUsize,
}

impl Shared {
    /// The one open handle, opening it on first use. Concurrent callers
    /// serialize on the mutex, so the device opens at most once per
    /// cached generation — never a second exclusive claim.
    fn handle(&self) -> Result<Arc<BlockDevice>> {
        let mut slot = self
            .state
            .lock()
            .map_err(|_| CoreError::invalid("write opener lock is poisoned".to_string()))?;
        if let Some(handle) = slot.as_ref() {
            return Ok(Arc::clone(handle));
        }
        let handle = Arc::new(self.backend.open()?);
        self.opens.fetch_add(1, Ordering::SeqCst);
        *slot = Some(Arc::clone(&handle));
        Ok(handle)
    }

    /// Forget the cached handle (flushing first): the next use reopens
    /// from scratch. The external formatters need this — see the module
    /// docs.
    fn release(&self) -> Result<()> {
        let taken = self
            .state
            .lock()
            .map_err(|_| CoreError::invalid("write opener lock is poisoned".to_string()))?
            .take();
        if let Some(handle) = taken {
            handle.flush()?;
        }
        Ok(())
    }

    /// The whole-disk target over the shared handle.
    fn device_target(&self) -> Result<Box<dyn Target>> {
        let handle = self.handle()?;
        let sector = handle.logical_sector_size();
        Ok(Box::new(SinkTarget::new(handle, sector)))
    }

    /// The data-partition window over the shared handle. Geometry comes
    /// off the live handle through the same planner call `Mkpart`
    /// stamps with — one triple, one function, no second computation.
    fn partition_volume(&self) -> Result<Box<dyn Volume>> {
        let handle = self.handle()?;
        let (offset, len) =
            single_data_window(self.table, handle.logical_sector_size(), handle.size())?;
        let sector = handle.logical_sector_size();
        Ok(Box::new(SinkVolume::new(handle, offset, len, sector)?))
    }
}

/// [`Opener`] for a real device node: opens lazily and exclusively,
/// serves the partition as a window over the same handle, resolves the
/// partition node through
/// [`partition_name`](crate::inspect::partition_name) (core never
/// invents the name), and waits for the node after `Mkpart` before an
/// external formatter may claim it.
#[derive(Debug)]
pub struct DeviceOpener(Arc<Shared>);

impl DeviceOpener {
    /// Record `device` (discovered, e.g. by enumeration) for the table
    /// `table`: nothing opens yet. The partition node spelling comes
    /// from the sysfs partition list when it names index 1, else the
    /// plain-digit rule — the same rule `S04` lists with.
    pub fn new(device: &Device, table: TableKind, sysfs: SysfsRoot) -> Self {
        let backend = Backend::Device {
            path: PathBuf::from(&device.dev_path),
            disk_name: device.name.clone(),
            part_name: partition_name(device, 1),
            size: device.size_bytes,
            logical: device.sector_size,
            physical: device.physical_sector_size,
            sysfs,
            usb: device.usb,
        };
        Self(Arc::new(Shared {
            table,
            backend,
            state: Mutex::new(None),
            opens: AtomicUsize::new(0),
        }))
    }
}

impl Opener for DeviceOpener {
    fn device(&self) -> Result<Box<dyn Target>> {
        self.0.device_target()
    }

    fn partition(&self) -> Result<Box<dyn Volume>> {
        self.0.partition_volume()
    }

    fn partition_path(&self) -> Result<PathBuf> {
        let Backend::Device {
            disk_name,
            part_name,
            sysfs,
            ..
        } = &self.0.backend
        else {
            return Err(CoreError::invalid(
                "device opener lost its device backend".to_string(),
            ));
        };
        // After Mkpart the kernel must know the new table before the
        // node exists: poll sysfs (bounded — an already-present node
        // answers on the first check) and name the node on timeout.
        wait_for_partitions(
            sysfs,
            disk_name,
            std::slice::from_ref(part_name),
            PARTITION_POLL_TIMEOUT,
            PARTITION_POLL_INTERVAL,
        )?;
        Ok(PathBuf::from(format!("/dev/{part_name}")))
    }

    fn release(&self) -> Result<()> {
        self.0.release()
    }

    /// Mount the data partition node (resolved through
    /// [`partition_path`](DeviceOpener::partition_path), so the kernel
    /// knows the node first) for `filesystem` through
    /// [`mount`](crate::mount::partition::mount): the guard owns the
    /// mount until its explicit release or its best-effort drop, and
    /// answers the copy pre-flight with `statvfs`.
    fn mount_partition(&self, filesystem: &Filesystem) -> Result<Box<dyn MountedPartition>> {
        let path = self.partition_path()?;
        let mounted = crate::mount::partition::mount(&path, filesystem)?;
        Ok(Box::new(mounted))
    }

    fn reset_device(&self) -> Result<bool> {
        let Backend::Device {
            disk_name,
            sysfs,
            usb,
            ..
        } = &self.0.backend
        else {
            return Err(CoreError::invalid(
                "device opener lost its device backend".to_string(),
            ));
        };
        if !usb {
            // No bus to reset: best effort, not an error.
            return Ok(false);
        }
        let Some(node) = usb_reset_node(sysfs, disk_name) else {
            // The bus/device address is unknowable here: best effort,
            // not an error.
            return Ok(false);
        };
        // A reset is a write-class operation, so the node opens
        // read-write with `O_NOFOLLOW` like the block layer (a swapped
        // symlink must never redirect a privileged reset); an
        // unopenable node is best effort too (permissions, a device
        // that just vanished) — never the write error.
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&node)
        {
            Ok(file) => file,
            Err(_) => return Ok(false),
        };
        crate::ioctl::usb_reset(&file).map_err(|error| CoreError::io(&node, error))?;
        Ok(true)
    }
}

/// [`Opener`] for the `--device-file` test seam: `path` is a regular
/// file (created empty when absent) opened buffered and sized from its
/// own length — never from the plan's device facts. Anything that is
/// not a regular file refuses: a block node (which is what a mounted
/// device path is), a directory, a character device, anything else.
/// Any symlink is refused at open as a symlink, without following it:
/// the check uses `symlink_metadata`, so a link to a device node never
/// even learns what it points at. The plan's device path is never
/// opened in this mode, so the seam cannot silently write a graded
/// device.
///
/// There is no partition node behind a file: `partition_path` refuses
/// honestly, so tool-based filesystems (NTFS, ext2/3/4, UDF) stay
/// real-device-only while the native engines run unchanged. Mounting
/// keeps the same default refusal for the same reason: a file seam has
/// no partition node to mount, so
/// [`mount_partition`](Opener::mount_partition) is not overridden here.
#[derive(Debug)]
pub struct FileOpener(Arc<Shared>);

impl FileOpener {
    /// Check the seam file (creating it empty when absent, refusing
    /// symlinks and non-regular nodes as usage errors) and open it
    /// eagerly: one `metadata` call, one handle, no check-then-use
    /// window for a swap in between. The handle lives in the shared
    /// slot, so [`release`](Opener::release) and the lazy reopen after
    /// it work exactly as for the device opener.
    ///
    /// A symlink argument is caller misuse, not device I/O, so it maps
    /// to exit 1 (`InvalidInput`); only a link swapped in after this
    /// check still fails later at the `O_NOFOLLOW` open as I/O, which
    /// is the fail-closed remainder of the same race.
    pub fn open(path: &Path, table: TableKind) -> Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(CoreError::invalid(format!(
                        "--device-file '{}' is a symlink: the write test seam takes regular files only, never a link",
                        path.display()
                    )));
                }
                check_regular(path, &meta)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| CoreError::io(path, error))?;
            }
            Err(error) => return Err(CoreError::io(path, error)),
        }
        let shared = Arc::new(Shared {
            table,
            backend: Backend::File {
                path: path.to_path_buf(),
            },
            state: Mutex::new(None),
            opens: AtomicUsize::new(0),
        });
        shared.handle()?;
        Ok(Self(shared))
    }
}

/// Refuse every `--device-file` node that is not a regular file, naming
/// what was found.
fn check_regular(path: &Path, meta: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::FileTypeExt as _;

    if meta.is_file() {
        return Ok(());
    }
    let kind = if meta.file_type().is_block_device() {
        "a block device"
    } else if meta.file_type().is_char_device() {
        "a character device"
    } else if meta.is_dir() {
        "a directory"
    } else {
        "not a regular file"
    };
    Err(CoreError::invalid(format!(
        "--device-file '{}' is {kind}: the write test seam takes regular files only, never a device node",
        path.display()
    )))
}

impl Opener for FileOpener {
    fn device(&self) -> Result<Box<dyn Target>> {
        self.0.device_target()
    }

    fn partition(&self) -> Result<Box<dyn Volume>> {
        self.0.partition_volume()
    }

    fn partition_path(&self) -> Result<PathBuf> {
        Err(CoreError::invalid(
            "the file seam has no partition node: tool-based filesystems (ntfs, ext2/3/4, udf) need a real device",
        ))
    }

    fn data_ranges(&self, path: &Path) -> Result<Option<Vec<(u64, u64)>>> {
        data_ranges_of_file(path)
    }

    fn release(&self) -> Result<()> {
        self.0.release()
    }
}

/// At most this many `SEEK_DATA`/`SEEK_HOLE` round trips per query:
/// 64 K ranges cover far more fragmentation than a real image file
/// ever shows (each trip is two syscalls, so the walk stays cheap),
/// while a file needing more is pathological — or the kernel stopped
/// making progress — and the query then falls back to `None` (whole
/// file as data, always correct) rather than looping forever.
const MAX_RANGES: usize = 64 * 1024;

/// The USB reset node for a disk: `/dev/bus/usb/BBB/DDD` from the
/// bus/device address, not from any stored field — the [`Device`]
/// model carries no bus or device numbers (only the `usb` flag, the
/// `vid:pid` and the port path), so the address is resolved live by
/// walking up from `<sysfs>/class/block/<disk>/device` to the ancestor
/// carrying the `busnum` and `devnum` attributes (the USB device node
/// itself). At most eight levels up: a real chain is four or fewer,
/// and anything deeper is not a USB stick. `None` when the chain, the
/// attributes, or their numbers are missing — best effort, never an
/// error here.
fn usb_reset_node(sysfs: &SysfsRoot, disk: &str) -> Option<PathBuf> {
    let mut dir = std::fs::canonicalize(
        sysfs
            .root
            .join("class")
            .join("block")
            .join(disk)
            .join("device"),
    )
    .ok()?;
    for _ in 0..8 {
        let address = std::fs::read_to_string(dir.join("busnum"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .zip(
                std::fs::read_to_string(dir.join("devnum"))
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok()),
            );
        if let Some((bus, dev)) = address {
            return Some(PathBuf::from(format!("/dev/bus/usb/{bus:03}/{dev:03}")));
        }
        dir = dir.parent()?.to_path_buf();
    }
    // No ancestor carries an address: not a USB stick under here.
    None
}
/// Hole map of the regular file at `path` through `SEEK_DATA`/
/// `SEEK_HOLE` (`rustix`, no new `unsafe`): ascending,
/// non-overlapping, merged data runs clamped to the file length —
/// exactly what
/// [`Opener::data_ranges`](rufus_core::pipeline::Opener::data_ranges)
/// promises. `None` when the filesystem cannot answer (`EINVAL`,
/// `ENOTSUP`/`EOPNOTSUPP`); `Some(vec![])` when the query succeeds on
/// a file with no data at all (including the zero-length file). Any
/// other failure is a genuine I/O error naming the path.
///
/// A non-regular path (FIFO, device node, directory, anything but a
/// file) is an unknown map, so `Ok(None)` and the caller streams it:
/// opening a FIFO would block forever and a node has no length to
/// clamp to, and neither can hold holes worth discovering.
fn data_ranges_of_file(path: &Path) -> Result<Option<Vec<(u64, u64)>>> {
    /// A `SEEK_DATA`/`SEEK_HOLE` refusal the caller cannot answer
    /// with: fall back to the whole file as data. (`rustix` reports
    /// raw codes here, so the comparison is against `libc` like the
    /// block layer's own errno mapping.)
    fn unsupported(raw: i32) -> bool {
        raw == libc::EINVAL || raw == libc::ENOTSUP || raw == libc::EOPNOTSUPP
    }

    // Stat first: a FIFO must never reach `open` (it would block
    // forever), and only a regular file has a length to clamp to and
    // holes worth discovering. One stat call, no second open.
    let meta = std::fs::metadata(path).map_err(|error| CoreError::io(path, error))?;
    if !meta.is_file() {
        return Ok(None);
    }
    let len = meta.len();
    // Read-only, no exclusive claim: this runs alongside the open
    // read-write handle without disturbing it.
    let file = std::fs::File::open(path).map_err(|error| CoreError::io(path, error))?;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut off = 0u64;
    while off < len {
        if ranges.len() >= MAX_RANGES {
            // Pathological fragmentation (or a stuck kernel): correct
            // beats sparse — the whole file as data.
            return Ok(None);
        }
        let data = match rustix::fs::seek(&file, rustix::fs::SeekFrom::Data(off)) {
            Ok(data) => data.min(len),
            // No data at or past `off`: a trailing hole to EOF.
            Err(error) if error.raw_os_error() == libc::ENXIO => break,
            Err(error) if unsupported(error.raw_os_error()) => return Ok(None),
            Err(error) => return Err(CoreError::io(path, std::io::Error::from(error))),
        };
        if data >= len {
            // Defensive: no data below EOF means a trailing hole.
            break;
        }
        if data < off {
            // The kernel went backwards: untrustworthy answer, fall
            // back rather than loop.
            return Ok(None);
        }
        let hole = match rustix::fs::seek(&file, rustix::fs::SeekFrom::Hole(data)) {
            Ok(hole) => hole.min(len),
            // No hole past `data` should be impossible (the kernel
            // implies one at EOF): read it as EOF.
            Err(error) if error.raw_os_error() == libc::ENXIO => len,
            Err(error) if unsupported(error.raw_os_error()) => return Ok(None),
            Err(error) => return Err(CoreError::io(path, std::io::Error::from(error))),
        };
        if hole <= data {
            // A zero-length or backwards run contradicts the walk:
            // fall back rather than record or loop on it.
            return Ok(None);
        }
        // Adjacent runs merge (a zero-length hole between them would
        // contradict the walk, so equality is the only case).
        if let Some(last) = ranges.last_mut() {
            if last.0 + last.1 == data {
                last.1 += hole - data;
            } else {
                ranges.push((data, hole - data));
            }
        } else {
            ranges.push((data, hole - data));
        }
        off = hole;
    }
    Ok(Some(ranges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemorySink;

    /// A shared memory sink behind an [`Arc`], like the openers hold
    /// their device.
    fn shared_sink(len: usize) -> Arc<MemorySink> {
        Arc::new(MemorySink::new(len))
    }

    #[test]
    fn sink_target_delegates_every_call() {
        let sink = shared_sink(4096);
        let target = SinkTarget::new(Arc::clone(&sink), 512);
        assert_eq!(target.size(), 4096);
        assert_eq!(target.sector_size(), 512);
        target.write_all_at(100, &[7u8; 16]).expect("write lands");
        let mut buf = [0u8; 16];
        target.read_at(100, &mut buf).expect("read lands");
        assert_eq!(buf, [7u8; 16]);
        let done = target
            .write_all_at_cancellable(200, &[9u8; 32], 8, &|| false)
            .expect("cancellable write lands");
        assert_eq!(done, 32);
        target.zero_range(200, 8, &|| false).expect("zero lands");
        target.read_at(200, &mut buf).expect("read lands");
        assert_eq!(&buf[..8], &[0u8; 8]);
        assert_eq!(&buf[8..], &[9u8; 8]);
        // Best-effort discard and the no-op rescan report Ok.
        target.discard(0, 4096).expect("discard hints");
        target.flush().expect("flush lands");
        target.reread_partitions().expect("rescan lands");
        // The bytes went to the shared sink, not a copy.
        assert_eq!(&sink.snapshot()[100..116], &[7u8; 16]);
    }

    #[test]
    fn sink_volume_windows_reads_and_writes() {
        let sink = shared_sink(8192);
        let mut view = SinkVolume::new(Arc::clone(&sink), 1024, 2048, 512).expect("window fits");
        assert_eq!(view.total_bytes(), 2048);
        assert_eq!(view.sector_size(), 512);
        view.write_all_at(0, &[3u8; 64])
            .expect("windowed write lands");
        let mut buf = [0u8; 64];
        view.read_exact_at(0, &mut buf)
            .expect("windowed read lands");
        assert_eq!(buf, [3u8; 64]);
        assert_eq!(&sink.snapshot()[1024..1088], &[3u8; 64]);
        assert_eq!(
            sink.snapshot()[1023],
            0,
            "one byte before the base is untouched"
        );
        view.flush().expect("flush lands");
    }

    #[test]
    fn sink_volume_refuses_bad_windows() {
        let sink = shared_sink(8192);
        // Past the end names base, end and size.
        let error = SinkVolume::new(Arc::clone(&sink), 8192, 512, 512)
            .expect_err("an overrunning window refuses");
        let text = error.to_string();
        assert!(text.contains("8192"), "{text}");
        assert!(text.contains("8704"), "{text}");
        // Alignment is a construction invariant.
        let error = SinkVolume::new(Arc::clone(&sink), 1000, 1024, 512)
            .expect_err("an unaligned base refuses");
        assert!(error.to_string().contains("1000"), "{error:?}");
        let error = SinkVolume::new(Arc::clone(&sink), 1024, 1000, 512)
            .expect_err("an unaligned length refuses");
        assert!(error.to_string().contains("1000"), "{error:?}");
        let error = SinkVolume::new(Arc::clone(&sink), 1024, 1024, 0)
            .expect_err("a zero sector size refuses");
        assert!(error.to_string().contains("zero"), "{error:?}");
        // Per-op bounds name offset, length and base.
        let mut view = SinkVolume::new(Arc::clone(&sink), 1024, 512, 512).expect("window fits");
        let error = view
            .write_all_at(500, &[1u8; 16])
            .expect_err("a past-the-window write refuses");
        let text = error.to_string();
        assert!(text.contains("500"), "{text}");
        assert!(text.contains("1024"), "{text}");
        let mut buf = [0u8; 16];
        let error = view
            .read_exact_at(500, &mut buf)
            .expect_err("a past-the-window read refuses");
        assert!(error.to_string().contains("500"), "{error:?}");
    }

    #[test]
    fn file_opener_shares_one_handle_and_reopens_after_release() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("stick.img");
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("seam file creates")
            .set_len(64 * 1024 * 1024)
            .expect("seam file sizes");
        let opener = FileOpener::open(&path, TableKind::Mbr).expect("seam opens");
        // Device and partition views share the one open: no second
        // exclusive claim, one counted open.
        let device = opener.device().expect("device opens");
        let mut partition = opener.partition().expect("partition views");
        assert_eq!(opener.0.opens.load(Ordering::SeqCst), 1);
        assert_eq!(device.size(), 64 * 1024 * 1024);
        // The planner's Single window on a 64 MiB MBR disk: 1 MiB base,
        // 63 MiB long.
        assert_eq!(partition.total_bytes(), 63 * 1024 * 1024);
        partition
            .write_all_at(0, &[5u8; 32])
            .expect("partition write lands");
        let mut buf = [0u8; 32];
        device
            .read_at(1024 * 1024, &mut buf)
            .expect("device sees the partition write");
        assert_eq!(buf, [5u8; 32]);
        // Release forgets the handle; the next device use reopens.
        opener.release().expect("release flushes");
        let device = opener.device().expect("device reopens");
        assert_eq!(opener.0.opens.load(Ordering::SeqCst), 2);
        device
            .read_at(1024 * 1024, &mut buf)
            .expect("bytes survive the reopen");
        assert_eq!(buf, [5u8; 32]);
    }

    #[test]
    fn device_opener_partitions_without_a_second_handle() {
        use crate::model::Transport;

        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("disk.img");
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("backing file creates")
            .set_len(64 * 1024 * 1024)
            .expect("backing file sizes");
        let device = Device {
            sysfs: dir.path().join("sys/class/block/sdb").display().to_string(),
            name: "sdb".to_string(),
            dev_path: path.display().to_string(),
            size_bytes: 64 * 1024 * 1024,
            sector_size: 512,
            physical_sector_size: 512,
            removable: true,
            read_only: false,
            usb: true,
            vendor: None,
            model: None,
            serial: None,
            transport: Transport::Unknown,
            partition_table: None,
            vid_pid: None,
            port_path: None,
            partitions: Vec::new(),
        };
        let opener = DeviceOpener::new(
            &device,
            TableKind::Mbr,
            SysfsRoot::new(dir.path().join("sys")),
        );
        // The partition is a window over the same open handle: one
        // counted open for both views, never a second exclusive claim.
        let device_target = opener.device().expect("device opens");
        let mut partition = opener.partition().expect("partition views");
        assert_eq!(opener.0.opens.load(Ordering::SeqCst), 1);
        assert_eq!(partition.total_bytes(), 63 * 1024 * 1024);
        partition
            .write_all_at(0, &[7u8; 32])
            .expect("partition write lands");
        let mut buf = [0u8; 32];
        device_target
            .read_at(1024 * 1024, &mut buf)
            .expect("device sees the partition write");
        assert_eq!(buf, [7u8; 32]);
    }

    #[test]
    fn file_seam_creates_refuses_and_has_no_node() {
        let dir = tempfile::tempdir().expect("scratch dir");
        // Absent: created empty (length 0 — the pipeline will refuse an
        // image that does not fit, which is the honest answer).
        let fresh = dir.path().join("fresh.img");
        let opener = FileOpener::open(&fresh, TableKind::Mbr).expect("seam creates");
        assert_eq!(opener.device().expect("device opens").size(), 0);
        // A directory is not a regular file.
        let error = FileOpener::open(dir.path(), TableKind::Mbr).expect_err("a dir refuses");
        assert!(error.to_string().contains("directory"), "{error:?}");
        // No partition node behind a file.
        let error = opener.partition_path().expect_err("the seam has no node");
        assert!(error.to_string().contains("no partition node"), "{error:?}");
    }

    #[test]
    fn data_ranges_of_a_sparse_file_are_exact() {
        use std::io::Seek as _;
        use std::io::Write as _;

        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("sparse.img");
        // Two 4 KiB data runs with holes around and between: 4 KiB at
        // 0, a hole to 6 MiB, 4 KiB there, a hole to EOF at 8 MiB.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("sparse file creates");
        file.write_all(&[0x5Au8; 4096]).expect("head writes");
        file.seek(std::io::SeekFrom::Start(6 * 1024 * 1024))
            .expect("hole seeks");
        file.write_all(&[0xA5u8; 4096]).expect("tail writes");
        file.set_len(8 * 1024 * 1024).expect("sparse file sizes");
        drop(file);
        let opener = FileOpener::open(&path, TableKind::Mbr).expect("seam opens");
        // A filesystem without hole queries answers `None`: accept
        // that explicitly (nothing to pin then) instead of assuming
        // tmpfs/ext4/overlayfs semantics everywhere.
        let Some(ranges) = opener.data_ranges(&path).expect("the query runs") else {
            return;
        };
        assert_eq!(ranges, [(0, 4096), (6 * 1024 * 1024, 4096)]);
        // The holes read back as zeros, and nothing is reported past
        // the length.
        let bytes = std::fs::read(&path).expect("sparse file reads");
        assert_eq!(bytes.len(), 8 * 1024 * 1024);
        assert!(bytes[4096..6 * 1024 * 1024].iter().all(|&byte| byte == 0));
        assert!(
            bytes[6 * 1024 * 1024 + 4096..]
                .iter()
                .all(|&byte| byte == 0)
        );
        let (last_off, last_len) = ranges.last().copied().expect("a data run");
        assert_eq!(last_off + last_len, 6 * 1024 * 1024 + 4096);
    }

    #[test]
    fn data_ranges_of_a_dense_file_is_one_range() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("dense.img");
        std::fs::write(&path, vec![0x5Au8; 1024 * 1024]).expect("dense file writes");
        let opener = FileOpener::open(&path, TableKind::Mbr).expect("seam opens");
        // A filesystem without hole queries answers `None`: accept
        // that explicitly (nothing to pin then) instead of assuming
        // tmpfs/ext4/overlayfs semantics everywhere.
        let Some(ranges) = opener.data_ranges(&path).expect("the query runs") else {
            return;
        };
        assert_eq!(ranges, [(0, 1024 * 1024)]);
    }

    #[test]
    fn data_ranges_of_an_empty_file_is_empty() {
        // The query succeeds on an empty file — there is just no data:
        // `Some([])`, never `None` (which means "cannot answer").
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("empty.img");
        std::fs::write(&path, []).expect("empty file writes");
        let opener = FileOpener::open(&path, TableKind::Mbr).expect("seam opens");
        // A filesystem without hole queries answers `None`: accept
        // that explicitly (nothing to pin then) instead of assuming
        // tmpfs/ext4/overlayfs semantics everywhere.
        let Some(ranges) = opener.data_ranges(&path).expect("the query runs") else {
            return;
        };
        assert!(ranges.is_empty(), "{ranges:?}");
    }

    #[test]
    fn reset_device_is_unsupported_off_usb() {
        use crate::model::Transport;

        // A non-USB disk: reset reports `Ok(false)` without touching
        // hardware (no bus node exists for it) — the reset ioctl
        // itself is pinned in `ioctl.rs` without any device at all.
        // The file seam keeps the same default by construction.
        let dir = tempfile::tempdir().expect("scratch dir");
        let device = Device {
            sysfs: dir.path().join("sys/class/block/sda").display().to_string(),
            name: "sda".to_string(),
            dev_path: "/dev/sda".to_string(),
            size_bytes: 1024 * 1024 * 1024,
            sector_size: 512,
            physical_sector_size: 512,
            removable: false,
            read_only: false,
            usb: false,
            vendor: None,
            model: None,
            serial: None,
            transport: Transport::Sata,
            partition_table: None,
            vid_pid: None,
            port_path: None,
            partitions: Vec::new(),
        };
        let opener = DeviceOpener::new(
            &device,
            TableKind::Mbr,
            SysfsRoot::new(dir.path().join("sys")),
        );
        assert!(!opener.reset_device().expect("no error"));
    }

    #[test]
    fn file_seam_refuses_symlinks_without_following() {
        use rufus_core::error::CoreError;

        let dir = tempfile::tempdir().expect("scratch dir");
        let target = dir.path().join("backing.img");
        std::fs::write(&target, vec![0xAAu8; 4096]).expect("backing writes");
        let link = dir.path().join("link.img");
        std::os::unix::fs::symlink(&target, &link).expect("link creates");
        // A link to a regular file refuses as a link, never as the
        // file: usage error (exit 1 at the CLI), not I/O.
        let error = FileOpener::open(&link, TableKind::Mbr).expect_err("a link refuses");
        assert!(
            matches!(error, CoreError::InvalidInput { .. }),
            "a symlink is misuse, not device failure: {error:?}"
        );
        assert!(error.to_string().contains("symlink"), "{error:?}");
        // A dangling link refuses the same way (symlink_metadata sees
        // the link itself, never its absent target).
        let dangling = dir.path().join("dangling.img");
        std::os::unix::fs::symlink(dir.path().join("absent.img"), &dangling).expect("link creates");
        let error = FileOpener::open(&dangling, TableKind::Mbr).expect_err("dangling refuses");
        assert!(error.to_string().contains("symlink"), "{error:?}");
    }
}
