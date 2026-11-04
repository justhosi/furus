//! `rufus-linux`: the only place in the rewrite that touches `/sys` and
//! `/run/udev`.
//!
//! Slice S04 delivers device discovery — the read-only half of the
//! crate. Every later slice (S05 introspection and safety verdicts, S07
//! block I/O, the S06 helper re-checks, the S24a GUI) builds on these
//! facts or can be tested against the same fixture trees, so keeping the
//! platform access in one crate is the point:
//!
//! * [`model`] — [`Device`](model::Device), [`Partition`](model::Partition)
//!   and [`Transport`](model::Transport): the facts PLAN §9-S04 pins,
//!   plus [`Device::identity`](model::Device::identity), the stable
//!   configuration key.
//!
//! * [`mount`] — the S06 mount seam moved here for the copy wiring:
//!   [`MountOps`](mount::MountOps) (the injectable mount/unmount
//!   surface), [`LiveOps`](mount::LiveOps) (the flag-pinned `NOSUID |
//!   NODEV` syscalls) and [`Recorder`](mount::Recorder) (the reverse
//!   sweep with the `MNT_DETACH` fallback), plus
//!   [`partition`](mount::partition) (the single-mount guard the copy
//!   step mounts, stats and releases).
//! * [`sysfs`] — [`SysfsRoot`](sysfs::SysfsRoot) (where to read),
//!   [`enumerate`](sysfs::enumerate) (discovery from `class/block` plus
//!   the udev data records) and [`filter`](sysfs::filter) (the
//!   Rufus-visible candidate rule), all fixture-friendly and testable
//!   without hardware.
//! * [`mounts`] — the running system's view of a device:
//!   [`MountTable`](mounts::MountTable) (parsed from
//!   `/proc/self/mountinfo`), swap entries (from `/proc/swaps`, see
//!   [`SwapEntry`](mounts::SwapEntry)) and [`holders`](mounts::holders)
//!   — the dm/md/bcache stack on top of a device.
//! * [`inspect`] — [`inspect`](inspect::inspect): the read-only device
//!   sampling that produces the reports and the [`Target`] the PLAN §6
//!   verdict consumes, with [`Inspected`](inspect::Inspected) carrying
//!   both. Never fails: an unreadable device is a verdict, not an error.
//! * [`udev_db`] — [`read_record`](udev_db::read_record): the flat
//!   `/run/udev/data/b<major>:<minor>` records without libudev.
//! * [`watch`] — [`DeviceWatcher`](watch::DeviceWatcher): inotify fast
//!   path with debounce, 2 s poll fallback, reports only real change.
//! * [`block`] — S07 block I/O: [`Sink`](block::Sink) (the write
//!   surface), [`BlockDevice`](block::BlockDevice) (a device node or a
//!   stand-in file), the [`AlignedBuf`](block::AlignedBuf) direct
//!   requests require plus the [`MemorySink`](block::MemorySink) and
//!   [`SparseFile`](block::SparseFile) test doubles.
//! * [`ioctl`] — the kernel ioctl shim (`BLKZEROOUT`, `BLKDISCARD`,
//!   `BLKRRPART`, `BLKFLSBUF`, plus `USBDEVFS_RESET` for the slice-8
//!   post-retry USB reset): the only module of the workspace that
//!   may compile unsafe code, and exactly what it may call.
//! * [`wipe`] — the S08 wipe sequence on the PLAN §6 rule-6 seam:
//!   [`wipe_device`](wipe::wipe_device) clears the first/last 1 MiB
//!   (optional whole-device discard hint first) and re-reads the
//!   table, [`wait_for_partitions`](wipe::wait_for_partitions) polls
//!   sysfs for the expected partition nodes within
//!   [`PARTITION_POLL_TIMEOUT`](wipe::PARTITION_POLL_TIMEOUT).
//! * [`adapter`] — the S17 write adapters: [`SinkTarget`](adapter::SinkTarget)
//!   (core `Target` over a block `Sink`), [`SinkVolume`](adapter::SinkVolume)
//!   (the partition window over the same open handle — a second `O_EXCL`
//!   claim on one disk fails, so the partition never re-opens), plus the
//!   [`DeviceOpener`](adapter::DeviceOpener) and [`FileOpener`](adapter::FileOpener)
//!   store suppliers with the release/reopen protocol the external
//!   formatters need.
//!
//! * [`signal`] — the S17 Ctrl-C flag: [`Cancel`](signal::Cancel)
//!   owns a per-run flag plus the process-global SIGINT arrival bit,
//!   with exactly one async-signal-safe handler install.
//!
//! The crate is dependency-light by design (rustix for syscalls, serde
//! for the model, `rufus-core` for errors): no libudev, no async, no
//! subprocesses — see PLAN §4/§5. The single exception is `libc`, and
//! only for the S07 ioctl shim above (rustix wraps nothing else the
//! block layer needs) plus the S17 SIGINT install (one `signal` call).

// Unsafe policy (S07, extended S17): the workspace lint is `deny` and
// this crate inherits it; exactly two `#[allow(unsafe_code)]` sites
// exist in the whole tree — the `ioctl_raw` shim inside `crate::ioctl`
// (see that module header for what is allowed and why) and the SIGINT
// install inside `crate::signal` (see that module charter). There must
// be no third unsafe use anywhere — the other crates still carry
// crate-level `#![forbid(unsafe_code)]`.

pub mod adapter;
pub mod block;
pub mod inspect;
mod ioctl;
pub mod model;
pub mod mount;
pub mod mounts;
pub mod signal;
pub mod sysfs;
pub mod udev_db;
pub mod watch;
pub mod wipe;

pub use adapter::DeviceOpener;
pub use adapter::FileOpener;
pub use adapter::FileTarget;
pub use adapter::SinkTarget;
pub use adapter::SinkVolume;
pub use block::{AlignedBuf, BlockDevice, MemorySink, Sink, SparseFile};
pub use inspect::Inspected;
pub use inspect::inspect;
pub use inspect::partition_name;
pub use model::Device;
pub use model::Partition;
pub use model::Transport;
pub use mounts::MountEntry;
pub use mounts::MountTable;
pub use mounts::SwapEntry;
pub use signal::Cancel;
pub use sysfs::Filter;
pub use sysfs::SysfsRoot;
pub use sysfs::enumerate;
pub use sysfs::filter;
pub use udev_db::UdevRecord;
pub use udev_db::read_record;
pub use watch::DeviceWatcher;
pub use wipe::PARTITION_POLL_INTERVAL;
pub use wipe::PARTITION_POLL_TIMEOUT;
pub use wipe::WIPE_WINDOW_BYTES;
pub use wipe::wait_for_partitions;
pub use wipe::wipe_device;
