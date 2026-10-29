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
//! * [`sysfs`] — [`SysfsRoot`](sysfs::SysfsRoot) (where to read),
//!   [`enumerate`](sysfs::enumerate) (discovery from `class/block` plus
//!   the udev data records) and [`filter`](sysfs::filter) (the
//!   Rufus-visible candidate rule), all fixture-friendly and testable
//!   without hardware.
//! * [`udev_db`] — [`read_record`](udev_db::read_record): the flat
//!   `/run/udev/data/b<major>:<minor>` records without libudev.
//! * [`watch`] — [`DeviceWatcher`](watch::DeviceWatcher): inotify fast
//!   path with debounce, 2 s poll fallback, reports only real change.
//!
//! The crate is dependency-light by design (rustix for syscalls, serde
//! for the model, `rufus-core` for errors): no libudev, no async, no
//! libc, no subprocesses — see PLAN §4/§5.

#![forbid(unsafe_code)]

pub mod model;
pub mod sysfs;
pub mod udev_db;
pub mod watch;

pub use model::Device;
pub use model::Partition;
pub use model::Transport;
pub use sysfs::Filter;
pub use sysfs::SysfsRoot;
pub use sysfs::enumerate;
pub use sysfs::filter;
pub use udev_db::UdevRecord;
pub use udev_db::read_record;
pub use watch::DeviceWatcher;
