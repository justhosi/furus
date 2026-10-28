//! `rufus-linux`: sysfs/udev device access and privileged I/O helpers.
//!
//! Slice S01 only: a placeholder module. Real discovery (`sysfs`, `udev_db`,
//! block I/O) arrives in S04/S07.

/// Placeholder for the sysfs device discovery owned by S04.
pub mod sysfs {
    /// Returns `true`; replaced by real enumeration in S04.
    pub fn placeholder() -> bool {
        true
    }
}
