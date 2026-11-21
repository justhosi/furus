//! The shared GUI / helper / packaging service contract.
//!
//! Every identifier that crosses the boundary between the unprivileged GUI,
//! the root helper and the installed packaging files lives here, exactly once.
//! The GUI and the helper import these constants; `xtask contract --check`
//! (wired into `cargo xtask ci`) reads this file and asserts the packaging
//! files agree with it. That gate is what keeps the three copies from
//! drifting silently: changing a value here without updating packaging — or
//! vice versa — fails CI with a file/line-specific message.
//!
//! These are wire identifiers (D-Bus names, error names, a polkit action and
//! the installed helper path). They are deliberately not derived from
//! anything else: a rename is a compatibility break for every client and
//! every installed system, so it must be a single, visible edit.
//!
//! Note for tooling: `xtask` scans this file for the literal
//! `pub const NAME: &str = "...";` declarations, so keep that exact spelling.

/// Well-known system-bus name the root helper owns and the GUI calls.
pub const BUS_NAME: &str = "org.furuslinux.Helper1";

/// Object path at which the helper exports [`INTERFACE_NAME`].
pub const OBJECT_PATH: &str = "/org/furuslinux/Helper1";

/// Interface name of the exported `Helper1` object.
///
/// Kept distinct from [`BUS_NAME`] even though the values match, so a rename
/// of one is a deliberate decision about the other. The zbus macro in the
/// helper needs a literal, so the `#[zbus::interface(name = "...")]` literal
/// is itself checked against this constant by `xtask contract --check`.
pub const INTERFACE_NAME: &str = "org.furuslinux.Helper1";

/// The one polkit action a caller must hold before a plan is read.
pub const POLKIT_ACTION: &str = "org.furuslinux.write-device";

/// D-Bus error name for a caller that is not authorized (or whose check
/// failed — fail closed).
pub const ERROR_NOT_AUTHORIZED: &str = "org.furuslinux.Error.NotAuthorized";

/// D-Bus error name for a request refused while another session runs.
pub const ERROR_BUSY: &str = "org.furuslinux.Error.Busy";

/// D-Bus error name for a plan that failed to parse or to validate.
pub const ERROR_INVALID_PLAN: &str = "org.furuslinux.Error.InvalidPlan";

/// D-Bus error name for a `Cancel` naming nothing running.
pub const ERROR_UNKNOWN_SESSION: &str = "org.furuslinux.Error.UnknownSession";

/// Installed path of the privileged helper binary (root-owned, mode 0755).
///
/// The D-Bus service file's `Exec=` line and every packaging recipe's
/// install/chown target must use this exact path.
pub const HELPER_BIN_PATH: &str = "/usr/libexec/furus-helper";

/// CLI argument that starts the helper in its long-lived D-Bus service mode.
///
/// Combined with [`HELPER_BIN_PATH`] it forms the service file's `Exec=` line.
pub const HELPER_DBUS_ARG: &str = "--dbus";
