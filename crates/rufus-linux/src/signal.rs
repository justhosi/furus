//! POSIX Ctrl-C flag for the write pipeline (S17, slice 4).
//!
//! Charter: exactly one unsafe operation lives here — the
//! `libc::signal` call in [`install_handler`], under a single
//! documented `#[allow(unsafe_code)]` matching the `ioctl.rs` precedent.
//! Everything else (flag, queries, the handler body) is safe code: the
//! handler performs one lock-free atomic store and touches nothing
//! else — no allocation, no locks, no I/O, no access to the
//! per-instance flags it cannot reach — which is the whole
//! async-signal-safety argument.
//!
//! Design: each [`Cancel`] owns its flag, so unit tests stay hermetic
//! without installing anything; a process-global flag records SIGINT
//! arrivals for whichever instance is installed. `is_cancelled` (and
//! [`as_fn`](Cancel::as_fn)) reports either flag, so a Ctrl-C cancels
//! the installed run even though the handler cannot route to one
//! instance. Installing twice reinstalls the same handler and resets
//! both flags — effectively a no-op — and the handler stays installed
//! for the process lifetime: the CLI installs once per `write`
//! invocation, and the reset at install means a stale Ctrl-C never
//! poisons the next run.
//!
//! Delivery: `libc::signal` keeps BSD semantics (`SA_RESTART`), so a
//! Ctrl-C during a blocked device write restarts the syscall instead
//! of failing it — the cancellation lands at the next chunk check,
//! never as a torn write. The install permanently replaces the default
//! `SIG_DFL` disposition (which would terminate the process), so a
//! second Ctrl-C sets the same flag again instead of force-killing a
//! run that is already unwinding.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use rufus_core::error::CoreError;
use rufus_core::error::Result;

/// Set by the SIGINT handler; read by every live [`Cancel`].
static SIGINT_SEEN: AtomicBool = AtomicBool::new(false);

/// The SIGINT handler: one atomic store, nothing else. See the module
/// charter for why this is async-signal-safe.
extern "C" fn on_sigint(_signum: libc::c_int) {
    SIGINT_SEEN.store(true, Ordering::SeqCst);
}

/// Install [`on_sigint`] for SIGINT, refusing the kernel's error.
#[allow(unsafe_code)]
fn install_handler() -> Result<()> {
    // SAFETY: `libc::signal` with the `SIGINT` constant and the
    // address of `on_sigint`, both verified against the locked libc
    // 0.2.191 sources (`sighandler_t` is `size_t`, so the pointer
    // round-trip carries the address unchanged). The handler itself is
    // safe code that only stores to a lock-free static atomic;
    // installing it twice reinstalls the identical handler.
    let previous =
        unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    if previous == libc::SIG_ERR {
        return Err(CoreError::invalid("could not install the SIGINT handler"));
    }
    Ok(())
}

/// A cancellable run's Ctrl-C flag: manual [`cancel`](Cancel::cancel)
/// for tests and plumbing, SIGINT once [`install`](Cancel::install)
/// runs. Cheap to clone (one shared flag): hand a clone to every
/// thread that needs the probe.
#[derive(Debug, Clone)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A fresh, un-cancelled flag.
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Reset both flags and install the SIGINT handler. Installing
    /// twice is a documented no-op in effect: the same handler goes
    /// back up and both flags start clear, so each run starts
    /// un-cancelled.
    pub fn install(&self) -> Result<()> {
        self.0.store(false, Ordering::SeqCst);
        SIGINT_SEEN.store(false, Ordering::SeqCst);
        install_handler()
    }

    /// Cancel manually, without any signal (tests and plumbing).
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// True after [`cancel`](Cancel::cancel) or a SIGINT past an
    /// [`install`](Cancel::install).
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst) || SIGINT_SEEN.load(Ordering::SeqCst)
    }

    /// A probe closure for the pipeline's `&dyn Fn() -> bool`.
    pub fn as_fn(&self) -> impl Fn() -> bool + '_ {
        let flag = Arc::clone(&self.0);
        move || flag.load(Ordering::SeqCst) || SIGINT_SEEN.load(Ordering::SeqCst)
    }
}

impl Default for Cancel {
    /// [`Cancel::new`]: a fresh, un-cancelled flag.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_flag_starts_clear() {
        let cancel = Cancel::new();
        assert!(!cancel.is_cancelled());
        assert!(!cancel.as_fn()());
    }

    #[test]
    fn cancel_sets_the_flag_and_the_probe() {
        let cancel = Cancel::new();
        let probe = cancel.as_fn();
        assert!(!probe());
        cancel.cancel();
        assert!(cancel.is_cancelled());
        assert!(probe());
    }

    #[test]
    fn default_matches_new() {
        let cancel = Cancel::default();
        assert!(!cancel.is_cancelled());
    }
}
