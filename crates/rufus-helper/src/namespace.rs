//! The per-run mount namespace (S06 part 4).
//!
//! A root helper that mounts anything must not drag the host into it:
//! `enter_mount_namespace` is the run's first privileged act after
//! validation — [`rustix::thread::unshare`] with `CLONE_NEWNS` gives
//! the run a fresh mount namespace, and `/` is made recursively private
//! so no later mount event (the S07/S17 writing pipeline's, the
//! recorder's cleanup) propagates to, or arrives uninvited from, the
//! host. Every mount this helper performs afterwards dies with the
//! helper process: a planned sweep stays planable, a crash cannot
//! strand state on the host, and nothing the host mounts mid-run can
//! change what this run sees.
//!
//! The call is one-shot and irreversible per process; `main` performs
//! it once, immediately before the plan loop starts, and aborts (exit
//! 4, ASCII stderr line) when it fails — validation having already
//! passed is no reason to run a write step in a namespace the helper
//! could not establish.
//!
//! # Why the deprecated wrapper
//!
//! `rustix::thread::unshare` is deprecated in favour of
//! `unshare_unsafe`, which this crate cannot call (it carries
//! `#![forbid(unsafe_code)]`, with no exception wanted here). The
//! deprecation's *stated* hazard is the `CLONE_FILES` misuse of the
//! safe-looking wrapper; the sole flag requested here is
//! `UnshareFlags::NEWNS`, which shares no file descriptor table, so
//! the safe wrapper is the right call — `main` runs it
//! single-threaded, before any reader threads exist.

use rufus_core::error::CoreError;
use rufus_core::text::device_text;
use rustix::mount::MountPropagationFlags;
use rustix::thread::UnshareFlags;

/// The stable snake_case reject code for a run that could not isolate
/// its mounts (front ends key codes, never messages).
pub const MOUNT_NAMESPACE_CODE: &str = "mount_namespace";

/// Enter a fresh mount namespace and make its root (`/` and every
/// mounted subtree, recursively) private.
///
/// Unsharing happens first and is a hard abort on failure (nothing was
/// touched yet); the propagation flip runs after and fails the same
/// way. Both messages are ASCII (sanitised) — `main` prefixes only
/// `failed: cannot isolate mounts: ` to the message it shows.
pub fn enter_mount_namespace() -> Result<(), CoreError> {
    #[allow(deprecated)]
    let isolated = rustix::thread::unshare(UnshareFlags::NEWNS);
    isolated.map_err(|source| {
        CoreError::invalid(device_text(&format!(
            "cannot enter a private mount namespace: {source}"
        )))
    })?;

    // `MS_REC | MS_PRIVATE` on `/`: the new namespace keeps whatever
    // peer-group relations the host had, so the recursive-private flip
    // is what actually stops mount events from leaking through them.
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|source| {
        CoreError::invalid(device_text(&format!(
            "cannot mark the new mount namespace private: {source}"
        )))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rufus_linux::mounts::MountTable;
    use tempfile::tempdir;

    use super::enter_mount_namespace;

    const THREAD_MOUNTINFO: &str = "/proc/thread-self/mountinfo";

    /// The kernel is the only judge of the grant: root (having
    /// `CAP_SYS_ADMIN`) gets the isolation, everyone else gets the
    /// abort. On current kernels this is exactly `unshare(2)`'s rule
    /// for `CLONE_NEWNS`; running as root here is self-contained — the
    /// fresh namespace changes only the calling thread's mounts, and
    /// the run mounts nothing.
    #[test]
    fn isolation_outcome_matches_the_kernel_grant() {
        if rustix::process::geteuid().as_raw() == 0 {
            enter_mount_namespace().expect("as root: unshare(CLONE_NEWNS) + private /");
        } else {
            let refused =
                enter_mount_namespace().expect_err("unprivileged runs cannot unshare(CLONE_NEWNS)");
            assert!(
                refused
                    .to_string()
                    .contains("cannot enter a private mount namespace"),
                "{refused}"
            );
        }
    }

    /// The whole point: a mount made after isolation is visible to this
    /// process and gone again after the sweep, without any host-visible
    /// trace (an isolated namespace's mounts simply die with the
    /// process). Needs real root for `unshare(CLONE_NEWNS)` and
    /// `mount(2)`; this repo's test runs are unprivileged, so it is
    /// skipped on purpose — never faked.
    ///
    /// The reads below use `/proc/thread-self/mountinfo` on purpose:
    /// `unshare(CLONE_NEWNS)` isolates only the calling thread while
    /// `/proc/self` follows the thread-group leader, so a test body
    /// running on a harness thread would read the host table through
    /// the default. The argv pipeline unshares on the main thread and
    /// may keep the default; the service worker unshares on its own
    /// thread, so any read it makes must pass the thread-specific
    /// path.
    #[ignore = "needs root: CAP_SYS_ADMIN for unshare(CLONE_NEWNS) + mount(2)"]
    #[test]
    fn a_mount_made_after_isolation_stays_inside_and_leaves_clean() {
        enter_mount_namespace().expect("as root: the run is now mount-isolated");
        let scratch = tempdir().expect("scratch dir inside the isolated namespace");
        let target = scratch.path().display().to_string();

        let mut live = crate::mount::LiveOps;
        let mut recorder = crate::mount::Recorder::new(&mut live);
        recorder
            .mount(std::path::Path::new("tmpfs"), scratch.path(), Some("tmpfs"))
            .expect("the isolated namespace still mounts tmpfs");

        let mounted_at = |table: &MountTable| {
            table
                .entries()
                .iter()
                .any(|entry| entry.fstype == "tmpfs" && entry.mountpoint == target)
        };
        let before = MountTable::read(Some(std::path::Path::new(THREAD_MOUNTINFO)))
            .expect("mountinfo of the isolated namespace");
        assert!(
            mounted_at(&before),
            "the mount is visible inside the namespace: {:?}",
            before.entries()
        );

        recorder
            .unmount_all()
            .expect("the unmounted tmpfs leaves the table again");
        let after = MountTable::read(Some(std::path::Path::new(THREAD_MOUNTINFO)))
            .expect("mountinfo after the sweep");
        assert!(
            !mounted_at(&after),
            "the recorder unmounted it: left, {:?}",
            after.entries()
        );
    }
}
