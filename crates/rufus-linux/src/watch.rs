//! Near-real-time device watching for the GUI hotplug list (S04; the GUI
//! wiring itself arrives in S24a).
//!
//! A re-scan on every udev blip is wasteful and flickery; a completely
//! event-driven design is fragile. [`DeviceWatcher`] sits in between:
//!
//! * inotify on `<sysfs-root>/class/block` (short) — the kernel's block
//!   subsystem creates and destroys device directories there, so
//!   add/remove/mount changes show up as CREATE/DELETE/ATTRIB events;
//!   a 200 ms debounce coalesces the burst into one rescan;
//! * a 2 s snapshot poll (long) for hosts and fixtures without inotify —
//!   containers and many CI sandboxes deny it — so behaviour degrades to
//!   slow instead of not working.
//!
//! inotify has no recursion: every device directory is watched in
//! addition to the class directory (partition create/delete react inside
//! it), and the watch set is re-attached before each rescan so
//! freshly-seen device directories are covered on the next wakeup.
//!
//! Both paths feed the same change filter: a cheap stable key per device
//! (name, size, partition names/sizes, removable/read-only flags) is
//! compared before anything is reported, so callers never see spurious
//! wakeups for attribute noise.
//!
//! No threads and no subprocesses are involved — the caller polls
//! [`DeviceWatcher::wait`] from *its* thread (the S24a GUI calls it on
//! its dedicated worker and forwards results to the event loop), and a
//! single CLI process has no need to watch at all.

use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use rustix::event::PollFd;
use rustix::event::PollFlags;
use rustix::event::Timespec;
use rustix::event::poll;
use rustix::fs::inotify;
use rustix::io::Errno;

use rufus_core::error::CoreError;
use rufus_core::error::Result;

use crate::model::Device;
use crate::sysfs::{self, Filter, SysfsRoot};

/// 200 ms debounce between an inotify wakeup and the rescan — enough to
/// swallow a kernel's CREATE/ATTRIB burst for one hotplug (PLAN §9-S04).
const DEBOUNCE: Duration = Duration::from_millis(200);
/// Fallback rescan cadence when the host offers no inotify.
const FALLBACK_CADENCE: Duration = Duration::from_secs(2);
/// Inotify read buffer bytes; a hotplug burst of events (16 bytes each
/// plus names) still fits comfortably.
const EVENT_BUFFER: usize = 4096;

/// Keeps a candidate device list current, reporting only real change.
pub struct DeviceWatcher {
    /// Where the snapshots come from (kept for rescans).
    sysfs: SysfsRoot,
    /// Candidate filter applied to every rescan.
    filter: Filter,
    /// inotify kernel open watch on `<root>/class/block`; `None` when
    /// inotify could not be created (see the module header).
    watch: Option<OwnedFd>,
    /// Most recent list *published* to the caller.
    snapshot: Vec<Device>,
    /// Stable key of `snapshot`; change detection needs no allocation on
    /// the noisy path.
    key: String,
    /// Last fallback rescan, pacing the poll path.
    last_poll: Instant,
}

impl DeviceWatcher {
    /// Build a watcher over `sysfs`, applying `filter` to every report.
    ///
    /// The first snapshot is taken synchronously and serves as the
    /// baseline. A missing or non-functional inotify is **not** an error
    /// (the module header explains the poll fallback); only a broken
    /// discovery (e.g. no `class/block`) fails here — the same error the
    /// CLI maps to exit 2.
    pub fn new(sysfs: SysfsRoot, filter: Filter) -> Result<Self> {
        let initial = sysfs::filter(sysfs::enumerate(&sysfs)?, filter);
        let key = snapshot_key(&initial);
        let watch = Self::open_watch(&sysfs).ok();
        Ok(DeviceWatcher {
            sysfs,
            filter,
            watch,
            snapshot: initial,
            key,
            last_poll: Instant::now(),
        })
    }

    /// Test-only watcher that skips inotify and always polls (the
    /// `watch: None` production state when the host offers no inotify).
    #[cfg(test)]
    fn new_with_poll_fallback(sysfs: SysfsRoot, filter: Filter) -> Result<Self> {
        let initial = sysfs::filter(sysfs::enumerate(&sysfs)?, filter);
        let key = snapshot_key(&initial);
        Ok(DeviceWatcher {
            sysfs,
            filter,
            watch: None,
            snapshot: initial,
            key,
            last_poll: Instant::now(),
        })
    }

    /// The last published device list (initial snapshot, or whatever
    /// [`DeviceWatcher::wait`] reported last).
    pub fn snapshot(&self) -> &[Device] {
        &self.snapshot
    }

    /// `true` when this host forced the 2 s poll fallback (no working
    /// inotify); a GUI may log the headline and it pins the watcher's
    /// timing expectations in tests.
    pub fn uses_poll_fallback(&self) -> bool {
        self.watch.is_none()
    }

    /// Block at most `timeout` for a device-list change.
    ///
    /// Returns the *new* list wrapped in `Some` when the stable key
    /// changed; `None` on a quiet timeout. Calling again in a loop is
    /// the intended pattern. Shutdown/unplugging races also emit falls
    /// out of the ordinary path: a rescan that now fails reports its
    /// error ([`CoreError::Io`]) instead of inventing empty data.
    pub fn wait(&mut self, timeout: Duration) -> Result<Option<Vec<Device>>> {
        let deadline = match Instant::now().checked_add(timeout) {
            Some(deadline) => deadline,
            // An unrepresentable timeout is treated as "now": silently
            // degrading to an immediate rescan keeps the API total.
            None => return self.rescan(),
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match self.watch.as_ref() {
                Some(fd) => {
                    if self.wakeup(fd, remaining)? {
                        self.drain(fd)?;
                        // Debounce: wait longest for the burst to settle,
                        // then scan exactly once.
                        let window = remaining.min(DEBOUNCE);
                        if self.wakeup(fd, window)? {
                            self.drain(fd)?;
                        }
                    }
                    // A timed-out poll falls through as well: the sync
                    // below keeps the watch set honest, the rescan
                    // returns `None` for an unchanged tree and the
                    // deadline check handles the report.
                }
                None => {
                    // Fallback cadence: sleep in max-fallback-size
                    // slices, never past the deadline.
                    let slice = FALLBACK_CADENCE
                        .saturating_sub(self.last_poll.elapsed())
                        .min(remaining);
                    // Not a thread — the caller's thread blocks here.
                    std::thread::sleep(slice);
                    self.last_poll = Instant::now();
                }
            }
            // The fd borrow above ends here; the facts can change now.
            // Sync the device watches before the comparison: a per-device
            // attach failure downgrades the inotify path entirely (see
            // `sync_watch_set`) rather than missing hotplug silently.
            self.sync_watch_set();
            if let Some(fresh) = self.rescan()? {
                return Ok(Some(fresh));
            }
        }
    }

    /// Open an inotify watch on `<root>/class/block` plus its current
    /// device directories.
    ///
    /// Every attach here is fatal: a partial initial set is
    /// untrustworthy, so `new` degrades the whole watcher to the poll
    /// fallback instead.
    fn open_watch(sysfs: &SysfsRoot) -> Result<OwnedFd> {
        let class_block = sysfs.class_block();
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
            .map_err(|errno| errno_to_core(&class_block, errno))?;
        inotify::add_watch(&fd, &class_block, watch_flags())
            .map_err(|errno| errno_to_core(&class_block, errno))?;
        // Seed the device directories discovered so far; the set is
        // re-attached before every rescan (inotify is not recursive).
        child_watches(&fd, &class_block).map_err(|errno| errno_to_core(&class_block, errno))?;
        Ok(fd)
    }

    /// Keep the device watch set in step with the current `class/block`
    /// children (no-op on the poll-fallback path).
    ///
    /// A per-device attach failure is never swallowed: ENOSPC (watch
    /// budget) and other real errors would leave the inotify set blind
    /// to later hotplug, so the watcher drops the whole inotify path and
    /// the 2 s poll takes over — observable via `uses_poll_fallback`.
    /// Transient child races (ENOENT/ENOTDIR) are handled inside
    /// [`attach_child_watch`] as plain skips, so they never reach this
    /// downgrade path.
    fn sync_watch_set(&mut self) {
        let Some(fd) = self.watch.as_ref() else {
            return;
        };
        let class_block = self.sysfs.class_block();
        if child_watches(fd, &class_block).is_err() {
            self.watch = None;
            // Poll from now on, consistent with the cadence contract: a
            // tree that races the attach is rescan'd on the next slice.
            self.last_poll = Instant::now();
        }
    }

    /// Block up to `at_most` waiting for the watch to become readable.
    /// `true` when the kernel reported readiness (events pending).
    ///
    /// The `poll` timeout is recomputed inside the retry loop, so an
    /// `EINTR` (or a stream of them) can only ever consume the caller's
    /// budget, never *add* to it — the deadline genuinely holds. The
    /// retry path itself is left untested on purpose: driving it needs a
    /// signal handler, and installing one requires `unsafe`, which the
    /// workspace forbids everywhere.
    fn wakeup(&self, fd: &OwnedFd, at_most: Duration) -> Result<bool> {
        // An unrepresentable budget behaves like "no wait possible",
        // matching a poll timeout's immediate answer.
        let deadline = match Instant::now().checked_add(at_most) {
            Some(deadline) => deadline,
            None => return Ok(false),
        };
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            match poll(&mut fds, Some(&timespec(remaining))) {
                Ok(ready) => return Ok(ready > 0),
                // Interrupted before the kernel reported anything: retry
                // with the rest of the budget, never a fresh slice.
                Err(Errno::INTR) => continue,
                Err(errno) => return Err(errno_to_core(&self.sysfs.class_block(), errno)),
            }
        }
    }

    /// Consume every queued inotify event; their *contents* are not
    /// inspected because rescan reads the full tree — any waking event
    /// in the watch set justifies one scan.
    fn drain(&self, fd: &OwnedFd) -> Result<()> {
        let mut buffer = [MaybeUninit::<u8>::uninit(); EVENT_BUFFER];
        let mut reader = inotify::Reader::new(fd, &mut buffer);
        loop {
            match reader.next() {
                // The queue is empty again; on Linux AGAIN and
                // WOULDBLOCK are the same number, and rustix raises it
                // for a drained NONBLOCK read.
                Err(Errno::WOULDBLOCK) => break,
                // A signal interrupted the read: the queue is still
                // there, so retry instead of failing the watch.
                Err(Errno::INTR) => continue,
                Err(errno) => {
                    return Err(errno_to_core(&self.sysfs.class_block(), errno));
                }
                Ok(_event) => {}
            }
        }
        Ok(())
    }

    /// Re-enumerate through the filter and report only real change.
    fn rescan(&mut self) -> Result<Option<Vec<Device>>> {
        let fresh = sysfs::filter(sysfs::enumerate(&self.sysfs)?, self.filter);
        let key = snapshot_key(&fresh);
        if key == self.key {
            // Keep the published snapshot untouched: attribute churn
            // must not visibly rewrite identity facts either.
            Ok(None)
        } else {
            self.snapshot = fresh.clone();
            self.key = key;
            Ok(Some(fresh))
        }
    }
}

/// Parse at most `i64` seconds of a duration into a poll timeout.
///
/// A caller passing `u64::MAX` seconds simply waits until the kernel's
/// limit — the deadline math in [`DeviceWatcher::wait`] still bounds the
/// total wait.
fn timespec(duration: Duration) -> Timespec {
    Timespec {
        tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(duration.subsec_nanos()),
    }
}

/// Error conversion for the watcher's fd operations; the class
/// directory is the most useful `path` context a log line can carry.
fn errno_to_core(path: &std::path::Path, errno: Errno) -> CoreError {
    CoreError::io(path, io::Error::from_raw_os_error(errno.raw_os_error()))
}

/// The event mask for the class directory and its device children:
/// creation/renaming/removal, attribute rewrites and in-place writes to
/// attribute files (the kernel rewrites them with truncate+write).
/// Onlydir simples a mis-pointed root away from watching stray files;
/// the stable change key filters the noise out on the reporting side.
fn watch_flags() -> inotify::WatchFlags {
    inotify::WatchFlags::CREATE
        | inotify::WatchFlags::DELETE
        | inotify::WatchFlags::MOVED_TO
        | inotify::WatchFlags::MOVED_FROM
        | inotify::WatchFlags::ATTRIB
        | inotify::WatchFlags::MODIFY
        | inotify::WatchFlags::DELETE_SELF
        | inotify::WatchFlags::ONLYDIR
}

/// (Re-)attach watches to every device directory currently under
/// `class_block`, stopping at the first failure.
///
/// inotify has no recursion, so partition create/delete inside a device
/// directory needs a watch on that directory itself. The call is
/// repeated before every rescan: re-adding a watched path just updates
/// the existing watch descriptor. Every returned errno is deliberate —
/// the callers degrade to the poll fallback rather than trusting a
/// partial watch set (see [`DeviceWatcher::sync_watch_set`]).
fn child_watches(fd: &OwnedFd, class_block: &Path) -> std::result::Result<(), Errno> {
    let Ok(entries) = fs::read_dir(class_block) else {
        // The tree vanished under us (or the inode changed); the class
        // watch's own delete-self event covers it on real systems, and
        // the rescan reports the missing directory as an error anyway.
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        // Follow the class-entry symlinks a live sysfs presents.
        match fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            _ => continue,
        }
        attach_child_watch(fd, &path)?;
    }
    Ok(())
}

/// Attach the device-directory watch for one child.
///
/// A child that vanished between the listing and this call (ENOENT) or
/// that stopped being a directory (ENOTDIR) is *skipped*, not fatal: the
/// class-directory watch still reports future arrivals, so the next sync
/// simply re-lists it. Real breakage — ENOSPC (the user's inotify watch
/// budget) and any other errno — is returned and downgrades the whole
/// watcher (see [`DeviceWatcher::sync_watch_set`]).
fn attach_child_watch(fd: &OwnedFd, path: &Path) -> std::result::Result<(), Errno> {
    match inotify::add_watch(fd, path, watch_flags()) {
        Ok(_) => Ok(()),
        Err(Errno::NOENT) | Err(Errno::NOTDIR) => {
            // Transient: the child is no longer there. Skip it and let
            // the class-dir watch re-report it if it returns.
            Ok(())
        }
        Err(errno) => Err(errno),
    }
}

/// Cheap change key over one device: the facts that matter to a device
/// picker (see the module header). Ordered and terminated, not hashed —
/// debug prints of the key stay readable in a log.
fn device_key(device: &Device) -> String {
    let mut key = format!(
        "{}|{}|{}|{}",
        device.name, device.size_bytes, device.removable, device.read_only,
    );
    for part in &device.partitions {
        key.push('|');
        key.push_str(&part.name);
        key.push(':');
        key.push_str(&part.size_bytes.to_string());
    }
    key
}

/// Stable key of one full snapshot.
fn snapshot_key(devices: &[Device]) -> String {
    // Devices arrive name-sorted from enumeration; keep that order.
    devices
        .iter()
        .map(device_key)
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::time::Instant;

    use super::DeviceWatcher;
    use super::Filter;
    use super::SysfsRoot;

    /// A scratch sysfs tree with plain class directories (no device
    /// links): watchers key on facts, not transport classification.
    struct Fixture {
        _scratch: tempfile::TempDir,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            Fixture {
                _scratch: scratch,
                root,
            }
        }

        /// Seed a minimal device `name`.
        fn stick(&self, name: &str, units: &str, removable: &str) {
            let dir = format!("class/block/{name}");
            fs::create_dir_all(self.root.join(&dir)).expect("class/block/<name>");
            fs::write(self.root.join(&dir).join("size"), units).expect("seed size");
            fs::write(self.root.join(&dir).join("removable"), removable).expect("seed ro");
            fs::write(self.root.join(&dir).join("dev"), "9:1").expect("seed dev");
        }

        /// Add a partition directory `part` under the existing disk
        /// `name` (a hotplug-style CREATE inside the watch set).
        fn stick_partition(&self, name: &str, part: &str, units: &str, dev: &str) {
            let dir = format!("class/block/{name}/{part}");
            fs::create_dir_all(self.root.join(&dir)).expect("class/block partition");
            fs::write(self.root.join(&dir).join("size"), units).expect("seed partition size");
            fs::write(self.root.join(&dir).join("dev"), dev).expect("seed partition dev");
        }

        fn watcher(&self, show_all: bool) -> DeviceWatcher {
            DeviceWatcher::new(SysfsRoot::new(&self.root), Filter { show_all })
                .expect("watcher over a fixture root")
        }

        /// Names of the watcher's current snapshot.
        fn names(watcher: &DeviceWatcher) -> Vec<String> {
            watcher.snapshot().iter().map(|d| d.name.clone()).collect()
        }
    }

    #[test]
    fn inotify_is_available_in_this_environment() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        let watcher = fixture.watcher(false);
        // On a normal Linux box inotify works; the test *pins* that
        // assumption so the timing contract earlier in this module is
        // honest (the fallback path would be cornered instead).
        assert!(
            !watcher.uses_poll_fallback(),
            "this environment must offer inotify (or the timing tests are void)"
        );
    }

    #[test]
    fn poll_fallback_reports_hotplug_add_and_remove() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        let mut watcher = DeviceWatcher::new_with_poll_fallback(
            SysfsRoot::new(&fixture.root),
            Filter { show_all: false },
        )
        .expect("poll-fallback watcher over a fixture root");
        assert!(watcher.uses_poll_fallback(), "the seam forces watch: None");
        assert_eq!(Fixture::names(&watcher), vec!["sdb".to_string()]);

        // Plug in a stick: the 2 s poll reports it (loosely — CI load
        // must not flake the suite, so the budget is generous).
        fixture.stick("sdz", "4096", "1");
        let started = Instant::now();
        let change = watcher
            .wait(Duration::from_secs(5))
            .expect("wait succeeds")
            .expect("the add is reported by the fallback");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "fallback add seen too slowly: {:?}",
            started.elapsed()
        );
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb", "sdz"],
        );

        // Unplug it again: the next poll reports the removal too.
        fs::remove_dir_all(fixture.root.join("class/block/sdz")).expect("remove sdz");
        let started = Instant::now();
        let change = watcher
            .wait(Duration::from_secs(5))
            .expect("wait succeeds")
            .expect("the removal is reported by the fallback");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "fallback removal seen too slowly: {:?}",
            started.elapsed()
        );
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb"],
        );
        assert!(
            watcher.uses_poll_fallback(),
            "still on the fallback after hotplug"
        );
    }

    #[test]
    fn per_device_watch_failure_degrades_to_the_poll_fallback() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        let mut watcher = fixture.watcher(false);
        assert!(
            !watcher.uses_poll_fallback(),
            "starts healthy on the inotify path"
        );

        // Swap the live inotify fd for a connected socket: every child
        // `inotify_add_watch` fails (EINVAL — the fd is not an inotify
        // object), which stands in for a watch-budget failure (ENOSPC)
        // without needing sysctl access. The socket is never written, so
        // the final watchdog blocks until it expires instead of waking.
        let (alibi, _peer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        watcher.watch = Some(alibi.into());

        // A hotplug *and* the failure must surface together: the sync in
        // `wait` refuses to keep a broken inotify set, degrades to the
        // poll fallback, and the watcher keeps reporting. No `last_poll`
        // ageing here — the first poll on the silent socket simply times
        // out, sync then downgrades, and the same iteration's rescan
        // still sees the change.
        fixture.stick("sdz", "4096", "1");
        let change = watcher
            .wait(Duration::from_millis(900))
            .expect("wait succeeds")
            .expect("the degraded watcher still reports the hotplug");
        assert!(
            watcher.uses_poll_fallback(),
            "the per-device watch failure must be observable"
        );
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb", "sdz"],
            "the rescan after the inotify poll timed out and sync had \
             degraded the watcher reports the change",
        );
    }

    #[test]
    fn vanished_child_watches_are_skipped_and_never_downgrade() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        let mut watcher = fixture.watcher(false);
        assert!(
            !watcher.uses_poll_fallback(),
            "healthy on the inotify path while the child exists"
        );

        // A child vanishing after the watch attached must not look like
        // breakage: re-syncing leaves the watcher on the inotify path.
        std::fs::remove_dir_all(fixture.root.join("class/block/sdb")).expect("vanish child");
        watcher.sync_watch_set();
        assert!(
            !watcher.uses_poll_fallback(),
            "a vanished child must not permanently downgrade the watcher"
        );

        // The skip is a real kernel ENOENT (nothing ever existed at the
        // path), and ENOTDIR through a plain file behaves the same.
        std::fs::write(fixture.root.join("class/block/why.txt"), "plain file")
            .expect("seed plain file");
        let fd =
            DeviceWatcher::open_watch(&SysfsRoot::new(&fixture.root)).expect("healthy inotify");
        assert!(
            super::attach_child_watch(&fd, &fixture.root.join("class/block/gone-disk")).is_ok(),
            "ENOENT on a vanished path must be a skip, not a downgrade"
        );
        assert!(
            super::attach_child_watch(&fd, &fixture.root.join("class/block/why.txt/sub")).is_ok(),
            "ENOTDIR through a file must be a skip, not a downgrade"
        );
    }

    #[test]
    fn hotplug_add_and_remove_are_seen_within_300_ms() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        let mut watcher = fixture.watcher(false);
        assert_eq!(Fixture::names(&watcher), vec!["sdb".to_string()]);

        // A quiet stretch reports no change and honestly waited.
        let started = Instant::now();
        assert_eq!(
            watcher
                .wait(Duration::from_millis(150))
                .expect("quiet wait"),
            None,
        );
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "wait must actually wait (took {:?})",
            started.elapsed()
        );

        // Plug in a stick: reported within the 200 ms debounce + ε,
        // never later than the 300 ms hotplug budget (PLAN §9-S04).
        fixture.stick("sdz", "4096", "1");
        let started = Instant::now();
        let change = watcher
            .wait(Duration::from_secs(2))
            .expect("wait succeeds")
            .expect("the add is a change");
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "hotplug seen too slowly: {:?}",
            started.elapsed()
        );
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb", "sdz"],
        );

        // Unplug it again.
        fs::remove_dir_all(fixture.root.join("class/block/sdz")).expect("remove sdz");
        let started = Instant::now();
        let change = watcher
            .wait(Duration::from_secs(2))
            .expect("wait succeeds")
            .expect("the removal is a change");
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "unplug seen too slowly: {:?}",
            started.elapsed()
        );
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb"],
        );
    }

    #[test]
    fn attribute_noise_and_show_all_do_not_emit_twice() {
        let fixture = Fixture::new();
        fixture.stick("sdb", "1234", "1");
        // An internal disk that the default filter must hide.
        fixture.stick("sdt", "8192", "0");

        let mut watcher = fixture.watcher(false);
        assert_eq!(Fixture::names(&watcher), vec!["sdb".to_string()]);

        // Rewriting an attribute *in place* raises MODIFY/ATTRIB, which
        // are in the watch set, so an event arrives and triggers a
        // rescan — but the stable change key is unchanged with the same
        // bytes, so the rescan reports nothing.
        fs::write(fixture.root.join("class/block/sdb/removable"), "1").expect("rewrite same value");
        assert_eq!(
            watcher.wait(Duration::from_millis(250)).expect("wait"),
            None,
            "attribute churn must not be reported"
        );

        // The show-all watcher is a *separate* wrapper over the same
        // tree: its snapshot alone already carries the fixed disk.
        let all_view = fixture.watcher(true);
        assert_eq!(
            Fixture::names(&all_view),
            vec!["sdb".to_string(), "sdt".to_string()],
            "show-all reveals internal disks in the baseline snapshot"
        );

        // A partition appearing in the watch set (CREATE) *and* in the
        // stable key is one report, with the fresh numbers.
        fixture.stick_partition("sdb", "sdb2", "50", "9:2");
        let change = watcher
            .wait(Duration::from_secs(1))
            .expect("wait succeeds")
            .expect("the partition add is a change");
        assert_eq!(
            change.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["sdb"],
        );
        let partitions: Vec<&str> = change[0]
            .partitions
            .iter()
            .map(|part| part.name.as_str())
            .collect();
        assert_eq!(partitions, vec!["sdb2"], "the new partition was picked up");
        let added = change[0].partitions.iter().find(|p| p.name == "sdb2");
        assert_eq!(
            added.map(|p| (p.number, p.size_bytes)),
            Some((Some(2), 50 * 512)),
            "the new partition carried its number and size"
        );
    }
}
