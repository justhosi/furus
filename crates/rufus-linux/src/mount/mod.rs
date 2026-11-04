//! Mount/unmount behind an injectable seam (S06 part 4, now owned by
//! `rufus-linux` for the copy wiring).
//!
//! The CLI process owns whatever it mounts: mounting a filesystem for
//! the device-writing pipeline must never leave a live mount on the
//! host when the run ends — planned or crashed. The split this module
//! makes is the one the rest of S06 uses: the *policy* (record what
//! succeeded, sweep it back in reverse, detach stubborn targets) is
//! testable stand-alone behind [`MountOps`], and the *syscall* side
//! ([`LiveOps`]) is a thin, flag-pinned shell over rustix's `mount(2)`
//! and `umount2(2)`.
//!
//! [`Recorder`] is the policy: it wraps any `&mut dyn MountOps`, keeps
//! every *successful* mount on its books, offers
//! [`Recorder::unmount_all`] with the documented `MNT_DETACH` fallback,
//! and implements [`Drop`] to sweep everything still mounted — reverse
//! order, every failure ignored, bookkeeping cleared, never panicking.
//!
//! [`partition`] is the single-mount guard the copy step uses: it mounts
//! one data partition through this seam, answers `free_bytes` with
//! `statvfs`, and unmounts (explicitly through
//! [`Recorder::unmount_all`], best-effort on drop) before removing its
//! mount point.
//!
//! # The `MNT_DETACH` fallback
//!
//! `umount(2)` fails with `EBUSY` (`ResourceBusy`) while something
//! still pins the mount — a cwd on it, an open file, another mount
//! inside. The helper does not retry in a loop or wait it out; it falls
//! back to *lazily detaching* the mount (`MNT_DETACH`): the kernel
//! unmounts it the moment nothing pins it any more, and — essential for
//! this helper — the mount leaves the namespace table at once. Any
//! other failure is surfaced (through [`Recorder::unmount_all`]) or
//! ignored ([`Drop`]), never hidden by pretending the cleanup
//! succeeded twice.
//!
//! # Bind mounts are a reserved slot
//!
//! The seam's `fstype` is `Option<&str>` because `mount(2)`'s filesystem
//! argument is empty for bind (`MS_BIND`) mounts — but rustix's `mount`
//! wrapper always passes a type pointer, and a live bind mount could
//! not carry the `NOSUID | NODEV` posture without a second remount
//! call. Rather than approximate, [`LiveOps`] *refuses* `None`
//! fail-closed; S07/S17 mount named filesystems, so the slot is a
//! declared hole, not a latent bug.
//
// The seam is wired by the copy path through [`partition`]: [`LiveOps`]
// and [`MountOps`] mount every data partition, and [`Recorder`] backs
// the guard's explicit release (plus its best-effort drop), so nothing
// below is dead: the former module-level `allow(dead_code)` (needed
// while the seam sat in the helper binary with only tests naming it)
// is gone, and clippy stays quiet without it.
pub mod partition;

use std::ffi::CStr;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use rustix::mount::MountFlags;
use rustix::mount::UnmountFlags;

/// The seam: real or recorded mount operations (`&mut` throughout, like
/// `StepCtx`'s sink: mount state lives through the borrow).
pub trait MountOps {
    /// Mount `source` on `target`, using `fstype` (`None` is the
    /// bind-mount slot; see the module docs).
    fn mount(&mut self, source: &Path, target: &Path, fstype: Option<&str>) -> io::Result<()>;

    /// Unmount `target`; `detach` requests the `MNT_DETACH` fallback.
    fn unmount(&mut self, target: &Path, detach: bool) -> io::Result<()>;
}

/// The real backend: `mount(2)` (always `NOSUID | NODEV` — a mounted
/// device tree must never honour suid bits nor expose its device
/// special files inside this helper's world) and `umount2(2)` with or
/// without `MNT_DETACH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveOps;

impl MountOps for LiveOps {
    fn mount(&mut self, source: &Path, target: &Path, fstype: Option<&str>) -> io::Result<()> {
        let Some(fstype) = fstype else {
            // Fail closed on the bind slot (module docs): rustix's
            // `mount` wrapper always passes a type pointer, so there is
            // no honest `None` call to make, and this refusal keeps the
            // hole explicit instead of shipping an empty fstype that
            // only fails obscurely inside the kernel.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the live mount backend needs a filesystem type (None is the bind-mount slot)",
            ));
        };
        // `None::<&CStr>`: no `mount(2)` data argument, like the
        // default typed `mount` invocation; rustix's `Errno` maps into
        // `io::Error` via the std backend the workspace uses.
        rustix::mount::mount(
            source,
            target,
            fstype,
            MountFlags::NOSUID | MountFlags::NODEV,
            None::<&CStr>,
        )
        .map_err(io::Error::from)
    }

    fn unmount(&mut self, target: &Path, detach: bool) -> io::Result<()> {
        rustix::mount::unmount(
            target,
            if detach {
                UnmountFlags::DETACH
            } else {
                UnmountFlags::empty()
            },
        )
        .map_err(io::Error::from)
    }
}

/// One successful mount, kept until it is unmounted (or the [`Drop`]
/// sweep gives up on it). The fields are the seam arguments as called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRecord {
    /// What was mounted (the seam's `source` argument).
    pub source: PathBuf,
    /// Where it is/was mounted (the seam's `target` argument).
    pub target: PathBuf,
    /// The filesystem type mounted, `None` for the bind-mount slot.
    pub fstype: Option<String>,
}

/// The mount bookkeeping: record what succeeded, sweep it back in
/// reverse order, never lose a mount knowingly.
///
/// The [`Drop`] runs the same sweep with all errors ignored — a
/// destructor must neither panic nor promote a stubborn mount into an
/// error the caller never asked for. After it, the books are empty.
pub struct Recorder<'a> {
    ops: &'a mut dyn MountOps,
    // Visible inside the crate so the single-mount [`partition`] guard
    // can move its one record out of a transient recorder (after the
    // single mount call) and back into one for the explicit release:
    // that reuses [`Recorder::unmount_all`] with its detach fallback
    // instead of duplicating the policy, without storing a borrow of
    // the guard's own backend.
    pub(crate) mounted: Vec<MountRecord>,
}

impl<'a> Recorder<'a> {
    /// Wrap `ops`; a fresh recorder has nothing on its books.
    #[must_use]
    pub fn new(ops: &'a mut dyn MountOps) -> Self {
        Self {
            ops,
            mounted: Vec::new(),
        }
    }

    /// Mount through the seam and record the success only: a failed
    /// mount leaves the books untouched.
    pub fn mount(&mut self, source: &Path, target: &Path, fstype: Option<&str>) -> io::Result<()> {
        self.ops.mount(source, target, fstype)?;
        self.mounted.push(MountRecord {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            fstype: fstype.map(str::to_string),
        });
        Ok(())
    }

    /// Everything still recorded as mounted, in mount order (the most
    /// recent mount is the last entry).
    #[must_use]
    pub fn mounted(&self) -> &[MountRecord] {
        &self.mounted
    }

    /// Unmount everything on the books, most recent first, with the
    /// `MNT_DETACH` fallback for busy (`ResourceBusy`) targets.
    ///
    /// The sweep is strictly reverse-ordered: a target that could not
    /// be unmounted (any failure, after its fallback was tried) stops
    /// the sweep — its entry, and every not-yet-reached one, stays on
    /// the books for a later attempt ([`Drop`]'s or the caller's).
    /// Successfully unmounted targets leave the books as they go.
    pub fn unmount_all(&mut self) -> io::Result<()> {
        let mut pending = std::mem::take(&mut self.mounted);
        while let Some(entry) = pending.pop() {
            match unmount_with_fallback(self.ops, &entry.target) {
                Ok(()) => {} // popped and unmounted: off the books
                Err(err) => {
                    // Still mounted: the entry goes back (with
                    // everything not reached yet) for a later attempt.
                    pending.push(entry);
                    self.mounted = pending;
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

impl Drop for Recorder<'_> {
    /// The best-effort sweep ([`unmount_with_fallback`]): reverse
    /// order, every failure ignored, and the books cleared regardless —
    /// the sweep continues past a failed target (unlike
    /// [`Recorder::unmount_all`]) so exactly one final attempt happens
    /// per still-mounted mount. Never panics, never loops.
    fn drop(&mut self) {
        // Best effort per entry: one attempt each, most recent first,
        // continuing past a failure so no mount is skipped merely
        // because an older one resisted.
        let mut pending = std::mem::take(&mut self.mounted);
        while let Some(entry) = pending.pop() {
            let _ = unmount_with_fallback(self.ops, &entry.target);
        }
        // Whatever resisted did get its one attempt; the books must not
        // outlive the sweep.
        self.mounted.clear();
    }
}

/// One unmount through the seam with the documented `MNT_DETACH`
/// fallback: `ResourceBusy` is retried detached once; any other
/// failure (or a failed retry) is returned unchanged.
fn unmount_with_fallback(ops: &mut dyn MountOps, target: &Path) -> io::Result<()> {
    match ops.unmount(target, false) {
        Err(err) if err.kind() == io::ErrorKind::ResourceBusy => ops.unmount(target, true),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::path::PathBuf;

    use super::LiveOps;
    use super::MountOps;
    use super::Recorder;

    /// The seam arguments, as recorded for the assertions: fake paths
    /// only (nothing here touches a real mountpoint).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Mount {
            source: String,
            target: String,
            fstype: Option<String>,
        },
        Unmount {
            target: String,
            detach: bool,
        },
    }

    /// A recording [`MountOps`]: succeeds by default, with per-target
    /// knobs for both branches of the fallback.
    struct FakeOps {
        calls: Vec<Call>,
        /// Normal unmounts of these targets fail with `ResourceBusy`
        /// (the branch that triggers the detach fallback).
        busy: Vec<String>,
        /// *All* unmounts of these targets fail hard (`InvalidInput`),
        /// ahead of the busy rule.
        locked: Vec<String>,
        /// Make the detach attempt of a busy target fail too.
        detach_fails: bool,
    }

    impl FakeOps {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                busy: Vec::new(),
                locked: Vec::new(),
                detach_fails: false,
            }
        }

        /// The unmount calls only, as `(target, detach)` pairs.
        fn unmounts(&self) -> Vec<(String, bool)> {
            let mut found = Vec::new();
            for call in &self.calls {
                if let Call::Unmount { target, detach } = call {
                    found.push((target.clone(), *detach));
                }
            }
            found
        }
    }

    impl MountOps for FakeOps {
        fn mount(&mut self, source: &Path, target: &Path, fstype: Option<&str>) -> io::Result<()> {
            self.calls.push(Call::Mount {
                source: source.display().to_string(),
                target: target.display().to_string(),
                fstype: fstype.map(str::to_string),
            });
            Ok(())
        }

        fn unmount(&mut self, target: &Path, detach: bool) -> io::Result<()> {
            let name = target.display().to_string();
            self.calls.push(Call::Unmount {
                target: name.clone(),
                detach,
            });
            if self.locked.contains(&name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fake hard failure",
                ));
            }
            let busy_target = self.busy.contains(&name);
            if busy_target && (!detach || self.detach_fails) {
                return Err(io::Error::from(io::ErrorKind::ResourceBusy));
            }
            Ok(())
        }
    }

    /// Inert fixture paths (the fakes never touch the filesystem).
    fn target_path(n: u32) -> PathBuf {
        Path::new("/mnt").join(format!("rufus-mount-test-{n}"))
    }

    fn target_str(n: u32) -> String {
        target_path(n).display().to_string()
    }

    fn source_str(n: u32) -> String {
        format!("/dev/rufus-mount-test-dev-{n}")
    }

    /// Mount fake target `n` (source `source_str(n)`, type vfat) and
    /// return its target path.
    fn mount_target(recorder: &mut Recorder<'_>, n: u32) -> PathBuf {
        let target = target_path(n);
        let source = source_str(n);
        let source = Path::new(&source);
        recorder
            .mount(source, &target, Some("vfat"))
            .expect("the fake backend mounts cleanly");
        target
    }

    // -- recording ---------------------------------------------------------

    #[test]
    fn mount_records_every_successful_mount_exactly() {
        let mut fake = FakeOps::new();
        {
            let mut recorder = Recorder::new(&mut fake);
            let first = mount_target(&mut recorder, 1);
            let second = mount_target(&mut recorder, 2);

            assert_eq!(
                recorder
                    .mounted()
                    .iter()
                    .map(|r| r.target.clone())
                    .collect::<Vec<PathBuf>>(),
                vec![first.clone(), second.clone()],
                "the books hold the mounts in call order"
            );
            // (the block owns the recorder, i.e. also its destructor's
            // sweep — asserted clean in the reverse-order test below)
        }
        // The destructor ran with the block, appending its own sweep;
        // the first two calls are the mounts the seam saw.
        assert_eq!(
            &fake.calls[..2],
            &[
                Call::Mount {
                    source: source_str(1),
                    target: target_str(1),
                    fstype: Some("vfat".to_string()),
                },
                Call::Mount {
                    source: source_str(2),
                    target: target_str(2),
                    fstype: Some("vfat".to_string()),
                },
            ][..],
            "the seam received exactly what the recorder passed through"
        );
    }

    // -- the reverse-order sweep with the MNT_DETACH fallback ---------------

    #[test]
    fn unmount_all_sweeps_in_reverse_order_with_the_detach_fallback() {
        let mut fake = FakeOps::new();
        fake.busy = vec![target_str(2)];

        let mut recorder = Recorder::new(&mut fake);
        mount_target(&mut recorder, 1);
        mount_target(&mut recorder, 2);
        mount_target(&mut recorder, 3);

        recorder
            .unmount_all()
            .expect("every target yields: normal or, once busy, detached");
        assert!(
            recorder.mounted().is_empty(),
            "cleaned targets leave the books"
        );
        drop(recorder);
        assert_eq!(
            fake.unmounts(),
            vec![
                (target_str(3), false),
                (target_str(2), false),
                (target_str(2), true),
                (target_str(1), false),
            ],
            "most recent first, and the busy middle got its detach retry"
        );
        // Three mounts + four unmounts above; the destructor after a
        // clean sweep adds nothing (its books are already empty).
        assert_eq!(fake.calls.len(), 7, "{:?}", fake.calls);
    }

    #[test]
    fn unmount_all_surfaces_hard_failures_and_keeps_the_uncleaned_books() {
        let mut fake = FakeOps::new();
        fake.locked = vec![target_str(2)];

        let mut recorder = Recorder::new(&mut fake);
        let first = mount_target(&mut recorder, 1);
        let second = mount_target(&mut recorder, 2);

        let err = recorder
            .unmount_all()
            .expect_err("the fake hard-fails the second target");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");

        // The books still hold what is mounted (the failed entry and
        // everything not reached), so a later attempt sees the truth.
        assert_eq!(
            recorder
                .mounted()
                .iter()
                .map(|r| r.target.clone())
                .collect::<Vec<PathBuf>>(),
            vec![first, second],
        );

        drop(recorder);
        assert_eq!(
            fake.unmounts().first(),
            Some(&(target_str(2), false)),
            "a non-busy failure stops the sweep before any detach attempt and before the older entry"
        );
    }

    // -- the destructor's best-effort sweep ----------------------------------

    #[test]
    fn failed_cleanup_in_drop_sweeps_every_entry_without_panicking() {
        let mut fake = FakeOps::new();
        fake.busy = vec![target_str(1), target_str(2)];
        fake.detach_fails = true;

        let mut recorder = Recorder::new(&mut fake);
        mount_target(&mut recorder, 1);
        mount_target(&mut recorder, 2);

        drop(recorder); // the destructor performs the best-effort sweep

        // No panic above (the test simply completed), and every entry
        // got its reverse-ordered attempt — normal first, then the
        // detach fallback, then the older entry: the destructor does
        // not give up at the first failure. Its books are cleared with
        // the run (`unmount_all`'s interrupted tail cannot outlive it;
        // nothing this type could expose after its own Drop reads the
        // books, which is why the sweep *sequence* is the evidence).
        assert_eq!(
            fake.unmounts(),
            vec![
                (target_str(2), false),
                (target_str(2), true),
                (target_str(1), false),
                (target_str(1), true),
            ],
            "the destructor swept everything, most recent first, fallback per entry"
        );
    }

    #[test]
    fn empty_books_sweep_to_a_noop() {
        let mut fake = FakeOps::new();
        let mut recorder = Recorder::new(&mut fake);

        recorder
            .unmount_all()
            .expect("nothing to sweep is plainly ok");
        assert!(recorder.mounted().is_empty());

        drop(recorder);
        assert!(
            fake.calls.is_empty(),
            "no seam call happened at all: {:?}",
            fake.calls
        );
    }

    // -- the live backend's fail-closed bind slot ------------------------------

    #[test]
    fn live_ops_refuses_the_bind_slot_fail_closed() {
        let mut live = LiveOps;
        // Inert paths: the refusal happens before any syscall, so this
        // runs unprivileged and touches nothing.
        let refused = MountOps::mount(
            &mut live,
            Path::new("/dev/rufus-mount-test-source"),
            Path::new("/mnt/rufus-mount-test-nowhere"),
            None,
        )
        .expect_err("the bind slot is refused, not approximated");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        assert!(
            refused.to_string().contains("filesystem type"),
            "the message names the missing half: {refused}"
        );
    }
}
