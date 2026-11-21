//! The safety verdict, spoken once and enforced everywhere (PLAN §6).
//!
//! The single most dangerous operation in the tool is opening the wrong
//! block device, so the refusal logic lives exactly once — here — and
//! both enforcement points (the GUI/CLI preview and the privileged
//! helper) must call [`judge`] with the same [`Target`] the inspection
//! half assembled. [`judge`] is *impure only in the input*: no reads, no
//! syscalls, so every refusal path is a table-driven unit test instead
//! of a hardware-explaining anecdote.
//!
//! # The fail-closed order
//!
//! [`Reason`]s are tried in a fixed precedence; the first match wins and
//! everything else is irrelevant for that verdict. The order encodes
//! "facts about the device first, user opinion last", and it is pinned
//! by the pairwise tests at the bottom:
//!
//! 1. `unreadable` — if the device cannot be read, no other fact was
//!    honestly gathered, so nothing may override this refusal;
//! 2. `zero_size` — a card reader with no card; carrying on would
//!    compute garbage offsets;
//! 3. `loopback` — kernel-managed names (loop, ram, zram, dm, md, sr)
//!    are not real writable media; the same rule S04's discovery filter
//!    uses, imported from one shared `const fn` so both cannot drift;
//! 4. `read_only`;
//! 5. `system_disk` — the device (or a partition of it) backs the
//!    running system; this must beat any mount-state judgement about
//!    *this* device;
//! 6. `mounted` — the device or a partition is mounted;
//! 7. `swap` — the device is an active swap source;
//! 8. `holder` — something (dm-crypt, LVM, mdraid, bcache) sits on top;
//! 9. `refused_filesystem` — the first refusable volume (whole disk
//!    before partitions, LVM2/btrfs/XFS/ZFS by [`FsKind::refusable`]);
//! 10. `too_small` — only when an image size is known and larger than
//!     the device (a missing or zero image size never refuses);
//! 11. `not_removable` — fixed disks stay hidden unless the user turned
//!     on the "show all devices" mode *and* re-typed the device's
//!     serial exactly;
//! 12. `Safe`.
//!
//! Things this module deliberately does **not** refuse: an unknown or
//! blank partition table (erasing a blank stick is the normal job), a
//! zero-size image, or a device because of its transport (bus names are
//! fragile discovery facts, not safety facts).

use std::fmt;

use serde::Serialize;

use crate::fsprobe::FsKind;
use crate::text::device_text;
use crate::units::human_bytes;

/// Which kernel-managed names are not real writable media. The same
/// prefixes S04's discovery filter drops — declared here because the
/// final verdict needs the identical rule, and two places with the same
/// list are one place with a future divergence bug.
///
/// The exact set, spelled once (see the module header for why it is
/// shared): loop, ram, zram, dm-, md, sr.
pub const fn is_builtin_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    is_prefix_of(bytes, b"loop")    // loopback mounts
        || is_prefix_of(bytes, b"ram") // in-kernel RAM disks
        || is_prefix_of(bytes, b"zram") // compressed RAM disks (often swap)
        || is_prefix_of(bytes, b"dm-") // device-mapper (LVM, dm-crypt)
        || is_prefix_of(bytes, b"md") // md RAID sets
        || is_prefix_of(bytes, b"sr") // optical drives
}

/// `const`-context prefix check: `str::starts_with` is not callable in
/// `const fn` on stable, so the bytes of `prefix` are walked by index
/// (guarded by the length test first, hence it cannot panic).
const fn is_prefix_of(name: &[u8], prefix: &[u8]) -> bool {
    if name.len() < prefix.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if name[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// One concrete refusal reason. Some variants carry the offending
/// string; `Display` renders an ASCII human sentence per variant (see
/// the impl below).
///
/// The enum is serialised for the `analyze --json` report; variant tags
/// are the lowercase snake_case of the constructors ("unreadable",
/// "not_removable", ...), equal to what [`Reason::code`] returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The device could not be opened/read at all; the detail says why.
    Unreadable {
        /// Opening/reading failure detail (already sanitised by the
        /// caller; Display re-sanitises defensively).
        detail: String,
    },
    /// The device reports zero capacity (card reader without a card).
    ZeroSize,
    /// Kernel-managed name — see [`is_builtin_name`].
    Loopback,
    /// The device is write-protected (sysfs `ro` or an SD lock switch).
    ReadOnly,
    /// The device (or a partition of it) backs the running system.
    SystemDisk,
    /// The device or one of its partitions is mounted.
    Mounted {
        /// The offending mountpoint.
        mountpoint: String,
    },
    /// The device is an active swap source.
    Swap {
        /// The swap-on path from `/proc/swaps`.
        source: String,
    },
    /// Something sits on top of the device (dm-crypt, LVM, mdraid...).
    Holder {
        /// The first holder's kernel name.
        holder: String,
    },
    /// The device holds a volume system the rewrite refuses to erase.
    RefusedFilesystem {
        /// What was recognised.
        fs: FsKind,
        /// The partition's kernel name, or `None` for the whole disk.
        partition: Option<String>,
    },
    /// The device is smaller than the image that is meant for it.
    TooSmall {
        /// Device capacity in bytes.
        device_bytes: u64,
        /// Image size in bytes.
        image_bytes: u64,
    },
    /// A fixed disk stays guarded unless show-all *and* the typed
    /// (non-empty) serial match the device's own.
    NotRemovable {
        /// The device's serial; `None` when the device states none.
        serial: Option<String>,
    },
}

impl Reason {
    /// Stable machine-readable slug per variant (`"unreadable"`,
    /// `"too_small"`, ...); the same strings the JSON serialisation
    /// uses as tags.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "unreadable",
            Self::ZeroSize => "zero_size",
            Self::Loopback => "loopback",
            Self::ReadOnly => "read_only",
            Self::SystemDisk => "system_disk",
            Self::Mounted { .. } => "mounted",
            Self::Swap { .. } => "swap",
            Self::Holder { .. } => "holder",
            Self::RefusedFilesystem { .. } => "refused_filesystem",
            Self::TooSmall { .. } => "too_small",
            Self::NotRemovable { .. } => "not_removable",
        }
    }
}

/// One ASCII human sentence per reason. Interpolated fragments are run
/// through [`device_text`] so a hostile mountpoint or serial can never
/// inject bytes into a status line — that keeps the whole sentence
/// ASCII by construction rather than by convention.
///
/// Cursor-less numbers use [`human_bytes`] so the sizes read like the
/// rest of the UI (`512.00 MiB`, `1.20 GiB`).
impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { detail } => {
                write!(f, "device is unreadable: {}", device_text(detail))
            }
            Self::ZeroSize => write!(f, "device has zero size"),
            Self::Loopback => write!(
                f,
                "device is not real media (loopback, ram, zram, dm, md or optical device)"
            ),
            Self::ReadOnly => write!(f, "device is read-only"),
            Self::SystemDisk => write!(f, "device backs the running system"),
            Self::Mounted { mountpoint } => write!(
                f,
                "device is mounted at {} - unmount it first",
                device_text(mountpoint)
            ),
            Self::Swap { source } => write!(
                f,
                "device is active swap on {} - disable swap first",
                device_text(source)
            ),
            Self::Holder { holder } => write!(f, "device is held by {}", device_text(holder)),
            Self::RefusedFilesystem { fs, partition } => match partition {
                Some(name) => write!(
                    f,
                    "device contains {} data at {} - erase it with a dedicated tool",
                    fs.as_str(),
                    device_text(name)
                ),
                None => write!(
                    f,
                    "device contains {} data - erase it with a dedicated tool",
                    fs.as_str()
                ),
            },
            Self::TooSmall {
                device_bytes,
                image_bytes,
            } => write!(
                f,
                "device is {} but the image needs {}",
                human_bytes(*device_bytes),
                human_bytes(*image_bytes)
            ),
            Self::NotRemovable { serial } => match serial {
                Some(serial) => write!(
                    f,
                    "device is not removable (serial {})",
                    device_text(serial)
                ),
                None => write!(f, "device is not removable"),
            },
        }
    }
}

/// The outcome of judging one target: either [`SafetyVerdict::Safe`] or
/// [`SafetyVerdict::Refuse`] with one [`Reason`].
///
/// There is no "warn": a refusal is always hard (PLAN §6 rule 2), and
/// soft facts about the *table* (CRC warnings, and so on) live on the
/// inspect side, not in this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyVerdict {
    /// The write may proceed; every downstream layer still re-checks.
    Safe,
    /// The operation must not proceed, with exactly one reason.
    Refuse(Reason),
}

impl SafetyVerdict {
    /// `true` only for [`SafetyVerdict::Safe`]. Named for reading
    /// pleasure at the call sites (`if !verdict.is_safe() { ... }`).
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe)
    }
}

/// Everything [`judge`] needs, assembled ready-made by the inspection
/// half (S05 part 2/3) from sysfs, mountinfo and the superblock probes.
///
/// This is a pure data bag on purpose: it can be constructed from
/// fixtures (tests, golden runs) without touching a device, and the
/// helper re-assembles it from its own privileges before writing.
#[derive(Debug, Clone)]
pub struct Target {
    /// Kernel name (e.g. `sdb`), feeding the builtin-name rule.
    pub name: String,
    /// Device node path, for messages (`/dev/sdb`).
    pub dev_path: String,
    /// Device capacity in bytes (`0` when unreadable).
    pub size_bytes: u64,
    /// sysfs write-protect state.
    pub read_only: bool,
    /// sysfs/card-removable state: true for "the plug looks removable".
    pub removable: bool,
    /// Stable serial (sysfs or udev) for the show-all confirmation and
    /// for messages.
    pub serial: Option<String>,
    /// The device (or a partition) backs `/`, `/boot`, `/usr`, `/var`.
    pub system_disk: bool,
    /// First mountpoint found (`/proc/self/mountinfo`), if any.
    pub mounted_at: Option<String>,
    /// Active swap source path (`/proc/swaps`), if any.
    pub swap_source: Option<String>,
    /// Kernel names of the upper blocks (dm/md/bcache) holding this one.
    pub holders: Vec<String>,
    /// `(partition name or None for the whole disk, kind)` — every
    /// superblock probe result, disk first, partitions after.
    pub filesystems: Vec<(Option<String>, FsKind)>,
    /// Size of the image to be written, when known.
    pub image_bytes: Option<u64>,
    /// "show all devices" is on (the user accepted fixed disks in
    /// principle, still not: typed serial required on top).
    pub allow_fixed: bool,
    /// What the user typed when show-all asked for the serial (PLAN §6
    /// rule 4): compared case-sensitively and non-empty.
    pub confirmed_serial: Option<String>,
    /// Why the device could not be opened/read, if it could not be;
    /// refuses first, before every other reason.
    pub unreadable: Option<String>,
}

/// The first refusable volume on the target, whole disk before any
/// partition (the whole-disk answer is the more general truth).
fn first_refusable(target: &Target) -> Option<Reason> {
    let whole_disk = target
        .filesystems
        .iter()
        .find(|(partition, fs)| partition.is_none() && fs.refusable());
    if let Some((_, fs)) = whole_disk {
        return Some(Reason::RefusedFilesystem {
            fs: *fs,
            partition: None,
        });
    }
    target
        .filesystems
        .iter()
        .find(|(_, fs)| fs.refusable())
        .map(|(partition, fs)| Reason::RefusedFilesystem {
            fs: *fs,
            partition: partition.clone(),
        })
}

/// Whether the show-all confirmation unblocks a non-removable device:
/// exactly show-all on, a non-empty typed serial, and an exact
/// case-sensitive match with the device's own serial.
fn removable_confirmed(target: &Target) -> bool {
    if !target.allow_fixed {
        return false;
    }
    let Some(typed) = target.confirmed_serial.as_deref() else {
        return false;
    };
    if typed.is_empty() {
        return false;
    }
    target.serial.as_deref() == Some(typed)
}

/// Judge one target and return the fail-closed verdict.
///
/// The precedence is documented (and pairwise-tested) on the module
/// header; here it is spelled as one straight-line early-return chain
/// so reading the code *is* reading the order. An audible reminder of
/// what is deliberately **not** refused: blank partition tables, zero
/// image sizes, and everything about transports.
#[must_use]
pub fn judge(target: &Target) -> SafetyVerdict {
    // 1. Unreadable first: no other fact was gathered honestly.
    if let Some(detail) = target.unreadable.as_deref() {
        return SafetyVerdict::Refuse(Reason::Unreadable {
            detail: detail.to_owned(),
        });
    }
    // 2. Zero capacity.
    if target.size_bytes == 0 {
        return SafetyVerdict::Refuse(Reason::ZeroSize);
    }
    // 3. Kernel-managed names.
    if is_builtin_name(&target.name) {
        return SafetyVerdict::Refuse(Reason::Loopback);
    }
    // 4. Write-protected.
    if target.read_only {
        return SafetyVerdict::Refuse(Reason::ReadOnly);
    }
    // 5. System disk: the strongest in-contention objection.
    if target.system_disk {
        return SafetyVerdict::Refuse(Reason::SystemDisk);
    }
    // 6. Mounted.
    if let Some(mountpoint) = target.mounted_at.as_deref() {
        return SafetyVerdict::Refuse(Reason::Mounted {
            mountpoint: mountpoint.to_owned(),
        });
    }
    // 7. Active swap.
    if let Some(source) = target.swap_source.as_deref() {
        return SafetyVerdict::Refuse(Reason::Swap {
            source: source.to_owned(),
        });
    }
    // 8. Held by dm/md/bcache.
    if let Some(holder) = target.holders.first() {
        return SafetyVerdict::Refuse(Reason::Holder {
            holder: holder.clone(),
        });
    }
    // 9. Refusable volume data (whole disk first, then partitions).
    if let Some(reason) = first_refusable(target) {
        return SafetyVerdict::Refuse(reason);
    }
    // 10. Too small — only with a known, larger image (no image, no
    //     refusal; PLAN's "erasing a blank stick is the normal case").
    if let Some(image_bytes) = target.image_bytes
        && image_bytes > target.size_bytes
    {
        return SafetyVerdict::Refuse(Reason::TooSmall {
            device_bytes: target.size_bytes,
            image_bytes,
        });
    }
    // 11. Non-removable, unless show-all *and* the typed serial matches.
    if !target.removable && !removable_confirmed(target) {
        return SafetyVerdict::Refuse(Reason::NotRemovable {
            serial: target.serial.clone(),
        });
    }
    // 12. Everything else writes on this device.
    SafetyVerdict::Safe
}

#[cfg(test)]
mod tests {
    use super::Reason;
    use super::SafetyVerdict;
    use super::Target;
    use super::judge;
    use crate::fsprobe::FsKind;

    /// A clean, removable, unmounted USB stick with the all-clear.
    fn clean_target() -> Target {
        Target {
            name: "sdb".to_owned(),
            dev_path: "/dev/sdb".to_owned(),
            size_bytes: 31_103_926_272, // a 32 GiB stick is 29.9 GiB, close enough here
            read_only: false,
            removable: true,
            serial: Some("4C530001120202116584".to_owned()),
            system_disk: false,
            mounted_at: None,
            swap_source: None,
            holders: Vec::new(),
            filesystems: Vec::new(),
            image_bytes: None,
            allow_fixed: false,
            confirmed_serial: None,
            unreadable: None,
        }
    }

    /// Apply one tweak `change` to the clean target and judge it.
    fn judged_with(change: impl FnOnce(&mut Target)) -> SafetyVerdict {
        let mut target = clean_target();
        change(&mut target);
        judge(&target)
    }

    // ------------------------------------------------------------------
    // Every reason in isolation
    // ------------------------------------------------------------------

    #[test]
    fn each_reason_refuses_in_isolation() {
        // Lambda types differ per row, so the closures are boxed for a
        // shared table type.
        type Case = (&'static str, Box<dyn FnOnce(&mut Target)>, SafetyVerdict);
        let cases: Vec<Case> = vec![
            (
                "unreadable",
                Box::new(|t: &mut Target| t.unreadable = Some("permission denied".to_owned())),
                SafetyVerdict::Refuse(Reason::Unreadable {
                    detail: "permission denied".to_owned(),
                }),
            ),
            (
                "zero size",
                Box::new(|t: &mut Target| t.size_bytes = 0),
                SafetyVerdict::Refuse(Reason::ZeroSize),
            ),
            (
                "loopback name",
                Box::new(|t: &mut Target| t.name = "dm-3".to_owned()),
                SafetyVerdict::Refuse(Reason::Loopback),
            ),
            (
                "read only",
                Box::new(|t: &mut Target| t.read_only = true),
                SafetyVerdict::Refuse(Reason::ReadOnly),
            ),
            (
                "system disk",
                Box::new(|t: &mut Target| t.system_disk = true),
                SafetyVerdict::Refuse(Reason::SystemDisk),
            ),
            (
                "mounted",
                Box::new(|t: &mut Target| t.mounted_at = Some("/media/user/STICK".to_owned())),
                SafetyVerdict::Refuse(Reason::Mounted {
                    mountpoint: "/media/user/STICK".to_owned(),
                }),
            ),
            (
                "swap",
                Box::new(|t: &mut Target| t.swap_source = Some("/dev/sdb1".to_owned())),
                SafetyVerdict::Refuse(Reason::Swap {
                    source: "/dev/sdb1".to_owned(),
                }),
            ),
            (
                "holder",
                Box::new(|t: &mut Target| t.holders = vec!["dm-0".to_owned()]),
                SafetyVerdict::Refuse(Reason::Holder {
                    holder: "dm-0".to_owned(),
                }),
            ),
            (
                "refused fs on a partition",
                Box::new(|t: &mut Target| {
                    t.filesystems = vec![
                        (Some("sdb1".to_owned()), FsKind::Fat32),
                        (Some("sdb2".to_owned()), FsKind::Lvm2),
                    ];
                }),
                SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                    fs: FsKind::Lvm2,
                    partition: Some("sdb2".to_owned()),
                }),
            ),
            (
                "refused fs on the whole disk",
                Box::new(|t: &mut Target| t.filesystems = vec![(None, FsKind::Btrfs)]),
                SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                    fs: FsKind::Btrfs,
                    partition: None,
                }),
            ),
            (
                "too small",
                Box::new(|t: &mut Target| t.image_bytes = Some(t.size_bytes + 1)),
                SafetyVerdict::Refuse(Reason::TooSmall {
                    device_bytes: 31_103_926_272,
                    image_bytes: 31_103_926_273,
                }),
            ),
            (
                "not removable",
                Box::new(|t: &mut Target| t.removable = false),
                SafetyVerdict::Refuse(Reason::NotRemovable {
                    serial: Some("4C530001120202116584".to_owned()),
                }),
            ),
        ];
        for (name, change, want) in cases {
            let verdict = judged_with(change);
            assert_eq!(verdict, want, "{name} must refuse as stated");
            assert!(!verdict.is_safe(), "{name} cannot be safe");
        }
    }

    // ------------------------------------------------------------------
    // Precedence pairs
    // ------------------------------------------------------------------

    #[test]
    fn precedence_pairs_all_resolved_in_the_documented_order() {
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.system_disk = true; // also mounted and too small
                t.mounted_at = Some("/".to_owned());
                t.image_bytes = Some(u64::MAX);
            }),
            SafetyVerdict::Refuse(Reason::SystemDisk),
            "system disk beats mounted and too_small"
        );
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.read_only = true; // also mounted
                t.mounted_at = Some("/run/media/x".to_owned());
            }),
            SafetyVerdict::Refuse(Reason::ReadOnly),
            "read_only beats mounted"
        );
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.image_bytes = Some(u64::MAX); // also not removable
                t.removable = false;
            }),
            SafetyVerdict::Refuse(Reason::TooSmall {
                device_bytes: 31_103_926_272,
                image_bytes: u64::MAX,
            }),
            "too_small beats not_removable"
        );
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.mounted_at = Some("/media/user".to_owned());
                t.filesystems = vec![(None, FsKind::Xfs)];
            }),
            SafetyVerdict::Refuse(Reason::Mounted {
                mountpoint: "/media/user".to_owned(),
            }),
            "mounted beats refused_filesystem"
        );
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.read_only = true;
                t.system_disk = true;
                t.mounted_at = Some("/".to_owned());
                t.swap_source = Some("/dev/sdb1".to_owned());
                t.holders = vec!["dm-1".to_owned()];
                t.filesystems = vec![(None, FsKind::Zfs)];
                t.image_bytes = Some(u64::MAX);
                t.removable = false;
            }),
            SafetyVerdict::Refuse(Reason::ReadOnly),
            "only the first reason in the order wins"
        );
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.unreadable = Some("I/O error".to_owned());
                t.size_bytes = 0;
                t.name = "dm-2".to_owned();
                t.system_disk = true;
                t.mounted_at = Some("/".to_owned());
            }),
            SafetyVerdict::Refuse(Reason::Unreadable {
                detail: "I/O error".to_owned(),
            }),
            "unreadable beats everything"
        );
    }

    #[test]
    fn holder_reports_the_first_holder_and_refusable_prefers_whole_disk() {
        assert_eq!(
            judged_with(|t: &mut Target| t.holders = vec!["md0".to_owned(), "bcache0".to_owned()]),
            SafetyVerdict::Refuse(Reason::Holder {
                holder: "md0".to_owned()
            })
        );
        // The whole-disk probe wins even when a refusable partition
        // appears earlier in the list (whole disk before partitions).
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.filesystems = vec![(Some("sdb1".to_owned()), FsKind::Lvm2), (None, FsKind::Zfs)];
            }),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Zfs,
                partition: None,
            }),
        );
        // With nothing refusable on the whole disk, list order decides
        // between partitions.
        assert_eq!(
            judged_with(|t: &mut Target| {
                t.filesystems = vec![
                    (Some("sdb1".to_owned()), FsKind::Lvm2),
                    (Some("sdb2".to_owned()), FsKind::Zfs),
                ];
            }),
            SafetyVerdict::Refuse(Reason::RefusedFilesystem {
                fs: FsKind::Lvm2,
                partition: Some("sdb1".to_owned()),
            }),
            "partitions keep list order when no whole-disk probe matches"
        );
    }

    // ------------------------------------------------------------------
    // The show-all serial confirmation
    // ------------------------------------------------------------------

    #[test]
    fn not_removable_path_gates_every_partial_attempt() {
        let serial = "4C530001120202116584".to_owned();
        // Lambda types differ per row, so the closures are boxed for a
        // shared table type.
        type Gate = (&'static str, Box<dyn FnOnce(&mut Target)>);
        let cases: Vec<Gate> = vec![
            (
                "allow_fixed alone",
                Box::new(|t: &mut Target| {
                    t.allow_fixed = true;
                    t.confirmed_serial = None;
                }),
            ),
            (
                "wrong serial",
                Box::new(|t: &mut Target| {
                    t.allow_fixed = true;
                    t.confirmed_serial = Some("0000".to_owned());
                }),
            ),
            (
                "empty confirmed serial",
                Box::new(|t: &mut Target| {
                    t.allow_fixed = true;
                    t.confirmed_serial = Some(String::new());
                }),
            ),
            (
                "serial typed but show-all off",
                Box::new(move |t: &mut Target| {
                    t.allow_fixed = false;
                    t.confirmed_serial = Some(serial.clone());
                }),
            ),
            (
                "device states no serial at all",
                Box::new(|t: &mut Target| {
                    t.allow_fixed = true;
                    t.confirmed_serial = Some("anything".to_owned());
                    t.serial = None;
                }),
            ),
        ];
        for (name, change) in cases {
            let mut target = clean_target();
            target.removable = false;
            change(&mut target);
            let verdict = judge(&target);
            assert_eq!(
                verdict,
                SafetyVerdict::Refuse(Reason::NotRemovable {
                    serial: target.serial.clone(),
                }),
                "{name} must not bypass the removable gate"
            );
        }
        // The one passing shape: show-all + exact non-empty match.
        let mut confirmed = clean_target();
        confirmed.removable = false;
        confirmed.allow_fixed = true;
        confirmed.confirmed_serial = Some("4C530001120202116584".to_owned());
        assert_eq!(judge(&confirmed), SafetyVerdict::Safe);
        // Case sensitivity is exact: a case-shifted serial must not
        // match a device that reports all-caps.
        let mut shifted = confirmed.clone();
        shifted.confirmed_serial = Some("4c530001120202116584".to_owned());
        assert_ne!(
            judge(&shifted),
            SafetyVerdict::Safe,
            "serial match is case-sensitive"
        );
    }

    // ------------------------------------------------------------------
    // The deliberate non-refusals
    // ------------------------------------------------------------------

    #[test]
    fn clean_stick_with_blank_table_and_missing_image_is_safe() {
        // A readable table but a blank/unknown one, and no image size:
        // the exactly normal erasing case — never a refusal.
        let mut target = clean_target();
        target.filesystems = vec![(None, FsKind::Fat32)];
        target.image_bytes = Some(0);
        assert_eq!(judge(&target), SafetyVerdict::Safe);
        assert!(judge(&target).is_safe());
    }

    #[test]
    fn image_of_zero_or_of_known_size_within_the_device_is_safe() {
        let mut target = clean_target();
        target.image_bytes = Some(target.size_bytes - 1);
        assert_eq!(judge(&target), SafetyVerdict::Safe);
        // Exactly device-sized also passes ("one sector of slack" comes
        // later in the helper's plan check; the verdict is binary).
        let mut equal = clean_target();
        equal.image_bytes = Some(equal.size_bytes);
        assert_eq!(judge(&equal), SafetyVerdict::Safe);
    }

    // ------------------------------------------------------------------
    // code() and Display pinning
    // ------------------------------------------------------------------

    #[test]
    fn reason_codes_are_pinned() {
        let reasons = [
            (
                Reason::Unreadable {
                    detail: "d".to_owned(),
                },
                "unreadable",
            ),
            (Reason::ZeroSize, "zero_size"),
            (Reason::Loopback, "loopback"),
            (Reason::ReadOnly, "read_only"),
            (Reason::SystemDisk, "system_disk"),
            (
                Reason::Mounted {
                    mountpoint: "/".to_owned(),
                },
                "mounted",
            ),
            (
                Reason::Swap {
                    source: "s".to_owned(),
                },
                "swap",
            ),
            (
                Reason::Holder {
                    holder: "h".to_owned(),
                },
                "holder",
            ),
            (
                Reason::RefusedFilesystem {
                    fs: FsKind::Lvm2,
                    partition: None,
                },
                "refused_filesystem",
            ),
            (
                Reason::TooSmall {
                    device_bytes: 1,
                    image_bytes: 2,
                },
                "too_small",
            ),
            (Reason::NotRemovable { serial: None }, "not_removable"),
        ];
        for (reason, code) in reasons {
            assert_eq!(reason.code(), code, "{reason:?} code");
        }
    }

    #[test]
    fn display_sentences_contain_the_offending_facts_and_stay_ascii() {
        let mounted = Reason::Mounted {
            mountpoint: "/media/user/STICK".to_owned(),
        };
        assert_eq!(
            mounted.to_string(),
            "device is mounted at /media/user/STICK - unmount it first"
        );
        assert!(mounted.to_string().is_ascii());

        let holder = Reason::Holder {
            holder: "dm-0".to_owned(),
        };
        assert_eq!(holder.to_string(), "device is held by dm-0");

        let refused = Reason::RefusedFilesystem {
            fs: FsKind::Lvm2,
            partition: Some("sdb1".to_owned()),
        };
        assert_eq!(
            refused.to_string(),
            "device contains lvm2 data at sdb1 - erase it with a dedicated tool"
        );

        let whole = Reason::RefusedFilesystem {
            fs: FsKind::Zfs,
            partition: None,
        };
        assert_eq!(
            whole.to_string(),
            "device contains zfs data - erase it with a dedicated tool"
        );

        let too_small = Reason::TooSmall {
            device_bytes: 536_870_912,
            image_bytes: 1_288_490_189,
        };
        assert_eq!(
            too_small.to_string(),
            "device is 512.00 MiB but the image needs 1.20 GiB"
        );

        let serial = Reason::NotRemovable {
            serial: Some("1234".to_owned()),
        };
        assert_eq!(serial.to_string(), "device is not removable (serial 1234)");

        let muted = Reason::NotRemovable { serial: None };
        assert_eq!(muted.to_string(), "device is not removable");

        let unreadable = Reason::Unreadable {
            detail: "permission denied".to_owned(),
        };
        assert_eq!(
            unreadable.to_string(),
            "device is unreadable: permission denied"
        );

        assert_eq!(Reason::ZeroSize.to_string(), "device has zero size");
        assert_eq!(Reason::ReadOnly.to_string(), "device is read-only");
        assert_eq!(
            Reason::SystemDisk.to_string(),
            "device backs the running system"
        );
        assert_eq!(
            Reason::Loopback.to_string(),
            "device is not real media (loopback, ram, zram, dm, md or optical device)"
        );

        // Hostile bytes are neutralised in the sentence itself (even if
        // a caller forgets to sanitise before building the reason).
        let hostile = Reason::Mounted {
            mountpoint: "/mnt/ST\u{1b}ICK".to_owned(),
        };
        assert_eq!(
            hostile.to_string(),
            "device is mounted at /mnt/ST?ICK - unmount it first"
        );
        assert!(hostile.to_string().is_ascii());
    }

    #[test]
    fn builtin_names_match_the_filter_documented_set() {
        for name in [
            "loop0", "ram0", "zram0", "dm-0", "md0", "sr0", "loop", "md", "sr",
        ] {
            assert!(super::is_builtin_name(name), "{name} is a builtin name");
        }
        for name in [
            "sda", "sda1", "sdb", "mmcblk0", "nvme0n1", "vdx", "", "dmx", "aardvark",
        ] {
            assert!(
                !super::is_builtin_name(name),
                "{name} is not a builtin name"
            );
        }
    }
}
