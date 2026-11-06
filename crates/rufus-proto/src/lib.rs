//! `rufus-proto`: versioned plan/progress types shared by the GUI, the CLI
//! and the privileged helper.
//!
//! Slice S03 delivers the plan contract: [`Plan`] (device, image, options,
//! steps, confirm hash) and its enums. S06 adds the helper event stream
//! (progress, log lines and completion) — see
//! [Helper event stream](#helper-event-stream) below; there are no
//! placeholder types.

#![forbid(unsafe_code)]
//!
//! [`Plan`] is the single artefact that travels from an unprivileged front
//! end to the root helper: the device to touch, the image to write, the
//! chosen options and the ordered [`Step`]s. Consumers:
//!
//! * S03 CLI — produces provisional plans (`rufus plan --dry-run`);
//! * S06 helper — validates a plan (version, [`Plan::confirm`]) and runs it;
//! * S17 executor — maps each step onto concrete block I/O.
//!
//! # Versioning contract
//!
//! * [`PLAN_VERSION`] is the whole-schema version, not a per-field one.
//!   `version` is checked by the helper before anything else; a plan
//!   carrying any other version (v1 included) is refused, fail closed
//!   (PLAN §2).
//! * Schema history: v1 was the S03 plan shape; v2 appended
//!   [`Options::confirmed_serial`] (as the last options field —
//!   declaration order is append-only, older fields keep their
//!   relative positions) — the typed device serial PLAN §6 rule 4
//!   wants as the second half of the show-all confirmation, so the
//!   helper can tell "user ticked show-all" apart from "user typed the
//!   serial". A v1 plan must not be blessed by a v2 reader: its
//!   confirm hash describes the v1 byte layout, so the version check
//!   refuses it outright. v3 appended [`Step::Mkpart::layout`] — the
//!   partition layout the data window derives from — so a v2 plan
//!   (whose mkpart step carries no layout) is refused outright for
//!   the same reason. v4 added the `kolibri` [`BootloaderMode`]
//!   variant — so a v3 plan is refused outright for the same reason
//!   (unknown enum variants refuse instead of guessing). v5 added the
//!   `msdos` [`BootloaderMode`] variant and appended
//!   [`Options::msdos_dir`] (as the last options field, like
//!   `confirmed_serial` before it) — so a v4 plan is refused
//!   outright for the same reason.
//! * `confirm` is the SHA-256 over the canonical JSON bytes of the plan
//!   with `confirm` set to `""` (see [`Plan::confirm`]). serde_json writes
//!   struct fields in declaration order, so the byte layout *is* the
//!   declaration order below.
//! * Changing the declaration order of any struct field changes every
//!   confirm hash and is therefore a schema change: bump [`PLAN_VERSION`].
//!   Adding a variant to an enum, adding/removing/reordering fields, or
//!   changing any field's meaning all require a bump for the same reason.
//! * Structs deliberately keep serde's default of *ignoring* unknown
//!   fields (there is no `deny_unknown_fields` anywhere): a newer writer
//!   may add fields and an older reader will still load the plan. The
//!   reader's `confirm` does not cover fields it does not know about, so
//!   trust the helper's validation, not confirm alone, across versions.
//!   Unknown *enum variants* (e.g. a future [`Step`] op) are not ignorable
//!   in serde: an old reader refuses the whole plan instead of guessing —
//!   PLAN §2 "fail closed" — so adding a variant also bumps
//!   [`PLAN_VERSION`].
//!
//! # Helper event stream
//!
//! [`Event`] (delivered with S06 in [`events`]) is the JSONL contract the
//! helper speaks to its front end while a plan runs: one event per line,
//! no framing bytes, tagged by its `kind` field and echoing the run's
//! `session` on every event — see the `events` module docs for the full
//! contract. [`EVENT_STREAM_VERSION`] versions this stream independently
//! of [`PLAN_VERSION`]; every [`Completion`] carries it.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

// S06: the helper event stream (progress/log/completion) lives in its own
// module so the stream schema versions independently of the plan schema.
// The re-exports below are the names user code references.
pub mod events;

pub use events::{Completion, EVENT_STREAM_VERSION, Event, LogLevel, LogLine, Outcome, Progress};

/// Schema version of [`Plan`]. v5 added the `msdos`
/// [`BootloaderMode`] variant and appended [`Options::msdos_dir`],
/// and refuses v1/v2/v3/v4 plans, fail
/// closed — see the schema history in the crate documentation. A
/// plan carrying a higher or older version must be refused by the
/// helper.
pub const PLAN_VERSION: u32 = 5;

/// A write plan: device, image, options, ordered steps and a confirm hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Must equal [`PLAN_VERSION`]; the helper refuses other values.
    pub version: u32,
    /// What produced this plan, e.g. `"rufus-linux/0.1.0 (<git hash>)"`.
    pub created_by: String,
    /// Target device.
    pub device: DeviceRef,
    /// Source image.
    pub image: ImageRef,
    /// Format/mount options as chosen by the user.
    pub options: Options,
    /// Ordered operations the executor performs.
    pub steps: Vec<Step>,
    /// `"sha256:<hex>"` integrity hash (see [`Plan::confirm`]).
    pub confirm: String,
}

impl Plan {
    /// Compute the confirm hash of this plan.
    ///
    /// The hash is `sha256:<hex>` where `<hex>` is the SHA-256 of the
    /// canonical serialisation (compact JSON) of the plan with its
    /// `confirm` field set to `""` — i.e. the field is *present* as
    /// `"confirm":""`, which pins the schema shape. The stored value of
    /// `self.confirm` is ignored; the caller compares the returned hash
    /// against what was written to the plan file.
    ///
    /// Falls back to `Err` only if serde_json serialisation fails — for
    /// this type that is practically impossible (all fields are
    /// JSON-native strings, numbers, bools, objects and arrays; there are
    /// no maps with non-string keys and no floats), but the API returns
    /// the error instead of panicking, and callers must fail closed (PLAN
    /// §2): never accept a plan whose confirm could not be recomputed.
    ///
    /// Note: because `Plan` ignores unknown fields on deserialise but
    /// `confirm` covers only known fields, a plan file with extra fields
    /// still verifies; see the crate documentation on forward compat
    /// (unknown enum variants refuse instead, which is the fail-closed
    /// behaviour PLAN §2 wants).
    pub fn confirm(&self) -> Result<String, serde_json::Error> {
        let mut neutral = self.clone();
        neutral.confirm.clear();
        let bytes = serde_json::to_vec(&neutral)?;
        Ok(format!("sha256:{}", hex(&Sha256::digest(&bytes))))
    }
}

/// The target device, identified by path and (later slices) enough context
/// for the helper to re-check it against sysfs before the first write.
///
/// `size_bytes`, `serial`, `model` and `sysfs` are filled from sysfs
/// discovery since S04 when the target path is a real device; they stay
/// `None` for dry-run plans over fixture paths (the S03 shape) and for
/// devices the kernel does not expose. The helper fails a plan whose
/// device lacks sysfs identity once S06 enforces plan §6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRef {
    /// Device path as presented, e.g. `/dev/sdb`.
    pub path: String,
    /// `true` only for real block devices (never a file, loop or
    /// character device).
    pub block_device: bool,
    /// Device capacity in bytes; `None` when discovery did not find the
    /// path (a dry-run over a fixture file, or an unreadable sysfs).
    pub size_bytes: Option<u64>,
    /// Stable serial (config identity); `None` when undiscovered.
    pub serial: Option<String>,
    /// Human-readable model; `None` when undiscovered.
    pub model: Option<String>,
    /// `/sys/class/block/<name>` path; `None` when undiscovered.
    pub sysfs: Option<String>,
}

/// The source image: path, size, digest and detected container kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    /// File path as presented.
    pub path: String,
    /// Exact file length in bytes.
    pub size_bytes: u64,
    /// SHA-256 of the whole image, lowercase hex.
    pub sha256: String,
    /// Container family (see [`ImageKind`]).
    pub kind: ImageKind,
}

/// Container family of an image, detected by magic only in this slice.
///
/// `Unknown` marks files too short for any check to apply; `Raw` is a
/// non-empty file where no known magic matched. Every other container
/// becomes a reader/executor job in S14/S15/S17.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    /// ISO9660 (`CD001` at 0x8001).
    Iso,
    /// Windows Imaging Format (`MSWIM\0\0\0` at 0).
    Wim,
    /// VHD (`conectix` footer at size-512).
    Vhd,
    /// VHDX (`vhdxfile` at 0).
    Vhdx,
    /// Samsung/Microsoft full-flash update (`ImageFlash` at 0).
    Ffu,
    /// gzip stream.
    Gzip,
    /// xz stream.
    Xz,
    /// bzip2 stream.
    Bzip2,
    /// zstd stream.
    Zstd,
    /// Windows PE (`MZ` at 0).
    Pe,
    /// qcow2 (`QFI\xfb` at 0).
    Qcow2,
    /// Raw disk image (no container magic).
    Raw,
    /// Unidentifiable (e.g. empty or too short to hold any magic).
    Unknown,
}

/// User-selected format options. Field order is the canonical confirm
/// order (see the crate documentation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    /// Partition table.
    pub scheme: Scheme,
    /// Boot target the media must serve.
    pub target: Target,
    /// Filesystem for the data partition.
    pub filesystem: Filesystem,
    /// Volume label as written; `None` lets the executor derive the
    /// Rufus-style default from the image.
    pub label: Option<String>,
    /// Cluster size in bytes; `None` is executor-chosen default.
    pub cluster_bytes: Option<u32>,
    /// Quick format (Rufus default); `false` means a full surface format.
    pub quick_format: bool,
    /// Scan for bad blocks in the wipe step, before the table and
    /// format.
    pub bad_blocks: bool,
    /// Read-back verification of the written image.
    pub verify: bool,
    /// Create a persistence partition (Linux live media).
    pub persistence: bool,
    /// "Show all devices" was enabled for this plan.
    pub show_all: bool,
    /// Serial the user typed to confirm writing a non-removable ("show all")
    /// device; `Some` only when `show_all` is true and the serial matched at
    /// plan time. `None` means no confirmation was given.
    pub confirmed_serial: Option<String>,
    /// Directory holding the user-supplied MS-DOS system files
    /// (`IO.SYS`, `MSDOS.SYS`, `COMMAND.COM`); `Some` only for `msdos`
    /// bootloader plans, `None` for every other plan. The `--image`
    /// reference stays required even for such plans (detection still
    /// runs) but is unused by them: the installer reads this
    /// directory, never the image.
    pub msdos_dir: Option<String>,
}

/// Partition table scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// Master Boot Record.
    Mbr,
    /// GUID Partition Table (protective MBR included).
    Gpt,
}

/// Firmware the media must boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// BIOS/CSM only.
    Bios,
    /// UEFI only.
    Uefi,
    /// Both (usual for hybrid distro ISOs).
    Dual,
}

/// Filesystem for the data partition; creation is natively implemented for
/// FAT32/exFAT (S09/S10) and via external tools for the rest (A4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filesystem {
    /// FAT32.
    Fat32,
    /// exFAT.
    Exfat,
    /// NTFS (needs `mkntfs`).
    Ntfs,
    /// ext2 (needs `mke2fs`).
    Ext2,
    /// ext3 (needs `mke2fs`).
    Ext3,
    /// ext4 (needs `mke2fs`).
    Ext4,
    /// UDF (needs `mkudffs`).
    Udf,
}

/// Step of [`Plan::steps`]; each maps to one executor stage in S17.
///
/// The steps deliberately describe *what* to do, not offset-level *how*:
/// exact LBA placement, alignment, gaps and per-engine arguments are the
/// executor's job, computed against the real device geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    /// Clear the device's first/last megabytes (and BLKDISCARD best
    /// effort), then rescan.
    Wipe,
    /// Write an empty partition table.
    Mklabel {
        /// Table to lay out.
        scheme: Scheme,
    },
    /// Create the data partition in the table.
    Mkpart {
        /// Table the partition lives in.
        scheme: Scheme,
        /// Layout the partition belongs to (the data partition's
        /// position and window derive from it).
        layout: Layout,
    },
    /// Format the data partition.
    Mkfs {
        /// Filesystem engine to run.
        filesystem: Filesystem,
        /// Volume label, or executor default.
        label: Option<String>,
        /// Cluster size in bytes, or executor default.
        cluster_bytes: Option<u32>,
        /// Quick (metadata only) or full surface format.
        quick: bool,
    },
    /// Transfer the image to the target.
    Write {
        /// How the image is transferred.
        mode: WriteMode,
    },
    /// Install the bootloader staged for the target.
    Bootloader {
        /// Bootloader family.
        mode: BootloaderMode,
    },
    /// Final checks + partition rescan + flush; done.
    Finalize,
}

/// Partition layout of a plan: which of the planner's table shapes
/// [`Step::Mkpart`] stamps. Wire-level mirror of the core planner's
/// `LayoutKind` (this crate has no dependencies, so the enum is
/// duplicated and core maps it exactly as `Scheme` maps to
/// `TableKind`): the data partition's position and byte window derive
/// from it, so the stamper, the opener and the node spelling cannot
/// drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// One data partition over the whole usable span.
    Single,
    /// A small FAT `UEFI_NTFS` partition followed by the data
    /// partition (the UEFI:NTFS boot shim for NTFS media).
    UefiNtfs,
    /// ESP + Microsoft Reserved + Windows data (portable Windows).
    WindowsToGo,
    /// Linux data first, then the ext4 persistence tail.
    Persistence,
}

/// How an image reaches the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    /// Block-for-block stream (ISOs, raw and compressed raw images).
    Dd,
    /// Copy the payload via a filesystem writer (`wimlib` apply, tree
    /// copy); used for WIM-based media in this schema generation.
    Copy,
}

/// Bootloader family for [`Step::Bootloader`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootloaderMode {
    /// Executor picks per-image (classification, S16).
    Auto,
    /// Syslinux 4.x/6.x.
    Syslinux,
    /// GNU GRUB 2.
    Grub2,
    /// GRUB4DOS.
    Grub4dos,
    /// UEFI:NTFS helper partition.
    UefiNtfs,
    /// FreeDOS.
    Freedos,
    /// KolibriOS.
    Kolibri,
    /// MS-DOS from user-supplied system files: MS-DOS cannot be
    /// bundled for licensing reasons, so the three files (`IO.SYS`,
    /// `MSDOS.SYS`, `COMMAND.COM`) come from the plan's `msdos_dir`,
    /// never from an embedded payload. The installer reads no image
    /// tree — an `msdos` plan carries no write step, and `run`
    /// short-circuits past the tree setup — so the plan image needs
    /// no readable tree.
    #[serde(rename = "msdos")]
    MsDos,
    /// No bootloader (plain data media).
    None,
}

impl fmt::Display for ImageKind {
    /// Lowercase snake-case JSON tag, e.g. `"iso"`, `"bzip2"`, `"unknown"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Iso => "iso",
            Self::Wim => "wim",
            Self::Vhd => "vhd",
            Self::Vhdx => "vhdx",
            Self::Ffu => "ffu",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Bzip2 => "bzip2",
            Self::Zstd => "zstd",
            Self::Pe => "pe",
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
            Self::Unknown => "unknown",
        })
    }
}

/// Lowercase hex (allocating); kept local so this crate stays standalone.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

// S06 bumps the schema to v2: `Options.confirmed_serial` is appended
// (PLAN §6 rule 4's typed serial confirmation). S20 bumps it to v3:
// `Step::Mkpart::layout` is appended (the partition layout the data
// window derives from). S20 part 10 bumps it to v4: the `kolibri`
// `BootloaderMode` variant is added. S20 part 11 bumps it to v5: the
// `msdos` `BootloaderMode` variant is added and `Options.msdos_dir`
// is appended (the user-supplied MS-DOS directory). Bumping the version must be a
// deliberate commit that also regenerates every golden file (see the
// crate documentation about field order and confirm hashes).
const _: () = assert!(PLAN_VERSION >= 1, "PLAN_VERSION must stay positive");

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated plan used by several tests; one field per branch
    /// of every enum where practical.
    fn sample() -> Plan {
        Plan {
            version: PLAN_VERSION,
            created_by: "rufus-linux/0.1.0 (test)".to_string(),
            device: DeviceRef {
                path: "/dev/sdb".to_string(),
                block_device: true,
                size_bytes: Some(32_010_928_128),
                serial: Some("ABC123".to_string()),
                model: Some("Rufus Test Stick".to_string()),
                sysfs: Some("/sys/class/block/sdb".to_string()),
            },
            image: ImageRef {
                path: "/home/u/ubuntu.iso".to_string(),
                size_bytes: 4_000_000_000,
                sha256: "0".repeat(64),
                kind: ImageKind::Iso,
            },
            options: Options {
                scheme: Scheme::Gpt,
                target: Target::Dual,
                filesystem: Filesystem::Fat32,
                label: Some("UBUNTU".to_string()),
                cluster_bytes: Some(32768),
                quick_format: true,
                bad_blocks: false,
                verify: true,
                persistence: false,
                show_all: false,
                confirmed_serial: Some("ABC123".to_string()),
                msdos_dir: None,
            },
            steps: vec![
                Step::Wipe,
                Step::Mklabel {
                    scheme: Scheme::Gpt,
                },
                Step::Mkpart {
                    scheme: Scheme::Gpt,
                    layout: Layout::Single,
                },
                Step::Mkfs {
                    filesystem: Filesystem::Fat32,
                    label: Some("UBUNTU".to_string()),
                    cluster_bytes: Some(32768),
                    quick: true,
                },
                Step::Write {
                    mode: WriteMode::Dd,
                },
                Step::Bootloader {
                    mode: BootloaderMode::Auto,
                },
                Step::Finalize,
            ],
            confirm: String::new(),
        }
    }

    #[test]
    fn schema_version_is_five_until_deliberately_bumped() {
        assert_eq!(PLAN_VERSION, 5);
        let mut plan = sample();
        plan.confirm = plan.confirm().expect("sample serialises to canonical JSON");
        assert_eq!(plan.version, PLAN_VERSION);
        let round =
            serde_json::from_str::<Plan>(&serde_json::to_string(&plan).expect("sample serialises"))
                .expect("sample round-trips");
        assert_eq!(plan, round);
    }

    #[test]
    fn msdos_dir_round_trips() {
        // v5's appended field survives the wire: a plan carrying a
        // user-supplied MS-DOS directory deserialises to itself.
        let mut plan = sample();
        plan.options.msdos_dir = Some("/tmp/dos".to_string());
        plan.confirm = plan.confirm().expect("sample serialises to canonical JSON");
        let round =
            serde_json::from_str::<Plan>(&serde_json::to_string(&plan).expect("sample serialises"))
                .expect("sample round-trips");
        assert_eq!(plan, round);
        assert_eq!(round.options.msdos_dir.as_deref(), Some("/tmp/dos"));
    }

    #[test]
    fn json_shape_is_the_documented_contract() {
        let mut plan = sample();
        plan.confirm = plan.confirm().expect("sample serialises to canonical JSON");
        let text = serde_json::to_string(&plan).expect("serialises");

        // 1. Canonical field order == declaration order (this is what the
        //    confirm hash is computed over). `serde_json::Value` uses an
        //    alphabetically ordered map, so the order is asserted on the
        //    compact string instead. Objects nest in declaration order, so
        //    the top-level keys sort after `options`/`image` etc. — the
        //    guard below is exact for `version`..`options` and range-based
        //    for `steps`/`confirm`.
        let positions: Vec<usize> = ["version", "created_by", "device", "image", "options"]
            .iter()
            .map(|key| text.find(&format!(r#""{key}":"#)).expect(key))
            .collect();
        for pair in positions.windows(2) {
            assert!(pair[0] < pair[1], "field order changed: {text}");
        }
        let confirm_at = text.find(r#""confirm":""#).expect("confirm key");
        let image_at = text.find(r#""image":{"#).expect("image key");
        assert!(image_at < confirm_at, "confirm must stay last: {text}");
        // v2 appended `confirmed_serial` inside `options`; pin it after
        // `show_all` so a reordering cannot slip through a hash-only
        // equality (the hash would change too, but this names the field).
        // v5 appended `msdos_dir` after it, for the same reason.
        let show_all_at = text.find(r#""show_all":"#).expect("show_all key");
        let confirmed_at = text
            .find(r#""confirmed_serial":"#)
            .expect("confirmed_serial key");
        assert!(
            show_all_at < confirmed_at,
            "confirmed_serial must follow show_all: {text}"
        );
        let msdos_at = text.find(r#""msdos_dir":"#).expect("msdos_dir key");
        assert!(
            confirmed_at < msdos_at,
            "msdos_dir must follow confirmed_serial: {text}"
        );

        // 2. Values and tags (order-insensitive via Value).
        let obj: serde_json::Value = serde_json::from_str(&text).expect("value");
        assert_eq!(obj["version"], 5);
        assert_eq!(obj["confirm"], plan.confirm);
        assert_eq!(
            obj["options"]["confirmed_serial"], "ABC123",
            "v2's typed serial confirmation rides in options"
        );
        assert_eq!(
            obj["options"]["msdos_dir"],
            serde_json::Value::Null,
            "v5's user-supplied MS-DOS directory rides in options, null here"
        );
        let steps = obj["steps"].as_array().expect("steps array");
        assert_eq!(steps[0]["op"], "wipe");
        assert_eq!(steps[1]["op"], "mklabel");
        assert_eq!(steps[1]["scheme"], "gpt");
        // v3 appended `layout` to the mkpart step; pin it after
        // `scheme` so a reordering cannot slip through a hash-only
        // equality (the hash would change too, but this names the field).
        assert_eq!(steps[2]["op"], "mkpart");
        assert_eq!(steps[2]["scheme"], "gpt");
        assert_eq!(steps[2]["layout"], "single");
        assert_eq!(steps[3]["op"], "mkfs");
        assert_eq!(steps[3]["filesystem"], "fat32");
        assert_eq!(steps[4]["op"], "write");
        assert_eq!(steps[4]["mode"], "dd");
        assert_eq!(steps[5]["op"], "bootloader");
        assert_eq!(steps[5]["mode"], "auto");
        assert_eq!(steps[6]["op"], "finalize");
        assert_eq!(obj["options"]["scheme"], "gpt");
        assert_eq!(obj["options"]["target"], "dual");
        assert_eq!(obj["options"]["quick_format"], true);
        assert_eq!(obj["options"]["bad_blocks"], false);
        assert_eq!(obj["image"]["kind"], "iso");
        assert_eq!(obj["device"]["block_device"], true);
        assert_eq!(obj["device"]["size_bytes"], 32_010_928_128u64);
    }

    #[test]
    fn confirm_is_stable_across_serialisations() {
        let mut a = sample();
        a.confirm = a.confirm().expect("a serialises");
        let bytes = serde_json::to_vec(&a).expect("serialises");
        let mut b: Plan = serde_json::from_slice(&bytes).expect("parses");
        b.confirm = b.confirm().expect("b serialises");
        assert_eq!(a.confirm, b.confirm);
        // bool/number/string fields round-trip exactly, keeping the hash
        // equal because the canonical bytes are equal.
        assert_eq!(serde_json::to_vec(&a).expect("a"), bytes);
        assert_eq!(serde_json::to_vec(&b).expect("b"), bytes);
    }

    #[test]
    fn confirm_covers_every_known_field() {
        let mut base = sample();
        base.confirm = base.confirm().expect("base serialises");

        let check = |label: &str, mutate: &dyn Fn(&mut Plan)| {
            let mut other = base.clone();
            mutate(&mut other);
            let fresh = other.confirm().expect("mutant serialises");
            other.confirm = fresh.clone();
            assert_ne!(fresh, base.confirm, "{label} did not change the hash");
        };

        check("version", &|p| p.version = 6);
        check("created_by", &|p| p.created_by = "x".into());
        check("device.path", &|p| p.device.path = "/dev/sdc".into());
        check("device.block_device", &|p| p.device.block_device = false);
        check("image.path", &|p| p.image.path = "/other.iso".into());
        check("image.sha256", &|p| p.image.sha256 = "1".repeat(64));
        check("image.kind", &|p| p.image.kind = ImageKind::Raw);
        check("scheme", &|p| p.options.scheme = Scheme::Mbr);
        check("target", &|p| p.options.target = Target::Uefi);
        check("filesystem", &|p| p.options.filesystem = Filesystem::Exfat);
        check("label", &|p| p.options.label = None);
        check("cluster", &|p| p.options.cluster_bytes = None);
        check("quick_format", &|p| p.options.quick_format = false);
        check("verify", &|p| p.options.verify = false);
        // v2: dropping the typed confirmation must change the hash, or a
        // tampered plan could shed its serial and still verify.
        check("confirmed_serial", &|p| p.options.confirmed_serial = None);
        // v5: changing the user-supplied MS-DOS directory must change
        // the hash, or a tampered plan could swap its DOS files and
        // still verify.
        check("msdos_dir", &|p| {
            p.options.msdos_dir = Some("/tmp/dos".to_string());
        });
        check("steps", &|p| p.steps.truncate(1));
        check("step payload", &|p| {
            if let Step::Write { mode } = &mut p.steps[4] {
                *mode = WriteMode::Copy;
            }
        });
        // v3: swapping the mkpart layout must change the hash, or a
        // tampered plan could move the data window and still verify.
        check("step layout", &|p| {
            if let Step::Mkpart { layout, .. } = &mut p.steps[2] {
                *layout = Layout::UefiNtfs;
            }
        });
    }

    #[test]
    fn confirm_ignores_stored_confirm_value() {
        let mut plan = sample();
        let hash = plan.confirm().expect("plan serialises");
        plan.confirm = "garbage".to_string();
        assert_eq!(
            plan.confirm().expect("recompute serialises"),
            hash,
            "recomputing must not read the field"
        );
    }

    #[test]
    fn unknown_fields_are_tolerated_for_forward_compatibility() {
        let json = r#"{
            "version": 1,
            "created_by": "future",
            "device": {"path": "/dev/sdb", "block_device": true,
                       "future_field": 7},
            "image": {"path": "x.iso", "size_bytes": 1, "sha256": "0",
                      "kind": "iso", "future": [1,2,3]},
            "options": {"scheme": "mbr", "target": "dual",
                          "filesystem": "fat32", "label": null,
                          "cluster_bytes": null, "quick_format": false,
                          "bad_blocks": false, "verify": false,
                          "persistence": false, "show_all": false,
                          "confirmed_serial": null, "msdos_dir": null,
                          "future_switch": true},
            "steps": [{"op": "wipe", "future_hint": 1}],
            "confirm": ""
        }"#;
        let plan: Plan = serde_json::from_str(json).expect("unknown fields are ignored");
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.version, 1);
        // Unknown *variants*, unlike unknown struct fields, make the reader
        // refuse (fail closed) — a deliberate schema property.
        let future_variant = r#"{"op":"future_op"}"#;
        assert!(serde_json::from_str::<Step>(future_variant).is_err());
    }

    #[test]
    fn bootloader_mode_tags_match_the_documented_modes() {
        for (mode, tag) in [
            (BootloaderMode::Auto, "auto"),
            (BootloaderMode::Syslinux, "syslinux"),
            (BootloaderMode::Grub2, "grub2"),
            (BootloaderMode::Grub4dos, "grub4dos"),
            (BootloaderMode::UefiNtfs, "uefi_ntfs"),
            (BootloaderMode::Freedos, "freedos"),
            (BootloaderMode::Kolibri, "kolibri"),
            (BootloaderMode::MsDos, "msdos"),
            (BootloaderMode::None, "none"),
        ] {
            let wire = serde_json::to_string(&mode).expect("mode serialises");
            assert_eq!(wire, format!(r#""{tag}""#), "the {tag} tag is pinned");
        }
        // The `kolibri` tag is the v4 addition: it must deserialize
        // back to the new variant, so a v3 reader's refusal is the
        // fail-closed behaviour the version check wants.
        let mode: BootloaderMode = serde_json::from_str(r#""kolibri""#).expect("kolibri parses");
        assert_eq!(mode, BootloaderMode::Kolibri);
        // The `msdos` tag is the v5 addition: it must deserialize
        // back to the new variant, so a v4 reader's refusal is the
        // fail-closed behaviour the version check wants.
        let mode: BootloaderMode = serde_json::from_str(r#""msdos""#).expect("msdos parses");
        assert_eq!(mode, BootloaderMode::MsDos);
    }

    #[test]
    fn layout_tags_match_the_documented_shapes() {
        for (layout, tag) in [
            (Layout::Single, "single"),
            (Layout::UefiNtfs, "uefi_ntfs"),
            (Layout::WindowsToGo, "windows_to_go"),
            (Layout::Persistence, "persistence"),
        ] {
            let wire = serde_json::to_string(&layout).expect("layout serialises");
            assert_eq!(wire, format!(r#""{tag}""#));
        }
    }

    #[test]
    fn image_kind_display_matches_json_tags() {
        for (kind, tag) in [
            (ImageKind::Iso, "iso"),
            (ImageKind::Wim, "wim"),
            (ImageKind::Vhd, "vhd"),
            (ImageKind::Vhdx, "vhdx"),
            (ImageKind::Ffu, "ffu"),
            (ImageKind::Gzip, "gzip"),
            (ImageKind::Xz, "xz"),
            (ImageKind::Bzip2, "bzip2"),
            (ImageKind::Zstd, "zstd"),
            (ImageKind::Pe, "pe"),
            (ImageKind::Qcow2, "qcow2"),
            (ImageKind::Raw, "raw"),
            (ImageKind::Unknown, "unknown"),
        ] {
            assert_eq!(kind.to_string(), tag);
            let wire = serde_json::to_string(&kind).expect("kind serialises");
            assert_eq!(wire, format!(r#""{tag}""#));
        }
    }
}
