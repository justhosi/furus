//! External-tool acceptance for the S13 UDF formatter (PLAN lines
//! 703-717: UDF volumes matching the mandate, built by the external
//! `mkudffs` formatter, verified with `udfinfo`, persistence of the label
//! and the written tree through a kernel mount).
//!
//! Every test drives the crate's real path - a sparse image file
//! (`File::set_len`, never a `Vec`) formatted by `udf::format` - and the
//! tool path wherever a tool is needed: the crate shells out to
//! `mkudffs --utf8 --media-type=hd --udfrev=0x0201 -b <512|2048>
//! [-l <label>] <target>` (`--utf8` first, the target last); then the raw
//! image goes to somebody else's reader, with only what that tool reports
//! asserted: `udfinfo` for the label, the block size and the revision.
//! A missing tool is printed as an explicit skip line; a failing tool
//! fails the test with its real output in the message.
//!
//! What is measured here, tool by tool (each bullet names what this run
//! actually did, measured with udftools 2.3 in an `archlinux:latest`
//! container - `pacman -Sy --noconfirm udftools` - unless noted):
//! - block-size matrix (16 MiB, labels `RUFUS512`/`RUFUS2048`):
//!   `format` returns `Recognition { nsr: Nsr03 }` for both
//!   `BlockSize::Bytes512` and `BlockSize::Bytes2048`, and `udfinfo`
//!   independently reports `label=<that label>`, `blocksize=512`/`2048`
//!   and `udfrev=2.01` on the same image.
//! - short ASCII label (`RUFUSUDF`): `udfinfo` reports `label=RUFUSUDF`
//!   (with `lvid=RUFUSUDF` and `vid=RUFUSUDF` alongside), and `format`
//!   returns NSR03.
//! - full 126-byte label (`UDF` repeated 42 times): accepted, and
//!   `udfinfo` reports all 126 bytes back in `label=` (the line is 133
//!   bytes: `label=` plus the 126 bytes plus a newline). 127 bytes are
//!   refused by the tool (`mkudffs: Error: Option --label is too long`);
//!   the API refuses them first (pinned by the crate's unit tests), so no
//!   acceptance test drives a 127-byte label through the tool.
//! - no label (no `-l` flag): the tool applies its own default and
//!   `udfinfo` reports `label=LinuxUDF` (with `lvid=LinuxUDF` and
//!   `vid=LinuxUDF` alongside). An explicit empty label (`-l ""`) is a
//!   different shape - `udfinfo` then reports a bare `label=` line - and
//!   stays a unit-level fact, not an acceptance row.
//! - the revision: `udfrev=2.01` in `udfinfo` on a freshly formatted
//!   image, with our own reader seeing the NSR03 identifier the pinned
//!   `--udfrev=0x0201` revision writes (NSR02 belongs to `--udfrev=0x0150`
//!   and is refused, pinned by the crate's unit tests).
//! - missing target: `format` on an absent path refuses with `does not
//!   exist` before any probe or spawn (the tool itself would exit 1 with
//!   `Cannot create new image file ... : block-count was not specified`,
//!   measured), and the path still does not exist afterwards. This test
//!   needs no tool, so it passes on a bare host too.
//! - reader agreement: `udf::recognition` over bytes 32768..38912 of the
//!   first-38912-byte read of a tool-formatted image returns NSR03 - the
//!   same verdict `udfinfo` gives (the descriptors sit at absolute
//!   32768/34816/36864 for both block sizes, each opening with the struct
//!   type byte `0x00` and version byte `0x01`; sector 19 at 38912 is
//!   zero throughout).
//! - image floor: the tool warns below 258 blocks
//!   (`mkudffs: Warning: UDF filesystem has less than 258 blocks, it can
//!   cause problems`, measured on a 64 KiB image) but still exits 0, so
//!   every test here formats 16 MiB (32768 blocks at `-b 512`, 8192 at
//!   `-b 2048`) and never meets the warning.
//!
//! Skip convention (the one tests/ext_format.rs, tests/exfat_format.rs
//! and tests/ntfs_format.rs carry): every test that needs a real tool
//! probes it first and prints an explicit `skip:` line when it is
//! missing - a skip is a documented limitation, never a silent pass.
//! Presence is probed by spawn alone - a bare `Command::new(program)`
//! with no arguments, spawn success only, never an exit-code or output
//! verdict - because this family accepts no version flag: `--version` is
//! an unrecognized option (exit 1), `-V` is an invalid option (exit 1),
//! and a bare run prints `mkudffs from udftools <version>` on stderr
//! with exit 1 (all three measured with udftools 2.3), so inventing a
//! `--version` probe would assert on exit codes instead of presence. A
//! tool that spawns but misbehaves fails the test loudly afterwards,
//! which is the right bias.
//!
//! One test is `#[ignore]`d: `the_kernel_mounts_the_written_tree` needs
//! root and a loop device (`losetup` plus `mount -t udf` read-write over
//! the attached node), so it runs only on demand. The non-root skip keeps
//! CI green; see the test for the skip line:
//!
//! ```text
//! cargo test --offline -p rufus-core --test udf_format --no-run
//! docker run --rm -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm udftools && <test-binary> --nocapture"
//! docker run --rm --privileged -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm udftools && <test-binary> --ignored --nocapture"
//! ```
//!
//! The plain `--nocapture` run is the file-scale suite; `--ignored` is
//! the kernel-mount run, and only it needs `--privileged`.
//!
//! The PLAN "done when" clause for this slice - UDF "verified with
//! `udfinfo`" plus "`mount -t udf`" - is fully measured here, with one
//! stated split. The `udfinfo` half is the file-scale suite above. The
//! `mount -t udf` half is the `#[ignore]`d test below: it was run in the
//! privileged container during verification - `mount -t udf` defaults to
//! read-write (`type udf (rw,relatime,iocharset=utf8)`), a 128 KiB file
//! written through the mount reads back byte-exact, the mounted root
//! holds exactly the written tree, and after unmount plus a read-only
//! remount the file still reads back byte-exact with `udfinfo`
//! reporting `label=RUFUSMNT`. The Windows half of the PLAN sentence
//! stays unmeasured: this environment has no Windows target, so no test
//! boots or attaches anything there.

mod common;

use common::Mounted;
use common::attach_loop;
use common::is_root;
use common::pattern;
use common::read_at;
use common::run_tool;
use common::sparse_image;
use std::path::Path;
use std::process::Command;

use rufus_core::fs::udf::BlockSize;
use rufus_core::fs::udf::Nsr;
use rufus_core::fs::udf::Options;
use rufus_core::fs::udf::Recognition;
use rufus_core::fs::udf::format;
use rufus_core::fs::udf::recognition;
use rufus_core::log::Level;
use rufus_core::log::Logger;

/// One MiB in bytes.
const MIB: u64 = 1024 * 1024;

/// The small-image size every file-scale test formats: 32768 blocks at
/// `-b 512` and 8192 at `-b 2048`, both far above the tool's sub-258
/// warning (measured - see the module header).
const SMALL_IMAGE_BYTES: u64 = 16 * MIB;

/// A short ASCII label, far inside the 126-byte on-disk ceiling.
const SHORT_LABEL: &str = "RUFUSUDF";
/// The label the tool itself applies when `-l` is omitted (measured -
/// see the module header), the acceptance value of the unlabeled row.
const TOOL_DEFAULT_LABEL: &str = "LinuxUDF";
/// The ignored mount test's label.
const MOUNT_LABEL: &str = "RUFUSMNT";

/// Absolute byte offset of the volume recognition sequence: three
/// consecutive 2048-byte sectors, identical for `-b 512` and `2048`.
const RECOGNITION_AT: usize = 32768;
/// One past the recognition region: the first-38912-byte read below
/// carries the full three-sector sequence.
const RECOGNITION_END: usize = 38912;

// ---------------------------------------------------------------------------
// The image double: mkudffs targets a filesystem path, so the suite
// needs only a sparse file ([`common::sparse_image`]). The captured
// tool run, byte reader, loop guard and root probe live in
// tests/common/mod.rs too.
// ---------------------------------------------------------------------------

/// Format `path` (freshly created sparse, `total` bytes) with `options`
/// through the crate's own `format`, and hand back the verified
/// recognition. Every caller gates on the formatter first.
fn format_image(path: &Path, total: u64, options: &Options) -> Recognition {
    sparse_image(path, total);
    let logger = Logger::new(Level::Trace);
    format(path, options, &logger).expect("the image formats")
}

/// Presence by spawn alone: a bare run with no arguments, spawn success
/// only. This family accepts no version flag (`--version` is
/// unrecognized, `-V` is invalid, both exit 1 - measured with udftools
/// 2.3), so the gate must not invent a `--version` probe; a tool that
/// spawns but misbehaves fails the test loudly afterwards, which is the
/// right bias (the ext_format.rs convention, restated for a flagless
/// family).
fn present(program: &str) -> bool {
    Command::new(program).output().is_ok()
}

/// The skip gate for the tests that drive [`format`]: the same two-name
/// scan `udf::find_tool` performs (`mkudffs` first, then the `mkfs.udf`
/// alias), expressed with the sibling files' presence-not-verdict probe
/// convention.
fn skip_without_formatter(what: &str) -> bool {
    if ["mkudffs", "mkfs.udf"].iter().any(|name| present(name)) {
        return false;
    }
    eprintln!(
        "skip: {what} needs mkudffs or mkfs.udf, which this host does not ship \
         (install udftools and re-run)"
    );
    true
}

/// The skip gate for the tests that drive `udfinfo` directly: presence
/// via a bare spawn, never a version verdict - `udfinfo --version` is an
/// unrecognized option too (exit 1, measured with udftools 2.3).
fn skip_without_udfinfo(what: &str) -> bool {
    if present("udfinfo") {
        return false;
    }
    eprintln!(
        "skip: {what} needs udfinfo, which this host does not ship (install udftools and re-run)"
    );
    true
}

/// Our own `recognition` over the first-38912-byte read of `target`:
/// the slice 32768..38912 is the three-sector sequence the parser
/// verifies. Panics with the refusal text when the sequence is absent.
fn read_recognition_of(target: &Path) -> Recognition {
    let head = read_at(target, 0, RECOGNITION_END);
    let region = head
        .get(RECOGNITION_AT..RECOGNITION_END)
        .expect("the head reaches past the recognition region");
    recognition(region).expect("the tool-written recognition sequence parses")
}

/// One `udfinfo` field of `target`: the line shaped `field=value`,
/// verbatim after the `=`. Panics with the tool output when the tool is
/// gone (after the skip gate), exits nonzero, or prints no such line.
fn udfinfo_field(target: &Path, field: &str) -> String {
    let display = target.display().to_string();
    let Some(run) = run_tool("udfinfo", &[&display]) else {
        panic!("udfinfo vanished after the skip check");
    };
    assert!(
        run.status.success(),
        "udfinfo failed on {display}:\n{}",
        run.combined()
    );
    run.stdout
        .lines()
        .find_map(|line| {
            line.split_once('=')
                .filter(|(name, _)| *name == field)
                .map(|(_, value)| value.to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "udfinfo of {display} carries no {field:?} line:\n{}",
                run.combined()
            )
        })
}

// ---------------------------------------------------------------------------
// The acceptance tests.
// ---------------------------------------------------------------------------

/// Both block sizes end to end: each formats a 16 MiB sparse image
/// through the crate's own `format`, which must return NSR03, and the
/// independent tool must agree - `udfinfo` reports the requested label,
/// the UDF revision `2.01` and the requested block size.
#[test]
fn both_block_sizes_format_end_to_end() {
    let what = "the block-size acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    for (block, token, label) in [
        (BlockSize::Bytes512, "512", "RUFUS512"),
        (BlockSize::Bytes2048, "2048", "RUFUS2048"),
    ] {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let path = dir.path().join("udf.img");
        let options = Options::new(block)
            .with_label(label)
            .expect("the matrix label is valid");
        let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
        assert_eq!(
            verified.nsr,
            Nsr::Nsr03,
            "block {token}: format must verify NSR03"
        );
        assert_eq!(
            udfinfo_field(&path, "label"),
            label,
            "block {token}: udfinfo must report the requested label"
        );
        assert_eq!(
            udfinfo_field(&path, "udfrev"),
            "2.01",
            "block {token}: udfinfo must report the pinned revision"
        );
        assert_eq!(
            udfinfo_field(&path, "blocksize"),
            token,
            "block {token}: udfinfo must report the requested block size"
        );
        eprintln!("block {token}: NSR03, label {label}, udfrev 2.01");
    }
}

/// A short ASCII label round-trips: `format` verifies NSR03 and
/// `udfinfo` reports the label in `label=` (with `lvid=` and `vid=`
/// alongside).
#[test]
fn a_short_ascii_label_round_trips() {
    let what = "the short-label acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let options = Options::new(BlockSize::Bytes2048)
        .with_label(SHORT_LABEL)
        .expect("the short label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.nsr,
        Nsr::Nsr03,
        "format must verify NSR03 under the short label"
    );
    assert_eq!(
        udfinfo_field(&path, "label"),
        SHORT_LABEL,
        "udfinfo must report the short label"
    );
    assert_eq!(
        udfinfo_field(&path, "lvid"),
        SHORT_LABEL,
        "udfinfo must report the short label as the logical volume id"
    );
    assert_eq!(
        udfinfo_field(&path, "vid"),
        SHORT_LABEL,
        "udfinfo must report the short label as the volume id"
    );
    eprintln!("short label: every udfinfo id reports {SHORT_LABEL}");
}

/// A full 126-byte label is accepted and round-trips byte-exact through
/// `udfinfo`: the fixture is `UDF` repeated 42 times, exactly the
/// ceiling the tool enforces (127 bytes are refused with
/// `Option --label is too long`, measured - the API refuses them first,
/// so no acceptance test drives one through the tool).
#[test]
fn a_full_126_byte_label_round_trips() {
    let what = "the full-width label acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    let full = "UDF".repeat(42);
    assert_eq!(
        full.len(),
        126,
        "the fixture must fill the 126-byte ceiling exactly"
    );
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let options = Options::new(BlockSize::Bytes2048)
        .with_label(full.clone())
        .expect("126 bytes fit the label");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.nsr,
        Nsr::Nsr03,
        "format must verify NSR03 under the full label"
    );
    assert_eq!(
        udfinfo_field(&path, "label"),
        full,
        "udfinfo must return all 126 bytes"
    );
    eprintln!("full-width label: 126 bytes out, 126 bytes back");
}

/// A format without `-l` leaves the label to the tool: it applies its
/// own default, and `udfinfo` reports `label=LinuxUDF` (with
/// `lvid=LinuxUDF` and `vid=LinuxUDF` alongside) - measured, not
/// assumed, so the assert pins the real default rather than an empty
/// line.
#[test]
fn format_without_a_label_leaves_the_tool_default() {
    let what = "the no-label acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let verified = format_image(
        &path,
        SMALL_IMAGE_BYTES,
        &Options::new(BlockSize::Bytes2048),
    );
    assert_eq!(
        verified.nsr,
        Nsr::Nsr03,
        "format must verify NSR03 without a label"
    );
    assert_eq!(
        udfinfo_field(&path, "label"),
        TOOL_DEFAULT_LABEL,
        "udfinfo must report the tool default for a labelless format"
    );
    assert_eq!(
        udfinfo_field(&path, "lvid"),
        TOOL_DEFAULT_LABEL,
        "udfinfo must default the logical volume id too"
    );
    assert_eq!(
        udfinfo_field(&path, "vid"),
        TOOL_DEFAULT_LABEL,
        "udfinfo must default the volume id too"
    );
    eprintln!("no label: udfinfo reports the {TOOL_DEFAULT_LABEL} default");
}

/// The revision is really 2.01: `udfinfo` reports `udfrev=2.01` on a
/// freshly formatted image, and our own reader saw the NSR03 identifier
/// the pinned `--udfrev=0x0201` revision writes.
#[test]
fn the_pinned_revision_reads_2_01() {
    let what = "the revision acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let options = Options::new(BlockSize::Bytes2048)
        .with_label(SHORT_LABEL)
        .expect("the label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        udfinfo_field(&path, "udfrev"),
        "2.01",
        "udfinfo must report the pinned revision"
    );
    assert_eq!(
        verified.nsr,
        Nsr::Nsr03,
        "our reader must see the NSR03 the pinned revision writes"
    );
    eprintln!("revision: udfinfo 2.01, our reader NSR03");
}

/// A missing target is refused and nothing is created: `format` on an
/// absent path errors with `does not exist` before any probe or spawn
/// (needs no tool, so no skip gate - this passes on a bare host), and
/// the path still does not exist afterwards.
#[test]
fn format_refuses_a_missing_target_and_creates_nothing() {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let missing = dir.path().join("no-such.img");
    let logger = Logger::new(Level::Trace);
    let options = Options::new(BlockSize::Bytes2048);
    let error = format(&missing, &options, &logger).expect_err("a missing target must refuse");
    let text = error.to_string();
    assert!(
        text.contains("does not exist"),
        "the refusal must name the missing target: {text}"
    );
    assert!(
        text.contains("no-such.img"),
        "the refusal must name the path: {text}"
    );
    assert!(!missing.exists(), "the refused run must create nothing");
    eprintln!("missing target refused: {text}");
}

/// Our reader agrees with the tool: `udf::recognition` over bytes
/// 32768..38912 of the first-38912-byte read of a tool-formatted image
/// returns NSR03 - the same verdict `udfinfo` gives on that image.
#[test]
fn our_reader_agrees_with_the_tool() {
    let what = "the reader-agreement acceptance";
    if skip_without_formatter(what) || skip_without_udfinfo(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let options = Options::new(BlockSize::Bytes512)
        .with_label(SHORT_LABEL)
        .expect("the label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(verified.nsr, Nsr::Nsr03, "format must verify NSR03");
    assert_eq!(
        read_recognition_of(&path).nsr,
        Nsr::Nsr03,
        "the re-read through our own parser must agree"
    );
    assert_eq!(
        udfinfo_field(&path, "label"),
        SHORT_LABEL,
        "udfinfo must agree on the label of the same image"
    );
    assert_eq!(
        udfinfo_field(&path, "udfrev"),
        "2.01",
        "udfinfo must agree on the revision of the same image"
    );
    eprintln!("reader agreement: parser NSR03, udfinfo label {SHORT_LABEL} rev 2.01");
}

// ---------------------------------------------------------------------------
// The kernel-mount acceptance, mirroring the ext sibling's
// the_kernel_mounts_the_written_tree: attach the image, mount it
// read-write, write a tree through the mounted path, unmount, then
// re-verify the image with our own reader and udfinfo on a read-only
// remount.
// ---------------------------------------------------------------------------

/// The kernel acceptance for the S13 "mount" line: a crate-formatted
/// UDF volume (label `RUFUSMNT`), mounted READ-WRITE by the kernel's
/// UDF driver over a loop node (`mount -t udf` defaults to read-write,
/// measured in the privileged-container run). A tree written through
/// the mounted path must read back byte-exact, the unmounted image must
/// still parse NSR03 through our own reader, and a read-only remount
/// must read the file back byte-exact with `udfinfo` still reporting
/// the label. Needs root and a loop device; it is `#[ignore]`d - see
/// the module docs for the container command.
#[test]
#[ignore = "needs root and a loop device: run inside the container; see the module docs"]
fn the_kernel_mounts_the_written_tree() {
    let what = "the kernel-mount acceptance";
    if !is_root() {
        eprintln!(
            "skip: {what} needs root for losetup; run inside the privileged container, see the module docs"
        );
        return;
    }
    // Root implies the tools for an --ignored container run (the image
    // installs udftools); no skip gates here, by the ext sibling's
    // convention - a missing tool fails loudly instead.
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("udf.img");
    let options = Options::new(BlockSize::Bytes2048)
        .with_label(MOUNT_LABEL)
        .expect("the mount label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.nsr,
        Nsr::Nsr03,
        "the crate must verify NSR03 before the kernel sees the image"
    );
    eprintln!("stage: volume formatted with label {MOUNT_LABEL}");

    let device = attach_loop(&path, what);
    eprintln!("stage: attached {device}");

    let mountpoint = dir.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("the mountpoint");
    // The guard is alive before the first mount assertion, so the
    // attach detaches on every exit path after it.
    let guard = Mounted {
        device: device.clone(),
        mountpoint: mountpoint.clone(),
    };
    let mounted = Command::new("mount")
        .args(["-t", "udf"])
        .arg(&device)
        .arg(&mountpoint)
        .output()
        .expect("mount runs");
    assert!(
        mounted.status.success(),
        "mounting {device} failed: {}",
        String::from_utf8_lossy(&mounted.stderr)
    );
    eprintln!("stage: mounted read-write with udf (kernel)");

    std::fs::create_dir(mountpoint.join("a")).expect("mkdir a through the mount");
    std::fs::create_dir(mountpoint.join("a/b")).expect("mkdir a/b through the mount");
    let payload = pattern(128 * 1024);
    let file = mountpoint.join("a/b/file.bin");
    std::fs::write(&file, &payload).expect("write the payload through the mount");
    let read_back = std::fs::read(&file).expect("read the payload back through the mount");
    assert_eq!(read_back, payload, "the mount must round-trip the bytes");
    let mut root_entries: Vec<String> = std::fs::read_dir(&mountpoint)
        .expect("the mounted root lists")
        .map(|entry| {
            entry
                .expect("a root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    // `read_dir` order is unspecified, so sort before the exact comparison.
    root_entries.sort();
    assert_eq!(
        root_entries,
        ["a"],
        "the mounted root must hold exactly the written tree"
    );
    let leaf_entries: Vec<String> = std::fs::read_dir(mountpoint.join("a/b"))
        .expect("a/b lists through the mount")
        .map(|entry| {
            entry
                .expect("a leaf entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        leaf_entries,
        ["file.bin"],
        "a/b must hold exactly the payload file"
    );
    eprintln!("stage: tree written and read back through the mount");
    drop(guard);
    eprintln!("stage: unmounted and detached");

    // Our own reader must still parse the post-session image bytes (no
    // reuse of the pre-mount struct).
    assert_eq!(
        read_recognition_of(&path).nsr,
        Nsr::Nsr03,
        "the recognition sequence must survive the kernel's read-write session"
    );
    eprintln!("stage: NSR03 survived the kernel writes");

    // Read-only remount: the file reads back byte-exact and the label
    // survived the kernel's writes.
    let device = attach_loop(&path, what);
    eprintln!("stage: re-attached {device}");
    let guard = Mounted {
        device: device.clone(),
        mountpoint: mountpoint.clone(),
    };
    let mounted = Command::new("mount")
        .args(["-t", "udf", "-o", "ro"])
        .arg(&device)
        .arg(&mountpoint)
        .output()
        .expect("mount runs");
    assert!(
        mounted.status.success(),
        "remounting {device} read-only failed: {}",
        String::from_utf8_lossy(&mounted.stderr)
    );
    let reread = std::fs::read(mountpoint.join("a/b/file.bin"))
        .expect("read the payload back through the read-only mount");
    assert_eq!(
        reread, payload,
        "the read-only remount must return the same bytes"
    );
    assert_eq!(
        udfinfo_field(&path, "label"),
        MOUNT_LABEL,
        "udfinfo must read the label after the kernel's writes"
    );
    drop(guard);
    eprintln!("stage: read-only remount read back byte-exact, label survived");
}
