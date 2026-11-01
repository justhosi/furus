//! External-tool acceptance for the S11 NTFS integration (rust-rewrite/
//! PLAN.md lines 661-679: NTFS volumes that Windows and the UEFI:NTFS
//! driver accept, built by the external `mkntfs`/`mkfs.ntfs` formatter).
//! The S11 "Tests" line names `ntfsfix -n`, mount, label, and cluster
//! sizes 512-64 KiB; this suite runs each of those against the real
//! tools and asserts only what the runs measured.
//!
//! The Windows-installer half of the S11 done-when ("a 32 GB NTFS
//! partition mounts and the Windows installer sees it") is NOT covered
//! here: it needs a real 32 GB device and a Windows installer boot - a
//! QEMU/VM or real-hardware run, real-device scale - which this
//! environment cannot measure. It stays an open acceptance item and
//! nothing in this file fakes it. The VBR-fix post-format hook is PLAN
//! lines 948-949, deferred to S21 - no hook code exists and this file
//! exercises none.
//!
//! Skip convention (the one tests/exfat_format.rs and
//! tests/fat32_format.rs carry): the host has NO ntfs tools (mkntfs,
//! mkfs.ntfs, ntfsfix, ntfslabel are all absent on this machine), so
//! every test that needs a real tool probes it first and prints an
//! explicit `skip:` line when it is missing - a skip is a documented
//! limitation, never a silent pass. Tools that ARE present get their
//! real output asserted, and a failing tool fails the test with its
//! real output in the message.
//!
//! Privileged-container runs (root + loop device are what mount needs).
//! Build the binary first; `<test-binary>` is the
//! `target/debug/deps/ntfs_format-<id>` path the `--no-run` build
//! prints. Measured package split on this run's archlinux image
//! (2026.9.28): `pacman -Sy ntfs-3g` installs ONLY the FUSE driver -
//! mkntfs, mkfs.ntfs, ntfsfix and ntfslabel live in a separate
//! `ntfsprogs` package - so the container command installs both:
//!
//! ```text
//! cargo test --offline -p rufus-core --test ntfs_format --no-run
//! docker run --rm --privileged -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm ntfs-3g ntfsprogs && <test-binary> --ignored --nocapture"
//! docker run --rm --privileged -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm ntfs-3g ntfsprogs && <test-binary> --nocapture"
//! ```
//!
//! Plain `--ignored` is the device-scale run: it attaches one 64 MiB
//! sparse file over a loop device and mounts it. The `--nocapture` run
//! is the plain file-scale run for the rest of the suite.
//!
//! Measured in the container runs of this file (each bullet names what
//! the run actually did):
//! - mkntfs v2026.9.28 REFUSES a plain file target without `-F`
//!   ("... is not a block device." + "Refusing to make a filesystem
//!   here!", exit 1); with `-F` it formats the file (warning that
//!   Windows cannot boot from it) and prints `mkntfs completed
//!   successfully. Have a nice day.` - so the crate's label-verified
//!   format() wrapper, which passes only `-f [-L] -c`, cannot complete
//!   on a file target; two tests below pin that measured refusal.
//! - mkntfs accepts a loop node with or without `-F`, and the VBR it
//!   writes carries 512-byte sectors with the requested cluster size
//!   (00 02 01 00 for -c 512, 00 02 08 00 for -c 4096, 00 02 80 00 for
//!   -c 65536, 00 10 10 00 for --sector-size 4096 + -c 65536). The
//!   label-read stage bounds-checks record 3 against the length the
//!   volume's own VBR declares (total sectors times bytes per
//!   sector), NOT the target's stat size (this run's loop node
//!   statted as 0 bytes), so the wrapper completes through the loop
//!   node - the test below pins the measured end-to-end label read
//!   (this run's volume: 67108352 declared bytes).
//! - `ntfsfix -n` on a freshly formatted volume: exit 0 + the lines
//!   "Mounting volume... OK" / "Processing of $MFT and $MFTMirr
//!   completed successfully." / "Checking the alternate boot sector...
//!   OK" / "NTFS volume version is 3.1." / "NTFS partition <target>
//!   was processed successfully."
//! - `ntfslabel` of a labelled volume prints the label (UTF-8 bytes,
//!   also under LC_ALL=C) and exits 0; of a label-less volume it
//!   prints ONE empty line and also exits 0.
//! - The kernel's ntfs3 driver (module on this host's 7.2.8 kernel)
//!   mounts an mkntfs volume read-write inside the privileged
//!   container, holds dirs/files written through the mount, unmounts
//!   clean, and the volume stays ntfsfix-clean with its label intact.
//! - The final binary runs of this file measured, test by test: all
//!   seven ladder steps format and read the label back at 512-byte
//!   sectors - this run handed the same real non-zero serial to all
//!   seven volumes (the serial source is mkntfs's, and no cause is
//!   claimed here); the raw record-3 walk
//!   found the first resident $VOLUME_NAME at record offset 360 with
//!   its value offset 0x18; the no-label read-back printed nothing
//!   but one empty stdout line (od-measured in this run's container)
//!   and the empty shape is pinned by a test below (at most one empty
//!   line in either stream, never a word); the Persian label agreed
//!   on both sides; the 4Kn refusal then the 4Kn volume verified; the
//!   file-target wrapper refusal measured exactly as documented
//!   above, and the loop-node wrapper completed with the label
//!   verified through the node; and the `#[ignore]`d mount run walked
//!   through every stage line (formatted, attached /dev/loop0,
//!   mounted read-write with ntfs3, tree written and read back,
//!   unmounted and detached, ntfsfix clean, label survived).

mod common;

use common::Mounted;
use common::ToolRun;
use common::attach_loop;
use common::is_root;
use common::pattern;
use common::read_at;
use common::run_tool;
use common::sparse_image;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use rufus_core::fs::ntfs::Boot;
use rufus_core::fs::ntfs::Options;
use rufus_core::fs::ntfs::boot_sector;
use rufus_core::fs::ntfs::format;
use rufus_core::fs::ntfs::volume_label;
use rufus_core::log::Level;
use rufus_core::log::Logger;

/// One MiB in bytes.
const MIB: u64 = 1024 * 1024;

/// The cluster ladder PLAN S11 names: 512 bytes to 64 KiB.
const CLUSTER_LADDER: [u32; 7] = [512, 1024, 4096, 8192, 16384, 32768, 65536];

/// The cluster size of the one-volume tests (64 MiB images).
const SMALL_IMAGE_CLUSTERS: u32 = 4096;

/// The Persian label of the non-ASCII acceptance, spelled with escapes
/// so this file stays ASCII: six units, the Persian name usually
/// transliterated as parvande.
const PERSIAN_LABEL: &str = "\u{67E}\u{631}\u{648}\u{646}\u{62F}\u{647}";

/// `$VOLUME_NAME`'s on-disk type code, restated here for the raw walk
/// (the crate's own constants are module-private).
const VOLUME_NAME_TYPE: u32 = 0x0000_0060;

/// The end-of-attributes marker type code, restated for the raw walk.
const END_MARKER_TYPE: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// The image double: mkntfs targets a filesystem path, so the suite needs
// only a sparse file ([`common::sparse_image`]) - no `Volume`
// implementation at all. The captured tool run, byte reader, loop
// guard and root probe live in tests/common/mod.rs too.
// ---------------------------------------------------------------------------

/// The sparse image path under a scratch directory.
fn image_path(dir: &Path) -> PathBuf {
    dir.join("ntfs.img")
}

/// The skip gate for tools the suite drives directly (`ntfsfix`,
/// `ntfslabel`, `mkntfs`): presence via `spawn --version`, not a
/// version verdict - a status check would tie the gate to one build's
/// exit codes, and a tool that spawns but misbehaves fails the test
/// loudly afterwards, which is the right bias (the exfat_format.rs
/// convention, restated).
fn skip_without_tool(program: &str, what: &str) -> bool {
    if Command::new(program).arg("--version").output().is_ok() {
        return false;
    }
    eprintln!(
        "skip: {what} needs {program}, which this host does not ship \
         (install ntfsprogs, or ntfs-3g on Debian/Ubuntu, and re-run)"
    );
    true
}

/// The skip gate for the tests that drive [`format`]: the same
/// two-name scan `ntfs::find_tool` performs (`mkntfs` first, then the
/// `mkfs.ntfs` alias), expressed with the sibling files' `--version`
/// probe convention (presence, not a version verdict).
fn skip_without_formatter(what: &str) -> bool {
    let present = ["mkntfs", "mkfs.ntfs"]
        .iter()
        .any(|program| Command::new(program).arg("--version").output().is_ok());
    if present {
        return false;
    }
    eprintln!(
        "skip: {what} needs mkntfs or mkfs.ntfs, which this host does not ship \
         (install ntfsprogs, or ntfs-3g on Debian/Ubuntu, and re-run)"
    );
    true
}

/// Run the real `mkntfs` directly with `-F` - the spelling this run
/// measured as the FILE-capable one (mkntfs without `-F` refuses
/// non-block targets) - plus the crate's own option order, `[-L label]
/// -c cluster [--sector-size N] <path>`. `None` when mkntfs is absent
/// (every caller gates on it first).
fn mkntfs_forced(
    path: &Path,
    label: Option<&str>,
    cluster: u32,
    sector_size: Option<u32>,
) -> Option<ToolRun> {
    let mut args: Vec<String> = vec!["-F".to_owned(), "-f".to_owned()];
    if let Some(label) = label {
        args.push("-L".to_owned());
        args.push(label.to_owned());
    }
    args.push("-c".to_owned());
    args.push(cluster.to_string());
    if let Some(sector_size) = sector_size {
        args.push("--sector-size".to_owned());
        args.push(sector_size.to_string());
    }
    args.push(path.display().to_string());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_tool("mkntfs", &borrowed)
}

/// The crate's boot_sector over the real VBR bytes of `target`: the
/// Boot facts every volume test re-asserts.
fn boot_of(target: &Path) -> Boot {
    let mut vbr = [0u8; 512];
    vbr.copy_from_slice(&read_at(target, 0, 512));
    boot_sector(&vbr).expect("the real mkntfs-written VBR parses")
}

/// Damage phrases for the `ntfsfix -n` guard below, pinned from the
/// container run (see the module header): the freshly formatted
/// volumes of that run printed none of them, and the refusal text for
/// an absent volume printed every one of them (exit 1 both times the
/// guard exercised the damaged shape).
const NTFSFIX_DAMAGE_PHRASES: [&str; 5] =
    ["corrupt", "invalid", "failed", "signature", "unrecoverable"];

/// `ntfsfix -n` must call `target` clean: the S11 "Tests" line's check.
/// Like the exFAT sibling's fsck guard, exit status AND the damage
/// phrase scan both apply - a checker that exits 0 while reporting
/// damage must not pass. `-n` repairs nothing either way; a checker
/// crash or a missing binary after the gate is a loud failure too.
fn assert_ntfsfix_clean(target: &Path, what: &str) {
    let display = target.display().to_string();
    let Some(run) = run_tool("ntfsfix", &["-n", &display]) else {
        panic!("ntfsfix vanished after the skip check ({what})");
    };
    let text = run.combined();
    let lower = text.to_lowercase();
    let mut problems: Vec<String> = Vec::new();
    if !run.status.success() {
        problems.push(format!("ntfsfix exited {}", run.status));
    }
    for phrase in NTFSFIX_DAMAGE_PHRASES {
        if lower.contains(phrase) {
            problems.push(format!("ntfsfix reported {phrase:?}"));
        }
    }
    assert!(
        problems.is_empty(),
        "{what}: ntfsfix must find nothing in {display}:\n{text}\n--- problems: {}",
        problems.join("; ")
    );
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        eprintln!("ntfsfix: {line}");
    }
}

/// The byte offset of `$MFT` record 3 of the volume `boot` describes:
/// `$MFT` start cluster times cluster bytes, plus three records.
fn record_three_offset(boot: &Boot) -> u64 {
    boot.mft_start_cluster * u64::from(boot.cluster_bytes) + 3 * u64::from(boot.mft_record_bytes)
}

/// A `u16` LE field at `at` of a raw on-disk window (the walk reads the
/// same fields the crate's record-3 reader reads, straight from the
/// image bytes).
fn u16_le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// A `u32` LE field at `at` of a raw on-disk window.
fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

// ---------------------------------------------------------------------------
// The acceptance tests.
// ---------------------------------------------------------------------------

/// The PLAN "cluster sizes 512-64 KiB" line as one measured sweep:
/// every ladder step is formatted by the real mkntfs directly (`-F`,
/// the file-capable spelling this run measured) with the label
/// `RUFUS NTFS`, the crate's readers verify the result, and
/// `ntfsfix -n` must call the volume clean afterwards. 128 MiB keeps
/// even the 64 KiB tier at a couple thousand clusters. The crate's own
/// format() wrapper (which cannot use `-F`) is measured separately
/// below - on a file target it is the mkntfs device refusal, not the
/// wrapper's own shape.
#[test]
fn cluster_sweep_formats_and_reads_back_the_label() {
    let what = "the cluster sweep acceptance";
    if skip_without_tool("mkntfs", what) || skip_without_tool("ntfsfix", what) {
        return;
    }
    for cluster in CLUSTER_LADDER {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let path = image_path(dir.path());
        sparse_image(&path, 128 * MIB);
        let run = mkntfs_forced(&path, Some("RUFUS NTFS"), cluster, None)
            .expect("mkntfs runs after the skip gate");
        assert!(
            run.status.success(),
            "mkntfs refused {cluster} byte clusters:\n{}",
            run.combined()
        );
        let boot = boot_of(&path);
        assert_eq!(
            boot.cluster_bytes, cluster,
            "the {cluster} byte cluster request must be honored"
        );
        assert!(
            matches!(boot.bytes_per_sector, 512 | 4096),
            "bytes per sector {} is off the house ladder",
            boot.bytes_per_sector
        );
        assert_ne!(boot.volume_serial, 0, "the serial must be a real u64");
        assert_eq!(
            volume_label(&path, &boot)
                .expect("record 3 must read from the real volume")
                .as_deref(),
            Some("RUFUS NTFS"),
            "the label must read back from record 3 at {cluster} byte clusters"
        );
        assert_ntfsfix_clean(&path, what);
        eprintln!(
            "cluster {cluster}: bps {}, serial 0x{:016X}",
            boot.bytes_per_sector, boot.volume_serial
        );
    }
}

/// Two independent label readers agree: the crate's record-3 walk and
/// the installed `ntfslabel` both report the formatted label. The raw
/// record-3 bytes of this run's real mkntfs volume also pin the
/// on-disk layout the reader walks - the first resident `$VOLUME_NAME`
/// attribute's value offset sits at attribute byte 0x18, measured from
/// the image bytes (the crate's unit tests only ever walk synthetic
/// records).
#[test]
fn ntfslabel_agrees_with_the_read_label() {
    let what = "the label acceptance";
    if skip_without_tool("mkntfs", what) || skip_without_tool("ntfslabel", what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let run = mkntfs_forced(&path, Some("RUFUS NTFS"), SMALL_IMAGE_CLUSTERS, None)
        .expect("mkntfs runs after the skip gate");
    assert!(run.status.success(), "mkntfs failed:\n{}", run.combined());
    let boot = boot_of(&path);
    assert_eq!(
        volume_label(&path, &boot)
            .expect("record 3 must read from the real volume")
            .as_deref(),
        Some("RUFUS NTFS"),
        "the crate must read the formatted label"
    );

    let read = run_tool("ntfslabel", &[&path.display().to_string()])
        .expect("ntfslabel runs after the skip gate");
    assert!(
        read.status.success(),
        "ntfslabel failed:\n{}",
        read.combined()
    );
    assert_eq!(
        read.combined().trim(),
        "RUFUS NTFS",
        "ntfslabel must read the same label:\n{}",
        read.combined()
    );
    eprintln!("ntfslabel read back: {}", read.combined().trim());

    // The raw window: `$MFT` record 3 of the real volume, straight from
    // the image bytes, walked the way the crate walks but on untouched
    // bytes (no fixup handling here - this run's mkntfs volume keeps
    // its attributes inside the first 512 byte block).
    let record = read_at(
        &path,
        record_three_offset(&boot),
        boot.mft_record_bytes as usize,
    );
    let record_len = record.len();
    let mut at = u16_le(&record, 20) as usize;
    let attr_at = loop {
        assert!(
            at + 8 <= record_len,
            "the raw walk ran off the {record_len} byte $MFT record at {at}"
        );
        let attribute = u32_le(&record, at);
        if attribute == VOLUME_NAME_TYPE {
            break at;
        }
        assert_ne!(
            attribute, END_MARKER_TYPE,
            "the raw walk hit the end marker at {at} before any $VOLUME_NAME"
        );
        let length = u32_le(&record, at + 4);
        assert_ne!(length, 0, "a zero-length attribute at {at} stops the walk");
        at = at
            .checked_add(length as usize)
            .expect("the attribute length fits a usize");
    };
    assert_eq!(
        record[attr_at + 8],
        0,
        "the first $VOLUME_NAME at record offset {attr_at} must be resident"
    );
    assert_eq!(
        u16_le(&record, attr_at + 20),
        0x18,
        "the unnamed resident value offset must sit at 0x18 (record offset {attr_at})"
    );
    eprintln!("raw record 3: resident $VOLUME_NAME at offset {attr_at}, value offset 0x18");
}

/// A format without `-L` leaves the volume nameless - measured by two
/// readers: the crate reads no `$VOLUME_NAME` from record 3, and
/// ntfslabel's read-back of the same image prints ONE empty line and
/// exits 0 (both pinned from the run in the module header).
#[test]
fn mkntfs_without_a_label_leaves_none() {
    let what = "the no-label acceptance";
    if skip_without_tool("mkntfs", what) || skip_without_tool("ntfslabel", what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let run = mkntfs_forced(&path, None, SMALL_IMAGE_CLUSTERS, None)
        .expect("mkntfs runs after the skip gate");
    assert!(run.status.success(), "mkntfs failed:\n{}", run.combined());
    let boot = boot_of(&path);
    assert_eq!(
        volume_label(&path, &boot).expect("record 3 must read from the real volume"),
        None,
        "the nameless format must read back nameless"
    );

    let read = run_tool("ntfslabel", &[&path.display().to_string()])
        .expect("ntfslabel runs after the skip gate");
    assert!(
        read.status.success(),
        "ntfslabel failed on a label-less volume:\n{}",
        read.combined()
    );
    // The exact empty shape this run measures: the combined output is
    // empty in words — `trim()` is empty and every line blank. The
    // harness join adds one `"\n"` of its own and ntfslabel prints at
    // most one of its own (measured: a single empty stdout line), so
    // at most two entries in `combined().lines()`, every one blank.
    assert!(
        read.combined().lines().count() <= 2 && read.combined().lines().all(str::is_empty),
        "ntfslabel must print nothing but one empty line for a label-less volume:\n{:?}",
        read.combined()
    );
}

/// A non-ASCII label through the tool path: mkntfs `-L` accepts a
/// Persian name under the C locale (measured: the run exits 0) and
/// both readers agree - the crate decodes the record-3 UTF-16LE value
/// and `ntfslabel` prints the label's UTF-8 bytes back unchanged.
#[test]
fn a_non_ascii_label_round_trips() {
    let what = "the non-ASCII label acceptance";
    if skip_without_tool("mkntfs", what) || skip_without_tool("ntfslabel", what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let run = mkntfs_forced(&path, Some(PERSIAN_LABEL), SMALL_IMAGE_CLUSTERS, None)
        .expect("mkntfs runs after the skip gate");
    assert!(
        run.status.success(),
        "mkntfs refused the non-ASCII label:\n{}",
        run.combined()
    );
    let boot = boot_of(&path);
    assert_eq!(
        volume_label(&path, &boot)
            .expect("record 3 must read from the real volume")
            .as_deref(),
        Some(PERSIAN_LABEL),
        "the crate must decode the non-ASCII label from record 3"
    );

    let read = run_tool("ntfslabel", &[&path.display().to_string()])
        .expect("ntfslabel runs after the skip gate");
    assert!(
        read.status.success(),
        "ntfslabel failed:\n{}",
        read.combined()
    );
    assert_eq!(
        read.combined().trim(),
        PERSIAN_LABEL,
        "ntfslabel must read the non-ASCII label back:\n{}",
        read.combined()
    );
    eprintln!("ntfslabel read back the Persian label unchanged");
}

/// The 4Kn probe, both halves measured in the container run. The
/// raw-argument attempt the acceptance brief asks for (mkntfs with
/// `--sector-size 4096` on a plain file, NO -F) hits the device
/// refusal every file target gets; the `-F` spelling formats the
/// 4Kn volume, and the crate's readers plus `ntfsfix -n` must accept
/// what mkntfs produced (measured VBR: 00 10 10 00 - 4096 byte
/// sectors, 65536 byte clusters).
#[test]
fn a_4kn_volume_stays_readable() {
    let what = "the 4Kn acceptance";
    if skip_without_tool("mkntfs", what) || skip_without_tool("ntfsfix", what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let display = path.display().to_string();

    // The brief's raw argument order, without -F: the measured refusal
    // of ANY file target, 4Kn included.
    let refused = run_tool(
        "mkntfs",
        &[
            "-f",
            "--sector-size",
            "4096",
            "-L",
            "RUFUS4K",
            "-c",
            "65536",
            &display,
        ],
    )
    .expect("mkntfs runs after the skip gate");
    assert!(
        !refused.status.success(),
        "mkntfs must keep refusing a plain file target:\n{}",
        refused.combined()
    );
    assert!(
        refused
            .combined()
            .contains("Refusing to make a filesystem here!"),
        "the refusal must be mkntfs's device refusal:\n{}",
        refused.combined()
    );
    eprintln!("4Kn without -F: mkntfs refused the file target, as measured");

    // With -F the 4Kn volume formats, and every reader accepts it.
    let run = mkntfs_forced(&path, Some("RUFUS4K"), 65536, Some(4096))
        .expect("mkntfs runs after the skip gate");
    assert!(
        run.status.success(),
        "mkntfs -F refused the 4Kn request:\n{}",
        run.combined()
    );
    let boot = boot_of(&path);
    assert_eq!(
        boot.bytes_per_sector, 4096,
        "the 4Kn request must land on 4096 byte sectors"
    );
    assert_eq!(
        boot.cluster_bytes, 65536,
        "the 4Kn request must keep the -c 65536 clusters"
    );
    assert_eq!(
        volume_label(&path, &boot)
            .expect("record 3 must read from the real volume")
            .as_deref(),
        Some("RUFUS4K"),
        "the 4Kn volume must carry its label"
    );
    assert_ntfsfix_clean(&path, what);
    eprintln!("4Kn volume verified: bps 4096, clusters 65536");
}

// ---------------------------------------------------------------------------
// The crate's format() wrapper itself, measured against the two target
// shapes this environment can produce: the wrapper's argument set
// cannot satisfy mkntfs on a plain file (the measured device refusal),
// and on a loop node - which mkntfs happily formats and which this
// kernel gives st_size 0 - the wrapper completes, because the label
// read checks the length the volume's own VBR declares, not the node's
// stat size.
// ---------------------------------------------------------------------------

/// A loop-detach guard: hand out the node, detach it on every exit
/// path (the formatting below happens directly on the node - no mount).
struct Detached {
    device: String,
}

impl Drop for Detached {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.device]).status();
    }
}

/// The measured refusal on the crate's file-target path: mkntfs
/// (v2026.9.28, driven by the crate's own spawn: bounded capture, C
/// locale, `-f [-L] -c` order) rejects a non-block target, so
/// `format()` surfaces the failing run exactly as the unit tests pin
/// the shape - a refusal naming the tool and the status, with the
/// tool's own lines logged. The wrapper's only wrong move is the
/// missing `-F`; every line it logged is mkntfs's.
#[test]
fn format_refuses_a_file_target_the_way_mkntfs_does() {
    let what = "the file-target refusal acceptance";
    if skip_without_formatter(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let logger = Logger::new(Level::Trace);
    let options = Options::new(Some("RUFUS NTFS".to_string()));
    let error = format(&path, &options, &logger)
        .expect_err("measured: mkntfs refuses a plain file target, so the wrapper must refuse");
    let text = error.to_string();
    assert!(
        text.contains(" failed") && text.contains("exit status: 1"),
        "the refusal must name whichever formatter ran (mkntfs or the mkfs.ntfs alias) \
         and its status:\n{text}"
    );
    // The tool's own refusal lines were logged verbatim (both streams),
    // and the refusal message names the status (mkntfs exits 1 here).
    let messages: Vec<String> = logger
        .snapshot()
        .iter()
        .map(|record| record.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("is not a block device.")),
        "mkntfs's device refusal must reach the log:\n{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Refusing to make a filesystem here!")),
        "mkntfs's scrub line must reach the log:\n{messages:?}"
    );
    eprintln!("format() on a file: refused exactly as mkntfs does");
}

/// The measured loop-target path: mkntfs accepts the loop node (exit
/// 0) and the wrapper completes — VBR verification and the label read
/// both run through the node, because `volume_label` bounds-checks
/// record 3 against the length the volume's own VBR declares (total
/// sectors times bytes per sector), not against the node's stat size
/// (which this kernel reports as 0 for loop nodes). ntfslabel through
/// the same node reads the same label, and the volume stays
/// ntfsfix-clean. Needs root for the losetup step — non-root runs skip;
/// see the module docs for the privileged-container command.
#[test]
fn format_on_a_loop_target_verifies_the_label_read() {
    let what = "the loop-target label-read acceptance";
    if !is_root() {
        eprintln!(
            "skip: {what} needs root for losetup; run inside the privileged container, see the module docs"
        );
        return;
    }
    if skip_without_formatter(what)
        || skip_without_tool("ntfsfix", what)
        || skip_without_tool("ntfslabel", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let device = attach_loop(&path, what);
    let loop_path = PathBuf::from(device.clone());
    let guard = Detached { device };
    let logger = Logger::new(Level::Trace);
    let options = Options::new(Some("RUFUS NTFS".to_string()));
    let volume = format(&loop_path, &options, &logger)
        .expect("measured: the wrapper completes label-verified on a loop node");
    assert_eq!(
        volume.label.as_deref(),
        Some("RUFUS NTFS"),
        "the wrapper must read the label it asked for, through the node: {volume:?}"
    );
    assert_eq!(
        volume.boot.cluster_bytes, SMALL_IMAGE_CLUSTERS,
        "the loop node's VBR must carry the requested cluster size"
    );
    assert_ne!(
        volume.boot.volume_serial, 0,
        "the serial must be a real u64"
    );
    // The run is a real success: the wrapper logged the label-verified
    // line and the tool summary (its own shape, not a tool claim) and
    // never the old `could not be verified` failure line.
    let messages: Vec<String> = logger
        .snapshot()
        .iter()
        .map(|record| record.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("verified NTFS volume label `RUFUS NTFS`")),
        "the wrapper must log the verified label:\n{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("verified NTFS volume with")),
        "the wrapper must log the final summary:\n{messages:?}"
    );
    assert!(
        messages
            .iter()
            .all(|message| !message.contains("could not be verified")),
        "no refusal stage may appear in the log:\n{messages:?}"
    );
    // The run formatted the volume: the loop node is ntfsfix-clean.
    assert_ntfsfix_clean(&loop_path, what);
    // Two independent readers agree through the loop node: the crate's
    // walk above and the installed ntfslabel.
    let read = run_tool("ntfslabel", &[&loop_path.display().to_string()])
        .expect("ntfslabel runs after the skip gate");
    assert!(
        read.status.success() && read.combined().trim() == "RUFUS NTFS",
        "ntfslabel must read the label through the loop node:\n{}",
        read.combined()
    );
    eprintln!(
        "format() on a loop node: completed, {} bytes of VBR-declared volume, label verified",
        volume.boot.volume_bytes
    );
    drop(guard);
}

// ---------------------------------------------------------------------------
// The kernel-mount acceptance, mirroring the FAT32 and exFAT siblings'
// the_kernel_mounts_the_written_tree: attach the image, mount it
// read-write (kernel ntfs3 first, the ntfs-3g FUSE helper as fallback),
// write a tree through the mounted path, unmount, then re-verify the
// image with the crate readers and ntfsfix.
// ---------------------------------------------------------------------------

/// Mount with filesystem type `kind` and capture the run.
fn mount_attempt(
    kind: &str,
    device: &str,
    mountpoint: &Path,
) -> std::io::Result<std::process::Output> {
    Command::new("mount")
        .args(["-t", kind])
        .arg(device)
        .arg(mountpoint)
        .output()
}

/// The kernel acceptance for the S11 "mounts" line: an mkntfs volume
/// (formatted with `-F`, the file-capable spelling this run measured -
/// the crate's own format() wrapper, which cannot pass `-F`, is pinned
/// to its measured refusals in the two tests above), mounted
/// READ-WRITE by the kernel's ntfs3 driver, falling back to the
/// ntfs-3g FUSE helper when the kernel offers no ntfs3. A tree written
/// through the mounted path must read back byte-exact, the unmounted
/// volume must stay ntfsfix-clean, and the record-3 label must survive
/// the kernel's writes. Needs root and a loop device; it is
/// `#[ignore]`d - see the module docs for the container command.
#[test]
#[ignore = "needs root and a loop device: run inside the container; see the module docs"]
fn the_kernel_mounts_the_written_tree() {
    if !is_root() {
        eprintln!("skip: mounting needs root; run the documented container command");
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = image_path(dir.path());
    sparse_image(&path, 64 * MIB);
    let run = mkntfs_forced(&path, Some("RUFUSMNT"), SMALL_IMAGE_CLUSTERS, None)
        .expect("mkntfs runs (root implies the tools for an --ignored container run)");
    assert!(run.status.success(), "mkntfs failed:\n{}", run.combined());
    let boot = boot_of(&path);
    assert_eq!(
        volume_label(&path, &boot)
            .expect("record 3 must read from the real volume")
            .as_deref(),
        Some("RUFUSMNT"),
        "the crate must read its own label before the kernel sees the image"
    );
    eprintln!("stage: volume formatted with label RUFUSMNT");

    let device = attach_loop(&path, "the mount acceptance");
    eprintln!("stage: attached {device}");

    let mountpoint = dir.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("the mountpoint");
    // The detach guard lives from before the first mount attempt: any
    // panic below unmounts and detaches on the way out.
    let guard = Mounted {
        device,
        mountpoint: mountpoint.clone(),
    };

    // Kernel driver first, FUSE fallback second: one of the two must
    // mount the volume read-write, and a double refusal fails the test
    // with both outputs.
    // Both match arms above bind only successful runs, so no second
    // status assert exists here: a reach past the match is by
    // construction a successful mount.
    match mount_attempt("ntfs3", &guard.device, &mountpoint) {
        Ok(run) if run.status.success() => {
            eprintln!("stage: mounted read-write with ntfs3 (kernel)");
            run
        }
        Ok(run) => match mount_attempt("ntfs-3g", &guard.device, &mountpoint) {
            Ok(fuse) if fuse.status.success() => {
                eprintln!(
                    "stage: ntfs3 refused ({}), mounted with ntfs-3g (FUSE) instead",
                    String::from_utf8_lossy(&run.stderr).trim()
                );
                fuse
            }
            Ok(fuse) => panic!(
                "mounting {} failed: ntfs3 refused ({}) and ntfs-3g refused ({})",
                guard.device,
                String::from_utf8_lossy(&run.stderr).trim(),
                String::from_utf8_lossy(&fuse.stderr).trim()
            ),
            Err(err) => panic!("the ntfs-3g mount could not be spawned: {err}"),
        },
        Err(err) => panic!("the ntfs3 mount could not be spawned: {err}"),
    };

    std::fs::create_dir(mountpoint.join("a")).expect("mkdir a through the mount");
    std::fs::create_dir(mountpoint.join("a/b")).expect("mkdir a/b through the mount");
    let payload = pattern(128 * 1024);
    let file = mountpoint.join("a/b/file.bin");
    std::fs::write(&file, &payload).expect("write the payload through the mount");
    let read_back = std::fs::read(&file).expect("read the payload back through the mount");
    assert_eq!(read_back, payload, "the mount must round-trip the bytes");
    let root_entries: Vec<String> = std::fs::read_dir(&mountpoint)
        .expect("the mounted root lists")
        .map(|entry| {
            entry
                .expect("a root entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        root_entries,
        ["a"],
        "the mounted root must hold exactly the tree this test wrote"
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

    assert_ntfsfix_clean(&path, "the mounted volume");

    // The label must survive the kernel's writes: re-derive the Boot
    // from the post-session VBR bytes (no reuse of the pre-mount
    // struct) and re-read the record-3 label.
    let mut vbr = [0u8; 512];
    vbr.copy_from_slice(&read_at(&path, 0, 512));
    let boot = boot_sector(&vbr).expect("the post-mount VBR must still parse");
    let label = volume_label(&path, &boot).expect("record 3 must read after the kernel writes");
    assert_eq!(
        label.as_deref(),
        Some("RUFUSMNT"),
        "the label must survive the kernel's read-write session"
    );
    eprintln!("stage: label survived the kernel writes");
}
