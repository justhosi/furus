//! External-tool acceptance for the S12 ext2/3/4 formatter (PLAN lines
//! 681-703: ext volumes matching Rufus's options, built by the external
//! `mke2fs` formatter, verified with `e2fsck -f -n`, persistence through
//! `debugfs`).
//!
//! Every test drives the crate's real path - a sparse image file
//! (`File::set_len`, never a `Vec`) formatted by `ext::format` - and the
//! tool path wherever a tool is needed: the crate shells out to
//! `mke2fs -q -F -t <flavour> [-L label] -b 4096 -I 256
//! [-O ^has_journal for ext2 only] -E lazy_itable_init=0[,lazy_journal_init=0]`;
//! then the raw image goes to somebody else's reader, with only what those tools
//! report is asserted: `dumpe2fs -h` for the geometry, `e2label` for the
//! on-disk-truth label comparison (never `blkid`, which trims trailing
//! spaces - see below), `e2fsck` for the checker, `debugfs` for the
//! persistence flag file. A missing tool is printed as an explicit skip
//! line; a failing tool fails the test with its real output in the message.
//!
//! What is measured here, tool by tool (each bullet names what this run
//! actually did, measured with e2fsprogs 1.47.4 unless noted):
//! - flavour matrix (64 MiB, labels `RUFUSEXT2`/`RUFUSEXT3`/`RUFUSEXT4`):
//!   our `superblock_for` read-back agrees with the tools - `block_bytes`
//!   4096, the requested label, journal bit set for ext3/ext4 and clear
//!   for ext2. `dumpe2fs -h` reports `Block size: 4096`, `Inode size: 256`,
//!   and a `Filesystem features:` line carrying `has_journal` for ext3 and
//!   ext4 but not for ext2 (ext2 line: `ext_attr resize_inode dir_index
//!   filetype sparse_super large_file`). `e2label` prints the label plus a
//!   newline and exits 0. `verify()` returns `Ok`, and `e2fsck -f -n`
//!   exits 0 with no `FILE SYSTEM WAS MODIFIED` line in either stream
//!   (Pass 1-5 on stdout, the `e2fsck 1.47.4` banner on stderr).
//! - no label (no `-L` flag): our reader reports `None`, `e2label` prints
//!   exactly one empty line (a single `\n` on stdout, empty stderr) and
//!   exits 0, `dumpe2fs -h` reports `Filesystem volume name: <none>`,
//!   `blkid -o value -s LABEL` prints nothing and exits 0 (measured with
//!   util-linux 2.42.4 on this host).
//! - full-width 16-byte label (`ABCDEFGHIJKLMNOP`): the on-disk
//!   `s_volume_name` run carries all 16 bytes with no NUL terminator, and
//!   both our reader and `e2label` return all 16 bytes.
//! - trailing-space label (`RUFUS `): the on-disk bytes keep the space
//!   (`RUFUS ` plus NUL padding), `e2label` keeps it (`RUFUS \n`),
//!   `dumpe2fs -h` keeps it - while our own reader trims it to `RUFUS`
//!   (it routes through the one `device_text` sanitiser, which trims) and
//!   `blkid` also trims it to `RUFUS` (measured with e2fsprogs 1.47.4 and
//!   util-linux 2.42.4 on this host).
//! - non-ASCII label: the API refuses it by design (`with_label` names
//!   `ASCII`), while `mke2fs -L` itself accepts the 12 UTF-8 bytes of the
//!   Persian name below and `e2label` round-trips them byte-exact.
//! - writing check: `e2fsck -f -y` exits 0 on a freshly formatted volume
//!   for all three flavours and the volume stays `verify()`-clean after.
//!   Note the deliberate spelling: a bare `e2fsck -f` with no `-y`/`-n`
//!   exits 8 (`e2fsck: need terminal for interactive repairs`, measured
//!   with e2fsprogs 1.47.4) whenever stdin is not a terminal - even on a
//!   clean volume, even with stdin from `/dev/null` - so no test harness
//!   without a terminal can assert on it. `-f -y` is still the writing run
//!   the PLAN sentence asks for (no `-n`, answers yes to any prompt, stdin
//!   null), and it is what the suite asserts.
//! - persistence (`Options` with `persistence: true`): the on-disk label
//!   is `persistence` (our reader and `e2label`), `debugfs -R "cat
//!   /persistence.conf"` returns exactly the 8 bytes `/ union\n` on
//!   stdout, `debugfs -R "stat /persistence.conf"` reports a regular
//!   `0644` file of size 8, and `e2fsck -f -n` stays clean. A conflicting
//!   label refuses before any tool runs, without touching the target.
//!   PLAN also mentions distro-specific variants (casper/Kali); the base
//!   `/ union` file is the shipped contract this suite pins.
//! - large image: a 2 TiB sparse ext4 image formats and stays clean.
//!   Measured on this host (twice, because the backing store matters):
//!   on the workspace disk (ext4 over dm-crypt) `mke2fs` wall 0.110 s
//!   with ~1.03 GiB of real writes (`du`: 1,103,425,536 bytes on this
//!   host's ext4 backing this pass, 1,103,433,728 in the review pass -
//!   the tail blocks wobble between runs) against 2.0 TiB apparent, and on
//!   `/tmp` (tmpfs, where the test's own scratch directory lives)
//!   `mke2fs` wall 0.036-0.053 s with 29,605,888 bytes real against
//!   2199023255552 bytes apparent; `e2fsck -f -n` wall ~2.5-3 s either
//!   way, exit 0, no `FILE SYSTEM WAS MODIFIED`. The test prints its own
//!   wall times and `du`/apparent sizes on every run, since those numbers
//!   are host- and filesystem-dependent. (The `-E lazy_itable_init=0`
//!   flag that makes the exFAT 2 TiB case nearly free still materialises
//!   only tens of MiB on tmpfs and ~1.03 GiB on ext4 here - measured, not
//!   assumed - so the 2 TiB case stays a normal, non-ignored test.)
//!
//! Skip convention (the one tests/exfat_format.rs and
//! tests/ntfs_format.rs carry): every test that needs a real tool probes
//! it first and prints an explicit `skip:` line when it is missing - a
//! skip is a documented limitation, never a silent pass. Presence is
//! probed by spawn, never by a version verdict: the probe flag is `-V`
//! for the e2fsprogs family (`mke2fs`, `mkfs.ext*`, `e2fsck`, `debugfs`,
//! `dumpe2fs`, `e2label` - the family rejects `--version` as an invalid
//! option, measured with e2fsprogs 1.47.4, so a `--version` probe would
//! assert on exit codes instead of presence) and `--version` for `blkid`.
//! The formatter gate probes the same four names `ext::find_tool` accepts
//! (`mke2fs` first, then the `mkfs.ext2/3/4` aliases). Tools that ARE
//! present get their real output asserted, and a failing tool fails the
//! test loudly afterwards, which is the right bias.
//!
//! One test is `#[ignore]`d: `the_kernel_mounts_the_written_tree` needs
//! root and a loop device (`losetup` plus `mount -t ext4` read-write over
//! the attached node), so it runs only on demand. The non-root skip keeps
//! CI green; see the test for the skip line:
//!
//! ```text
//! cargo test --offline -p rufus-core --test ext_format --no-run
//! docker run --rm --privileged -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm e2fsprogs && <test-binary> --ignored --nocapture"
//! docker run --rm --privileged -v /dev:/dev -v /sys:/sys:ro -v "$PWD:$PWD" -w "$PWD" archlinux:latest sh -c "pacman -Sy --noconfirm e2fsprogs && <test-binary> --nocapture"
//! ```
//!
//! Plain `--ignored` is the device-scale run: it attaches one 64 MiB
//! sparse file over a loop device and mounts it. The `--nocapture` run
//! is the plain file-scale run for the rest of the suite. (`e2fsprogs`
//! ships with the archlinux base, so the install is a no-op there - the
//! command names it explicitly so a minimal image still works.)
//!
//! The PLAN "done when" clause for this slice - "ext4 with journal, label
//! and persistence.conf survives `e2fsck -f` and boots" - is only half
//! measured here, and nothing in this file fakes the other half. The
//! `e2fsck -f` survival is the writing-check test above (spelled `-f -y`
//! for the terminal reason documented there). The boot half needs QEMU
//! and an Ubuntu ISO: this environment has neither (`which
//! qemu-system-x86_64` finds nothing on this host), so no test boots
//! anything. The command a maintainer would use - not run here, stated
//! plainly as not run - is:
//!
//! ```text
//! qemu-system-x86_64 -drive file=<image>,format=raw -cdrom <ubuntu.iso> -boot order=d -m 4G -enable-kvm
//! ```
//!
//! Measured on this machine (page-cached sparse images): 64 MiB ext4
//! format well under a second + `e2fsck -f -n` instant; 2 TiB format
//! 0.036-0.110 s (tmpfs vs ext4 backing - see above) + `e2fsck -f -n`
//! ~2.5-3 s (the sparse file is never materialised beyond the tens of
//! MiB to ~1.03 GiB above).

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::time::Instant;

use rufus_core::fs::ext::Flavour;
use rufus_core::fs::ext::Options;
use rufus_core::fs::ext::Super;
use rufus_core::fs::ext::format;
use rufus_core::fs::ext::superblock_for;
use rufus_core::fs::ext::verify;
use rufus_core::log::Level;
use rufus_core::log::Logger;

/// One MiB in bytes.
const MIB: u64 = 1024 * 1024;
/// One TiB in bytes.
const TIB: u64 = 1024 * 1024 * MIB;

/// The small-image size every file-scale test formats.
const SMALL_IMAGE_BYTES: u64 = 64 * MIB;

/// A short ASCII label, well inside the 16-byte on-disk field.
const SHORT_LABEL: &str = "RUFUS";
/// A full-width label: exactly 16 bytes, so the on-disk run carries no
/// NUL terminator (the `da2aeb6` finding).
const FULL_WIDTH_LABEL: &str = "ABCDEFGHIJKLMNOP";
/// A label with a trailing space: on-disk and `e2label` keep it, our own
/// reader and `blkid` trim it (measured - see the module header).
const TRAILING_SPACE_LABEL: &str = "RUFUS ";
/// The non-ASCII label of the tool-behaviour acceptance, spelled with
/// escapes so this file stays ASCII: six units, the Persian name usually
/// transliterated as parvande (12 bytes in UTF-8).
const PERSIAN_LABEL: &str = "\u{67E}\u{631}\u{648}\u{646}\u{62F}\u{647}";
/// The persistence label the crate enforces before any tool runs.
const PERSISTENCE_LABEL: &str = "persistence";
/// The exact bytes `/persistence.conf` must carry, restated here for the
/// byte-exact read-back assert (the crate's own constant is
/// module-private).
const PERSISTENCE_CONF_BYTES: &[u8] = b"/ union\n";

// ---------------------------------------------------------------------------
// The image double + external-tool harness, copied across from
// tests/ntfs_format.rs (and tests/exfat_format.rs), minimised: mke2fs
// targets a filesystem path, so the suite needs only a sparse file.
// ---------------------------------------------------------------------------

/// Create `path` (or truncate it) as a sparse image of `total` bytes:
/// `set_len` on a fresh file is a hole, not a write, so a 64 MiB image
/// costs almost nothing on disk before the formatter touches it.
fn sparse_image(path: &Path, total: u64) {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .expect("the sparse image opens");
    file.set_len(total).expect("the sparse image extends");
}

/// Format `path` (freshly created sparse, `total` bytes) with `options`
/// through the crate's own `format`, and hand back the verified
/// superblock. Every caller gates on the formatter first.
fn format_image(path: &Path, total: u64, options: &Options) -> Super {
    sparse_image(path, total);
    let logger = Logger::new(Level::Trace);
    format(path, options, &logger).expect("the image formats")
}

/// One captured invocation of an external tool (spawned with a C locale,
/// like the crate's own formatter run), both streams verbatim.
struct ToolRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl ToolRun {
    fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Run `program` with `args` under `LC_ALL=C` (the crate's own spawn
/// environment, so diagnostics read the same way), or `None` when the
/// program could not be spawned at all (the everyday reason: it is not
/// on this host's PATH).
fn run_tool(program: &str, args: &[&str]) -> Option<ToolRun> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    Some(ToolRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// The skip gate for the tools the suite drives directly (`e2fsck`,
/// `debugfs`, `dumpe2fs`, `e2label`, `blkid`): presence via spawn, not a
/// version verdict - the e2fsprogs family rejects `--version` as an
/// invalid option (measured with e2fsprogs 1.47.4: `mke2fs --version`
/// exits 1, `e2fsck --version` exits 16), so the probe flag is `-V` for
/// that family and `--version` only for `blkid`. A status check would tie
/// the gate to one build's exit codes, and a tool that spawns but
/// misbehaves fails the test loudly afterwards, which is the right bias
/// (the exfat_format.rs convention, restated).
fn skip_without_tool(program: &str, what: &str) -> bool {
    let probe = if program == "blkid" {
        "--version"
    } else {
        "-V"
    };
    if Command::new(program).arg(probe).output().is_ok() {
        return false;
    }
    let package = if program == "blkid" {
        "util-linux"
    } else {
        "e2fsprogs"
    };
    eprintln!(
        "skip: {what} needs {program}, which this host does not ship (install {package} and re-run)"
    );
    true
}

/// The skip gate for the tests that drive [`format`]: the same four-name
/// scan `ext::find_tool` performs (`mke2fs` first, then the
/// `mkfs.ext2/3/4` aliases - see `ext.rs` `TOOL_NAMES`), expressed with
/// the sibling files' presence-not-verdict probe convention.
fn skip_without_formatter(what: &str) -> bool {
    let present = ["mke2fs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4"]
        .iter()
        .any(|program| Command::new(program).arg("-V").output().is_ok());
    if present {
        return false;
    }
    eprintln!(
        "skip: {what} needs mke2fs or mkfs.ext*, which this host does not ship \
         (install e2fsprogs and re-run)"
    );
    true
}

/// Read `len` bytes at `offset` from the image.
fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let file = std::fs::File::open(path).expect("the image opens");
    let mut buffer = vec![0u8; len];
    file.read_exact_at(&mut buffer, offset)
        .expect("the read works");
    buffer
}

/// The crate's `superblock_for` over the real first-block bytes of
/// `target`: the parsed on-disk facts every volume test re-asserts.
fn read_superblock_of(target: &Path, flavour: Flavour) -> Super {
    let region = read_at(target, 0, 4096);
    let block: &[u8; 4096] = region
        .as_slice()
        .try_into()
        .expect("the first block is 4096 bytes");
    superblock_for(block, flavour).expect("the real mke2fs-written superblock parses")
}

/// One `dumpe2fs -h` field of `target`: the line whose name (before the
/// colon) is `field`, trimmed. Panics with the tool output when the tool
/// is gone (after the skip gate) or the field is missing.
fn dumpe2fs_field(target: &Path, field: &str) -> String {
    let display = target.display().to_string();
    let Some(run) = run_tool("dumpe2fs", &["-h", &display]) else {
        panic!("dumpe2fs vanished after the skip check");
    };
    assert!(
        run.status.success(),
        "dumpe2fs -h failed on {display}:\n{}",
        run.combined()
    );
    run.stdout
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.trim() == field)
                .map(|(_, value)| value.trim().to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "dumpe2fs -h of {display} carries no {field:?} line:\n{}",
                run.combined()
            )
        })
}

/// `e2label`'s stdout for `target`, verbatim (the trailing newline is
/// part of the shape: a label-less volume prints exactly `"\n"`).
/// Panics with the tool output when the tool is gone or fails.
fn e2label_stdout(target: &Path) -> String {
    let display = target.display().to_string();
    let Some(run) = run_tool("e2label", &[&display]) else {
        panic!("e2label vanished after the skip check");
    };
    assert!(
        run.status.success(),
        "e2label failed on {display}:\n{}",
        run.combined()
    );
    run.stdout.clone()
}

/// The per-flavour label of the matrix: `RUFUSEXT2`, `RUFUSEXT3`,
/// `RUFUSEXT4` - 9 bytes each, distinct per generation.
fn flavour_label(flavour: Flavour) -> String {
    format!("RUFUS{}", flavour.as_str().to_ascii_uppercase())
}

/// `e2fsck` with `args` plus the target path: exit 0 and no
/// `FILE SYSTEM WAS MODIFIED` line in either stream. Exit status AND the
/// modified-phrase scan both apply - a checker that exits 0 while
/// reporting a modification must not pass. A checker crash or a missing
/// binary after the gate is a loud failure too.
fn assert_e2fsck_clean(target: &Path, args: &[&str], what: &str) {
    let display = target.display().to_string();
    let mut full: Vec<&str> = args.to_vec();
    full.push(&display);
    let Some(run) = run_tool("e2fsck", &full) else {
        panic!("e2fsck vanished after the skip check ({what})");
    };
    let text = run.combined();
    assert!(
        run.status.success(),
        "{what}: e2fsck {} exited {} on {display}:\n{text}",
        args.join(" "),
        run.status
    );
    assert!(
        !text.contains("FILE SYSTEM WAS MODIFIED"),
        "{what}: e2fsck {} must report no modification of {display}:\n{text}",
        args.join(" ")
    );
    let verdict = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("(no output at all)");
    eprintln!("e2fsck {}: {verdict}", args.join(" "));
}

/// A deterministic byte pattern, so a mismatch points at the exact
/// offset (the mounted-tree check reuses it).
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// FNV-1a over a byte run: not cryptographic, just a compact
/// change-detector for the untouched-target assert below.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// The acceptance tests.
// ---------------------------------------------------------------------------

/// The flavour matrix: ext2/ext3/ext4 each format a 64 MiB sparse image
/// through the crate's own `format`, then three independent readers agree
/// on the result - our `superblock_for` read-back (`block_bytes` 4096,
/// the requested label, journal present for ext3/ext4 and absent for
/// ext2), `dumpe2fs -h` (`Block size: 4096`, `Inode size: 256`, the
/// `has_journal` feature matching the flavour), and `e2label` (the label
/// plus a newline, exit 0). `verify()` returns `Ok`, and `e2fsck -f -n`
/// independently exits 0 with no `FILE SYSTEM WAS MODIFIED` line in
/// either stream.
#[test]
fn flavour_matrix_reports_the_mandated_geometry_and_stays_clean() {
    let what = "the flavour matrix acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("e2fsck", what)
        || skip_without_tool("dumpe2fs", what)
        || skip_without_tool("e2label", what)
    {
        return;
    }
    for flavour in [Flavour::Ext2, Flavour::Ext3, Flavour::Ext4] {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let path = dir.path().join("ext.img");
        let label = flavour_label(flavour);
        let options = Options::new(flavour)
            .with_label(&label)
            .expect("the matrix label is valid");
        let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
        let wants_journal = flavour != Flavour::Ext2;

        assert_eq!(
            verified.block_bytes, 4096,
            "{flavour}: the mandate pins -b 4096"
        );
        assert_eq!(
            verified.label.as_deref(),
            Some(label.as_str()),
            "{flavour}: our reader must return the requested label"
        );
        assert_eq!(
            verified.has_journal, wants_journal,
            "{flavour}: the journal bit must match the mandate split"
        );
        // The same facts straight from the image bytes, not the
        // crate's return value.
        let reread = read_superblock_of(&path, flavour);
        assert_eq!(reread, verified, "{flavour}: the re-read must match");

        assert_eq!(
            dumpe2fs_field(&path, "Block size"),
            "4096",
            "{flavour}: dumpe2fs must report the mandated block size"
        );
        assert_eq!(
            dumpe2fs_field(&path, "Inode size"),
            "256",
            "{flavour}: dumpe2fs must report the mandated inode size"
        );
        let features = dumpe2fs_field(&path, "Filesystem features");
        assert_eq!(
            features.contains("has_journal"),
            wants_journal,
            "{flavour}: dumpe2fs features must match the journal split: {features}"
        );
        assert_eq!(
            e2label_stdout(&path),
            format!("{label}\n"),
            "{flavour}: e2label must print the label plus a newline"
        );

        let logger = Logger::new(Level::Trace);
        verify(&path, &logger).expect("verify() must call the fresh volume clean");
        assert_e2fsck_clean(&path, &["-f", "-n"], what);
        eprintln!("{flavour}: block 4096, inode 256, journal {wants_journal}, label {label}");
    }
}

/// A format without `-L` leaves the volume nameless - measured by three
/// readers: our reader reports `None`, `e2label` prints exactly one empty
/// line (a single `\n` on stdout, empty stderr) and exits 0, `dumpe2fs`
/// reports `Filesystem volume name: <none>`, and `blkid` prints nothing
/// and exits 0.
#[test]
fn format_without_a_label_leaves_the_volume_nameless() {
    let what = "the no-label acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("e2fsck", what)
        || skip_without_tool("dumpe2fs", what)
        || skip_without_tool("e2label", what)
        || skip_without_tool("blkid", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &Options::new(Flavour::Ext4));
    assert_eq!(
        verified.label, None,
        "the labelless format must read back labelless"
    );
    assert_eq!(
        read_superblock_of(&path, Flavour::Ext4).label,
        None,
        "the re-read must agree"
    );
    assert_eq!(
        dumpe2fs_field(&path, "Filesystem volume name"),
        "<none>",
        "dumpe2fs must report the volume nameless"
    );

    let display = path.display().to_string();
    let read = run_tool("e2label", &[&display]).expect("e2label runs after the skip gate");
    assert!(
        read.status.success(),
        "e2label failed on a label-less volume:\n{}",
        read.combined()
    );
    assert_eq!(
        read.stdout, "\n",
        "e2label must print exactly one empty line for a label-less volume: {:?}",
        read.stdout
    );
    assert!(
        read.stderr.is_empty(),
        "e2label must stay silent on stderr for a label-less volume: {:?}",
        read.stderr
    );

    let blank = run_tool("blkid", &["-o", "value", "-s", "LABEL", &display])
        .expect("blkid runs after the skip gate");
    assert!(
        blank.status.success(),
        "blkid failed on a label-less volume:\n{}",
        blank.combined()
    );
    assert!(
        blank.stdout.is_empty(),
        "blkid must print nothing for a label-less volume: {:?}",
        blank.stdout
    );
    assert_e2fsck_clean(&path, &["-f", "-n"], what);
    eprintln!("no label: reader None, e2label one empty line, dumpe2fs <none>, blkid empty");
}

/// A short ASCII label round-trips through every reader: our read-back,
/// `dumpe2fs`, and `e2label` all report it.
#[test]
fn a_short_ascii_label_round_trips() {
    let what = "the short-label acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("dumpe2fs", what)
        || skip_without_tool("e2label", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let options = Options::new(Flavour::Ext4)
        .with_label(SHORT_LABEL)
        .expect("the short label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.label.as_deref(),
        Some(SHORT_LABEL),
        "our reader must return the short label"
    );
    assert_eq!(
        dumpe2fs_field(&path, "Filesystem volume name"),
        SHORT_LABEL,
        "dumpe2fs must report the short label"
    );
    assert_eq!(
        e2label_stdout(&path),
        format!("{SHORT_LABEL}\n"),
        "e2label must print the short label plus a newline"
    );
    eprintln!("short label: every reader reports {SHORT_LABEL}");
}

/// A full-width 16-byte label has no NUL terminator on disk (the
/// `da2aeb6` finding): the `s_volume_name` run carries all 16 bytes, and
/// both our reader and `e2label` return all 16.
#[test]
fn a_full_width_sixteen_byte_label_has_no_terminator() {
    let what = "the full-width label acceptance";
    if skip_without_formatter(what) || skip_without_tool("e2label", what) {
        return;
    }
    assert_eq!(
        FULL_WIDTH_LABEL.len(),
        16,
        "the fixture must be exactly 16 bytes"
    );
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let options = Options::new(Flavour::Ext4)
        .with_label(FULL_WIDTH_LABEL)
        .expect("16 ASCII bytes fit the field");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.label.as_deref(),
        Some(FULL_WIDTH_LABEL),
        "our reader must return all 16 bytes"
    );
    let run = read_at(&path, 1024 + 120, 16);
    assert_eq!(
        run,
        FULL_WIDTH_LABEL.as_bytes(),
        "the on-disk run must be the 16 label bytes with no NUL: {run:?}"
    );
    assert!(
        !run.contains(&0),
        "a full-width run carries no terminator: {run:?}"
    );
    assert_eq!(
        e2label_stdout(&path),
        format!("{FULL_WIDTH_LABEL}\n"),
        "e2label must return all 16 bytes plus a newline"
    );
    eprintln!("full-width label: 16 bytes on disk, no NUL, both readers agree");
}

/// A trailing space survives on disk and through `e2label`, but not
/// through our own reader or `blkid`: the on-disk bytes keep the space,
/// `e2label` prints `RUFUS ` plus a newline, our reader trims to `RUFUS`
/// (the one `device_text` sanitiser trims), and `blkid -o value -s LABEL`
/// prints `RUFUS` - measured with e2fsprogs 1.47.4 and util-linux 2.42.4
/// on this host, so comparisons must use the on-disk field or
/// `e2label`/`dumpe2fs`, never `blkid`.
#[test]
fn a_trailing_space_survives_on_disk_but_not_in_blkid() {
    let what = "the trailing-space label acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("e2label", what)
        || skip_without_tool("blkid", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let options = Options::new(Flavour::Ext4)
        .with_label(TRAILING_SPACE_LABEL)
        .expect("a trailing space is still ASCII inside 16 bytes");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.label.as_deref(),
        Some(SHORT_LABEL),
        "our reader trims the trailing space (device_text trims)"
    );
    let run = read_at(&path, 1024 + 120, 16);
    let mut expected = vec![0u8; 16];
    expected[..TRAILING_SPACE_LABEL.len()].copy_from_slice(TRAILING_SPACE_LABEL.as_bytes());
    assert_eq!(
        run, expected,
        "the on-disk run must keep the space: {run:?}"
    );
    assert_eq!(
        e2label_stdout(&path),
        format!("{TRAILING_SPACE_LABEL}\n"),
        "e2label must keep the trailing space"
    );
    let display = path.display().to_string();
    let trimmed = run_tool("blkid", &["-o", "value", "-s", "LABEL", &display])
        .expect("blkid runs after the skip gate");
    assert!(
        trimmed.status.success(),
        "blkid failed:\n{}",
        trimmed.combined()
    );
    assert_eq!(
        trimmed.stdout.trim(),
        SHORT_LABEL,
        "blkid trims the trailing space: {:?}",
        trimmed.stdout
    );
    eprintln!("trailing space: on-disk and e2label keep it, our reader and blkid trim it");
}

/// A non-ASCII label pins both sides of the boundary: the API refuses it
/// by design (`with_label` names `ASCII`), while `mke2fs -L` itself
/// accepts the 12 UTF-8 bytes of the Persian name and `e2label`
/// round-trips them byte-exact. The second half documents the tool, not
/// our API - the refusal above is the API contract, and no test loosens
/// it to make anything pass.
#[test]
fn a_non_ascii_label_is_refused_by_the_api_but_accepted_by_mke2fs() {
    let what = "the non-ASCII label acceptance";
    let refusal = Options::new(Flavour::Ext4)
        .with_label(PERSIAN_LABEL)
        .expect_err("a non-ASCII label must refuse");
    let text = refusal.to_string();
    assert!(
        text.contains("ASCII"),
        "the refusal must name the ASCII rule: {text}"
    );
    assert!(
        text.contains("16"),
        "the refusal must name the 16-byte field ceiling: {text}"
    );
    eprintln!("api refusal: {text}");

    if skip_without_formatter(what) || skip_without_tool("e2label", what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    sparse_image(&path, SMALL_IMAGE_BYTES);
    let display = path.display().to_string();
    let run = run_tool(
        "mke2fs",
        &[
            "-q",
            "-F",
            "-t",
            "ext4",
            "-L",
            PERSIAN_LABEL,
            "-b",
            "4096",
            "-I",
            "256",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            &display,
        ],
    )
    .expect("mke2fs runs after the skip gate");
    assert!(
        run.status.success(),
        "mke2fs refused the non-ASCII label:\n{}",
        run.combined()
    );
    assert_eq!(
        e2label_stdout(&path),
        format!("{PERSIAN_LABEL}\n"),
        "e2label must round-trip the UTF-8 bytes"
    );
    eprintln!("tool behaviour: mke2fs accepted 12 UTF-8 bytes, e2label round-tripped them");
}

/// The PLAN sentence's real claim, spelled so a terminal-less harness can
/// assert it: `e2fsck -f -y` (a writing run - no `-n`, answers yes to any
/// repair prompt, stdin null) exits 0 on a freshly formatted volume for
/// all three flavours, with no `FILE SYSTEM WAS MODIFIED` line, and
/// `verify()` still calls the same now-touched volume clean. A bare
/// `e2fsck -f` would exit 8 without a terminal (measured - see the module
/// header), so the suite does not pretend to run that spelling here.
#[test]
fn a_writing_check_leaves_fresh_volumes_clean() {
    let what = "the writing-check acceptance";
    if skip_without_formatter(what) || skip_without_tool("e2fsck", what) {
        return;
    }
    for flavour in [Flavour::Ext2, Flavour::Ext3, Flavour::Ext4] {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let path = dir.path().join("ext.img");
        let options = Options::new(flavour)
            .with_label(flavour_label(flavour))
            .expect("the matrix label is valid");
        format_image(&path, SMALL_IMAGE_BYTES, &options);
        let run = {
            let display = path.display().to_string();
            run_tool("e2fsck", &["-f", "-y", &display]).expect("e2fsck runs after the skip gate")
        };
        let text = run.combined();
        assert!(
            run.status.success(),
            "{flavour}: e2fsck -f -y exited {}:\n{text}",
            run.status
        );
        assert!(
            !text.contains("FILE SYSTEM WAS MODIFIED"),
            "{flavour}: the writing run must report no modification:\n{text}"
        );
        let logger = Logger::new(Level::Trace);
        verify(&path, &logger).expect("verify() must stay clean after the writing run");
        eprintln!("{flavour}: e2fsck -f -y exit 0, verify() still clean");
    }
}

/// Persistence through the crate's own `format` with `persistence: true`:
/// the on-disk label is `persistence` (our reader and `e2label`),
/// `debugfs -R "cat /persistence.conf"` returns exactly the 8 bytes
/// `/ union\n` on stdout, `debugfs -R "stat /persistence.conf"` reports
/// a regular `0644` file of size 8, and `e2fsck -f -n` stays clean.
/// PLAN also mentions distro-specific variants (casper/Kali) - the base
/// `/ union` file is the shipped contract this test pins.
#[test]
fn persistence_writes_the_flag_file_and_survives_the_checker() {
    let what = "the persistence acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("e2fsck", what)
        || skip_without_tool("debugfs", what)
        || skip_without_tool("e2label", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let mut options = Options::new(Flavour::Ext4);
    options.persistence = true;
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.label.as_deref(),
        Some(PERSISTENCE_LABEL),
        "the persistence volume must carry the persistence label"
    );
    assert_eq!(
        read_superblock_of(&path, Flavour::Ext4).label.as_deref(),
        Some(PERSISTENCE_LABEL),
        "the re-read must agree"
    );
    assert_eq!(
        e2label_stdout(&path),
        format!("{PERSISTENCE_LABEL}\n"),
        "e2label must read the persistence label"
    );

    let display = path.display().to_string();
    let cat = run_tool("debugfs", &["-R", "cat /persistence.conf", &display])
        .expect("debugfs runs after the skip gate");
    assert!(
        cat.status.success(),
        "debugfs cat failed:\n{}",
        cat.combined()
    );
    assert_eq!(
        cat.stdout.as_bytes(),
        PERSISTENCE_CONF_BYTES,
        "the flag file must be exactly `/ union` plus a newline: {:?}",
        cat.stdout.as_bytes()
    );

    let stat = run_tool("debugfs", &["-R", "stat /persistence.conf", &display])
        .expect("debugfs runs after the skip gate");
    assert!(
        stat.status.success(),
        "debugfs stat failed:\n{}",
        stat.combined()
    );
    assert!(
        stat.stdout.contains("Type: regular"),
        "the flag file must be regular:\n{}",
        stat.combined()
    );
    assert!(
        stat.stdout.contains("Mode:  0644"),
        "the flag file must be 0644:\n{}",
        stat.combined()
    );
    // `Size: 8` rides at the end of the `User: ... Group: ... Size: 8`
    // line (measured with e2fsprogs 1.47.4), so the match is a contains
    // on the one line - the only other `Size` line is the
    // `Size of extra inode fields` one, which carries no `Size: 8`.
    assert!(
        stat.stdout.lines().any(|line| line.contains("Size: 8")),
        "the flag file must be 8 bytes:\n{}",
        stat.combined()
    );

    let logger = Logger::new(Level::Trace);
    verify(&path, &logger).expect("verify() must call the persistence volume clean");
    assert_e2fsck_clean(&path, &["-f", "-n"], what);
    eprintln!("persistence: label persistence, 8 flag bytes, regular 0644, checker clean");
}

/// A conflicting label with `persistence: true` refuses before any tool
/// runs - and the refusal must not touch the target (the probe ordering
/// itself is pinned by the crate's unit test
/// `persistence_refuses_a_conflicting_label_before_any_tool_runs`; this
/// acceptance test proves the target is untouched). The test formats a
/// persistence volume, records its length plus the FNV-1a hash of its
/// first 4096 bytes, attempts the conflicting format, and asserts the
/// length and the hash are both unchanged.
#[test]
fn persistence_refuses_a_conflicting_label_without_touching_the_target() {
    let what = "the persistence-conflict acceptance";
    if skip_without_formatter(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let mut good = Options::new(Flavour::Ext4);
    good.persistence = true;
    format_image(&path, SMALL_IMAGE_BYTES, &good);

    let before_len = std::fs::metadata(&path)
        .expect("the image is statable")
        .len();
    let before_head = read_at(&path, 0, 4096);
    let before_hash = fnv1a(&before_head);
    eprintln!("before: length {before_len}, fnv1a {before_hash:016x}");

    let mut bad = Options::new(Flavour::Ext4);
    bad.persistence = true;
    bad.label = Some("RUFUS-X".to_string());
    let logger = Logger::new(Level::Trace);
    let error = format(&path, &bad, &logger).expect_err("a conflicting label must refuse");
    let text = error.to_string();
    assert!(
        text.contains(PERSISTENCE_LABEL),
        "the refusal must name the required label: {text}"
    );
    assert!(
        text.contains("RUFUS-X"),
        "the refusal must name the conflict: {text}"
    );

    let after_len = std::fs::metadata(&path)
        .expect("the image is statable")
        .len();
    let after_head = read_at(&path, 0, 4096);
    assert_eq!(
        after_len, before_len,
        "the refused run must not change the image length"
    );
    assert_eq!(
        after_head, before_head,
        "the refused run must not change the first 4096 bytes"
    );
    assert_eq!(
        fnv1a(&after_head),
        before_hash,
        "the refused run must not change the head hash"
    );
    eprintln!(
        "after: length {after_len}, fnv1a {:016x} - untouched",
        fnv1a(&after_head)
    );
}

/// The 2 TiB sparse image: formats through the crate's own `format`,
/// carries the mandated geometry at scale (536870912 4 KiB blocks,
/// 134217728 inodes, label intact), and `e2fsck -f -n` exits 0 with no
/// `FILE SYSTEM WAS MODIFIED`. The test prints its own wall times and
/// `du`/apparent sizes on every run - the module header carries this
/// host's numbers (format 0.036-0.110 s depending on the backing store,
/// tens of MiB real on tmpfs vs ~1.03 GiB on ext4, check ~2.5-3 s), and a
/// drift there is information, not a failure.
#[test]
fn a_two_tebibyte_sparse_image_formats_and_stays_clean() {
    let what = "the 2 TiB acceptance";
    if skip_without_formatter(what)
        || skip_without_tool("e2fsck", what)
        || skip_without_tool("dumpe2fs", what)
        || skip_without_tool("e2label", what)
    {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    sparse_image(&path, 2 * TIB);
    let options = Options::new(Flavour::Ext4)
        .with_label("BIG2T")
        .expect("the large-image label is valid");
    let logger = Logger::new(Level::Trace);
    let started = Instant::now();
    let verified = format(&path, &options, &logger).expect("the 2 TiB image formats");
    let format_time = started.elapsed();
    assert_eq!(
        verified.block_bytes, 4096,
        "the large image must keep the mandated block size"
    );
    assert!(verified.has_journal, "the large image must carry a journal");
    assert_eq!(
        verified.label.as_deref(),
        Some("BIG2T"),
        "the large image must carry its label"
    );

    let apparent = std::fs::metadata(&path)
        .expect("the image is statable")
        .len();
    let display = path.display().to_string();
    // A diagnostic, never an assert: a minimal image without coreutils
    // still passes this test, it just prints the apparent size only.
    if let Some(du) = run_tool("du", &["-B1", &display]) {
        let real: u64 = du
            .stdout
            .split_whitespace()
            .next()
            .expect("du prints a size")
            .parse()
            .expect("du prints a number");
        eprintln!(
            "2 TiB: format {format_time:?}, du {real} bytes real vs {apparent} bytes apparent"
        );
    } else {
        eprintln!("2 TiB: format {format_time:?}, no du on PATH; {apparent} bytes apparent");
    }

    assert_eq!(
        dumpe2fs_field(&path, "Block count"),
        "536870912",
        "2 TiB at 4 KiB blocks is 536870912 blocks"
    );
    assert_eq!(
        dumpe2fs_field(&path, "Inode count"),
        "134217728",
        "the default inode ratio gives 134217728 inodes"
    );
    assert_eq!(
        e2label_stdout(&path),
        "BIG2T\n",
        "e2label must read the large-image label"
    );
    let started = Instant::now();
    verify(&path, &logger).expect("verify() must call the large image clean");
    let check_time = started.elapsed();
    eprintln!("2 TiB: verify {check_time:?}");
    assert_e2fsck_clean(&path, &["-f", "-n"], what);
}

// ---------------------------------------------------------------------------
// The failure shapes: a target the tool cannot format must surface the
// house refusal (tool name, exit status, tool tail) - never a panic, and
// never a claim that the package is missing when the tool ran and spoke.
// ---------------------------------------------------------------------------

/// A target that is a directory: the formatter runs, `mke2fs` exits 1
/// (`mke2fs: Device size reported to be zero ...`, measured with
/// e2fsprogs 1.47.4), and the refusal names the tool and the status
/// without claiming the package is missing.
#[test]
fn format_refuses_a_directory_target() {
    let what = "the directory-target refusal";
    if skip_without_formatter(what) {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let target = dir.path().join("a-directory");
    std::fs::create_dir(&target).expect("the directory target exists");
    let logger = Logger::new(Level::Trace);
    let options = Options::new(Flavour::Ext4);
    let error = format(&target, &options, &logger).expect_err("a directory target must refuse");
    let text = error.to_string();
    assert!(
        text.contains("mke2fs"),
        "the refusal must name the tool that ran: {text}"
    );
    assert!(
        text.contains("exit status: 1"),
        "the refusal must name the status: {text}"
    );
    assert!(
        !text.contains("e2fsprogs"),
        "the tool ran and spoke, so the refusal must not claim the package is missing: {text}"
    );
    let messages: Vec<String> = logger
        .snapshot()
        .iter()
        .map(|record| record.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("Device size reported to be zero")),
        "the tool's own line must reach the log: {messages:?}"
    );
    eprintln!("directory target refused: {text}");
}

/// A path whose parent is missing - or present but read-only - is the
/// tool's failure, not ours: `mke2fs` exits 1 (`The file ... does not
/// exist and no size was specified.`, measured with e2fsprogs 1.47.4) and
/// the refusal names the tool and the status without claiming the package
/// is missing. The read-only half is skipped for root (root writes
/// through directory permissions, so the refusal would not happen).
#[test]
fn format_refuses_a_path_without_a_writable_parent() {
    let what = "the unwritable-parent refusal";
    if skip_without_formatter(what) {
        return;
    }
    let logger = Logger::new(Level::Trace);
    let options = Options::new(Flavour::Ext4);

    let dir = tempfile::tempdir().expect("a scratch directory");
    let missing = dir.path().join("no-such-dir").join("ext.img");
    let error = format(&missing, &options, &logger).expect_err("a missing parent must refuse");
    let text = error.to_string();
    assert!(
        text.contains("mke2fs"),
        "the refusal must name the tool that ran: {text}"
    );
    assert!(
        text.contains("exit status: 1"),
        "the refusal must name the status: {text}"
    );
    assert!(
        !text.contains("e2fsprogs"),
        "the tool ran and spoke, so the refusal must not claim the package is missing: {text}"
    );
    assert!(!missing.exists(), "the refused run must create nothing");
    eprintln!("missing parent refused: {text}");

    if is_root() {
        eprintln!(
            "skip: {what} read-only half needs a non-root user; root writes through permissions"
        );
        return;
    }
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).expect("the locked directory exists");
    let mut permissions = std::fs::metadata(&locked)
        .expect("the locked directory is statable")
        .permissions();
    use std::os::unix::fs::PermissionsExt as _;
    permissions.set_mode(0o555);
    std::fs::set_permissions(&locked, permissions).expect("the directory locks");
    let inside = locked.join("ext.img");
    let error = format(&inside, &options, &logger).expect_err("a read-only parent must refuse");
    let text = error.to_string();
    assert!(
        text.contains("mke2fs"),
        "the refusal must name the tool that ran: {text}"
    );
    assert!(
        text.contains("exit status: 1"),
        "the refusal must name the status: {text}"
    );
    assert!(
        !text.contains("e2fsprogs"),
        "the tool ran and spoke, so the refusal must not claim the package is missing: {text}"
    );
    assert!(!inside.exists(), "the refused run must create nothing");
    let mut permissions = std::fs::metadata(&locked)
        .expect("the locked directory is statable")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&locked, permissions).expect("the directory unlocks");
    eprintln!("read-only parent refused: {text}");
}

// ---------------------------------------------------------------------------
// The kernel-mount acceptance, mirroring the ntfs sibling's
// the_kernel_mounts_the_written_tree: attach the image, mount it
// read-write, write a tree through the mounted path, unmount, then
// re-verify the image with the crate readers and e2fsck.
// ---------------------------------------------------------------------------

/// The loop mount guard: attach (via [`attach_loop`]), track the
/// mountpoint, and on every exit path unmount and detach.
struct Mounted {
    device: String,
    mountpoint: PathBuf,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.mountpoint).status();
        let _ = Command::new("losetup").args(["-d", &self.device]).status();
    }
}

/// Attach `path` as a fresh loop device and return the node string.
/// `--direct-io=off` matches the siblings' mount bookkeeping: the
/// image is page-cached. The caller wraps the node in [`Mounted`],
/// which unmounts and detaches on every exit path.
fn attach_loop(path: &Path, what: &str) -> String {
    let attached = Command::new("losetup")
        .args(["--find", "--show", "--direct-io=off"])
        .arg(path)
        .output()
        .expect("losetup runs");
    assert!(
        attached.status.success(),
        "losetup failed ({what}): {}",
        String::from_utf8_lossy(&attached.stderr)
    );
    let device = String::from_utf8_lossy(&attached.stdout).trim().to_owned();
    assert!(!device.is_empty(), "losetup printed no node ({what})");
    device
}

fn is_root() -> bool {
    // euid 0 is the only identity that can mount; a non-root run
    // reports a skip rather than pretending the check passed.
    std::fs::metadata("/proc/self").is_ok()
        && Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

/// The kernel acceptance for the S12 "mounts" line: a crate-formatted
/// ext4 volume (label `RUFUSMNT`), mounted READ-WRITE by the kernel's
/// ext4 driver over a loop node. A tree written through the mounted path
/// must read back byte-exact, the unmounted volume must stay `verify()`-
/// and `e2fsck -f -n`-clean, and the label must survive the kernel's
/// writes. The mounted root also holds the `lost+found` directory the
/// formatter itself creates (measured with e2fsprogs 1.47.4 in the
/// privileged-container run). Needs root and a loop device; it is
/// `#[ignore]`d - see the module docs for the container command.
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
    // installs e2fsprogs); no skip gates here, by the ntfs sibling's
    // convention - a missing tool fails loudly instead.
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = dir.path().join("ext.img");
    let options = Options::new(Flavour::Ext4)
        .with_label("RUFUSMNT")
        .expect("the mount label is valid");
    let verified = format_image(&path, SMALL_IMAGE_BYTES, &options);
    assert_eq!(
        verified.label.as_deref(),
        Some("RUFUSMNT"),
        "the crate must read its own label before the kernel sees the image"
    );
    eprintln!("stage: volume formatted with label RUFUSMNT");

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
        .args(["-t", "ext4"])
        .arg(&device)
        .arg(&mountpoint)
        .output()
        .expect("mount runs");
    assert!(
        mounted.status.success(),
        "mounting {device} failed: {}",
        String::from_utf8_lossy(&mounted.stderr)
    );
    eprintln!("stage: mounted read-write with ext4 (kernel)");

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
        ["a", "lost+found"],
        "the mounted root must hold the written tree plus the `lost+found` mke2fs creates"
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

    let logger = Logger::new(Level::Trace);
    verify(&path, &logger).expect("verify() must stay clean after the kernel writes");
    assert_e2fsck_clean(&path, &["-f", "-n"], "the mounted volume");

    // The label must survive the kernel's writes: re-read from the
    // post-session image bytes (no reuse of the pre-mount struct) and
    // through e2label.
    assert_eq!(
        read_superblock_of(&path, Flavour::Ext4).label.as_deref(),
        Some("RUFUSMNT"),
        "the label must survive the kernel's read-write session"
    );
    assert_eq!(
        e2label_stdout(&path),
        "RUFUSMNT\n",
        "e2label must read the label after the kernel's writes"
    );
    eprintln!("stage: label survived the kernel writes");
}
