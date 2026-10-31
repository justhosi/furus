//! External-tool acceptance evidence for the S09 FAT32 formatter (part
//! A) — the slice's "Done when" against the FAT tooling this machine
//! actually ships: `fsck.fat 4.2` must accept what
//! [`format`](rufus_core::fs::fat32::format) lays down, on the size
//! classes the slice brief names (64 MiB, 2 GiB, 32 GiB large FAT32 and
//! the 2 TiB limit).
//!
//! Every test drives the real path: a sparse image file (`std::fs::File`
//! with `set_len`, never a `VecVolume` — see [`FileVolume`]) the
//! formatter writes through the [`Volume`] trait, then the raw image
//! goes to `fsck.fat -n`, whose exit status *and* full output are both
//! asserted (the "no error line" half exists because fsck.fat is known
//! to exit 0 while still reporting repairable errors). One external-tool
//! invocation must fail the test with the tool's real output in the
//! message; a missing tool is printed as an explicit skip line and the
//! test stays loud about what was proven — never a silent pass, and
//! never at the cost of the tool-independent assertions that already
//! ran before the tool block.
//!
//! The geometry-only side of each test (cluster size, FAT identity,
//! label entry) is re-asserted here from the image bytes so a run still
//! carries evidence on hosts without dosfstools; the skip line states
//! exactly what only `fsck.fat` can vouch for. Timing notes are comments
//! with the measured wall times of this machine.
//!
//! Measured on this machine (page-cached sparse images, whole suite
//! ≈1 s): 64 MiB format 0.000 s + fsck 0.007 s; 2 GiB format 0.002 s +
//! fsck 0.017 s; 32 GiB format 0.006 s + fsck 0.020 s; 2 TiB format
//! 0.084 s + fsck 0.722 s. The "Free cluster summary uninitialized
//! (should be N)" note fsck.fat prints against the unknown counts the
//! formatter publishes is informational — it contains no error line
//! and the exit status stays 0 (verified before pinning).

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::time::Instant;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::fs::Volume;
use rufus_core::fs::fat32::bpb::DEFAULT_OEM;
use rufus_core::fs::fat32::format::FormatOptions;
use rufus_core::fs::fat32::format::format;
use rufus_core::fs::fat32::geometry::Geometry;
use rufus_core::fs::fat32::geometry::geometry;
use rufus_core::fs::fat32::volume::Fat32;

/// One TiB in bytes (the 2 TiB test multiplies it).
const MIB: u64 = 1024 * 1024;
/// One GiB.
const GIB: u64 = 1024 * MIB;
/// The FAT32 2 TiB ceiling the PLAN pins for large FAT32.
const TIB: u64 = 1024 * GIB;

/// The volume id and label the acceptance images carry (a real,
/// non-zero serial and an 11-byte-friendly label).
const VOLUME_ID: u32 = 0x1_2C_3E_50;

// ---------------------------------------------------------------------------
// The file-backed Volume double of this file: sparse std::fs::File
// ---------------------------------------------------------------------------

/// A sparse image file — the file-backed [`Volume`] double this suite
/// runs on, exactly the shape the multi-GiB tests need (`set_len` on a
/// fresh file is a hole, not a write, so a 2 TiB image costs a few
/// hundred KiB on disk) while a plain `VecVolume` would need that
/// memory physically in RAM.
///
/// The full trait contract rides along: bounds come from the
/// formatter's own checks and the store's exact positional I/O; a read
/// past the end of the file surfaces as the
/// [`UnexpectedEof`](std::io::ErrorKind::UnexpectedEof) styled
/// [`CoreError::io`] (never zero-filled), every write is exact, and
/// [`flush`] is the fd's `sync_data`.
struct FileVolume {
    file: std::fs::File,
    total_bytes: u64,
    sector_size: u32,
}

impl FileVolume {
    /// Create (or truncate) `path` as a sparse image of `total_bytes`.
    fn create(path: &Path, total_bytes: u64, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))?;
        // set_len on a fresh file extends without touching the pages:
        // the image is sparse from the first moment.
        file.set_len(total_bytes)
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Self {
            file,
            total_bytes,
            sector_size,
        })
    }

    /// Open an existing image for reads (seek-free, exact).
    fn open(path: &Path, total_bytes: u64, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Self {
            file,
            total_bytes,
            sector_size,
        })
    }

    /// The path under a [`tempfile::TempDir`] this volume first was.
    fn path(dir: &Path) -> PathBuf {
        dir.join("fat32.img")
    }
}

impl Volume for FileVolume {
    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|error| CoreError::io("<fat32 volume>", error))
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file
            .write_all_at(buf, offset)
            .map_err(|error| CoreError::io("<fat32 volume>", error))
    }

    fn flush(&mut self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|error| CoreError::io("<fat32 volume>", error))
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

// ---------------------------------------------------------------------------
// The external-tool harness: capture, report, skip-with-a-reason — the
// convention of crates/rufus-linux/tests/partition_table.rs, restated
// here so this slice carries its own copy.
// ---------------------------------------------------------------------------

/// One captured invocation of `fsck.fat`, spawned with a C locale so
/// every byte it answers is ASCII.
struct ToolRun {
    /// The process result: `None` when the binary could not be spawned
    /// at all (absent from `PATH` is the everyday cause); `Some` is the
    /// exit status of a process that ran.
    ran: Option<ExitStatus>,
    /// The spawn failure text, when the binary never started.
    spawn: Option<String>,
    /// The verbatim standard output of the run.
    stdout: String,
    /// The verbatim standard error of the run.
    stderr: String,
}

impl ToolRun {
    /// The two captured texts joined for a failure message: stdout
    /// first, stderr under a marker, both trimmed.
    fn text(&self) -> String {
        let mut text = self.stdout.trim_end().to_owned();
        let stderr = self.stderr.trim_end();
        if !stderr.is_empty() {
            if !text.is_empty() {
                text.push_str("\n--- stderr ---\n");
            }
            text.push_str(stderr);
        }
        text
    }
}

/// Invoke `program` with `args`, both streams captured, ASCII locale.
/// The returned run carries nothing timed; callers measure around it.
fn run_tool(program: &str, args: &[&str]) -> ToolRun {
    match Command::new(program).args(args).env("LC_ALL", "C").output() {
        Ok(output) => ToolRun {
            ran: Some(output.status),
            spawn: None,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(error) => ToolRun {
            ran: None,
            spawn: Some(format!("{program}: {error}")),
            stdout: String::new(),
            stderr: String::new(),
        },
    }
}

/// The documented skip when a required tool is not installed: without
/// the tool the test also loses its proofs, so it ends early with the
/// reason printed — a skip stays explicit, never a silent pass.
/// Returns `true` when `tool` could not be spawned at all.
fn skip_without_tool(run: &ToolRun, tool: &str, what: &str) -> bool {
    let Some(reason) = &run.spawn else {
        return false;
    };
    eprintln!(
        "skip: {what} cannot run without {tool}; this environment does not ship it \
               ({reason}), see the module docs for what a maintainer runs instead"
    );
    true
}

/// The lines `fsck.fat` prints while still exiting 0.
///
/// Measured on `fsck.fat 4.2 (2021-01-31)`: a clobbered backup boot
/// sector prints "There are differences between boot sector and its
/// backup." with status 0, and an overwritten long-name run prints
/// "Unfinished long file name ..." plus "Long filename fragment ...
/// Not auto-correcting this." with status 0 as well. A guard scanning
/// only for the word "error" accepted both of those damaged images, so
/// each measured phrase is spelled out here.
const FSCK_DAMAGE_PHRASES: [&str; 6] = [
    "differences between boot sector",
    "not auto-correcting",
    "unfinished long file name",
    "free cluster summary wrong",
    "reclaimed",
    "corrupt",
];

/// Everything wrong with an `fsck` run, empty when the image is clean.
///
/// A non-zero exit is a problem; so is a zero exit carrying any
/// [`FSCK_DAMAGE_PHRASES`] line. The informational
/// "Free cluster summary uninitialized (should be N)" note that a
/// freshly formatted image produces is deliberately not a problem - it
/// is what the FAT32 formatter's documented "unknown counts" choice
/// means, and `fsck` repairs it on the first mounted write.
fn fsck_problems(fsck: &ToolRun) -> Vec<String> {
    let mut problems = Vec::new();
    match fsck.ran {
        None => problems.push("fsck.fat did not run".to_string()),
        Some(status) if !status.success() => problems.push(format!("fsck.fat exited {status}")),
        Some(_) => {}
    }
    for line in fsck
        .stdout
        .lines()
        .chain(fsck.stderr.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error")
            || FSCK_DAMAGE_PHRASES
                .iter()
                .any(|phrase| lower.contains(phrase))
        {
            problems.push(line.to_string());
        }
    }
    problems
}

/// Assert the image is clean in the strong sense above, printing the
/// real tool output on failure.
fn assert_fsck_clean(fsck: &ToolRun, what: &str) {
    let problems = fsck_problems(fsck);
    assert!(
        problems.is_empty(),
        "{what}: fsck.fat reported a problem line\n{}\n{}",
        problems.join("\n"),
        fsck.text()
    );
}

// ---------------------------------------------------------------------------
// The shared steps: create a sparse image, format it, then read its
// rendered geometry back from the bytes (independent of any tool).
// ---------------------------------------------------------------------------

/// Formats the FAT32 options this suite carries.
fn rufus_options() -> FormatOptions<'static> {
    FormatOptions {
        label: Some("RUFUS"),
        volume_id: VOLUME_ID,
        oem: DEFAULT_OEM,
    }
}

/// Create `path` as a sparse image of `size_bytes` at `sector_size`,
/// format it, publish both readings and the elapsed seconds.
fn formatted_image(
    path: &Path,
    size_bytes: u64,
    sector_size: u32,
    options: &FormatOptions<'_>,
) -> Result<(Geometry, f64)> {
    let mut volume = FileVolume::create(path, size_bytes, sector_size)?;
    let started = Instant::now();
    let geometry = format(&mut volume, options)?;
    volume.flush()?;
    let elapsed = started.elapsed().as_secs_f64();
    Ok((geometry, elapsed))
}

/// Read the rendered geometry back from the image bytes — the checks
/// that need no external tool, and that stay proven on hosts without
/// one:
///
/// * both FAT copies are byte-identical, scaffolding pinned, the rest
///   free (zeros);
/// * the boot sector and its backup agree, the FSInfo and its backup
///   agree;
/// * the root directory carries the label entry exactly when a label
///   was formatted in, with nothing else set.
fn assert_image_self_consistent(
    dir: &Path,
    tested: &Geometry,
    sector_size: u32,
    expects_label: bool,
) {
    let path = FileVolume::path(dir);
    let volume = FileVolume::open(&path, tested.total_bytes, sector_size)
        .expect("the just-formatted image opens");
    let sector = u64::from(sector_size);
    assert_eq!(
        u64::from(tested.bytes_per_sector),
        sector,
        "sector size round trip"
    );

    // boot and backup boot, fsinfo and backup fsinfo
    let fat_offset = tested.fat_offset();
    let mut boot = vec![0u8; 512];
    let mut mirror = vec![0u8; 512];
    volume.read_exact_at(0, &mut boot).expect("boot sector");
    volume
        .read_exact_at(6 * sector, &mut mirror)
        .expect("backup boot sector");
    assert_eq!(boot, mirror, "backup boot at sector 6 mirrors the primary");
    volume.read_exact_at(sector, &mut mirror).expect("fsinfo");
    assert!(
        mirror.starts_with(b"RRaA"),
        "the fsinfo signature is stamped"
    );
    volume
        .read_exact_at(7 * sector, &mut mirror)
        .expect("backup fsinfo");
    assert!(
        mirror[..512].starts_with(b"RRaA"),
        "the backup fsinfo carries the same signature"
    );

    // both FATs identical, first three entries pinned
    let fat_bytes = usize::try_from(tested.fat_length_bytes()).expect("2 TiB class FATs fit usize");
    let mut fat_one = vec![0u8; fat_bytes];
    let mut fat_two = vec![0u8; fat_bytes];
    volume
        .read_exact_at(fat_offset, &mut fat_one)
        .expect("first FAT copy");
    volume
        .read_exact_at(fat_offset + tested.fat_length_bytes(), &mut fat_two)
        .expect("second FAT copy");
    assert_eq!(fat_one, fat_two, "both FAT copies are identical");
    let expected = [
        0x0FFF_FFF8u32.to_le_bytes(),
        0x0FFF_FFFFu32.to_le_bytes(),
        0x0FFF_FFFFu32.to_le_bytes(),
    ]
    .concat();
    assert_eq!(
        fat_one[..12],
        expected,
        "the first three FAT entries are the scaffolding"
    );

    // the root cluster: label entry exactly when a label was requested
    let root = tested
        .cluster_offset(tested.root_cluster)
        .expect("the root cluster resolves");
    let mut head = vec![0u8; 32];
    volume
        .read_exact_at(root, &mut head)
        .expect("root directory head");
    if expects_label {
        assert_eq!(
            &head[..11],
            b"RUFUS      ",
            "the label entry carries the name"
        );
        assert_eq!(head[11], 0x08, "the entry is the volume label attribute");
        assert!(
            head[12..].iter().all(|&b| b == 0),
            "timestamps stay zero here"
        );
    } else {
        assert!(head.iter().all(|&b| b == 0), "no entry without a label");
    }
    let mut after = vec![0u8; usize::try_from(tested.cluster_bytes()).expect("cluster fits usize")];
    volume
        .read_exact_at(root, &mut after)
        .expect("the whole root cluster");
    let non_zero_beyond_entry = if expects_label { 32 } else { 0 };
    assert!(
        after[non_zero_beyond_entry..].iter().all(|&b| b == 0),
        "the root directory holds nothing beyond the label entry"
    );
}

// ---------------------------------------------------------------------------
// The acceptance tests: 64 MiB, 2 GiB, 32 GiB large FAT32, 2 TiB.
// ---------------------------------------------------------------------------

/// The 64 MiB acceptance: the geometry the small-FAT32 class solves,
/// the formatted image self-consistent, and `fsck.fat -n` clean.
/// Measured on this machine: format 0.000 s, fsck 0.007 s.
#[test]
fn fsck_fat_accepts_a_64_mib_image() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let options = rufus_options();
    let (geometry, format_elapsed) =
        formatted_image(&path, 64 * MIB, 512, &options).expect("the 64 MiB image formats");
    eprintln!("64 MiB format: {format_elapsed:.3} s");

    // the pinned small-class values (engineered table, machine checked)
    assert_eq!(geometry.sectors_per_cluster, 1, "512-byte clusters");
    assert_eq!(geometry.fat_sectors, 1009, "the slack lands on 1009");
    assert_eq!(geometry.cluster_count, 129_022);
    assert_image_self_consistent(dir.path(), &geometry, 512, true);

    let started = Instant::now();
    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    let fsck_elapsed = started.elapsed().as_secs_f64();
    if skip_without_tool(&fsck, "fsck.fat", "the 64 MiB image acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the 64 MiB image acceptance");
    eprintln!("64 MiB fsck: {fsck_elapsed:.3} s");
}

/// The 2 GiB acceptance, formatted without a label so the NO-NAME
/// path meets the checker too. Measured on this machine: format
/// 0.002 s, fsck 0.017 s.
#[test]
fn fsck_fat_accepts_a_2_gib_image() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let options = FormatOptions {
        label: None,
        volume_id: VOLUME_ID,
        oem: DEFAULT_OEM,
    };
    let (geometry, format_elapsed) =
        formatted_image(&path, 2 * GIB, 512, &options).expect("the 2 GiB image formats");
    eprintln!("2 GiB format: {format_elapsed:.3} s");

    assert_eq!(
        geometry.sectors_per_cluster, 8,
        "4 KiB clusters under 8 GiB"
    );
    assert_eq!(geometry.cluster_count, 523_261);
    assert_image_self_consistent(dir.path(), &geometry, 512, false);

    let started = Instant::now();
    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    let fsck_elapsed = started.elapsed().as_secs_f64();
    if skip_without_tool(&fsck, "fsck.fat", "the 2 GiB image acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the 2 GiB image acceptance");
    eprintln!("2 GiB fsck: {fsck_elapsed:.3} s");
}

/// The 32 GiB large-FAT32 acceptance: the 64 KiB cluster tier is the
/// whole point, and fsck.fat's clean read of the result. Measured on
/// this machine: format 0.006 s, fsck 0.020 s — far inside the slice
/// brief's ~5 s budget for writing the two ~2 MB FATs plus the check.
#[test]
fn large_fat32_uses_64_kib_clusters_at_32_gib() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let options = FormatOptions {
        label: None,
        volume_id: VOLUME_ID,
        oem: DEFAULT_OEM,
    };
    let started = Instant::now();
    let (geometry, _) =
        formatted_image(&path, 32 * GIB, 512, &options).expect("the 32 GiB image formats");

    // the geometry assertions stand whether or not the tool exists
    assert_eq!(geometry.sectors_per_cluster, 128, "64 KiB clusters");
    assert_eq!(
        geometry.cluster_bytes(),
        65_536,
        "large FAT32 cluster bytes"
    );
    assert_eq!(
        geometry.fat_sectors, 4097,
        "the FAT fits the tier's 524,223 clusters"
    );

    assert_image_self_consistent(dir.path(), &geometry, 512, false);
    let format_elapsed = started.elapsed().as_secs_f64();
    eprintln!("32 GiB format: {format_elapsed:.3} s");

    let started = Instant::now();
    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    let fsck_elapsed = started.elapsed().as_secs_f64();
    if skip_without_tool(&fsck, "fsck.fat", "the 32 GiB large FAT32 acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the 32 GiB large FAT32 acceptance");
    eprintln!("32 GiB fsck: {fsck_elapsed:.3} s");
}

/// The 2 TiB law itself: the largest volume the formatter accepts, at
/// 512-byte sectors one sector shy of a u32 sector field — with the
/// solver's fixed point, FAT size and cluster count pinned **without**
/// any I/O, plus the real sparse-image run. The brief's "if you can
/// afford a real 2 TiB sparse format + fsck under ~30 s, do it" is
/// comfortably met: measured 0.084 s to format (the two 134 MB FAT
/// copies through the bounded 64 KiB chunks) and 0.722 s for fsck.
#[test]
fn two_tib_geometry_is_exact() {
    // geometry only, exactly the numbers the 2 TiB wall implies
    let g = geometry(2 * TIB - MIB, 512).expect("2 TiB minus 1 MiB is in range");
    assert_eq!(
        g.total_sectors, 4_294_965_248_u32,
        "still fits the 32-bit boot sector field"
    );
    assert_eq!(g.sectors_per_cluster, 128, "large FAT32");
    assert_eq!(g.cluster_count, 33_550_320, "≈33.5M clusters");
    assert_eq!(
        g.fat_length_bytes(),
        134_201_856,
        "≈134 MB per FAT copy (the +1 slack included)"
    );
    // no overflow anywhere the formatter would write: every rootable
    // cluster resolves inside the volume's byte length
    let last = g
        .cluster_offset(g.cluster_count + 1)
        .expect("the largest cluster number resolves");
    assert!(
        last < 2 * TIB - MIB,
        "the last cluster ends inside the 2 TiB cap"
    );

    // The real 2 TiB sparse run (268 MB of FAT copies + fsck over a
    // 536 MB FAT pair): measured on this machine it takes 0.084 s to
    // format and 0.722 s for fsck — well inside the brief's 30 s
    // window, so the run stays in and the brief's "if you can afford
    // it" clause is met. The geometry pins above already carry the 2
    // TiB limit proof for less capable hosts.
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let options = rufus_options();
    let started = Instant::now();
    let (formatted, _) = formatted_image(&path, 2 * TIB - MIB, 512, &options)
        .expect("the 2 TiB sparse image formats");
    let format_elapsed = started.elapsed().as_secs_f64();
    eprintln!("2 TiB format: {format_elapsed:.3} s");
    assert_eq!(
        formatted, g,
        "the I/O run agrees with the geometry-only numbers"
    );
    assert_image_self_consistent(dir.path(), &formatted, 512, true);

    let started = Instant::now();
    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    let fsck_elapsed = started.elapsed().as_secs_f64();
    if skip_without_tool(&fsck, "fsck.fat", "the 2 TiB image acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the 2 TiB image acceptance");
    eprintln!("2 TiB fsck: {fsck_elapsed:.3} s");
}

/// The end-to-end acceptance: build a real three-level tree with an LFN
/// name and a 300 KiB payload, flush it, read it back through the API,
/// and then let `fsck.fat -n` judge the result. This is the check that
/// the formatter, the allocator, the LFN runs and the chain bookkeeping
/// all agree with an independent implementation.
#[test]
fn a_written_tree_stays_fsck_clean() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let volume = FileVolume::create(&path, 64 * MIB, 512).expect("the sparse image");
    let mut fs = Fat32::format(Box::new(volume), &rufus_options()).expect("the image formats");

    fs.mkdir("/a").expect("mkdir a");
    fs.mkdir("/a/b").expect("mkdir a/b");
    fs.mkdir("/a/b/c").expect("mkdir a/b/c");

    let size = 300 * 1024;
    let payload: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    fs.create_file("/a/b/c/file.bin", size)
        .expect("create file.bin");
    fs.write_at("/a/b/c/file.bin", 0, &payload)
        .expect("write the payload");
    fs.create_file("/a/notes.txt", 11)
        .expect("create notes.txt");
    fs.write_at("/a/notes.txt", 0, b"hello world")
        .expect("write the notes");
    fs.create_file("/a/The Quick Brown Fox.txt", 4)
        .expect("create a long-named file");
    // a twenty-piece run: a directory growth plus the longest legal name
    let longest = format!("{}.bin", "z".repeat(251));
    fs.create_file(&format!("/a/{longest}"), 8)
        .expect("create the longest legal name");
    // six pieces: the physical order is 6|0x40, then plain 5, 4, 3, 2,
    // 1, so one slot's raw byte is 0x05 - the "deleted" alias the reader
    // and the free-slot scan must not apply to long-name pieces
    let six_pieces = format!("{}.dat", "y".repeat(62));
    fs.create_file(&format!("/a/{six_pieces}"), 4)
        .expect("create a six-piece long name");
    // a refused create must leave nothing behind for fsck to reclaim
    let refused = format!("{}.refused", "x".repeat(252));
    fs.create_file(&format!("/a/{refused}"), 0)
        .expect_err("one unit past the long-name limit is refused");
    fs.flush().expect("flush the tree");

    // the API reads its own tree back before any tool judges it
    assert_eq!(
        fs.read_file("/a/b/c/file.bin").expect("read file.bin"),
        payload
    );
    assert_eq!(
        fs.read_file("/a/notes.txt").expect("read notes.txt"),
        b"hello world"
    );
    let listing = fs.list_dir("/a").expect("list a");
    for expected in [
        "The Quick Brown Fox.txt",
        longest.as_str(),
        six_pieces.as_str(),
    ] {
        assert!(
            listing.iter().any(|entry| entry.name == expected),
            "the long name {expected:?} survives the flush"
        );
    }
    drop(fs);

    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    if skip_without_tool(&fsck, "fsck.fat", "the written-tree acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the written-tree acceptance");
}

/// The loop-device guard: attach the image, hand out the node, and
/// detach it on every exit path.
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

fn is_root() -> bool {
    // euid 0 is the only thing that can mount; a non-root run reports a
    // skip rather than pretending the check passed.
    std::fs::metadata("/proc/self").is_ok()
        && Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

/// The kernel acceptance: a real vfat mount of the tree this crate wrote.
/// The PLAN's "a Linux host mounts a three-level tree" step. Needs root
/// and a loop device, so it is `#[ignore]`d:
///
/// ```text
/// sudo -E $(which cargo) test --offline -p rufus-core --test fat32_format -- --ignored --nocapture
/// ```
#[test]
#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
fn the_kernel_mounts_the_written_tree() {
    if !is_root() {
        eprintln!("skip: mounting needs root; run the documented sudo command");
        return;
    }
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let volume = FileVolume::create(&path, 64 * MIB, 512).expect("the sparse image");
    let mut fs = Fat32::format(Box::new(volume), &rufus_options()).expect("the image formats");
    fs.mkdir("/a").expect("mkdir a");
    fs.mkdir("/a/b").expect("mkdir a/b");
    fs.mkdir("/a/b/c").expect("mkdir a/b/c");
    fs.create_file("/a/b/c/file.bin", 4096)
        .expect("create file.bin");
    fs.write_at("/a/b/c/file.bin", 0, b"the kernel reads this")
        .expect("write");
    fs.create_file("/a/The Quick Brown Fox.txt", 4)
        .expect("create the long name");
    fs.flush().expect("flush");
    drop(fs);

    let attached = Command::new("losetup")
        .args(["--find", "--show", "--direct-io=off"])
        .arg(&path)
        .output()
        .expect("losetup runs");
    assert!(
        attached.status.success(),
        "losetup failed: {}",
        String::from_utf8_lossy(&attached.stderr)
    );
    let device = String::from_utf8_lossy(&attached.stdout).trim().to_owned();
    assert!(!device.is_empty(), "losetup printed no node");
    let mountpoint = dir.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("mountpoint");
    let mounted = Command::new("mount")
        .args(["-t", "vfat", "-o", "ro"])
        .arg(&device)
        .arg(&mountpoint)
        .output()
        .expect("mount runs");
    let guard = Mounted {
        device: device.clone(),
        mountpoint: mountpoint.clone(),
    };
    assert!(
        mounted.status.success(),
        "mounting {device} failed: {}",
        String::from_utf8_lossy(&mounted.stderr)
    );
    let payload = std::fs::read(mountpoint.join("a/b/c/file.bin")).expect("the kernel path");
    assert_eq!(&payload[..21], b"the kernel reads this");
    assert!(mountpoint.join("a/The Quick Brown Fox.txt").exists());
    let listing = std::fs::read_dir(mountpoint.join("a")).expect("list a");
    assert_eq!(listing.count(), 2, "a holds the directory and the file");
    drop(guard);
}

/// `mtools` reads the tree independently of the kernel and of
/// `fsck.fat` — a third opinion on the same bytes. `mdir`/`mcopy` are
/// not part of util-linux and are absent from most build hosts, so a
/// missing tool prints the maintainer command instead of passing
/// silently.
#[test]
fn mtools_agrees_with_the_written_tree() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let volume = FileVolume::create(&path, 64 * MIB, 512).expect("the sparse image");
    let mut fs = Fat32::format(Box::new(volume), &rufus_options()).expect("the image formats");
    fs.mkdir("/m").expect("mkdir m");
    fs.create_file("/m/notes.txt", 5).expect("create notes.txt");
    fs.write_at("/m/notes.txt", 0, b"hello").expect("write");
    fs.flush().expect("flush");
    drop(fs);

    let image = path.to_str().expect("utf8 path");
    // `-i <image>` only: the image carries no partition table, so the
    // filesystem starts at offset zero. `@@1M` would read 1 MiB in,
    // inside the second FAT.
    let listing = run_tool("mdir", &["-i", image, "::/m"]);
    if skip_without_tool(&listing, "mdir", "the mtools cross-check") {
        eprintln!(
            "maintainer command: mdir -i '{image}' ::/m  (expect notes.txt, 5 bytes); \
             mtools is absent here, so this shape is unverified on this host"
        );
        return;
    }
    assert!(
        listing.ran.is_some_and(|status| status.success()),
        "mdir failed: {}",
        listing.text()
    );
    assert!(
        listing.text().contains("notes.txt"),
        "mtools lists the file: {}",
        listing.text()
    );

    let copied = dir.path().join("copy.txt");
    let mcopy = run_tool(
        "mcopy",
        &[
            "-i",
            image,
            "::/m/notes.txt",
            copied.to_str().expect("utf8 path"),
        ],
    );
    if skip_without_tool(&mcopy, "mcopy", "the mtools cross-check") {
        return;
    }
    assert!(
        mcopy.ran.is_some_and(|status| status.success()),
        "mcopy failed: {}",
        mcopy.text()
    );
    assert_eq!(
        std::fs::read(&copied).expect("the copy"),
        b"hello",
        "mtools reads the same bytes"
    );
}

/// The guard in [`assert_fsck_clean`] must reject a damaged image that
/// `fsck.fat` still blesses with exit 0. The damage here is the measured
/// shape: the backup boot sector is wiped, so `fsck` prints "There are
/// differences between boot sector and its backup." and returns 0.
///
/// This test exists because a mutation clobbering sector 6 once survived
/// the whole suite: a guard scanning only for the word "error" cannot see
/// that line.
#[test]
fn the_fsck_guard_rejects_a_wiped_backup_boot_sector() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let volume = FileVolume::create(&path, 64 * MIB, 512).expect("the sparse image");
    let mut fs = Fat32::format(Box::new(volume), &rufus_options()).expect("the image formats");
    fs.flush().expect("the layout is on disk");
    drop(fs);

    // Wipe only the backup boot sector at sector 6. The primary must stay
    // intact: zeroing it too makes `fsck.fat` refuse with "Logical sector
    // size is zero" and exit 1, which would exercise the exit-status branch
    // instead of the damage-phrase scan this test exists to pin.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the image opens");
    use std::os::unix::fs::FileExt;
    file.write_all_at(&[0u8; 512], 6 * 512).expect("the wipe");
    file.sync_all().expect("sync");
    drop(file);

    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    if skip_without_tool(&fsck, "fsck.fat", "the fsck guard acceptance") {
        return;
    }
    assert!(
        !fsck_problems(&fsck).is_empty(),
        "the guard must reject a wiped backup boot sector, but it saw it as clean:\n{}",
        fsck.text()
    );
}

/// A 4096-byte-sector image exercises the small-volume tier where the
/// cluster would otherwise be smaller than one sector: the geometry
/// clamp lifts it to a single sector, and the result must still be a
/// filesystem `fsck.fat` accepts.
#[test]
fn a_four_kn_image_formats_and_stays_fsck_clean() {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let path = FileVolume::path(dir.path());
    let volume = FileVolume::create(&path, 260 * MIB, 4096).expect("the sparse image");
    let mut fs = Fat32::format(Box::new(volume), &rufus_options()).expect("the image formats");
    assert_eq!(fs.geometry().bytes_per_sector, 4096);
    assert!(
        fs.geometry().cluster_bytes() >= 4096,
        "a cluster spans at least one 4 Kn sector"
    );
    fs.mkdir("/kn").expect("mkdir");
    fs.create_file("/kn/a.txt", 3).expect("create");
    fs.write_at("/kn/a.txt", 0, b"abc").expect("write");
    fs.flush().expect("flush");
    assert_eq!(fs.read_file("/kn/a.txt").expect("read"), b"abc");
    drop(fs);

    let fsck = run_tool("fsck.fat", &["-n", path.to_str().expect("utf8 path")]);
    if skip_without_tool(&fsck, "fsck.fat", "the 4 Kn acceptance") {
        return;
    }
    assert_fsck_clean(&fsck, "the 4 Kn acceptance");
}
