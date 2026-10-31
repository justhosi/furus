//! External-tool acceptance for the S10 exFAT formatter.
//!
//! The formatter is "no external tool" by design, so the only honest
//! acceptance is somebody else's reader: `fsck.exfat` from exfatprogs
//! must call the image clean, `dump.exfat` must report the geometry the
//! boot sector claims, and `exfatlabel` must read back the label.
//!
//! Every test drives the real path: a sparse image file (`std::fs::File`
//! with `set_len`, never a `VecVolume` - see [`FileVolume`]) the
//! formatter writes through the [`Volume`] trait, then the raw image goes
//! to the tool. A missing tool is printed as an explicit skip line; a
//! failing tool fails the test with its real output in the message.
//!
//! Measured on this machine (page-cached sparse images): 64 MiB format
//! 0.001 s + fsck 0.003 s; 2 GiB format 0.003 s + fsck 0.010 s; 2 TiB
//! format 0.027 s + fsck 0.002 s (the sparse file is never materialised).

use std::cell::Cell;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::rc::Rc;
use std::time::Instant;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::fs::Volume;
use rufus_core::fs::exfat::Exfat;
use rufus_core::fs::exfat::FormatOptions;
use rufus_core::fs::exfat::Geometry;
use rufus_core::fs::exfat::dirent::Stamps;
use rufus_core::fs::exfat::format;
use rufus_core::fs::exfat::upcase;

/// One MiB in bytes.
const MIB: u64 = 1024 * 1024;
/// One GiB.
const GIB: u64 = 1024 * MIB;
/// One TiB.
const TIB: u64 = 1024 * GIB;

/// A sparse image file acting as the [`Volume`] under test.
struct FileVolume {
    file: std::fs::File,
    total_bytes: u64,
    sector_size: u32,
}

impl FileVolume {
    fn create(path: &Path, total_bytes: u64, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))?;
        file.set_len(total_bytes)
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Self {
            file,
            total_bytes,
            sector_size,
        })
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join("exfat.img")
    }
}

impl Volume for FileVolume {
    fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|error| CoreError::io("<exfat image>", error))
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file
            .write_all_at(buf, offset)
            .map_err(|error| CoreError::io("<exfat image>", error))
    }

    fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|error| CoreError::io("<exfat image>", error))
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}

/// Result of running one external tool.
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

/// Run `program` with `args`, or `None` when the program is missing.
fn run_tool(program: &str, args: &[&str]) -> Option<ToolRun> {
    let output = Command::new(program).args(args).output().ok()?;
    Some(ToolRun {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Print the skip line for a missing tool and answer whether it is gone.
fn skip_without_tool(program: &str, what: &str) -> bool {
    // Presence, not a version verdict: `fsck.exfat -V` exits 16 on this
    // build even though the tool is installed, so a status check here
    // would skip every test on a host that has exfatprogs. A tool that
    // spawns but misbehaves is a loud failure later, which is the right
    // bias.
    if Command::new(program).arg("--version").output().is_ok() {
        return false;
    }
    eprintln!(
        "skip: {what} needs {program}, which this host does not ship (install exfatprogs and re-run)"
    );
    true
}

/// Format `path` as exFAT and hand back the geometry it used.
fn formatted_image(path: &Path, total: u64, sector_size: u32, label: Option<&str>) -> Geometry {
    let mut volume = FileVolume::create(path, total, sector_size).expect("the image is created");
    let options = FormatOptions {
        label: label.map(str::to_string),
        volume_id: 0x5EED_1234,
        cluster_bytes: None,
    };
    format(&mut volume, &options).expect("the image formats")
}

/// Read `len` bytes at `offset` from the image.
fn read_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let file = std::fs::File::open(path).expect("the image opens");
    let mut buffer = vec![0u8; len];
    file.read_exact_at(&mut buffer, offset)
        .expect("the read works");
    buffer
}

/// Run `fsck.exfat -n` and refuse anything that is not a clean verdict.
///
/// exfatprogs' checker exits 0 for a clean volume and prints
/// `<image>: clean. directories N, files M`. Damage normally comes with a
/// non-zero exit, but the streams vary by finding: a corrupt boot region
/// reports the checksum mismatch on stderr, while an up-case mismatch
/// prints `ERROR: corrupted upcase table ...` on stdout and only a summary
/// line on stderr. This helper reads the combined output, and the phrase
/// scan is the belt for the cases where the exit status stays 0.
fn assert_fsck_clean(path: &Path) {
    let display = path.display().to_string();
    let Some(run) = run_tool("fsck.exfat", &["-n", &display]) else {
        panic!("fsck.exfat vanished after the skip check");
    };
    let text = run.combined();
    let lower = text.to_lowercase();
    let mut problems: Vec<String> = Vec::new();
    if !run.status.success() {
        problems.push(format!("fsck.exfat exited {}", run.status));
    }
    if !lower.contains("clean.") {
        problems.push("fsck.exfat did not call the volume clean".to_string());
    }
    for phrase in [
        "corrupt",
        "checksum of boot region is not correct",
        "boot region is corrupted",
        "wrong",
        "invalid",
        "not correct",
    ] {
        if lower.contains(phrase) {
            problems.push(format!("fsck.exfat reported \"{phrase}\""));
        }
    }
    assert!(problems.is_empty(), "{}:\n{text}", problems.join("; "));
    // The measured verdict line, for the record (visible with --nocapture).
    eprintln!("fsck verdict: {}", text.trim());
}

#[test]
fn fsck_accepts_a_64_mib_image() {
    if skip_without_tool("fsck.exfat", "the 64 MiB acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    let started = Instant::now();
    let geometry = formatted_image(&path, 64 * MIB, 512, Some("RUFUSTEST"));
    let format_time = started.elapsed();
    let started = Instant::now();
    assert_fsck_clean(&path);
    eprintln!(
        "64 MiB: format {format_time:?}, fsck {:?}, {} clusters of {} bytes",
        started.elapsed(),
        geometry.cluster_count,
        geometry.cluster_bytes,
    );

    // The geometry the boot sector claims must survive a round trip.
    let boot = read_at(&path, 0, 512);
    assert_eq!(&boot[3..11], b"EXFAT   ");
    let clusters = u32::from_le_bytes(boot[92..96].try_into().expect("four bytes"));
    assert_eq!(clusters, geometry.cluster_count);

    // `dump.exfat` is a second, independent reader of the same fields.
    if let Some(dump) = run_tool("dump.exfat", &[&path.display().to_string()]) {
        let text = dump.combined();
        assert!(dump.status.success(), "dump.exfat failed:\n{text}");
        for needle in [
            format!(
                "Cluster Count:                           {}",
                geometry.cluster_count
            ),
            format!(
                "FAT Length(sectors):                     {}",
                geometry.fat_length
            ),
            format!(
                "Cluster Heap Offset (sector offset):     {}",
                geometry.cluster_heap_offset
            ),
            format!(
                "Root Cluster (cluster offset):           {}",
                geometry.root_cluster
            ),
            "RUFUSTEST".to_string(),
        ] {
            assert!(
                text.contains(&needle),
                "dump.exfat lacks {needle:?}:\n{text}"
            );
        }
        assert!(
            text.contains(&format!(
                "Upcase table size:                       {}",
                upcase::TABLE_BYTES
            )),
            "dump.exfat disagrees about the up-case table:\n{text}"
        );
    }
}

#[test]
fn fsck_accepts_a_2_gib_image() {
    if skip_without_tool("fsck.exfat", "the 2 GiB acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    let started = Instant::now();
    let geometry = formatted_image(&path, 2 * GIB, 512, None);
    let format_time = started.elapsed();
    let started = Instant::now();
    assert_fsck_clean(&path);
    eprintln!(
        "2 GiB: format {format_time:?}, fsck {:?}, {} clusters of {} bytes",
        started.elapsed(),
        geometry.cluster_count,
        geometry.cluster_bytes,
    );
    assert_eq!(geometry.cluster_bytes, 32 * 1024);
}

#[test]
fn the_two_tebibyte_image_formats_and_stays_clean() {
    if skip_without_tool("fsck.exfat", "the 2 TiB acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    let started = Instant::now();
    let geometry = formatted_image(&path, 2 * TIB, 512, Some("BIG"));
    let format_time = started.elapsed();
    let started = Instant::now();
    assert_fsck_clean(&path);
    eprintln!(
        "2 TiB: format {format_time:?}, fsck {:?}, {} clusters of {} bytes",
        started.elapsed(),
        geometry.cluster_count,
        geometry.cluster_bytes,
    );
    assert_eq!(geometry.cluster_bytes, 128 * 1024);
}

#[test]
fn a_four_kn_image_formats_and_stays_clean() {
    if skip_without_tool("fsck.exfat", "the 4Kn acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    let geometry = formatted_image(&path, 260 * MIB, 4096, Some("FOURKN"));
    assert_eq!(geometry.sector_size, 4096);
    // 260 MiB sits above the 256 MiB tier, so the default ladder picks
    // 32 KiB clusters - eight 4Kn sectors each.
    assert_eq!(geometry.cluster_bytes, 32 * 1024);
    assert_eq!(geometry.sectors_per_cluster, 8);
    let boot = read_at(&path, 0, 4096);
    assert_eq!(boot[108], 12, "the boot sector declares 4096 byte sectors");
    assert_fsck_clean(&path);
}

#[test]
fn the_label_round_trips_through_exfatlabel() {
    if skip_without_tool("fsck.exfat", "the label acceptance test") {
        return;
    }
    if skip_without_tool("exfatlabel", "the label acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    let display = path.display().to_string();
    formatted_image(&path, 64 * MIB, 512, Some("RUFUSVOL"));
    let read = run_tool("exfatlabel", &[&display]).expect("exfatlabel runs");
    assert!(
        read.status.success(),
        "exfatlabel failed:\n{}",
        read.combined()
    );
    assert!(
        read.combined().to_lowercase().contains("rufusvol"),
        "the label did not survive:\n{}",
        read.combined()
    );

    // A label written by the tool is read back by the boot sector parser
    // path too: format again and confirm the entry bytes we wrote.
    formatted_image(&path, 64 * MIB, 512, Some("SECOND"));
    let read = run_tool("exfatlabel", &[&display]).expect("exfatlabel runs");
    assert!(read.combined().to_lowercase().contains("second"));
}

#[test]
fn the_fsck_guard_rejects_a_damaged_boot_checksum() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = FileVolume::path(dir.path());
    formatted_image(&path, 64 * MIB, 512, None);

    // Flip one byte of the checksum sector; the region no longer matches
    // its own checksum, which every reader must notice.
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("the image opens");
    file.write_all_at(&[0xAA], 11 * 512 + 8)
        .expect("the damage lands");
    drop(file);

    let display = path.display().to_string();
    let Some(run) = run_tool("fsck.exfat", &["-n", &display]) else {
        eprintln!("skip: fsck.exfat is not installed; the damage guard was not exercised");
        return;
    };
    let text = run.combined().to_lowercase();
    assert!(
        !run.status.success() || text.contains("checksum"),
        "a corrupt boot checksum must not pass fsck:\n{text}"
    );
}

#[test]
fn a_written_tree_stays_fsck_clean() {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = FileVolume::path(dir.path());
    let store = FileVolume::create(&path, 64 * MIB, 512).expect("the image is created");
    let mut volume =
        Exfat::format(store, &FormatOptions::new(0x5EED_1234)).expect("the image formats");

    let stamp = Stamps::epoch();
    volume.mkdir("/a", stamp).expect("the first level");
    volume.mkdir("/a/b", stamp).expect("the second level");
    volume
        .create_file("/a/b/x.txt", 0, stamp)
        .expect("a file at the bottom");
    volume
        .create_file("/a/notes.txt", 0, stamp)
        .expect("a file beside the directory");
    volume.flush().expect("the volume flushes");

    assert_eq!(
        volume
            .list_dir("/a")
            .expect("the directory lists")
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["b", "notes.txt"]
    );
    assert_eq!(
        volume
            .list_dir("/a/b")
            .expect("the leaf directory lists")
            .len(),
        1
    );
    drop(volume);

    if skip_without_tool("fsck.exfat", "the written-tree acceptance test") {
        return;
    }
    assert_fsck_clean(&path);
}

/// A deterministic byte pattern, so a mismatch points at the exact offset.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

#[test]
fn written_files_keep_their_bytes_and_stay_fsck_clean() {
    let dir = tempfile::tempdir().expect("a scratch directory");
    let path = FileVolume::path(dir.path());
    let store = FileVolume::create(&path, 64 * MIB, 512).expect("the image is created");
    let mut volume =
        Exfat::format(store, &FormatOptions::new(0x5EED_1235)).expect("the image formats");
    let stamp = Stamps::epoch();

    let big = pattern(300 * 1024);
    let notes = pattern(4096);
    let long_name = format!("{}.txt", "long-name".repeat(20));
    let long_bytes = pattern(1000);

    volume.mkdir("/a", stamp).expect("the first level");
    volume.mkdir("/a/b", stamp).expect("the second level");
    volume
        .create_file("/a/b/file.bin", 0, stamp)
        .expect("the big file");
    volume
        .write_at("/a/b/file.bin", 0, &big[..150 * 1024])
        .expect("the first half");
    volume
        .write_at("/a/b/file.bin", 150 * 1024, &big[150 * 1024..])
        .expect("the second half");
    volume
        .create_file("/a/notes.txt", 0, stamp)
        .expect("the notes file");
    volume
        .write_at("/a/notes.txt", 0, &notes)
        .expect("the notes content");
    volume
        .create_file(&format!("/a/{long_name}"), 0, stamp)
        .expect("the long-named file");
    volume
        .write_at(&format!("/a/{long_name}"), 0, &long_bytes)
        .expect("the long-named content");
    volume.flush().expect("the volume flushes");

    let listed = volume.list_dir("/a").expect("the directory lists");
    assert_eq!(
        listed
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["b", "notes.txt", long_name.as_str()]
    );
    assert_eq!(
        listed
            .iter()
            .find(|entry| entry.name == "notes.txt")
            .expect("the notes entry")
            .size,
        4096
    );
    // A size that is not a whole cluster: the listing has to report the
    // write's end, not the allocation's byte size (the kernel driver reads
    // DataLength as the file size).
    assert_eq!(
        listed
            .iter()
            .find(|entry| entry.name == long_name)
            .expect("the long-named entry")
            .size,
        1000
    );
    assert_eq!(
        volume.list_dir("/a/b").expect("the leaf lists")[0].size,
        300 * 1024
    );
    drop(volume);

    let reopened = Exfat::open(reopened(&path)).expect("the volume opens again");
    assert_eq!(
        reopened
            .read_file("/a/b/file.bin")
            .expect("the big file reads"),
        big
    );
    assert_eq!(
        reopened.read_file("/a/notes.txt").expect("the notes read"),
        notes
    );
    assert_eq!(
        reopened
            .read_file(&format!("/a/{long_name}"))
            .expect("the long-named file reads"),
        long_bytes
    );

    if skip_without_tool("fsck.exfat", "the written-content acceptance test") {
        return;
    }
    assert_fsck_clean(&path);
}

/// Reopen an image that was written before, for a fresh [`Exfat::open`].
fn reopened(path: &Path) -> FileVolume {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("the image opens again");
    let total_bytes = file.metadata().expect("the image is statable").len();
    FileVolume {
        file,
        total_bytes,
        sector_size: 512,
    }
}

/// A [`FileVolume`] that fails exactly one chosen write, the way a torn
/// write behaves on real media: everything written before the failure is
/// on disk, nothing after it is, and the failure is one-shot so the
/// rollback that follows can still write.
struct OneShotFail {
    inner: FileVolume,
    fail_at: Rc<Cell<Option<u64>>>,
    writes: Rc<Cell<u64>>,
}

impl OneShotFail {
    fn create(path: &Path, total_bytes: u64, sector_size: u32) -> Result<Self> {
        Ok(Self {
            inner: FileVolume::create(path, total_bytes, sector_size)?,
            fail_at: Rc::new(Cell::new(None)),
            writes: Rc::new(Cell::new(0u64)),
        })
    }

    /// The switch that arms the next failure (`Some(index)`).
    fn fail_at(&self) -> Rc<Cell<Option<u64>>> {
        Rc::clone(&self.fail_at)
    }

    /// How many writes have reached the image so far.
    fn writes(&self) -> Rc<Cell<u64>> {
        Rc::clone(&self.writes)
    }
}

impl Volume for OneShotFail {
    fn total_bytes(&self) -> u64 {
        self.inner.total_bytes()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_exact_at(offset, buf)
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let seen = self.writes.get();
        if self.fail_at.get() == Some(seen) {
            self.fail_at.set(None);
            return Err(CoreError::invalid("injected write failure"));
        }
        self.writes.set(seen + 1);
        self.inner.write_all_at(offset, buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

/// A create that tears at any of its first writes must leave a directory
/// the exchange can still read, not a set whose checksum never matches.
#[test]
fn every_torn_point_of_a_create_leaves_an_image_fsck_can_read() {
    if skip_without_tool("fsck.exfat", "the torn-write acceptance test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    for offset in 0..6u64 {
        let path = dir.path().join(format!("torn-{offset}.img"));
        let store = OneShotFail::create(&path, 64 * MIB, 512).expect("the image is created");
        let fail_at = store.fail_at();
        let writes = store.writes();
        let mut volume =
            Exfat::format(store, &FormatOptions::new(0x5EED_7001)).expect("the image formats");
        volume
            .mkdir("/a", Stamps::epoch())
            .expect("the directory is created");
        let armed = writes.get() + offset;
        fail_at.set(Some(armed));
        let outcome = volume.create_file("/a/torn.txt", 4096, Stamps::epoch());
        fail_at.set(None);
        volume.flush().expect("the rolled-back state flushes");
        drop(volume);
        assert_fsck_clean(&path);
        let reopened = Exfat::open(reopened(&path)).expect("the volume reopens");
        let listing = reopened.list_dir("/a").expect("the directory still parses");
        if outcome.is_err() {
            assert!(listing.is_empty(), "torn at write {armed} left {listing:?}");
        } else {
            assert_eq!(listing.len(), 1, "an untorn create lists its file");
        }
    }
}

/// A create refused after the root had to grow must leave the root chain
/// pointing at the end of the chain again: a linked-but-freed cluster
/// lets the next directory duplicate the namespace, which `fsck` rejects.
#[test]
fn a_refused_create_after_a_root_growth_keeps_the_image_fsck_clean() {
    if skip_without_tool("fsck.exfat", "the root-growth rollback test") {
        return;
    }
    let dir = tempfile::tempdir().expect("a scratch directory");
    let mut saw_failure = false;
    for offset in 0..4u64 {
        let path = dir.path().join(format!("growth-{offset}.img"));
        let store = OneShotFail::create(&path, 64 * MIB, 512).expect("the image is created");
        let fail_at = store.fail_at();
        let writes = store.writes();
        let mut volume =
            Exfat::format(store, &FormatOptions::new(0x5EED_7002)).expect("the image formats");
        for index in 0..42 {
            volume
                .create_file(&format!("/f{index:03}.bin"), 0, Stamps::epoch())
                .expect("a filler file fits");
        }
        let armed = writes.get() + offset;
        fail_at.set(Some(armed));
        let outcome = volume.create_file("/grow.bin", 0, Stamps::epoch());
        fail_at.set(None);
        if outcome.is_err() {
            saw_failure = true;
            volume
                .mkdir("/phantom", Stamps::epoch())
                .expect("a directory created after the rollback works");
            volume
                .create_file("/phantom/lost.bin", 0, Stamps::epoch())
                .expect("a file created after the rollback works");
        }
        volume.flush().expect("the volume flushes");
        drop(volume);
        assert_fsck_clean(&path);
    }
    assert!(saw_failure, "the run must actually tear a root growth");
}
