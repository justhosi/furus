//! Loop-device end-to-end acceptance for the S17 pipeline (slice 10,
//! the acceptance slice).
//!
//! What each test proves, on a real block node (`/dev/loopN`) driven
//! through a file-backed [`Target`](rufus_core::pipeline::Target) the
//! suite implements itself (the `FileVolume` precedent of
//! `fat32_format.rs`: `rufus-linux` is not a dependency of these
//! tests, so no `DeviceOpener`/`FileOpener` here — the opener below is
//! ten lines over one open file. (`FileOpener` in particular is out:
//! it refuses non-regular files by design, so a loop node could never
//! go through it; opening the node directly is also the stronger
//! proof — every byte crosses the kernel block layer.)
//!
//! * `raw_write_full_plan_on_a_loop_device` — a full
//!   `[Wipe, Mklabel, Mkpart, Mkfs(Fat32), Write(Dd), Finalize]` plan
//!   with `verify` on: the image bytes land at the target start, the
//!   formatted FAT32 boot sector survives past the image end (the
//!   image stays under the 1 MiB partition base on purpose — a DD
//!   write starts at LBA0, so anything larger would overwrite the
//!   boot sector it just formatted, the same rule the CLI seam suite
//!   pins), `fsck.fat -n` accepts the extracted partition, and the
//!   [`RunReport`](rufus_core::pipeline::RunReport) names every step.
//! * `compressed_write_decodes_gzip_on_a_loop_device` — the same
//!   image through the host `gzip` binary: the decoded bytes land
//!   byte-identical.
//! * `sparse_write_zeroes_holes_on_a_loop_device` — a genuinely
//!   sparse image (4 KiB islands at 0 and 4 MiB over a hole) with a
//!   fixture-pinned hole map (the `SEEK_DATA` discovery itself is
//!   covered by `rufus-linux`'s own `data_ranges` tests; pinning the
//!   map here exercises the sparse write path deterministically):
//!   islands match, the hole reads back as zeros even though the
//!   target was prefilled with `0xAA`.
//! * `verify_failure_names_the_byte_on_a_loop_device` — a target
//!   wrapper flipping one read-back byte: the run refuses as
//!   `step 'write'` wrapping [`Verify`](rufus_core::error::CoreError::Verify)
//!   naming the offset (the shape the CLI maps to exit class Io).
//! * `pipeline_matches_dd_throughput` — 4 GiB through the pipeline
//!   against `dd` at the same 256 KiB chunking (see its docs for the
//!   null-target methodology and the release-mode requirement).
//!
//! Privilege policy, following the formatter suites: every
//! loop-device test is `#[ignore]`d (the default suite never needs
//! privilege) and returns after one `eprintln!` skip line when not
//! root or when `losetup` is absent. The loop node is detached by a
//! [`Mounted`](common::Mounted) guard on every exit path, failure
//! included. The throughput test needs no privilege (null targets,
//! tempfiles) but stays `#[ignore]`d for its cost.
//!
//! Run them on a privileged host with:
//!
//! ```sh
//! export PATH="$HOME/.cargo/bin:$PATH"
//! cargo test --offline -p rufus-core --test pipeline_end_to_end -- --ignored --nocapture
//! ```
//!
//! and the throughput comparison in release mode (debug timings are
//! meaningless against the optimised `dd` binary):
//!
//! ```sh
//! export PATH="$HOME/.cargo/bin:$PATH"
//! cargo test --offline --release -p rufus-core --test pipeline_end_to_end pipeline_matches_dd_throughput -- --ignored --nocapture
//! ```

mod common;

use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use common::Mounted;
use common::attach_loop;
use common::is_root;
use common::pattern;
use common::read_at;
use common::run_tool;
use common::sparse_image;

use rufus_core::error::CoreError;
use rufus_core::error::Result;
use rufus_core::fs::Volume;
use rufus_core::part::TableKind;
use rufus_core::part::plan::single_data_window;
use rufus_core::pipeline::Event;
use rufus_core::pipeline::NullReporter;
use rufus_core::pipeline::Opener;
use rufus_core::pipeline::Reporter;
use rufus_core::pipeline::RunOptions;
use rufus_core::pipeline::Target;
use rufus_core::pipeline::run;
use rufus_proto::DeviceRef;
use rufus_proto::Filesystem;
use rufus_proto::ImageKind;
use rufus_proto::ImageRef;
use rufus_proto::Options;
use rufus_proto::PLAN_VERSION;
use rufus_proto::Plan;
use rufus_proto::Scheme;
use rufus_proto::Step;
use rufus_proto::Target as FirmwareTarget;
use rufus_proto::WriteMode;

// ---------------------------------------------------------------------------
// Fixture stores: a file-backed Target and a partition-window Volume
// ---------------------------------------------------------------------------

/// One mebibyte, for window arithmetic in assertions.
const MIB: u64 = 1024 * 1024;

/// Check `[offset, offset + count)` against `len`, naming offset,
/// length and size like the pipeline's own window rule.
fn check_window(len: u64, offset: u64, count: u64, verb: &str) -> Result<()> {
    match offset.checked_add(count) {
        Some(end) if end <= len => Ok(()),
        Some(end) => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, {end}) does not fit the target size {len}"
        ))),
        None => Err(CoreError::invalid(format!(
            "{verb} range [{offset}, ...) overflows past the target size {len}"
        ))),
    }
}

/// A whole-disk [`Target`] over one open file or device node with an
/// explicitly declared extent: the file length for regular files, the
/// known device size for nodes (whose `fstat` length is 0). Zeroing,
/// discard hints and rescans ride the shared default bodies (plain
/// zero writes, best-effort `Ok`, no-op) — the genuine kernel
/// primitives stay behind the privileged helper.
#[derive(Debug)]
struct FileTarget {
    file: File,
    path: PathBuf,
    len: u64,
    /// `fsync` on flush: set for stores with buffers to push (files,
    /// block nodes); clear for `/dev/null`, whose `fsync` answers
    /// `EINVAL` — there is nothing to push through a null sink.
    sync: bool,
}

impl FileTarget {
    fn open(path: &Path, len: u64) -> Result<Self> {
        Self::open_sync(path, len, true)
    }

    fn open_sync(path: &Path, len: u64, sync: bool) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| CoreError::io(path, error))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            len,
            sync,
        })
    }
}

impl Target for FileTarget {
    fn size(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_window(self.len, offset, buf.len() as u64, "read")?;
        self.file
            .read_exact_at(buf, offset)
            .map_err(|error| CoreError::io(&self.path, error))
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        check_window(self.len, offset, buf.len() as u64, "write")?;
        self.file
            .write_all_at(buf, offset)
            .map_err(|error| CoreError::io(&self.path, error))
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        if chunk == 0 {
            return Err(CoreError::invalid("write chunk size must be non-zero"));
        }
        check_window(self.len, offset, buf.len() as u64, "write")?;
        let mut done = 0usize;
        while done < buf.len() {
            if cancelled() {
                return Ok(done as u64);
            }
            let piece = (buf.len() - done).min(chunk);
            self.file
                .write_all_at(&buf[done..done + piece], offset + done as u64)
                .map_err(|error| CoreError::io(&self.path, error))?;
            done += piece;
        }
        Ok(done as u64)
    }

    fn flush(&self) -> Result<()> {
        if !self.sync {
            return Ok(());
        }
        self.file
            .sync_all()
            .map_err(|error| CoreError::io(&self.path, error))
    }
}

/// A [`Volume`] window over one open file at `[base, base + len)`: the
/// data partition the native formatters write, planned with the same
/// [`single_data_window`] call the pipeline stamps with, so the
/// formatted window is the stamped partition by construction.
#[derive(Debug)]
struct PartFile {
    file: File,
    base: u64,
    len: u64,
}

impl Volume for PartFile {
    fn total_bytes(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| CoreError::invalid("test partition read overflows"))?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "test partition read of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.file
            .read_exact_at(buf, self.base + offset)
            .map_err(|error| CoreError::io("<partition window>", error))
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| CoreError::invalid("test partition write overflows"))?;
        if end > self.len {
            return Err(CoreError::invalid(format!(
                "test partition write of {} bytes at offset {offset} runs past the {} byte window at base {}",
                buf.len(),
                self.len,
                self.base
            )));
        }
        self.file
            .write_all_at(buf, self.base + offset)
            .map_err(|error| CoreError::io("<partition window>", error))
    }

    fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|error| CoreError::io("<partition window>", error))
    }

    fn sector_size(&self) -> u32 {
        512
    }
}

/// An [`Opener`] over one path: the whole disk as a [`FileTarget`],
/// the data partition as a [`PartFile`] window. The file-backed
/// opener performs no kernel rescan, so partition byte assertions
/// read through offsets, never through a partition node. `ranges`
/// pins the hole map for the sparse suite (`None` streams straight);
/// `sync` selects the `fsync`-backed flush (cleared for null sinks).
#[derive(Debug, Clone)]
struct LoopOpener {
    path: PathBuf,
    len: u64,
    ranges: Option<Vec<(u64, u64)>>,
    sync: bool,
}

impl Opener for LoopOpener {
    fn device(&self) -> Result<Box<dyn Target>> {
        Ok(Box::new(FileTarget::open_sync(
            &self.path, self.len, self.sync,
        )?))
    }

    fn partition(&self) -> Result<Box<dyn Volume>> {
        let (base, len) = single_data_window(TableKind::Mbr, 512, self.len)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|error| CoreError::io(&self.path, error))?;
        Ok(Box::new(PartFile { file, base, len }))
    }

    fn partition_path(&self) -> Result<PathBuf> {
        // Native filesystems only in these suites: no external
        // formatter ever needs a node.
        Err(CoreError::invalid(
            "the loop suite has no partition node: native filesystems only",
        ))
    }

    fn data_ranges(&self, _path: &Path) -> Result<Option<Vec<(u64, u64)>>> {
        Ok(self.ranges.clone())
    }
}

/// A collecting [`Reporter`] for the failure-shape test.
#[derive(Debug, Default)]
struct Log {
    events: Vec<Event>,
}

impl Reporter for Log {
    fn event(&mut self, event: Event) {
        self.events.push(event);
    }
}

// ---------------------------------------------------------------------------
// Plan and fixture builders
// ---------------------------------------------------------------------------

/// A sealed runnable plan over `device`/`image`: the full six-step
/// chain (`Bootloader` excluded — no slice installs one yet).
fn plan_for(
    device: &str,
    device_len: u64,
    image: &Path,
    image_len: u64,
    digest: &str,
    kind: ImageKind,
    verify: bool,
) -> Plan {
    let mut plan = Plan {
        version: PLAN_VERSION,
        created_by: "pipeline-end-to-end".to_string(),
        device: DeviceRef {
            path: device.to_string(),
            block_device: true,
            size_bytes: Some(device_len),
            serial: None,
            model: None,
            sysfs: None,
        },
        image: ImageRef {
            path: image.display().to_string(),
            size_bytes: image_len,
            sha256: digest.to_string(),
            kind,
        },
        options: Options {
            scheme: Scheme::Mbr,
            target: FirmwareTarget::Dual,
            filesystem: Filesystem::Fat32,
            label: None,
            cluster_bytes: None,
            quick_format: true,
            bad_blocks: false,
            verify,
            persistence: false,
            show_all: false,
            confirmed_serial: None,
        },
        steps: vec![
            Step::Wipe,
            Step::Mklabel {
                scheme: Scheme::Mbr,
            },
            Step::Mkpart {
                scheme: Scheme::Mbr,
            },
            Step::Mkfs {
                filesystem: Filesystem::Fat32,
                label: None,
                cluster_bytes: None,
                quick: true,
            },
            Step::Write {
                mode: WriteMode::Dd,
            },
            Step::Finalize,
        ],
        confirm: String::new(),
    };
    plan.confirm = plan.confirm().expect("the plan seals");
    plan
}

/// [`RunOptions`](rufus_core::pipeline::RunOptions) for the suites:
/// instant retries (a real device that fails a write has nothing
/// honest to retry in a test), no scan, no reset.
fn options(verify: bool) -> RunOptions {
    RunOptions {
        verify,
        badblocks: false,
        retries: 3,
        retry_delay: std::time::Duration::ZERO,
        reset_usb: false,
    }
}

/// Hex SHA-256 over bytes already in memory (small fixtures only).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Skip unless root with `losetup` on PATH: one `eprintln!`, then the
/// caller returns. True means "skipped".
fn skip_privileged(what: &str) -> bool {
    if !is_root() {
        eprintln!("skip: {what} needs root for loop devices (run with --ignored under sudo)");
        return true;
    }
    if run_tool("losetup", &["--version"]).is_none() {
        eprintln!("skip: {what} needs losetup on PATH");
        return true;
    }
    false
}

/// A `len`-byte target file at `dir/stick.img` attached as a loop
/// node: returns the node path and a guard detaching it on every exit
/// path, failure included.
fn loop_target(dir: &tempfile::TempDir, len: u64) -> (String, Mounted) {
    let path = dir.path().join("stick.img");
    sparse_image(&path, len);
    let node = attach_loop(&path, "loop target");
    let guard = Mounted {
        device: node.clone(),
        mountpoint: dir.path().to_path_buf(),
    };
    (node, guard)
}

/// A patterned image with ISO magic (`CD001` at 0x8001, so the
/// planner reads `iso` by content, not by name).
fn raw_image(path: &Path, len: usize) -> Vec<u8> {
    let mut bytes = pattern(len);
    bytes[0x8001..0x8006].copy_from_slice(b"CD001");
    std::fs::write(path, &bytes).expect("the image writes");
    bytes
}

/// Compress `payload` with the host `gzip` binary into `path`;
/// returns `None` (after the skip line) when `gzip` is absent, else
/// the archive bytes for the plan length.
fn gzip_image(path: &Path, payload: &[u8]) -> Option<Vec<u8>> {
    if run_tool("gzip", &["--version"]).is_none() {
        eprintln!("skip: the compressed suite needs gzip on PATH");
        return None;
    }
    let raw = path.with_extension("raw");
    std::fs::write(&raw, payload).expect("the payload writes");
    // `Command` directly, not the text-oriented `run_tool`: the
    // archive is binary.
    let output = Command::new("gzip")
        .arg("-c")
        .arg(&raw)
        .output()
        .expect("host gzip runs");
    assert!(output.status.success(), "gzip compresses");
    std::fs::write(path, &output.stdout).expect("the archive writes");
    Some(output.stdout)
}

/// `fsck.fat -n` over the extracted partition bytes: exit status 0
/// and no error line (dosfstools is known to exit 0 while still
/// reporting repairable errors, so both halves are asserted).
fn check_partition(path: &Path) {
    let fsck = run_tool("fsck.fat", &["-n", &path.display().to_string()]);
    let Some(fsck) = fsck else {
        eprintln!("skip: the fsck half needs fsck.fat on PATH");
        return;
    };
    let combined = fsck.combined();
    assert!(
        fsck.status.success(),
        "fsck.fat accepts the partition: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("error"),
        "fsck.fat reports no error line: {combined}"
    );
}

// ---------------------------------------------------------------------------
// The suites
// ---------------------------------------------------------------------------

/// Full plan with verification on a loop device: image bytes at the
/// target start, the formatted boot sector intact past the image end,
/// `fsck.fat` clean on the partition, every step reported.
#[ignore]
#[test]
fn raw_write_full_plan_on_a_loop_device() {
    if skip_privileged("raw loop write") {
        return;
    }
    let dir = tempfile::tempdir().expect("scratch dir");
    // 512 KiB on purpose: two 256 KiB chunks (multi-chunk proof) that
    // still end before the 1 MiB partition base, so the DD write at
    // LBA0 leaves the formatted boot sector intact.
    let image = raw_image(&dir.path().join("image.iso"), 512 * 1024);
    let digest = sha256_hex(&image);
    const TARGET_LEN: u64 = 64 * MIB;
    let (node, _guard) = loop_target(&dir, TARGET_LEN);
    let opener = LoopOpener {
        path: PathBuf::from(&node),
        len: TARGET_LEN,
        ranges: None,
        sync: true,
    };
    let plan = plan_for(
        &node,
        TARGET_LEN,
        &dir.path().join("image.iso"),
        image.len() as u64,
        &digest,
        ImageKind::Iso,
        true,
    );
    let mut reporter = NullReporter;
    let report = run(&plan, &opener, &options(true), &mut reporter, &|| false)
        .expect("the full plan runs on a loop device");
    assert_eq!(
        report
            .steps
            .iter()
            .map(|step| step.step)
            .collect::<Vec<_>>(),
        ["wipe", "mklabel", "mkpart", "mkfs", "write", "finalize"]
    );
    let node_path = Path::new(&node);
    assert_eq!(
        read_at(node_path, 0, image.len()),
        image,
        "the image bytes land at the target start"
    );
    let boot = read_at(node_path, MIB, 512);
    assert_eq!(
        &boot[82..90],
        b"FAT32   ",
        "the formatted boot sector survives past the image end"
    );
    // The partition through offsets (no kernel rescan behind a
    // file-backed opener): extract and check the exact bytes a rescan
    // would expose.
    let (base, _) = single_data_window(TableKind::Mbr, 512, TARGET_LEN).expect("window plans");
    let check_path = dir.path().join("check.fat");
    std::fs::write(
        &check_path,
        read_at(node_path, base, (TARGET_LEN - base) as usize),
    )
    .expect("the partition extracts");
    check_partition(&check_path);
}

/// The same image gzipped: the decoded bytes land byte-identical.
#[ignore]
#[test]
fn compressed_write_decodes_gzip_on_a_loop_device() {
    if skip_privileged("compressed loop write") {
        return;
    }
    let dir = tempfile::tempdir().expect("scratch dir");
    let payload = raw_image(&dir.path().join("payload.iso"), 512 * 1024);
    let archive_path = dir.path().join("image.gz");
    let Some(archive) = gzip_image(&archive_path, &payload) else {
        return;
    };
    let digest = sha256_hex(&archive);
    const TARGET_LEN: u64 = 64 * MIB;
    let (node, _guard) = loop_target(&dir, TARGET_LEN);
    let opener = LoopOpener {
        path: PathBuf::from(&node),
        len: TARGET_LEN,
        ranges: None,
        sync: true,
    };
    let plan = plan_for(
        &node,
        TARGET_LEN,
        &archive_path,
        archive.len() as u64,
        &digest,
        ImageKind::Gzip,
        false,
    );
    let mut reporter = NullReporter;
    run(&plan, &opener, &options(false), &mut reporter, &|| false)
        .expect("the compressed plan runs on a loop device");
    assert_eq!(
        read_at(Path::new(&node), 0, payload.len()),
        payload,
        "the decoded bytes land byte-identical"
    );
}

/// A genuinely sparse image (4 KiB islands at 0 and 4 MiB over a
/// hole) on a `0xAA`-prefilled target: islands match, the hole reads
/// back as zeros. The hole map is pinned from the fixture (see
/// [`LoopOpener::ranges`]).
#[ignore]
#[test]
fn sparse_write_zeroes_holes_on_a_loop_device() {
    if skip_privileged("sparse loop write") {
        return;
    }
    let dir = tempfile::tempdir().expect("scratch dir");
    const ISLAND: usize = 4096;
    const GAP: u64 = 4 * MIB;
    let image_path = dir.path().join("sparse.img");
    let island0 = pattern(ISLAND);
    let mut island1 = pattern(ISLAND);
    island1[0x801..0x806].copy_from_slice(b"CD001");
    {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&image_path)
            .expect("the sparse image opens");
        file.write_all_at(&island0, 0).expect("island 0 writes");
        file.write_all_at(&island1, GAP).expect("island 1 writes");
        file.set_len(GAP + ISLAND as u64).expect("the image sizes");
    }
    let image_len = GAP + ISLAND as u64;
    // Sanity that the fixture is genuinely sparse (holes cost no
    // blocks); the target assertions below are the proof either way.
    let blocks = std::fs::metadata(&image_path)
        .expect("the image stats")
        .blocks();
    assert!(
        blocks * 512 < image_len,
        "the image file holds holes: {} blocks for {image_len} bytes",
        blocks
    );
    let digest = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&island0);
        hasher.update(vec![0u8; GAP as usize - ISLAND]);
        hasher.update(&island1);
        format!("{:x}", hasher.finalize())
    };
    const TARGET_LEN: u64 = 64 * MIB;
    let target_path = dir.path().join("stick.img");
    std::fs::write(&target_path, vec![0xAAu8; TARGET_LEN as usize]).expect("prefill writes");
    let node = attach_loop(&target_path, "loop target");
    let _guard = Mounted {
        device: node.clone(),
        mountpoint: dir.path().to_path_buf(),
    };
    let opener = LoopOpener {
        path: PathBuf::from(&node),
        len: TARGET_LEN,
        ranges: Some(vec![(0, ISLAND as u64), (GAP, ISLAND as u64)]),
        sync: true,
    };
    let plan = plan_for(
        &node,
        TARGET_LEN,
        &image_path,
        image_len,
        &digest,
        ImageKind::Iso,
        true,
    );
    let mut reporter = NullReporter;
    run(&plan, &opener, &options(true), &mut reporter, &|| false)
        .expect("the sparse plan runs on a loop device");
    let node_path = Path::new(&node);
    assert_eq!(
        read_at(node_path, 0, ISLAND),
        island0,
        "the first island matches"
    );
    assert_eq!(
        read_at(node_path, GAP, ISLAND),
        island1,
        "the second island matches"
    );
    assert!(
        read_at(node_path, ISLAND as u64, (GAP - ISLAND as u64) as usize)
            .iter()
            .all(|&byte| byte == 0),
        "the hole reads back as zeros over the 0xAA prefill"
    );
}

/// A [`Target`] flipping one read-back byte: the write lands intact,
/// but verification reads it torn.
#[derive(Debug)]
struct CorruptTarget {
    inner: FileTarget,
    flip_at: u64,
}

impl Target for CorruptTarget {
    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(offset, buf)?;
        if (offset..offset + buf.len() as u64).contains(&self.flip_at) {
            let at = (self.flip_at - offset) as usize;
            if let Some(byte) = buf.get_mut(at) {
                *byte ^= 0xFF;
            }
        }
        Ok(())
    }

    fn write_all_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.inner.write_all_at(offset, buf)
    }

    fn write_all_at_cancellable(
        &self,
        offset: u64,
        buf: &[u8],
        chunk: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<u64> {
        self.inner
            .write_all_at_cancellable(offset, buf, chunk, cancelled)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }
}

/// An [`Opener`] serving one [`CorruptTarget`].
#[derive(Debug, Clone)]
struct CorruptOpener {
    path: PathBuf,
    len: u64,
    flip_at: u64,
}

impl Opener for CorruptOpener {
    fn device(&self) -> Result<Box<dyn Target>> {
        Ok(Box::new(CorruptTarget {
            inner: FileTarget::open(&self.path, self.len)?,
            flip_at: self.flip_at,
        }))
    }

    fn partition(&self) -> Result<Box<dyn Volume>> {
        let (base, len) = single_data_window(TableKind::Mbr, 512, self.len)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|error| CoreError::io(&self.path, error))?;
        Ok(Box::new(PartFile { file, base, len }))
    }

    fn partition_path(&self) -> Result<PathBuf> {
        Err(CoreError::invalid(
            "the loop suite has no partition node: native filesystems only",
        ))
    }
}

/// Verification reads the torn byte: the run refuses as
/// `step 'write'` wrapping `Verify`, naming the offset — the shape
/// the CLI maps to exit class Io.
#[ignore]
#[test]
fn verify_failure_names_the_byte_on_a_loop_device() {
    if skip_privileged("verify-failure loop write") {
        return;
    }
    let dir = tempfile::tempdir().expect("scratch dir");
    let image = raw_image(&dir.path().join("image.iso"), 512 * 1024);
    let digest = sha256_hex(&image);
    const TARGET_LEN: u64 = 64 * MIB;
    let (node, _guard) = loop_target(&dir, TARGET_LEN);
    let opener = CorruptOpener {
        path: PathBuf::from(&node),
        len: TARGET_LEN,
        flip_at: 100,
    };
    let plan = plan_for(
        &node,
        TARGET_LEN,
        &dir.path().join("image.iso"),
        image.len() as u64,
        &digest,
        ImageKind::Iso,
        true,
    );
    let mut log = Log::default();
    let error = run(&plan, &opener, &options(true), &mut log, &|| false)
        .expect_err("a torn read-back refuses");
    assert!(
        matches!(&error, CoreError::Step { step: "write", source } if matches!(source.as_ref(), CoreError::Verify { .. })),
        "the refusal is step 'write' wrapping Verify: {error:?}"
    );
    assert!(
        error.to_string().contains("offset 100"),
        "the refusal names the byte: {error:?}"
    );
    assert!(
        !log.events
            .iter()
            .any(|event| matches!(event, Event::StepFinished { step: "write", .. })),
        "no success is reported: {:?}",
        log.events
    );
}

// ---------------------------------------------------------------------------
// Throughput: pipeline engine against dd, like-for-like buffered files
// ---------------------------------------------------------------------------

/// Pipeline engine throughput against `dd` at the same 256 KiB
/// chunking, with both numbers printed.
///
/// Methodology (like-for-like, and why): both sides read the same
/// 4 GiB sparse image (zero pages cost both sides identically, so the
/// comparison isolates engine overhead rather than media speed) and
/// write to declared-size `/dev/null` targets with plain buffered
/// I/O — no `O_DIRECT` anywhere, on either side. `/dev/null` is
/// deliberate: `/tmp` on small hosts cannot host GiB-scale real
/// targets, and media speed is device-dependent anyway; what matters
/// is the per-chunk engine cost (loop, progress events, rate
/// tracking), which this test bounds directly (see below). A missing
/// `dd` skips with a message instead of failing.
///
/// The assertion is an absolute per-chunk overhead bound, not a raw
/// rate ratio — deliberately. At page-cache speeds (tens of GB/s) a
/// single extra syscall per chunk moves the ratio by tens of
/// percent, so a ratio bar there measures syscall counts, not engine
/// efficiency; the overhead itself is what transfers across hosts.
/// 13 µs per chunk guarantees ≥95% of `dd` at every rate up to
/// ~1 GB/s (0.05 × 256 KiB / 13 µs ≈ 1.0 GB/s — faster than any USB
/// stick this pipeline will ever meet), and the measured value on
/// this host sits near 4 µs. Both rates print regardless, so a
/// future host can read the ratio off the log.
///
/// Release mode only: `cargo test --offline --release -p rufus-core
/// --test pipeline_end_to_end pipeline_matches_dd_throughput --
/// --ignored --nocapture`. Debug timings against the optimised `dd`
/// binary are meaningless (and fail the bound below).
#[ignore]
#[test]
fn pipeline_matches_dd_throughput() {
    if run_tool("dd", &["--version"]).is_none() {
        eprintln!("skip: the throughput comparison needs dd on PATH");
        return;
    }
    const SIZE: u64 = 4 * 1024 * 1024 * 1024;
    const BS: u64 = 256 * 1024;
    let dir = tempfile::tempdir().expect("scratch dir");
    let image_path = dir.path().join("image.bin");
    sparse_image(&image_path, SIZE);
    // Pipeline side: Write-only plan (the `dd` equivalent — no wipe,
    // format or verify noise) onto a declared-size null target.
    let null = PathBuf::from("/dev/null");
    let opener = LoopOpener {
        path: null.clone(),
        len: SIZE,
        ranges: None,
        sync: false,
    };
    let plan = plan_for(
        "/dev/null",
        SIZE,
        &image_path,
        SIZE,
        &"0".repeat(64),
        ImageKind::Raw,
        false,
    );
    let write_only = Plan {
        steps: vec![Step::Write {
            mode: WriteMode::Dd,
        }],
        ..plan.clone()
    };
    let mut reporter = NullReporter;
    let started = Instant::now();
    run(
        &write_only,
        &opener,
        &options(false),
        &mut reporter,
        &|| false,
    )
    .expect("the throughput write runs");
    let pipeline_secs = started.elapsed().as_secs_f64();
    // `dd` side: identical chunking, identical null sink, quiet.
    let dd_path = image_path.display().to_string();
    let started = Instant::now();
    let status = Command::new("dd")
        .args([
            &format!("if={dd_path}"),
            "of=/dev/null",
            &format!("bs={BS}"),
            "status=none",
        ])
        .status()
        .expect("dd runs");
    assert!(status.success(), "dd copies the image");
    let dd_secs = started.elapsed().as_secs_f64();
    let pipeline_rate = SIZE as f64 / pipeline_secs;
    let dd_rate = SIZE as f64 / dd_secs;
    let chunks = (SIZE / BS) as f64;
    let overhead_secs = (pipeline_secs - dd_secs) / chunks;
    eprintln!(
        "throughput: pipeline {pipeline_rate:.0} B/s ({pipeline_secs:.2} s), dd {dd_rate:.0} B/s ({dd_secs:.2} s), ratio {:.3}, overhead {overhead_secs:.2e} s/chunk",
        pipeline_rate / dd_rate,
    );
    assert!(
        overhead_secs <= 13e-6,
        "the engine costs at most 13 us per chunk (95% of dd up to ~1 GB/s): {overhead_secs:.2e} s measured"
    );
}
