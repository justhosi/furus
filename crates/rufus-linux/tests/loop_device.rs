//! Root-gated integration tests for the S07 [`BlockDevice`]/[`Sink`]
//! surface of `src/block.rs` against a real kernel loop device.
//!
//! Every test in this file attaches its own fresh loop device to a
//! scratch backing image, drives the block-I/O surface through it, and
//! detaches in the teardown. That needs root (attaching a loop device
//! and opening it exclusively are privileged) and a kernel with loop
//! support, so all four tests are `#[ignore]`d by default: a plain
//! `cargo test --workspace` compiles this file and skips every test
//! here, without failing.
//!
//! The manual procedure, verbatim (run once as root after a first
//! unprivileged build, so nothing is compiled under sudo; `$HOME` and
//! the target cache come from the invoking user via `-E`):
//!
//! ```text
//! sudo -E $(which cargo) test --offline -p rufus-linux --test loop_device -- --ignored --nocapture
//! ```
//!
//! What each test drives:
//!
//! * `loop_device_round_trip_matches_written_bytes` - a 4 MiB pattern
//!   written at offset 0 and at a mid-image 4 MiB-aligned offset,
//!   read back byte-identical through the device, with the backing
//!   image cross-checked too;
//! * `zero_range_and_discard_on_a_loop_device` - `zero_range` must
//!   zero a 1 MiB window for real; `discard` is documented best
//!   effort (must not error, medium must stay readable) and
//!   `reread_partitions` must succeed on a live loop node;
//! * `o_direct_writes_match_buffered_writes_when_available` - the
//!   same content comparison across handle kinds: an aligned window
//!   written through the direct descriptor and another through a
//!   plain buffered `std::fs` handle (opened *before* the exclusive
//!   one, so the two handles never coexist), both read back through
//!   the device and compared byte-for-byte (skip note otherwise);
//! * `direct_throughput_is_within_five_percent_of_dd` - 128 MiB
//!   written with `write_all_at_cancellable` against a `dd
//!   oflag=direct` baseline, three passes per side, all samples plus
//!   both medians printed under `--nocapture`, with our median at
//!   least 95 percent of dd's.
//!
//! On a machine without root every test reports a skip through an
//! explanatory message instead of failing: the helpers below never
//! panic when the environment lacks loop-device support, they print
//! the reason and return early (see `LoopDevice::acquire`). The
//! privilege gate is `is_root()` (the effective user id): *without*
//! privileges, an attach failure is the documented skip; *with* them,
//! an acquisition failure is a real failure and `acquire` panics with
//! `losetup`'s actual stderr instead of quietly skipping — a root
//! run that cannot acquire a loop device has found a bug, and the
//! reviewer's privileged runs must not pass while testing nothing.
//!
//! The tests attach with `losetup --direct-io=off --partscan` on
//! purpose: with `--direct-io=off` the kernel keeps its writes inside
//! the backing file's page cache, so plain file reads of the backing
//! image see what the device surface wrote (the cross-checks below
//! stay coherent), while `dd` in the throughput test still measures a
//! direct front end; with `--partscan` the kernel partition-scans the
//! attached image, so `BLKRRPART` (`reread_partitions`) is a
//! meaningful request that a live node can actually succeed at
//! instead of the EINVAL a non-partscanned loop device answers.

use std::fs;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

use rufus_linux::AlignedBuf;
use rufus_linux::BlockDevice;
use rufus_linux::Sink;

/// Convenience unit: one MiB in bytes.
const MIB: u64 = 1024 * 1024;

/// 4 MiB, the pattern window: exactly one [`AlignedBuf`] default
/// chunk, aligned end to end for every request shape.
const WINDOW_LEN: u64 = 4 * MIB;

/// Fill `buf` with the deterministic non-zero pattern the module
/// shares (same shape as the unit tests in `src/block.rs`): every byte
/// position cycles through 1..=250, so any alien byte in a copy shows
/// up as a mismatch.
fn fill_pattern(buf: &mut [u8]) {
    for (index, byte) in buf.iter_mut().enumerate() {
        *byte = (index % 251 + 1) as u8;
    }
}

// ---------------------------------------------------------------------------
// LoopDevice: attach a scratch image, tear it down on Drop
// ---------------------------------------------------------------------------

/// Whether this process counts as root (effective user id 0): the
/// gate `LoopDevice::acquire` reads to tell a documented skip (no
/// privileges, see the module docs) from a real failure (root asked
/// for a loop device and did not get one — panic with the reason
/// instead of silently passing an empty test).
fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

/// Report an acquisition failure honestly. Without privileges this is
/// the documented skip — print the reason, return `None` (the caller
/// ends the test, which reports as skipped). As root the environment
/// is presumed working, so an acquisition failure is a bug: panic
/// with the real reason (the captured `losetup` stderr in
/// particular) instead of quietly letting a privileged run pass
/// while testing nothing.
fn fail_or_skip<T>(message: String) -> Option<T> {
    if is_root() {
        panic!("the loop-device tests ran as root but could not acquire a loop device: {message}");
    }
    eprintln!("skip: {message}");
    None
}

/// One loop device `acquire` attached to this test's scratch image;
/// `Drop` detaches it again.
struct LoopDevice {
    /// The device node losetup picked, e.g. `/dev/loop7`.
    path: PathBuf,
    /// The backing image created for it (the task's helper pins one
    /// field, `path`; the second private field only records where the
    /// image lives so [`LoopDevice::backing_bytes`] can read it back).
    image: PathBuf,
}

impl LoopDevice {
    /// Create `dir/backing.img` of `len` bytes (sparse: `set_len`
    /// only), attach a free loop device to it with
    /// `losetup --find --show --direct-io=off --partscan`, and return
    /// the device.
    ///
    /// The `--partscan` flag is not decoration: without kernel
    /// partition scanning `BLKRRPART` answers `EINVAL` no matter how
    /// quiet the node is (the S07 review proved that on this exact
    /// attach mode), so `reread_partitions` in the tests below is
    /// only a meaningful request on a partscanned device.
    ///
    /// Returns `None` (with an explanatory `eprintln!`) when the
    /// process is *not* root and the attach fails on missing
    /// privileges — the caller then simply ends the test, which
    /// reports as a skip. Every failure path goes through
    /// [`fail_or_skip`], so a *root* run panics with the real reason
    /// and never returns `None`; see the module docs.
    fn acquire(dir: &Path, len: u64) -> Option<LoopDevice> {
        let image = dir.join("backing.img");
        let file = match File::create(&image) {
            Ok(file) => file,
            Err(error) => {
                return fail_or_skip(format!(
                    "cannot create the backing image {}: {error}",
                    image.display()
                ));
            }
        };
        if let Err(error) = file.set_len(len) {
            return fail_or_skip(format!(
                "cannot size the backing image {}: {error}",
                image.display()
            ));
        }
        drop(file);

        let attach = match Command::new("losetup")
            .arg("--find")
            .arg("--show")
            .arg("--direct-io=off")
            .arg("--partscan")
            .arg(&image)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                return fail_or_skip(format!(
                    "losetup is missing or cannot run ({error}); the loop-device tests \
                     need util-linux and root, see the module docs"
                ));
            }
        };
        if !attach.status.success() {
            let stderr = String::from_utf8_lossy(&attach.stderr);
            let stderr = stderr.trim_end();
            return fail_or_skip(format!(
                "losetup did not attach a loop device ({}); on a machine without root \
                 this is the expected permission failure, see the module docs: {stderr}",
                attach.status
            ));
        }
        let stdout = String::from_utf8_lossy(&attach.stdout).trim().to_string();
        let Some(node) = stdout
            .lines()
            .last()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        else {
            return fail_or_skip(
                "losetup attached a device but printed no node path; cannot continue".to_string(),
            );
        };
        let path = PathBuf::from(node);

        // Guard: the node must actually be a block device. A regular
        // file there would mean we are not root and the attach answer
        // cannot be trusted for block I/O.
        let is_block = match fs::metadata(&path) {
            Ok(meta) => meta.file_type().is_block_device(),
            Err(error) => {
                return fail_or_skip(format!(
                    "cannot stat the loop node {}: {error}",
                    path.display()
                ));
            }
        };
        if !is_block {
            return fail_or_skip(format!(
                "{} is not a block device (probably not root); see the module docs",
                path.display()
            ));
        }
        Some(LoopDevice { path, image })
    }

    /// The backing image bytes as they stand right now, for comparison
    /// against what the device surface reports.
    fn backing_bytes(&self) -> Vec<u8> {
        // This failure is not a skip condition (the image was created
        // by `acquire` and nothing deleted it), so panic with context
        // instead of silently handing back wrong bytes to compare
        // against.
        fs::read(&self.image).expect("backing image is readable")
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        // Detach the loop device; failures here (already detached,
        // busy, privileges gone) are teardown noise, not a verdict,
        // so they are ignored.
        let _ = Command::new("losetup").arg("-d").arg(&self.path).status();
    }
}

// ---------------------------------------------------------------------------
// Geometry: the sysfs numbers open_with should be fed
// ---------------------------------------------------------------------------

/// Sysfs geometry of a block device node: the extent in bytes plus
/// logical and physical block sizes, i.e. what
/// [`BlockDevice::open_with`] expects from the S05 enumeration facts.
///
/// The node's `std::fs::metadata().len()` is deliberately not the
/// source: for a loop node the truth lives in
/// `/sys/block/<name>/size` (512-byte sectors), with
/// `queue/logical_block_size` and `queue/physical_block_size` beside
/// it. Missing sysfs values fall back to 512/4096 bytes (the same
/// defaults `BlockDevice::open` uses); a missing extent falls back to
/// the node length with a warning, because the callers skip before
/// this point when the node is not a real block device.
fn geometry(path: &Path) -> (u64, u32, u32) {
    let size = match sysfs_value(path, "size") {
        Some(sectors) => sectors * 512,
        None => {
            eprintln!(
                "warning: /sys/block/<name>/size is unreadable for {}; \
                 falling back to the node length",
                path.display()
            );
            fs::metadata(path)
                .map(|meta| meta.len())
                .unwrap_or_default()
        }
    };
    let logical = queue_value(path, "logical_block_size", 512);
    let physical = queue_value(path, "physical_block_size", 4096);
    (size, logical, physical)
}

/// One integer from `/sys/block/<name>/<file>`, where `<name>` is the
/// node's file name; `None` when the name or the file is unreadable.
fn sysfs_value(path: &Path, file: &str) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let text = fs::read_to_string(Path::new("/sys/block").join(name).join(file)).ok()?;
    text.trim().parse::<u64>().ok()
}

/// One integer from `/sys/block/<name>/queue/<file>` with the byte
/// fallback the task pins; a loop device always publishes both files,
/// so the fallbacks only fire on an unusual sysfs layout.
fn queue_value(path: &Path, file: &str, fallback: u32) -> u32 {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return fallback;
    };
    let Ok(text) = fs::read_to_string(Path::new("/sys/block").join(name).join("queue").join(file))
    else {
        eprintln!(
            "warning: /sys/block/{name}/queue/{file} is unreadable; falling back to {fallback}"
        );
        return fallback;
    };
    text.trim().parse::<u32>().unwrap_or(fallback)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
#[test]
fn loop_device_round_trip_matches_written_bytes() {
    let dir = tempfile::tempdir().expect("test scratch directory");
    let Some(device) = LoopDevice::acquire(dir.path(), 16 * MIB) else {
        return;
    };
    let (size, logical, physical) = geometry(&device.path);
    let dev = BlockDevice::open_with(&device.path, size, logical, physical)
        .expect("loop device opens exclusively for the test");

    assert_eq!(
        dev.size(),
        size,
        "the sink extent comes from the sysfs geometry"
    );

    // The deterministic 4 MiB pattern, written at the start and at a
    // 4 MiB-aligned window in the middle of the 16 MiB image.
    let mut payload = AlignedBuf::with_len(WINDOW_LEN as usize);
    fill_pattern(payload.as_mut_slice());
    let middle = 8 * MIB;
    dev.write_all_at(0, payload.as_slice())
        .expect("pattern write at offset 0");
    dev.write_all_at(middle, payload.as_slice())
        .expect("pattern write at the middle window");
    dev.flush().expect("flush pushes the writes down");

    // Both windows read back byte-identical through the device.
    let mut back = AlignedBuf::with_len(WINDOW_LEN as usize);
    dev.read_at(0, back.as_mut_slice())
        .expect("read back offset 0");
    assert_eq!(
        back.as_slice(),
        payload.as_slice(),
        "the first window survived the round trip"
    );
    dev.read_at(middle, back.as_mut_slice())
        .expect("read back the middle");
    assert_eq!(
        back.as_slice(),
        payload.as_slice(),
        "the middle window survived the round trip"
    );

    // The writes also really landed in the backing image, so the
    // device writes are not hidden in some shadow copy.
    let image = device.backing_bytes();
    assert_eq!(
        image.len() as u64,
        size,
        "the backing image keeps the chosen geometry"
    );
    assert_eq!(
        &image[..WINDOW_LEN as usize],
        payload.as_slice(),
        "the backing image holds the first window"
    );
    assert_eq!(
        &image[middle as usize..(middle + WINDOW_LEN) as usize],
        payload.as_slice(),
        "the backing image holds the middle window"
    );
}

#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
#[test]
fn zero_range_and_discard_on_a_loop_device() {
    let dir = tempfile::tempdir().expect("test scratch directory");
    let Some(device) = LoopDevice::acquire(dir.path(), 16 * MIB) else {
        return;
    };
    let (size, logical, physical) = geometry(&device.path);
    let dev = BlockDevice::open_with(&device.path, size, logical, physical)
        .expect("loop device opens exclusively for the test");

    // A 1 MiB aligned window, seeded with the pattern so zeroing has
    // real data to clear.
    let window = MIB;
    let offset = 8 * MIB;
    let mut payload = AlignedBuf::with_len(window as usize);
    fill_pattern(payload.as_mut_slice());
    dev.write_all_at(offset, payload.as_slice())
        .expect("seed the window with the pattern");
    dev.flush().expect("seed flush");

    dev.zero_range(offset, window)
        .expect("zero_range succeeds (BLKZEROOUT or the write fallback)");
    dev.flush().expect("flush after zeroing");

    // Read the window back through the device: every byte zero.
    let mut back = AlignedBuf::with_len(window as usize);
    dev.read_at(offset, back.as_mut_slice())
        .expect("read the zeroed window back");
    assert!(
        back.as_slice().iter().all(|&byte| byte == 0),
        "the window reads all zeroes through the device"
    );

    // Discard is documented best effort: it must not error, and the
    // device must still read afterwards (the data may stay, matching
    // the kernel's own definition of "best effort").
    dev.discard(offset, window)
        .expect("discard reports Ok on a loop device");
    dev.flush().expect("flush after discard");
    let mut after = AlignedBuf::with_len(window as usize);
    dev.read_at(offset, after.as_mut_slice())
        .expect("the device still reads after discard");

    // Partition rescanning stays healthy on a live, non-busy loop node.
    dev.reread_partitions()
        .expect("reread_partitions succeeds on a live loop device");
}

#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
#[test]
fn o_direct_writes_match_buffered_writes_when_available() {
    let dir = tempfile::tempdir().expect("test scratch directory");
    let Some(device) = LoopDevice::acquire(dir.path(), 16 * MIB) else {
        return;
    };

    // Pattern B rides a plain *buffered* `std::fs` handle, opened
    // BEFORE the exclusive `BlockDevice` open so the two handles never
    // coexist (O_EXCL would refuse a second open). The direct-vs-
    // buffered comparison only means something when both handles see
    // the same node: aligned offsets, different content, one handle
    // each.
    let buffered_payload_offset = 8 * MIB;
    let mut buffered_payload = AlignedBuf::with_len(WINDOW_LEN as usize);
    fill_pattern(buffered_payload.as_mut_slice());
    {
        let plain = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device.path)
            .expect("plain buffered open of the loop node");
        FileExt::write_all_at(&plain, buffered_payload.as_slice(), buffered_payload_offset)
            .expect("buffered write of the second pattern");
        plain
            .sync_all()
            .expect("the buffered write is pushed down before the exclusive open");
    } // the plain handle is dropped before the exclusive open below

    let (size, logical, physical) = geometry(&device.path);
    let dev = BlockDevice::open_with(&device.path, size, logical, physical)
        .expect("loop device opens exclusively for the test");

    if !dev.is_direct() {
        println!(
            "skip: the kernel opened the loop node buffered (O_DIRECT not accepted), so \
             there is no direct handle to compare against here"
        );
        return;
    }

    // Pattern A rides the direct descriptor itself: same window shape
    // (4 MiB aligned buffer at a 4 MiB-aligned offset), different
    // content, different offset than the buffered pattern wrote.
    let direct_pattern_offset = 0;
    let mut direct_payload = AlignedBuf::with_len(WINDOW_LEN as usize);
    direct_payload.as_mut_slice().fill(0xA5);
    dev.write_all_at(direct_pattern_offset, direct_payload.as_slice())
        .expect("direct write of the first pattern");
    dev.flush().expect("direct flush");

    // Both windows read back through the DEVICE surface, each matching
    // the content its own handle wrote — the direct fd and the plain
    // buffered fd must agree about the same medium.
    let mut back = AlignedBuf::with_len(WINDOW_LEN as usize);
    dev.read_at(direct_pattern_offset, back.as_mut_slice())
        .expect("read the direct window back");
    assert_eq!(
        back.as_slice(),
        direct_payload.as_slice(),
        "the direct-written window survived through the device"
    );
    dev.read_at(buffered_payload_offset, back.as_mut_slice())
        .expect("read the buffered window back");
    assert_eq!(
        back.as_slice(),
        buffered_payload.as_slice(),
        "the buffered-written window survived through the device"
    );

    // And the backing image holds both patterns, proving neither
    // handle's write is hidden in some shadow copy.
    let image = device.backing_bytes();
    assert_eq!(
        &image[direct_pattern_offset as usize..WINDOW_LEN as usize],
        direct_payload.as_slice(),
        "the backing image holds the direct-written window"
    );
    assert_eq!(
        &image[buffered_payload_offset as usize..(buffered_payload_offset + WINDOW_LEN) as usize],
        buffered_payload.as_slice(),
        "the backing image holds the buffered-written window"
    );
}

// ---------------------------------------------------------------------------
// Throughput helpers: multipass timing, one command for every dd pass
// ---------------------------------------------------------------------------

/// How many passes each side of the throughput comparison runs: a
/// single pass is one 0.3-ish-second sample, and container runs of
/// the one-pass shape swung bimodally (350-426 MiB/s), so the verdict
/// reads the median of three instead.
const PASS_COUNT: usize = 3;

/// Write the throughput payload to a scratch file outside any timed
/// region, so `dd` can read the *same* bytes our writer writes.
///
/// Both sides of the comparison must carry the same payload class: the
/// loop device is attached with `--direct-io=off`, so the backing
/// filesystem is the measured medium, and a compressible source
/// (`/dev/zero`) would let a compressing filesystem (btrfs + zstd, for
/// example) hand `dd` a several-fold advantage that says nothing about
/// dd's write path.
fn write_payload_source(path: &Path, payload: &[u8]) {
    let mut file = std::fs::File::create(path).expect("payload source is created");
    file.write_all(payload)
        .expect("the whole payload reaches the source file");
    file.sync_all()
        .expect("the payload source is durable before timing starts");
}

/// One dd baseline pass: fill the first 128 MiB of the device from the
/// payload source file with `oflag=direct` plus `conv=fsync`, timed end
/// to end. One command in one place — every dd pass is this exact
/// invocation, so the passes cannot drift apart. Missing dd means the
/// comparison cannot be made and the caller gets `None` for a
/// documented skip; a dd that *runs* and fails is a real failure
/// worth the exit message.
fn run_dd_pass(source: &Path, device: &Path) -> Option<Duration> {
    let started = Instant::now();
    let dd = match Command::new("dd")
        .arg(format!("if={}", source.display()))
        .arg(format!("of={}", device.display()))
        .arg("bs=4M")
        .arg("count=32")
        .arg("oflag=direct")
        .arg("conv=fsync")
        .arg("status=none")
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skip: dd is not available ({error}); the throughput baseline needs it");
            return None;
        }
    };
    let elapsed = started.elapsed();
    let stderr = String::from_utf8_lossy(&dd.stderr).trim_end().to_string();
    assert!(
        dd.status.success(),
        "dd oflag=direct failed on the loop node ({}): {stderr}",
        dd.status
    );
    Some(elapsed)
}

/// The median of exactly [`PASS_COUNT`] (=3) pass times: the middle
/// one after sorting a copy, robust against a single outlier sample.
/// The caller's slice keeps pass order so the printed samples stay
/// labelled by pass.
fn median_of_three(passes: &[Duration]) -> Duration {
    assert_eq!(
        passes.len(),
        PASS_COUNT,
        "the comparison is defined over exactly three passes"
    );
    let mut sorted = passes.to_vec();
    sorted.sort();
    sorted[1]
}

#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
#[test]
fn direct_throughput_is_within_five_percent_of_dd() {
    // 160 MiB backing so the 128 MiB dd fill plus our 128 MiB write
    // both fit without growing the image.
    let dir = tempfile::tempdir().expect("test scratch directory");
    let Some(device) = LoopDevice::acquire(dir.path(), 160 * MIB) else {
        return;
    };
    let (size, logical, physical) = geometry(&device.path);
    assert!(
        size >= 128 * MIB,
        "the loop device is at least 128 MiB, got {size} bytes"
    );
    let dev = BlockDevice::open_with(&device.path, size, logical, physical)
        .expect("loop device opens exclusively for the test");

    // 128 MiB of deterministic payload, filled before the clocks
    // start so only the I/O is timed. The same bytes land in a scratch
    // source file for dd, so both sides carry the same payload class.
    let mut payload = AlignedBuf::with_len((128 * MIB) as usize);
    fill_pattern(payload.as_mut_slice());
    let payload_source = dir.path().join("payload.bin");
    write_payload_source(&payload_source, payload.as_slice());

    // Ours: the cancellable writer in whole 4 MiB pieces, full 128
    // MiB from offset 0, with the flush inside the timed region — the
    // same shape dd's conv=fsync costs. Every pass is identical, so
    // the medians below compare like with like.
    let mut ours_passes: Vec<Duration> = Vec::new();
    for pass in 0..PASS_COUNT {
        let started = Instant::now();
        let written = dev
            .write_all_at_cancellable(0, payload.as_slice(), (4 * MIB) as usize, &|| false)
            .expect("the cancellable writer completes");
        dev.flush()
            .expect("flush inside the timed region (dd pays conv=fsync)");
        assert_eq!(
            written,
            128 * MIB,
            "pass {}: the cancellable writer completed the full 128 MiB",
            pass + 1
        );
        ours_passes.push(started.elapsed());
    }

    // The baseline: three identical dd passes (see `run_dd_pass`),
    // each timed end to end from offset 0 like our passes.
    let mut dd_passes: Vec<Duration> = Vec::new();
    for _ in 0..PASS_COUNT {
        let Some(elapsed) = run_dd_pass(&payload_source, &device.path) else {
            return;
        };
        dd_passes.push(elapsed);
    }

    // The verdict reads the medians (PLAN §9 S07 keeps the five
    // percent criterion, moved onto the median of three passes); the
    // printed samples show what the medians were picked from.
    let mibs = |elapsed: Duration| 128.0 * MIB as f64 / elapsed.as_secs_f64() / MIB as f64;
    let ours_median = median_of_three(&ours_passes);
    let dd_median = median_of_three(&dd_passes);
    println!("our write_all_at_cancellable (median is the verdict):");
    for (index, elapsed) in ours_passes.iter().enumerate() {
        println!(
            "  pass {} : {:8.1} MiB/s in {elapsed:?}",
            index + 1,
            mibs(*elapsed)
        );
    }
    println!(
        "  median : {:8.1} MiB/s in {ours_median:?}",
        mibs(ours_median)
    );
    println!("dd oflag=direct baseline (median is the verdict):");
    for (index, elapsed) in dd_passes.iter().enumerate() {
        println!(
            "  pass {} : {:8.1} MiB/s in {elapsed:?}",
            index + 1,
            mibs(*elapsed)
        );
    }
    println!("  median : {:8.1} MiB/s in {dd_median:?}", mibs(dd_median));

    let ours_median_mibs = mibs(ours_median);
    let dd_median_mibs = mibs(dd_median);
    assert!(
        ours_median_mibs >= 0.95 * dd_median_mibs,
        "our direct write path runs at a median of {ours_median_mibs:.1} MiB/s, that is below \
         95 percent of the dd baseline's median ({dd_median_mibs:.1} MiB/s)"
    );
}
