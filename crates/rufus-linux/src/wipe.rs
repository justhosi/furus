//! The wipe sequence (PLAN §9-S08 "Wipe", on the PLAN §6 rule-6 seam:
//! "re-read the partition table after writing and verify the expected
//! partitions exist before formatting").
//!
//! [`wipe_device`] clears the table surfaces of a sink — first and
//! last 1 MiB, optionally preceded by a full-device [`Sink::discard`]
//! hint — then flushes and asks the kernel to re-read the table.
//! [`wait_for_partitions`] polls the sysfs watch root until every
//! expected partition node has appeared (both the
//! `class/block/<disk>/<node>` layout and the sibling
//! `class/block/<node>` spelling a re-scanned disk shows), bounded by
//! [`PARTITION_POLL_TIMEOUT`].
//!
//! Rules the tests pin:
//!
//! * **Zero-size is a no-op** — nothing is touched, the flush/reread
//!   step is skipped too, the call is `Ok`.
//! * **Below `2 * WIPE_WINDOW_BYTES` the whole device is zeroed once**
//!   — no double-write through overlapping front/last windows, no
//!   underflow wrapping `size - MIB` around zero.
//! * **The discard request is best effort** — an unsupported or failing
//!   [`Sink::discard`] is *ignored* by design (the Sink contract
//!   documents the hint as optional), and the zeroing happens anyway
//!   with unchanged semantics.
//! * **The poll honours the caller's interval** — every sleep is
//!   exactly the passed `interval` (never longer), the first check is
//!   immediate (a seeded sysfs answers without sleeping at all), and
//!   an expired timeout raises [`CoreError`] naming the missing nodes
//!   and the disk, ASCII only.
//!
//! Nothing here sleeps longer than the caller asks for, spawns
//! processes, or touches the real `/sys`: both functions take their
//! sink / sysfs root as parameters, so every mutation and every poll
//! is testable against in-memory doubles and fixture trees.

use std::time::Duration;
use std::time::Instant;

use rufus_core::error::CoreError;
use rufus_core::error::Result;

use crate::block::Sink;
use crate::sysfs::SysfsRoot;

/// One end of the table area: the wipe clears this much at the front
/// and at the tail of the device (PLAN §9-S08: "zero first and last
/// 1 MiB"). The middle — where the data lives — is never touched by a
/// wipe, which is exactly why the write pipeline can reuse it.
pub const WIPE_WINDOW_BYTES: u64 = 1_048_576;

/// How long the post-write partition scan may take at most
/// (PLAN §9-S08: "poll `/sys`, ≤ 3 s").
pub const PARTITION_POLL_TIMEOUT: Duration = Duration::from_secs(3);

/// How often the partition scan re-checks sysfs between attempts.
pub const PARTITION_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Zero the table surfaces of `sink` (`size_bytes` is the device
/// extent the caller enumerated), then flush and re-read the table.
///
/// * `discard == true` sends one whole-device [`Sink::discard`] first
///   (flash/SSD wear-speed accounting) and **ignores its outcome** —
///   the Sink contract marks the call best effort, so unsupported
///   hardware simply keeps its data and the *authoritative* clearing
///   below does the real work regardless;
/// * devices smaller than `2 * WIPE_WINDOW_BYTES` are zeroed as **one**
///   `zero_range` over the whole extent (front and last windows would
///   overlap otherwise, and the `size - MIB` rear offset would wrap);
/// * anything else takes the two-window shape `[0, MIB)` and
///   `[size - MIB, size)`;
/// * the step ends on [`Sink::flush`] + [`Sink::reread_partitions`]
///   (PLAN §6 rule 6) so the kernel surfaces the fresh table before
///   the caller's [`wait_for_partitions`] polls for the nodes.
pub fn wipe_device(sink: &mut dyn Sink, size_bytes: u64, discard: bool) -> Result<()> {
    if size_bytes == 0 {
        // Nothing to wipe, nothing to reread; a zero-size sink cannot
        // host a table, so the no-op IS the correct sequence.
        return Ok(());
    }
    if discard {
        // Best effort (Sink docs): every error — unsupported primitive,
        // busy device, whatever — is swallowed here on purpose. A hard
        // device failure surfaces on the zeroing writes next, where it
        // belongs, instead of aborting on a hint.
        let _ = sink.discard(0, size_bytes);
    }
    let window = WIPE_WINDOW_BYTES;
    if size_bytes < window.saturating_mul(2) {
        // One pass over the whole (small) extent: no overlap, no
        // underflow on the rear offset.
        sink.zero_range(0, size_bytes)?;
    } else {
        sink.zero_range(0, window)?;
        sink.zero_range(size_bytes - window, window)?;
    }
    sink.flush()?;
    sink.reread_partitions()
}

/// Poll the partition nodes into existence, or time out.
///
/// Every `expected` node is looked up in its whole-disk directory
/// (`<sysfs>/class/block/<disk_name>/<node>`) **or** as the sibling
/// the kernel also links (`<sysfs>/class/block/<node>`) — the class
/// listing links both forms, so neither spelling may be privileged.
/// An empty `expected` returns immediately (a layout without
/// partitions needs no waiting). The first check happens before any
/// sleep, a freshly re-read table answers within one pass, and the
/// fixed [`PARTITION_POLL_TIMEOUT`] / [`PARTITION_POLL_INTERVAL`] pair
/// is only the default the write pipeline passes through.
pub fn wait_for_partitions(
    sysfs: &SysfsRoot,
    disk_name: &str,
    expected: &[String],
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    loop {
        let missing: Vec<&str> = expected
            .iter()
            .filter(|node| !node_present(sysfs, disk_name, node))
            .map(String::as_str)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(CoreError::invalid(format!(
                "partition nodes [{}] did not appear on disk {disk_name} within {timeout:?}",
                missing.join(", ")
            )));
        }
        // Exactly one interval per pass — no longer, no deep idle.
        std::thread::sleep(interval);
    }
}

/// Does `node` exist in either sysfs spelling? `class_block()` is
/// crate-internal plumbing on purpose: form A is the whole-disk
/// directory, form B the sibling the kernel links next to the disk.
fn node_present(sysfs: &SysfsRoot, disk_name: &str, node: &str) -> bool {
    let class_block = sysfs.class_block();
    class_block.join(disk_name).join(node).exists() || class_block.join(node).exists()
}

// ---------------------------------------------------------------------------
// Tests: the sequence against memory doubles, and the poll against a
// fixture sysfs tree.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use rufus_core::error::CoreError;
    use rufus_core::error::Result;

    use super::WIPE_WINDOW_BYTES;
    use super::wait_for_partitions;
    use super::wipe_device;
    use crate::block::MemorySink;
    use crate::block::Sink;
    use crate::sysfs::SysfsRoot;

    // -- test doubles -------------------------------------------------------

    /// Wraps a [`MemorySink`], records every sink-level operation as
    /// `(what, offset, len)` and lets tests assert the *sequence* —
    /// discard placement, window count, the single zero pass on small
    /// devices, and the flush/reread tail.
    struct RecordingSink {
        inner: MemorySink,
        ops: Mutex<Vec<(&'static str, u64, u64)>>,
    }

    impl RecordingSink {
        fn new(len: usize) -> Self {
            Self {
                inner: MemorySink::new(len),
                ops: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, what: &'static str, offset: u64, len: u64) {
            self.ops
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((what, offset, len));
        }

        fn ops(&self) -> Vec<(&'static str, u64, u64)> {
            self.ops
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl Sink for RecordingSink {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn is_direct(&self) -> bool {
            self.inner.is_direct()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
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

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            self.record("zero", offset, len);
            self.inner.zero_range(offset, len)
        }

        fn discard(&self, offset: u64, len: u64) -> Result<()> {
            self.record("discard", offset, len);
            self.inner.discard(offset, len)
        }

        fn flush(&self) -> Result<()> {
            self.record("flush", 0, 0);
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.record("reread", 0, 0);
            self.inner.reread_partitions()
        }
    }

    /// A double whose [`Sink::discard`] always fails with a plain
    /// "unsupported" error — the wipe must ignore it and zero anyway.
    struct RefusingDiscard {
        inner: MemorySink,
    }

    impl Sink for RefusingDiscard {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn is_direct(&self) -> bool {
            self.inner.is_direct()
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.inner.read_at(offset, buf)
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

        fn zero_range(&self, offset: u64, len: u64) -> Result<()> {
            self.inner.zero_range(offset, len)
        }

        fn discard(&self, _offset: u64, _len: u64) -> Result<()> {
            Err(CoreError::invalid("discard unsupported on this stub"))
        }

        fn flush(&self) -> Result<()> {
            self.inner.flush()
        }

        fn reread_partitions(&self) -> Result<()> {
            self.inner.reread_partitions()
        }
    }

    /// Fill `sink[target..target+len)` with one repeated byte.
    fn seed(sink: &mut MemorySink, target: u64, len: usize, byte: u8) {
        sink.write_all_at(target, &vec![byte; len])
            .expect("seed the sink pattern");
    }

    // -- wipe sequencing ----------------------------------------------------

    #[test]
    fn zeroes_front_and_last_and_leaves_the_middle_untouched() {
        const MIB: u64 = WIPE_WINDOW_BYTES;
        let mut sink = MemorySink::new(4 * MIB as usize);
        seed(&mut sink, 0, MIB as usize, 0x11); // front window: must go
        seed(&mut sink, MIB, (2 * MIB) as usize, 0xA5); // middle: stays
        seed(&mut sink, 3 * MIB, MIB as usize, 0x22); // last window: must go

        wipe_device(&mut sink, 4 * MIB, false)
            .unwrap_or_else(|error| panic!("wipe 4 MiB: {error}"));
        let image = sink.snapshot();
        assert!(
            image[..MIB as usize].iter().all(|&byte| byte == 0),
            "the front MiB is zeroed"
        );
        assert!(
            image[MIB as usize..(3 * MIB) as usize]
                .iter()
                .all(|&byte| byte == 0xA5),
            "the middle carries the seeded pattern, untouched"
        );
        assert!(
            image[(3 * MIB) as usize..].iter().all(|&byte| byte == 0),
            "the last MiB is zeroed"
        );
    }

    #[test]
    fn records_the_discard_first_then_both_windows_then_flush_reread() {
        const MIB: u64 = WIPE_WINDOW_BYTES;
        let mut sink = RecordingSink::new(4 * MIB as usize);
        wipe_device(&mut sink, 4 * MIB, true).unwrap_or_else(|error| panic!("wipe 4 MiB: {error}"));
        assert_eq!(
            sink.ops(),
            vec![
                ("discard", 0, 4 * MIB),
                ("zero", 0, MIB),
                ("zero", 3 * MIB, MIB),
                ("flush", 0, 0),
                ("reread", 0, 0),
            ],
            "discard first, then the two windows, then the rule-6 tail"
        );
    }

    #[test]
    fn skips_discard_when_not_requested() {
        const MIB: u64 = WIPE_WINDOW_BYTES;
        let mut sink = RecordingSink::new(4 * MIB as usize);
        wipe_device(&mut sink, 4 * MIB, false)
            .unwrap_or_else(|error| panic!("wipe 4 MiB: {error}"));
        assert_eq!(
            sink.ops(),
            vec![
                ("zero", 0, MIB),
                ("zero", 3 * MIB, MIB),
                ("flush", 0, 0),
                ("reread", 0, 0),
            ],
            "no discard step in the sequence"
        );
    }

    #[test]
    fn below_two_mib_is_one_whole_extent_zero() {
        let cases = [
            (2 * WIPE_WINDOW_BYTES - 1024, "2 MiB minus a peck"),
            (WIPE_WINDOW_BYTES - 512, "under one MiB"),
            (WIPE_WINDOW_BYTES, "exactly one MiB"),
        ];
        for (size, label) in cases {
            let mut sink = RecordingSink::new(size as usize);
            wipe_device(&mut sink, size, false)
                .unwrap_or_else(|error| panic!("wipe {label}: {error}"));
            assert_eq!(
                sink.ops(),
                vec![("zero", 0, size), ("flush", 0, 0), ("reread", 0, 0)],
                "{label}: the whole device zeroes in a single pass"
            );
            assert!(
                sink.inner.snapshot().iter().all(|&byte| byte == 0),
                "{label}: fully zeroed"
            );
        }
    }

    #[test]
    fn two_mib_exactly_splits_into_non_overlapping_windows() {
        const MIB: u64 = WIPE_WINDOW_BYTES;
        let mut sink = RecordingSink::new(2 * MIB as usize);
        wipe_device(&mut sink, 2 * MIB, false)
            .unwrap_or_else(|error| panic!("wipe 2 MiB: {error}"));
        assert_eq!(
            sink.ops(),
            vec![
                ("zero", 0, MIB),
                ("zero", MIB, MIB),
                ("flush", 0, 0),
                ("reread", 0, 0),
            ],
            "at exactly 2 MiB the windows meet without overlapping"
        );
    }

    #[test]
    fn zero_size_is_a_no_op() {
        let mut sink = RecordingSink::new(0);
        wipe_device(&mut sink, 0, true).unwrap_or_else(|error| panic!("wipe 0: {error}"));
        assert_eq!(
            sink.ops(),
            Vec::<(&'static str, u64, u64)>::new(),
            "nothing at all happens on a zero-size device"
        );
    }

    #[test]
    fn failing_discard_is_ignored_and_the_zero_still_happens() {
        const MIB: u64 = WIPE_WINDOW_BYTES;
        let mut inner = MemorySink::new(4 * MIB as usize);
        seed(&mut inner, MIB, (2 * MIB) as usize, 0x5A);
        let mut sink = RefusingDiscard { inner };
        wipe_device(&mut sink, 4 * MIB, true)
            .unwrap_or_else(|error| panic!("wipe with a failing discard: {error}"));
        let image = sink.inner.snapshot();
        assert!(
            image[..MIB as usize].iter().all(|&byte| byte == 0),
            "front zeroed despite the discard refusal"
        );
        assert!(
            image[MIB as usize..(3 * MIB) as usize]
                .iter()
                .all(|&byte| byte == 0x5A),
            "the middle pattern survives, as it should"
        );
        assert!(
            image[(3 * MIB) as usize..].iter().all(|&byte| byte == 0),
            "rear zeroed despite the discard refusal"
        );
    }

    // -- partition polling --------------------------------------------------

    /// A scratch sysfs root plus its `class/block` directory.
    struct Fixture {
        _scratch: tempfile::TempDir,
        sysfs: SysfsRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let root = scratch.path().to_path_buf();
            fs::create_dir_all(root.join("class").join("block")).expect("class/block");
            Fixture {
                _scratch: scratch,
                sysfs: SysfsRoot::new(root),
            }
        }

        /// Create the empty (block-node stand-in) path `rel` relative
        /// to the fixture root.
        fn seed(&self, rel: &str) {
            fs::create_dir_all(self.sysfs.root.join(rel))
                .unwrap_or_else(|error| panic!("seed {rel}: {error}"));
        }
    }

    #[test]
    fn pre_seeded_nodes_answer_immediately() {
        let fixture = Fixture::new();
        // Form A: the node inside its whole-disk directory.
        fixture.seed("class/block/sdb/sdb1");
        // Form B: the kernel's sibling spelling next to the disk.
        fixture.seed("class/block/sdb2");
        let started = Instant::now();
        wait_for_partitions(
            &fixture.sysfs,
            "sdb",
            &["sdb1".to_owned(), "sdb2".to_owned()],
            Duration::from_millis(200),
            Duration::from_millis(50),
        )
        .unwrap_or_else(|error| panic!("seeded nodes: {error}"));
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "the first check runs before any sleep ({:?})",
            started.elapsed()
        );
    }

    #[test]
    fn the_poll_waits_a_full_interval_before_checking_again() {
        // The node appears 40 ms in, well inside the 200 ms interval: a
        // poll that re-checks continuously would answer at ~40 ms, so
        // this pins the pacing rather than only the eventual success.
        let fixture = Fixture::new();
        let late_node = fixture.sysfs.root.join("class/block/sdb/sdb2");
        let seeder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            fs::create_dir_all(&late_node).expect("seed the late node");
        });
        let started = Instant::now();
        wait_for_partitions(
            &fixture.sysfs,
            "sdb",
            &["sdb2".to_owned()],
            Duration::from_millis(900),
            Duration::from_millis(200),
        )
        .unwrap_or_else(|error| panic!("the late node must be found: {error}"));
        let elapsed = started.elapsed();
        seeder.join().expect("the seeder thread");
        assert!(
            elapsed >= Duration::from_millis(150),
            "the poll slept its interval before the second check ({elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "and answered as soon as the node existed ({elapsed:?})"
        );
    }

    #[test]
    fn each_node_form_alone_is_enough() {
        for (rel, node) in [
            ("class/block/sdc/sdc1", "sdc1"), // inside the disk's dir
            ("class/block/sdc1", "sdc1"),     // the sibling form
        ] {
            let fixture = Fixture::new();
            fixture.seed(rel);
            wait_for_partitions(
                &fixture.sysfs,
                "sdc",
                &[node.to_owned()],
                Duration::from_millis(200),
                Duration::from_millis(50),
            )
            .unwrap_or_else(|error| panic!("node via {rel}: {error}"));
        }
    }

    #[test]
    fn timeout_names_the_missing_nodes_and_the_disk() {
        let fixture = Fixture::new();
        fixture.seed("class/block/sdb/sdb1"); // present
        // sdb2 stays missing.
        let started = Instant::now();
        let error = wait_for_partitions(
            &fixture.sysfs,
            "sdb",
            &["sdb1".to_owned(), "sdb2".to_owned()],
            Duration::from_millis(100),
            Duration::from_millis(20),
        )
        .expect_err("sdb2 never appears");
        let text = error.to_string();
        assert!(text.contains("sdb2"), "{text}");
        assert!(text.contains("sdb"), "{text}");
        assert!(text.is_ascii(), "the message is ASCII: {text}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "the timeout is honoured, not exited early ({elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(100) + Duration::from_secs(1),
            "no runaway sleeping ({elapsed:?})"
        );
    }

    #[test]
    fn empty_expected_list_returns_without_touching_sysfs() {
        // A sysfs root whose class/block does not exist at all: still
        // an instant Ok, because there is nothing to wait for.
        let scratch = tempfile::tempdir().expect("scratch dir");
        let sysfs = SysfsRoot::new(scratch.path().to_path_buf());
        assert!(!Path::new(&sysfs.root).join("class").exists());
        let started = Instant::now();
        wait_for_partitions(
            &sysfs,
            "sdb",
            &[],
            Duration::from_millis(100),
            Duration::from_millis(50),
        )
        .unwrap_or_else(|error| panic!("empty list: {error}"));
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "the fast path never sleeps ({:?})",
            started.elapsed()
        );
    }
}
