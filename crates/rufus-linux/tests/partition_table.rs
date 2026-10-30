//! External-tool acceptance evidence for the S08 table writers — the
//! slice's "Done when" proven against the partitioning tools this
//! environment actually ships: `sfdisk`, `fdisk` and `parted` must
//! accept what [`plan`](rufus_core::part::plan::plan) renders
//! ([`render`](rufus_core::part::plan::render)), and [`wipe_device`]
//! must leave nothing behind. `gdisk`/`sgdisk` and `qemu` are absent on
//! this machine, so the GPT verdict is carried by sfdisk/fdisk/parted
//! plus one **documented** gdisk recipe (test 5) instead of a real run.
//!
//! Every unprivileged test writes the rendered sectors of a planned
//! layout through a [`SparseFile`] (the file-backed [`Sink`] double),
//! then hands the raw image file to the real tools and asserts their
//! exit status *and* the tool-reported geometry. One external-tool
//! invocation must fail the test with the tool's stderr in the message;
//! a missing tool is printed as an explicit skip, never passed silent.
//! The whole unprivileged part stays under the ~5 s budget: each test
//! makes one sparse image and spawns a few short commands.
//!
//! The kernel-final round is the root test:
//!
//! * `kernel_publishes_the_planned_partitions` — attach a loop device
//!   (needs root and `losetup`, like `tests/loop_device.rs`), write the
//!   GPT table through a real [`BlockDevice`], `reread_partitions`,
//!   wait for the published node in real `/sys` with
//!   `wait_for_partitions` (the 3 s PLAN window), and compare the
//!   sysfs sector sizes against the plan. The manual procedure,
//!   verbatim (run once as root after a first unprivileged build, so
//!   nothing is compiled under sudo; `-E` keeps `$HOME` and the target
//!   cache of the invoking user):
//!
//! ```text
//! sudo -E $(which cargo) test --offline -p rufus-linux --test partition_table -- --ignored --nocapture
//! ```
//!
//! The gdisk recipe a maintainer with gdisk installed should run
//! (documented because sgdisk is not available here to run it):
//!
//! ```text
//! sgdisk --verify <image stamped with the rendered GPT single layout>
//! ```
//!
//! Blank-image behaviour, measured once on this machine and pinned by
//! the wipe test: `sfdisk --verify` on a signature-less image exits
//! **0** saying "unrecognized partition table type", and `fdisk -l`
//! prints no `Disklabel type:` line at all. That is what "nothing
//! behind" looks like to these tools; both shapes are asserted
//! explicitly, never ignored.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;

use rufus_core::part::TableKind;
use rufus_core::part::detect_layout;
use rufus_core::part::plan::DataType;
use rufus_core::part::plan::LayoutKind;
use rufus_core::part::plan::PlanRequest;
use rufus_core::part::plan::Rendered;
use rufus_core::part::plan::TablePlan;
use rufus_core::part::plan::plan;
use rufus_core::part::plan::render;
use rufus_linux::AlignedBuf;
use rufus_linux::BlockDevice;
use rufus_linux::PARTITION_POLL_INTERVAL;
use rufus_linux::PARTITION_POLL_TIMEOUT;
use rufus_linux::Sink;
use rufus_linux::SparseFile;
use rufus_linux::SysfsRoot;
use rufus_linux::wait_for_partitions;
use rufus_linux::wipe_device;

/// Convenience unit: one MiB in bytes.
const MIB: u64 = 1024 * 1024;

/// The 64 MiB scratch disk the single-partition tests live on (the
/// geometry PLAN §9-S08 names for an acceptance check).
const DISK_BYTES: u64 = 64 * MIB;

/// The Windows-to-go scratch disk. A second, larger image because the
/// WTG planner windows are pinned (100 MiB ESP + 16 MiB MSR beyond the
/// table span); a 64 MiB disk cannot fit the layout at all.
const WTG_DISK_BYTES: u64 = 128 * MIB;

/// The logical sector size of every scratch disk here.
const SECTOR: u64 = 512;

/// Final sector index of the 64 MiB disk (`size / sector - 1`).
const LAST_LBA: u64 = DISK_BYTES / SECTOR - 1;

/// Final sector index of the 128 MiB disk.
const WTG_LAST_LBA: u64 = WTG_DISK_BYTES / SECTOR - 1;

/// O_DIRECT window size: offsets, lengths and buffer addresses of a
/// direct write must line up on [`AlignedBuf::ALIGN`].
const WINDOW: u64 = AlignedBuf::ALIGN as u64;

// ---------------------------------------------------------------------------
// Planning and rendering helpers
// ---------------------------------------------------------------------------

/// Plan one of the S08 layouts: 512-byte logical sectors, `last_lba` as
/// given, planner-default windows, Microsoft basic data for the data
/// partition (WindowsToGo pins its own types; the request value there
/// is unused by the planner).
fn planned(kind: LayoutKind, table: TableKind, last_lba: u64) -> TablePlan {
    plan(&PlanRequest {
        kind,
        table,
        sector_size: 512,
        last_lba,
        data_type: DataType::MicrosoftBasicData,
        esp_bytes: 0,
        persistence_bytes: 0,
    })
    .unwrap_or_else(|error| panic!("the {kind:?} plan on {table:?} was refused: {error}"))
}

/// Render `table` at the same geometry the planner used.
fn rendered(table: &TablePlan, last_lba: u64) -> Rendered {
    let kind = table.kind;
    render(table, 512, last_lba)
        .unwrap_or_else(|error| panic!("the {kind:?} render was refused: {error}"))
}

/// The one partition a `Single` layout carries: its planned
/// `(start, last, sectors)` triple, the exact numbers the external
/// tools must report back.
fn single_span(table: &TablePlan) -> (u64, u64, u64) {
    let partition = &table.partitions[0];
    (
        partition.start_lba,
        partition.last_lba,
        partition.last_lba - partition.start_lba + 1,
    )
}

/// Write every rendered sector through `sink` at its absolute byte
/// offset, then flush.
///
/// Sector-sized writes at sector-multiple offsets are only legal on a
/// *buffered* sink; a direct sink (a device node held open with
/// O_DIRECT) demands 4 KiB-aligned windows, so [`touched_windows`]
/// composes those instead. Both paths push exactly the rendered bytes
/// and zeros nowhere else.
fn stamp_table(sink: &dyn Sink, rendered: &Rendered, image_size: u64) {
    if sink.is_direct() {
        for (offset, bytes) in touched_windows(rendered, image_size) {
            write_aligned(sink, offset, &bytes);
        }
    } else {
        for write in &rendered.writes {
            sink.write_all_at(write.lba * SECTOR, &write.bytes)
                .unwrap_or_else(|error| {
                    panic!("sector write at lba {} failed: {error}", write.lba)
                });
        }
    }
    sink.flush()
        .unwrap_or_else(|error| panic!("flush after the table writes failed: {error}"));
}

/// Stage the rendered table into every 4 KiB window it touches
/// (`offset -> whole window bytes`, zero-filled beyond the rendered
/// sectors).
///
/// The padding a window needs past a table sector is zero bytes in
/// *unpartitioned* space only: every rendered sector is table
/// metadata, and what the windows reach past them is the gap between
/// the table and the first partition (or the image end, exactly on a
/// 4 KiB-multiple image). So a composed window never invents data
/// below the render nor above it — it is the same table bytes the
/// pipeline would ultimately write, just in direct-shaped pieces.
fn touched_windows(rendered: &Rendered, image_size: u64) -> BTreeMap<u64, Vec<u8>> {
    let mut windows: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for write in &rendered.writes {
        let start = write.lba * SECTOR;
        let end = start + write.bytes.len() as u64; // sector-sized renders only
        let mut window_start = start / WINDOW * WINDOW;
        while window_start < end {
            assert!(
                window_start + WINDOW <= image_size,
                "window [{window_start}, {}) runs past the image size {image_size}; the \
                 scratch images here are whole 4 KiB multiples, so this never fires on \
                 the planned geometry",
                window_start + WINDOW
            );
            let window = windows
                .entry(window_start)
                .or_insert_with(|| vec![0u8; WINDOW as usize]);
            let from = (start - window_start) as usize;
            let to = (end - window_start) as usize;
            window[from..to].copy_from_slice(&write.bytes);
            window_start += WINDOW;
        }
    }
    windows
}

/// One direct-shaped window write: an [`AlignedBuf`] window (aligned
/// address), an [`AlignedBuf::ALIGN`]-aligned offset and a whole
/// [`AlignedBuf::ALIGN`]-strong length, which is exactly the shape the
/// direct rule demands.
fn write_aligned(sink: &dyn Sink, offset: u64, bytes: &[u8]) {
    let mut buffer = AlignedBuf::with_len(bytes.len());
    buffer.as_mut_slice().copy_from_slice(bytes);
    sink.write_all_at(offset, buffer.as_slice())
        .unwrap_or_else(|error| panic!("aligned window write at offset {offset} failed: {error}"));
}

// ---------------------------------------------------------------------------
// External-tool harness: capture, report, skip-with-a-reason
// ---------------------------------------------------------------------------

/// One captured invocation of an external tool, spawned with a C
/// locale so every byte it answers is ASCII.
struct ToolRun {
    /// The process result: `None` when the binary could not be spawned
    /// at all (absent from `PATH` is the everyday cause); `Some` is the
    /// exit status of a process that ran.
    ran: Option<ExitStatus>,
    /// The spawn failure text, when the binary never started.
    spawn: Option<String>,
    /// The verbatim standard output of the run ("" when never spawned).
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

/// Assert the backup GPT header really sits in the final LBA, with the
/// swapped `my_lba`/`alternate_lba` pair, by reading the raw bytes back
/// from the image.
///
/// The external tools are lenient here: all three exit 0 with a
/// corrupt or missing backup, `sfdisk --verify` even prints "No
/// errors detected" for a zeroed backup sector, and fdisk/parted only
/// print "the backup GPT table is corrupt, but the primary appears
/// OK". So the backup's placement and its swapped link are pinned
/// against the image bytes instead. `sector_size` is the logical sector
/// of the rendered table; `last_lba` is the disk's final LBA.
fn assert_backup_header(path: &Path, last_lba: u64, sector_size: u64) {
    use std::io::{Read, Seek, SeekFrom};

    let offset = last_lba.saturating_mul(sector_size);
    let mut header = [0u8; 92];
    let mut file = File::open(path).expect("open the stamped image for the backup header");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to the backup header");
    file.read_exact(&mut header)
        .expect("read the backup header sector");

    assert_eq!(
        &header[..8],
        b"EFI PART",
        "no GPT signature at the last LBA {last_lba}"
    );
    let my_lba = u64::from_le_bytes(header[24..32].try_into().expect("my_lba field"));
    let alternate_lba = u64::from_le_bytes(header[32..40].try_into().expect("alternate_lba field"));
    assert_eq!(
        my_lba, last_lba,
        "the backup header claims to live at LBA {my_lba}, not {last_lba}"
    );
    assert_eq!(
        alternate_lba, 1,
        "the backup header's alternate must be the primary at LBA 1, got {alternate_lba}"
    );
}

/// Assert the tool process ran *and* exited 0; on failure, the tool's
/// captured stdout and stderr are in the message.
fn assert_exit_zero(run: &ToolRun, what: &str) {
    match &run.ran {
        Some(status) if status.success() => {}
        Some(status) => panic!("{what} exited {status}: {}", run.text()),
        None => panic!(
            "{what}: the tool could not be spawned at all ({}); that is not a table \
             verdict, it is a broken invocation",
            run.spawn.as_deref().unwrap_or("(no reason)")
        ),
    }
}

/// The first `fdisk -l` table row naming `type_text` must show every
/// `token` as its own whitespace-separated word.
///
/// Caller-side geometry check: the numbers the planner planned must be
/// the numbers fdisk prints for the same partition — not just a
/// "success" verdict.
fn assert_fdisk_row(output: &str, type_text: &str, tokens: &[&str], what: &str) {
    let row = output
        .lines()
        .find(|line| line.contains(type_text))
        .unwrap_or_else(|| {
            panic!(
                "{what}: fdisk printed no table row naming {type_text:?}; its output was:\n{output}"
            )
        });
    for token in tokens {
        assert!(
            row.split_whitespace().any(|word| word == *token),
            "{what}: the fdisk row [{row}] does not show {token:?} (the planned value); \
             the whole output was:\n{output}"
        );
    }
}

/// Does any captured text still announce a GPT label? The wipe
/// verdict reads this: after wiping, none of the tool outputs may
/// still name GPT as the disk's label.
fn mentions_gpt(output: &str) -> bool {
    output.to_lowercase().contains("gpt")
}

// ---------------------------------------------------------------------------
// The unprivileged tests: rendered tables into the real tools
// ---------------------------------------------------------------------------

#[test]
fn gpt_single_table_is_accepted_by_the_real_tools() {
    let temp = tempfile::tempdir().expect("scratch directory for the GPT image");
    let image_path = temp.path().join("gpt-single.img");
    let sink = SparseFile::create(&image_path, DISK_BYTES)
        .unwrap_or_else(|error| panic!("create the 64 MiB sparse image: {error}"));

    // The GPT single layout, rendered and stamped with only its own
    // sectors — nothing else.
    let table = planned(LayoutKind::Single, TableKind::Gpt, LAST_LBA);
    let output = rendered(&table, LAST_LBA);
    stamp_table(&sink, &output, DISK_BYTES);

    // The backup header must live in the final LBA with the swapped
    // link, which the external tools below do not check.
    assert_backup_header(&image_path, LAST_LBA, SECTOR);

    // sfdisk is the first opinion, but its exit status is
    // unconditional: this util-linux inspects both headers, prints
    // warnings — "the primary/backup GPT table is corrupt" — and still
    // exits 0. A backup whose `alternate_lba` merely disagrees with the
    // primary's `my_lba` gets one step further: "Primary and backup
    // header mismatch." plus "1 error detected.", also with exit 0. So
    // the real evidence is the fdisk output below, and the backup
    // itself is pinned against the image bytes above.
    let path = image_path.display().to_string();
    let verify = run_tool("sfdisk", ["--verify", path.as_str()].as_slice());
    if skip_without_tool(&verify, "sfdisk", "the GPT single-table acceptance test") {
        return;
    }
    assert_exit_zero(&verify, "sfdisk --verify on the stamped GPT image");
    println!("sfdisk --verify (GPT single):\n{}", verify.text());

    // fdisk lists the disk with a GPT label and *the planned numbers*.
    let listing = run_tool("fdisk", ["-l", path.as_str()].as_slice());
    if skip_without_tool(&listing, "fdisk", "the GPT single-table acceptance test") {
        return;
    }
    assert_exit_zero(&listing, "fdisk -l on the stamped GPT image");
    let lowered = listing.text().to_lowercase();
    assert!(
        lowered.contains("disklabel type: gpt"),
        "fdisk does not report a GPT disklabel for the stamped image:\n{}",
        listing.text()
    );
    let (start, last, sectors) = single_span(&table);
    assert_fdisk_row(
        &listing.text(),
        "Microsoft basic data",
        &[&start.to_string(), &last.to_string(), &sectors.to_string()],
        "fdisk on the stamped GPT image",
    );
    println!("fdisk -l (GPT single):\n{}", listing.text());

    // parted is the third opinion, when the environment has it.
    let parted = run_tool(
        "parted",
        ["--script", path.as_str(), "unit", "s", "print"].as_slice(),
    );
    if skip_without_tool(&parted, "parted", "the parted cross-check of the GPT image") {
        return;
    }
    assert_exit_zero(&parted, "parted --script ... unit s print on the GPT image");
    assert!(
        parted
            .text()
            .to_lowercase()
            .contains("partition table: gpt"),
        "parted does not report a GPT partition table:\n{}",
        parted.text()
    );
    assert!(
        parted.text().contains(&format!("{start}s")) && parted.text().contains(&format!("{last}s")),
        "parted misses the planned span {start}s..{last}s:\n{}",
        parted.text()
    );
    println!("parted unit s print (GPT single):\n{}", parted.text());
}

#[test]
fn mbr_single_table_is_accepted_by_the_real_tools() {
    let temp = tempfile::tempdir().expect("scratch directory for the MBR image");
    let image_path = temp.path().join("mbr-single.img");
    let sink = SparseFile::create(&image_path, DISK_BYTES)
        .unwrap_or_else(|error| panic!("create the 64 MiB sparse image: {error}"));

    // The MBR single layout: one 512-byte LBA0 written, everything
    // else blank. The writer's CHS fields come from the LBA-compatible
    // 255/63 geometry; legacy-warnings (fdisk's "physical/logical
    // ... differs" style) are not failures here — exit 0 is the rule.
    let table = planned(LayoutKind::Single, TableKind::Mbr, LAST_LBA);
    let output = rendered(&table, LAST_LBA);
    stamp_table(&sink, &output, DISK_BYTES);

    let path = image_path.display().to_string();
    let verify = run_tool("sfdisk", ["--verify", path.as_str()].as_slice());
    if skip_without_tool(&verify, "sfdisk", "the MBR single-table acceptance test") {
        return;
    }
    assert_exit_zero(&verify, "sfdisk --verify on the stamped MBR image");
    println!("sfdisk --verify (MBR single):\n{}", verify.text());

    let listing = run_tool("fdisk", ["-l", path.as_str()].as_slice());
    if skip_without_tool(&listing, "fdisk", "the MBR single-table acceptance test") {
        return;
    }
    assert_exit_zero(&listing, "fdisk -l on the stamped MBR image");
    let lowered = listing.text().to_lowercase();
    assert!(
        lowered.contains("disklabel type: dos"),
        "fdisk does not report a DOS label for the stamped image:\n{}",
        listing.text()
    );
    // The type id must be the one the plan picked (0x07 basic data) and
    // the span the exact planned one.
    let (start, last, sectors) = single_span(&table);
    assert_fdisk_row(
        &listing.text(),
        "HPFS/NTFS/exFAT",
        &[&start.to_string(), &last.to_string(), &sectors.to_string()],
        "fdisk on the stamped MBR image",
    );
    println!("fdisk -l (MBR single):\n{}", listing.text());
}

#[test]
fn gpt_windows_to_go_layout_is_accepted() {
    // Three pinned windows (ESP 100 MiB, MSR 16 MiB, data) never fit a
    // 64 MiB disk, so this layout's image is 128 MiB; it is still one
    // sparse file, so the run stays cheap.
    let temp = tempfile::tempdir().expect("scratch directory for the WTG image");
    let image_path = temp.path().join("wtg.img");
    let sink = SparseFile::create(&image_path, WTG_DISK_BYTES)
        .unwrap_or_else(|error| panic!("create the 128 MiB sparse image: {error}"));

    let table = planned(LayoutKind::WindowsToGo, TableKind::Gpt, WTG_LAST_LBA);
    let output = rendered(&table, WTG_LAST_LBA);
    stamp_table(&sink, &output, WTG_DISK_BYTES);

    let path = image_path.display().to_string();
    assert_backup_header(&image_path, WTG_LAST_LBA, SECTOR);
    let verify = run_tool("sfdisk", ["--verify", path.as_str()].as_slice());
    if skip_without_tool(&verify, "sfdisk", "the windows-to-go acceptance test") {
        return;
    }
    assert_exit_zero(&verify, "sfdisk --verify on the windows-to-go image");
    println!("sfdisk --verify (windows-to-go):\n{}", verify.text());

    let listing = run_tool("fdisk", ["-l", path.as_str()].as_slice());
    if skip_without_tool(&listing, "fdisk", "the windows-to-go acceptance test") {
        return;
    }
    assert_exit_zero(&listing, "fdisk -l on the windows-to-go image");
    assert!(
        listing
            .text()
            .to_lowercase()
            .contains("disklabel type: gpt"),
        "fdisk does not report a GPT disklabel for the windows-to-go image:\n{}",
        listing.text()
    );
    // The three planned partitions in fdisk's own words, with the
    // three planned start LBAs.
    let esp = &table.partitions[0];
    let msr = &table.partitions[1];
    let data = &table.partitions[2];
    assert_fdisk_row(
        &listing.text(),
        "EFI System",
        &[&esp.start_lba.to_string(), &esp.last_lba.to_string()],
        "windows-to-go ESP row",
    );
    assert_fdisk_row(
        &listing.text(),
        "Microsoft reserved",
        &[&msr.start_lba.to_string(), &msr.last_lba.to_string()],
        "windows-to-go MSR row",
    );
    assert_fdisk_row(
        &listing.text(),
        "Microsoft basic data",
        &[&data.start_lba.to_string(), &data.last_lba.to_string()],
        "windows-to-go data row",
    );
    println!("fdisk -l (windows-to-go):\n{}", listing.text());
}

#[test]
fn wipe_removes_the_table() {
    let temp = tempfile::tempdir().expect("scratch directory for the wiped image");
    let image_path = temp.path().join("wiped.img");
    let mut sink = SparseFile::create(&image_path, DISK_BYTES)
        .unwrap_or_else(|error| panic!("create the 64 MiB sparse image: {error}"));

    // Build the same GPT disk as the acceptance test above: it is the
    // thing the wipe has to make disappear.
    let table = planned(LayoutKind::Single, TableKind::Gpt, LAST_LBA);
    let output = rendered(&table, LAST_LBA);
    stamp_table(&sink, &output, DISK_BYTES);

    // The wipe: first and last 1 MiB zeroed, flushed, table re-read.
    // A 64 MiB disk takes the two-window shape (it is larger than
    // 2 MiB), which covers the whole GPT metadata surface.
    wipe_device(&mut sink, DISK_BYTES, false)
        .unwrap_or_else(|error| panic!("wipe of the 64 MiB GPT image failed: {error}"));

    // Re-read the table surfaces through the same sink and hand them
    // to the parser: LBA0 signature gone means no layout at all — the
    // blank-media verdict, not an error.
    let mut lba0 = vec![0u8; 512];
    sink.read_at(0, &mut lba0)
        .unwrap_or_else(|error| panic!("re-read LBA0 after wipe: {error}"));
    let mut header = vec![0u8; 512];
    sink.read_at(512, &mut header)
        .unwrap_or_else(|error| panic!("re-read the GPT header after wipe: {error}"));
    let mut entries = vec![0u8; 32 * 512];
    sink.read_at(1024, &mut entries)
        .unwrap_or_else(|error| panic!("re-read the GPT entries after wipe: {error}"));
    let mut last_sector = vec![0u8; 512];
    sink.read_at(LAST_LBA * SECTOR, &mut last_sector)
        .unwrap_or_else(|error| panic!("re-read the final sector after wipe: {error}"));
    let layout = detect_layout(
        &lba0,
        Some(&header),
        Some(&entries),
        Some(&last_sector),
        512,
    );
    assert!(
        layout.is_none(),
        "the wiped image still parses as a layout: {layout:?}"
    );

    // The tools must agree. On the blank image sfdisk legitimately
    // answers exit 0 with "unrecognized partition table type" (measured
    // on this machine, see the module docs) — but then its text may not
    // name GPT; a hard failure is an acceptable blank-disk refusal, and
    // either shape is printed, never swallowed.
    let path = image_path.display().to_string();
    let verify = run_tool("sfdisk", ["--verify", path.as_str()].as_slice());
    if skip_without_tool(&verify, "sfdisk", "the wipe acceptance test") {
        // Reported as a skip above; the fdisk verdict below still runs.
    } else if verify.ran.is_some_and(|status| status.success()) {
        assert!(
            !mentions_gpt(&verify.text()),
            "sfdisk --verify still sees a GPT label on the wiped image:\n{}",
            verify.text()
        );
    }
    println!("sfdisk --verify (wiped):\n{}", verify.text());

    // fdisk's blank disk shows no disklabel line at all: the second
    // "nothing behind" verdict.
    let listing = run_tool("fdisk", ["-l", path.as_str()].as_slice());
    if skip_without_tool(&listing, "fdisk", "the wipe acceptance test") {
        return;
    }
    assert_exit_zero(&listing, "fdisk -l on the wiped image");
    assert!(
        !listing.text().to_lowercase().contains("disklabel type"),
        "fdisk still reports a disklabel on the wiped image:\n{}",
        listing.text()
    );
    println!("fdisk -l (wiped):\n{}", listing.text());
}

#[test]
fn sgdisk_verification_is_documented_when_available() {
    let temp = tempfile::tempdir().expect("scratch directory for the gdisk image");
    let image_path = temp.path().join("gpt-single.img");
    let sink = SparseFile::create(&image_path, DISK_BYTES)
        .unwrap_or_else(|error| panic!("create the 64 MiB sparse image: {error}"));
    let table = planned(LayoutKind::Single, TableKind::Gpt, LAST_LBA);
    stamp_table(&sink, &rendered(&table, LAST_LBA), DISK_BYTES);

    let path = image_path.display().to_string();
    let verify = run_tool("sgdisk", ["--verify", path.as_str()].as_slice());
    if skip_without_tool(&verify, "sgdisk", "the gdisk verification step") {
        eprintln!(
            "maintainer command with gdisk installed (the same rendered GPT single \
             layout this test just stamped): sgdisk --verify <image>"
        );
        eprintln!("expected verdict: exit 0, and 'Verification ... OK' style lines only");
        return;
    }
    // sgdisk is here: run the documented command for real.
    assert_exit_zero(&verify, "sgdisk --verify on the stamped GPT image");
    println!("sgdisk --verify:\n{}", verify.text());
}

// ---------------------------------------------------------------------------
// The root test: the kernel publishes what the plan planned
// ---------------------------------------------------------------------------

/// Whether this process counts as root (effective user id 0): the gate
/// `LoopDevice::acquire` reads to tell a documented skip from a real
/// failure, exactly like `tests/loop_device.rs`.
fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

/// Report an acquisition failure honestly: without privileges it is
/// the documented skip (print the reason, `None`, the caller ends the
/// test); as root the environment is presumed working, so a failure is
/// a bug and panics with the real reason.
fn fail_or_skip<T>(message: String) -> Option<T> {
    if is_root() {
        panic!("the loop-device test ran as root but could not attach a loop device: {message}");
    }
    eprintln!("skip: {message}");
    None
}

/// One loop device attached to this test's scratch image; `Drop`
/// detaches it again. Same shape as the `LoopDevice` of
/// `tests/loop_device.rs`, tuned for the partition-publish test:
/// `--direct-io=off` keeps the kernel's writes inside the backing
/// file's page cache, `--partscan` makes the kernel partition-scan the
/// attached image so the table write below can really publish nodes.
struct LoopDevice {
    /// The device node losetup picked, e.g. `/dev/loop7`.
    path: PathBuf,
    /// Kernel disk name of the node (`loop7`), for sysfs paths.
    name: String,
}

impl LoopDevice {
    /// Create `dir/backing.img` of `len` bytes (sparse: `set_len`
    /// only) and attach a free loop device to it with
    /// `losetup --find --show --direct-io=off --partscan`. Returns
    /// `None` (with an explanatory `eprintln!`) when the process is
    /// not root and the attach fails on missing privileges; a *root*
    /// run panics on any failure instead of quietly testing nothing.
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
                    "losetup is missing or cannot run ({error}); the partition-publish test \
                     needs util-linux and root, see the module docs"
                ));
            }
        };
        if !attach.status.success() {
            let stderr = String::from_utf8_lossy(&attach.stderr)
                .trim_end()
                .to_owned();
            return fail_or_skip(format!(
                "losetup did not attach a loop device ({}); without root this is the \
                 expected permission failure, see the module docs: {stderr}",
                attach.status
            ));
        }
        let stdout = String::from_utf8_lossy(&attach.stdout);
        let Some(node) = stdout
            .lines()
            .last()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        else {
            return fail_or_skip(
                "losetup attached a device but printed no node path; cannot continue".to_owned(),
            );
        };
        let path = PathBuf::from(node);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        // Guard: the node must be a real block device — a regular file
        // there would mean the attach answer cannot be trusted.
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
        Some(LoopDevice { path, name })
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        // Detach; teardown failures (already detached, busy) are noise,
        // not a verdict, so they are ignored — like the loop_device.rs
        // pattern this mirrors.
        let _ = Command::new("losetup").arg("-d").arg(&self.path).status();
    }
}

/// The sysfs geometry of the loop node that [`LoopDevice::acquire`]
/// attached, mirrored from `tests/loop_device.rs`: the extent in bytes
/// (sysfs `size` is in 512-byte units whatever the block size), plus
/// the logical and physical block sizes with the 512/4096 fallbacks.
/// Unreadable values fall back to the S07 defaults, mirroring the
/// pattern this copies.
fn geometry(path: &Path) -> (u64, u32, u32) {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let size = fs::read_to_string(Path::new("/sys/block").join(name).join("size"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or_default()
        * 512;
    let queue = |file: &str, fallback: u32| {
        fs::read_to_string(Path::new("/sys/block").join(name).join("queue").join(file))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .unwrap_or(fallback)
    };
    let logical = queue("logical_block_size", 512);
    let physical = queue("physical_block_size", 4096);
    (size, logical, physical)
}

/// The sysfs sector count of one published partition node read from
/// the whole-disk directory spelling, `<sysfs>/class/block/<disk>/<node>/size`.
fn published_sectors(disk: &str, node: &str) -> std::io::Result<u64> {
    let text = fs::read_to_string(
        Path::new("/sys/class/block")
            .join(disk)
            .join(node)
            .join("size"),
    )?;
    text.trim().parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("a size of {node:?} on disk {disk:?} is not a number: {error}"),
        )
    })
}

#[ignore = "needs root and a loop device: sudo losetup; see the module docs"]
#[test]
fn kernel_publishes_the_planned_partitions() {
    let temp = tempfile::tempdir().expect("scratch directory for the loop test");
    let Some(device) = LoopDevice::acquire(temp.path(), DISK_BYTES) else {
        return;
    };
    let (size, logical, physical) = geometry(&device.path);
    assert_eq!(
        size, DISK_BYTES,
        "the loop extent is exactly the planned 64 MiB, so the plan below is the plan"
    );
    let dev = BlockDevice::open_with(&device.path, size, logical, physical)
        .unwrap_or_else(|error| panic!("open the loop node exclusively: {error}"));

    // The GPT single table, written through the real BlockDevice sink
    // (direct-shaped windows when the kernel took O_DIRECT), then the
    // kernel is told to re-read it.
    let table = planned(LayoutKind::Single, TableKind::Gpt, LAST_LBA);
    let output = rendered(&table, LAST_LBA);
    stamp_table(&dev, &output, DISK_BYTES);
    dev.reread_partitions()
        .unwrap_or_else(|error| panic!("BLKRRPART on {}: {error}", device.path.display()));

    // One partition only, on a loop device whose name already ends in
    // a digit, so the node is `<disk>p1` (e.g. `loop7p1`).
    let (start, last, sectors) = single_span(&table);
    let node = format!("{}p1", device.name);
    wait_for_partitions(
        &SysfsRoot::new("/sys"),
        &device.name,
        std::slice::from_ref(&node),
        PARTITION_POLL_TIMEOUT,
        PARTITION_POLL_INTERVAL,
    )
    .unwrap_or_else(|error| panic!("the kernel did not publish {node} in time: {error}"));

    // The published node's sysfs size must equal the planned sector
    // count exactly — the kernel's view of the span matches the
    // planner's bytes.
    let sysfs_sectors = published_sectors(&device.name, &node)
        .unwrap_or_else(|error| panic!("read the sysfs size of {node}: {error}"));
    assert_eq!(
        sysfs_sectors, sectors,
        "the kernel published node {node} from sector {start} to sector {last}; its size \
         count must equal the planned sector count ({sectors})"
    );
    println!(
        "the kernel published {node} at /sys/class/block/{}/{} with size {sysfs_sectors} \
         (planned {sectors})",
        device.name, node
    );
}
