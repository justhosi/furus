use super::super::windows::loader_description;
use super::super::windows::windows_identity;
use super::*;
use crate::part::plan::data_window;
use crate::windows::bcd;

#[test]
fn run_windows_refuses_a_non_gpt_table() {
    // A hand-built plan with a recorded MBR table: the GPT-only
    // layout refuses before the device or the mounts are touched,
    // naming what is needed.
    let partitions = Rc::new(Cell::new(0usize));
    let opener = CountingOpener {
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Mbr));
    let error = run(
        &mut ctx,
        &BootloaderMode::Windows,
        &image_ref("missing.wim", furus_proto::ImageKind::Wim),
        &furus_proto::Filesystem::Ntfs,
        None,
    )
    .expect_err("a non-GPT table refuses");
    assert!(
        !matches!(error, CoreError::NotImplemented { .. }),
        "a wired mode is never NotImplemented: {error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("GPT"), "names what is needed: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(partitions.get(), 0, "the partition never opens");
}

#[test]
fn run_windows_refuses_an_unparsable_stamped_gpt() {
    // A recorded GPT table over a zeroed disk: the ESP formats, then
    // the re-read finds no GPT header and refuses as invalid naming
    // the problem, before any mount.
    let target = VecTarget::new(256 * 1024 * 1024, 512).expect("the disk allocates");
    let partitions = Rc::new(Cell::new(0usize));
    let opener = DiskOpener {
        target: target.clone(),
        partitions: Rc::clone(&partitions),
    };
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Gpt));
    let error = run(
        &mut ctx,
        &BootloaderMode::Windows,
        &image_ref("missing.wim", furus_proto::ImageKind::Wim),
        &furus_proto::Filesystem::Ntfs,
        None,
    )
    .expect_err("an unparsable GPT refuses");
    assert!(
        !matches!(error, CoreError::NotImplemented { .. }),
        "a wired mode is never NotImplemented: {error:?}"
    );
    let text = error.to_string();
    assert!(text.contains("GPT"), "names the problem: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(partitions.get(), 0, "the data partition never opens");
}

/// A mounted-partition double over a shared temp dir: `free_bytes`
/// answers huge, `release` counts its calls and optionally fails.
/// The root is `Rc`-shared with the test so the placed files stay
/// inspectable after the run drops its own handle.
#[derive(Debug)]
struct CountingMount {
    root: Rc<tempfile::TempDir>,
    releases: Rc<Cell<usize>>,
    fail_release: bool,
    /// When the data mount is a real FUSE NTFS mount over the raw
    /// image, `release` must also unmount it so the writes flush back
    /// into the image before the test inspects it.
    unmount: bool,
}

impl crate::pipeline::opener::MountedPartition for CountingMount {
    fn path(&self) -> &std::path::Path {
        self.root.path()
    }

    fn free_bytes(&self) -> TestResult<u64> {
        Ok(u64::MAX)
    }

    fn release(&mut self) -> TestResult<()> {
        self.releases.set(self.releases.get() + 1);
        if self.fail_release {
            return Err(CoreError::invalid("test mount release fails".to_string()));
        }
        if self.unmount {
            let run = std::process::Command::new("fusermount3")
                .arg("-u")
                .arg(self.root.path())
                .output();
            match run {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    return Err(CoreError::invalid(format!(
                        "test mount unmount fails: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                Err(source) => {
                    return Err(CoreError::io(self.root.path(), source));
                }
            }
        }
        Ok(())
    }
}

/// A test [`Opener`](crate::pipeline::opener::Opener) for the
/// Windows arm: the whole disk is one shared [`VecTarget`], the
/// data and ESP mounts are [`CountingMount`] doubles over distinct
/// temp dirs. The three knobs pin the three teardown paths: a
/// failing ESP mount, a failing data release, a failing ESP
/// release. Every opener call is logged to `events` in order, so a
/// test can prove which calls the arm never makes — `partition`
/// among them: opening it re-caches the whole-disk handle the arm
/// just released.
#[derive(Debug)]
struct WindowsOpener {
    target: VecTarget,
    data_root: Rc<tempfile::TempDir>,
    esp_root: Rc<tempfile::TempDir>,
    data_releases: Rc<Cell<usize>>,
    esp_releases: Rc<Cell<usize>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_esp_mount: bool,
    fail_data_release: bool,
    fail_esp_release: bool,
    /// The raw NTFS image `partition_path` hands back. It lives in its
    /// own temp dir, separate from `data_root`, because `data_root` is
    /// the *mount point* for that image in the success test, not the
    /// directory that holds it. The `Rc` keeps the directory alive for
    /// the whole run; `partition_node()` names the file inside it.
    image_dir: Rc<tempfile::TempDir>,
    partition_capacity: u64,
    /// When true, `mount_partition` performs a real FUSE NTFS mount of
    /// the raw image onto `data_root` instead of returning a bare
    /// directory. The success test flips this on so `to_go::install`
    /// reads what `apply_ntfs` actually wrote.
    mount_data: bool,
}

impl WindowsOpener {
    fn new(target: VecTarget) -> Self {
        let image_dir = Rc::new(tempfile::tempdir().expect("the image dir allocates"));
        Self {
            target,
            data_root: Rc::new(tempfile::tempdir().expect("the data mount allocates")),
            esp_root: Rc::new(tempfile::tempdir().expect("the esp mount allocates")),
            data_releases: Rc::new(Cell::new(0)),
            esp_releases: Rc::new(Cell::new(0)),
            events: Rc::new(RefCell::new(Vec::new())),
            fail_esp_mount: false,
            fail_data_release: false,
            fail_esp_release: false,
            image_dir,
            partition_capacity: 256 * 1024 * 1024,
            mount_data: false,
        }
    }

    /// The path of the raw NTFS image inside `image_dir`.
    fn partition_node(&self) -> std::path::PathBuf {
        self.image_dir.path().join("ntfs.img")
    }
}

impl crate::pipeline::opener::Opener for WindowsOpener {
    fn device(&self) -> TestResult<Box<dyn crate::pipeline::target::Target>> {
        self.events.borrow_mut().push("device");
        Ok(Box::new(self.target.clone()))
    }

    fn partition(&self) -> TestResult<Box<dyn Volume>> {
        self.events.borrow_mut().push("partition");
        Ok(Box::new(
            crate::fs::VecVolume::new(self.partition_capacity, 512)
                .expect("the test partition volume allocates"),
        ))
    }

    fn partition_path(&self) -> TestResult<std::path::PathBuf> {
        Ok(self.partition_node())
    }

    fn release(&self) -> TestResult<()> {
        self.events.borrow_mut().push("release");
        Ok(())
    }

    fn mount_partition(
        &self,
        _filesystem: &furus_proto::Filesystem,
    ) -> TestResult<Box<dyn crate::pipeline::opener::MountedPartition>> {
        self.events.borrow_mut().push("mount_data");
        let mut unmount = false;
        if self.mount_data {
            let run = std::process::Command::new("ntfs-3g")
                .arg("-o")
                .arg("noallow_other,no_def_opts")
                .arg(self.partition_node())
                .arg(self.data_root.path())
                .output();
            match run {
                Ok(output) if output.status.success() => unmount = true,
                Ok(output) => {
                    return Err(CoreError::invalid(format!(
                        "test data mount fails: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                Err(source) => {
                    return Err(CoreError::io(self.partition_node(), source));
                }
            }
        }
        Ok(Box::new(CountingMount {
            root: Rc::clone(&self.data_root),
            releases: Rc::clone(&self.data_releases),
            fail_release: self.fail_data_release,
            unmount,
        }))
    }

    fn mount_esp(&self) -> TestResult<Box<dyn crate::pipeline::opener::MountedPartition>> {
        self.events.borrow_mut().push("mount_esp");
        if self.fail_esp_mount {
            return Err(CoreError::invalid("test esp mount fails".to_string()));
        }
        Ok(Box::new(CountingMount {
            root: Rc::clone(&self.esp_root),
            releases: Rc::clone(&self.esp_releases),
            fail_release: self.fail_esp_release,
            unmount: false,
        }))
    }
}

/// Stamp a `WindowsToGo` GPT onto a zeroed [`VecTarget`] of `size`
/// bytes with 512-byte sectors, through the same
/// `request`/`plan`/`render` the stamper runs, and hand back the
/// target plus the plan it stamped. The data partition's GUIDs come
/// out of the plan (never a positional literal), which is what the
/// identity tests compare against.
fn stamp_windows_gpt(size: u64) -> (VecTarget, crate::part::plan::TablePlan) {
    let target = VecTarget::new(size, 512).expect("the disk allocates");
    let request = crate::part::plan::request(
        LayoutKind::WindowsToGo,
        TableKind::Gpt,
        512,
        size,
        crate::part::plan::DataType::MicrosoftBasicData,
    )
    .expect("the request plans");
    let plan = crate::part::plan::plan(&request).expect("the layout plans");
    let rendered =
        crate::part::plan::render(&plan, 512, request.last_lba).expect("the table renders");
    for write in &rendered.writes {
        target
            .write_all_at(write.lba * 512, &write.bytes)
            .expect("the sector lands");
    }
    (target, plan)
}

/// 512 MiB with 512-byte sectors, the same shape as the
/// `data_window_matches_the_planned_data_role` fixture: the Windows
/// arm's stamped layout at a realistic scale.
const WINDOWS_DISK_BYTES: u64 = 512 * 1024 * 1024;

#[test]
fn windows_identity_reports_the_planned_data_partition() {
    // The stamped GPT re-read through `windows_identity`: the disk
    // GUID equals the renderer's, and the partition GUID equals the
    // parsed entry at the planned data window — found by its LBA
    // span, never by its table position.
    let (mut target, plan) = stamp_windows_gpt(WINDOWS_DISK_BYTES);
    let identities =
        windows_identity(&mut target, 512, WINDOWS_DISK_BYTES).expect("the identity reads");
    let bcd::DeviceIdentity::Gpt {
        disk_guid,
        partition_guid,
    } = identities.data
    else {
        panic!("a GPT table reports the GPT identity");
    };
    assert_eq!(disk_guid, plan.disk_guid, "the disk GUID is the renderer's");
    let data = plan
        .partitions
        .iter()
        .find(|partition| partition.role == "data")
        .expect("the plan holds a data partition");
    assert_eq!(
        partition_guid, data.unique_guid,
        "the partition GUID is the data entry's"
    );
    // The ESP identity is found by the entry's type GUID, not by its
    // position, and carries the ESP's own unique GUID with the same
    // disk GUID as the data identity.
    let bcd::DeviceIdentity::Gpt {
        disk_guid: esp_disk_guid,
        partition_guid: esp_guid,
    } = identities.esp
    else {
        panic!("the ESP identity is GPT");
    };
    let esp = plan
        .partitions
        .iter()
        .find(|partition| partition.role == "esp")
        .expect("the plan holds an ESP");
    assert_eq!(esp_disk_guid, plan.disk_guid, "ESP carries the disk GUID");
    assert_eq!(
        esp_guid, esp.unique_guid,
        "the ESP GUID is the planned ESP entry's"
    );
    assert_ne!(
        esp_guid, partition_guid,
        "ESP and data are distinct entries"
    );
    // The same GUID through the parser: read the stamped header and
    // entry array back and find the entry whose span is the planned
    // data window.
    let (data_offset, data_len) = data_window(
        LayoutKind::WindowsToGo,
        TableKind::Gpt,
        512,
        WINDOWS_DISK_BYTES,
    )
    .expect("the data window plans");
    let data_start_lba = data_offset / 512;
    let data_sectors = data_len / 512;
    let mut header = vec![0u8; 512];
    target.read_at(512, &mut header).expect("the header reads");
    assert_eq!(
        &header[56..72],
        &disk_guid,
        "the stamped header carries the disk GUID"
    );
    let range = crate::part::gpt::gpt_entry_range(&header).expect("the array locates");
    let array_len = range.count as usize * range.entry_size as usize;
    let mut array = vec![0u8; array_len];
    target
        .read_at(range.entry_lba * 512, &mut array)
        .expect("the array reads");
    let (entries, _warnings) =
        crate::part::gpt::parse_gpt(&header, &array, 512).expect("the stamped table parses");
    let entry = entries
        .iter()
        .find(|entry| entry.start_lba == data_start_lba && entry.sectors == data_sectors)
        .expect("the parsed table holds the data entry");
    assert_eq!(
        entry.unique_guid.as_deref(),
        Some(crate::part::gpt::guid_to_string(&partition_guid).as_str()),
        "the parsed entry at the planned span carries the identity GUID"
    );
}

#[test]
fn windows_identity_refuses_without_a_planned_data_entry() {
    // The same stamped table with the data entry's span moved by one
    // sector: the parser still reads (an entry-array CRC mismatch is
    // only a warning), but no entry sits at the planned span, so the
    // identity refuses naming the window.
    let (mut target, plan) = stamp_windows_gpt(WINDOWS_DISK_BYTES);
    let slot = plan
        .partitions
        .iter()
        .position(|partition| partition.role == "data")
        .expect("the plan holds a data partition");
    // One entry is 128 bytes; the first-LBA field sits 32 bytes in.
    // The primary array starts at LBA 2 (see `write_gpt`).
    let at = 2 * 512 + slot as u64 * 128 + 32;
    let mut first = [0u8; 8];
    target.read_at(at, &mut first).expect("the entry reads");
    let moved = u64::from_le_bytes(first).wrapping_add(1).to_le_bytes();
    target.write_all_at(at, &moved).expect("the span moves");
    let error = windows_identity(&mut target, 512, WINDOWS_DISK_BYTES)
        .expect_err("a span-less table refuses");
    let text = error.to_string();
    assert!(text.contains("no data partition"), "names the miss: {text}");
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn windows_identity_refuses_without_an_esp_entry() {
    // Clear the ESP entry's type GUID so no entry carries the EFI
    // System type. The table still parses (an entry-array CRC
    // mismatch is only a warning), but the boot manager has no
    // partition to point at, so the identity refuses naming it.
    let (mut target, plan) = stamp_windows_gpt(WINDOWS_DISK_BYTES);
    let slot = plan
        .partitions
        .iter()
        .position(|partition| partition.role == "esp")
        .expect("the plan holds an ESP");
    // The type GUID is the first 16 bytes of a 128-byte entry; the
    // primary array starts at LBA 2 (see `write_gpt`).
    let at = 2 * 512 + slot as u64 * 128;
    target
        .write_all_at(at, &[0u8; 16])
        .expect("the ESP type clears");
    let error = windows_identity(&mut target, 512, WINDOWS_DISK_BYTES)
        .expect_err("an ESP-less table refuses");
    let text = error.to_string();
    assert!(
        text.contains("no EFI System partition"),
        "names the miss: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
}

#[test]
fn loader_description_prefers_name_then_description_then_windows() {
    // The exact string produced for the real install.wim image 1.
    assert_eq!(
        loader_description("Windows 11 Enterprise Evaluation", None),
        "Windows 11 Enterprise Evaluation"
    );
    // An unnamed image falls back to its non-empty description.
    assert_eq!(
        loader_description("", Some("A Windows description")),
        "A Windows description"
    );
    // Neither present (or whitespace-only) means the literal fallback.
    assert_eq!(loader_description("", None), "Windows");
    assert_eq!(loader_description("   ", Some("  ")), "Windows");
    // Whatever is chosen is always non-empty: the 12000004 element
    // must be a real string or bootmgr fails with 0xc0000001.
    assert!(!loader_description("", None).is_empty());
}

#[test]
fn windows_install_failure_releases_both_mounts_once() {
    if skip_without_wim_backend() || skip_without_ntfs_formatter() {
        return;
    }
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let wim = capture_windows_wim_without_bcd_template(scratch.path());
    let (target, _plan) = stamp_windows_gpt(256 * 1024 * 1024);
    let mut opener = WindowsOpener::new(target.clone());
    // Format the scratch image so the raw apply succeeds; the install
    // still mounts both partitions and releases them cleanly, so this
    // phase wants the real mounted data tree.
    format_ntfs_scratch(&mut opener);
    opener.mount_data = true;
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Gpt));
    let error = run(
        &mut ctx,
        &BootloaderMode::Windows,
        &image_ref(&wim.display().to_string(), furus_proto::ImageKind::Wim),
        &furus_proto::Filesystem::Ntfs,
        None,
    )
    .expect_err("a WIM without a BCD template refuses");
    assert!(
        !matches!(
            error,
            CoreError::Cancelled | CoreError::NotImplemented { .. }
        ),
        "a wired mode reports its install error: {error:?}"
    );
    let text = error.to_string();
    assert!(
        text.contains("BCD template") && text.contains("not a Windows image"),
        "the install error reports the refusal: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    assert_eq!(
        opener.data_releases.get(),
        1,
        "the data mount releases once on an install failure"
    );
    assert_eq!(
        opener.esp_releases.get(),
        1,
        "the esp mount releases once on an install failure"
    );
    let warns: Vec<&str> = reporter
        .events
        .iter()
        .filter_map(|event| match event {
            crate::pipeline::event::Event::Message {
                level: "warn",
                text,
            } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        warns
            .iter()
            .all(|line| !line.contains("mount release failed")),
        "clean releases fire no teardown warn: {warns:?}"
    );
}

#[test]
fn windows_esp_mount_failure_releases_the_data_mount_once() {
    if skip_without_wim_backend() || skip_without_ntfs_formatter() {
        return;
    }
    for fail_data_release in [false, true] {
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        // The ESP mount fails before `to_go::install` ever reads the
        // data tree, so the WIM only has to survive `apply_ntfs`: the
        // cheap template-less capture is enough here.
        let wim = capture_windows_wim_without_bcd_template(scratch.path());
        let (target, _plan) = stamp_windows_gpt(256 * 1024 * 1024);
        let mut opener = WindowsOpener::new(target.clone());
        opener.fail_esp_mount = true;
        opener.fail_data_release = fail_data_release;
        // Format the image so the raw apply succeeds, but leave
        // `mount_data` false: no FUSE mount is opened, so a failing
        // `release` cannot strand one past the test.
        format_ntfs_scratch(&mut opener);
        let mut reporter = Recorder::default();
        let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Gpt));
        let error = run(
            &mut ctx,
            &BootloaderMode::Windows,
            &image_ref(&wim.display().to_string(), furus_proto::ImageKind::Wim),
            &furus_proto::Filesystem::Ntfs,
            None,
        )
        .expect_err("a failing ESP mount refuses");
        let text = error.to_string();
        assert!(
            text.contains("esp mount fails"),
            "phase {fail_data_release}: the install error reports the ESP mount: {text}"
        );
        assert!(text.is_ascii(), "stays ASCII: {text}");
        assert_eq!(
            opener.data_releases.get(),
            1,
            "phase {fail_data_release}: the data mount releases exactly once after the ESP mount fails"
        );
        assert_eq!(
            opener.esp_releases.get(),
            0,
            "phase {fail_data_release}: the ESP mount never opens"
        );
        let warns: Vec<&str> = reporter
            .events
            .iter()
            .filter_map(|event| match event {
                crate::pipeline::event::Event::Message {
                    level: "warn",
                    text,
                } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        if fail_data_release {
            assert_eq!(
                warns
                    .iter()
                    .filter(|line| line.contains("mount release failed"))
                    .count(),
                1,
                "phase {fail_data_release}: the data-release failure is reported exactly once: {warns:?}"
            );
        } else {
            assert!(
                warns.is_empty(),
                "phase {fail_data_release}: clean releases fire no teardown warn: {warns:?}"
            );
        }
    }
}

#[test]
fn windows_releases_the_disk_before_mounting_the_partitions() {
    // The whole-disk handle stays open exclusively on a real
    // device, so opening a partition node while it is open fails
    // with EBUSY: `run_windows` releases the disk after the last
    // raw read (the BCD identity) and before the first mount, and
    // the opener reopens lazily on the next use. The run below
    // fails at the missing WIM during the raw NTFS apply, which is
    // before either mount opens, so the event log pins the order:
    // exactly one release, ahead of either mount attempt, and no
    // partition-volume open at all (that open re-caches the
    // whole-disk handle the release dropped, so the data mount
    // would then fail with EBUSY).
    let (target, _plan) = stamp_windows_gpt(256 * 1024 * 1024);
    let opener = WindowsOpener::new(target.clone());
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Gpt));
    let error = run(
        &mut ctx,
        &BootloaderMode::Windows,
        &image_ref("missing.wim", furus_proto::ImageKind::Wim),
        &furus_proto::Filesystem::Ntfs,
        None,
    )
    .expect_err("a missing WIM refuses before the mounts");
    let text = error.to_string();
    assert!(
        text.contains("missing.wim") || text.contains("wimlib"),
        "the install error reports the WIM: {text}"
    );
    assert!(text.is_ascii(), "stays ASCII: {text}");
    let events = opener.events.borrow();
    assert_eq!(
        events.iter().filter(|event| **event == "release").count(),
        1,
        "the disk releases exactly once: {events:?}"
    );
    // The capacity the raw apply needs comes from the stamped plan
    // geometry, so the partition volume never opens: opening it
    // re-caches the whole-disk handle the release above dropped,
    // and the first mount would then fail with EBUSY (the reported
    // bug).
    assert!(
        !events.contains(&"partition"),
        "the data partition volume never opens, only its node name: {events:?}"
    );
    let release = events
        .iter()
        .position(|event| *event == "release")
        .expect("the release is logged");
    assert!(
        !events.contains(&"mount_data"),
        "the data mount never opens when the raw apply refuses: {events:?}"
    );
    assert!(
        !events.contains(&"mount_esp"),
        "the ESP mount never opens when the raw apply refuses: {events:?}"
    );
    assert!(
        release < events.len(),
        "the disk releases before the run ends: {events:?}"
    );
}

/// Start a minimal hive: header plus two bins holding a `name` key
/// and free space — the same allocation shape the `to_go` fixture
/// uses, duplicated here because that helper is private to its
/// tests module. The BCD template names its root `System`; the
/// SYSTEM hive names its root `ROOT`.
fn windows_hive_root(name: &[u8]) -> crate::windows::regf::Hive {
    use crate::windows::regf::HBIN_USABLE;
    use crate::windows::regf::HDR_BIN_LENGTH;
    use crate::windows::regf::HDR_CHECKSUM;
    use crate::windows::regf::HDR_ROOT;
    use crate::windows::regf::Hive;
    use crate::windows::regf::NONE;
    assert!(
        name.len() <= 8,
        "the fixture root name fits the hand-built cell"
    );
    let mut buf = vec![0u8; 0x200];
    buf[0..4].copy_from_slice(b"regf");
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    buf[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes());
    buf[HDR_ROOT..HDR_ROOT + 4].copy_from_slice(&0x20u32.to_le_bytes());
    buf[HDR_BIN_LENGTH..HDR_BIN_LENGTH + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    buf.resize(0x3000, 0);
    buf[0x1000..0x1004].copy_from_slice(b"hbin");
    buf[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes());
    buf[0x1008..0x100C].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[0x2000..0x2004].copy_from_slice(b"hbin");
    buf[0x2004..0x2008].copy_from_slice(&0u32.to_le_bytes());
    buf[0x2008..0x200C].copy_from_slice(&0x1000u32.to_le_bytes());
    // Root key at cell 0x20: 4 + 0x4C + 4 = 84, rounded 88.
    let root_file = 0x1020usize;
    buf[root_file..root_file + 4].copy_from_slice(&(-88i32).to_le_bytes());
    buf[root_file + 4..root_file + 6].copy_from_slice(b"nk");
    buf[root_file + 6..root_file + 8].copy_from_slice(&0x20u16.to_le_bytes());
    buf[root_file + 0x14..root_file + 0x18].copy_from_slice(&NONE.to_le_bytes());
    buf[root_file + 0x20..root_file + 0x24].copy_from_slice(&NONE.to_le_bytes());
    buf[root_file + 0x2C..root_file + 0x30].copy_from_slice(&NONE.to_le_bytes());
    buf[root_file + 0x34..root_file + 0x38].copy_from_slice(&NONE.to_le_bytes());
    let name_len = u16::try_from(name.len()).expect("the fixture root name fits u16");
    buf[root_file + 0x4C..root_file + 0x4E].copy_from_slice(&name_len.to_le_bytes());
    buf[root_file + 0x50..root_file + 0x50 + name.len()].copy_from_slice(name);
    // Free cell covering the rest of the first bin.
    let free_file = root_file + 88;
    let free_size = 0x1000u32 - 0x20 - 88;
    buf[free_file..free_file + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
    // Second bin stays one free cell.
    let free2 = 0x2020usize;
    buf[free2..free2 + 4].copy_from_slice(&(HBIN_USABLE as i32).to_le_bytes());
    let checksum = Hive::header_checksum(&buf).expect("fixture header must checksum");
    buf[HDR_CHECKSUM..HDR_CHECKSUM + 4].copy_from_slice(&checksum.to_le_bytes());
    Hive::parse(&buf).expect("hand-built fixture must parse")
}

/// Add a subkey and return its cell offset.
fn windows_add_key(hive: &mut crate::windows::regf::Hive, parent: usize, name: &[u8]) -> usize {
    hive.add_child_key(parent, name, None)
        .expect("fixture key must allocate")
}

/// Add a DWORD value under `key`.
fn windows_add_dword(hive: &mut crate::windows::regf::Hive, key: usize, name: &[u8], value: u32) {
    hive.add_value(
        key,
        name,
        crate::windows::regf::REG_DWORD,
        &value.to_le_bytes(),
    )
    .expect("fixture DWORD must allocate");
}

/// Add an `Elements\{id}` subkey plus its `Element` value, mirroring
/// the `bcd` fixture pattern.
fn windows_add_element(
    hive: &mut crate::windows::regf::Hive,
    elements: usize,
    id: &str,
    vtype: u32,
    data: &[u8],
) {
    let key = windows_add_key(hive, elements, id.as_bytes());
    hive.add_value(key, b"Element", vtype, data)
        .expect("fixture element must allocate");
}

/// The resume object the template's loaders point at; `bcd::build`
/// now requires it so it can wire the device and winresume path.
const TEST_RESUME_GUID: &str = "{0c334284-9a41-4de1-99b3-a7e87e8ff07e}";

/// A synthetic BCD template the builder accepts for both firmwares:
/// the same objects and elements the `to_go` fixture carries,
/// duplicated here because that helper is private to its tests
/// module. Stand-in bytes (synthetic, not a real Windows hive).
fn windows_template_bytes() -> Vec<u8> {
    use crate::windows::bcd::OBJECT_BOOTMGR;
    use crate::windows::bcd::OBJECT_MEMDIAG;
    use crate::windows::bcd::TEMPLATE_LOADER_A194;
    use crate::windows::bcd::TEMPLATE_LOADER_B012;
    use crate::windows::bcd::TEMPLATE_LOADER_CBD9;
    use crate::windows::regf::REG_BINARY;
    use crate::windows::regf::REG_SZ;
    use crate::windows::regf::utf16_nul;
    let mut hive = {
        let root = windows_hive_root(b"ROOT");
        // Rename the root `ROOT` to `System`: the builder keys off
        // the root name. The hand-built cell holds the name length
        // at 0x4C and the bytes at 0x50; `System` fits the same
        // 88-byte cell with room to spare.
        let cell = root.root();
        let file = crate::windows::regf::Hive::cell_file(cell, "fixture root")
            .expect("the root cell locates");
        let mut bytes = root.to_bytes();
        bytes[file + 0x4C..file + 0x4E].copy_from_slice(&6u16.to_le_bytes());
        bytes[file + 0x50..file + 0x56].copy_from_slice(b"System");
        let parsed =
            crate::windows::regf::Hive::parse(&bytes).expect("the renamed root must parse");
        let checksum = crate::windows::regf::Hive::header_checksum(&parsed.to_bytes())
            .expect("the renamed root must checksum");
        let mut stamped = parsed.to_bytes();
        stamped[crate::windows::regf::HDR_CHECKSUM..crate::windows::regf::HDR_CHECKSUM + 4]
            .copy_from_slice(&checksum.to_le_bytes());
        crate::windows::regf::Hive::parse(&stamped).expect("the stamped root must parse")
    };
    let root = hive.root();
    let objects = windows_add_key(&mut hive, root, b"Objects");
    let bootmgr = windows_add_key(&mut hive, objects, OBJECT_BOOTMGR.as_bytes());
    let uefi = windows_add_key(&mut hive, objects, TEMPLATE_LOADER_B012.as_bytes());
    let bios = windows_add_key(&mut hive, objects, TEMPLATE_LOADER_A194.as_bytes());
    let resume = windows_add_key(&mut hive, objects, TEST_RESUME_GUID.as_bytes());
    let memdiag = windows_add_key(&mut hive, objects, OBJECT_MEMDIAG.as_bytes());
    let bootmgr_el = windows_add_key(&mut hive, bootmgr, b"Elements");
    windows_add_element(
        &mut hive,
        bootmgr_el,
        "23000003",
        REG_SZ,
        &utf16_nul(TEMPLATE_LOADER_CBD9),
    );
    windows_add_element(
        &mut hive,
        bootmgr_el,
        "12000002",
        REG_SZ,
        &utf16_nul("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
    );
    windows_add_element(&mut hive, bootmgr_el, "25000004", REG_BINARY, &[0x1e]);
    for (loader, suffix) in [
        (uefi, "\\system32\\winload.efi"),
        (bios, "\\system32\\winload.exe"),
    ] {
        let elements = windows_add_key(&mut hive, loader, b"Elements");
        windows_add_element(
            &mut hive,
            elements,
            "22000002",
            REG_SZ,
            &utf16_nul("\\windows"),
        );
        windows_add_element(&mut hive, elements, "42000002", REG_SZ, &utf16_nul(suffix));
        windows_add_element(
            &mut hive,
            elements,
            "23000003",
            REG_SZ,
            &utf16_nul(TEST_RESUME_GUID),
        );
    }
    let resume_el = windows_add_key(&mut hive, resume, b"Elements");
    windows_add_element(
        &mut hive,
        resume_el,
        "42000002",
        REG_SZ,
        &utf16_nul("\\system32\\winresume.efi"),
    );
    let memdiag_el = windows_add_key(&mut hive, memdiag, b"Elements");
    windows_add_element(
        &mut hive,
        memdiag_el,
        "12000002",
        REG_SZ,
        &utf16_nul("\\boot\\memtest.exe"),
    );
    hive.update_checksum().expect("fixture checksum must store");
    hive.into_bytes()
}

/// A minimal SYSTEM hive the SAN-policy patch accepts:
/// `Select\Current = 1` plus `ControlSet001\Services` with no
/// `partmgr` yet. Stand-in bytes (synthetic, not a real hive).
fn windows_system_bytes() -> Vec<u8> {
    let mut hive = windows_hive_root(b"ROOT");
    let root = hive.root();
    let select = windows_add_key(&mut hive, root, b"Select");
    windows_add_dword(&mut hive, select, b"Current", 1);
    let control = windows_add_key(&mut hive, root, b"ControlSet001");
    windows_add_key(&mut hive, control, b"Services");
    hive.update_checksum().expect("fixture checksum must store");
    hive.into_bytes()
}

/// Capture a synthetic Windows-shaped tree into a WIM: the fake
/// boot managers, `boot.sdi`, the synthetic BCD template and a
/// minimal SYSTEM hive. Enough for `to_go::install` to return `Ok`
/// — the smallest tree the installer accepts, with stand-in payload
/// bytes (synthetic, not real Windows files).
fn capture_windows_wim(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("src");
    let config = src.join("Windows/System32/config");
    std::fs::create_dir_all(&config).expect("the config dir creates");
    std::fs::write(config.join("BCD-Template"), windows_template_bytes())
        .expect("the template writes");
    std::fs::write(config.join("SYSTEM"), windows_system_bytes()).expect("the system writes");
    std::fs::create_dir_all(src.join("Windows/Boot/EFI")).expect("the efi dir creates");
    std::fs::create_dir_all(src.join("Windows/Boot/PCAT")).expect("the pcat dir creates");
    std::fs::write(
        src.join("Windows/Boot/EFI/bootmgfw.efi"),
        b"fake-windows-efi-loader",
    )
    .expect("the efi loader writes");
    std::fs::write(
        src.join("Windows/Boot/PCAT/bootmgr"),
        b"fake-windows-bios-loader",
    )
    .expect("the bios loader writes");
    std::fs::write(
        src.join("Windows/Boot/PCAT/boot.sdi"),
        b"fake-windows-boot-sdi",
    )
    .expect("boot.sdi writes");
    let wim = dir.join("windows-test.wim");
    let run = std::process::Command::new("wimlib-imagex")
        .arg("capture")
        .arg(&src)
        .arg(&wim)
        .arg("testimg")
        .output()
        .expect("wimlib-imagex capture spawns past the skip gate");
    assert!(
        run.status.success(),
        "capture failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    wim
}

/// Capture a synthetic Windows-shaped tree into a WIM with no
/// `Windows/System32/config/BCD-Template`, so `apply_ntfs` succeeds
/// but `to_go::install` then refuses "not a Windows image".
fn capture_windows_wim_without_bcd_template(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("the src dir creates");
    std::fs::write(src.join("a.txt"), b"not windows\n").expect("the file writes");
    let wim = dir.join("windows-no-template.wim");
    let run = std::process::Command::new("wimlib-imagex")
        .arg("capture")
        .arg(&src)
        .arg(&wim)
        .arg("testimg")
        .output()
        .expect("wimlib-imagex capture spawns past the skip gate");
    assert!(
        run.status.success(),
        "capture failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    wim
}

/// Build a real NTFS volume the raw apply writes into and return the
/// raw image path. This only formats the image; it leaves `mount_data`
/// alone, so a caller that needs the image mounted over the data root
/// has to set `mount_data` itself before the run.
fn format_ntfs_scratch(opener: &mut WindowsOpener) -> std::path::PathBuf {
    let partition_node = opener.partition_node();
    let image = std::fs::File::create(&partition_node).expect("the scratch ntfs image creates");
    image
        .set_len(opener.partition_capacity)
        .expect("the scratch ntfs image sizes");
    let format = std::process::Command::new("mkntfs")
        .arg("-F")
        .arg("-Q")
        .arg(&partition_node)
        .output()
        .expect("mkntfs spawns past the skip gate");
    assert!(
        format.status.success(),
        "mkntfs failed: {}",
        String::from_utf8_lossy(&format.stderr)
    );
    partition_node
}

/// Skip gate (the `skip:` convention): the library probe first,
/// then the `wimlib-imagex` presence probe.
fn skip_without_wim_backend() -> bool {
    if !wimlib_sys::linked() {
        eprintln!("skip: the windows success install needs libwim, which this build did not link");
        return true;
    }
    if std::process::Command::new("wimlib-imagex")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!(
            "skip: the windows success install needs wimlib-imagex, which this host does not ship"
        );
        return true;
    }
    false
}

/// Skip gate for the success path's NTFS round-trip: it needs a real
/// formatter (`mkntfs`/`mkfs.ntfs`) to build the scratch image, `ntfs-3g`
/// to mount it (unprivileged FUSE), and `fusermount3` to release it.
fn skip_without_ntfs_formatter() -> bool {
    if crate::fs::ntfs::find_tool().is_err() {
        eprintln!(
            "skip: the windows success install needs mkntfs/mkfs.ntfs, which this host does not ship"
        );
        return true;
    }
    if std::process::Command::new("ntfs-3g")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: the windows success install needs ntfs-3g to mount the applied image");
        return true;
    }
    if std::process::Command::new("fusermount3")
        .arg("--help")
        .output()
        .is_err()
    {
        eprintln!(
            "skip: the windows success install needs fusermount3 to release the applied image"
        );
        return true;
    }
    false
}

/// Read one file out of the raw NTFS image with `ntfscat`, so the
/// success test can inspect what `apply_ntfs` actually wrote without a
/// live mount.
fn ntfs_read(image: &std::path::Path, path: &str) -> Vec<u8> {
    let run = std::process::Command::new("ntfscat")
        .arg(image)
        .arg(path)
        .output()
        .expect("ntfscat spawns past the skip gate");
    assert!(
        run.status.success(),
        "ntfscat {path} failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    run.stdout
}

#[test]
fn windows_success_releases_both_mounts_once() {
    // The full `run` against a synthetic WIM the installer accepts:
    // both mounts release exactly once each (no double release, no
    // leak), the summary reports, the UEFI store lands on the ESP,
    // the BIOS boot files land on data, and the applied SYSTEM
    // carries the offline SAN policy. Needs no root and no real
    // device: the disk is a stamped `VecTarget`, the mounts are temp
    // dirs, the WIM is captured at test time.
    if skip_without_wim_backend() || skip_without_ntfs_formatter() {
        return;
    }
    let scratch = tempfile::tempdir().expect("scratch dir fits");
    let wim = capture_windows_wim(scratch.path());
    let (target, _plan) = stamp_windows_gpt(256 * 1024 * 1024);
    let mut opener = WindowsOpener::new(target.clone());
    // Build a real NTFS volume the raw apply writes into, then mount it
    // over the data root so `to_go::install` sees the files `apply_ntfs`
    // actually laid down. The capacity matches the stamped layout.
    let partition_node = format_ntfs_scratch(&mut opener);
    opener.mount_data = true;
    let mut reporter = Recorder::default();
    let mut ctx = run_context_table(&opener, &mut reporter, Some(TableKind::Gpt));
    run(
        &mut ctx,
        &BootloaderMode::Windows,
        &image_ref(&wim.display().to_string(), furus_proto::ImageKind::Wim),
        &furus_proto::Filesystem::Ntfs,
        None,
    )
    .expect("the windows install runs");
    assert_eq!(
        opener.data_releases.get(),
        1,
        "the data mount releases exactly once"
    );
    assert_eq!(
        opener.esp_releases.get(),
        1,
        "the esp mount releases exactly once"
    );
    let texts: Vec<&str> = reporter
        .events
        .iter()
        .filter_map(|event| match event {
            crate::pipeline::event::Event::Message { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        texts
            .iter()
            .any(|line| line.contains("installed windows (") && line.contains("files applied")),
        "the summary reports the applied files: {texts:?}"
    );
    assert!(
        texts.iter().all(|line| line.is_ascii()),
        "every message stays ASCII"
    );
    assert!(
        opener
            .esp_root
            .path()
            .join("EFI/Microsoft/Boot/BCD")
            .is_file(),
        "the UEFI store lands on the ESP"
    );
    // Regression guard: the To Go loader must carry 12000004 or
    // bootmgr fails with 0xc0000001. Reverting the caller's
    // `description: Some(...)` back to `None` must fail this test.
    let bytes = std::fs::read(opener.esp_root.path().join("EFI/Microsoft/Boot/BCD"))
        .expect("the uefi store reads");
    let hive = crate::windows::regf::Hive::parse(&bytes).expect("the store re-parses");
    let loader = crate::windows::bcd::default_object(crate::windows::bcd::Firmware::Uefi);
    let (vtype, data) = hive
        .element_data(loader, 0x1200_0004)
        .expect("read the description element")
        .expect("the To Go loader must carry 12000004 (bootmgr needs it)");
    assert_eq!(vtype, crate::windows::regf::REG_SZ);
    assert_eq!(
        crate::windows::regf::decode_sz(&data).expect("description text"),
        "testimg",
        "the loader description comes from the applied WIM image"
    );
    assert_eq!(
        ntfs_read(&partition_node, "bootmgr"),
        b"fake-windows-bios-loader",
        "the BIOS boot manager lands on data"
    );
    assert_eq!(
        ntfs_read(&partition_node, "boot/boot.sdi"),
        b"fake-windows-boot-sdi",
        "boot.sdi lands on data"
    );
    // The SAN policy in the applied SYSTEM is offline (4).
    use crate::windows::regf::Hive;
    use crate::windows::regf::REG_DWORD;
    let system = ntfs_read(&partition_node, "Windows/System32/config/SYSTEM");
    let hive = Hive::parse(&system).expect("the applied SYSTEM re-parses");
    let root = hive.root();
    let control = hive
        .find_child(root, b"ControlSet001")
        .expect("find control")
        .expect("ControlSet001 survives");
    let services = hive
        .find_child(control, b"Services")
        .expect("find services")
        .expect("Services survives");
    let partmgr = hive
        .find_child(services, b"partmgr")
        .expect("find partmgr")
        .expect("partmgr exists after the patch");
    let parameters = hive
        .find_child(partmgr, b"Parameters")
        .expect("find parameters")
        .expect("Parameters exists after the patch");
    let (vtype, value) = hive
        .read_value(parameters, b"SanPolicy")
        .expect("read SanPolicy")
        .expect("SanPolicy exists after the patch");
    let bytes: [u8; 4] = value.as_slice().try_into().expect("a DWORD stays 4 bytes");
    assert_eq!(
        (vtype, u32::from_le_bytes(bytes)),
        (REG_DWORD, 4),
        "the offline SAN policy lands"
    );
}
