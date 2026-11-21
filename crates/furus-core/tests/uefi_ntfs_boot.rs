//! The UEFI:NTFS shim boots a real NTFS data partition under OVMF.
//!
//! The end-to-end proof the shim's unit tests cannot give. The planner
//! lays out an MBR disk (a 1 MiB ESP, then the NTFS data partition); the
//! pinned shim image goes at the ESP offset through
//! [`uefi_ntfs::install`]; a real NTFS volume holding
//! `/EFI/Boot/BOOTX64.EFI` is spliced at the data offset; and OVMF boots
//! the disk in QEMU with the serial console captured. OVMF has no NTFS
//! driver of its own, so the shim is the only route to the payload. The
//! negative control boots the same disk with no shim and must not print
//! the marker. The marker is printed by the payload's embedded GRUB
//! config, not by the firmware.
//!
//! Host tools: `qemu-system-x86_64`, the OVMF code and vars images,
//! `grub-mkimage`, `mkntfs`, `ntfscp`, `unshare` and `ntfs-3g`. Each one
//! is probed, and a missing one skips with a reason. `ntfscp` cannot
//! create directories and `ntfsmkdir` is not installed, so the
//! `/EFI/Boot` directory is made by `ntfs-3g` mounted through FUSE inside
//! a user namespace (no root). A host that refuses that mount skips with
//! the reason from the probe.

use std::fs::File;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use furus_core::boot::Resource;
use furus_core::boot::load_from;
use furus_core::boot::uefi_ntfs;
use furus_core::error::CoreError;
use furus_core::error::Result as CoreResult;
use furus_core::fs::Volume;
use furus_core::part::TableKind;
use furus_core::part::plan;
use furus_core::part::plan::DataType;
use furus_core::part::plan::LayoutKind;
use furus_core::part::plan::Rendered;

const MIB: u64 = 1024 * 1024;
const DISK_BYTES: u64 = 128 * MIB;
const SECTOR_BYTES: u32 = 512;
/// Printed by the payload's embedded config (see [`EARLY_CFG`]).
const MARKER: &str = "UEFI-NTFS-OK";
/// OVMF code/vars pairs from the installation layouts we support, in
/// priority order. A code file must never be paired with a vars file from
/// a different layout. Keep in sync with `xtask/src/main.rs`.
const OVMF_PAIRS: &[(&str, &str)] = &[
    (
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
        "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    ),
    (
        "/usr/share/edk2/x64/OVMF_CODE.fd",
        "/usr/share/edk2/x64/OVMF_VARS.fd",
    ),
    (
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    ),
    (
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
    ),
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    ),
];
const BOOT_DEADLINE: Duration = Duration::from_secs(60);
const NEGATIVE_DEADLINE: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(200);
/// The path the UEFI:NTFS shim chainloads from the NTFS partition.
const PAYLOAD_PATH: &str = "/EFI/Boot/BOOTX64.EFI";
const PAYLOAD_DIR: &str = "EFI/Boot";
/// Serial on COM1 (the `-serial` QEMU sink), then the marker line.
const EARLY_CFG: &str = "serial --unit=0 --speed=115200\n\
terminal_input serial\n\
terminal_output serial\n\
echo UEFI-NTFS-OK\n";

/// A read-write [`Volume`] over a sparse image file. `furus_core`'s
/// `FileVolume` is read-only, so the test carries its own writable
/// store, the same shape the format suites use.
struct ImageFile {
    file: File,
    total: u64,
}

impl ImageFile {
    /// Create `path` as a sparse image of `total` bytes.
    fn create(path: &Path, total: u64) -> Self {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("the disk image opens");
        file.set_len(total).expect("the disk image extends");
        Self { file, total }
    }
}

/// Refuse a window that runs past the image, before any I/O.
fn check_window(total: u64, offset: u64, len: usize, what: &str) -> CoreResult<()> {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    match offset.checked_add(len) {
        Some(end) if end <= total => Ok(()),
        _ => Err(CoreError::invalid(format!(
            "{what} of {len} bytes at offset {offset} runs past the {total} byte image: refusing"
        ))),
    }
}

impl Volume for ImageFile {
    fn total_bytes(&self) -> u64 {
        self.total
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> CoreResult<()> {
        check_window(self.total, offset, buf.len(), "read")?;
        self.file
            .read_exact_at(buf, offset)
            .map_err(|source| CoreError::io("<uefi-ntfs disk>", source))
    }

    fn write_all_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<()> {
        check_window(self.total, offset, buf.len(), "write")?;
        self.file
            .write_all_at(buf, offset)
            .map_err(|source| CoreError::io("<uefi-ntfs disk>", source))
    }

    fn flush(&mut self) -> CoreResult<()> {
        self.file
            .sync_data()
            .map_err(|source| CoreError::io("<uefi-ntfs disk>", source))
    }
}

/// Keep printable ASCII and tab/CR; every other character becomes `?`,
/// so tool output and the serial log print as plain ASCII.
fn ascii(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\t' || c == '\r' || (' '..='~').contains(&c) {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// One line of ASCII, for skip reasons and refusals.
fn one_line(text: &str) -> String {
    ascii(text).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The whole text with right-trimmed lines, for the test log.
fn report(text: &str) -> String {
    ascii(text)
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn text(path: &Path) -> &str {
    path.to_str().expect("the scratch path is UTF-8")
}

/// Run `program` under `LC_ALL=C` and return its output, or the reason
/// it failed (spawn error, or non-zero exit with the output named).
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|source| format!("{program} did not start: {source}"))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "{program} exited with {}: {}",
            output.status,
            one_line(&combined)
        ))
    }
}

/// Format `image` as NTFS with the label the shim's README expects.
fn format_ntfs(image: &Path) -> Result<(), String> {
    run("mkntfs", &["-F", "-q", "-L", "FURUSBIN", text(image)]).map(|_| ())
}

/// Create the relative directory `dirs` (e.g. `EFI/Boot`) on the NTFS
/// `image` without root. `ntfs-3g` mounts the image through FUSE inside
/// a fresh user namespace, where the process is uid 0; `mkdir -p` runs
/// on the mount; `umount` detaches it before `ntfscp` touches the image.
fn make_ntfs_dirs(image: &Path, mountpoint: &Path, dirs: &str) -> Result<(), String> {
    std::fs::create_dir_all(mountpoint)
        .map_err(|source| format!("cannot create {}: {source}", mountpoint.display()))?;
    const SCRIPT: &str = r#"ntfs-3g "$2" "$1" -o rw || exit 3; mkdir -p "$1/$3" || { umount "$1"; exit 4; }; umount "$1" || exit 5"#;
    run(
        "unshare",
        &[
            "-rm",
            "sh",
            "-c",
            SCRIPT,
            "sh",
            text(mountpoint),
            text(image),
            dirs,
        ],
    )
    .map(|_| ())
}

/// The first pair whose code AND vars both satisfy `exists`. Kept pure so
/// discovery can be tested without touching the filesystem or the environment.
fn first_existing_pair<'a>(
    pairs: &'a [(&'a str, &'a str)],
    exists: impl Fn(&str) -> bool,
) -> Option<(&'a str, &'a str)> {
    pairs
        .iter()
        .copied()
        .find(|(code, vars)| exists(code) && exists(vars))
}

/// Find a complete OVMF code/vars pair. Explicit `FURUS_OVMF_CODE` and
/// `FURUS_OVMF_VARS` override discovery, but both must be set and valid.
fn resolve_ovmf_pair() -> Result<(PathBuf, PathBuf), String> {
    let from_code = std::env::var_os("FURUS_OVMF_CODE");
    let from_vars = std::env::var_os("FURUS_OVMF_VARS");
    if from_code.is_some() || from_vars.is_some() {
        let code = from_code.ok_or_else(|| {
            "FURUS_OVMF_CODE is not set (set both FURUS_OVMF_CODE and FURUS_OVMF_VARS)".to_string()
        })?;
        let vars = from_vars.ok_or_else(|| {
            "FURUS_OVMF_VARS is not set (set both FURUS_OVMF_CODE and FURUS_OVMF_VARS)".to_string()
        })?;
        let code = PathBuf::from(code);
        let vars = PathBuf::from(vars);
        if !code.is_file() {
            return Err(format!(
                "FURUS_OVMF_CODE path {} is not a file",
                code.display()
            ));
        }
        if !vars.is_file() {
            return Err(format!(
                "FURUS_OVMF_VARS path {} is not a file",
                vars.display()
            ));
        }
        return Ok((code, vars));
    }
    match first_existing_pair(OVMF_PAIRS, |path| Path::new(path).is_file()) {
        Some((code, vars)) => Ok((PathBuf::from(code), PathBuf::from(vars))),
        None => Err(
            "no OVMF code/vars firmware pair found in standard paths (set FURUS_OVMF_CODE and FURUS_OVMF_VARS to override)"
                .to_string(),
        ),
    }
}

#[test]
fn ovmf_pair_discovery_never_mixes_layouts() {
    let pairs: &[(&str, &str)] = &[
        ("/first/CODE.fd", "/first/VARS.fd"),
        ("/second/CODE.fd", "/second/VARS.fd"),
    ];
    let exists = |path: &str| path == "/first/CODE.fd" || path == "/second/VARS.fd";
    assert_eq!(
        first_existing_pair(pairs, exists),
        None,
        "one member from each layout is not a pair"
    );
    let exists = |path: &str| path.starts_with("/second/");
    assert_eq!(
        first_existing_pair(pairs, exists),
        Some(("/second/CODE.fd", "/second/VARS.fd")),
        "a whole later pair wins"
    );
    assert_eq!(first_existing_pair(&[], |_| true), None);
}

/// Why this host cannot run the boot test, or `None` when it can.
fn skip_reason(scratch: &Path, ovmf: &Result<(PathBuf, PathBuf), String>) -> Option<String> {
    for program in [
        "qemu-system-x86_64",
        "grub-mkimage",
        "mkntfs",
        "ntfscp",
        "unshare",
        "ntfs-3g",
    ] {
        if Command::new(program).arg("--version").output().is_err() {
            return Some(format!("{program} is not on PATH on this host"));
        }
    }
    if let Err(reason) = ovmf {
        return Some(reason.clone());
    }
    // Probe the one step that needs the namespace mount, on a throwaway
    // volume, so a host that refuses it skips here and not mid-test.
    let probe = scratch.join("probe.ntfs");
    let mountpoint = scratch.join("probe-mnt");
    drop(ImageFile::create(&probe, 16 * MIB));
    if let Err(reason) = format_ntfs(&probe) {
        return Some(format!("mkntfs cannot format a probe image ({reason})"));
    }
    if let Err(reason) = make_ntfs_dirs(&probe, &mountpoint, PAYLOAD_DIR) {
        return Some(format!(
            "cannot create an NTFS directory without root on this host ({reason})"
        ));
    }
    None
}

/// Kills and reaps the QEMU child on every exit path.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What one QEMU run left behind: the serial console and QEMU's stderr.
struct Boot {
    serial: String,
    qemu_stderr: String,
}

fn read_lossy(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

/// Boot `disk` under OVMF until [`MARKER`] appears on the serial log,
/// the deadline passes, or QEMU exits; then ask the monitor to quit and
/// kill and reap the machine.
fn boot(disk: &Path, work: &Path, deadline: Duration, ovmf: &(PathBuf, PathBuf)) -> Boot {
    std::fs::create_dir_all(work).expect("the boot work directory");
    let vars = work.join("OVMF_VARS.fd");
    std::fs::copy(&ovmf.1, &vars).expect("the OVMF vars copy");
    let serial = work.join("serial.log");
    let monitor = work.join("mon.sock");
    let qemu_stderr = work.join("qemu.stderr");
    let stderr_file = File::create(&qemu_stderr).expect("the qemu stderr file");
    let child = Command::new("qemu-system-x86_64")
        .arg("-machine")
        .arg("q35")
        .arg("-m")
        .arg("256")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-monitor")
        .arg(format!("unix:{},server,nowait", monitor.display()))
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,unit=0,file={}",
            ovmf.0.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=1,file={}",
            vars.display()
        ))
        .arg("-drive")
        .arg(format!("file={},format=raw,if=ide", disk.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("qemu-system-x86_64 starts");
    let mut guard = Guard(child);
    let started = Instant::now();
    loop {
        if read_lossy(&serial).contains(MARKER) {
            break;
        }
        if started.elapsed() >= deadline {
            break;
        }
        if matches!(guard.0.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(POLL);
    }
    if let Ok(mut stream) = UnixStream::connect(&monitor) {
        let _ = stream.write_all(b"quit\n");
    }
    drop(guard);
    Boot {
        serial: read_lossy(&serial),
        qemu_stderr: read_lossy(&qemu_stderr),
    }
}

/// Write the planner's rendered table into the disk. The MBR render is
/// one sector at LBA 0; nothing else is written.
fn write_table(disk: &mut ImageFile, rendered: &Rendered) {
    for write in &rendered.writes {
        disk.write_all_at(write.lba * u64::from(SECTOR_BYTES), &write.bytes)
            .expect("the partition table writes");
    }
}

fn read_back(disk: &ImageFile, offset: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    disk.read_exact_at(offset, &mut out)
        .expect("the disk read fits");
    out
}

/// Copy `source` whole into `disk` at `offset`, returning the bytes
/// copied.
fn splice(disk: &mut ImageFile, source: &Path, offset: u64) -> u64 {
    let mut file = File::open(source).expect("the NTFS image opens");
    let mut chunk = vec![0u8; MIB as usize];
    let mut at = offset;
    loop {
        let read = file.read(&mut chunk).expect("the NTFS image reads");
        if read == 0 {
            break;
        }
        disk.write_all_at(at, &chunk[..read])
            .expect("the NTFS image splices into the disk");
        at += read as u64;
    }
    disk.flush().expect("the disk flushes");
    at - offset
}

/// Build `BOOTX64.EFI`: a GRUB EFI image whose embedded config puts the
/// serial console on COM1 and prints the marker. Its prefix points at a
/// directory that does not exist; the marker needs no module from disk.
fn build_payload(dir: &Path) -> PathBuf {
    let cfg = dir.join("early.cfg");
    std::fs::write(&cfg, EARLY_CFG).expect("the early config writes");
    let out = dir.join("BOOTX64.EFI");
    run(
        "grub-mkimage",
        &[
            "-O",
            "x86_64-efi",
            "-o",
            text(&out),
            "-p",
            "/EFI/grub",
            "-c",
            text(&cfg),
            "serial",
            "terminal",
            "echo",
            "normal",
        ],
    )
    .expect("grub-mkimage links the payload");
    out
}

#[test]
fn uefi_ntfs_shim_boots_an_ntfs_payload_under_ovmf() {
    let scratch = tempfile::tempdir().expect("a scratch directory for the boot test");
    let dir = scratch.path();
    let ovmf = resolve_ovmf_pair();
    let pair = match &ovmf {
        Ok(pair) => pair.clone(),
        Err(reason) => {
            eprintln!("skip: {reason}");
            return;
        }
    };
    if let Some(reason) = skip_reason(dir, &ovmf) {
        eprintln!("skip: {reason}");
        return;
    }

    // Layout through the product: the planner decides every offset.
    let request = plan::request(
        LayoutKind::UefiNtfs,
        TableKind::Mbr,
        SECTOR_BYTES,
        DISK_BYTES,
        DataType::Ntfs,
    )
    .expect("the uefi-ntfs request builds");
    let table = plan::plan(&request).expect("the uefi-ntfs layout plans");
    let rendered =
        plan::render(&table, SECTOR_BYTES, request.last_lba).expect("the uefi-ntfs table renders");
    assert_eq!(
        rendered
            .writes
            .iter()
            .map(|write| write.lba)
            .collect::<Vec<_>>(),
        vec![0],
        "the MBR render writes LBA 0 only"
    );
    let (esp_offset, esp_len) = plan::esp_window(
        LayoutKind::UefiNtfs,
        TableKind::Mbr,
        SECTOR_BYTES,
        DISK_BYTES,
    )
    .expect("the ESP window resolves");
    let (data_offset, data_len) = plan::data_window(
        LayoutKind::UefiNtfs,
        TableKind::Mbr,
        SECTOR_BYTES,
        DISK_BYTES,
    )
    .expect("the data window resolves");
    assert_eq!(
        esp_len,
        uefi_ntfs::IMAGE_BYTES,
        "the ESP window is the pinned shim size"
    );

    // The NTFS data partition: a real volume with the payload at the
    // path the shim chainloads.
    let payload = build_payload(dir);
    let data_image = dir.join("data.ntfs");
    drop(ImageFile::create(&data_image, data_len));
    format_ntfs(&data_image).expect("mkntfs formats the data window");
    make_ntfs_dirs(&data_image, &dir.join("data-mnt"), PAYLOAD_DIR)
        .expect("the EFI/Boot directory is created on the NTFS volume");
    run(
        "ntfscp",
        &["-f", text(&data_image), text(&payload), PAYLOAD_PATH],
    )
    .expect("ntfscp writes the payload into the NTFS volume");
    assert_eq!(
        std::fs::metadata(&data_image).map(|meta| meta.len()).ok(),
        Some(data_len),
        "the NTFS image is exactly the data window"
    );

    // Positive disk: table, then the shim at the ESP, then the NTFS
    // volume at the data offset.
    let shim_disk = dir.join("shim.img");
    let mut disk = ImageFile::create(&shim_disk, DISK_BYTES);
    write_table(&mut disk, &rendered);
    let assets = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../assets/resources"
    ));
    let shim = load_from(assets, Resource::UefiNtfsImage)
        .expect("the pinned UEFI:NTFS image loads from the assets");
    let installed = uefi_ntfs::install(&mut disk, shim.bytes(), esp_offset, esp_offset + esp_len)
        .expect("the shim installs in the ESP window");
    assert_eq!(
        installed.bytes(),
        shim.len() as u64,
        "the whole shim image lands"
    );
    assert!(
        read_back(&disk, esp_offset, shim.len()) == shim.bytes(),
        "the shim bytes at the ESP offset match the pinned asset"
    );
    assert!(
        read_back(&disk, data_offset, 512)
            .iter()
            .all(|byte| *byte == 0),
        "the data window is still zero after the shim install"
    );
    let spliced = splice(&mut disk, &data_image, data_offset);
    assert_eq!(spliced, data_len, "the NTFS volume spliced whole");

    // Negative control: the same table and NTFS volume with no shim.
    let no_shim_disk = dir.join("noshim.img");
    let mut control = ImageFile::create(&no_shim_disk, DISK_BYTES);
    write_table(&mut control, &rendered);
    let spliced = splice(&mut control, &data_image, data_offset);
    assert_eq!(spliced, data_len, "the NTFS volume spliced whole (control)");
    drop(control);
    drop(disk);

    let positive = boot(&shim_disk, &dir.join("boot-shim"), BOOT_DEADLINE, &pair);
    eprintln!(
        "uefi-ntfs boot, with shim, serial log:\n{}",
        report(&positive.serial)
    );
    eprintln!(
        "uefi-ntfs boot, with shim, qemu stderr:\n{}",
        report(&positive.qemu_stderr)
    );
    let negative = boot(
        &no_shim_disk,
        &dir.join("boot-noshim"),
        NEGATIVE_DEADLINE,
        &pair,
    );
    eprintln!(
        "uefi-ntfs boot, no shim, serial log:\n{}",
        report(&negative.serial)
    );
    eprintln!(
        "uefi-ntfs boot, no shim, qemu stderr:\n{}",
        report(&negative.qemu_stderr)
    );

    assert!(
        positive.serial.contains(MARKER),
        "the shim did not chainload the NTFS payload: {MARKER} missing from the serial log after {BOOT_DEADLINE:?}"
    );
    assert!(
        !negative.serial.contains(MARKER),
        "{MARKER} appeared with no shim installed, so it did not come through the shim"
    );
}
