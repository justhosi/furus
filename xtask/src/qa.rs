//! `cargo xtask qa`: two-tier end-to-end release gate (S27).

use std::io::Read;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use crate::util::tool_present;

// ---------------------------------------------------------------------------
// qa — two-tier end-to-end release gate (S27)
// ---------------------------------------------------------------------------

/// Backstop deadline for one `cargo test` suite. The suites themselves have
/// their own internal guards (a formatter's tool check, QEMU's 10–12s capture
/// deadline, ...); this only exists so a hung process can never hang CI.
const QA_SUITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Deadline for the self-contained BIOS boot smoke test. A marker written by
/// a 162-byte real-mode loop appears in well under a second; 30s is generous
/// and strictly inside the 30–60s window the release gate promises.
const QA_QEMU_TIMEOUT: Duration = Duration::from_secs(30);

/// The marker the hand-assembled boot sector prints to COM1. The orchestrated
/// OVMF/UEFI:NTFS suite asserts its own `UEFI-NTFS-OK` debugcon marker inside
/// that suite; this constant is only for the self-contained BIOS smoke test.
const QA_BOOT_MARKER: &str = "FURUS-QA-OK";

/// Unique suffix for the smoke-test scratch directory. Fully qualified so the
/// unit-test module's own atomic imports stay untouched.
static QA_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Parsed `cargo xtask qa` options. Kept as a value so the validation is
/// directly unit-testable without spawning anything.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QaOptions {
    require_qemu: bool,
    privileged: bool,
}

pub(crate) fn parse_qa_options(args: &[String]) -> Result<QaOptions> {
    let mut options = QaOptions {
        require_qemu: false,
        privileged: false,
    };
    for arg in args {
        match arg.as_str() {
            "--require-qemu" => options.require_qemu = true,
            "--privileged" => options.privileged = true,
            other => bail!(
                "qa: unknown option `{other}` (usage: cargo xtask qa [--require-qemu] [--privileged])"
            ),
        }
    }
    Ok(options)
}

/// OVMF code/vars pairs from the installation layouts we support, in
/// priority order. Keep in sync with `crates/furus-core/tests/uefi_ntfs_boot.rs`.
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

/// First pair whose code AND vars both satisfy `exists`, so the two files
/// can never come from different installation layouts.
fn first_existing_pair<'a>(
    pairs: &'a [(&'a str, &'a str)],
    exists: impl Fn(&str) -> bool,
) -> Option<(&'a str, &'a str)> {
    pairs
        .iter()
        .copied()
        .find(|(code, vars)| exists(code) && exists(vars))
}

/// Whether a complete OVMF code + vars pair is installed on this host.
fn ovmf_present() -> bool {
    let from_code = std::env::var_os("FURUS_OVMF_CODE");
    let from_vars = std::env::var_os("FURUS_OVMF_VARS");
    if from_code.is_some() || from_vars.is_some() {
        return match (from_code, from_vars) {
            (Some(code), Some(vars)) => Path::new(&code).is_file() && Path::new(&vars).is_file(),
            _ => false,
        };
    }
    first_existing_pair(OVMF_PAIRS, |path| Path::new(path).is_file()).is_some()
}

/// Names in `tools` whose `--version` does not run successfully (the same
/// probe as `tool_present`, kept as a pure list so it can be tested).
fn missing_tools<'a>(tools: &'a [&'a str]) -> Vec<&'a str> {
    tools
        .iter()
        .copied()
        .filter(|tool| !tool_present(tool))
        .collect()
}

/// Case-insensitive ASCII substring search over raw serial bytes. QEMU's
/// stdio capture is byte-exact, but tolerating case makes the assertion robust
/// across BIOS/terminal wrappers that normalise output.
fn contains_ascii_ci(haystack: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(haystack)
        .to_ascii_uppercase()
        .contains(&needle.to_ascii_uppercase())
}

/// Build a 512-byte MBR boot sector whose entry point prints `marker` to COM1
/// (port 0x3F8) one byte at a time and then halts. No unsafe code: the 16-bit
/// real-mode machine code is assembled by pushing byte literals into a `Vec`.
///
/// Per byte we poll the line-status register (0x3FD, transmit-holding-register
/// empty = bit 5) before writing the data port, so no character is dropped by
/// a busy 16550 FIFO. The 0x55AA signature at offsets 510/511 is what makes
/// SeaBIOS execute sector 0 at 0x7C00.
fn boot_sector_bytes(marker: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0xFA]); // cli
    code.extend_from_slice(&[0xFC]); // cld
    code.extend_from_slice(&[0xBA, 0xFD, 0x03]); // mov dx, 0x03fd (LSR)
    for &ch in marker {
        code.extend_from_slice(&[
            0xEC, // wait: in al, dx
            0xA8, 0x20, //       test al, 0x20
            0x74, 0xFB, //       jz wait  (-5: back to `in al, dx`)
        ]);
        code.extend_from_slice(&[0xBA, 0xF8, 0x03]); // mov dx, 0x03f8 (data)
        code.extend_from_slice(&[0xB0, ch]); // mov al, <byte>
        code.extend_from_slice(&[0xEE]); // out dx, al
        code.extend_from_slice(&[0xBA, 0xFD, 0x03]); // mov dx, 0x03fd (LSR again)
    }
    code.extend_from_slice(&[0xF4]); // hlt
    code.extend_from_slice(&[0xEB, 0xFE]); // jmp $ — park if hlt is disturbed

    assert!(
        code.len() <= 446,
        "boot code ({} bytes) must fit before the partition table",
        code.len()
    );
    let mut sector = vec![0u8; 512];
    sector[..code.len()].copy_from_slice(&code);
    sector[510] = 0x55;
    sector[511] = 0xAA;
    sector
}

/// A spawned QEMU that is killed and reaped on drop, so no machine survives a
/// failed assertion, a timeout or an early return.
struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Boot `disk` under SeaBIOS with COM1 on stdio and assert `QA_BOOT_MARKER`
/// appears before the deadline. Stdout is read on a thread so the main thread
/// can enforce the timeout; stderr is drained so QEMU never blocks on a full
/// pipe. Every path kills and reaps the child and joins both readers.
fn qemu_bios_smoke(disk: &Path, timeout: Duration) -> Result<()> {
    let drive = format!("file={},format=raw,if=ide", disk.display());
    let child = Command::new("qemu-system-x86_64")
        .args([
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-no-reboot",
            "-drive",
            drive.as_str(),
        ])
        .env_remove("APPDIR")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn qemu-system-x86_64")?;

    let mut guard = ChildGuard(Some(child));
    let child = guard.0.as_mut().expect("the guard owns the child");
    let stdout = child.stdout.take().context("qemu stdout is piped")?;
    let stderr = child.stderr.take().context("qemu stderr is piped")?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = thread::spawn(move || {
        let mut source = stdout;
        let mut buf = [0u8; 4096];
        loop {
            match source.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let drainer = thread::spawn(move || {
        let mut source = stderr;
        let _ = std::io::copy(&mut source, &mut std::io::sink());
    });

    let started = Instant::now();
    let mut captured = Vec::new();
    let mut result = Ok(());
    loop {
        while let Ok(chunk) = rx.try_recv() {
            captured.extend_from_slice(&chunk);
        }
        if contains_ascii_ci(&captured, QA_BOOT_MARKER) {
            break;
        }
        if started.elapsed() >= timeout {
            result = Err(anyhow!(
                "BIOS boot marker did not appear within {}s (captured {:?})",
                timeout.as_secs(),
                String::from_utf8_lossy(&captured)
            ));
            break;
        }
        let child = guard.0.as_mut().expect("the guard owns the child");
        match child.try_wait() {
            Ok(Some(status)) => {
                result = Err(anyhow!(
                    "QEMU exited with {status} before the marker appeared (captured {:?})",
                    String::from_utf8_lossy(&captured)
                ));
                break;
            }
            Ok(None) => {}
            Err(error) => {
                result = Err(error).context("cannot poll QEMU");
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Kill and reap before joining: QEMU stays alive after `hlt`, so the
    // readers only see EOF once the machine is actually gone.
    if let Some(child) = guard.0.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = reader.join();
    let _ = drainer.join();
    result
}

/// Poll `child` until it exits or `timeout` elapses. On timeout or a poll
/// error the child is killed and reaped; on success `try_wait` has already
/// reaped it. No spawned process survives this function.
fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("timed out after {}s", timeout.as_secs());
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("cannot poll child");
            }
        }
    }
}

/// One PASS/FAIL line for a suite, so direct and orchestrated checks report
/// in the same shape.
fn report(label: &str, result: &Result<()>) {
    match result {
        Ok(()) => println!("PASS  {label}"),
        Err(error) => eprintln!("FAIL  {label}: {error:#}"),
    }
}

/// Spawn one QA suite with inherited stdio (so each test's own SKIP lines stay
/// visible) and a hard deadline. Prints PASS/FAIL and returns the outcome.
fn run_suite(label: &str, cmd: &str, args: &[&str], cwd: &Path, timeout: Duration) -> Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        // A stale APPDIR from the caller breaks asset resolution in the suites.
        .env_remove("APPDIR")
        .spawn()
        .with_context(|| format!("{label}: failed to spawn `{cmd}`"))?;

    let result = match wait_child(&mut child, timeout) {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(anyhow!("`{cmd} {}` exited with {status}", args.join(" "))),
        Err(error) => Err(error),
    };
    report(label, &result);
    result
}

/// Accumulates failed suite labels so the gate reports every failure instead
/// of stopping at the first one.
#[derive(Default)]
struct QaSummary {
    failed: Vec<String>,
}

impl QaSummary {
    fn record(&mut self, label: &str, result: Result<()>) {
        if result.is_err() {
            self.failed.push(label.to_string());
        }
    }

    fn skip(&self, label: &str, reason: &str) {
        println!("SKIP  {label}: {reason}");
    }

    fn finish(&self) -> Result<()> {
        if self.failed.is_empty() {
            println!("qa: all suites passed");
            Ok(())
        } else {
            bail!(
                "qa: {} suite(s) failed: {}",
                self.failed.len(),
                self.failed.join(", ")
            )
        }
    }
}

pub(crate) fn cmd_qa(root: &Path, options: QaOptions) -> Result<()> {
    let mut summary = QaSummary::default();

    // ---- Tier 1: unprivileged, file / sparse-file targets only -----------
    println!("==> tier 1: unprivileged structural suites");
    let suites: &[(&str, &[&str])] = &[
        (
            "tier1/mbr-gpt-partitions",
            &["test", "-p", "furus-linux", "--test", "partition_table"],
        ),
        (
            "tier1/fat32",
            &["test", "-p", "furus-core", "--test", "fat32_format"],
        ),
        (
            "tier1/exfat",
            &["test", "-p", "furus-core", "--test", "exfat_format"],
        ),
        (
            "tier1/ntfs",
            &["test", "-p", "furus-core", "--test", "ntfs_format"],
        ),
        (
            "tier1/ext4",
            &["test", "-p", "furus-core", "--test", "ext_format"],
        ),
        (
            "tier1/udf",
            &["test", "-p", "furus-core", "--test", "udf_format"],
        ),
        (
            "tier1/uefi-ntfs-structure",
            &["test", "-p", "furus-core", "--lib", "uefi_ntfs::"],
        ),
        // BCD elements 11000001/12000004/12000005/21000001/23000003/
        // 16000009, stripped class-0x4 elements and the 0xc0000001 guard all
        // live here; SYSTEM hive SanPolicy=4 lives in the `to_go` tests.
        (
            "tier1/windows-bcd",
            &["test", "-p", "furus-core", "--lib", "windows::bcd::"],
        ),
        (
            "tier1/windows-system-hive",
            &["test", "-p", "furus-core", "--lib", "windows::to_go::"],
        ),
        (
            "tier1/windows-boot-files",
            &["test", "-p", "furus-core", "--lib", "windows::boot_files::"],
        ),
        (
            "tier1/windows-bootloader",
            &[
                "test",
                "-p",
                "furus-core",
                "--lib",
                "pipeline::bootloader::tests::windows::",
            ],
        ),
    ];
    for (label, args) in suites {
        let result = run_suite(label, "cargo", args, root, QA_SUITE_TIMEOUT);
        summary.record(label, result);
    }

    // The end-to-end pipeline tests are all loop-device (or slow throughput)
    // cases and are `#[ignore]`d by default: opt in only with --privileged.
    let pipeline_label = "tier1/pipeline-loop";
    if options.privileged {
        let result = run_suite(
            pipeline_label,
            "cargo",
            &[
                "test",
                "-p",
                "furus-core",
                "--test",
                "pipeline_end_to_end",
                "--",
                "--ignored",
                "loop", // exclude the 4 GiB `pipeline_matches_dd_throughput` benchmark
            ],
            root,
            QA_SUITE_TIMEOUT,
        );
        summary.record(pipeline_label, result);
        for (label, suite) in [
            ("tier1/loop-device", "loop_device"),
            ("tier1/mount-seam", "mount_seam"),
        ] {
            let result = run_suite(
                label,
                "cargo",
                &[
                    "test",
                    "-p",
                    "furus-linux",
                    "--test",
                    suite,
                    "--",
                    "--ignored",
                ],
                root,
                QA_SUITE_TIMEOUT,
            );
            summary.record(label, result);
        }
    } else {
        summary.skip(
            pipeline_label,
            "loop-device / throughput tests need --privileged",
        );
    }

    // ---- Tier 2: headless QEMU boot, strict deadline + kill/reap ----------
    println!("==> tier 2: headless QEMU boot");
    if !tool_present("qemu-system-x86_64") {
        let reason = "qemu-system-x86_64 is not installed";
        if options.require_qemu {
            bail!("qa: --require-qemu set but {reason}");
        }
        summary.skip("tier2/bios-smoke", reason);
        summary.skip("tier2/bios-bootloaders", reason);
        summary.skip("tier2/uefi-ntfs-ovmf", reason);
        return summary.finish();
    }

    // BIOS: a self-contained marker boot that we drive directly, with our own
    // process guard. A sparse 512-byte MBR is a file target — no loop device
    // and no root, so this is safe on a plain GitHub Actions runner.
    let smoke_label = "tier2/bios-smoke";
    let scratch = std::env::temp_dir().join(format!(
        "furus-qa-bios-{}-{}",
        std::process::id(),
        QA_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let smoke = (|| -> Result<()> {
        std::fs::create_dir_all(&scratch).context("cannot create QA smoke scratch dir")?;
        let disk = scratch.join("boot.img");
        std::fs::write(&disk, boot_sector_bytes(QA_BOOT_MARKER.as_bytes()))
            .context("cannot write QA boot sector")?;
        qemu_bios_smoke(&disk, QA_QEMU_TIMEOUT)
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    report(smoke_label, &smoke);
    summary.record(smoke_label, smoke);

    // Real bootloader BIOS boots (Syslinux 4.07, FreeDOS, GRUB2). Each test in
    // the suite has its own 10–12s QEMU capture guard; the outer 120s deadline
    // is only a backstop for a hung cargo process.
    let bios_label = "tier2/bios-bootloaders";
    let result = run_suite(
        bios_label,
        "cargo",
        &[
            "test",
            "-p",
            "furus-core",
            "--lib",
            "pipeline::bootloader::end_to_end::qemu_boot::",
        ],
        root,
        QA_SUITE_TIMEOUT,
    );
    summary.record(bios_label, result);

    // UEFI: orchestrate the existing OVMF/UEFI:NTFS boot suite rather than
    // hand-crafting an EFI binary; it asserts its own debugcon marker.
    let uefi_label = "tier2/uefi-ntfs-ovmf";
    let mut missing = missing_tools(&[
        "qemu-system-x86_64",
        "grub-mkimage",
        "mkntfs",
        "ntfscp",
        "unshare",
        "ntfs-3g",
    ]);
    if !ovmf_present() {
        missing.push("OVMF firmware");
    }
    if !missing.is_empty() {
        let reason = format!("missing {}", missing.join(", "));
        if options.require_qemu {
            bail!("qa: --require-qemu set but {reason}");
        }
        summary.skip(uefi_label, &reason);
    } else {
        let result = run_suite(
            uefi_label,
            "cargo",
            &["test", "-p", "furus-core", "--test", "uefi_ntfs_boot"],
            root,
            QA_SUITE_TIMEOUT,
        );
        summary.record(uefi_label, result);
    }

    summary.finish()
}

#[cfg(test)]
mod tests;
