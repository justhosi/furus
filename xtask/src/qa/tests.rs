use super::*;

use crate::util::TempDir;
use crate::util::repo_root;

// --- qa gate helpers ---------------------------------------------------

#[test]
fn qa_option_parsing() {
    let opt = |args: &[&str]| {
        parse_qa_options(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap()
    };
    assert_eq!(
        opt(&[]),
        QaOptions {
            require_qemu: false,
            privileged: false
        }
    );
    assert_eq!(
        opt(&["--require-qemu"]),
        QaOptions {
            require_qemu: true,
            privileged: false
        }
    );
    assert_eq!(
        opt(&["--privileged"]),
        QaOptions {
            require_qemu: false,
            privileged: true
        }
    );
    assert_eq!(
        opt(&["--privileged", "--require-qemu", "--privileged"]),
        QaOptions {
            require_qemu: true,
            privileged: true
        }
    );
    assert!(parse_qa_options(&["--loop".to_string()]).is_err());
    assert!(parse_qa_options(&["qa".to_string()]).is_err());
}

#[test]
fn boot_sector_is_a_valid_mbr_with_the_marker() {
    let sector = boot_sector_bytes(QA_BOOT_MARKER.as_bytes());
    assert_eq!(sector.len(), 512);
    assert_eq!(&sector[510..], &[0x55, 0xAA]);
    // Each character is emitted via `mov al, <byte>` (B0 xx); the
    // port-setup opcodes interleave the characters, so check the
    // immediates rather than one contiguous string.
    for &ch in QA_BOOT_MARKER.as_bytes() {
        assert!(
            sector.windows(2).any(|w| w == [0xB0, ch]),
            "marker byte {ch:#04x} must be loaded as an immediate"
        );
    }
    // Code stops before the partition table at offset 446.
    let signature = sector[..510]
        .iter()
        .rposition(|b| *b != 0)
        .expect("the sector has code");
    assert!(signature < 446);
}

#[test]
fn boot_sector_uses_com1_port_io() {
    let sector = boot_sector_bytes(QA_BOOT_MARKER.as_bytes());
    assert!(sector.contains(&0xEC), "in al, dx (poll LSR) is missing");
    assert!(sector.contains(&0xEE), "out dx, al (write COM1) is missing");
    assert!(
        sector.windows(3).any(|w| w == [0xBA, 0xFD, 0x03]),
        "mov dx, 0x03fd (line status register) is missing"
    );
    assert!(
        sector.windows(3).any(|w| w == [0xBA, 0xF8, 0x03]),
        "mov dx, 0x03f8 (COM1 data port) is missing"
    );
}

#[test]
fn serial_marker_search_is_case_insensitive_and_bounded() {
    let bytes = b"noise\x1b[2JFURUS-QA-OK\r\nmore";
    assert!(contains_ascii_ci(bytes, "furus-qa-ok"));
    assert!(contains_ascii_ci(bytes, "FURUS-QA-OK"));
    assert!(!contains_ascii_ci(bytes, "FURUS-QA-FAIL"));
}

#[test]
fn firmware_discovery_only_accepts_real_pairs() {
    let tmp = TempDir::new("ovmf");
    let code_a = tmp.path().join("CODE_A.fd");
    let vars_a = tmp.path().join("VARS_A.fd");
    let code_b = tmp.path().join("CODE_B.fd");
    let vars_b = tmp.path().join("VARS_B.fd");
    let code_c = tmp.path().join("CODE_C.fd");
    let vars_c = tmp.path().join("VARS_C.fd");
    let pairs: &[(&str, &str)] = &[
        (code_a.to_str().unwrap(), vars_a.to_str().unwrap()),
        (code_b.to_str().unwrap(), vars_b.to_str().unwrap()),
        (code_c.to_str().unwrap(), vars_c.to_str().unwrap()),
    ];
    // Only the code of pair A and the vars of pair B exist: a mixed
    // pair must not be accepted.
    std::fs::write(&code_a, b"code").unwrap();
    std::fs::write(&vars_b, b"vars").unwrap();
    assert_eq!(first_existing_pair(pairs, |p| Path::new(p).is_file()), None);
    // With both files of a later pair present, that pair resolves.
    std::fs::write(&code_c, b"code").unwrap();
    std::fs::write(&vars_c, b"vars").unwrap();
    assert_eq!(
        first_existing_pair(pairs, |p| Path::new(p).is_file()),
        Some((code_c.to_str().unwrap(), vars_c.to_str().unwrap()))
    );
    assert_eq!(first_existing_pair(&[], |_| true), None);
}

#[test]
fn missing_tools_flags_absent_programs() {
    assert!(missing_tools(&[]).is_empty());
    let absent = ["furus-qa-no-such-tool-a", "furus-qa-no-such-tool-b"];
    assert_eq!(missing_tools(&absent), absent);
}

#[test]
fn wait_child_kills_and_reaps_on_timeout() {
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let started = Instant::now();
    assert!(wait_child(&mut child, Duration::from_millis(200)).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the gate must not hang past its deadline"
    );
    // Calling wait again returns at once: the timed-out child was reaped.
    assert!(child.wait().is_ok());
}

#[test]
fn run_suite_reports_nonzero_exit_and_timeout() {
    let root = repo_root();
    // A non-zero exit must surface as an error carrying the reason (this
    // is the path that prints the FAIL line).
    let failed = run_suite(
        "test/fail",
        "sh",
        &["-c", "exit 7"],
        &root,
        Duration::from_secs(5),
    );
    assert!(failed.is_err());
    assert!(format!("{:#}", failed.unwrap_err()).contains("exited with"));

    // A hung suite must be killed and reported, not left running.
    let started = Instant::now();
    let timed_out = run_suite(
        "test/timeout",
        "sleep",
        &["30"],
        &root,
        Duration::from_millis(200),
    );
    assert!(timed_out.is_err());
    assert!(format!("{:#}", timed_out.unwrap_err()).contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(5));
}
