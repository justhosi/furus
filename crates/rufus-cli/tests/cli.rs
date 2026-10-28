//! `rufus` CLI integration tests (S03).
//!
//! Each test drives the real binary via `std::process::Command` +
//! `CARGO_BIN_EXE_rufus` (no extra dev-dependency crates): happy paths,
//! failure paths, the `--json` error-object shapes and the S03 plan
//! golden (see `tests/golden/README.md` for how `plan-v1.json` is
//! regenerated after a deliberate `PLAN_VERSION` bump).
//!
//! `sha256sum`/`md5sum` come from coreutils and are used as the cross-check
//! for `checksum` on Linux (PLAN §1 A3 targets Linux distros only).

use std::path::PathBuf;
use std::process::Command;

use rufus_proto::Plan;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Run {
    /// Process exit code (`None` means killed by a signal — a failure).
    code: i32,
    stdout: String,
    stderr: String,
}

/// Spawn the binary with the given arguments.
fn run_args(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_rufus"))
        .args(args)
        .output()
        .expect("spawn rufus binary");
    Run {
        code: out.status.code().expect("killed by a signal"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn run(args: &[&str]) -> Run {
    run_args(args)
}

/// Run with `XDG_STATE_HOME` pointed into `dir` (log tests) and everything
/// else inherited.
fn run_with_state(dir: &std::path::Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_rufus"))
        .args(args)
        .env("XDG_STATE_HOME", dir)
        .output()
        .expect("spawn rufus binary");
    Run {
        code: out.status.code().expect("killed by a signal"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Build a `plan` invocation (as a `&str` vector ready for [`run`]).
///
/// `dry_run == false` is the safety-checking mode of PLAN §6 preview;
/// `json == false` keeps the human rendering and stderr error lines.
fn plan_args(image: &std::path::Path, device: &str, dry_run: bool, json: bool) -> Vec<String> {
    let mut args = vec![
        "plan".to_string(),
        "--target".to_string(),
        "bios".to_string(),
        "--filesystem".to_string(),
        "fat32".to_string(),
        "--image".to_string(),
        image.display().to_string(),
        "--device".to_string(),
        device.to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }
    if json {
        args.push("--json".to_string());
    }
    args
}

/// `plan --dry-run --json` over `image`/`device` (golden-mode runs).
fn plan_run(image: &std::path::Path, device: &str, dry_run: bool) -> Run {
    run_plan(image, device, dry_run, true)
}

fn run_plan(image: &std::path::Path, device: &str, dry_run: bool, json: bool) -> Run {
    let args = plan_args(image, device, dry_run, json);
    run_args(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// The deterministic plan fixture: 32,780 zero bytes with `CD001` at
/// 0x8001 (16-byte shift into the normal sector-16 ISO9660 volume
/// descriptor). Size must be ≥ 0x8006 or the magic physically does not
/// fit; must match `tests/golden/README.md` exactly.
fn fixture_bytes() -> Vec<u8> {
    let mut buf = vec![0u8; 32_780];
    buf[0x8001..0x8006].copy_from_slice(b"CD001");
    buf
}

/// SHA-256 of [`fixture_bytes`], pinned so image detection surprises show
/// up as test failures instead of quiet golden drift.
const FIXTURE_SHA256: &str = "a92aff4686534129ee3a8edcfe10e9288938c15a632a0f331f61e8b4790dc06a";

/// Write the fixture into a fresh scratch dir; returns its path.
fn fixture(path: &std::path::Path) -> PathBuf {
    std::fs::write(path, fixture_bytes()).expect("write fixture");
    path.to_path_buf()
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

#[test]
fn version_human_and_json() {
    let out = run(&["version"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(
        out.stdout.trim_end(),
        format!("rufus 0.1.0 ({})", rufus_core::git_hash()),
        "stdout: {:?}",
        out.stdout
    );

    let out = run(&["version", "--json"]);
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("version json");
    assert_eq!(value["version"], "0.1.0");
    assert_eq!(value["plan_version"], 1);
    assert!(!value["git_hash"].as_str().expect("hash").is_empty());
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

#[test]
fn help_lists_commands_and_documented_flags() {
    let out = run(&["--help"]);
    assert_eq!(out.code, 0);
    for command in [
        "version", "checksum", "analyze", "list", "plan", "write", "log",
    ] {
        assert!(out.stdout.contains(command), "missing command {command}");
    }
    for flag in [
        "--json",
        "-v, --verbose",
        "-q, --quiet",
        "--locale",
        "--yes",
        "--dry-run",
        "--extra-devs",
        "--gui",
        "--iso",
        "--wait",
        "--version",
    ] {
        assert!(out.stdout.contains(flag), "missing global flag {flag}");
    }

    let out = run(&["plan", "--help"]);
    assert_eq!(out.code, 0);
    for flag in [
        "--image",
        "--device",
        "--scheme",
        "--target",
        "--filesystem",
        "--label",
        "--cluster",
        "--quick",
        "--badblocks",
        "--verify",
        "--persistence",
        "--show-all",
    ] {
        assert!(out.stdout.contains(flag), "missing plan flag {flag}");
    }
    // The plan help must document that steps are high-level provisional
    // descriptions, with the offset work owned by the S17 executor.
    assert!(
        out.stdout.contains("S17"),
        "plan --help must mention the executor slice"
    );

    let out = run(&["checksum", "--help"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("--algo"),
        "checksum --help lacks --algo"
    );

    let out = run(&["write", "--help"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("--plan"), "write --help lacks --plan");

    let out = run(&["log", "--help"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("--lines"), "log --help lacks --lines");
}

// ---------------------------------------------------------------------------
// clap error mapping (exit 1, never clap's 2)
// ---------------------------------------------------------------------------

#[test]
fn unknown_flags_map_to_exit_1() {
    let out = run(&["--frobnicate", "version"]);
    assert_eq!(out.code, 1, "clap parse errors must exit 1, got {:?}", out);
    assert!(out.stderr.contains("frobnicate"), "{}", out.stderr);

    // Same mapping at subcommand level.
    let out = run(&["version", "--nope"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("nope"), "{}", out.stderr);

    // No subcommand at all: also a usage failure (exit 1, help on stderr).
    let out = run(&[]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("Usage"), "{}", out.stderr);
}

// ---------------------------------------------------------------------------
// checksum
// ---------------------------------------------------------------------------

#[test]
fn checksum_matches_coreutils_and_reports_json() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let data = b"rufus golden hash material\n\x00\x01\x02"; // NUL-safe ascii+binary
    let path = dir.path().join("material.bin");
    std::fs::write(&path, data).expect("write material");

    let sha = coreutils_hash("sha256sum", &path);
    let out = run(&["checksum", path.to_str().expect("utf-8 temp path")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout.trim_end(),
        format!("{sha}  {}", path.display()),
        "sha256sum-compatible line"
    );

    // Default == explicit sha256; also matches the tool binary.
    let out = run(&["checksum", "--algo", "sha256", path.to_str().expect("path")]);
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.trim_end(), format!("{sha}  {}", path.display()));

    // md5 variant reports its algorithm and matches `md5sum`.
    let md5 = coreutils_hash("md5sum", &path);
    let out = run(&[
        "checksum",
        "--algo",
        "md5",
        path.to_str().expect("path"),
        "--json",
    ]);
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("checksum json");
    assert_eq!(value["algo"], "md5");
    assert_eq!(value["hash"], md5);
    assert_eq!(value["path"], path.display().to_string());
    assert_eq!(value["bytes"], data.len() as u64);

    // Missing file: exit 4 naming the path, JSON error object on stdout.
    let missing = dir.path().join("gone.bin");
    let out = run(&["checksum", missing.to_str().expect("path"), "--json"]);
    assert_eq!(out.code, 4, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
    assert_eq!(value["error"], "io");
    assert!(
        value["message"].as_str().expect("msg").contains("gone.bin"),
        "{}",
        value["message"]
    );
}

/// First token of `<tool> <path>` (coreutils hashes) for cross-checks.
fn coreutils_hash(tool: &str, path: &std::path::Path) -> String {
    let out = Command::new(tool)
        .arg(path)
        .output()
        .expect("coreutils must be on PATH (sha256sum/md5sum)");
    assert!(out.status.success(), "{tool} failed: {:?}", out);
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("digest token")
        .to_string()
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------

#[test]
fn analyze_detects_iso_magic_at_sector_16() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));

    let out = run(&["analyze", "--json", iso.to_str().expect("path")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    assert_eq!(value["kind"], "iso");
    assert_eq!(value["size_bytes"], 32_780u64);
    assert_eq!(value["sha256"], FIXTURE_SHA256);
    assert_eq!(value["path"], iso.display().to_string());

    let out = run(&["analyze", iso.to_str().expect("path")]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("kind:   iso"), "{}", out.stdout);
    assert!(out.stdout.contains(FIXTURE_SHA256), "{}", out.stdout);
}

#[test]
fn analyze_short_and_empty_files_never_panic() {
    let dir = tempfile::tempdir().expect("scratch dir");
    for (name, bytes, want) in [
        ("empty.bin", Vec::new(), "unknown"),
        ("gzip.bin", vec![0x1F, 0x8B], "gzip"),
        ("pe.bin", b"MZ".to_vec(), "pe"),
        ("bzip2.bin", b"BZh".to_vec(), "bzip2"),
        ("odd.bin", vec![0xFF], "unknown"),
        ("raw.bin", vec![0xAA; 4096], "raw"),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).expect("write tiny file");
        let out = run(&["analyze", "--json", path.to_str().expect("path")]);
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
        assert_eq!(value["kind"], want, "{name} misdetected");
        assert_eq!(value["size_bytes"], bytes.len() as u64, "{name}");
    }
}

// ---------------------------------------------------------------------------
// plan (golden + device safety)
// ---------------------------------------------------------------------------

#[test]
fn plan_dry_run_matches_golden_v1() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));
    let out = plan_run(&iso, "/dev/null", true);
    assert_eq!(out.code, 0, "{}", out.stderr);

    let raw: serde_json::Value = serde_json::from_str(&out.stdout).expect("plan json");

    // The CLI's own sealing is real: confirm must equal Plan::confirm()
    // over the *unnormalised* plan (the actual temp paths).
    let original: Plan = serde_json::from_value(raw.clone()).expect("plan struct");
    assert_eq!(
        original.confirm().expect("reopen serialises"),
        raw["confirm"],
        "CLI-emitted confirm does not recompute"
    );

    // Normalise exactly as tests/golden/README.md documents.
    let mut value = raw.clone();
    value["image"]["path"] = "fixture.iso".into();
    value["created_by"] = "<created_by>".into();
    let plan: Plan = serde_json::from_value(value.clone()).expect("struct after normalise");
    value["confirm"] = plan.confirm().expect("normalised serialises").into();

    let golden: serde_json::Value =
        serde_json::from_str(include_str!("golden/plan-v1.json")).expect("golden");
    assert_eq!(value, golden, "plan output drifted from the golden");
}

#[test]
fn plan_device_safety_exits_without_dry_run() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));

    // A character device is not a block device -> safety refusal (exit 3).
    // Human mode prints the refusal to stderr; --json keeps it as an
    // {"error","message"} object on stdout.
    let out = run_plan(&iso, "/dev/null", false, false);
    assert_eq!(out.code, 3, "{:?}", out);
    assert!(
        out.stderr.contains("is not a block device"),
        "{}",
        out.stderr
    );

    let out = run_plan(&iso, "/dev/null", false, true);
    assert_eq!(out.code, 3, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "safety");
    assert!(
        value["message"]
            .as_str()
            .expect("msg")
            .contains("/dev/null"),
        "{}",
        value["message"]
    );

    // A really missing device path -> device error (exit 2).
    let missing = dir.path().join("no-such-device");
    let out = run_plan(&iso, missing.to_str().expect("path"), false, false);
    assert_eq!(out.code, 2, "{:?}", out);
    assert!(out.stderr.contains("device"), "{}", out.stderr);

    // --dry-run relaxes both: the missing device is planned with
    // block_device=false, exit 0.
    let out = run_plan(&iso, missing.to_str().expect("path"), true, true);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["device"]["block_device"], false);
    assert_eq!(value["device"]["path"], missing.display().to_string());
}

// ---------------------------------------------------------------------------
// write (validation + not-implemented)
// ---------------------------------------------------------------------------

#[test]
fn write_validates_then_refuses_with_exit_7() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));
    let plan_out = plan_run(&iso, "/dev/null", true);
    assert_eq!(plan_out.code, 0, "{}", plan_out.stderr);
    let plan_file = dir.path().join("plan.json");
    std::fs::write(&plan_file, &plan_out.stdout).expect("save plan");

    // A verifying plan reaches the honest not-implemented stub.
    let out = run(&["write", "--plan", plan_file.to_str().expect("path")]);
    assert_eq!(out.code, 7, "{:?}", out);
    assert!(out.stderr.contains("not implemented"), "{}", out.stderr);

    // Exit 7 keeps its {"error","slice"} object in --json mode.
    let out = run(&[
        "write",
        "--json",
        "--plan",
        plan_file.to_str().expect("path"),
    ]);
    assert_eq!(out.code, 7);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "not_implemented");
    assert_eq!(value["slice"], "S06/S17");
}

#[test]
fn write_refuses_tampered_plans() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));
    let plan_out = plan_run(&iso, "/dev/null", true);
    assert_eq!(plan_out.code, 0, "{}", plan_out.stderr);

    // 1) field tamper -> confirm mismatch, exit 1.
    let tampered = plan_out.stdout.replace("\"/dev/null\"", "\"/dev/sdb\"");
    assert_ne!(tampered, plan_out.stdout, "device path present in plan");
    let file = dir.path().join("tampered.json");
    std::fs::write(&file, tampered).expect("save tampered plan");
    let out = run(&["write", "--plan", file.to_str().expect("path")]);
    assert_eq!(out.code, 1, "{:?}", out);
    assert!(
        out.stderr.contains("confirm hash mismatch"),
        "{}",
        out.stderr
    );
    let out = run(&["write", "--json", "--plan", file.to_str().expect("path")]);
    assert_eq!(out.code, 1);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "confirm_mismatch");

    // 2) version bump on the wire -> unsupported, exit 1 (before confirm).
    let bumped = plan_out.stdout.replace("\"version\": 1", "\"version\": 2");
    assert_ne!(bumped, plan_out.stdout, "version field present in plan");
    let file = dir.path().join("bumped.json");
    std::fs::write(&file, bumped).expect("save bumped plan");
    let out = run(&["write", "--plan", file.to_str().expect("path")]);
    assert_eq!(out.code, 1, "{:?}", out);
    assert!(out.stderr.contains("version 2"), "{}", out.stderr);

    // 3) unparsable JSON -> invalid_plan, exit 1.
    let junk = dir.path().join("junk.json");
    std::fs::write(&junk, "{not json").expect("save junk");
    let out = run(&["write", "--json", "--plan", junk.to_str().expect("path")]);
    assert_eq!(out.code, 1, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "invalid_plan");

    // 4) missing plan file -> io, exit 4.
    let missing = dir.path().join("absent.json");
    let out = run(&["write", "--json", "--plan", missing.to_str().expect("path")]);
    assert_eq!(out.code, 4, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "io");
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[test]
fn list_is_an_honest_stub() {
    let out = run(&["list"]);
    assert_eq!(out.code, 7, "list must exit 7 until S04: {:?}", out);
    assert!(out.stderr.contains("S04"), "{}", out.stderr);

    let out = run(&["list", "--json"]);
    assert_eq!(out.code, 7);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["error"], "not_implemented");
    assert_eq!(value["slice"], "S04");
}

// ---------------------------------------------------------------------------
// log
// ---------------------------------------------------------------------------

#[test]
fn log_reports_missing_state_file_calmly() {
    let dir = tempfile::tempdir().expect("scratch dir");

    let out = run_with_state(dir.path(), &["log"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("rufus.log"), "{}", out.stdout);
    assert!(out.stdout.contains("no log file"), "{}", out.stdout);

    let out = run_with_state(dir.path(), &["log", "--json"]);
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["exists"], false);
    assert_eq!(value["lines"], serde_json::json!([]));
    assert!(value["path"].as_str().expect("path").contains("rufus.log"));
}

#[test]
fn log_tails_last_lines_when_a_file_exists() {
    let dir = tempfile::tempdir().expect("scratch dir");
    // The CLI resolves `$XDG_STATE_HOME/rufus-linux/rufus.log`.
    let state = dir.path().join("state").join("rufus-linux");
    std::fs::create_dir_all(&state).expect("state dir");
    let lines: Vec<String> = (1..=60).map(|i| format!("{i:03} line")).collect();
    std::fs::write(state.join("rufus.log"), lines.join("\n")).expect("seed log");

    let out = run_with_state(&dir.path().join("state"), &["log", "--lines", "5"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("showing 5 of 60 lines"),
        "{}",
        out.stdout
    );
    for tail in ["056 line", "057 line", "058 line", "059 line", "060 line"] {
        assert!(out.stdout.contains(tail), "{tail} missing");
    }
    assert!(!out.stdout.contains("001 line"), "head must not leak");

    let out = run_with_state(
        &dir.path().join("state"),
        &["log", "--lines", "5", "--json"],
    );
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("json");
    assert_eq!(value["exists"], true);
    let shown = value["lines"].as_array().expect("lines");
    assert_eq!(shown.len(), 5);
    assert_eq!(shown[4], "060 line");
}
