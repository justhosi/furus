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

use std::os::unix::fs::FileExt;
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
        // S04/S05 test hooks.
        "--sysfs-root",
        "--mountinfo",
        // S05 swaps hook.
        "--swaps",
    ] {
        assert!(out.stdout.contains(flag), "missing global flag {flag}");
    }

    let out = run(&["analyze", "--help"]);
    assert_eq!(out.code, 0);
    for flag in ["--device", "--device-file", "--confirm-serial"] {
        assert!(out.stdout.contains(flag), "missing analyze flag {flag}");
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

    // Independent single-field assertions (S03 review): the whole-blob
    // equality below does not name the fields that matter, so a one-line
    // drift deserves a one-field failure message. The expected values
    // mirror tests/golden/plan-v1.json unmodified — change the golden by
    // hand after a deliberate PLAN_VERSION bump, then update these.
    assert_eq!(raw["version"], 1, "schema version");
    // device (graded): a non-block dry-run device keeps the facts null.
    assert_eq!(raw["device"]["path"], "/dev/null");
    assert_eq!(raw["device"]["block_device"], false);
    for fact in ["size_bytes", "serial", "model", "sysfs"] {
        assert_eq!(
            raw["device"][fact],
            serde_json::Value::Null,
            "{fact} stays null"
        );
    }
    // image (detected + hashed).
    assert_eq!(raw["image"]["kind"], "iso");
    assert_eq!(raw["image"]["size_bytes"], 32_780u64);
    assert_eq!(
        raw["image"]["sha256"], FIXTURE_SHA256,
        "fixture digest drift"
    );
    // options (the exact ten CLI switches, in the plan's spelling).
    let options: [(&str, serde_json::Value); 10] = [
        ("scheme", serde_json::json!("mbr")),
        ("target", serde_json::json!("bios")),
        ("filesystem", serde_json::json!("fat32")),
        ("label", serde_json::Value::Null),
        ("cluster_bytes", serde_json::Value::Null),
        ("quick_format", serde_json::json!(false)),
        ("bad_blocks", serde_json::json!(false)),
        ("verify", serde_json::json!(false)),
        ("persistence", serde_json::json!(false)),
        ("show_all", serde_json::json!(false)),
    ];
    for (key, want) in options {
        assert_eq!(raw["options"][key], want, "options.{key} drift");
    }
    // steps: non-empty, wipe first, finalize last.
    let steps = raw["steps"].as_array().expect("steps array");
    assert!(!steps.is_empty(), "steps must never be empty");
    assert_eq!(steps[0]["op"], "wipe", "first step");
    assert_eq!(steps[steps.len() - 1]["op"], "finalize", "last step");

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
fn plan_rejects_unusable_cluster_sizes_before_anything_else() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));

    // Not a power of two, zero, and above the gate: exit 1 with the
    // exact message, in human mode (stderr) and JSON mode (the standard
    // error object on stdout).
    for bad in ["0", "3000", "1000000"] {
        let mut args = plan_args(&iso, "/dev/null", true, false);
        args.push("--cluster".to_string());
        args.push(bad.to_string());
        let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(out.code, 1, "cluster {bad}: {:?}", out);
        assert!(
            out.stderr.contains(&format!(
                "invalid cluster size '{bad}' (expected a power of two between 512 and 1048576 bytes)"
            )),
            "{:?}",
            out.stderr
        );

        let mut args = plan_args(&iso, "/dev/null", true, true);
        args.push("--cluster".to_string());
        args.push(bad.to_string());
        let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(out.code, 1);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
        assert_eq!(value["error"], "usage");
        assert!(
            value["message"]
                .as_str()
                .expect("msg")
                .contains("expected a power of two"),
            "{}",
            value["message"]
        );
    }

    // The usable gate edges: exit 0 and the cluster lands in the plan.
    for good in ["512", "4096", "1048576"] {
        let mut args = plan_args(&iso, "/dev/null", true, true);
        args.push("--cluster".to_string());
        args.push(good.to_string());
        let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(out.code, 0, "cluster {good}: {}", out.stderr);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("plan json");
        assert_eq!(
            value["options"]["cluster_bytes"],
            good.parse::<u64>().expect("cluster number"),
            "cluster {good} must be planned exactly"
        );
    }
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
// list (S04 device discovery)
// ---------------------------------------------------------------------------

/// Minimal synthetic sysfs fixture for the `list`/`plan` CLI tests, built
/// programmatically so nothing binary is committed (see
/// `tests/fixtures/README.md`): a removable 512 MiB stick (`sdb`,
/// 1_048_576 units of 512 bytes) and a fixed 1 GiB disk (`sda`,
/// 2_097_152 units). The udev record directory exists but stays empty —
/// udev may not run in a container, which is normal, not an error.
fn sysfs_fixture(scratch: &std::path::Path) -> PathBuf {
    let root = scratch.join("sys");
    for (name, units, removable, dev) in [
        ("sda", "2097152", "0", "8:0"),
        ("sdb", "1048576", "1", "8:16"),
    ] {
        let dir = root.join("class/block").join(name);
        std::fs::create_dir_all(&dir).expect("create device dir");
        std::fs::write(dir.join("size"), units).expect("seed size");
        std::fs::write(dir.join("removable"), removable).expect("seed removable");
        std::fs::write(dir.join("dev"), dev).expect("seed dev");
    }
    std::fs::create_dir_all(root.join("run/udev/data")).expect("create record dir");
    root
}

#[test]
fn list_json_matches_the_default_filter() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let sysfs = sysfs_fixture(dir.path());

    let out = run(&[
        "list",
        "--json",
        "--sysfs-root",
        sysfs.to_str().expect("utf-8"),
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("list json");
    assert_eq!(value["show_all"], false);
    let devices = value["devices"].as_array().expect("devices array");
    assert_eq!(
        devices.len(),
        1,
        "only the removable stick is a default candidate: {value}"
    );
    assert_eq!(devices[0]["name"], "sdb");
    assert_eq!(devices[0]["dev_path"], "/dev/sdb");
    // 1_048_576 sysfs units of 512 bytes == 512 MiB (the unit-based
    // kernel contract, independent of the logical block size).
    assert_eq!(devices[0]["size_bytes"], 536_870_912u64);
    assert_eq!(devices[0]["removable"], true);
    // Transport wire tag pinned here (the `Transport` unit test leans on
    // this CLI assertion for the JSON spelling): the fixture's class
    // entries carry no device link, so they classify as Unknown.
    assert_eq!(devices[0]["transport"], "unknown");
    assert_eq!(
        devices[0]["usb"], false,
        "no device link: not classified USB"
    );
    assert_eq!(
        devices[0]["partitions"]
            .as_array()
            .expect("partitions")
            .len(),
        0
    );
}

#[test]
fn list_all_and_minus_x_reveal_fixed_disks_with_warning() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let sysfs = sysfs_fixture(dir.path());
    let root = sysfs.to_str().expect("utf-8");

    // `--all` and the Rufus-legacy `-x/--extra-devs` are synonyms now.
    for variant in [
        vec!["list", "--json", "--all", "--sysfs-root", root],
        vec!["list", "--json", "-x", "--sysfs-root", root],
    ] {
        let out = run(&variant);
        assert_eq!(out.code, 0, "{}", out.stderr);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("list json");
        assert_eq!(value["show_all"], true);
        let devices = value["devices"].as_array().expect("devices array");
        let names: Vec<&str> = devices
            .iter()
            .map(|device| device["name"].as_str().expect("name"))
            .collect();
        assert_eq!(names, vec!["sda", "sdb"], "name-sorted output");
        assert!(
            out.stderr.contains("destroy the system"),
            "show-all must warn on stderr: {}",
            out.stderr
        );
    }
}

#[test]
fn list_skips_partition_siblings_but_keeps_partitions_inside_the_disk() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let sysfs = sysfs_fixture(dir.path());
    // Live kernels list partitions as siblings too: add `sdb1` next to
    // `sdb`, linked at the real partition directory which carries the
    // `partition` attribute, with a USB udev record so it would be a
    // write candidate if enumeration did not skip it.
    let inner = sysfs.join("class/block/sdb/sdb1");
    std::fs::create_dir_all(&inner).expect("inner partition dir");
    std::fs::write(inner.join("size"), "59").expect("seed size");
    std::fs::write(inner.join("dev"), "8:17").expect("seed dev");
    std::fs::write(inner.join("partition"), "1").expect("seed partition");
    std::fs::write(
        sysfs.join("run/udev/data/b8:17"),
        "I:56732\nE:ID_FS_TYPE=vfat\nE:ID_BUS=usb\n",
    )
    .expect("seed partition record");
    std::os::unix::fs::symlink(&inner, sysfs.join("class/block/sdb1"))
        .expect("link partition sibling");
    let root = sysfs.to_str().expect("utf-8");

    for extra in [false, true] {
        let mut args = vec!["list", "--sysfs-root", root];
        if extra {
            args.push("--all");
        }
        let out = run(&args);
        assert_eq!(out.code, 0, "extra={extra}: {}", out.stderr);
        assert!(
            !out.stdout.contains("/dev/sdb1"),
            "extra={extra}: partition sibling must never list: {}",
            out.stdout
        );
        // The disk itself keeps its partition — skipping the *sibling*
        // must not lose the walk inside the disk ("1 partition(s)" on
        // the sdb line while sda stays "0 partition(s)").
        assert!(
            out.stdout.contains("1 partition(s)"),
            "extra={extra}: the in-disk partition survives the sibling skip: {}",
            out.stdout
        );
        let disks: Vec<&str> = out
            .stdout
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|first| *first == "/dev/sdb")
            .collect();
        assert_eq!(
            disks.len(),
            1,
            "extra={extra}: /dev/sdb exactly once: {}",
            out.stdout
        );
    }
}

#[test]
fn list_show_all_warns_even_without_fixed_disks() {
    let dir = tempfile::tempdir().expect("scratch dir");
    // Removable-only fixture: no fixed disks at all.
    let root = dir.path().join("sys");
    let disk = root.join("class/block/sdb");
    std::fs::create_dir_all(&disk).expect("create device dir");
    std::fs::write(disk.join("size"), "1048576").expect("seed size");
    std::fs::write(disk.join("removable"), "1").expect("seed removable");
    std::fs::write(disk.join("dev"), "8:16").expect("seed dev");
    std::fs::create_dir_all(root.join("run/udev/data")).expect("record dir");
    let root_str = root.to_str().expect("utf-8");

    // `--all` still warns exactly once, even with nothing fixed to show.
    let out = run(&["list", "--all", "--sysfs-root", root_str]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stderr.matches("destroy the system").count(),
        1,
        "show-all must warn once on stderr: {:?}",
        out.stderr
    );

    // The default path stays silent.
    let out = run(&["list", "--sysfs-root", root_str]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        !out.stderr.contains("destroy"),
        "default list must not warn: {:?}",
        out.stderr
    );
}

#[test]
fn list_missing_sysfs_root_exits_2() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let missing = dir.path().join("no/such/sysfs");
    let missing = missing.to_str().expect("utf-8");

    // Human mode: the refusal names the unreadable class directory.
    let out = run(&["list", "--sysfs-root", missing]);
    assert_eq!(out.code, 2, "{:?}", out);
    assert!(out.stderr.contains("class/block"), "{}", out.stderr);

    // --json keeps the standard {"error","message"} object on stdout.
    let out = run(&["list", "--json", "--sysfs-root", missing]);
    assert_eq!(out.code, 2);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
    assert_eq!(value["error"], "device");
    assert!(
        value["message"]
            .as_str()
            .expect("msg")
            .contains("class/block"),
        "{}",
        value["message"]
    );
}

#[test]
fn list_human_is_plain_ascii_one_line_per_device() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let sysfs = sysfs_fixture(dir.path());
    // Untrusted USB strings: a vendor descriptor embedding a newline
    // (would break the one-line format) and an ESC sequence (terminal
    // injection). Discovery must neutralise both before printing.
    std::fs::create_dir_all(sysfs.join("class/block/sdb/device")).expect("device dir");
    std::fs::write(
        sysfs.join("class/block/sdb/device/vendor"),
        "EVIL\n\u{1b}[2Jcaf\u{e9}INJECTED",
    )
    .expect("seed evil vendor");
    // And the record side: udev values overwrite the cleaned sysfs
    // facts, so their bytes must pass the same sanitiser (reviewer's
    // repro: ESC sequences inside ID_MODEL).
    std::fs::write(
        sysfs.join("run/udev/data/b8:16"),
        "I:5\nE:ID_MODEL=EVIL\u{1b}[2Judev-model\n",
    )
    .expect("seed evil record");

    let out = run(&[
        "list",
        "--all",
        "--sysfs-root",
        sysfs.to_str().expect("utf-8"),
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    // One header plus one line per device, plain ASCII throughout.
    assert!(!out.stdout.contains('{'), "{}", out.stdout);
    assert!(out.stdout.is_ascii(), "{}", out.stdout);
    assert!(
        !out.stdout.contains('\u{1b}'),
        "ESC must be neutralised: {:?}",
        out.stdout
    );
    assert_eq!(
        out.stdout.lines().count(),
        3,
        "header + 2 devices, no embedded newline: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("EVIL??[2Jcaf?INJECTED"),
        "sanitised vendor must print: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("EVIL?[2Judev-model"),
        "sanitised udev model must print: {:?}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("EVIL\n"),
        "raw newline must not leak: {:?}",
        out.stdout
    );
    assert!(out.stdout.contains("sdb"), "{}", out.stdout);
    assert!(out.stdout.contains("sda"), "{}", out.stdout);
    assert!(out.stdout.contains("512.00 MiB"), "{}", out.stdout);
    assert!(out.stdout.contains("1.00 GiB"), "{}", out.stdout);
    assert!(out.stdout.contains("<no serial>"), "{}", out.stdout);
    assert!(out.stdout.contains("0 partition(s)"), "{}", out.stdout);
    assert_eq!(
        out.stdout
            .lines()
            .filter(|line| line.contains("partition(s)"))
            .count(),
        2,
        "one line per device: {:?}",
        out.stdout
    );
    assert!(out.stderr.contains("destroy the system"));

    // The same fixture through `--json` must parse cleanly and carry the
    // sanitised record strings too (both sources checked here: sysfs
    // vendor above, udev model below).
    let out = run(&[
        "list",
        "--json",
        "--all",
        "--sysfs-root",
        sysfs.to_str().expect("utf-8"),
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("list json parses");
    let stick = value["devices"]
        .as_array()
        .expect("devices array")
        .iter()
        .find(|device| device["name"] == "sdb")
        .expect("the stick is listed");
    assert_eq!(stick["model"], "EVIL?[2Judev-model");
    assert_eq!(stick["vendor"], "EVIL??[2Jcaf?INJECTED");
    let text = format!(
        "{}|{}",
        stick["model"].as_str().expect("model"),
        stick["vendor"].as_str().expect("vendor")
    );
    assert!(text.is_ascii(), "json strings must be ASCII: {text:?}");
    assert!(
        !text.contains('\u{1b}'),
        "ESC must not leak into JSON: {text:?}"
    );

    // Default filter hides the fixed disk again and stays silent.
    let out = run(&["list", "--sysfs-root", sysfs.to_str().expect("utf-8")]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.is_ascii(), "{}", out.stdout);
    assert_eq!(
        out.stdout.lines().count(),
        2,
        "header + 1 device: {:?}",
        out.stdout
    );
    assert!(out.stdout.contains("sdb"));
    assert!(!out.stdout.contains("sda"));
    assert!(!out.stderr.contains("destroy"), "{}", out.stderr);
}

#[test]
fn plan_dry_run_enriches_the_device_ref_without_breaking_the_stub_shape() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let sysfs = sysfs_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // With a sysfs root the graded device picks up the S04 facts (the
    // local /dev node need not exist: the fixture tree is the truth).
    let mut args = plan_args(&iso, "/dev/sdb", true, true);
    args.push("--sysfs-root".to_string());
    args.push(sysfs.display().to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("plan json");
    assert_eq!(value["device"]["path"], "/dev/sdb");
    assert_eq!(value["device"]["block_device"], true);
    assert_eq!(value["device"]["size_bytes"], 536_870_912u64);
    assert_eq!(value["device"]["model"], serde_json::Value::Null);
    assert_eq!(
        value["device"]["sysfs"],
        format!("{}/class/block/sdb", sysfs.display())
    );

    // Without enrichment (no fixture root, /dev/null resolves to no
    // block device in sysfs) the S03 plan shape is untouched.
    let out = plan_run(&iso, "/dev/null", true);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("plan json");
    assert_eq!(value["device"]["block_device"], false);
    assert_eq!(value["device"]["size_bytes"], serde_json::Value::Null);
    assert_eq!(value["device"]["sysfs"], serde_json::Value::Null);
    assert_eq!(value["device"]["serial"], serde_json::Value::Null);
}

// ---------------------------------------------------------------------------
// analyze --device (S05 device inspection + PLAN §6 verdict)
// ---------------------------------------------------------------------------

/// The S05 stick fixture in `scratch`: a synthetic sysfs tree (fixed
/// `sda`, 1 GiB, plus removable `sdb`, 512 MiB, carrying one `sdb1`
/// partition in the live-kernel sibling-symlink layout with the
/// `device/{vendor,model,serial}` identity fields and a udev record
/// dir), an 8 MiB sparse device buffer (MBR + FAT32 surface, the bytes
/// the tests sample through the `--device-file` hook) and a mountinfo
/// file with a `/` mount on 8:1 — nothing mounts the fixture disk by
/// default. Tests enrich the tree or rewrite the mountinfo in place.
/// Nothing binary is committed (see `tests/fixtures/README.md`).
fn stick_fixture(scratch: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
    let sysfs = scratch.join("sys");
    for (name, units, removable, dev) in [
        ("sda", "2097152", "0", "8:0"),
        ("sdb", "1048576", "1", "8:16"),
    ] {
        let dir = sysfs.join("class/block").join(name);
        std::fs::create_dir_all(&dir).expect("create device dir");
        std::fs::write(dir.join("size"), units).expect("seed size");
        std::fs::write(dir.join("removable"), removable).expect("seed removable");
        std::fs::write(dir.join("ro"), "0").expect("seed ro");
        std::fs::write(dir.join("dev"), dev).expect("seed dev");
    }
    // The stick's identity fields live on its `device` node (a plain
    // directory inside the class entry here; discovery ignores it as
    // junk when walking partitions).
    let device_dir = sysfs.join("class/block/sdb/device");
    std::fs::create_dir_all(&device_dir).expect("device dir");
    std::fs::write(device_dir.join("vendor"), "SanDisk").expect("seed vendor");
    std::fs::write(device_dir.join("model"), "Extreme").expect("seed model");
    std::fs::write(device_dir.join("serial"), "ABCD1234").expect("seed serial");
    // Inner partition + the partition sibling link + its udev record:
    // the exact pattern of `list_skips_partition_siblings…` (S04).
    let inner = sysfs.join("class/block/sdb/sdb1");
    std::fs::create_dir_all(&inner).expect("inner partition dir");
    std::fs::write(inner.join("size"), "524288").expect("seed size");
    std::fs::write(inner.join("dev"), "8:17").expect("seed dev");
    std::fs::write(inner.join("partition"), "1").expect("seed partition");
    std::fs::create_dir_all(sysfs.join("run/udev/data")).expect("record dir");
    std::fs::write(
        sysfs.join("run/udev/data/b8:17"),
        "I:56732\nE:ID_FS_TYPE=vfat\nE:ID_BUS=usb\n",
    )
    .expect("seed partition record");
    std::os::unix::fs::symlink(&inner, sysfs.join("class/block/sdb1"))
        .expect("link partition sibling");

    let dev_file = stick_device_file(&scratch.join("sdb"), 8 * 1024 * 1024);

    // The default table: only `/` on 8:1, which is not the fixture
    // disk. Tests rewrite the file for the mounted/system-disk cases.
    let mountinfo = scratch.join("mountinfo");
    std::fs::write(&mountinfo, "1 0 8:1 / / rw,relatime - ext4 /dev/root rw\n")
        .expect("seed mountinfo");
    (sysfs, dev_file, mountinfo)
}

/// A sparse device file of `len` bytes holding the stick surface an
/// `analyze --device` run reads: an MBR in LBA0 (0x55AA at 510; entry 1
/// at 446 with type 0x0c, start LBA 2048, 4096 sectors) and a FAT32
/// BPB at byte 2048×512 (bytes-per-sector 512 at offset 11, `FAT32   `
/// at 82, 0x55AA at 510). Sparse via `set_len`, so an 8 MiB fixture
/// costs no bulk zeroing.
fn stick_device_file(path: &std::path::Path, len: u64) -> PathBuf {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create device file");
    file.set_len(len).expect("device file length");

    let mut mbr = [0u8; 512];
    mbr[510..512].copy_from_slice(&rufus_core::partition::MBR_SIGNATURE);
    mbr[446 + 4] = 0x0c;
    mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());

    let mut bpb = [0u8; 512];
    bpb[11..13].copy_from_slice(&512u16.to_le_bytes());
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510..512].copy_from_slice(&rufus_core::partition::MBR_SIGNATURE);

    file.write_at(&mbr, 0).expect("write MBR");
    file.write_at(&bpb, 2048 * 512).expect("write FAT32 BPB");
    path.to_path_buf()
}

/// A blank sparse device file of `len` bytes (no table, no content) —
/// the fixed-disk fixture.
fn blank_device_file(path: &std::path::Path, len: u64) -> PathBuf {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create device file");
    file.set_len(len).expect("device file length");
    path.to_path_buf()
}

/// Stamp `bytes` at `offset` of a device file (S05 tests enrich the
/// [`stick_device_file`] surface in place: whole-disk LVM2 labels).
fn patch_file(path: &std::path::Path, offset: u64, bytes: &[u8]) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open file to patch");
    file.write_at(bytes, offset).expect("patch bytes");
}

/// Base `analyze --device` invocation over the fixture paths. `node`
/// is the discovered device node spelling (always `/dev/<name>` in
/// these fixtures), `device_file` the fixture buffer handed to the
/// S05 `--device-file` hook; tests push `--json` and their own extra
/// switches themselves.
fn analyze_device_args(
    image: &std::path::Path,
    sysfs: &std::path::Path,
    mountinfo: &std::path::Path,
    node: &str,
    device_file: &std::path::Path,
) -> Vec<String> {
    vec![
        "analyze".to_string(),
        image.display().to_string(),
        "--sysfs-root".to_string(),
        sysfs.display().to_string(),
        "--mountinfo".to_string(),
        mountinfo.display().to_string(),
        "--device".to_string(),
        node.to_string(),
        "--device-file".to_string(),
        device_file.display().to_string(),
    ]
}

#[test]
fn analyze_device_reports_a_clean_usb_as_safe() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.is_empty(), "{}", out.stderr);

    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    // The S03 image facts ride on top unchanged.
    assert_eq!(value["path"], iso.display().to_string());
    assert_eq!(value["size_bytes"], 32_780u64);
    assert_eq!(value["sha256"], FIXTURE_SHA256);
    assert_eq!(value["kind"], "iso");

    let device = &value["device"];
    assert_eq!(device["name"], "sdb");
    assert_eq!(
        device["path"],
        dev_file.display().to_string(),
        "the report names the sampled file (--device-file hook)"
    );
    assert_eq!(device["size_bytes"], 536_870_912u64);
    assert_eq!(device["serial"], "ABCD1234");
    assert_eq!(device["model"], "Extreme");
    assert_eq!(device["verdict"], serde_json::json!({ "safe": true }));
    assert!(
        device["verdict"].get("reason").is_none(),
        "a safe verdict carries no reason key: {device}"
    );
    assert_eq!(device["table"]["kind"], "mbr");
    assert_eq!(device["table"]["backup_gpt"], false);
    let parts = device["table"]["partitions"]
        .as_array()
        .expect("table partitions");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["kind"], "fat32");
    assert_eq!(
        device["partition_filesystems"],
        serde_json::json!([{ "partition": "sdb1", "filesystem": "fat32" }]),
    );
    assert!(
        device["mounts"]
            .as_array()
            .expect("mounts array")
            .is_empty()
    );
    assert!(device["swaps"].as_array().expect("swaps array").is_empty());
    assert!(
        device["holders"]
            .as_array()
            .expect("holders array")
            .is_empty(),
    );
    assert!(
        device["warnings"]
            .as_array()
            .expect("warnings array")
            .is_empty(),
        "{device}"
    );
}

#[test]
fn analyze_device_refuses_a_mounted_stick() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // The desktop mounted sdb1; `\040` is the kernel's escaped space.
    std::fs::write(
        &mountinfo,
        "1 0 8:17 / /media/user/my\\040stick rw,relatime - vfat /dev/sdb1 rw\n",
    )
    .expect("rewrite mountinfo");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    // analyze *reports* the verdict and exits 0; S06 enforces refusals.
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["verdict"]["reason"], "mounted");
    assert_eq!(
        device["verdict"]["message"],
        "device is mounted at /media/user/my stick - unmount it first",
    );
    assert_eq!(
        device["mounts"],
        serde_json::json!([{
            "dev": "8:17",
            "mountpoint": "/media/user/my stick",
            "fstype": "vfat",
            "source": "/dev/sdb1",
        }]),
        "the mountpoint arrives octal-unescaped",
    );

    // The human spelling stays ASCII and unmangled.
    let out = run_args(
        &analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("verdict:"), "{}", out.stdout);
    assert!(out.stdout.contains("refuse:"), "{}", out.stdout);
    assert!(
        out.stdout.contains("mounted:  /media/user/my stick (vfat)"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.is_ascii(), "{}", out.stdout);
}

#[test]
fn analyze_device_refuses_the_system_disk() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // The machine boots from sdb1: its devnum mounts `/`.
    std::fs::write(&mountinfo, "1 0 8:17 / / rw,relatime - ext4 /dev/root rw\n")
        .expect("rewrite mountinfo");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    assert_eq!(value["device"]["verdict"]["reason"], "system_disk");
    assert_eq!(
        value["device"]["verdict"]["message"],
        "device backs the running system",
    );
}

#[test]
fn analyze_device_refuses_active_swap() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    let swaps = dir.path().join("swaps");
    std::fs::write(
        &swaps,
        "Filename\t\tType\t\tSize\t\tUsed\t\tPriority\n\
         /dev/sdb1                       partition\t3000\t0\t-2\n",
    )
    .expect("seed swaps");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--swaps".to_string());
    args.push(swaps.display().to_string());
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["verdict"]["reason"], "swap");
    assert_eq!(
        device["verdict"]["message"],
        "device is active swap on /dev/sdb1 - disable swap first",
    );
    assert_eq!(device["swaps"], serde_json::json!(["/dev/sdb1"]),);
}

#[test]
fn analyze_device_refuses_an_lvm_pv() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // A whole-disk LVM2 label around the existing MBR: the label is the
    // refusal, the table keeps parsing as rot-free metadata.
    patch_file(&dev_file, 512, b"LABELONE");
    patch_file(&dev_file, 536, b"LVM2 001");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["verdict"]["reason"], "refused_filesystem");
    let message = device["verdict"]["message"].as_str().expect("message");
    assert!(message.contains("lvm2"), "{message}");
    assert_eq!(device["filesystem"], "lvm2");
}

#[test]
fn analyze_device_reports_a_holder() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // dm-crypt/LVM stacked on top of the disk itself.
    std::fs::create_dir_all(sysfs.join("class/block/sdb/holders/dm-0")).expect("holder dir");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["verdict"]["reason"], "holder");
    assert_eq!(device["verdict"]["message"], "device is held by dm-0");
    assert_eq!(device["holders"], serde_json::json!(["dm-0"]));
}

#[test]
fn analyze_device_extended_container_warns_in_human_and_json() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // Two-slot MBR: slot 0 becomes an extended container (type 0x0F),
    // slot 1 keeps the FAT32 primary at the geometry the stick
    // fixture's BPB already sits at (LBA 2048, 4096 sectors). The
    // container drops out of the listed partitions with one warning.
    let mut mbr = [0u8; 512];
    mbr[510..512].copy_from_slice(&rufus_core::partition::MBR_SIGNATURE);
    mbr[446 + 4] = 0x0f;
    mbr[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());
    mbr[446 + 16 + 4] = 0x0c;
    mbr[446 + 16 + 8..446 + 16 + 12].copy_from_slice(&2048u32.to_le_bytes());
    mbr[446 + 16 + 12..446 + 16 + 16].copy_from_slice(&4096u32.to_le_bytes());
    patch_file(&dev_file, 0, &mbr);

    // Human mode: one `warning:` line, and the note is report-only —
    // the verdict stays safe.
    let out = run_args(
        &analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.is_empty(), "{}", out.stderr);
    assert!(
        out.stdout.contains(
            "warning:  extended partition (type 0x0f): logical partitions are not listed"
        ),
        "human output carries the table note:\n{}",
        out.stdout
    );
    assert!(out.stdout.contains("verdict:  safe"), "{}", out.stdout);

    // JSON mode: the same string in the report's `warnings` array —
    // exactly once — and the layout's own `table.warnings` copy intact.
    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    let text = "extended partition (type 0x0f): logical partitions are not listed";
    let reported = device["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .map(|warning| warning.as_str().expect("plain-text warning"))
        .collect::<Vec<_>>();
    assert_eq!(
        reported.iter().filter(|warning| **warning == text).count(),
        1,
        "exactly one report warning: {device}"
    );
    let table = device["table"]["warnings"]
        .as_array()
        .expect("table warnings array")
        .iter()
        .map(|warning| warning.as_str().expect("plain-text warning"))
        .collect::<Vec<_>>();
    assert!(table.contains(&text), "{device}");
    assert_eq!(device["verdict"], serde_json::json!({ "safe": true }));
}

#[test]
fn analyze_device_without_a_device_key_keeps_the_s03_shape() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let iso = fixture(&dir.path().join("fixture.iso"));

    let out = run(&["analyze", "--json", iso.to_str().expect("path")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    // Exactly the S03 four keys (the parsed `Value` sorts them; the
    // declaration order on the wire is pinned by the leading `path`).
    let keys = value
        .as_object()
        .expect("analyze object")
        .keys()
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 4, "exactly the S03 keys: {keys:?}");
    assert_eq!(
        keys,
        ["kind", "path", "sha256", "size_bytes"],
        "the four image keys, no more"
    );
    assert!(value.get("device").is_none(), "no device key");
    assert!(
        out.stdout.starts_with("{\n  \"path\":"),
        "declaration order puts path first: {}",
        out.stdout
    );

    // And the human rendering stays byte-identical to the S03
    // contract: exactly the four image lines.
    let out = run(&["analyze", iso.to_str().expect("path")]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(
        out.stdout,
        format!(
            "image:  {}\nsize:   {} ({})\nkind:   {}\nsha256: {}\n",
            iso.display(),
            32_780,
            rufus_core::human_bytes(32_780),
            "iso",
            FIXTURE_SHA256,
        ),
    );
}

#[test]
fn analyze_device_unknown_path_exits_2() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // Nothing resolves a path that merely *ends* in a device name
    // (that inference was removed; the `--device-file` hook is the
    // explicit way to sample fixture bytes).
    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/no/such/sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 2, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
    assert_eq!(value["error"], "device");
    assert!(
        value["message"]
            .as_str()
            .expect("msg")
            .contains("no/such/sdb"),
        "{}",
        value["message"]
    );
}

#[test]
fn analyze_device_empty_confirm_serial_is_usage() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &dev_file);
    args.push("-x".to_string());
    args.push("--confirm-serial".to_string());
    args.push("  ".to_string());
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 1, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
    assert_eq!(value["error"], "usage");
    assert_eq!(value["message"], "confirmation serial must not be empty",);
}

#[test]
fn analyze_device_needs_show_all_and_serial_for_a_fixed_disk() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, _dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // A blank 1 GiB fixed disk, known by its serial (udev record).
    let sda_file = blank_device_file(&dir.path().join("sda"), 1024 * 1024 * 1024);
    std::fs::write(
        sysfs.join("run/udev/data/b8:0"),
        "I:5\nE:ID_SERIAL_SHORT=SER0001\n",
    )
    .expect("seed fixed-disk serial record");

    // Each row: the extra flags and whether the verdict may be safe.
    let variants: Vec<(Vec<&str>, bool)> = vec![
        (vec![], false),     // no -x: hidden unless shown
        (vec!["-x"], false), // show-all alone does not confirm
        (vec!["-x", "--confirm-serial", "WRONG"], false),
        (vec!["-x", "--confirm-serial", "SER0001"], true),
    ];
    for (extra, want_safe) in &variants {
        let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sda", &sda_file);
        args.extend(extra.iter().map(|flag| flag.to_string()));
        args.push("--json".to_string());
        let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(out.code, 0, "extras {extra:?}: {}", out.stderr);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
        let device = &value["device"];
        assert_eq!(device["name"], "sda", "extras {extra:?}");
        assert_eq!(device["verdict"]["safe"], *want_safe, "extras {extra:?}");
        if *want_safe {
            assert!(
                device["verdict"].get("reason").is_none(),
                "extras {extra:?}"
            );
        } else {
            assert_eq!(
                device["verdict"]["reason"], "not_removable",
                "extras {extra:?}"
            );
        }
    }
}

#[test]
fn analyze_device_partition_path_names_the_disk() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // A partition path is the common miss: the refusal says which disk
    // owns the name. Spellings that share the basename behave the same.
    for requested in ["/dev/sdb1", "sdb1"] {
        let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, requested, &dev_file);
        args.push("--json".to_string());
        let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(out.code, 2, "requested {requested}: {:?}", out);
        let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
        assert_eq!(value["error"], "device");
        assert_eq!(
            value["message"],
            format!("{requested} is a partition of /dev/sdb - select the whole disk"),
            "requested {requested}"
        );
    }
}

#[test]
fn analyze_device_regular_file_no_longer_resolves_a_disk() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // No basename inference: the fixture buffer itself is not a device
    // spelling. Sampling fixture bytes needs the explicit S05 hook.
    let args = vec![
        "analyze".to_string(),
        iso.display().to_string(),
        "--sysfs-root".to_string(),
        sysfs.display().to_string(),
        "--mountinfo".to_string(),
        mountinfo.display().to_string(),
        "--device".to_string(),
        dev_file.display().to_string(),
        "--json".to_string(),
    ];
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 2, "{:?}", out);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("error json");
    assert_eq!(value["error"], "device");
    assert_eq!(
        value["message"],
        format!("no block device found for {}", dev_file.display()),
    );
}

#[test]
fn analyze_device_bare_kernel_name_resolves() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));

    // The bare kernel name is a device spelling: it resolves the sdb
    // device (fixture root) while `--device-file` redirects the bytes.
    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "sdb", &dev_file);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["name"], "sdb");
    assert_eq!(device["path"], dev_file.display().to_string());
    assert_eq!(device["verdict"], serde_json::json!({ "safe": true }));
}

#[test]
fn analyze_device_unreadable_says_so_in_the_table_line() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, _dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // The hook points at a path that cannot be opened at all (as a
    // real dead USB bridge or a permission problem would): the report
    // must still be answerable, and the table line must not claim a
    // blank disk.
    let gone = dir.path().join("no-such-device-file");

    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &gone);
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    let device = &value["device"];
    assert_eq!(device["verdict"]["reason"], "unreadable");
    let message = device["verdict"]["message"].as_str().expect("message");
    assert!(message.contains("/no-such-device-file"), "{message}");
    assert_eq!(device["table"], serde_json::Value::Null, "nothing read");

    // The human spelling: the table line admits the unreadable state.
    let out = run_args(
        &analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sdb", &gone)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("table:    unreadable"),
        "{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("table:    none"),
        "unreadable must not read as blank: {}",
        out.stdout
    );
    assert!(out.stdout.contains("verdict:"), "{}", out.stdout);
    assert!(out.stdout.contains("refuse:"), "{}", out.stdout);
    assert!(
        out.stdout.contains("device is unreadable:"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.is_ascii(), "{}", out.stdout);
}

#[test]
fn analyze_device_trims_the_confirm_serial() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (sysfs, _dev_file, mountinfo) = stick_fixture(dir.path());
    let iso = fixture(&dir.path().join("fixture.iso"));
    // The same fixed-disk shape as the show-all test: serial SER0001.
    let sda_file = blank_device_file(&dir.path().join("sda"), 1024 * 1024 * 1024);
    std::fs::write(
        sysfs.join("run/udev/data/b8:0"),
        "I:5\nE:ID_SERIAL_SHORT=SER0001\n",
    )
    .expect("seed fixed-disk serial record");

    // Surrounding whitespace does not hide a match: the typed serial
    // is trimmed once, where it is accepted, before the comparison.
    let mut args = analyze_device_args(&iso, &sysfs, &mountinfo, "/dev/sda", &sda_file);
    args.push("-x".to_string());
    args.push("--confirm-serial".to_string());
    args.push("  SER0001\t".to_string());
    args.push("--json".to_string());
    let out = run_args(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(out.code, 0, "{}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).expect("analyze json");
    assert_eq!(
        value["device"]["verdict"],
        serde_json::json!({ "safe": true })
    );
    assert!(value["device"]["verdict"].get("reason").is_none());
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
