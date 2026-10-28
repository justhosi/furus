//! `xtask`: repo maintenance tasks for the furus workspace (S01).
//!
//! No feature code lives here; only checks and reports:
//!
//! * `assets --check` — validate `assets/manifest.json` against files on disk
//! * `parity`          — validate `data/parity.csv` against `data/functions.csv`
//! * `parity --check`  — additionally prove `data/parity.csv` is freshly
//!   regenerated (CI gate; never dirties the tree)
//! * `size`            — release-build, enforce budgets, compare against the
//!   committed baseline (never writes it)
//! * `size --write-baseline` — update the committed baseline (humans only)
//! * `ci`              — run every gate in order (fmt, clippy, test, ...)
//! * `qa`, `dist`      — honest stubs for S27 / S26
//!
//! The xtask must work when invoked from the repo root
//! (`cargo xtask ...`); all paths are anchored at the workspace root derived
//! from `CARGO_MANIFEST_DIR`, never at the current directory.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;
use sha2::Digest;

// ---------------------------------------------------------------------------
// Root + process helpers
// ---------------------------------------------------------------------------

/// Workspace root: the directory containing `xtask/` (`CARGO_MANIFEST_DIR`
/// is `<root>/xtask` both for `cargo xtask` and for unit tests).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one level below the repo root")
        .to_path_buf()
}

/// Run a command with inherited stdio; fail on non-zero exit.
fn run(cmd: &str, args: &[&str], cwd: &Path) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("`{cmd} {}` exited with {status}", args.join(" "))
    }
}

/// Run a command with captured output (keeps scratch paths out of the log);
/// fail on non-zero exit.
fn run_quiet(cmd: &str, args: &[&str], cwd: &Path) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;
    if !out.status.success() {
        bail!(
            "`{cmd} {}` exited with {}\n{}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True when `<tool> --version` runs successfully.
fn tool_present(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// assets --check
// ---------------------------------------------------------------------------

const EXPECTED_ASSET_COUNT: usize = 86;

#[derive(Debug, Deserialize)]
struct Manifest {
    meta: serde_json::Value,
    resources: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // id/type/name/source/licence are parsed for schema checks, not read
struct ManifestEntry {
    id: String,
    #[serde(rename = "type")]
    rtype: String,
    name: String,
    file: String,
    bytes: u64,
    sha256: String,
    source: String,
    licence: String,
    #[serde(default)]
    notes: Option<String>,
}

fn parse_manifest(text: &str) -> Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_str(text).context("assets/manifest.json is not valid JSON")?;
    if !manifest.meta.is_object() {
        bail!("assets/manifest.json: `meta` must be a JSON object");
    }
    if manifest.resources.len() != EXPECTED_ASSET_COUNT {
        bail!(
            "assets/manifest.json: expected {EXPECTED_ASSET_COUNT} entries, found {}",
            manifest.resources.len()
        );
    }
    Ok(manifest)
}

/// Resolve a manifest `file` value to a path inside `resources_dir`.
///
/// The value must be exactly one normal path component. Anything else —
/// `..`, absolute paths, subdirectories, `.`, empty — fails closed so a
/// hostile manifest entry can never escape `assets/resources/`.
fn manifest_file_path(resources_dir: &Path, file: &str) -> Result<PathBuf> {
    let rel = Path::new(file);
    let mut components = rel.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(resources_dir.join(rel)),
        _ => bail!("unsafe asset file name in manifest: {file:?}"),
    }
}

/// Fail closed on symlinks and non-regular files; return the size on success.
fn asset_file_size(path: &Path, display: &str) -> Result<u64> {
    let file_type = std::fs::symlink_metadata(path)
        .with_context(|| format!("missing asset file: {display}"))?
        .file_type();
    if file_type.is_symlink() {
        bail!("asset file must not be a symlink: {display}");
    }
    if !file_type.is_file() {
        bail!("asset is not a regular file: {display}");
    }
    Ok(std::fs::metadata(path)
        .with_context(|| format!("cannot stat {display}"))?
        .len())
}

fn sha256_of(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn cmd_assets_check(root: &Path) -> Result<()> {
    let manifest_path = root.join("assets/manifest.json");
    let resources_dir = root.join("assets/resources");
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    let manifest = parse_manifest(&text)?;

    let mut expected_files: BTreeSet<String> = BTreeSet::new();
    for entry in &manifest.resources {
        let path = manifest_file_path(&resources_dir, &entry.file)?;
        let len = asset_file_size(&path, &entry.file)?;
        if len != entry.bytes {
            bail!(
                "size mismatch for {}: manifest says {} bytes, disk has {}",
                entry.file,
                entry.bytes,
                len
            );
        }
        let digest = sha256_of(&path)?;
        if digest != entry.sha256.to_lowercase() {
            bail!(
                "SHA-256 mismatch for {}:\n  manifest: {}\n  actual:   {digest}",
                entry.file,
                entry.sha256
            );
        }
        println!("PASS {} ({} bytes, sha256 ok)", entry.file, entry.bytes);
        if !expected_files.insert(entry.file.clone()) {
            bail!("duplicate manifest entry for {}", entry.file);
        }
    }

    // Fail on files present on disk but absent from the manifest, and fail
    // closed on symlinks (they are never legitimate asset payloads).
    let mut extra = Vec::new();
    let dir = std::fs::read_dir(&resources_dir)
        .with_context(|| format!("cannot list {}", resources_dir.display()))?;
    for item in dir {
        let item = item.with_context(|| "cannot read resources dir entry")?;
        let name = item.file_name().to_string_lossy().into_owned();
        let file_type = item.file_type()?;
        if file_type.is_symlink() {
            bail!("unexpected symlink in assets/resources: {name}");
        }
        if file_type.is_file() && !expected_files.contains(&name) {
            extra.push(name);
        }
    }
    if !extra.is_empty() {
        bail!("files on disk missing from manifest: {}", extra.join(", "));
    }

    println!(
        "assets: {} entries, {} files verified",
        manifest.resources.len(),
        expected_files.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// parity
// ---------------------------------------------------------------------------

const EXPECTED_PARITY_ROWS: usize = 2_709;
const DISPOSITIONS: &[&str] = &["port", "c-ffi", "crate", "system-tool", "replace", "thunk"];

/// Expected per-disposition counts from the analysed baseline.
fn expected_disposition_counts() -> BTreeMap<&'static str, usize> {
    [
        ("port", 484),
        ("c-ffi", 393),
        ("crate", 407),
        ("system-tool", 236),
        ("replace", 1154),
        ("thunk", 35),
    ]
    .into_iter()
    .collect()
}

fn is_valid_disposition(d: &str) -> bool {
    DISPOSITIONS.contains(&d)
}

/// Valid slice ids are `S00`..=`S27` (two digits, zero-padded).
fn is_valid_slice(s: &str) -> bool {
    let digits = s.strip_prefix('S').unwrap_or("");
    digits.len() == 2
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u32>().map(|n| n <= 27).unwrap_or(false)
}

#[derive(Debug)]
struct ParityRow {
    address: String,
    disposition: String,
    slice: String,
}

fn parse_parity_rows(text: &str) -> Result<Vec<ParityRow>> {
    let mut reader = csv::Reader::from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .context("parity CSV has no header")?
        .clone();
    for col in [
        "address",
        "name",
        "size",
        "module",
        "kind",
        "disposition",
        "slice",
        "notes",
    ] {
        if !headers.iter().any(|h| h == col) {
            bail!("parity CSV: missing required column `{col}`");
        }
    }
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record.context("parity CSV: malformed record")?;
        let get = |col: &str| {
            headers
                .iter()
                .position(|h| h == col)
                .map(|i| record.get(i).unwrap_or("").to_string())
                .unwrap_or_default()
        };
        rows.push(ParityRow {
            address: get("address"),
            disposition: get("disposition"),
            slice: get("slice"),
        });
    }
    Ok(rows)
}

/// Validate the committed `data/parity.csv` against `data/functions.csv`.
fn validate_parity_files(root: &Path) -> Result<()> {
    let text = std::fs::read_to_string(root.join("data/parity.csv"))
        .context("cannot read data/parity.csv")?;
    let rows = parse_parity_rows(&text)?;
    if rows.len() != EXPECTED_PARITY_ROWS {
        bail!(
            "data/parity.csv: expected {EXPECTED_PARITY_ROWS} data rows, found {}",
            rows.len()
        );
    }

    let mut by_disposition: BTreeMap<&str, usize> = BTreeMap::new();
    let mut port_by_slice: BTreeMap<String, usize> = BTreeMap::new();
    for row in &rows {
        if !is_valid_disposition(&row.disposition) {
            bail!(
                "data/parity.csv: {} has invalid disposition `{}`",
                row.address,
                row.disposition
            );
        }
        *by_disposition.entry(row.disposition.as_str()).or_default() += 1;
        if row.disposition == "port" {
            if !is_valid_slice(&row.slice) {
                bail!(
                    "data/parity.csv: port row {} has invalid slice `{}`",
                    row.address,
                    row.slice
                );
            }
            *port_by_slice.entry(row.slice.clone()).or_default() += 1;
        }
    }

    println!("parity: {} data rows", rows.len());
    println!("per-disposition counts:");
    for (name, expected) in expected_disposition_counts() {
        let actual = by_disposition.get(name).copied().unwrap_or(0);
        let flag = if actual == expected { "ok" } else { "MISMATCH" };
        println!("  {name:<12} {actual:<6} (expected {expected}) [{flag}]");
        if actual != expected {
            bail!("disposition `{name}`: expected {expected} rows, found {actual}");
        }
    }
    println!("per-slice port counts:");
    for (slice, count) in &port_by_slice {
        println!("  {slice:<5} {count}");
    }

    // functions.csv must cover exactly the same address set.
    let functions_text = std::fs::read_to_string(root.join("data/functions.csv"))
        .context("cannot read data/functions.csv")?;
    let mut reader = csv::Reader::from_reader(functions_text.as_bytes());
    let headers = reader
        .headers()
        .context("functions CSV has no header")?
        .clone();
    let addr_idx = headers
        .iter()
        .position(|h| h == "address")
        .context("functions CSV: missing `address` column")?;
    let mut function_addrs: BTreeSet<String> = BTreeSet::new();
    for record in reader.records() {
        let record = record.context("functions CSV: malformed record")?;
        function_addrs.insert(record.get(addr_idx).unwrap_or("").to_string());
    }
    if function_addrs.len() != EXPECTED_PARITY_ROWS {
        bail!(
            "data/functions.csv: expected {EXPECTED_PARITY_ROWS} data rows, found {}",
            function_addrs.len()
        );
    }
    let parity_addrs: BTreeSet<String> = rows.iter().map(|r| r.address.clone()).collect();
    if parity_addrs != function_addrs {
        let only_parity: Vec<_> = parity_addrs.difference(&function_addrs).take(5).collect();
        let only_functions: Vec<_> = function_addrs.difference(&parity_addrs).take(5).collect();
        bail!(
            "address sets differ (parity-only sample: {only_parity:?}, functions-only sample: {only_functions:?})"
        );
    }
    println!("parity: address sets of parity.csv and functions.csv match (2,709)");

    Ok(())
}

/// Regenerate the ledger into a scratch directory that mirrors the repo
/// layout (`tools/parity.py` next to `data/`), so the committed tree is
/// never touched. Returns the regenerated bytes.
fn regenerate_parity_bytes(root: &Path) -> Result<Vec<u8>> {
    let tmp = std::env::temp_dir().join(format!("furus-parity-check-{}", std::process::id()));
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp).with_context(|| format!("cannot clear {}", tmp.display()))?;
    }
    std::fs::create_dir_all(tmp.join("tools"))?;
    std::fs::create_dir_all(tmp.join("data"))?;
    std::fs::copy(root.join("tools/parity.py"), tmp.join("tools/parity.py"))
        .context("cannot stage tools/parity.py")?;
    std::fs::copy(
        root.join("data/functions.csv"),
        tmp.join("data/functions.csv"),
    )
    .context("cannot stage data/functions.csv")?;
    let result = run_quiet("python3", &["tools/parity.py"], &tmp).and_then(|_| {
        std::fs::read(tmp.join("data/parity.csv"))
            .context("tools/parity.py did not produce data/parity.csv")
    });
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

fn check_regeneration_fresh(committed: &[u8], regenerated: &[u8]) -> Result<()> {
    if committed == regenerated {
        println!("parity: data/parity.csv is fresh (regeneration changes nothing)");
        Ok(())
    } else {
        bail!(
            "data/parity.csv is stale: regenerating via tools/parity.py would change it; \
             run `cargo xtask parity --regenerate` and commit the result"
        );
    }
}

enum ParityMode {
    Validate,
    Regenerate,
    Check,
}

fn cmd_parity(root: &Path, mode: ParityMode) -> Result<()> {
    match mode {
        ParityMode::Regenerate => {
            let before = std::fs::read(root.join("data/parity.csv")).ok();
            let before_hash = before
                .as_deref()
                .map(sha2::Sha256::digest)
                .map(|d| hex_encode(&d));
            println!("running: python3 tools/parity.py");
            run("python3", &["tools/parity.py"], root)?;
            let after = std::fs::read(root.join("data/parity.csv"))
                .context("tools/parity.py did not produce data/parity.csv")?;
            let after_hash = hex_encode(&sha2::Sha256::digest(&after));
            if before_hash.as_deref() == Some(after_hash.as_str()) {
                println!("parity: data/parity.csv unchanged by --regenerate");
            } else {
                println!("parity: data/parity.csv changed by --regenerate");
            }
        }
        ParityMode::Check => {
            let committed = std::fs::read(root.join("data/parity.csv"))
                .context("cannot read data/parity.csv")?;
            let regenerated = regenerate_parity_bytes(root)?;
            check_regeneration_fresh(&committed, &regenerated)?;
        }
        ParityMode::Validate => {}
    }
    validate_parity_files(root)
}

// ---------------------------------------------------------------------------
// size
// ---------------------------------------------------------------------------

struct BinaryBudget {
    name: &'static str,
    budget: u64,
}

const BINARY_BUDGETS: &[BinaryBudget] = &[
    BinaryBudget {
        name: "rufus",
        budget: 3_000_000,
    },
    BinaryBudget {
        name: "rufus-helper",
        budget: 2_500_000,
    },
    BinaryBudget {
        name: "rufus-gui",
        budget: 12_000_000,
    },
];

#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
struct BaselineEntry {
    bytes: u64,
    budget: u64,
}

fn parse_size_baseline(text: &str) -> Result<BTreeMap<String, BaselineEntry>> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("size-baseline.json is not valid JSON")?;
    let binaries = value
        .get("binaries")
        .and_then(|b| b.as_object())
        .context("size-baseline.json: missing `binaries` object")?;
    let mut out = BTreeMap::new();
    for (name, entry) in binaries {
        let entry: BaselineEntry = serde_json::from_value(entry.clone())
            .with_context(|| format!("size-baseline.json: bad entry for `{name}`"))?;
        out.insert(name.clone(), entry);
    }
    Ok(out)
}

/// Fail when a measured binary differs from the committed baseline, or when
/// the baseline entry is missing or carries a different budget (stale).
fn check_size_drift(
    measured: &BTreeMap<String, u64>,
    baseline: &BTreeMap<String, BaselineEntry>,
) -> Result<()> {
    for spec in BINARY_BUDGETS {
        let entry = baseline.get(spec.name).with_context(|| {
            format!(
                "size baseline has no entry for `{}`; run `cargo xtask size --write-baseline`",
                spec.name
            )
        })?;
        if entry.budget != spec.budget {
            bail!(
                "size baseline budget for `{}` is stale ({} vs {}); run `cargo xtask size --write-baseline`",
                spec.name,
                entry.budget,
                spec.budget
            );
        }
        let bytes = measured.get(spec.name).copied().unwrap_or(0);
        if bytes != entry.bytes {
            bail!(
                "size drift for `{}`: baseline {} bytes, measured {} bytes; run `cargo xtask size --write-baseline` to update the baseline",
                spec.name,
                entry.bytes,
                bytes
            );
        }
    }
    Ok(())
}

fn cmd_size(root: &Path, write_baseline: bool) -> Result<()> {
    println!("building release workspace...");
    run("cargo", &["build", "--release", "--workspace"], root)?;

    let mut over_budget = Vec::new();
    let mut measured: BTreeMap<String, u64> = BTreeMap::new();
    let mut entries = serde_json::Map::new();
    let mut total: u64 = 0;
    for spec in BINARY_BUDGETS {
        let path = root.join("target/release").join(spec.name);
        let bytes = std::fs::metadata(&path)
            .with_context(|| format!("missing release binary {}", path.display()))?
            .len();
        total += bytes;
        let ok = bytes <= spec.budget;
        println!(
            "{}: {bytes} bytes (budget {}) [{}]",
            spec.name,
            spec.budget,
            if ok { "OK" } else { "OVER BUDGET" }
        );
        if !ok {
            over_budget.push(spec.name);
        }
        measured.insert(spec.name.to_string(), bytes);
        entries.insert(
            spec.name.to_string(),
            serde_json::json!({"bytes": bytes, "budget": spec.budget}),
        );
    }
    println!("total: {total} bytes");

    // Budgets are always enforced, even when (re)writing the baseline.
    if !over_budget.is_empty() {
        bail!("over budget: {}", over_budget.join(", "));
    }

    if write_baseline {
        let baseline = serde_json::json!({ "binaries": entries });
        let text =
            serde_json::to_string_pretty(&baseline).context("cannot serialise size baseline")?;
        std::fs::write(root.join("size-baseline.json"), text + "\n")
            .context("cannot write size-baseline.json")?;
        println!("wrote size-baseline.json");
        return Ok(());
    }

    let text = std::fs::read_to_string(root.join("size-baseline.json")).with_context(
        || "size-baseline.json is missing; run `cargo xtask size --write-baseline` to create it",
    )?;
    let baseline = parse_size_baseline(&text)?;
    check_size_drift(&measured, &baseline)?;
    println!("size: matches committed baseline, all budgets OK");
    Ok(())
}

// ---------------------------------------------------------------------------
// ci / qa / dist
// ---------------------------------------------------------------------------

fn cmd_ci(root: &Path) -> Result<()> {
    println!("==> fmt");
    run("cargo", &["fmt", "--all", "--", "--check"], root)?;
    println!("==> clippy");
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        root,
    )?;
    println!("==> test");
    run("cargo", &["test", "--workspace"], root)?;
    println!("==> assets --check");
    cmd_assets_check(root)?;
    println!("==> parity --check");
    cmd_parity(root, ParityMode::Check)?;
    println!("==> size");
    cmd_size(root, false)?;
    for tool in ["cargo-deny", "cargo-audit"] {
        if tool_present(tool) {
            println!("==> {tool}");
            let args: &[&str] = if tool == "cargo-deny" {
                &["deny", "check"]
            } else {
                &["audit"]
            };
            run("cargo", args, root)?;
        } else {
            println!("SKIP (not installed): {tool}");
        }
    }
    println!("ci: all gates passed");
    Ok(())
}

fn print_usage() {
    println!(
        "\
usage: cargo xtask <task> [options]

tasks:
  assets --check   validate assets/manifest.json against assets/resources/
  parity [--regenerate | --check]
                   validate data/parity.csv (--regenerate rewrites it in
                   place; --check proves a rewrite would change nothing)
  size [--write-baseline]
                   release-build, enforce budgets, compare against the
                   committed baseline (--write-baseline updates it instead)
  ci               fmt + clippy + test + assets + parity --check + size (+ deny/audit)
  qa               not implemented (S27)
  dist             not implemented (S26)"
    );
}

fn main() -> Result<()> {
    let root = repo_root();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        bail!("no task given");
    }
    let task = args.remove(0);
    match task.as_str() {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "--version" => {
            println!("xtask {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "assets" => {
            if args.iter().any(|a| a == "--check") {
                cmd_assets_check(&root)
            } else {
                bail!("usage: cargo xtask assets --check");
            }
        }
        "parity" => {
            let regenerate = args.iter().any(|a| a == "--regenerate");
            let check = args.iter().any(|a| a == "--check");
            if regenerate && check {
                bail!("parity: --regenerate and --check are mutually exclusive");
            }
            if let Some(unknown) = args
                .iter()
                .find(|a| *a != "--regenerate" && *a != "--check")
            {
                bail!(
                    "parity: unknown option `{unknown}` (usage: cargo xtask parity [--regenerate | --check])"
                );
            }
            cmd_parity(
                &root,
                if regenerate {
                    ParityMode::Regenerate
                } else if check {
                    ParityMode::Check
                } else {
                    ParityMode::Validate
                },
            )
        }
        "size" => {
            let write_baseline = args.iter().any(|a| a == "--write-baseline");
            if let Some(unknown) = args.iter().find(|a| *a != "--write-baseline") {
                bail!(
                    "size: unknown option `{unknown}` (usage: cargo xtask size [--write-baseline])"
                );
            }
            cmd_size(&root, write_baseline)
        }
        "ci" => cmd_ci(&root),
        "qa" => {
            println!("qa: not implemented (S27)");
            Ok(())
        }
        "dist" => {
            println!("dist: not implemented (S26)");
            Ok(())
        }
        other => bail!("unknown task `{other}` (see `cargo xtask --help`)"),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MANIFEST: &str = r#"{
        "meta": {"description": "test manifest"},
        "resources": []
    }"#;

    #[test]
    fn manifest_requires_86_entries() {
        // Too few entries must fail, even when `meta` is present.
        assert!(parse_manifest(SAMPLE_MANIFEST).is_err());
    }

    #[test]
    fn manifest_requires_meta_object() {
        let text = r#"{"meta": 42, "resources": []}"#;
        assert!(parse_manifest(text).is_err());
    }

    #[test]
    fn manifest_parses_single_entry() {
        let text = r#"{
            "meta": {"description": "x"},
            "resources": [
                {"id": "1", "type": "RT_ICON", "name": "n",
                 "file": "ICON_1.bin", "bytes": 3, "sha256": "abc",
                 "source": "s", "licence": "GPL-3.0-or-later"}
            ]
        }"#;
        // Parses fine; the count gate (86) rejects it.
        let manifest: Manifest = serde_json::from_str(text).unwrap();
        assert_eq!(manifest.resources.len(), 1);
        assert_eq!(manifest.resources[0].file, "ICON_1.bin");
        assert!(parse_manifest(text).is_err());
    }

    #[test]
    fn frozen_manifest_has_86_entries() {
        let text = std::fs::read_to_string(repo_root().join("assets/manifest.json")).unwrap();
        let manifest = parse_manifest(&text).unwrap();
        assert_eq!(manifest.resources.len(), 86);
        assert!(manifest.meta.is_object());
    }

    #[test]
    fn manifest_file_name_confinement() {
        let dir = Path::new("/nonexistent/resources");
        // Exactly one normal component is accepted.
        assert_eq!(
            manifest_file_path(dir, "ICON_1.bin").unwrap(),
            dir.join("ICON_1.bin")
        );
        // Everything else fails closed: traversal, absolute, nested,
        // current-dir, empty.
        for evil in [
            "../../escape/outside.bin",
            "../outside.bin",
            "/abs/path.bin",
            "sub/dir.bin",
            ".",
            "",
        ] {
            assert!(
                manifest_file_path(dir, evil).is_err(),
                "{evil:?} should be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn asset_symlink_fails_closed() {
        let dir = std::env::temp_dir().join(format!("furus-symlink-test-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.bin");
        std::fs::write(&target, b"payload").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link.bin")).unwrap();
        // Regular file passes, symlink fails.
        assert_eq!(asset_file_size(&target, "real.bin").unwrap(), 7);
        assert!(asset_file_size(&dir.join("link.bin"), "link.bin").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parity_parses_quoted_notes() {
        // Notes may contain commas inside quotes; they must stay one field.
        let text = "address,name,size,module,kind,disposition,slice,notes\n\
                    0x140001000,FUN_X,8,stdfn,internal,port,S02,\"helper, with comma\"\n";
        let rows = parse_parity_rows(text).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address, "0x140001000");
        assert_eq!(rows[0].disposition, "port");
        assert_eq!(rows[0].slice, "S02");
    }

    #[test]
    fn parity_check_detects_stale_output() {
        // Identical bytes are fresh; any difference fails.
        assert!(check_regeneration_fresh(b"a,b,c\n", b"a,b,c\n").is_ok());
        assert!(check_regeneration_fresh(b"a,b,c\n", b"a,b,X\n").is_err());
    }

    #[test]
    fn disposition_validation() {
        for valid in ["port", "c-ffi", "crate", "system-tool", "replace", "thunk"] {
            assert!(is_valid_disposition(valid), "{valid} should be valid");
        }
        for invalid in ["", "PORT", "rust", "vendor", "port "] {
            assert!(
                !is_valid_disposition(invalid),
                "{invalid} should be invalid"
            );
        }
    }

    #[test]
    fn slice_validation() {
        assert!(is_valid_slice("S00"));
        assert!(is_valid_slice("S17"));
        assert!(is_valid_slice("S27"));
        assert!(!is_valid_slice(""));
        assert!(!is_valid_slice("S28"));
        assert!(!is_valid_slice("S99"));
        assert!(!is_valid_slice("S1"));
        assert!(!is_valid_slice("17"));
    }

    #[test]
    fn size_drift_detection() {
        let measured: BTreeMap<String, u64> =
            [("rufus".to_string(), 100), ("rufus-helper".to_string(), 90)]
                .into_iter()
                .collect();
        let baseline: BTreeMap<String, BaselineEntry> = [
            (
                "rufus".to_string(),
                BaselineEntry {
                    bytes: 100,
                    budget: 3_000_000,
                },
            ),
            (
                "rufus-helper".to_string(),
                BaselineEntry {
                    bytes: 90,
                    budget: 2_500_000,
                },
            ),
            (
                "rufus-gui".to_string(),
                BaselineEntry {
                    bytes: 80,
                    budget: 12_000_000,
                },
            ),
        ]
        .into_iter()
        .collect();
        // Exact match passes; any byte difference fails.
        let mut drifted = measured.clone();
        drifted.insert("rufus".to_string(), 101);
        // check_size_drift iterates BINARY_BUDGETS, so give it a full map.
        let mut full = drifted.clone();
        full.insert("rufus-gui".to_string(), 80);
        assert!(check_size_drift(&full, &baseline).is_err());
        let mut exact = measured.clone();
        exact.insert("rufus-gui".to_string(), 80);
        assert!(check_size_drift(&exact, &baseline).is_ok());
        // Missing baseline entry fails.
        let mut missing = baseline.clone();
        missing.remove("rufus-gui");
        assert!(check_size_drift(&exact, &missing).is_err());
    }
}
