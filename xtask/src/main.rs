//! `xtask`: repo maintenance tasks for the furus workspace (S01).
//!
//! No feature code lives here; only checks and reports:
//!
//! * `assets --check` — validate `assets/manifest.json` against files on disk
//! * `parity`          — validate `data/parity.csv` against `data/functions.csv`
//! * `parity --check`  — additionally prove `data/parity.csv` is freshly
//!   regenerated (CI gate; never dirties the tree)
//! * `size`            — release-build, enforce budgets, check growth
//!   against the committed baseline within allowance (never writes it)
//! * `size --write-baseline` — update the committed baseline (humans only)
//! * `ci`              — run every gate in order (fmt, clippy, test, ...)
//! * `dist`            — release-build, validate packaging/, emit a
//!   deterministic bundle (tar.gz + SHA256SUMS; .deb when dpkg-deb is
//!   available)
//! * `qa`              — end-to-end release gate. Tier 1 always runs,
//!   unprivileged, over sparse file targets: it orchestrates the existing
//!   formatter / partition / pipeline / BCD / SYSTEM-hive test suites.
//!   Tier 2 boots BIOS and UEFI images headlessly when QEMU + firmware are
//!   installed, with a hard per-invocation timeout and kill/reap on every
//!   path. `--require-qemu` makes a missing Tier 2 toolchain fatal;
//!   `--privileged` additionally enables loop-device suites (off by default).
//!
//! The xtask must work when invoked from the repo root
//! (`cargo xtask ...`); all paths are anchored at the workspace root derived
//! from `CARGO_MANIFEST_DIR`, never at the current directory.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
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
use flate2::Compression;
use flate2::GzBuilder;
use flate2::read::GzDecoder;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::Deserialize;
use sha2::Digest;
use tar::Archive;
use tar::Builder;
use tar::EntryType;
use tar::Header;

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
        name: "furus",
        budget: 3_000_000,
    },
    BinaryBudget {
        name: "furus-helper",
        budget: 2_500_000,
    },
    BinaryBudget {
        name: "furus-gui",
        budget: 14_000_000,
    },
];

/// How many bytes a measured binary may exceed its committed baseline
/// before the gate calls it drift. Rust binaries are not byte-identical
/// across systems: the same rustc 1.99.0 produced +80 bytes (`furus`),
/// +264 bytes (`furus-helper`) and +32 bytes (`furus-gui`) on the
/// ubuntu-latest runner versus the recording host (CI run 41327026453,
/// total +376). The allowance is far larger than that measured noise and
/// far smaller than any real regression (a new crate or feature adds tens
/// of kilobytes).
const SIZE_DRIFT_ALLOWANCE: u64 = 4096;

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

/// Fail when a measured binary grows beyond its baseline plus the
/// committed allowance, or when the baseline entry is missing or carries
/// a different budget (stale). Shrinkage and growth within the allowance
/// pass: the same compiler emits slightly different bytes on different
/// system linkers, so byte-exact equality cannot hold off the recording
/// host.
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
        if bytes > entry.bytes + SIZE_DRIFT_ALLOWANCE {
            bail!(
                "size drift for `{}`: baseline {} bytes, measured {} bytes (growth {} bytes exceeds allowance {} bytes); run `cargo xtask size --write-baseline` to update the baseline",
                spec.name,
                entry.bytes,
                bytes,
                bytes.saturating_sub(entry.bytes),
                SIZE_DRIFT_ALLOWANCE
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
    println!("size: within committed baseline allowance, all budgets OK");
    Ok(())
}

// ---------------------------------------------------------------------------
// dist
// ---------------------------------------------------------------------------

/// The 11 files finalized in S26-T2. Every one must exist and validate before
/// dist stages anything; the list is also the exact set held in `Packaging`.
const PACKAGING_FILES: &[&str] = &[
    "dbus/org.furuslinux.Helper1.service",
    "dbus/org.furuslinux.Helper1.conf",
    "polkit/org.furuslinux.policy",
    "org.furuslinux.Furus.desktop",
    "org.furuslinux.Furus.metainfo.xml",
    "org.furuslinux.Furus.svg",
    "deb/control",
    "deb/postinst",
    "arch/PKGBUILD",
    "rpm/furus.spec",
    "README.md",
];

// Naming invariant: these identifiers are hardcoded in the shipped GUI and
// helper (bus name, polkit action, desktop id). Never rewrite them to the
// spec's literal `org.furus.*` form; see packaging/README.md.
const BUS_NAME: &str = "org.furuslinux.Helper1";
const POLKIT_ACTION: &str = "org.furuslinux.write-device";
const DESKTOP_ID: &str = "org.furuslinux.Furus.desktop";

/// Validated packaging texts, keyed by path relative to `packaging/`.
#[derive(Debug)]
struct Packaging {
    texts: BTreeMap<String, String>,
}

impl Packaging {
    fn get(&self, rel: &str) -> Result<&str> {
        packaged(&self.texts, rel)
    }
}

fn packaged<'a>(texts: &'a BTreeMap<String, String>, rel: &str) -> Result<&'a str> {
    texts
        .get(rel)
        .map(String::as_str)
        .with_context(|| format!("validated packaging has no `{rel}`"))
}

/// Small element tree built from quick-xml events. It is intentionally not a
/// general XML model: it only needs attributes, direct text and children to
/// assert the semantics the packaging files promise.
#[derive(Debug, Default)]
struct XmlNode {
    name: String,
    attrs: BTreeMap<String, String>,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn child<'a>(&'a self, name: &'a str) -> Option<&'a XmlNode> {
        self.children_named(name).next()
    }

    fn text_trimmed(&self) -> &str {
        self.text.trim()
    }
}

fn xml_node_from(e: quick_xml::events::BytesStart<'_>, label: &str) -> Result<XmlNode> {
    let name = std::str::from_utf8(e.name().0)
        .with_context(|| format!("{label}: non-UTF-8 element name"))?
        .to_string();
    let mut node = XmlNode {
        name,
        ..XmlNode::default()
    };
    for attr in e.attributes() {
        let attr =
            attr.with_context(|| format!("{label}: malformed attribute in <{}>", node.name))?;
        let key = std::str::from_utf8(attr.key.0)
            .with_context(|| format!("{label}: non-UTF-8 attribute name"))?
            .to_string();
        let value = String::from_utf8_lossy(&attr.value).into_owned();
        node.attrs.insert(key, value);
    }
    Ok(node)
}

/// Parse a whole XML document, failing on malformed input, mismatched tags or
/// unclosed elements. quick-xml does the tokenisation; this adds structure.
fn xml_tree(text: &str, label: &str) -> Result<XmlNode> {
    let mut reader = Reader::from_str(text);
    let mut root = XmlNode {
        name: "#document".to_string(),
        ..XmlNode::default()
    };
    let mut stack: Vec<XmlNode> = Vec::new();
    loop {
        let event = reader
            .read_event()
            .with_context(|| format!("{label}: malformed XML"))?;
        match event {
            Event::Start(e) => {
                let node = xml_node_from(e, label)?;
                stack.push(node);
            }
            Event::Empty(e) => {
                let node = xml_node_from(e, label)?;
                let parent = stack.last_mut().unwrap_or(&mut root);
                parent.children.push(node);
            }
            Event::End(e) => {
                let name = std::str::from_utf8(e.name().0).unwrap_or("");
                let open = stack
                    .pop()
                    .with_context(|| format!("{label}: unexpected </{name}>"))?;
                if open.name != name {
                    bail!(
                        "{label}: mismatched tags: <{}> closed by </{name}>",
                        open.name
                    );
                }
                let parent = stack.last_mut().unwrap_or(&mut root);
                parent.children.push(open);
            }
            Event::Text(t) => {
                let frag = String::from_utf8_lossy(&t);
                let parent = stack.last_mut().unwrap_or(&mut root);
                parent.text.push_str(&frag);
            }
            Event::CData(t) => {
                let frag = String::from_utf8_lossy(&t);
                let parent = stack.last_mut().unwrap_or(&mut root);
                parent.text.push_str(&frag);
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::DocType(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => {}
        }
    }
    if let Some(open) = stack.last() {
        bail!("{label}: unclosed element <{}>", open.name);
    }
    Ok(root)
}

fn attr_is(node: &XmlNode, key: &str, expected: &str) -> bool {
    node.attrs.get(key).map(String::as_str) == Some(expected)
}

fn validate_polkit(text: &str) -> Result<()> {
    let doc = xml_tree(text, "polkit policy")?;
    let config = doc
        .child("policyconfig")
        .context("polkit policy: missing <policyconfig>")?;
    let action = config
        .children_named("action")
        .find(|a| attr_is(a, "id", POLKIT_ACTION))
        .with_context(|| format!("polkit policy: missing action id `{POLKIT_ACTION}`"))?;
    let defaults = action
        .child("defaults")
        .context("polkit policy: action has no <defaults>")?;
    for (tag, expected) in [
        ("allow_any", "no"),
        ("allow_inactive", "no"),
        ("allow_active", "auth_admin_keep"),
    ] {
        let actual = defaults
            .child(tag)
            .with_context(|| format!("polkit policy: <defaults> has no <{tag}>"))?
            .text_trimmed();
        if actual != expected {
            bail!("polkit policy: <{tag}> is `{actual}`, expected `{expected}`");
        }
    }
    Ok(())
}

fn validate_bus_conf(text: &str) -> Result<()> {
    let doc = xml_tree(text, "D-Bus system.d config")?;
    let config = doc
        .child("busconfig")
        .context("D-Bus system.d config: missing <busconfig>")?;
    let root_owns = config
        .children_named("policy")
        .filter(|p| attr_is(p, "user", "root"))
        .any(|p| {
            p.children_named("allow")
                .any(|a| attr_is(a, "own", BUS_NAME))
        });
    if !root_owns {
        bail!(
            "D-Bus system.d config: missing <policy user=\"root\"> with <allow own=\"{BUS_NAME}\"/>"
        );
    }
    let default_policy = config
        .children_named("policy")
        .filter(|p| attr_is(p, "context", "default"))
        .any(|p| {
            p.children_named("deny")
                .any(|d| attr_is(d, "own", BUS_NAME))
                && p.children_named("allow")
                    .any(|a| attr_is(a, "send_destination", BUS_NAME))
        });
    if !default_policy {
        bail!(
            "D-Bus system.d config: default policy must deny `own` and allow `send_destination` for {BUS_NAME}"
        );
    }
    Ok(())
}

fn validate_metainfo(text: &str) -> Result<()> {
    let doc = xml_tree(text, "AppStream metainfo")?;
    let comp = doc
        .child("component")
        .context("AppStream metainfo: missing <component>")?;
    let id = comp
        .child("id")
        .context("AppStream metainfo: missing <id>")?
        .text_trimmed();
    if id != DESKTOP_ID {
        bail!("AppStream metainfo: <id> is `{id}`, expected `{DESKTOP_ID}`");
    }
    let launchable = comp
        .child("launchable")
        .context("AppStream metainfo: missing <launchable>")?;
    if !attr_is(launchable, "type", "desktop-id") || launchable.text_trimmed() != id {
        bail!("AppStream metainfo: <launchable> must be a desktop-id for `{id}`");
    }
    let licence = comp
        .child("project_license")
        .context("AppStream metainfo: missing <project_license>")?
        .text_trimmed();
    if licence != "GPL-3.0-or-later" {
        bail!("AppStream metainfo: <project_license> is `{licence}`, expected `GPL-3.0-or-later`");
    }
    Ok(())
}

/// Hand-written INI reader for the two INI-shaped packaging files. It accepts
/// blank lines and `#`/`;` comments, `[section]` headers and `key=value`
/// lines, and fails closed on duplicates, malformed lines and stray keys.
fn parse_ini(text: &str) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                bail!("INI line {line_no}: malformed section header `{line}`");
            }
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() {
                bail!("INI line {line_no}: empty section name");
            }
            if sections.insert(name.to_string(), BTreeMap::new()).is_some() {
                bail!("INI line {line_no}: duplicate section `[{name}]`");
            }
            current = Some(name.to_string());
            continue;
        }
        let section = current.as_deref().with_context(|| {
            format!("INI line {line_no}: key=value outside a section: `{line}`")
        })?;
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("INI line {line_no}: expected key=value, got `{line}`"))?;
        let key = key.trim();
        if key.is_empty() {
            bail!("INI line {line_no}: empty key");
        }
        let entry = sections
            .get_mut(section)
            .with_context(|| format!("INI line {line_no}: missing section `[{section}]`"))?;
        if entry
            .insert(key.to_string(), value.trim().to_string())
            .is_some()
        {
            bail!("INI line {line_no}: duplicate key `{key}` in `[{section}]`");
        }
    }
    Ok(sections)
}

fn validate_service(text: &str) -> Result<()> {
    let ini = parse_ini(text).context("D-Bus service: invalid INI")?;
    let service = ini
        .get("D-Bus Service")
        .context("D-Bus service: missing [D-Bus Service]")?;
    for (key, expected) in [
        ("Name", BUS_NAME),
        ("Exec", "/usr/libexec/furus-helper --dbus"),
        ("User", "root"),
    ] {
        let actual = service
            .get(key)
            .with_context(|| format!("D-Bus service: missing `{key}`"))?;
        if actual != expected {
            bail!("D-Bus service: {key}=`{actual}`, expected `{expected}`");
        }
    }
    Ok(())
}

fn validate_desktop(text: &str) -> Result<()> {
    let ini = parse_ini(text).context("desktop entry: invalid INI")?;
    let entry = ini
        .get("Desktop Entry")
        .context("desktop entry: missing [Desktop Entry]")?;
    for (key, expected) in [
        ("Type", "Application"),
        ("Exec", "furus-gui"),
        ("Terminal", "false"),
    ] {
        let actual = entry
            .get(key)
            .with_context(|| format!("desktop entry: missing `{key}`"))?;
        if actual != expected {
            bail!("desktop entry: {key}=`{actual}`, expected `{expected}`");
        }
    }
    for key in ["Name", "Icon", "Categories"] {
        let value = entry
            .get(key)
            .with_context(|| format!("desktop entry: missing `{key}`"))?;
        if value.is_empty() {
            bail!("desktop entry: `{key}` is empty");
        }
    }
    Ok(())
}

fn require_tokens(text: &str, label: &str, tokens: &[&str]) -> Result<()> {
    for token in tokens {
        if !text.contains(token) {
            bail!("{label}: missing required `{token}`");
        }
    }
    Ok(())
}

fn validate_deb_control(text: &str) -> Result<()> {
    if !text.lines().any(|l| l == "Architecture: any") {
        bail!("deb control: missing literal `Architecture: any` line");
    }
    let recommends = text
        .lines()
        .find(|l| l.starts_with("Recommends:"))
        .context("deb control: missing `Recommends:` line")?;
    require_tokens(
        recommends,
        "deb control Recommends",
        &["ntfs-3g", "e2fsprogs", "udftools", "libwim15"],
    )
}

fn validate_arch_pkgbuild(text: &str) -> Result<()> {
    let mut block = String::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !inside {
            if trimmed.starts_with("optdepends=(") {
                inside = true;
                block.push_str(trimmed);
                if trimmed.contains(')') {
                    break;
                }
            }
        } else {
            block.push('\n');
            block.push_str(trimmed);
            if trimmed.starts_with(')') {
                break;
            }
        }
    }
    if !inside {
        bail!("Arch PKGBUILD: missing `optdepends=(...)` block");
    }
    require_tokens(
        &block,
        "Arch PKGBUILD optdepends",
        &[
            "'ntfs-3g'",
            "'ntfsprogs'",
            "'e2fsprogs'",
            "'udftools'",
            "'wimlib'",
        ],
    )
}

fn validate_rpm_spec(text: &str) -> Result<()> {
    let recommends = text
        .lines()
        .find(|l| l.starts_with("Recommends:"))
        .context("rpm spec: missing `Recommends:` line")?;
    require_tokens(
        recommends,
        "rpm spec Recommends",
        // Fedora uses `wimlib`; `libwim15` is the Debian name kept only in the
        // deb control validator above.
        &["ntfs-3g", "e2fsprogs", "udftools", "wimlib"],
    )
}

/// Read and validate every finalized packaging file before staging. Returns
/// their texts so staging never has to re-read or re-interpret them.
fn validate_packaging(packaging_root: &Path) -> Result<Packaging> {
    let mut texts = BTreeMap::new();
    for rel in PACKAGING_FILES {
        let path = packaging_root.join(rel);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("missing packaging file {}", path.display()))?;
        texts.insert((*rel).to_string(), text);
    }
    validate_service(packaged(&texts, "dbus/org.furuslinux.Helper1.service")?)?;
    validate_bus_conf(packaged(&texts, "dbus/org.furuslinux.Helper1.conf")?)?;
    validate_polkit(packaged(&texts, "polkit/org.furuslinux.policy")?)?;
    validate_desktop(packaged(&texts, "org.furuslinux.Furus.desktop")?)?;
    validate_metainfo(packaged(&texts, "org.furuslinux.Furus.metainfo.xml")?)?;
    validate_deb_control(packaged(&texts, "deb/control")?)?;
    validate_rpm_spec(packaged(&texts, "rpm/furus.spec")?)?;
    validate_arch_pkgbuild(packaged(&texts, "arch/PKGBUILD")?)?;
    println!("dist: validated {} packaging files", PACKAGING_FILES.len());
    Ok(Packaging { texts })
}

/// Debian `Architecture:` value for a target triple prefix.
fn debian_arch(triple: &str) -> Result<&'static str> {
    if triple.starts_with("x86_64") {
        Ok("amd64")
    } else if triple.starts_with("aarch64") || triple.starts_with("arm64") {
        Ok("arm64")
    } else {
        bail!(
            "dist: unsupported target triple `{triple}` for Debian architecture mapping \
             (expected x86_64-* or aarch64-*)"
        )
    }
}

/// Host triple as reported by `rustc -vV` (the `host:` line).
fn host_triple(root: &Path) -> Result<String> {
    let out = run_quiet("rustc", &["-vV"], root)?;
    out.lines()
        .find_map(|line| line.strip_prefix("host:").map(str::trim))
        .map(str::to_string)
        .context("rustc -vV produced no `host:` line")
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot set mode {mode:o} on {}", path.display()))
}

fn stage_bytes(staging: &Path, rel: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let dst = staging.join(rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::write(&dst, bytes).with_context(|| format!("cannot write {}", dst.display()))?;
    set_mode(&dst, mode)
}

fn stage_copy(src: &Path, staging: &Path, rel: &str, mode: u32) -> Result<()> {
    let dst = staging.join(rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::copy(src, &dst)
        .with_context(|| format!("cannot copy {} to {}", src.display(), dst.display()))?;
    set_mode(&dst, mode)
}

/// Build a clean staging tree with the exact install layout and modes.
fn stage_tree(
    root: &Path,
    arch: &str,
    bin_dir: &Path,
    packaging: &Packaging,
    staging: &Path,
) -> Result<()> {
    if staging.exists() {
        std::fs::remove_dir_all(staging)
            .with_context(|| format!("cannot clear {}", staging.display()))?;
    }
    std::fs::create_dir_all(staging)
        .with_context(|| format!("cannot create {}", staging.display()))?;

    stage_copy(&bin_dir.join("furus"), staging, "usr/bin/furus", 0o755)?;
    stage_copy(
        &bin_dir.join("furus-gui"),
        staging,
        "usr/bin/furus-gui",
        0o755,
    )?;
    stage_copy(
        &bin_dir.join("furus-helper"),
        staging,
        "usr/libexec/furus-helper",
        0o755,
    )?;

    for (src, dst) in [
        (
            "polkit/org.furuslinux.policy",
            "usr/share/polkit-1/actions/org.furuslinux.policy",
        ),
        (
            "dbus/org.furuslinux.Helper1.service",
            "usr/share/dbus-1/system-services/org.furuslinux.Helper1.service",
        ),
        (
            "dbus/org.furuslinux.Helper1.conf",
            "usr/share/dbus-1/system.d/org.furuslinux.Helper1.conf",
        ),
        (
            "org.furuslinux.Furus.desktop",
            "usr/share/applications/org.furuslinux.Furus.desktop",
        ),
        (
            "org.furuslinux.Furus.metainfo.xml",
            "usr/share/metainfo/org.furuslinux.Furus.metainfo.xml",
        ),
        (
            "org.furuslinux.Furus.svg",
            "usr/share/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg",
        ),
    ] {
        stage_bytes(staging, dst, packaging.get(src)?.as_bytes(), 0o644)?;
    }

    let licenses = std::fs::read(root.join("LICENSES.md"))
        .context("cannot read LICENSES.md from the repo root")?;
    stage_bytes(staging, "usr/share/doc/furus/LICENSES.md", &licenses, 0o644)?;

    // `Architecture: any` is literal in the source; rewrite exactly that one
    // line for the concrete target (validated by validate_deb_control).
    let control = packaging.get("deb/control")?;
    let marker = "Architecture: any";
    let occurrences = control.matches(marker).count();
    if occurrences != 1 {
        bail!("deb/control: expected exactly one `{marker}` line, found {occurrences}");
    }
    let control = control.replace(marker, &format!("Architecture: {arch}"));
    stage_bytes(staging, "DEBIAN/control", control.as_bytes(), 0o644)?;
    stage_bytes(
        staging,
        "DEBIAN/postinst",
        packaging.get("deb/postinst")?.as_bytes(),
        0o755,
    )?;

    println!("dist: staged bundle into {}", staging.display());
    Ok(())
}

/// Staged file relative path -> (unix mode, on-disk path).
type StagedFiles = BTreeMap<String, (u32, PathBuf)>;

/// All staged directories and files, sorted by their path relative to the
/// staging root. Non-regular entries fail closed so nothing unexpected leaks
/// into the archive.
fn collect_staged(staging: &Path) -> Result<(BTreeSet<String>, StagedFiles)> {
    fn walk(
        base: &Path,
        dir: &Path,
        dirs: &mut BTreeSet<String>,
        files: &mut StagedFiles,
    ) -> Result<()> {
        let entries =
            std::fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("cannot read entry in {}", dir.display()))?;
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .with_context(|| format!("{} is outside staging", path.display()))?
                .to_string_lossy()
                .into_owned();
            let kind = entry
                .file_type()
                .with_context(|| format!("cannot stat {}", path.display()))?;
            if kind.is_dir() {
                dirs.insert(rel);
                walk(base, &path, dirs, files)?;
            } else if kind.is_file() {
                let mode = entry
                    .metadata()
                    .with_context(|| format!("cannot stat {}", path.display()))?
                    .permissions()
                    .mode()
                    & 0o7777;
                files.insert(rel, (mode, path));
            } else {
                bail!(
                    "dist: unexpected non-regular staged entry {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let mut dirs = BTreeSet::new();
    let mut files = BTreeMap::new();
    walk(staging, staging, &mut dirs, &mut files)?;
    Ok((dirs, files))
}

/// Write the whole deterministic .tar.gz to `w`. Exposed so tests can build
/// the archive twice into two files and compare the bytes. Every header has
/// mtime=0, uid=0, gid=0 and empty uname/gname; paths are emitted in sorted
/// order with directories before files.
fn write_dist_archive<W: Write>(staging: &Path, w: W) -> Result<()> {
    let encoder = GzBuilder::new().mtime(0).write(w, Compression::best());
    let mut ar = Builder::new(encoder);
    let (dirs, files) = collect_staged(staging)?;

    for rel in dirs {
        let path = format!("{rel}/");
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header
            .set_path(&path)
            .with_context(|| format!("dist: cannot encode directory path `{path}`"))?;
        header.set_size(0);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        ar.append(&header, std::io::empty())
            .with_context(|| format!("dist: cannot write directory entry `{path}`"))?;
    }

    for (rel, (mode, path)) in files {
        let mut header = Header::new_gnu();
        header
            .set_path(&rel)
            .with_context(|| format!("dist: cannot encode file path `{rel}`"))?;
        header.set_size(
            std::fs::metadata(&path)
                .with_context(|| format!("cannot stat {}", path.display()))?
                .len(),
        );
        header.set_mode(mode);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        let data = std::fs::File::open(&path)
            .with_context(|| format!("cannot open {}", path.display()))?;
        ar.append(&header, data)
            .with_context(|| format!("dist: cannot write file entry `{rel}`"))?;
    }

    ar.finish().context("dist: cannot finish tar archive")?;
    let encoder = ar.into_inner().context("dist: cannot release tar writer")?;
    encoder
        .finish()
        .context("dist: cannot finish gzip stream")?;
    Ok(())
}

/// Read the produced archive back and check it matches the staged tree.
fn verify_archive(archive: &Path, staging: &Path) -> Result<()> {
    let (dirs, files) = collect_staged(staging)?;
    let mut expected: BTreeSet<String> = dirs.into_iter().map(|d| format!("{d}/")).collect();
    expected.extend(files.into_keys());

    let file = std::fs::File::open(archive)
        .with_context(|| format!("cannot open {}", archive.display()))?;
    let mut ar = Archive::new(GzDecoder::new(file));
    let mut seen = BTreeSet::new();
    for entry in ar
        .entries()
        .context("dist: cannot read back the generated archive")?
    {
        let entry = entry.context("dist: corrupt archive entry")?;
        let header = entry.header();
        let name = header
            .path()
            .context("dist: archive entry has an invalid path")?
            .to_string_lossy()
            .into_owned();
        if header.mtime().context("dist: bad entry mtime")? != 0 {
            bail!("dist: archive entry `{name}` has a non-zero mtime");
        }
        if header.uid().context("dist: bad entry uid")? != 0
            || header.gid().context("dist: bad entry gid")? != 0
        {
            bail!("dist: archive entry `{name}` has a non-zero uid/gid");
        }
        if !seen.insert(name.clone()) {
            bail!("dist: duplicate archive entry `{name}`");
        }
    }
    if seen != expected {
        let missing: Vec<_> = expected.difference(&seen).collect();
        let extra: Vec<_> = seen.difference(&expected).collect();
        bail!("dist: archive entries differ from staging (missing: {missing:?}, extra: {extra:?})");
    }
    Ok(())
}

/// Write one `<sha256>  <name>` line per artifact into `<out_dir>/SHA256SUMS`,
/// in the order given. Factored out of `cmd_dist` so the exact format the CLI
/// emits can be exercised directly by tests without a release build.
fn write_sha256sums(out_dir: &Path, artifacts: &[String]) -> Result<()> {
    let mut sums = String::new();
    for name in artifacts {
        let digest = sha256_of(&out_dir.join(name))?;
        sums.push_str(&format!("{digest}  {name}\n"));
    }
    let path = out_dir.join("SHA256SUMS");
    std::fs::write(&path, sums).with_context(|| format!("cannot write {}", path.display()))
}

/// Full distribution pipeline: build + size gates, packaging validation,
/// staging, deterministic tarball, conditional .deb and SHA256SUMS.
fn cmd_dist(target: Option<String>, out_dir: Option<PathBuf>) -> Result<()> {
    let root = repo_root();
    let host = host_triple(&root)?;
    let triple = target.clone().unwrap_or_else(|| host.clone());
    // Fail fast on a triple we cannot map to a Debian architecture, before
    // spending time on a release build.
    let arch = debian_arch(&triple)?;
    // An explicit `--target` always makes Cargo use `target/<triple>/release`,
    // even when it is the host triple; without it the host build lands in
    // `target/release`.
    let bin_dir = if target.is_some() {
        root.join("target").join(&triple).join("release")
    } else {
        root.join("target/release")
    };
    let out = match out_dir {
        Some(dir) => root.join(dir),
        None => root.join("target/dist").join(&triple),
    };

    // 1. Build the release workspace and enforce the committed size budgets.
    println!("dist: building release workspace for {triple}...");
    let mut build_args: Vec<&str> = vec!["build", "--release", "--workspace"];
    if target.is_some() {
        build_args.extend_from_slice(&["--target", &triple]);
    }
    run("cargo", &build_args, &root)?;
    for spec in BINARY_BUDGETS {
        let path = bin_dir.join(spec.name);
        let bytes = std::fs::metadata(&path)
            .with_context(|| format!("missing release binary {}", path.display()))?
            .len();
        println!(
            "dist: {}: {bytes} bytes (budget {}) [{}]",
            spec.name,
            spec.budget,
            if bytes <= spec.budget {
                "OK"
            } else {
                "OVER BUDGET"
            }
        );
        if bytes > spec.budget {
            bail!(
                "dist: `{}` is over budget: {bytes} bytes > {}",
                spec.name,
                spec.budget
            );
        }
    }

    // 2. Validate every finalized packaging file before it is staged.
    let packaging = validate_packaging(&root.join("packaging"))?;

    // 3. Clean staging tree with the exact install layout and modes.
    let staging = root.join("target/dist-staging").join(&triple);
    stage_tree(&root, arch, &bin_dir, &packaging, &staging)?;

    // 4. Deterministic archive, verified by reading it back.
    std::fs::create_dir_all(&out).with_context(|| format!("cannot create {}", out.display()))?;
    let stem = format!("furus-{}-{triple}", env!("CARGO_PKG_VERSION"));
    let tgz_name = format!("{stem}.tar.gz");
    let tgz_path = out.join(&tgz_name);
    let file = std::fs::File::create(&tgz_path)
        .with_context(|| format!("cannot create {}", tgz_path.display()))?;
    write_dist_archive(&staging, file)?;
    verify_archive(&tgz_path, &staging)?;
    println!("dist: wrote {}", tgz_path.display());

    // 5. A .deb only where dpkg-deb exists; this environment has no dpkg-deb,
    //    so the tar.gz + SHA256SUMS are still a successful build here.
    let mut artifacts = vec![tgz_name];
    if tool_present("dpkg-deb") {
        let deb_name = format!("{stem}.deb");
        let deb_path = out.join(&deb_name);
        let staging_s = staging
            .to_str()
            .context("dist: staging path is not valid UTF-8")?;
        let deb_s = deb_path
            .to_str()
            .context("dist: .deb path is not valid UTF-8")?;
        run(
            "dpkg-deb",
            &["--root-owner-group", "--build", staging_s, deb_s],
            &root,
        )?;
        println!("dist: wrote {}", deb_path.display());
        artifacts.push(deb_name);
    } else {
        println!("skip .deb: dpkg-deb not available");
    }

    // 6. One digest line per produced artifact, in a stable order.
    write_sha256sums(&out, &artifacts)?;

    println!("dist: target={triple} out_dir={}", out.display());
    println!("dist: artifacts: {}", artifacts.join(", "));
    Ok(())
}

// ---------------------------------------------------------------------------
// ci / qa
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// contract — GUI / helper / packaging identifier single-source check
// ---------------------------------------------------------------------------

/// Read the value of a `pub const NAME: &str = "...";` declaration from the
/// single source of truth (`crates/furus-proto/src/service.rs`). The file is
/// ours, so a missing or unterminated declaration is a hard failure with a
/// file-specific message. Simple string scanning; no new dependency.
fn contract_const<'a>(source: &'a str, name: &str, path: &Path) -> Result<&'a str> {
    let marker = format!("pub const {name}: &str = \"");
    let at = source
        .find(&marker)
        .with_context(|| format!("{}: missing `pub const {name}: &str`", path.display()))?;
    let rest = &source[at + marker.len()..];
    let end = rest
        .find('"')
        .with_context(|| format!("{}: unterminated value for `{name}`", path.display()))?;
    Ok(&rest[..end])
}

/// 1-based line number of the first line containing `needle`, if any. Used
/// only to make failures point at a file *and line*.
fn contract_line(text: &str, needle: &str) -> Option<usize> {
    text.lines()
        .position(|line| line.contains(needle))
        .map(|n| n + 1)
}

/// Require an INI-style `key=value` line (used by the `.service` file).
fn contract_require_kv(path: &Path, text: &str, key: &str, expected: &str) -> Result<()> {
    let wanted = format!("{key}={expected}");
    if text.lines().any(|line| line.trim() == wanted) {
        return Ok(());
    }
    match contract_line(text, &format!("{key}=")) {
        Some(line) => bail!(
            "{}:{line}: `{key}=` must be `{expected}`, not what is on this line",
            path.display()
        ),
        None => bail!("{}: missing `{wanted}`", path.display()),
    }
}

/// Require an XML attribute value such as `allow own="..."`. The `tag`
/// argument is the exact `name="` prefix (e.g. `allow own="`).
fn contract_require_attr(path: &Path, text: &str, tag: &str, expected: &str) -> Result<()> {
    let wanted = format!("{tag}{expected}\"");
    if text.contains(&wanted) {
        return Ok(());
    }
    // `tag` already ends in `="`; drop it to locate the declaring line.
    let bare = tag.trim_end_matches("=\"");
    match contract_line(text, bare) {
        Some(line) => bail!(
            "{}:{line}: `{bare}` must have value `{expected}`",
            path.display()
        ),
        None => bail!("{}: missing `{wanted}`", path.display()),
    }
}

/// Recursively collect the regular files under `dir` (no symlink following).
fn contract_collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot read an entry in {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            contract_collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Verify the D-Bus / polkit / helper-path identifiers used by the GUI, the
/// helper and the packaging files are the single values declared in
/// `crates/furus-proto/src/service.rs`. Reads and scans files only — no build,
/// no bus, no root, no new dependencies.
fn cmd_contract(root: &Path) -> Result<()> {
    let service_rel = "crates/furus-proto/src/service.rs";
    let service_path = root.join(service_rel);
    let service_src = std::fs::read_to_string(&service_path)
        .with_context(|| format!("cannot read {}", service_path.display()))?;
    let bus_name = contract_const(&service_src, "BUS_NAME", &service_path)?;
    let interface_name = contract_const(&service_src, "INTERFACE_NAME", &service_path)?;
    let polkit_action = contract_const(&service_src, "POLKIT_ACTION", &service_path)?;
    let helper_bin = contract_const(&service_src, "HELPER_BIN_PATH", &service_path)?;
    let helper_arg = contract_const(&service_src, "HELPER_DBUS_ARG", &service_path)?;
    let expected_exec = format!("{helper_bin} {helper_arg}");
    println!("PASS {service_rel} (single source of truth read)");

    // 1. + 2. packaging/dbus/*.service (Name=, Exec=) and *.conf
    //         (allow own, deny own, allow send_destination).
    let dbus_root = root.join("packaging/dbus");
    let mut service_files = 0usize;
    let mut conf_files = 0usize;
    for entry in std::fs::read_dir(&dbus_root)
        .with_context(|| format!("cannot list {}", dbus_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("cannot read an entry in {}", dbus_root.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if name.ends_with(".service") {
            service_files += 1;
            contract_require_kv(&path, &text, "Name", bus_name)?;
            contract_require_kv(&path, &text, "Exec", &expected_exec)?;
            println!("PASS {name} (Name/Exec match the shared contract)");
        } else if name.ends_with(".conf") {
            conf_files += 1;
            for tag in ["allow own=\"", "deny own=\"", "allow send_destination=\""] {
                contract_require_attr(&path, &text, tag, bus_name)?;
            }
            println!("PASS {name} (own/send_destination match the shared contract)");
        }
    }
    if service_files == 0 {
        bail!(
            "{}: no `*.service` file found to check",
            dbus_root.display()
        );
    }
    if conf_files == 0 {
        bail!("{}: no `*.conf` file found to check", dbus_root.display());
    }

    // 3. packaging/polkit/*.policy: the <action id="..."> value.
    let polkit_root = root.join("packaging/polkit");
    let mut policy_files = 0usize;
    for entry in std::fs::read_dir(&polkit_root)
        .with_context(|| format!("cannot list {}", polkit_root.display()))?
    {
        let entry =
            entry.with_context(|| format!("cannot read an entry in {}", polkit_root.display()))?;
        let path = entry.path();
        if !path.is_file() || !path.to_string_lossy().ends_with(".policy") {
            continue;
        }
        policy_files += 1;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        contract_require_attr(&path, &text, "<action id=\"", polkit_action)?;
        println!(
            "PASS {} (polkit action id matches the shared contract)",
            entry.file_name().to_string_lossy()
        );
    }
    if policy_files == 0 {
        bail!(
            "{}: no `*.policy` file found to check",
            polkit_root.display()
        );
    }

    // 4. crates/furus-helper/src/dbus.rs: the `#[zbus::interface(name = "...")]`
    //    literal the macro needs. It cannot be a constant, so the source is
    //    read and compared to INTERFACE_NAME here.
    let helper_dbus_rel = "crates/furus-helper/src/dbus.rs";
    let helper_dbus_path = root.join(helper_dbus_rel);
    let helper_dbus_src = std::fs::read_to_string(&helper_dbus_path)
        .with_context(|| format!("cannot read {}", helper_dbus_path.display()))?;
    let wanted_interface = format!("#[zbus::interface(name = \"{interface_name}\")]");
    if !helper_dbus_src.contains(&wanted_interface) {
        match contract_line(&helper_dbus_src, "#[zbus::interface") {
            Some(line) => bail!(
                "{}:{line}: zbus interface name must be `{interface_name}`",
                helper_dbus_path.display()
            ),
            None => bail!(
                "{}: missing `{wanted_interface}`",
                helper_dbus_path.display()
            ),
        }
    }
    println!("PASS {helper_dbus_rel} (zbus interface literal matches INTERFACE_NAME)");

    // 5. Packaging recipes must all install/chown the shared helper path.
    for rel in [
        "packaging/arch/PKGBUILD",
        "packaging/rpm/furus.spec",
        "packaging/deb/postinst",
    ] {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if !text.contains(helper_bin) {
            bail!("{rel}: must reference helper path `{helper_bin}`");
        }
        println!("PASS {rel} (references {helper_bin})");
    }

    // 6. Negative scan: no wrong namespace prefix or legacy helper path in
    //    any packaging file or either D-Bus source file. `packaging/README.md`
    //    is documentation that deliberately explains the rejected
    //    `org.furus.*` namespace, so it is the one intentional exception.
    let gui_dbus_rel = "crates/furus-gui/src/ipc/dbus.rs";
    let gui_dbus_path = root.join(gui_dbus_rel);
    let gui_dbus_src = std::fs::read_to_string(&gui_dbus_path)
        .with_context(|| format!("cannot read {}", gui_dbus_path.display()))?;
    let mut negative_files: Vec<(PathBuf, String)> = Vec::new();
    let packaging_root = root.join("packaging");
    let mut packaging_files = Vec::new();
    contract_collect_files(&packaging_root, &mut packaging_files)?;
    for path in packaging_files {
        if path.file_name().and_then(|n| n.to_str()) == Some("README.md") {
            continue; // documentation, not an identifier-bearing data file
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        negative_files.push((path, text));
    }
    negative_files.push((gui_dbus_path, gui_dbus_src));
    negative_files.push((helper_dbus_path.clone(), helper_dbus_src));
    for (path, text) in &negative_files {
        for (index, line) in text.lines().enumerate() {
            let line_no = index + 1;
            if line.contains("org.furus.") {
                bail!(
                    "{}:{line_no}: wrong namespace prefix `org.furus.` (expected `org.furuslinux.`)",
                    path.display()
                );
            }
            if line.contains("/usr/lib/furus/furus-helper") {
                bail!(
                    "{}:{line_no}: wrong helper path `/usr/lib/furus/furus-helper` (expected `{helper_bin}`)",
                    path.display()
                );
            }
        }
    }
    println!(
        "PASS no wrong namespace prefix or legacy helper path ({} files scanned)",
        negative_files.len()
    );

    println!("contract: all identifiers match the single source of truth");
    Ok(())
}

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
    println!("==> contract --check");
    cmd_contract(root)?;
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
struct QaOptions {
    require_qemu: bool,
    privileged: bool,
}

fn parse_qa_options(args: &[String]) -> Result<QaOptions> {
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

fn cmd_qa(root: &Path, options: QaOptions) -> Result<()> {
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
                   release-build, enforce budgets, check growth against the
                   committed baseline within 4096-byte allowance
                   (--write-baseline updates it instead)
  ci               fmt + clippy + test + assets + parity --check + size (+ deny/audit)
  qa [--require-qemu] [--privileged]
                    two-tier end-to-end release gate:
                      tier 1 (always): unprivileged sparse-file suites — MBR/GPT,
                      FAT32/exFAT/NTFS/ext4/UDF, UEFI:NTFS structure, BCD +
                      SYSTEM hive, Windows boot files/bootloader
                      tier 2 (when QEMU + firmware exist): headless BIOS smoke,
                      real BIOS bootloader boots, OVMF/UEFI:NTFS boot — each
                      with a hard 30-120s timeout and kill/reap on every path
                      --require-qemu: fail instead of skipping when QEMU or the
                      UEFI firmware/toolchain is missing
                      --privileged: also run loop-device/mount suites (off by
                      default; unprivileged sparse-file mode is the default)
  dist [--target <triple>] [--out-dir <dir>]
                   release-build, validate packaging/, stage a deterministic
                   bundle (tar.gz + SHA256SUMS, .deb when dpkg-deb exists)
                   default target = rustc host triple; default out-dir =
                   target/dist/<triple>"
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
        "qa" => cmd_qa(&root, parse_qa_options(&args)?),
        "dist" => {
            let mut target: Option<String> = None;
            let mut out_dir: Option<PathBuf> = None;
            let mut it = args.iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--target" => {
                        target = Some(
                            it.next()
                                .context("dist: --target needs a target triple")?
                                .clone(),
                        );
                    }
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(
                            it.next().context("dist: --out-dir needs a directory")?,
                        ));
                    }
                    other => bail!(
                        "dist: unknown option `{other}` (usage: cargo xtask dist [--target <triple>] [--out-dir <dir>])"
                    ),
                }
            }
            cmd_dist(target, out_dir)
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
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    /// Unique scratch directory per test, cleaned up on drop. The process id
    /// plus an atomic counter keeps names distinct even when tests run in
    /// parallel inside the same test binary (no external tempfile crate).
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("furus-dist-test-{tag}-{}-{n}", std::process::id()));
            if path.exists() {
                std::fs::remove_dir_all(&path).unwrap();
            }
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Re-read a generated SHA256SUMS and check every `<digest>  <name>` line
    /// against the on-disk bytes. Test-only counterpart of `write_sha256sums`.
    fn verify_sha256sums(out_dir: &Path) -> Result<()> {
        let path = out_dir.join("SHA256SUMS");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        for line in text.lines() {
            let (digest, name) = line
                .split_once("  ")
                .with_context(|| format!("malformed SHA256SUMS line: {line:?}"))?;
            let actual = sha256_of(&out_dir.join(name))?;
            if actual != digest {
                bail!("SHA256SUMS: digest mismatch for `{name}`: {digest} != {actual}");
            }
        }
        Ok(())
    }

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
        let baseline: BTreeMap<String, BaselineEntry> = [
            (
                "furus".to_string(),
                BaselineEntry {
                    bytes: 100,
                    budget: 3_000_000,
                },
            ),
            (
                "furus-helper".to_string(),
                BaselineEntry {
                    bytes: 90,
                    budget: 2_500_000,
                },
            ),
            (
                "furus-gui".to_string(),
                BaselineEntry {
                    bytes: 80,
                    budget: 14_000_000,
                },
            ),
        ]
        .into_iter()
        .collect();
        let full = |furus_bytes: u64| -> BTreeMap<String, u64> {
            [
                ("furus".to_string(), furus_bytes),
                ("furus-helper".to_string(), 90),
                ("furus-gui".to_string(), 80),
            ]
            .into_iter()
            .collect()
        };
        // Exact match passes; growth within the allowance passes and any
        // shrink passes; only growth beyond the allowance fails.
        assert!(check_size_drift(&full(100), &baseline).is_ok());
        assert!(check_size_drift(&full(100 + SIZE_DRIFT_ALLOWANCE), &baseline).is_ok());
        assert!(check_size_drift(&full(100 + SIZE_DRIFT_ALLOWANCE + 1), &baseline).is_err());
        assert!(check_size_drift(&full(99), &baseline).is_ok());
        // Missing baseline entry fails.
        let mut missing = baseline.clone();
        missing.remove("furus-gui");
        assert!(check_size_drift(&full(100), &missing).is_err());
        // Stale budget fails even when the bytes match.
        let mut stale = baseline.clone();
        stale.insert(
            "furus".to_string(),
            BaselineEntry {
                bytes: 100,
                budget: 3_000_001,
            },
        );
        assert!(check_size_drift(&full(100), &stale).is_err());
    }

    #[test]
    fn parse_ini_accepts_comments_and_rejects_duplicates() {
        let text = "# leading comment\n; another\n[Desktop Entry]\nType=Application\nName = x # not a comment\n";
        let ini = parse_ini(text).unwrap();
        assert_eq!(ini["Desktop Entry"]["Type"], "Application");
        assert_eq!(ini["Desktop Entry"]["Name"], "x # not a comment");

        for bad in [
            "Type=Application\n",   // key before any section
            "[A]\nx=1\nx=2\n",      // duplicate key
            "[A]\nx=1\n[A]\ny=2\n", // duplicate section
            "[A\nx=1\n",            // malformed section header
            "[A]\nno-equals\n",     // malformed key=value
        ] {
            assert!(parse_ini(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn finalized_packaging_validates() {
        let packaging = validate_packaging(&repo_root().join("packaging")).unwrap();
        assert_eq!(packaging.texts.len(), PACKAGING_FILES.len());
        assert!(
            packaging
                .get("deb/control")
                .unwrap()
                .contains("Recommends: ntfs-3g")
        );
    }

    #[test]
    fn contract_check_passes_for_the_repository() {
        // The committed single source and the packaging files must agree.
        cmd_contract(&repo_root()).unwrap();
    }

    #[test]
    fn contract_const_reads_the_single_source_declarations() {
        let src = "pub const BUS_NAME: &str = \"org.example.Name\";\n\
                   pub const HELPER_DBUS_ARG: &str = \"--dbus\";\n";
        assert_eq!(
            contract_const(src, "BUS_NAME", Path::new("service.rs")).unwrap(),
            "org.example.Name"
        );
        assert_eq!(
            contract_const(src, "HELPER_DBUS_ARG", Path::new("service.rs")).unwrap(),
            "--dbus"
        );
        assert!(contract_const(src, "MISSING", Path::new("service.rs")).is_err());
    }

    #[test]
    fn debian_arch_maps_supported_triples() {
        assert_eq!(debian_arch("x86_64-unknown-linux-gnu").unwrap(), "amd64");
        assert_eq!(debian_arch("aarch64-unknown-linux-gnu").unwrap(), "arm64");
        assert!(debian_arch("i686-unknown-linux-gnu").is_err());
    }

    #[test]
    fn dist_archive_is_byte_identical() {
        let dir = std::env::temp_dir().join(format!("furus-dist-tar-test-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        let staging = dir.join("staging");
        std::fs::create_dir_all(staging.join("usr/bin")).unwrap();
        let binary = staging.join("usr/bin/furus");
        std::fs::write(&binary, b"binary payload").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

        let a = dir.join("a.tar.gz");
        let b = dir.join("b.tar.gz");
        write_dist_archive(&staging, std::fs::File::create(&a).unwrap()).unwrap();
        write_dist_archive(&staging, std::fs::File::create(&b).unwrap()).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        verify_archive(&a, &staging).unwrap();
        // Pin the deterministic header invariants carried by every entry.
        let file = std::fs::File::open(&a).unwrap();
        let mut ar = Archive::new(GzDecoder::new(file));
        let mut entries = 0;
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            let h = entry.header();
            let name = h.path().unwrap().to_string_lossy().into_owned();
            assert_eq!(h.mtime().unwrap(), 0, "{name}: mtime must be zero");
            assert_eq!(h.uid().unwrap(), 0, "{name}: uid must be zero");
            assert_eq!(h.gid().unwrap(), 0, "{name}: gid must be zero");
            if name == "usr/bin/furus" {
                assert_eq!(h.mode().unwrap() & 0o7777, 0o755);
            }
            entries += 1;
        }
        assert_eq!(entries, 3); // two directories (usr, usr/bin) + one file
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The exact 12 paths staged by `stage_tree`, with their expected modes.
    /// Binaries, the helper and the postinst are 0755; all data is 0644.
    const STAGED_LAYOUT: &[(&str, u32)] = &[
        ("usr/bin/furus", 0o755),
        ("usr/bin/furus-gui", 0o755),
        ("usr/libexec/furus-helper", 0o755),
        ("usr/share/polkit-1/actions/org.furuslinux.policy", 0o644),
        (
            "usr/share/dbus-1/system-services/org.furuslinux.Helper1.service",
            0o644,
        ),
        (
            "usr/share/dbus-1/system.d/org.furuslinux.Helper1.conf",
            0o644,
        ),
        ("usr/share/applications/org.furuslinux.Furus.desktop", 0o644),
        (
            "usr/share/metainfo/org.furuslinux.Furus.metainfo.xml",
            0o644,
        ),
        (
            "usr/share/icons/hicolor/scalable/apps/org.furuslinux.Furus.svg",
            0o644,
        ),
        ("usr/share/doc/furus/LICENSES.md", 0o644),
        ("DEBIAN/control", 0o644),
        ("DEBIAN/postinst", 0o755),
    ];

    #[test]
    fn staged_layout_has_exact_paths_and_modes() {
        let tmp = TempDir::new("layout");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        for name in ["furus", "furus-gui", "furus-helper"] {
            std::fs::write(bin_dir.join(name), format!("fixture binary {name}")).unwrap();
        }
        let packaging = validate_packaging(&repo_root().join("packaging")).unwrap();

        let arch = debian_arch("x86_64-unknown-linux-gnu").unwrap();
        let staging = tmp.path().join("staging-amd64");
        stage_tree(&repo_root(), arch, &bin_dir, &packaging, &staging).unwrap();

        for (rel, mode) in STAGED_LAYOUT {
            let path = staging.join(rel);
            assert!(path.is_file(), "missing staged file {rel}");
            let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(actual, *mode, "wrong mode for {rel}: {actual:o}");
        }

        // No extra staged files beyond the 12 (collect_staged walks the tree).
        let (_, files) = collect_staged(&staging).unwrap();
        assert_eq!(files.len(), STAGED_LAYOUT.len());

        // The literal `Architecture: any` was rewritten for the concrete
        // target, and nowhere else did the control text change shape.
        let control = std::fs::read_to_string(staging.join("DEBIAN/control")).unwrap();
        assert!(control.lines().any(|l| l == "Architecture: amd64"));
        assert!(!control.contains("Architecture: any"));
    }

    #[test]
    fn staged_control_architecture_follows_target_mapping() {
        let tmp = TempDir::new("arch");
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        for name in ["furus", "furus-gui", "furus-helper"] {
            std::fs::write(bin_dir.join(name), b"x").unwrap();
        }
        let packaging = validate_packaging(&repo_root().join("packaging")).unwrap();

        for (triple, expected) in [
            ("x86_64-unknown-linux-gnu", "amd64"),
            ("aarch64-unknown-linux-gnu", "arm64"),
        ] {
            // Test the mapping directly as well as its effect on staging.
            assert_eq!(debian_arch(triple).unwrap(), expected);
            let staging = tmp.path().join(format!("staging-{expected}"));
            let arch = debian_arch(triple).unwrap();
            stage_tree(&repo_root(), arch, &bin_dir, &packaging, &staging).unwrap();
            let control = std::fs::read_to_string(staging.join("DEBIAN/control")).unwrap();
            assert!(
                control
                    .lines()
                    .any(|l| l == format!("Architecture: {expected}")),
                "{triple} did not map to {expected}"
            );
        }
        assert!(debian_arch("i686-unknown-linux-gnu").is_err());
    }

    #[test]
    fn real_packaging_xml_and_ini_files_validate() {
        let root = repo_root().join("packaging");
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
        // XML-backed definitions.
        validate_polkit(&read("polkit/org.furuslinux.policy")).unwrap();
        validate_bus_conf(&read("dbus/org.furuslinux.Helper1.conf")).unwrap();
        validate_metainfo(&read("org.furuslinux.Furus.metainfo.xml")).unwrap();
        // INI-backed definitions.
        validate_service(&read("dbus/org.furuslinux.Helper1.service")).unwrap();
        validate_desktop(&read("org.furuslinux.Furus.desktop")).unwrap();
        // Distro metadata tokens.
        validate_deb_control(&read("deb/control")).unwrap();
        validate_rpm_spec(&read("rpm/furus.spec")).unwrap();
        validate_arch_pkgbuild(&read("arch/PKGBUILD")).unwrap();
        // All 11 finalized files exist, including the non-validated payloads.
        assert_eq!(PACKAGING_FILES.len(), 11);
        for rel in PACKAGING_FILES {
            assert!(root.join(rel).is_file(), "missing packaging file {rel}");
        }
    }

    #[test]
    fn malformed_xml_is_rejected() {
        // Unclosed element.
        assert!(
            validate_polkit("<policyconfig><action id=\"org.furuslinux.write-device\">").is_err()
        );
        // Mismatched closing tag.
        assert!(validate_bus_conf("<busconfig><policy></busconfig>").is_err());
        // Polkit action with the wrong/missing id.
        let no_id = "<policyconfig><action id=\"other\"><defaults>\
                     <allow_any>no</allow_any><allow_inactive>no</allow_inactive>\
                     <allow_active>auth_admin_keep</allow_active></defaults></action></policyconfig>";
        assert!(validate_polkit(no_id).is_err());
        assert!(validate_polkit("<policyconfig/>").is_err());
        // Polkit defaults missing auth_admin_keep (wrong value).
        let wrong_keep = "<policyconfig><action id=\"org.furuslinux.write-device\"><defaults>\
                          <allow_any>no</allow_any><allow_inactive>no</allow_inactive>\
                          <allow_active>yes</allow_active></defaults></action></policyconfig>";
        assert!(validate_polkit(wrong_keep).is_err());
        // Bus config missing the root-owned `own` rule.
        let bus_no_root = "<busconfig><policy context=\"default\">\
                           <deny own=\"org.furuslinux.Helper1\"/>\
                           <allow send_destination=\"org.furuslinux.Helper1\"/>\
                           </policy></busconfig>";
        assert!(validate_bus_conf(bus_no_root).is_err());
        // Metainfo missing the required <id>.
        assert!(
            validate_metainfo("<component type=\"desktop-application\"><name>x</name></component>")
                .is_err()
        );
        // Metainfo with the wrong id.
        assert!(
            validate_metainfo("<component type=\"desktop-application\"><id>wrong</id></component>")
                .is_err()
        );
    }

    #[test]
    fn malformed_ini_is_rejected_by_validators() {
        // Duplicate section, duplicate key and key outside a section all go
        // through parse_ini; the higher-level validators must refuse them too.
        assert!(validate_service("[D-Bus Service]\nName=x\nName=y\n").is_err());
        assert!(validate_service("[D-Bus Service]\nName=x\n[D-Bus Service]\nExec=y\n").is_err());
        assert!(validate_desktop("Exec=furus-gui\n[Desktop Entry]\nType=Application\n").is_err());
        // Missing required keys: Exec in the desktop entry, User in the
        // service. Both otherwise-valid files must still be rejected.
        let no_exec = "[Desktop Entry]\nType=Application\nName=x\nIcon=x\nTerminal=false\nCategories=System;\n";
        assert!(validate_desktop(no_exec).is_err());
        let no_user =
            "[D-Bus Service]\nName=org.furuslinux.Helper1\nExec=/usr/libexec/furus-helper --dbus\n";
        assert!(validate_service(no_user).is_err());
        // A wrong Exec value is rejected as well.
        let wrong_exec =
            "[D-Bus Service]\nName=org.furuslinux.Helper1\nExec=/bin/false\nUser=root\n";
        assert!(validate_service(wrong_exec).is_err());
    }

    #[test]
    fn sha256sums_match_artifact_bytes_and_detect_corruption() {
        let tmp = TempDir::new("sums");
        let a = tmp.path().join("artifact.bin");
        let b = tmp.path().join("other.txt");
        std::fs::write(&a, b"deterministic payload 12345").unwrap();
        std::fs::write(&b, b"second").unwrap();
        let names = vec!["artifact.bin".to_string(), "other.txt".to_string()];

        write_sha256sums(tmp.path(), &names).unwrap();
        let text = std::fs::read_to_string(tmp.path().join("SHA256SUMS")).unwrap();
        // Exact GNU-coreutils-style format: `<hex>  <name>\n`, stable order.
        assert_eq!(
            text,
            format!(
                "{}  artifact.bin\n{}  other.txt\n",
                sha256_of(&a).unwrap(),
                sha256_of(&b).unwrap()
            )
        );
        for (line, name) in text.lines().zip(&names) {
            let (digest, n) = line.split_once("  ").unwrap();
            assert_eq!(n, name);
            assert_eq!(digest, &sha256_of(&tmp.path().join(name)).unwrap());
        }
        verify_sha256sums(tmp.path()).unwrap();

        // A corrupted digest line is detected.
        std::fs::write(tmp.path().join("SHA256SUMS"), "deadbeef  artifact.bin\n").unwrap();
        assert!(verify_sha256sums(tmp.path()).is_err());

        // Rewriting correct sums then mutating an artifact is also detected.
        write_sha256sums(tmp.path(), &names).unwrap();
        std::fs::write(&a, b"tampered payload").unwrap();
        assert!(verify_sha256sums(tmp.path()).is_err());
    }

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
}
