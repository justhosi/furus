//! Parity ledger validation and freshness checking.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use sha2::Digest;

use crate::util::hex_encode;
use crate::util::run;
use crate::util::run_quiet;

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

pub(crate) enum ParityMode {
    Validate,
    Regenerate,
    Check,
}

pub(crate) fn cmd_parity(root: &Path, mode: ParityMode) -> Result<()> {
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

#[cfg(test)]
mod tests;
