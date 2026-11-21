//! Release binary budgets and the committed size baseline.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::util::run;

pub(crate) struct BinaryBudget {
    pub(crate) name: &'static str,
    pub(crate) budget: u64,
}

pub(crate) const BINARY_BUDGETS: &[BinaryBudget] = &[
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

pub(crate) fn cmd_size(root: &Path, write_baseline: bool) -> Result<()> {
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

#[cfg(test)]
mod tests;
