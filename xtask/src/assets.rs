//! `assets --check`: validate assets/manifest.json against files on disk.

use std::collections::BTreeSet;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::util::sha256_of;

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

pub(crate) fn cmd_assets_check(root: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests;
