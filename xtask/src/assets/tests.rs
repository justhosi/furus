use super::*;

use crate::util::repo_root;

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
