use super::*;

use crate::util::TempDir;

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
