//! Distribution bundles: staging, deterministic tarball, SHA256SUMS.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use flate2::Compression;
use flate2::GzBuilder;
use flate2::read::GzDecoder;
use tar::Archive;
use tar::Builder;
use tar::EntryType;
use tar::Header;

use crate::packaging::Packaging;
use crate::packaging::validate_packaging;
use crate::size::BINARY_BUDGETS;
use crate::util::repo_root;
use crate::util::run;
use crate::util::run_quiet;
use crate::util::sha256_of;
use crate::util::tool_present;

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
pub(crate) fn cmd_dist(target: Option<String>, out_dir: Option<PathBuf>) -> Result<()> {
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

#[cfg(test)]
mod tests;
