//! GUI / helper / packaging identifier single-source check.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

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
pub(crate) fn cmd_contract(root: &Path) -> Result<()> {
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

#[cfg(test)]
mod tests;
