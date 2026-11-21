//! Validation of the finalized `packaging/` files.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use quick_xml::Reader;
use quick_xml::events::Event;

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
pub(crate) struct Packaging {
    texts: BTreeMap<String, String>,
}

impl Packaging {
    pub(crate) fn get(&self, rel: &str) -> Result<&str> {
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
pub(crate) fn validate_packaging(packaging_root: &Path) -> Result<Packaging> {
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

#[cfg(test)]
mod tests;
