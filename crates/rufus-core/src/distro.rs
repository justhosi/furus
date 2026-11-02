//! The distro rule table (S16, slice 4 of 6): volume-label globs with
//! distro names, replacing the hard-coded table in `0x140031220.c`.
//!
//! Rufus compares the volume label against eight anchored POSIX regexes
//! (`^AlmaLinux-[8-9].*` and friends) and then three literal prefixes
//! (`Install-SUSE`, `Install-LEAP`, `openSUSE-Tumbleweed`); a hit sets
//! only the "enforce DD image mode" flag. This module keeps that
//! behaviour in data: [`DistroRule`] pairs a glob with a distro name
//! and a `forces_dd` bit, [`DistroTable`] matches a label against the
//! rules in order, and [`forces_dd`] answers the DD-mode question for
//! the write slices.
//!
//! Glob syntax (matched case-sensitively — Rufus compiles its regexes
//! without `REG_ICASE`, so case matters here too — and anchored at both
//! ends, so `AlmaLinux-[8-9]*` behaves like `^AlmaLinux-[8-9].*$`):
//!
//! * `*` matches any byte run, including the empty run;
//! * `?` matches exactly one byte;
//! * `[abc]` matches one byte from the set, `[a-z]` one byte from the
//!   inclusive range; a `-` at either edge is a literal `-`, and `!`
//!   has no special meaning (`[!ab]` matches `!`, `a` or `b`);
//! * any other byte — including an unclosed `[`, which matches a
//!   literal `[` — matches only itself.
//!
//! Matching is byte-wise (no Unicode folding: labels are ASCII in
//! practice) with a two-pointer greedy scan and no recursion (see
//! [`glob_matches`]); labels longer than [`MAX_GLOB_BYTES`] never match.
//!
//! The shipped rules live in `distros.toml` next to this file, compiled
//! in with `include_str!` and parsed once behind
//! [`DistroTable::embedded`]. [`DistroTable::load`] appends an optional
//! user file's rules after the embedded ones, so a user rule can extend
//! but never silently shadow the shipped table: the first match in
//! order wins.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;
use serde::Serialize;

use crate::error::CoreError;
use crate::error::Result;

/// Cap on label length in bytes: real labels are tens of bytes, so a
/// longer label fails closed (never matches) rather than letting a
/// hostile image buy scan work.
pub const MAX_GLOB_BYTES: usize = 256;

/// The shipped rule table, compiled in from `distros.toml`.
const EMBEDDED_TOML: &str = include_str!("distros.toml");

/// One label rule: a [`DistroTable`] reports the first rule whose glob
/// matches the volume label.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DistroRule {
    /// Glob matched against the volume label (see the module docs).
    pub label: String,
    /// Short distro identifier reported on a match.
    pub distro: String,
    /// Rufus's "not ISO mode compatible" rule: a match means the image
    /// is written in DD mode.
    #[serde(default)]
    pub forces_dd: bool,
}

/// The rule table: ordered rules, first match wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroTable {
    rules: Vec<DistroRule>,
}

/// The on-disk shape: one `[[rule]]` table per rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistroFile {
    /// The rules in match order (absent means none).
    #[serde(default)]
    rule: Vec<DistroRule>,
}

/// Match one pattern element at `pattern[px]` against the text byte:
/// `Some(step)` when it matches, where `step` is how far past the
/// element the pattern cursor moves (1 for `?` and literals, the whole
/// `[...]` span for a class); `None` when it does not match, when `px`
/// is past the pattern end, or when the element is `*` (the caller
/// handles stars, which consume text, never here).
fn match_element(pattern: &[u8], px: usize, byte: u8) -> Option<usize> {
    let current = *pattern.get(px)?;
    if current == b'*' {
        return None;
    }
    if current == b'?' {
        return Some(1);
    }
    if current != b'[' {
        return if current == byte { Some(1) } else { None };
    }
    // A character class: find its closing `]` (an unclosed `[` matches
    // a literal `[`, documented in the module docs).
    let mut end = px.saturating_add(1);
    while let Some(&next) = pattern.get(end) {
        if next == b']' {
            break;
        }
        end = end.saturating_add(1);
    }
    if pattern.get(end) != Some(&b']') {
        return if byte == b'[' { Some(1) } else { None };
    }
    // Members in pattern[px + 1..end]: literal bytes and `a-z` ranges
    // (a `-` at either edge falls through to the literal arm).
    let mut member = px.saturating_add(1);
    let mut hit = false;
    while member < end {
        let first = match pattern.get(member) {
            Some(&found) => found,
            None => break,
        };
        if pattern.get(member.saturating_add(1)) == Some(&b'-') && member.saturating_add(2) < end {
            let last = match pattern.get(member.saturating_add(2)) {
                Some(&found) => found,
                None => break,
            };
            if first <= byte && byte <= last {
                hit = true;
            }
            member = member.saturating_add(3);
        } else {
            if first == byte {
                hit = true;
            }
            member = member.saturating_add(1);
        }
    }
    if hit {
        Some(end.saturating_sub(px).saturating_add(1))
    } else {
        None
    }
}

/// Match `text` against the glob `pattern`, anchored at both ends and
/// case-sensitively (byte-wise). `Some`/`None` discipline throughout:
/// no indexing, no panic, no allocation.
///
/// Two-pointer greedy scan, no recursion: a `*` records its pattern
/// position and the scan backtracks there on mismatch, letting the star
/// consume one more byte. A hostile pattern therefore costs at most
/// (label bytes × pattern bytes) steps — and the label is capped at
/// [`MAX_GLOB_BYTES`] — instead of blowing up exponentially.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    if text.len() > MAX_GLOB_BYTES {
        return false;
    }
    let mut px: usize = 0;
    let mut tx: usize = 0;
    let mut star: Option<usize> = None;
    let mut resume: usize = 0;
    while tx < text.len() {
        let byte = match text.get(tx) {
            Some(&found) => found,
            None => break,
        };
        let mut advanced = false;
        if px < pattern.len() {
            if pattern.get(px) == Some(&b'*') {
                star = Some(px);
                resume = tx;
                px = px.saturating_add(1);
                advanced = true;
            } else if let Some(step) = match_element(pattern, px, byte) {
                px = px.saturating_add(step);
                tx = tx.saturating_add(1);
                advanced = true;
            }
        }
        if advanced {
            continue;
        }
        match star {
            Some(saved) => {
                px = saved.saturating_add(1);
                resume = resume.saturating_add(1);
                tx = resume;
            }
            None => return false,
        }
    }
    // A trailing run of `*` matches the empty tail.
    while pattern.get(px) == Some(&b'*') {
        px = px.saturating_add(1);
    }
    px >= pattern.len()
}

static EMBEDDED: OnceLock<DistroTable> = OnceLock::new();

impl DistroTable {
    /// The shipped table, parsed once: `&'static` so no call ever
    /// re-parses the compiled-in TOML. A broken embedded table (only
    /// possible by editing `distros.toml` itself, which the tests pin
    /// rule by rule) yields an empty table rather than a panic.
    pub fn embedded() -> &'static DistroTable {
        EMBEDDED.get_or_init(|| match Self::from_toml(EMBEDDED_TOML) {
            Ok(table) => table,
            Err(_) => DistroTable { rules: Vec::new() },
        })
    }

    /// Parse a rule table from TOML text (`[[rule]]` tables, see
    /// `distros.toml`). Refusals name the problem: an empty `label` or
    /// `distro` names its rule index; a malformed document or an unknown
    /// key surfaces as the `toml` crate's own error, wrapped with
    /// context.
    pub fn from_toml(text: &str) -> Result<DistroTable> {
        let file: DistroFile = toml::from_str(text).map_err(|error| {
            CoreError::invalid(format!("distros table does not parse: {error}"))
        })?;
        let mut rules = Vec::new();
        for (index, rule) in file.rule.into_iter().enumerate() {
            if rule.label.trim().is_empty() {
                return Err(CoreError::invalid(format!(
                    "distros rule {index} has an empty label"
                )));
            }
            if rule.distro.trim().is_empty() {
                return Err(CoreError::invalid(format!(
                    "distros rule {index} has an empty distro name"
                )));
            }
            rules.push(rule);
        }
        Ok(DistroTable { rules })
    }

    /// The embedded table plus, when `override_path` is `Some`, the
    /// rules from that file appended after the embedded ones — so a
    /// user rule can extend but never silently shadow the shipped
    /// table, first match in order winning either way. `None` means the
    /// embedded table only. A missing or unreadable file is a refusal
    /// naming the path; a bad document names the path with the parse
    /// problem. No environment is read.
    pub fn load(override_path: Option<&Path>) -> Result<DistroTable> {
        let mut table = Self::embedded().clone();
        if let Some(path) = override_path {
            let text = fs::read_to_string(path).map_err(|source| CoreError::io(path, source))?;
            let extra = Self::from_toml(&text).map_err(|error| {
                CoreError::invalid(format!("distro override '{}': {error}", path.display()))
            })?;
            table.rules.extend(extra.rules);
        }
        Ok(table)
    }

    /// The first rule whose glob matches `label`, if any.
    #[must_use]
    pub fn match_label(&self, label: &str) -> Option<&DistroRule> {
        self.rules
            .iter()
            .find(|rule| glob_matches(&rule.label, label))
    }

    /// The rules in match order.
    #[must_use]
    pub fn rules(&self) -> &[DistroRule] {
        &self.rules
    }
}

/// True when `label` matches a rule that forces DD mode: the
/// data-driven form of `0x140031220.c`'s hard-coded table, whose hit
/// sets only the enforce-DD-image-mode flag — later logging `Note: DD
/// image mode enforced since this ISOHybrid is not ISO mode compatible.`
/// and clearing the ISO-mode flag.
#[must_use]
pub fn forces_dd(label: &str) -> bool {
    DistroTable::embedded()
        .match_label(label)
        .is_some_and(|rule| rule.forces_dd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shipped rule against its positive example (label text
    /// shaped like the real media the decompiled regexes target).
    const POSITIVES: &[(&str, &str)] = &[
        ("AlmaLinux-9.3-x86_64", "AlmaLinux"),
        ("AlmaLinux-8.10-x86_64-dvd", "AlmaLinux"),
        ("CentOS-Stream-9-latest", "CentOS"),
        ("Circle-9.3", "Circle"),
        ("Fedora-Workstation-Live-x86_64-39-1.5", "Fedora"),
        ("MIRACLE-LINUX-9.3", "MIRACLE-LINUX"),
        ("OL-9.3", "OL"),
        ("RHEL-9.3", "RHEL"),
        ("Rocky-9.3", "Rocky"),
        ("Rocky-8.9-x86_64-dvd", "Rocky"),
        ("Install-SUSE-15", "SUSE"),
        ("Install-LEAP-15.5", "openSUSE Leap"),
        (
            "openSUSE-Tumbleweed-DVD-x86_64-Snapshot20240101",
            "openSUSE Tumbleweed",
        ),
    ];

    #[test]
    fn shipped_rules_match_their_labels() {
        let table = DistroTable::embedded();
        for (label, distro) in POSITIVES {
            assert!(
                table
                    .match_label(label)
                    .is_some_and(|hit| hit.distro == *distro && hit.forces_dd),
                "label {label}"
            );
        }
    }

    #[test]
    fn non_matching_labels_match_nothing() {
        let table = DistroTable::embedded();
        for label in [
            "Ubuntu 24.04 LTS",
            "Debian 12.5",
            "AlmaLinux-7.9",
            "Fedora-Workstation-Live-x86_64-32-1.5",
            "Rocky-10.0",
            "",
        ] {
            assert_eq!(table.match_label(label), None, "label {label}");
        }
    }

    #[test]
    fn glob_operators_behave() {
        // `*` still needs the literal around it: the suffix is missing.
        assert!(!glob_matches("Install-SUSE*", "Install-SUS"));
        assert!(glob_matches("Install-SUSE*", "Install-SUSE-15"));
        // `?` is exactly one byte.
        assert!(glob_matches("A?C", "ABC"));
        assert!(!glob_matches("A?C", "AC"));
        assert!(!glob_matches("A?C", "ABBC"));
        // Classes take members and ranges only.
        assert!(glob_matches("[8-9]", "8"));
        assert!(glob_matches("[8-9]", "9"));
        assert!(!glob_matches("[8-9]", "7"));
        assert!(glob_matches("[-a]", "-"));
        assert!(glob_matches("[-a]", "a"));
        assert!(!glob_matches("[-a]", "b"));
        // An unclosed `[` is a literal.
        assert!(glob_matches("A[B", "A[B"));
        assert!(!glob_matches("A[B", "AXB"));
        // Anchored at both ends, matched case-sensitively.
        assert!(!glob_matches("Rocky-[8-9]*", "xRocky-9.3"));
        assert!(!glob_matches("rocky-[8-9]*", "Rocky-9.3"));
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "x"));
        // Overlong labels never match, even against `*`.
        assert!(!glob_matches("*", &"A".repeat(MAX_GLOB_BYTES + 1)));
        assert!(glob_matches("*", &"A".repeat(MAX_GLOB_BYTES)));
    }

    #[test]
    fn embedded_rules_come_first() {
        let mut table = DistroTable::embedded().clone();
        let user =
            DistroTable::from_toml("[[rule]]\nlabel = \"Rocky-[8-9]*\"\ndistro = \"Shadow\"\n")
                .expect("the user table parses");
        table.rules.extend(user.rules);
        let hit = table
            .match_label("Rocky-9.3")
            .expect("the glob still matches");
        assert_eq!(hit.distro, "Rocky");
        assert!(hit.forces_dd);
    }

    #[test]
    fn from_toml_refuses_empty_fields_naming_the_rule() {
        let error = DistroTable::from_toml("[[rule]]\nlabel = \"\"\ndistro = \"X\"\n")
            .expect_err("an empty label refuses");
        let text = error.to_string();
        assert!(text.contains("rule 0"), "{text}");
        assert!(text.contains("label"), "{text}");
        let second =
            "[[rule]]\nlabel = \"A*\"\ndistro = \"A\"\n[[rule]]\nlabel = \"B*\"\ndistro = \"\"\n";
        let error = DistroTable::from_toml(second).expect_err("an empty distro refuses");
        let text = error.to_string();
        assert!(text.contains("rule 1"), "{text}");
        assert!(text.contains("distro"), "{text}");
        let bogus = "[[rule]]\nlabel = \"A*\"\ndistro = \"A\"\nbogus = 1\n";
        let error = DistroTable::from_toml(bogus).expect_err("an unknown key refuses");
        let text = error.to_string();
        assert!(text.contains("bogus"), "{text}");
    }

    #[test]
    fn forces_dd_answers_the_table() {
        assert!(forces_dd("Rocky-9.3"));
        assert!(!forces_dd("Ubuntu 24.04 LTS"));
    }

    #[test]
    fn load_reads_an_override_file() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let missing = dir.path().join("nope.toml");
        let error = DistroTable::load(Some(&missing)).expect_err("a missing override refuses");
        let text = error.to_string();
        assert!(text.contains("nope.toml"), "{text}");
        let path = dir.path().join("extra.toml");
        std::fs::write(
            &path,
            "[[rule]]\nlabel = \"Ubuntu*\"\ndistro = \"Ubuntu\"\n",
        )
        .expect("the override writes");
        let table = DistroTable::load(Some(&path)).expect("the override loads");
        assert_eq!(
            table.rules().len(),
            DistroTable::embedded().rules().len() + 1
        );
        let hit = table
            .match_label("Ubuntu 24.04 LTS")
            .expect("the user rule matches");
        assert_eq!(hit.distro, "Ubuntu");
        assert!(!hit.forces_dd);
        let embedded = DistroTable::load(None).expect("no override loads");
        assert_eq!(
            embedded.rules().len(),
            DistroTable::embedded().rules().len()
        );
    }
}
