//! `i18n_bridge`: headless localisation bridge for the GUI (slice 7/7).
//!
//! All locale decisions live here; `main.rs` only marshals the strings and
//! flags this module produces into Slint properties. There is no global
//! state, no lazy static and no network access.
//!
//! A catalog is loaded from the system asset (`RCDATA_500.bin`, then
//! `rufus.loc`) when one is available, otherwise from [`EMBEDDED_CATALOG`],
//! a small but valid pollock-format `.loc` constant. The embedded fallback
//! makes catalog loading independent of `$APPDIR`, a broken asset directory
//! or a missing FHS install — unit tests stay deterministic and offline.
//!
//! # RTL limitation
//!
//! Slint 1.19 has **no right-to-left layout engine**. This module computes
//! `rtl` from the locale's primary subtag so the UI can mirror pure
//! presentation (text alignment, button order). It deliberately does not
//! invent any business rule from the locale: device, plan and safety
//! decisions stay language-independent.

use std::collections::HashMap;

use furus_core::i18n::Catalog;
use furus_core::i18n::Translator;

/// Locale used when neither config nor caller supplies one.
pub const DEFAULT_LOCALE: &str = "en-US";

/// Static form captions: `(msgid, English literal)`.
///
/// The English literal is used only when the catalog returns the msgid
/// unchanged (i.e. the id is not translated anywhere in that catalog).
pub const CAPTIONS: &[(&str, &str)] = &[
    ("IDS_DEVICE_TXT", "Device"),
    ("IDS_BOOT_SELECTION_TXT", "Boot selection"),
    ("IDS_PARTITION_TYPE_TXT", "Partition scheme"),
    ("IDS_TARGET_SYSTEM_TXT", "Target system"),
    ("IDS_FILE_SYSTEM_TXT", "File system"),
    ("IDS_CLUSTER_SIZE_TXT", "Cluster size"),
    ("IDS_FORMAT_OPTIONS_TXT", "Format Options"),
];

/// Minimal valid UTF-8 `.loc` catalog used when no system asset is present.
///
/// Grammar is the same pollock format as `assets/resources/RCDATA_500.bin`
/// (see `furus_core::i18n`): `l` opens a language block, `t` holds one
/// translation. The English block carries every caption so the fallback
/// chain always has a source text, and the RTL languages are listed so the
/// locale combo and the `rtl` flag stay meaningful offline.
const EMBEDDED_CATALOG: &str = "v 4.14\n\
l \"en-US\" \"English (English)\"\n\
t IDS_DEVICE_TXT \"Device\"\n\
t IDS_BOOT_SELECTION_TXT \"Boot selection\"\n\
t IDS_PARTITION_TYPE_TXT \"Partition scheme\"\n\
t IDS_TARGET_SYSTEM_TXT \"Target system\"\n\
t IDS_FILE_SYSTEM_TXT \"File system\"\n\
t IDS_CLUSTER_SIZE_TXT \"Cluster size\"\n\
t IDS_FORMAT_OPTIONS_TXT \"Format Options\"\n\
l \"de-DE\" \"German (Deutsch)\"\n\
b \"en-US\"\n\
t IDS_DEVICE_TXT \"Gerät\"\n\
t IDS_BOOT_SELECTION_TXT \"Boot-Auswahl\"\n\
l \"fr-FR\" \"French (Français)\"\n\
b \"en-US\"\n\
t IDS_DEVICE_TXT \"Périphérique\"\n\
l \"ar-SA\" \"Arabic (العربية)\"\n\
a \"r\"\n\
b \"en-US\"\n\
l \"he-IL\" \"Hebrew (עברית)\"\n\
a \"r\"\n\
b \"en-US\"\n\
l \"fa-IR\" \"Persian (پارسی)\"\n\
a \"r\"\n\
b \"en-US\"\n\
l \"ur-PK\" \"Urdu (اردو)\"\n\
a \"r\"\n\
b \"en-US\"\n";

/// Read one `"..."` quoted value, returning it and the text after the
/// closing quote. Used only for `l "<tag>" "<display>" ...` header lines.
fn quoted(text: &str) -> Option<(&str, &str)> {
    let rest = text.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some((&rest[..end], &rest[end + 1..]))
}

/// Extract `tag -> display name` from a `.loc` source.
///
/// `furus_core::Catalog` deliberately keeps only translations, so the
/// human-readable language names live in the `l` header lines. Parsing them
/// here keeps that presentation concern out of `furus-core`.
fn display_names(data: &[u8]) -> HashMap<String, String> {
    let mut names = HashMap::new();
    let Ok(text) = std::str::from_utf8(data) else {
        return names;
    };
    for raw in text.lines() {
        let Some(rest) = raw.trim().strip_prefix("l ") else {
            continue;
        };
        let Some((tag, after_tag)) = quoted(rest) else {
            continue;
        };
        let Some((display, _)) = quoted(after_tag) else {
            continue;
        };
        if !tag.is_empty() {
            names.insert(tag.to_string(), display.to_string());
        }
    }
    names
}

/// English literal for a known caption id, when the catalog has no text.
fn english_literal(msgid: &str) -> Option<&'static str> {
    CAPTIONS
        .iter()
        .find(|(id, _)| *id == msgid)
        .map(|(_, english)| *english)
}

/// Asset-or-embedded locale catalog plus the active locale selection.
///
/// Owned data only (`Catalog` parses eagerly into plain Rust values), so
/// this type is `Send`/`Sync` and can be shared with Slint callbacks.
pub struct LocaleCatalog {
    catalog: Catalog,
    display_names: HashMap<String, String>,
    lang: String,
}

impl LocaleCatalog {
    /// Load the first catalog that parses: the system asset, else the
    /// embedded fallback. `lang` is the active selection (`None` → English).
    pub fn load(lang: Option<&str>) -> Self {
        let bytes = Self::asset_bytes().unwrap_or_else(|| EMBEDDED_CATALOG.as_bytes().to_vec());
        Self::from_bytes(&bytes, lang)
    }

    /// Force the embedded fallback (headless tests / deterministic startup).
    pub fn embedded(lang: Option<&str>) -> Self {
        Self::from_bytes(EMBEDDED_CATALOG.as_bytes(), lang)
    }

    /// Build from explicit `.loc` bytes (fixture catalogs in tests).
    pub fn from_bytes(data: &[u8], lang: Option<&str>) -> Self {
        let catalog = Catalog::from_bytes(data).expect("locale catalog bytes must be valid .loc");
        let display_names = display_names(data);
        let lang = Translator::new(&catalog, lang.unwrap_or(DEFAULT_LOCALE))
            .lang()
            .to_string();
        Self {
            catalog,
            display_names,
            lang,
        }
    }

    /// Resolve either shipped asset name. A missing or corrupt asset is not
    /// an error here: the caller falls back to [`EMBEDDED_CATALOG`].
    fn asset_bytes() -> Option<Vec<u8>> {
        // "rufus.loc" is the real upstream asset filename embedded in
        // RCDATA_500.bin; keep it verbatim so locale loading still finds it.
        for name in ["RCDATA_500.bin", "rufus.loc"] {
            let Ok(path) = furus_core::paths::asset_path(name) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if Catalog::from_bytes(&bytes).is_ok() {
                return Some(bytes);
            }
        }
        None
    }

    /// Locale tags in catalog file order (stable across calls and runs for a
    /// given catalog asset).
    pub fn languages(&self) -> Vec<String> {
        self.catalog
            .languages()
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// Human-readable name for `tag`, or the tag itself when unknown.
    pub fn display_name(&self, tag: &str) -> String {
        self.display_names
            .get(tag)
            .cloned()
            .unwrap_or_else(|| tag.to_string())
    }

    /// `(tag, display name)` pairs in stable order for a UI locale model.
    pub fn locale_entries(&self) -> Vec<(String, String)> {
        self.languages()
            .into_iter()
            .map(|tag| {
                let display = self.display_name(&tag);
                (tag, display)
            })
            .collect()
    }

    /// Resolve a UI display label back to its locale tag.
    pub fn tag_for_display(&self, display: &str) -> Option<String> {
        self.locale_entries()
            .into_iter()
            .find(|(_, name)| name == display)
            .map(|(tag, _)| tag)
    }

    /// Translate `msgid` for `lang` via the catalog's fallback chain
    /// (full tag → primary subtag → English). When no translation exists,
    /// the known English literal is used; otherwise the id is returned.
    pub fn translate(&self, lang: &str, msgid: &str) -> String {
        let text = Translator::new(&self.catalog, lang).t(msgid);
        if text == msgid {
            english_literal(msgid).unwrap_or(msgid).to_string()
        } else {
            text.to_string()
        }
    }

    /// Whether `lang` is right-to-left, decided from its primary subtag.
    ///
    /// This is pure presentation: it never changes formatting behaviour.
    pub fn rtl(&self, lang: &str) -> bool {
        let translator = Translator::new(&self.catalog, lang);
        let primary = translator.lang().split('-').next().unwrap_or("");
        matches!(primary, "ar" | "he" | "fa" | "ur")
    }

    /// Active locale tag (normalised once at construction).
    pub fn lang(&self) -> &str {
        &self.lang
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full tag → primary subtag → English → msgid, in one small fixture.
    const FIXTURE: &str = "l \"en-US\" \"English\"\n\
t FULL \"English full\"\n\
t PRIMARY \"English primary\"\n\
t ONLY_EN \"English only\"\n\
l \"de\" \"German\"\n\
t PRIMARY \"German primary\"\n\
l \"de-DE\" \"German (Deutsch)\"\n\
t FULL \"German full\"\n";

    #[test]
    fn embedded_catalog_supplies_english_fallback_without_the_asset() {
        // `embedded()` never touches the filesystem or `$APPDIR`.
        let bridge = LocaleCatalog::embedded(Some(DEFAULT_LOCALE));
        assert_eq!(bridge.display_name("en-US"), "English (English)");
        assert_eq!(bridge.display_name("de-DE"), "German (Deutsch)");
        assert_eq!(bridge.translate("en-US", "IDS_DEVICE_TXT"), "Device");
        assert_eq!(bridge.translate("de-DE", "IDS_DEVICE_TXT"), "Gerät");
        // Unknown locale resolves through the English block, and an unknown
        // msgid is returned verbatim.
        assert_eq!(bridge.translate("xx-YY", "IDS_DEVICE_TXT"), "Device");
        assert_eq!(bridge.translate("xx-YY", "NO_SUCH_ID"), "NO_SUCH_ID");
    }

    #[test]
    fn locale_list_is_stable_and_rtl_flags_only_rtl_languages() {
        let bridge = LocaleCatalog::embedded(Some(DEFAULT_LOCALE));
        let first = bridge.languages();
        assert_eq!(first, bridge.languages(), "order must be stable");
        assert!(first.iter().any(|tag| tag == "en-US"));
        assert!(first.iter().any(|tag| tag == "de-DE"));
        for lang in ["ar-SA", "he-IL", "fa-IR", "ur-PK", "ar", "UR_pk"] {
            assert!(bridge.rtl(lang), "{lang} must be RTL");
        }
        for lang in ["en-US", "de-DE", "fr-FR", "en", "xx-YY", ""] {
            assert!(!bridge.rtl(lang), "{lang} must not be RTL");
        }
    }

    #[test]
    fn translation_falls_back_full_tag_then_primary_then_msgid() {
        let bridge = LocaleCatalog::from_bytes(FIXTURE.as_bytes(), Some("de-DE"));
        assert_eq!(bridge.lang(), "de-de");
        assert_eq!(bridge.translate("de-DE", "FULL"), "German full");
        assert_eq!(bridge.translate("de-DE", "PRIMARY"), "German primary");
        assert_eq!(bridge.translate("de_DE.UTF-8", "PRIMARY"), "German primary");
        assert_eq!(bridge.translate("de-DE", "ONLY_EN"), "English only");
        assert_eq!(bridge.translate("de-DE", "NO_SUCH_ID"), "NO_SUCH_ID");
    }
}
