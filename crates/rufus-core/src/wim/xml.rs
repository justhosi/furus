//! The narrow WIM XML scanner: just enough XML for the image metadata.
//!
//! The input is decoded as UTF-16LE with `String::from_utf16_lossy` (a
//! `FF FE` BOM is stripped when present; a trailing odd byte is
//! dropped). Only little-endian is accepted: big-endian bytes decode to
//! garbage in which the scanner simply finds no tags, deterministically.
//! There is no general XML parser and no new dependency on purpose: the
//! WIM XML shape is fixed (`WIM/IMAGE/WINDOWS/VERSION`, a few text
//! fields), so a small hand scanner with explicit caps replaces a
//! library.
//!
//! Scanner rules (all central to the contract, all tested):
//!
//! * Element and attribute names compare ASCII case-insensitively; the
//!   real XML is uppercase.
//! * A tiny explicit stack of open elements (max depth 64): an element
//!   opened deeper is ignored together with its whole subtree (the
//!   subtree is skipped, not failed). A self-closing element opens
//!   nothing and never touches the cap.
//! * `<IMAGE INDEX="1">`: the `INDEX` attribute accepts double or
//!   single quotes with optional whitespace around `=`; entity
//!   references inside the value are decoded. A missing or unparsable
//!   `INDEX` falls back to the 1-based position of the `IMAGE` element
//!   in the document (every `IMAGE` start tag counts, even a skipped
//!   one). A self-closing `<IMAGE/>` still yields an entry (with empty
//!   fields). At most 10_000 entries are stored (the header's
//!   `MAX_IMAGE_COUNT`): further `IMAGE` elements still parse for
//!   structure — depth tracking, the root `TOTALBYTES` — but their
//!   fields are dropped and no entry is added, so the scan keeps going
//!   deterministically instead of stopping at the cap.
//! * Inside an `IMAGE`, the direct-child text of `NAME`, `DISPLAYNAME`
//!   and `DESCRIPTION` is captured, trimmed, entity-decoded and capped
//!   at 4096 characters (the rest of a longer run is dropped).
//!   Whitespace-only or empty text leaves the field `None`; a repeated
//!   element lets the last one win. Mixed content keeps the last text
//!   run: the pending text resets at every tag.
//! * Inside an `IMAGE`, inside `WINDOWS`, inside `VERSION`, the direct
//!   children `MAJOR`, `MINOR` and `BUILD` parse as decimal `u32`. Any
//!   unparsable (or missing) value makes the whole [`WimVersion`]
//!   `None` rather than defaulting to 0; the last closed `VERSION`
//!   wins.
//! * A `TOTALBYTES` that is a direct child of the root `WIM` parses as
//!   decimal `u64` (per-image `TOTALBYTES` elements are ignored); the
//!   last one wins and an unparsable one keeps the previous value.
//! * Entities: `&amp;` `&lt;` `&gt;` `&quot;` `&apos;` and numeric
//!   `&#NN;` / `&#xNN;` (an out-of-range numeric, e.g. a surrogate,
//!   counts as unparsable). An unknown entity stays literal, `&` and
//!   `;` included; an `&` with no `;` within 16 bytes (or with another
//!   `&` first) is literal text.
//! * `CDATA` sections append their content literally (no entity
//!   decoding); comments (`<!-- -->`) and processing instructions
//!   (`<? ?>`, including the `<?xml ?>` declaration) are skipped
//!   without touching the pending text. Other `<!...>` declarations
//!   are skipped to the next `>`.
//! * Malformed or unterminated markup is never an error: the scan stops
//!   and whatever was collected so far is returned. A `<` that opens
//!   nothing (a `<` in text, e.g. `a < b`) stays literal text and the
//!   scan continues; a tag that never closes, an unterminated comment,
//!   `CDATA` or attribute value stops the scan. A stray or mismatched
//!   end tag is ignored outright. At end of input, open elements stay
//!   as collected (`IMAGE` entries persist; pending text and a partial
//!   version are dropped).
//!
//! [`parse`] is infallible (`parse(bytes) -> WimXml`, not a `Result`):
//! nothing in the pipeline can genuinely fail — the decode is lossy,
//! every slice is bounds-checked, every number is validated before
//! parsing, and every allocation is capped (captured text at 4096
//! characters, attribute values at 256, the element stack at depth 64,
//! the image list at 10_000 entries, each entry by the input length).
//! Arbitrary bytes therefore never panic and never grow memory
//! without bound.

use super::header::MAX_IMAGE_COUNT;

/// Cap on captured text per field, in characters.
const MAX_TEXT_CHARS: usize = 4096;
/// Cap on a decoded attribute value, in characters.
const MAX_ATTR_CHARS: usize = 256;

/// How far past an `&` the scanner looks for the closing `;` before
/// calling the `&` literal text.
const MAX_ENTITY_LEN: usize = 16;

/// Max depth of the open-element stack; deeper elements are skipped.
const MAX_DEPTH: usize = 64;

/// One `WINDOWS/VERSION` triple from the WIM XML.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WimVersion {
    /// The `<MAJOR>` value (e.g. 10).
    pub major: u32,
    /// The `<MINOR>` value (e.g. 0).
    pub minor: u32,
    /// The `<BUILD>` value (e.g. 22631).
    pub build: u32,
}

/// One `<IMAGE>` element from the WIM XML.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageXml {
    /// The `INDEX` attribute, or the 1-based document position when the
    /// attribute is missing or unparsable.
    pub index: u32,
    /// The `<NAME>` text, when the XML carries a non-blank one.
    pub name: Option<String>,
    /// The `<DISPLAYNAME>` text, when the XML carries a non-blank one.
    pub display_name: Option<String>,
    /// The `<DESCRIPTION>` text, when the XML carries a non-blank one.
    pub description: Option<String>,
    /// The `WINDOWS/VERSION` triple, when all three of `MAJOR`,
    /// `MINOR` and `BUILD` parsed.
    pub version: Option<WimVersion>,
}

/// The collected WIM XML: one entry per `<IMAGE>` plus the root
/// `<TOTALBYTES>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WimXml {
    /// One entry per `<IMAGE>` element, in document order.
    pub images: Vec<ImageXml>,
    /// The root-level `<TOTALBYTES>` value, when one parsed.
    pub total_bytes: Option<u64>,
}

/// The element kinds the scanner tracks. Anything else is [`Kind::Other`]:
/// still stacked (so depth and parent checks stay honest) but never
/// captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Wim,
    Image,
    Windows,
    Version,
    Name,
    DisplayName,
    Description,
    Major,
    Minor,
    Build,
    TotalBytes,
    Other,
}

/// Map an element name to its kind (ASCII case-insensitive).
fn kind_of(name: &str) -> Kind {
    if name.eq_ignore_ascii_case("WIM") {
        Kind::Wim
    } else if name.eq_ignore_ascii_case("IMAGE") {
        Kind::Image
    } else if name.eq_ignore_ascii_case("WINDOWS") {
        Kind::Windows
    } else if name.eq_ignore_ascii_case("VERSION") {
        Kind::Version
    } else if name.eq_ignore_ascii_case("NAME") {
        Kind::Name
    } else if name.eq_ignore_ascii_case("DISPLAYNAME") {
        Kind::DisplayName
    } else if name.eq_ignore_ascii_case("DESCRIPTION") {
        Kind::Description
    } else if name.eq_ignore_ascii_case("MAJOR") {
        Kind::Major
    } else if name.eq_ignore_ascii_case("MINOR") {
        Kind::Minor
    } else if name.eq_ignore_ascii_case("BUILD") {
        Kind::Build
    } else if name.eq_ignore_ascii_case("TOTALBYTES") {
        Kind::TotalBytes
    } else {
        Kind::Other
    }
}

/// One stacked open element: its kind plus, for `IMAGE`, the index of
/// its entry in the image list.
#[derive(Debug, Clone, Copy)]
struct Open {
    kind: Kind,
    image: Option<usize>,
}

/// True for bytes that may appear in a tag or attribute name.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

/// True for bytes that may start a tag (`<` dispatch only).
fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':')
}

/// Decode one entity body (the text between `&` and `;`): the five
/// named entities and numeric `&#NN;` / `&#xNN;` references. `None`
/// means "unknown": the caller keeps the reference literal.
fn decode_entity(body: &str) -> Option<String> {
    match body {
        "amp" => Some("&".to_string()),
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        _ => {
            let digits = body.strip_prefix('#')?;
            let value = if let Some(hex) = digits
                .strip_prefix('x')
                .or_else(|| digits.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                digits.parse::<u32>().ok()?
            };
            char::from_u32(value).map(|found| found.to_string())
        }
    }
}

/// Push `text` into `out` (tracking the pushed character count in
/// `count`) until `cap` characters are reached.
fn push_chars(out: &mut String, count: &mut usize, text: &str, cap: usize) {
    for next in text.chars() {
        if *count >= cap {
            break;
        }
        out.push(next);
        *count += 1;
    }
}

/// Append `run` to `out` with entity references decoded, stopping once
/// `count` reaches `cap` characters (the rest of the run is dropped, so
/// a hostile text run cannot grow memory). `count` tracks the
/// characters already in `out` and is updated for every push.
fn append_decoded(out: &mut String, count: &mut usize, run: &str, cap: usize) {
    let bytes = run.as_bytes();
    // Start of the not-yet-flushed literal segment.
    let mut segment = 0usize;
    let mut pos = 0usize;
    while *count < cap {
        let Some(&byte) = bytes.get(pos) else {
            break;
        };
        if byte != b'&' {
            pos += 1;
            continue;
        }
        // A candidate entity: scan for `;`, giving up at a second `&`
        // or past the length bound (then this `&` is literal text).
        let mut end = pos.saturating_add(1);
        let mut semi: Option<usize> = None;
        while let Some(&next) = bytes.get(end) {
            if end.saturating_sub(pos.saturating_add(1)) >= MAX_ENTITY_LEN {
                break;
            }
            if next == b'&' {
                break;
            }
            if next == b';' {
                semi = Some(end);
                break;
            }
            end += 1;
        }
        let Some(stop) = semi else {
            pos += 1;
            continue;
        };
        if let Some(literal) = run.get(segment..pos) {
            push_chars(out, count, literal, cap);
        }
        if *count >= cap {
            break;
        }
        if let Some(body) = run.get(pos.saturating_add(1)..stop) {
            if let Some(decoded) = decode_entity(body) {
                push_chars(out, count, &decoded, cap);
            } else if let Some(literal) = run.get(pos..stop.saturating_add(1)) {
                // Unknown entity: stays literal, `&` and `;` included.
                push_chars(out, count, literal, cap);
            }
        }
        segment = stop.saturating_add(1);
        pos = stop.saturating_add(1);
    }
    // Flush the tail (which is the whole run when no `&` was seen).
    if *count < cap
        && let Some(literal) = run.get(segment..)
    {
        push_chars(out, count, literal, cap);
    }
}

/// Decode entity references in `value`, capped at `cap` characters.
fn decode_entities_capped(value: &str, cap: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    append_decoded(&mut out, &mut count, value, cap);
    out
}

/// Parse the `INDEX` attribute out of a start-tag attribute region (the
/// text between the element name and the closing `>` or `/>`).
/// Returns `None` when no `INDEX` attribute parsed: the caller falls
/// back to the document position. An unterminated attribute value also
/// yields `None` (the tag is malformed; later attributes are not
/// consulted).
fn parse_index_attr(region: &str) -> Option<u32> {
    let raw = region.as_bytes();
    let mut pos = 0;
    while pos < raw.len() {
        while matches!(raw.get(pos), Some(next) if next.is_ascii_whitespace()) {
            pos += 1;
        }
        if raw.get(pos).is_none() {
            break;
        }
        let name_start = pos;
        while let Some(&next) = raw.get(pos) {
            if !is_name_byte(next) {
                break;
            }
            pos += 1;
        }
        if pos == name_start {
            // A stray byte (a leftover `/`, `=`, ...): step over it so
            // the scan always makes progress.
            pos += 1;
            continue;
        }
        let name = region.get(name_start..pos);
        while matches!(raw.get(pos), Some(next) if next.is_ascii_whitespace()) {
            pos += 1;
        }
        if raw.get(pos) != Some(&b'=') {
            // A valueless attribute: keep scanning after it.
            continue;
        }
        pos += 1;
        while matches!(raw.get(pos), Some(next) if next.is_ascii_whitespace()) {
            pos += 1;
        }
        let &quote = raw.get(pos)?;
        if quote != b'\'' && quote != b'"' {
            // Unquoted values are not INDEX-shaped: keep scanning.
            continue;
        }
        pos += 1;
        let mut end = pos;
        while let Some(&next) = raw.get(end) {
            if next == quote {
                break;
            }
            end += 1;
        }
        if raw.get(end) != Some(&quote) {
            return None;
        }
        if name.is_some_and(|found| found.eq_ignore_ascii_case("INDEX")) {
            return index_value(region.get(pos..end).unwrap_or(""));
        }
        pos = end.saturating_add(1);
    }
    None
}

/// Parse one `INDEX` attribute value: entity-decoded, trimmed, ASCII
/// digits only (at most 10, so the `u32` parse cannot overflow into an
/// error that is not already `None`).
fn index_value(value: &str) -> Option<u32> {
    let decoded = decode_entities_capped(value, MAX_ATTR_CHARS);
    let trimmed = decoded.trim();
    if trimmed.is_empty() || trimmed.len() > 10 {
        return None;
    }
    if !trimmed.bytes().all(|next| next.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

/// Find `needle` in `raw` at or after `from`.
fn find_byte(raw: &[u8], from: usize, needle: u8) -> Option<usize> {
    let mut pos = from;
    while let Some(&next) = raw.get(pos) {
        if next == needle {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

/// Find `needle` in `raw` at or after `from`.
fn find_slice(raw: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(from);
    }
    let mut pos = from;
    while raw.get(pos).is_some() {
        let mut hits = true;
        for (offset, &wanted) in needle.iter().enumerate() {
            if raw.get(pos.saturating_add(offset)) != Some(&wanted) {
                hits = false;
                break;
            }
        }
        if hits {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

/// End of the tag name starting at `from` (first non-name byte).
fn tag_name_end(raw: &[u8], mut pos: usize) -> usize {
    while let Some(&next) = raw.get(pos) {
        if !is_name_byte(next) {
            break;
        }
        pos += 1;
    }
    pos
}

/// Decode UTF-16LE bytes to a string: lossy (never fails), BOM stripped
/// when present, a trailing odd byte dropped. Only little-endian is
/// accepted (see the module docs).
fn decode_utf16le(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len().saturating_add(1) / 2);
    let mut pos: usize = 0;
    while pos.saturating_add(1) < bytes.len() {
        match (bytes.get(pos), bytes.get(pos.saturating_add(1))) {
            (Some(&low), Some(&high)) => units.push(u16::from_le_bytes([low, high])),
            _ => break,
        }
        pos = pos.saturating_add(2);
    }
    let text = String::from_utf16_lossy(&units);
    match text.strip_prefix('\u{FEFF}') {
        Some(rest) => rest.to_string(),
        None => text,
    }
}

/// The scanner state: everything collected so far plus the open-element
/// stack and the pending text of the innermost element.
#[derive(Debug, Default)]
struct Scanner {
    images: Vec<ImageXml>,
    total_bytes: Option<u64>,
    stack: Vec<Open>,
    /// While non-zero, elements are ignored with their whole subtree
    /// (the over-depth element that opened the skip plus one per nested
    /// start tag, minus one per end tag).
    skip: usize,
    /// 1-based count of `IMAGE` start tags seen (the `INDEX` fallback).
    image_seq: u32,
    ver_major: Option<u32>,
    ver_minor: Option<u32>,
    ver_build: Option<u32>,
    /// Any in-context version part failed to parse: the version stays
    /// `None` rather than defaulting to 0.
    ver_bad: bool,
    /// Innermost image enclosing the current `VERSION`, if any.
    ver_image: Option<usize>,
    pending: String,
    pending_chars: usize,
}

impl Scanner {
    /// Append a text run (with entity decoding) unless inside skipped
    /// markup.
    fn push_text(&mut self, run: &str) {
        if self.skip > 0 || run.is_empty() {
            return;
        }
        append_decoded(
            &mut self.pending,
            &mut self.pending_chars,
            run,
            MAX_TEXT_CHARS,
        );
    }

    /// Append `CDATA` content literally (no entity decoding), unless
    /// inside skipped markup.
    fn push_raw(&mut self, content: &str) {
        if self.skip > 0 || content.is_empty() {
            return;
        }
        push_chars(
            &mut self.pending,
            &mut self.pending_chars,
            content,
            MAX_TEXT_CHARS,
        );
    }

    /// The innermost enclosing image entry, if any.
    fn innermost_image(&self) -> Option<usize> {
        let mut pos = self.stack.len();
        while pos > 0 {
            pos -= 1;
            if let Some(Open {
                kind: Kind::Image,
                image: Some(at),
            }) = self.stack.get(pos).copied()
            {
                return Some(at);
            }
        }
        None
    }

    /// Handle a start tag (the `INDEX` value was parsed by the caller;
    /// `None` unless this is an `IMAGE` tag with a good attribute).
    fn start_tag(&mut self, kind: Kind, index: Option<u32>, self_closing: bool) {
        self.pending.clear();
        self.pending_chars = 0;
        if kind == Kind::Image {
            self.image_seq = self.image_seq.saturating_add(1);
        }
        if self.skip > 0 {
            if !self_closing {
                self.skip += 1;
            }
            return;
        }
        if self_closing {
            // A self-closing element opens nothing (never touches the
            // depth cap): only an `IMAGE` leaves a trace, an entry with
            // empty fields (still subject to the image cap below).
            if kind == Kind::Image && self.images.len() < MAX_IMAGE_COUNT as usize {
                let fallback = self.image_seq;
                self.images.push(ImageXml {
                    index: match index {
                        Some(found) => found,
                        None => fallback,
                    },
                    ..ImageXml::default()
                });
            }
            return;
        }
        if self.stack.len() >= MAX_DEPTH {
            // Over the cap: ignore the element and its whole subtree.
            self.skip = 1;
            return;
        }
        match kind {
            Kind::Image => {
                // Past the cap the element still parses for structure
                // (stack, depth, root TOTALBYTES) but its fields are
                // dropped: the open element carries no entry index, so
                // no capture below can reach the image list.
                let entry = if self.images.len() < MAX_IMAGE_COUNT as usize {
                    let at = self.images.len();
                    let fallback = self.image_seq;
                    self.images.push(ImageXml {
                        index: match index {
                            Some(found) => found,
                            None => fallback,
                        },
                        ..ImageXml::default()
                    });
                    Some(at)
                } else {
                    None
                };
                self.stack.push(Open { kind, image: entry });
            }
            Kind::Version => {
                self.ver_major = None;
                self.ver_minor = None;
                self.ver_build = None;
                self.ver_bad = false;
                self.ver_image = self.innermost_image();
                self.stack.push(Open { kind, image: None });
            }
            _ => {
                self.stack.push(Open { kind, image: None });
            }
        }
    }

    /// Capture the pending text into a direct child field of an
    /// `IMAGE`: `NAME`, `DISPLAYNAME` or `DESCRIPTION`. Blank text
    /// leaves the field `None`; a repeated element lets the last one
    /// win.
    fn capture_text(&mut self, kind: Kind) {
        if self.stack.len() < 2 {
            return;
        }
        let parent = match self.stack.get(self.stack.len().saturating_sub(2)) {
            Some(open) => *open,
            None => return,
        };
        let at = match parent {
            Open {
                kind: Kind::Image,
                image: Some(at),
            } => at,
            _ => return,
        };
        let trimmed = self.pending.trim();
        if trimmed.is_empty() {
            return;
        }
        let value: String = trimmed.chars().take(MAX_TEXT_CHARS).collect();
        let Some(image) = self.images.get_mut(at) else {
            return;
        };
        match kind {
            Kind::Name => image.name = Some(value),
            Kind::DisplayName => image.display_name = Some(value),
            Kind::Description => image.description = Some(value),
            _ => {}
        }
    }

    /// Capture a `MAJOR` / `MINOR` / `BUILD` value: only when directly
    /// inside `VERSION` inside `WINDOWS` with an `IMAGE` ancestor. An
    /// unparsable value poisons the version (`ver_bad`) so the whole
    /// [`WimVersion`] stays `None` rather than defaulting to 0.
    fn capture_version_part(&mut self, kind: Kind) {
        let depth = self.stack.len();
        if depth < 3 {
            return;
        }
        let (grandparent, parent) = match (
            self.stack.get(depth.saturating_sub(3)),
            self.stack.get(depth.saturating_sub(2)),
        ) {
            (Some(grandparent), Some(parent)) => (*grandparent, *parent),
            _ => return,
        };
        if parent.kind != Kind::Version || grandparent.kind != Kind::Windows {
            return;
        }
        let mut image: Option<usize> = None;
        let mut pos = depth.saturating_sub(3);
        while pos > 0 {
            pos -= 1;
            if let Some(Open {
                kind: Kind::Image,
                image: Some(at),
            }) = self.stack.get(pos).copied()
            {
                image = Some(at);
                break;
            }
        }
        let Some(at) = image else {
            return;
        };
        let trimmed = self.pending.trim();
        let value = if trimmed.is_empty()
            || trimmed.len() > 10
            || !trimmed.bytes().all(|next| next.is_ascii_digit())
        {
            None
        } else {
            trimmed.parse::<u32>().ok()
        };
        match value {
            Some(found) => {
                let slot = match kind {
                    Kind::Major => &mut self.ver_major,
                    Kind::Minor => &mut self.ver_minor,
                    _ => &mut self.ver_build,
                };
                *slot = Some(found);
                self.ver_image = Some(at);
            }
            None => {
                self.ver_bad = true;
            }
        }
    }

    /// Handle an end tag: stray and mismatched end tags are ignored
    /// outright (no pop, pending text kept); a match finalises the
    /// capture for that element, pops it and resets the pending text.
    fn end_tag(&mut self, kind: Kind) {
        if self.skip > 0 {
            self.skip -= 1;
            self.pending.clear();
            self.pending_chars = 0;
            return;
        }
        let top = match self.stack.last() {
            Some(open) => *open,
            None => return,
        };
        if top.kind != kind {
            return;
        }
        match kind {
            Kind::Name | Kind::DisplayName | Kind::Description => self.capture_text(kind),
            Kind::Major | Kind::Minor | Kind::Build => self.capture_version_part(kind),
            Kind::Version => {
                match (
                    self.ver_major,
                    self.ver_minor,
                    self.ver_build,
                    self.ver_image,
                ) {
                    (Some(major), Some(minor), Some(build), Some(at)) if !self.ver_bad => {
                        if let Some(image) = self.images.get_mut(at) {
                            // The last closed VERSION wins.
                            image.version = Some(WimVersion {
                                major,
                                minor,
                                build,
                            });
                        }
                    }
                    _ => {}
                }
                self.ver_major = None;
                self.ver_minor = None;
                self.ver_build = None;
                self.ver_bad = false;
                self.ver_image = None;
            }
            Kind::TotalBytes
                if self.stack.len() >= 2
                    && let Some(parent) = self.stack.get(self.stack.len().saturating_sub(2))
                    && parent.kind == Kind::Wim =>
            {
                // Only the root-level TOTALBYTES counts: a direct child
                // of WIM. Per-image ones are ignored.
                let trimmed = self.pending.trim();
                if !trimmed.is_empty()
                    && trimmed.len() <= 20
                    && trimmed.bytes().all(|next| next.is_ascii_digit())
                    && let Ok(found) = trimmed.parse::<u64>()
                {
                    // The last one wins; an unparsable one keeps the
                    // previous value.
                    self.total_bytes = Some(found);
                }
            }
            _ => {}
        }
        self.stack.pop();
        self.pending.clear();
        self.pending_chars = 0;
    }
}

/// Handle the tag at `pos` (where `raw[pos] == b'<'` and `raw[pos+1]`
/// opens a tag): returns the position to continue from, or `None` to
/// stop the whole scan (malformed or unterminated markup).
fn handle_tag(scanner: &mut Scanner, text: &str, raw: &[u8], pos: usize) -> Option<usize> {
    let &next = raw.get(pos.saturating_add(1))?;
    if next == b'!' {
        // Comment, CDATA, or a skipped declaration.
        if text.get(pos..pos.saturating_add(4)) == Some("<!--") {
            let end = find_slice(raw, pos.saturating_add(4), b"-->")?;
            return Some(end.saturating_add(3));
        }
        if text.get(pos..pos.saturating_add(9)) == Some("<![CDATA[") {
            let end = find_slice(raw, pos.saturating_add(9), b"]]>")?;
            if scanner.skip == 0
                && let Some(content) = text.get(pos.saturating_add(9)..end)
            {
                scanner.push_raw(content);
            }
            return Some(end.saturating_add(3));
        }
        let end = find_byte(raw, pos.saturating_add(2), b'>')?;
        return Some(end.saturating_add(1));
    }
    if next == b'?' {
        // Processing instruction (including `<?xml ?>`): skipped.
        let end = find_slice(raw, pos.saturating_add(2), b"?>")?;
        return Some(end.saturating_add(2));
    }
    if next == b'/' {
        // A lenient end tag: optional whitespace, a name, then the
        // first `>` (an unterminated one stops the scan).
        let mut name_at = pos.saturating_add(2);
        while matches!(raw.get(name_at), Some(found) if found.is_ascii_whitespace()) {
            name_at += 1;
        }
        let name_end = tag_name_end(raw, name_at);
        match (text.get(name_at..name_end), find_byte(raw, name_end, b'>')) {
            (Some(name), Some(close)) => {
                scanner.end_tag(kind_of(name));
                Some(close.saturating_add(1))
            }
            _ => None,
        }
    } else {
        // A start tag: name, quoted attributes, `>` or `/>`. A second
        // `<` (or the end of input) before the close stops the scan.
        let name_end = tag_name_end(raw, pos.saturating_add(1));
        let name = text.get(pos.saturating_add(1)..name_end)?;
        let kind = kind_of(name);
        let mut cursor = name_end;
        let mut quote: Option<u8> = None;
        let mut close: Option<usize> = None;
        let mut broken = false;
        while let Some(&found) = raw.get(cursor) {
            if let Some(open) = quote {
                if found == open {
                    quote = None;
                }
            } else if found == b'\'' || found == b'"' {
                quote = Some(found);
            } else if found == b'>' {
                close = Some(cursor);
                break;
            } else if found == b'<' {
                broken = true;
                break;
            }
            cursor += 1;
        }
        if broken {
            return None;
        }
        let stop = close?;
        // Self-closing when the last non-space byte before `>` is `/`.
        let mut back = stop;
        while back > name_end {
            if matches!(raw.get(back.saturating_sub(1)), Some(found) if found.is_ascii_whitespace())
            {
                back -= 1;
            } else {
                break;
            }
        }
        let self_closing = raw.get(back.saturating_sub(1)) == Some(&b'/');
        let attr_end = if self_closing {
            back.saturating_sub(1)
        } else {
            stop
        };
        let index = if kind == Kind::Image {
            text.get(name_end..attr_end).and_then(parse_index_attr)
        } else {
            None
        };
        scanner.start_tag(kind, index, self_closing);
        Some(stop.saturating_add(1))
    }
}

/// Scan decoded text into a [`WimXml`]: malformed or unterminated
/// markup stops the scan with whatever was collected so far (see the
/// module docs). At end of input, open elements stay as collected.
fn scan(text: &str) -> WimXml {
    let mut scanner = Scanner::default();
    let raw = text.as_bytes();
    let mut pos = 0;
    while let Some(&byte) = raw.get(pos) {
        if byte == b'<' {
            if let Some(&next) = raw.get(pos.saturating_add(1)) {
                if next == b'!' || next == b'/' || next == b'?' || is_name_start(next) {
                    match handle_tag(&mut scanner, text, raw, pos) {
                        Some(after) => {
                            pos = after;
                            continue;
                        }
                        None => break,
                    }
                }
            } else {
                // A trailing `<` ends the scan.
                break;
            }
        }
        // A text run (a `<` that opens nothing stays literal text).
        let mut end = pos.saturating_add(1);
        while let Some(&next) = raw.get(end) {
            if next == b'<' {
                break;
            }
            end += 1;
        }
        if let Some(run) = text.get(pos..end) {
            scanner.push_text(run);
        }
        pos = end;
    }
    WimXml {
        images: scanner.images,
        total_bytes: scanner.total_bytes,
    }
}

/// Parse WIM XML bytes into a [`WimXml`]. Infallible by design (see the
/// module docs): arbitrary bytes never fail and never panic, so the
/// caller only decides what a missing field means.
pub fn parse(bytes: &[u8]) -> WimXml {
    scan(&decode_utf16le(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(&[0xFF, 0xFE]);
        }
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    const WINDOWS_XML: &str = "<WIM>
  <IMAGE INDEX=\"1\">
    <NAME>Windows 11 Pro</NAME>
    <DISPLAYNAME>Windows 11 Pro &amp; Extras &#x41;</DISPLAYNAME>
    <DESCRIPTION>Pro <!-- a comment --> edition</DESCRIPTION>
    <TOTALBYTES>111</TOTALBYTES>
    <FLAGS/>
    <WINDOWS>
      <VERSION>
        <MAJOR>10</MAJOR>
        <MINOR>0</MINOR>
        <BUILD>22631</BUILD>
      </VERSION>
    </WINDOWS>
  </IMAGE>
  <IMAGE INDEX='2'>
    <NAME>Windows 11 Home</NAME>
    <WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>22631</BUILD></VERSION></WINDOWS>
  </IMAGE>
  <TOTALBYTES>123456</TOTALBYTES>
</WIM>";

    #[test]
    fn windows_style_xml_parses_per_image() {
        let parsed = parse(&utf16le(WINDOWS_XML, true));
        assert_eq!(parsed.images.len(), 2);
        let first = &parsed.images[0];
        assert_eq!(first.index, 1);
        assert_eq!(first.name.as_deref(), Some("Windows 11 Pro"));
        assert_eq!(
            first.display_name.as_deref(),
            Some("Windows 11 Pro & Extras A")
        );
        assert_eq!(first.description.as_deref(), Some("Pro  edition"));
        assert_eq!(
            first.version,
            Some(WimVersion {
                major: 10,
                minor: 0,
                build: 22631,
            })
        );
        let second = &parsed.images[1];
        assert_eq!(second.index, 2);
        assert_eq!(second.name.as_deref(), Some("Windows 11 Home"));
        assert_eq!(second.display_name, None);
        assert_eq!(second.description, None);
        assert_eq!(
            second.version,
            Some(WimVersion {
                major: 10,
                minor: 0,
                build: 22631,
            })
        );
        // The root TOTALBYTES wins over the per-image one.
        assert_eq!(parsed.total_bytes, Some(123456));
    }

    #[test]
    fn index_spacing_quotes_and_fallback_position() {
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX = \"7\"><NAME>Spaced</NAME></IMAGE><IMAGE><NAME>NoIndex</NAME></IMAGE><IMAGE INDEX=\"bogus\"><NAME>Bad</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images.len(), 3);
        assert_eq!(parsed.images[0].index, 7);
        assert_eq!(parsed.images[1].index, 2);
        // An unparsable INDEX falls back to the document position.
        assert_eq!(parsed.images[2].index, 3);
    }

    #[test]
    fn entities_decode_and_unknown_ones_stay_literal() {
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>A &bogus; B &#65; C &#x43; D &lt;E&gt; &quot;F&quot; &apos;G&apos; &amp;</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(
            parsed.images[0].name.as_deref(),
            Some("A &bogus; B A C C D <E> \"F\" 'G' &")
        );
    }

    #[test]
    fn unparsable_version_is_none_not_zero() {
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>X</NAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>x</MINOR><BUILD>22631</BUILD></VERSION></WINDOWS></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images[0].version, None);

        // A missing part poisons the version the same way.
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>X</NAME><WINDOWS><VERSION><MAJOR>10</MAJOR><BUILD>22631</BUILD></VERSION></WINDOWS></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images[0].version, None);

        // A version outside WINDOWS/IMAGE is ignored, not captured.
        let parsed = parse(&utf16le(
            "<WIM><VERSION><MAJOR>1</MAJOR><MINOR>2</MINOR><BUILD>3</BUILD></VERSION><IMAGE INDEX=\"1\"><NAME>X</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images[0].version, None);
    }

    #[test]
    fn self_closing_image_yields_an_empty_entry() {
        let parsed = parse(&utf16le("<WIM><IMAGE INDEX=\"1\"/></WIM>", true));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(
            parsed.images[0],
            ImageXml {
                index: 1,
                ..ImageXml::default()
            }
        );
    }

    #[test]
    fn duplicate_name_is_last_wins() {
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>First</NAME><NAME>Second</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Second"));
    }

    #[test]
    fn last_closed_version_wins_without_leaking() {
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>A</NAME><WINDOWS><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>1000</BUILD></VERSION><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>2000</BUILD></VERSION></WINDOWS></IMAGE><IMAGE INDEX=\"2\"><NAME>B</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images.len(), 2);
        assert_eq!(
            parsed.images[0].version,
            Some(WimVersion {
                major: 10,
                minor: 0,
                build: 2000,
            })
        );
        // The second image has no VERSION: nothing leaks into it.
        assert_eq!(parsed.images[1].version, None);
    }

    #[test]
    fn image_list_is_capped_and_parsing_continues() {
        let mut xml = "<WIM>".to_string();
        xml.push_str(&"<IMAGE/>".repeat(10_001));
        xml.push_str("<TOTALBYTES>7</TOTALBYTES></WIM>");
        let parsed = parse(&utf16le(&xml, true));
        assert_eq!(parsed.images.len(), 10_000);
        // The scan kept going past the cap: the root TOTALBYTES still
        // parsed.
        assert_eq!(parsed.total_bytes, Some(7));
    }

    #[test]
    fn malformed_markup_never_panics_and_keeps_what_was_collected() {
        // Truncated mid-tag: the IMAGE entry exists, the name is lost.
        let parsed = parse(&utf16le("<WIM><IMAGE INDEX=\"1\"><NA", true));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name, None);

        // Truncated inside the attribute: the tag never closes.
        let parsed = parse(&utf16le("<WIM><IMAGE INDEX=\"1", true));
        assert!(parsed.images.is_empty());

        // Unclosed IMAGE: the closed NAME is still collected.
        let parsed = parse(&utf16le("<WIM><IMAGE INDEX=\"1\"><NAME>Foo</NAME>", true));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Foo"));

        // A `<` in text stays literal and the scan continues past it.
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>a < b</NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images[0].name.as_deref(), Some("a < b"));

        // Unterminated comment stops the scan with prior work kept.
        let parsed = parse(&utf16le(
            "<WIM><IMAGE INDEX=\"1\"><NAME>Foo</NAME></IMAGE><!-- never closed",
            true,
        ));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Foo"));

        // Nested deeper than the cap: the NAME is ignored, the IMAGE
        // entry (opened in bounds) persists.
        let mut deep = "<WIM><IMAGE INDEX=\"1\">".to_string();
        deep.push_str(&"<A>".repeat(70));
        deep.push_str("<NAME>Deep</NAME>");
        deep.push_str(&"</A>".repeat(70));
        deep.push_str("</IMAGE></WIM>");
        let parsed = parse(&utf16le(&deep, true));
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name, None);

        // Empty and garbage inputs yield empty results, never a panic.
        assert_eq!(parse(b""), WimXml::default());
        assert_eq!(parse(b"\x00\x01\x02\xff\xfe"), WimXml::default());
    }

    #[test]
    fn cdata_is_text_and_pi_is_skipped() {
        let parsed = parse(&utf16le(
            "<?xml version=\"1.0\"?><WIM><IMAGE INDEX=\"1\"><NAME><![CDATA[A<B>&amp;]]></NAME></IMAGE></WIM>",
            true,
        ));
        assert_eq!(parsed.images[0].name.as_deref(), Some("A<B>&amp;"));
    }

    #[test]
    fn case_insensitive_names_and_trailing_odd_byte() {
        let mut bytes = utf16le(
            "<wim><image index=\"1\"><name>Lower</name></image></wim>",
            false,
        );
        bytes.push(0x99);
        let parsed = parse(&bytes);
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].name.as_deref(), Some("Lower"));
    }
}
