//! Directory entries (S09 part B): the byte-level and rule-level logic
//! the live [`Fat32`](crate::fs::fat32::Fat32) volume drives — name
//! validation, 8.3 rendering with collision tails, LFN run imaging and
//! reassembly, per-entry field access and the full 32-byte entry image
//! builders.
//!
//! The module is deliberately pure: nothing here touches a
//! [`Volume`](crate::fs::Volume), so every rule and byte map is testable
//! without I/O. The volume type (S09 part B, `volume.rs`) supplies the
//! scanning and the read-modify-write; the *rules* live here, next to
//! the volume-label rules of [`bpb`](crate::fs::fat32::bpb), with one
//! job each:
//!
//! * writes: [`validate_name`] gates user paths; [`sfn_candidate`] and
//!   [`needs_lfn`] derive what the on-disk layout must carry; the image
//!   builders render the exact 32-byte entries;
//! * reads: [`reassemble_lfn`] turns a scanned LFN run back into a name
//!   (falling back to `None` — never an error — on a corrupt run), and
//!   the field accessors decode the 32-byte images.
//!
//! Terminology of the 8.3 rendering follows the Rufus/Windows family:
//! the *base* is the pre-extension part of the uppercase name, the
//! numeric tail (`~1`..) rides *inside* the 8-character budget so the
//! 11-byte short field always splits `base(8) + extension(3)`, and the
//! *given* case of the caller is preserved in the LFN run, never in the
//! short field, which is always uppercase. The NT-byte lowercase alias
//! (0x0C/0x10) is deliberately not used: short fields are written with
//! NT byte 0 and the LFN run alone carries the caller's case.

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::fat32::put_u16;

/// The 32-byte size of every directory entry (short or LFN).
pub const ENTRY_LEN: usize = 32;

/// The 11 bytes of a short-name field: 8 base + 3 extension, spaces
/// padded.
pub const SHORT_NAME_LEN: usize = 11;

/// UTF-16 code units carried by one LFN entry (5 + 6 + 2).
pub const LFN_PIECE_UNITS: usize = 13;

/// Most LFN entries a name may spend: 255 UTF-16 units plus the
/// terminator entry round up to at most 20 pieces (`20 × 13 = 260 ≥ 256`).
const MAX_LFN_PIECES: usize = 20;

/// Longest user name in UTF-16 code units the file API takes. This is
/// the FAT long-name law itself; longer names are refused, not cropped.
const MAX_NAME_UNITS: usize = 255;

/// Attribute byte of a plain file entry: the archive bit, as every
/// normally written FAT file carries (read-only, hidden, system clear).
pub const ATTR_ARCHIVE: u8 = 0x20;
/// Attribute byte of a directory entry.
pub const ATTR_DIRECTORY: u8 = 0x10;
/// Attribute byte of a volume-label entry.
pub const ATTR_VOLUME_ID: u8 = 0x08;
/// Attribute byte of an LFN entry: read-only | hidden | system | label,
/// exactly 0x0F. Check [`is_lfn`] *before* every other attribute test —
/// 0x0F contains the label bit and would otherwise read as a label.
pub const ATTR_LONG_NAME: u8 = 0x0F;
/// Bits 6-7 of the attribute byte are reserved on short entries:
/// cleared on write, tolerated on read.
const ATTR_RESERVED: u8 = 0xC0;

/// Characters Windows refuses in file and directory names: `" * / : < >
/// ? \ |`. [`bpb`]'s label encoder carries the same *set* for volume
/// labels; the lists stay separate constants because a *name* keeps
/// extra rules of its own (trailing dot/space, the 255-unit cap,
/// `.`/`..`) while the label field's only extra rule is the 11-byte cap.
const FORBIDDEN_NAME_CHARS: [u8; 9] = *b"\"*/:<>?\\|";

/// The short-name field of a `.` entry (a dot plus ten spaces).
pub const DOT_FIELD: [u8; 11] = *b".          ";
/// The short-name field of a `..` entry (two dots plus nine spaces).
pub const DOTDOT_FIELD: [u8; 11] = *b"..         ";

/// The first byte of a slot that never carried an entry, and the
/// end-of-directory marker: everything from the first 0x00 onward is
/// free-directory tail.
pub const END_OF_DIR_MARKER: u8 = 0x00;
/// The first byte a deleted entry carries; deleted entries are
/// reusable slot-wise.
pub const DELETED_MARKER: u8 = 0xE5;
/// The spec's KANJI-lead alias of a deleted first byte (every real
/// formatter treats it as deleted; this crate never writes it).
pub const KANJI_DELETED_MARKER: u8 = 0x05;

/// The raw DOS timestamp pair every entry stores: the `(date, time)`
/// 16-bit fields at their spec encodings
/// (`((year-1980) << 9) | (month << 5) | day` and
/// `(hour << 11) | (minute << 5) | (second / 2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatTime {
    /// DOS date field (the 1980 epoch, 1-based month/day).
    pub date: u16,
    /// DOS time field (2-second tick granularity).
    pub time: u16,
}

impl Default for FatTime {
    /// The DOS epoch itself (`1980-01-01 00:00`): the volume's default
    /// "now" so every stamp is deterministic until a caller (a later
    /// slice's pipeline, the tests here) injects the real time.
    fn default() -> Self {
        Self {
            date: (1 << 5) | 1,
            time: 0,
        }
    }
}

impl FatTime {
    /// Encode `(year, month, day, hour, minute, second)` wall-clock
    /// values into a DOS stamp.
    ///
    /// Refusals (all [`CoreError::invalid`], naming the offending
    /// field): a month outside `1..=12`, a day outside `1..={max of the
    /// month}` (leap-corrected), an hour outside `0..=23`, a minute or
    /// second outside `0..=59`, or a year above 2107 — the DOS date
    /// field simply runs out of its 7 year bits.
    ///
    /// The 1980-epoch clamping rule: any year *below* 1980 clamps the
    /// whole stamp to `1980-01-01 00:00:00` instead of erroring — the
    /// FAT timestamp field cannot express earlier moments, and a
    /// "pre-epoch" clock is far likelier than an intentional lie, so the
    /// stamp lands on the first representable moment. (Seconds encode at
    /// 2-second granularity, the DOS field's native tick: a second of 59
    /// rounds down to 58.)
    pub fn from_ymdhms(
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
    ) -> Result<FatTime> {
        if year < 1980 {
            return Ok(FatTime::default());
        }
        if year > 2107 {
            return Err(CoreError::invalid(format!(
                "year {year} is above the dos stamp limit of 2107"
            )));
        }
        if !(1..=12).contains(&month) {
            return Err(CoreError::invalid(format!(
                "month {month} is not a valid month (1..=12)"
            )));
        }
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let month_days: [u16; 12] = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let max_day = month_days.get(usize::from(month - 1)).copied().unwrap_or(0);
        if !(1..=max_day).contains(&day) {
            return Err(CoreError::invalid(format!(
                "day {day} is not valid for month {month} of {year} (1..={max_day})"
            )));
        }
        if hour > 23 {
            return Err(CoreError::invalid(format!(
                "hour {hour} is not a valid hour (0..=23)"
            )));
        }
        if minute > 59 {
            return Err(CoreError::invalid(format!(
                "minute {minute} is not a valid minute (0..=59)"
            )));
        }
        if second > 59 {
            return Err(CoreError::invalid(format!(
                "second {second} is not a valid second (0..=59)"
            )));
        }
        Ok(FatTime {
            date: ((year - 1980) << 9) | (month << 5) | day,
            time: (hour << 11) | (minute << 5) | (second / 2),
        })
    }
}

/// Validate one user-supplied file or directory name (a single path
/// component, already split off the path).
///
/// Refusals (all [`CoreError::invalid`], naming the offending rule):
/// the empty name; a name longer than [`MAX_NAME_UNITS`] UTF-16 units
/// (ASCII names count one unit per byte); any control byte (`< 0x20` or
/// `0x7F`); any non-ASCII byte (`≥ 0x80`) — this file API writes ASCII
/// names only, so a multi-byte UTF-8 name is refused rather than
/// silently re-encoded; any of [`FORBIDDEN_NAME_CHARS`]; a *trailing*
/// dot or trailing space (Windows-incompatible names — leading and
/// interior dots/spaces are legal); and the pure dot names `.` and
/// `..`, which belong to the linkage a generated directory carries,
/// never to a caller's path.
///
/// The [`bpb`](crate::fs::fat32::bpb) rules stay the single source for
/// *volume labels*; this function is the single source for *file and
/// directory names*.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::invalid("a file or directory name is empty"));
    }
    let units = name.chars().map(char::len_utf16).sum::<usize>();
    if units > MAX_NAME_UNITS {
        return Err(CoreError::invalid(format!(
            "name is {units} utf-16 code units long, the fat limit is 255"
        )));
    }
    if name == "." || name == ".." {
        return Err(CoreError::invalid(
            "'.' and '..' are reserved for directory linkage, not user names",
        ));
    }
    for &byte in name.as_bytes() {
        if byte < 0x20 || byte == 0x7F {
            return Err(CoreError::invalid(format!(
                "name carries a control byte (0x{byte:02X}), names are plain ascii text"
            )));
        }
        if byte >= 0x80 {
            return Err(CoreError::invalid(
                "name carries a non-ascii byte, names are plain ascii text",
            ));
        }
        if FORBIDDEN_NAME_CHARS.contains(&byte) {
            let character = char::from_u32(u32::from(byte)).unwrap_or('?');
            return Err(CoreError::invalid(format!(
                "name carries '{character}' which windows forbids in a file name"
            )));
        }
    }
    if name.ends_with('.') {
        return Err(CoreError::invalid(
            "name ends with a dot, which windows refuses (trailing dots are reserved)",
        ));
    }
    if name.ends_with(' ') {
        return Err(CoreError::invalid(
            "name ends with a space, which windows refuses",
        ));
    }
    Ok(())
}

/// The rendered 8.3 candidate for one name: an uppercase,
/// character-stripped *base* (at most 8 bytes after a numeric tail's
/// budget) and an *extension* (at most 3 bytes), both ready for
/// [`short_field`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfnRender {
    /// Base part (forbidden/dot characters stripped, uppercased).
    pub base: String,
    /// Extension part (empty when the name has none).
    pub ext: String,
}

/// Strip every byte 8.3 fields cannot carry: the Windows-forbidden set,
/// dots (the extension split already consumed the last one, but interior
/// or tail dots of the base die here) and — out of paranoia against
/// callers that skipped [`validate_name`] — control and non-ASCII bytes.
/// Spaces stay: they are legal inside both 8.3 fields.
fn strip_hidden_chars(bytes: impl Iterator<Item = u8>) -> String {
    bytes
        .filter(|&byte| {
            (0x20..0x80).contains(&byte) && byte != b'.' && !FORBIDDEN_NAME_CHARS.contains(&byte)
        })
        .map(|byte| char::from_u32(u32::from(byte)).unwrap_or('_'))
        .collect()
}

/// Render the 8.3 candidate of `name`, with the optional numeric tail.
///
/// Rules, in order:
///
/// 1. uppercase the name (ASCII case fold);
/// 2. split at the *last* dot — what follows is the extension;
/// 3. strip forbidden and dot characters from both parts (spaces stay);
/// 4. an extension longer than 3 truncates to 3;
/// 5. a base that strips to nothing means the dot split swallowed the
///    name (`.hidden`): the whole stripped name becomes the base and the
///    extension is abandoned. Should even that stay empty (`"..."`), an
///    underscore base is the last resort — the renderer is total and
///    never fails;
/// 6. `tail: Some(n)` inserts `~n` (n ≥ 1) *before* the extension. The
///    tail eats into the 8-byte budget — the numeric tail uses the full
///    width: a 12-character base truncates to `LONGFILE` without a tail
///    and to `LONGFI~1` with one; a 6-character base becomes `ABCDEF~1`
///    whole;
/// 7. without a tail the base truncates to 8 bytes.
///
/// Truncation never reopens the extension split: the extension is the
/// name's own trailing text (so `a.tar.gz` renders `ATAR.GZ` — the base
/// keeps its interior dot, stripped bare — and therefore carries an LFN;
/// see [`needs_lfn`]).
#[must_use]
pub fn sfn_candidate(name: &str, tail: Option<u32>) -> SfnRender {
    let upper = name.to_ascii_uppercase();
    // Input is ASCII-only where callers validated it; byte arithmetic
    // on the uppercase view stays in bounds through iterator windows,
    // never slices.
    let bytes = upper.as_bytes();
    let dot = bytes.iter().rposition(|&byte| byte == b'.');
    let split = dot.unwrap_or(bytes.len());
    let mut base = strip_hidden_chars(bytes.iter().take(split).copied());
    let mut ext = strip_hidden_chars(bytes.iter().skip(split).skip(1).copied());
    if base.is_empty() {
        base = strip_hidden_chars(bytes.iter().copied());
        if base.is_empty() {
            base.push('_');
        }
        ext.clear();
    }
    ext.truncate(3);
    if let Some(number) = tail {
        // One or more digits plus the tilde: the 8-byte base budget
        // shrinks by the tail's width so base+tail never exceeds 8.
        let tail_text = format!("~{number}");
        let budget = 8usize.checked_sub(tail_text.len()).unwrap_or(1).max(1);
        base.truncate(budget);
        base.push_str(&tail_text);
    }
    base.truncate(8);
    SfnRender { base, ext }
}

/// The 11-byte short-name field of a rendered candidate: base padded to
/// 8, extension padded to 3, all uppercase (the renderer already
/// uppercased).
#[must_use]
pub fn short_field(render: &SfnRender) -> [u8; 11] {
    let mut field = [b' '; 11];
    let base = render.base.as_bytes();
    let ext = render.ext.as_bytes();
    let base_len = base.len().min(8);
    let ext_len = ext.len().min(3);
    if let Some(window) = field.get_mut(..base_len) {
        for (slot, &byte) in window.iter_mut().zip(base) {
            *slot = byte.to_ascii_uppercase();
        }
    }
    if let Some(window) = field.get_mut(8..8 + ext_len) {
        for (slot, &byte) in window.iter_mut().zip(ext) {
            *slot = byte.to_ascii_uppercase();
        }
    }
    field
}

/// The short name as user-visible text: the trimmed base, joined to the
/// trimmed extension by one dot when an extension exists. Interior
/// spaces survive (they are legal inside the field). A byte stream
/// shorter than 11 (a hostile raw directory read) decodes with both
/// windows truncated instead of panicking.
#[must_use]
pub fn short_name_text(field: &[u8]) -> String {
    let base = trimmed_slice(field.get(..8).unwrap_or(field));
    let ext = trimmed_slice(field.get(8..).unwrap_or(&[]));
    let mut text = ascii_text(base);
    if !ext.is_empty() {
        text.push('.');
        text.push_str(&ascii_text(ext));
    }
    text
}

/// The field bytes up to (and excluding) the first NUL — foreign
/// formatters may leave NULs, ours never do — with the *trailing spaces*
/// then dropped: the name data is `chars + space padding`, so interior
/// spaces belong to the data while only the tail is padding.
fn trimmed_slice(bytes: &[u8]) -> &[u8] {
    let cut = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    let window = bytes.get(..cut).unwrap_or(bytes);
    let used = window
        .iter()
        .rposition(|&byte| byte != b' ')
        .map_or(0, |keep| keep + 1);
    window.get(..used).unwrap_or(window)
}

/// ASCII-ish bytes back to a `String`: NUL bytes become `?` so the
/// decoding side of this file API has a total, panic-free text form of a
/// hostile field.
fn ascii_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| char::from_u32(u32::from(byte)).unwrap_or('?'))
        .collect()
}

/// Whether the given name would lose information when stored as its 8.3
/// candidate alone: the rendered short name differs from the name as
/// handed (case folded upper, stripped characters, truncated base or
/// extension) — *or* the short field cannot represent the name at all:
/// a base that ends in a space (`A .TXT`) reads back as `A.TXT`, the
/// space indistinguishable from padding once the field is trimmed, so
/// such names carry an LFN run with the given name too. Truly lossless
/// names carry none — the entry is its own 8.3 form.
#[must_use]
pub fn needs_lfn(name: &str, render: &SfnRender) -> bool {
    let mut text = render.base.clone();
    if !render.ext.is_empty() {
        text.push('.');
        text.push_str(&render.ext);
    }
    // A trailing space inside the *field* is padding, data or both —
    // the reader trims it either way, so only the LFN run can carry
    // the name's real spelling. (The extension cannot end in a space
    // for a validated name — trailing spaces are refused — but the
    // check stays total for hand-built renders.)
    text != name || render.base.ends_with(' ') || render.ext.ends_with(' ')
}

/// The checksum every LFN piece of one entry carries: a right-rotate-add
/// over the 11 short-name bytes (`((chk & 1) << 7) + (chk >> 1) + byte`,
/// 8-bit wrap). A mismatched checksum on read marks the LFN run corrupt
/// — the reader falls back to the short name, never erroring.
#[must_use]
pub fn sfn_checksum(field: &[u8]) -> u8 {
    let mut checksum: u16 = 0;
    for index in 0..SHORT_NAME_LEN {
        let byte = u16::from(field.get(index).copied().unwrap_or(b' '));
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF;
    }
    checksum as u8
}

/// UTF-16 code units of a name: ASCII input means one unit per byte.
/// A non-BMP character (impossible for validated names) saturates into
/// the unit `0` — an input the reassembler would strip as garbage, never
/// a panic.
#[must_use]
pub fn units_of(name: &str) -> Vec<u16> {
    name.chars()
        .map(|character| u16::try_from(u32::from(character)).unwrap_or(0))
        .collect()
}

/// How many LFN entries the name spends: one 13-unit slot per populated
/// chunk, plus one *terminator entry* exactly when the name's unit count
/// is a multiple of 13 (the 0x0000 terminator then needs a repository
/// slot of its own; otherwise it hides inline after the last character).
#[must_use]
pub fn lfn_entry_count(units: usize) -> usize {
    units.saturating_add(1).div_ceil(LFN_PIECE_UNITS)
}

/// The 13 UTF-16 units of LFN entry `piece_index` (0-based, *logical*:
/// piece 0 carries the name's first characters) — the name's units, then
/// exactly one 0x0000 terminator (inline when the name ends mid-piece,
/// the head of the extra entry when the length is a multiple of 13),
/// then 0xFFFF padding.
#[must_use]
pub fn lfn_piece_units(units: &[u16], piece_index: usize) -> [u16; LFN_PIECE_UNITS] {
    let mut image = [0xFFFF_u16; LFN_PIECE_UNITS];
    for (slot, image_slot) in image.iter_mut().enumerate() {
        let absolute = piece_index
            .saturating_mul(LFN_PIECE_UNITS)
            .saturating_add(slot);
        if let Some(&unit) = units.get(absolute) {
            *image_slot = unit;
        } else if absolute == units.len() {
            *image_slot = 0x0000;
        }
        // Past both: stays 0xFFFF padding.
    }
    image
}

/// One LFN entry image: the sequence byte as the caller hands it (the
/// pieces store sequence numbers 1..=20; the *first-in-order* piece —
/// the one physically written last, sitting directly before the short
/// entry — folds the `0x40` flag into that byte itself), the shared
/// checksum of the short field and the 13 UTF-16 units. Attribute is
/// the constant [`ATTR_LONG_NAME`], the type byte stays 0, the two bytes
/// that would hold a first-cluster stay 0 — the full LFN layout.
#[must_use]
pub fn lfn_piece_image(seq: u8, checksum: u8, units: &[u16; LFN_PIECE_UNITS]) -> [u8; ENTRY_LEN] {
    let mut piece = [0u8; ENTRY_LEN];
    if let Some(slot) = piece.get_mut(0) {
        *slot = seq & 0x7F;
    }
    for (position, &unit) in units.iter().enumerate() {
        // Units 1..5 live at bytes 1..11, 6..11 at 14..26, 12..13 at
        // 28..32 — every offset a compile-time constant inside the
        // 32-byte image, so the checked writes cannot miss and drop
        // their `ok`, like [`bpb::fsinfo`](crate::fs::fat32::bpb::fsinfo).
        let at = match position {
            0..=4 => Some(1 + position * 2),
            5..=10 => Some(14 + (position - 5) * 2),
            11..=12 => Some(28 + (position - 11) * 2),
            _ => None,
        };
        if let Some(at) = at {
            put_u16(&mut piece, at, unit).ok();
        }
    }
    if let Some(slot) = piece.get_mut(11) {
        *slot = ATTR_LONG_NAME;
    }
    if let Some(slot) = piece.get_mut(13) {
        *slot = checksum;
    }
    piece
}

/// The UTF-16 units one scanned LFN piece carries (13 of them, padding
/// included as-is — the reassembler knows the name's real end).
#[must_use]
pub fn lfn_piece_units_of(piece: &[u8; ENTRY_LEN]) -> [u16; LFN_PIECE_UNITS] {
    let mut units = [0x0000_u16; LFN_PIECE_UNITS];
    for (position, unit) in units.iter_mut().enumerate() {
        let at = match position {
            0..=4 => Some(1 + position * 2),
            5..=10 => Some(14 + (position - 5) * 2),
            11..=12 => Some(28 + (position - 11) * 2),
            _ => None,
        };
        if let Some(at) = at {
            let low = u16::from(piece.get(at).copied().unwrap_or(0));
            let high = u16::from(piece.get(at + 1).copied().unwrap_or(0));
            // Little-endian pair; `at + 1` stays inside the piece for
            // every offset above (a truncated slice decodes as zeros
            // instead of panicking).
            *unit = (high << 8) | low;
        }
    }
    units
}

/// Reassemble one LFN run into its `String` name.
///
/// `pieces` is the scanned run in physical order — sequence numbers
/// ascending `1..=N`, the flagged (`0x40`) piece *last* — and
/// `checksum` is the short field's checksum every piece must carry.
/// Returns `None` (never an error) on any corruption: a missing flag on
/// the last piece, a sequence gap, a piece count above
/// [`MAX_LFN_PIECES`], a checksum mismatch, a padding unit before the
/// terminator, or a unit sequence that is not valid UTF-16 text.
///
/// The name ends at its first 0x0000 unit; a run without a terminator
/// (a foreign writer's choice) yields the units up to the first 0xFFFF
/// pad, or the whole run when nothing padded.
#[must_use]
pub fn reassemble_lfn(
    pieces: &[([u8; ENTRY_LEN], [u16; LFN_PIECE_UNITS])],
    checksum: u8,
) -> Option<String> {
    let first = pieces.first()?.0.first().copied().unwrap_or(0);
    if (first & 0x40) == 0 {
        return None; // the run lost its first-in-order piece
    }
    let count = usize::from(first & 0x3F);
    if count == 0 || count > MAX_LFN_PIECES || count != pieces.len() {
        return None;
    }
    let mut ordered = vec![0xFFFF_u16; count.saturating_mul(LFN_PIECE_UNITS)];
    // Piece validation: the physical slots run from sequence N (the
    // `0x40` first-in-order piece, written directly before the short
    // entry's predecessors) down to sequence 1, which sits next to the
    // short entry; every piece carries the same checksum.
    for (position, piece) in pieces.iter().enumerate() {
        let seq = piece.0.first().copied().unwrap_or(0);
        let clean = seq & 0x3F;
        let is_flagged = (seq & 0x40) != 0;
        let want_seq = count - position;
        if usize::from(clean) != want_seq || is_flagged != (position == 0) {
            return None; // sequence gap, or a flag in the wrong place
        }
        if piece.0.get(13).copied().unwrap_or(!checksum) != checksum {
            return None; // corrupt checksum: fall back to the short name
        }
        // Sequence k holds characters 13·(k−1)..13·k.
        let start = usize::from(clean)
            .checked_sub(1)
            .and_then(|chunk| chunk.checked_mul(LFN_PIECE_UNITS))?;
        for (offset, unit) in piece.1.iter().enumerate() {
            {
                let slot = ordered.get_mut(start + offset)?;
                *slot = *unit;
            }
        }
    }
    // The name ends at the terminator; a pad (0xFFFF) before it marks
    // the run corrupt.
    let end = match ordered.iter().position(|&unit| unit == 0x0000) {
        Some(end) => {
            if ordered[..end].contains(&0xFFFF) {
                return None;
            }
            end
        }
        None => ordered
            .iter()
            .position(|&unit| unit == 0xFFFF)
            .unwrap_or(ordered.len()),
    };
    String::from_utf16(ordered.get(..end).unwrap_or(&ordered[..])).ok()
}

/// The 11-byte short field of a scanned 32-byte entry (spaces padded;
/// a short input pads by default instead of panicking).
#[must_use]
pub fn short_field_of(entry: &[u8]) -> [u8; SHORT_NAME_LEN] {
    let mut field = [b' '; SHORT_NAME_LEN];
    for (slot, at) in field.iter_mut().zip(0..SHORT_NAME_LEN) {
        if let Some(&byte) = entry.get(at) {
            *slot = byte;
        }
    }
    field
}

/// The attribute byte of a scanned entry.
#[must_use]
pub fn attr_of(entry: &[u8]) -> u8 {
    entry.get(11).copied().unwrap_or(0)
}

/// Whether the entry is scan-contained: *not* the end-of-directory
/// marker (first byte 0x00) and *not* a deleted entry (first byte 0xE5,
/// or 0x05 — the KANJI-lead alias the spec reserves and every formatter
/// treats as deleted).
///
/// The 0x05 rule applies to *short* entries only: inside an LFN run the
/// first byte is the piece sequence number, so `0x05` there is the
/// legitimate high ordinal of a `N`-piece run (a 5-piece run writes
/// 0x45 flagged, 4, 3, 2, 1 — and a longer run writes an unflagged 0x05
/// piece). Reading 0x05 as deleted there silently ate sequence 5 out of
/// every run of six or more pieces and re-used its slot for the next
/// file — an 8.3-truncating, name-corrupting read. An LFN piece is
/// therefore only ever excluded by 0x00 (the end marker) or 0xE5
/// (deleted); its attribute byte ([`ATTR_LONG_NAME`]) decides which
/// rule applies before the first byte is judged.
#[must_use]
pub fn is_usable(entry: &[u8]) -> bool {
    let first = entry.first().copied().unwrap_or(0);
    if attr_of(entry) == ATTR_LONG_NAME {
        // An LFN piece: 0x05 is a legal ordinal, never a deleted lead.
        return !matches!(first, 0x00 | 0xE5);
    }
    !matches!(first, 0x00 | 0xE5 | 0x05)
}

/// Whether a *usable* entry is an LFN piece ([`ATTR_LONG_NAME`]
/// attribute). Call this before [`is_volume_label`] — the 0x0F
/// attribute contains the label bit.
#[must_use]
pub fn is_lfn(entry: &[u8]) -> bool {
    attr_of(entry) == ATTR_LONG_NAME
}

/// Whether a *usable, non-LFN* entry is a volume-label entry: the label
/// bit set and the directory bit clear (real labels are read-only at
/// most).
#[must_use]
pub fn is_volume_label(entry: &[u8]) -> bool {
    let attr = attr_of(entry);
    (attr & ATTR_VOLUME_ID) != 0 && (attr & ATTR_DIRECTORY) == 0
}

/// Whether a *usable* entry names a directory (the directory bit).
#[must_use]
pub fn is_directory(entry: &[u8]) -> bool {
    (attr_of(entry) & ATTR_DIRECTORY) != 0
}

/// Whether an 11-byte short field spells `.` or `..`: a structural
/// entry every directory carries, never a user-visible name.
#[must_use]
pub fn is_dot_entry(field: &[u8; SHORT_NAME_LEN]) -> bool {
    let Some((&first, rest)) = field.split_first() else {
        return false;
    };
    if first != b'.' {
        return false;
    }
    let mut allowed_dot = true;
    for &byte in rest {
        if byte == b' ' {
            continue;
        }
        if byte == b'.' && allowed_dot {
            allowed_dot = false;
            continue;
        }
        return false;
    }
    true
}

/// The entry's first cluster number: the high pair at 20-21 and the low
/// pair at 26-27, little-endian each.
#[must_use]
pub fn first_cluster_of(entry: &[u8]) -> u32 {
    let high_low = u32::from(entry.get(20).copied().unwrap_or(0));
    let high_high = u32::from(entry.get(21).copied().unwrap_or(0));
    let low_low = u32::from(entry.get(26).copied().unwrap_or(0));
    let low_high = u32::from(entry.get(27).copied().unwrap_or(0));
    ((high_high << 8) | high_low) << 16 | (low_high << 8) | low_low
}

/// The entry's file size in bytes (live data bytes for files, 0 for
/// directories).
#[must_use]
pub fn size_of(entry: &[u8]) -> u64 {
    let mut bytes = [0u8; 4];
    for (slot, at) in bytes.iter_mut().zip(28..32) {
        *slot = entry.get(at).copied().unwrap_or(0);
    }
    u64::from(u32::from_le_bytes(bytes))
}

/// The entry's *write* timestamp pair (the carrier the file API reports).
#[must_use]
pub fn write_times_of(entry: &[u8]) -> FatTime {
    FatTime {
        time: u16_pair(
            entry.get(22).copied().unwrap_or(0),
            entry.get(23).copied().unwrap_or(0),
        ),
        date: u16_pair(
            entry.get(24).copied().unwrap_or(0),
            entry.get(25).copied().unwrap_or(0),
        ),
    }
}

/// One u16 from its little-endian byte pair.
fn u16_pair(low: u8, high: u8) -> u16 {
    (u16::from(high) << 8) | u16::from(low)
}

/// Build a full 32-byte entry image: short field, attribute, times
/// (create and write written, the access date gets the same date),
/// first cluster and size. The NT reserved byte (12) sits at 0 — the
/// lowercase-8.3 alias is deliberately unowned; the LFN run carries the
/// caller's case (see the module docs).
#[must_use]
pub fn entry_image(
    short_name: &[u8; SHORT_NAME_LEN],
    attr: u8,
    first_cluster: u32,
    size_bytes: u32,
    times: FatTime,
) -> [u8; ENTRY_LEN] {
    let mut entry = [0u8; ENTRY_LEN];
    if let Some(window) = entry.get_mut(..SHORT_NAME_LEN) {
        window.clone_from_slice(short_name);
    }
    if let Some(slot) = entry.get_mut(11) {
        *slot = attr & !ATTR_RESERVED;
    }
    // create time/date at 14..18
    put_u16(&mut entry, 14, times.time).ok();
    put_u16(&mut entry, 16, times.date).ok();
    // access date at 18..20
    put_u16(&mut entry, 18, times.date).ok();
    // first cluster high at 20..22
    put_u16(&mut entry, 20, (first_cluster >> 16) as u16).ok();
    // write time/date at 22..26
    put_u16(&mut entry, 22, times.time).ok();
    put_u16(&mut entry, 24, times.date).ok();
    // first cluster low at 26..28
    put_u16(&mut entry, 26, first_cluster as u16).ok();
    // size at 28..32
    let size_le = size_bytes.to_le_bytes();
    if let Some(window) = entry.get_mut(28..32) {
        window.copy_from_slice(&size_le);
    }
    entry
}

/// Build the `.`/`..` entry of a generated directory: the dot short
/// field at directory attributes, carrying the linkage cluster.
#[must_use]
pub fn dot_entry_image(
    field: &[u8; SHORT_NAME_LEN],
    cluster: u32,
    times: FatTime,
) -> [u8; ENTRY_LEN] {
    entry_image(field, ATTR_DIRECTORY, cluster, 0, times)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_refuses_every_forbidden_shape() {
        // the whole Windows-forbidden set, control bytes, non-ascii
        for &forbidden in FORBIDDEN_NAME_CHARS.iter() {
            let character = char::from_u32(u32::from(forbidden)).unwrap_or('?');
            let name = format!("x{character}y");
            let error = validate_name(&name).expect_err("forbidden character");
            assert!(error.to_string().contains(character), "{error}");
        }
        for name in [
            "a\u{1}b", "a\u{7f}b", "a\u{fc}b", "", " ", "  ", "a ", "a.", "a\tb",
        ] {
            assert!(validate_name(name).is_err(), "must refuse ({name:?})");
        }
        assert!(validate_name(".").is_err());
        assert!(validate_name("..").is_err());
        // too long: 255 units fit, 256 do not
        let at_limit = "x".repeat(255);
        assert!(validate_name(&at_limit).is_ok(), "255 units is the limit");
        let past_limit = "x".repeat(256);
        let error = validate_name(&past_limit).expect_err("256 units");
        assert!(error.to_string().contains("255"), "{error}");
        // legal shapes: interior dots and spaces, leading dot
        assert!(validate_name("a b").is_ok());
        assert!(validate_name("a.b").is_ok());
        assert!(validate_name(".hidden").is_ok());
        assert!(validate_name("x").is_ok());
    }

    #[test]
    fn sfn_render_truncates_strips_and_upcases() {
        // the pinned LONGFILE / LONGFI~1 example of the brief
        let plain = sfn_candidate("LongFilename.txt", None);
        assert_eq!(plain.base, "LONGFILE");
        assert_eq!(plain.ext, "TXT");
        let tailed = sfn_candidate("LongFilename.txt", Some(1));
        assert_eq!(tailed.base, "LONGFI~1");
        assert_eq!(tailed.ext, "TXT");
        // a 6-char base carries the tail whole: 6 + "~1" = 8
        let six = sfn_candidate("abcdef!.txt", Some(1));
        assert_eq!(six.base, "ABCDEF~1");
        // strips forbidden characters and interior dots, keeps spaces
        let stripped = sfn_candidate("a.b c*d.txt", None);
        assert_eq!(stripped.base, "AB CD");
        assert_eq!(stripped.ext, "TXT");
        // no-dot name: an empty extension, uppercase
        let none = sfn_candidate("ru fus", None);
        assert_eq!(none.base, "RU FUS");
        assert_eq!(none.ext, "");
        // leading-dot name: the dot split swallows the base, the whole
        // stripped name becomes the base and the extension is abandoned
        let hidden = sfn_candidate(".hidden", None);
        assert_eq!(
            hidden,
            SfnRender {
                base: "HIDDEN".to_owned(),
                ext: String::new()
            }
        );
        // dotted-all name falls to the underscore base
        let dots = sfn_candidate("...", None);
        assert_eq!(dots.base, "_");
        // a 2-digit tail leaves 5 base bytes: "LONGFILENAME" → "LONGF~99"
        let two = sfn_candidate("LongFilename.txt", Some(99));
        assert_eq!(two.base, "LONGF~99");
        // multi-dot names split at the last dot; the base keeps its
        // remaining (stripped) dots
        let layered = sfn_candidate("a.tar.gz", None);
        assert_eq!(layered.base, "ATAR");
        assert_eq!(layered.ext, "GZ");
    }

    #[test]
    fn needs_lfn_holds_for_information_loss_only() {
        // lossless candidates carry no LFN run
        assert!(!needs_lfn(
            "READ ME.TXT",
            &sfn_candidate("READ ME.TXT", None)
        ));
        assert!(!needs_lfn("RUFUS", &sfn_candidate("RUFUS", None)));
        assert!(!needs_lfn("A.TXT", &sfn_candidate("A.TXT", None)));
        assert!(!needs_lfn("NO-LFN.BIN", &sfn_candidate("NO-LFN.BIN", None)));
        // case loss, stripped characters, truncation: LFN runs carry
        // the given name
        assert!(needs_lfn("readme.txt", &sfn_candidate("readme.txt", None)));
        assert!(needs_lfn(
            "LongFilename.txt",
            &sfn_candidate("LongFilename.txt", None)
        ));
        assert!(needs_lfn("a*b.txt", &sfn_candidate("a*b.txt", None)));
        assert!(needs_lfn(
            "toolongbasename.txt",
            &sfn_candidate("toolongbasename.txt", None)
        ));
        // a base ending in a space before the dot: the short field
        // trims that space as padding (`A `.TXT` reads back as
        // `A.TXT`), so only an LFN run can carry the spelling
        assert!(needs_lfn("A .TXT", &sfn_candidate("A .TXT", None)));
    }

    #[test]
    fn checksum_is_the_rotate_add_of_the_short_field() {
        // an independent formulation of the published algorithm (right
        // rotate, then add with u8 wrap) the pinned implementation must
        // agree with
        fn reference(bytes: &[u8]) -> u8 {
            let mut checksum: u8 = 0;
            for &byte in bytes {
                checksum = (((u16::from(checksum) & 1) << 7)
                    + (u16::from(checksum) >> 1)
                    + u16::from(byte)) as u8;
            }
            checksum
        }
        for (name, tail) in [
            ("LONGFILE.TXT", None),
            ("LongFilename05.txt", Some(1)),
            ("LongFilename06.txt", Some(2)),
            ("readme.txt", None),
        ] {
            let render = sfn_candidate(name, tail);
            let field = short_field(&render);
            assert_eq!(sfn_checksum(&field), reference(&field), "field of {name:?}");
        }
        // one hand-walked pin, over the full 11-byte field with padding:
        // A → 0x41 → 0xC0 → 0x80 → 0x60 → 0x50 → 0x48 → 0x44 → 0x42 →
        // 0x41 → 0xC0 → 0x80 (the padding spaces keep rotating the top
        // bit down every second step)
        assert_eq!(sfn_checksum(b"A          "), 0x80);
        // the pinned collision pair hashes differently
        let plain = short_field(&sfn_candidate("LongFilename.txt", None));
        let tailed = short_field(&sfn_candidate("LongFilename.txt", Some(1)));
        assert_ne!(sfn_checksum(&plain), sfn_checksum(&tailed));
    }

    #[test]
    fn lfn_piece_image_layout_pinned() {
        let units: [u16; LFN_PIECE_UNITS] = [
            77, 121, 32, 76, 111, 110, 103, 0, 0xFFFF, 0xFFFF, 0, 0xFFFF, 0xFFFF,
        ];
        let sum = sfn_checksum(b"MYLONGNAM     ");
        let piece = lfn_piece_image(0x42, sum, &units);
        assert_eq!(piece[0], 0x42, "seq 2 carries the 0x40 first-in-order flag");
        assert_eq!(piece[11], ATTR_LONG_NAME);
        assert_eq!(piece[12], 0, "LFN type byte stays 0");
        assert_eq!(piece[13], sum, "checksum over the 11 short bytes");
        // chars 1-5 at bytes 1..11 (little-endian utf-16)
        assert_eq!(&piece[1..3], &[0x4D, 0x00]);
        assert_eq!(&piece[3..5], &[0x79, 0x00]);
        // chars 6-11 at 14..26; the first-cluster floor stays zero
        assert_eq!(&piece[14..16], &[0x6E, 0x00], "units[5] = 'n' at 14");
        assert!(piece[26..28].iter().all(|&byte| byte == 0));
        // chars 12-13 at 28..32
        assert_eq!(&piece[28..30], &[0xFF, 0xFF], "units[11] = 0xFFFF at 28");
        // the reassemble side decodes exactly back
        assert_eq!(lfn_piece_units_of(&piece), units);
    }

    #[test]
    fn lfn_piece_fill_and_entry_count_follow_the_name_length() {
        // 10 units spend ONE entry (inline terminator at unit 10)
        let ten = units_of("MyLongName");
        assert_eq!(ten.len(), 10);
        assert_eq!(lfn_entry_count(ten.len()), 1);
        let piece = lfn_piece_units(&ten, 0);
        assert_eq!(&piece[..10], &ten[..]);
        assert_eq!(piece[10], 0x0000, "inline terminator");
        assert_eq!(piece[11], 0xFFFF, "padding past the terminator");

        // exactly 13 units → the terminator needs its own entry
        let fourteen = units_of("MyLongFileName"); // 14 units
        assert_eq!(lfn_entry_count(fourteen.len()), 2);
        let second = lfn_piece_units(&fourteen, 1);
        assert_eq!(second[0], u16::from(b'e'), "unit 13 of the name");
        assert_eq!(second[1], 0x0000, "the terminator rides inline");
        assert!(second[2..].iter().all(|&unit| unit == 0xFFFF));

        // exactly 13 units → terminator entry of its own
        let full = units_of("MyLongPiecesA"); // exactly 13
        assert_eq!(lfn_entry_count(full.len()), 2);
        let extra = lfn_piece_units(&full, 1);
        assert_eq!(extra[0], 0x0000, "the extra terminator entry");
        assert!(extra[1..].iter().all(|&unit| unit == 0xFFFF));

        // 26 units → first two pieces full, the third carries nothing
        // but the terminator
        let long: String = "abcdefghij".repeat(2); // 20
        let mut units26 = units_of(&long);
        units26.extend(units_of("FEDCBA")); // 26
        assert_eq!(units26.len(), 26);
        assert_eq!(lfn_entry_count(26), 3);
        let extra = lfn_piece_units(&units26, 2);
        assert_eq!(extra[0], 0x0000);
        assert!(extra[1..].iter().all(|&unit| unit == 0xFFFF));
        let second_piece = lfn_piece_units(&units26, 1);
        assert_eq!(
            &second_piece[..],
            &units26[13..26],
            "the second piece carries characters 14..26"
        );
    }

    #[test]
    fn reassemble_lfn_round_trips_the_written_layout() {
        let name = "ReadmeLong.txt";
        let units = units_of(name);
        let count = lfn_entry_count(units.len());
        assert_eq!(count, 2);
        let field = short_field(&sfn_candidate(name, Some(1)));
        let sum = sfn_checksum(&field);
        // physical scan order: seq N (flagged 0x40) down to seq 1, which
        // sits directly before the short entry; piece seq k carries
        // characters 13·(k−1)..13·k
        let scanned: Vec<([u8; ENTRY_LEN], [u16; LFN_PIECE_UNITS])> = (0..count)
            .map(|j| {
                let seq = count - j;
                let chunk = seq - 1;
                let tagged = if j == 0 {
                    (seq as u8) | 0x40
                } else {
                    seq as u8
                };
                let image = lfn_piece_image(tagged, sum, &lfn_piece_units(&units, chunk));
                (image, lfn_piece_units_of(&image))
            })
            .collect();
        assert_eq!(
            reassemble_lfn(&scanned, sum).as_deref(),
            Some(name),
            "the written layout reads back as the name"
        );
        // a wrong checksum on the *reader* side also falls back
        assert_eq!(reassemble_lfn(&scanned, sum + 1), None);
    }

    #[test]
    fn reassemble_lfn_refuses_corrupt_runs() {
        let name = "ReadmeLong.txt";
        let units = units_of(name);
        let count = lfn_entry_count(units.len());
        let field = short_field(&sfn_candidate(name, Some(1)));
        let sum = sfn_checksum(&field);
        let scanned: Vec<([u8; ENTRY_LEN], [u16; LFN_PIECE_UNITS])> = (0..count)
            .map(|j| {
                let seq = count - j;
                let chunk = seq - 1;
                let tagged = if j == 0 {
                    (seq as u8) | 0x40
                } else {
                    seq as u8
                };
                let image = lfn_piece_image(tagged, sum, &lfn_piece_units(&units, chunk));
                (image, lfn_piece_units_of(&image))
            })
            .collect();
        // zero sequence number on any piece = reserved garbage
        let mut zeroed = scanned.clone();
        let (first_image, _) = &mut zeroed[0];
        first_image[0] = 0x00;
        assert_eq!(
            reassemble_lfn(&zeroed, sum),
            None,
            "a zero sequence refuses"
        );
        // a run without the flagged first-in-order piece
        assert_eq!(
            reassemble_lfn(
                &scanned
                    .iter()
                    .take(1)
                    .map(|(image, units)| (*image, *units))
                    .collect::<Vec<_>>(),
                sum
            ),
            None,
            "the flagged piece is required"
        );
        // an empty run is not a name
        assert_eq!(reassemble_lfn(&[], sum), None);
        // a pad (0xFFFF) before the terminator marks the run corrupt
        let mut padded = scanned.clone();
        let (_, last_units) = padded.last_mut().expect("two pieces");
        last_units[0] = 0xFFFF;
        assert_eq!(reassemble_lfn(&padded, sum), None);
    }

    #[test]
    fn fat_time_encodes_and_clamps_per_the_epoch_rules() {
        // a plain 21st-century stamp
        let stamp = FatTime::from_ymdhms(2026, 10, 30, 14, 20, 59).expect("2026-10-30 14:20:59");
        assert_eq!(stamp.date, (46 << 9) | (10 << 5) | 30);
        assert_eq!(
            stamp.time,
            (14 << 11) | (20 << 5) | 29,
            "59 s round down to 58"
        );
        // the epoch itself
        assert_eq!(
            FatTime::from_ymdhms(1980, 1, 1, 0, 0, 0).expect("epoch"),
            FatTime::default(),
            "1980-01-01 00:00 is the DOS epoch"
        );
        // the clamp: anything pre-epoch lands on 1980-01-01 00:00
        assert_eq!(
            FatTime::from_ymdhms(1979, 12, 31, 23, 59, 59).expect("pre-epoch clamps"),
            FatTime::default(),
            "1979 clamps to the DOS epoch"
        );
        let default_time = FatTime::default();
        assert_eq!(default_time.date, 0x0021);
        assert_eq!(default_time.time, 0);
        // the top of the DOS field is accepted
        assert!(FatTime::from_ymdhms(2107, 12, 31, 23, 59, 58).is_ok());
    }

    #[test]
    fn fat_time_refuses_out_of_range_input() {
        for (year, month, day, hour, minute, second, fragment) in [
            (2026u16, 13u16, 1u16, 0u16, 0u16, 0u16, "month 13"),
            (2026, 0, 1, 0, 0, 0, "month 0"),
            (2025, 2, 30, 0, 0, 0, "day 30"),
            (2025, 2, 29, 0, 0, 0, "day 29"),
            (2026, 5, 0, 0, 0, 0, "day 0"),
            (2026, 5, 31, 24, 0, 0, "hour 24"),
            (2026, 5, 31, 0, 60, 0, "minute 60"),
            (2026, 5, 31, 0, 0, 60, "second 60"),
            (2108, 1, 1, 0, 0, 0, "2107"),
        ] {
            let error =
                FatTime::from_ymdhms(year, month, day, hour, minute, second).expect_err(fragment);
            assert!(error.to_string().contains(fragment), "{error}");
        }
        // 2028 is a leap year and accepts its February 29
        assert!(FatTime::from_ymdhms(2028, 2, 29, 0, 0, 0).is_ok());
    }

    #[test]
    fn field_accessors_decode_the_written_image() {
        let short = short_field(&sfn_candidate("linking.bin", None));
        let times = FatTime::from_ymdhms(2026, 10, 30, 1, 2, 3).expect("stamp");
        let entry = entry_image(&short, ATTR_ARCHIVE, 12, 4567, times);
        assert_eq!(short_field_of(&entry), short);
        assert_eq!(attr_of(&entry), ATTR_ARCHIVE);
        assert_eq!(first_cluster_of(&entry), 12);
        assert_eq!(size_of(&entry), 4567);
        assert_eq!(write_times_of(&entry), times);
        assert!(is_usable(&entry));
        assert!(!is_lfn(&entry));
        assert!(!is_volume_label(&entry));
        assert!(!is_directory(&entry));

        // directories, dots and labels
        let dot = dot_entry_image(&DOT_FIELD, 5, times);
        assert_eq!(attr_of(&dot), ATTR_DIRECTORY);
        assert!(is_directory(&dot));
        assert_eq!(first_cluster_of(&dot), 5);
        assert_eq!(size_of(&dot), 0);
        let label = entry_image(b"RUFUS      ", ATTR_VOLUME_ID, 0, 0, times);
        assert!(is_volume_label(&label));
        assert!(!is_volume_label(&dot));
        assert!(!is_lfn(&dot), "LFN test comes before label tests");

        // deleted and end markers
        assert!(!is_usable(&[0xE5, 0, 0, 0]));
        assert!(!is_usable(&[0x00, 0, 0, 0]));
        assert!(!is_usable(&[0x05, 0, 0, 0]));
        // the 0x05 KANJI rule is short-entry-only: inside an LFN run
        // that byte is the legitimate ordinal of piece 5
        let piece = lfn_piece_image(5, 0xA5, &[0x41; LFN_PIECE_UNITS]);
        assert_eq!(attr_of(&piece), ATTR_LONG_NAME, "the piece is an LFN");
        assert_eq!(piece.first(), Some(&0x05), "ordinal 5 in the clear");
        assert!(is_usable(&piece), "seq 5 is a live LFN piece");
        // a flagged (first-in-order) 5-piece run lead too
        let flagged = lfn_piece_image(5 | 0x40, 0xA5, &[0x41; LFN_PIECE_UNITS]);
        assert!(is_usable(&flagged));
        // and a genuinely deleted LFN piece is still unusable
        let mut struck = piece;
        if let Some(slot) = struck.first_mut() {
            *slot = 0xE5;
        }
        assert!(!is_usable(&struck));
    }

    #[test]
    fn short_name_text_trims_padding_and_honors_the_dot() {
        assert_eq!(short_name_text(b"LONGFI~1TOK"), "LONGFI~1.TOK");
        assert_eq!(
            short_name_text(b"LONGFI~1TXT"),
            "LONGFI~1.TXT",
            "base and ext join through the dot"
        );
        assert_eq!(
            short_name_text(b"A B     "),
            "A B",
            "trailing pad trimmed, interior kept"
        );
        assert_eq!(short_name_text(b"RU      TXT"), "RU.TXT");
        assert_eq!(short_name_text(b"NOEXT"), "NOEXT");
        // a shorter, hostile field decodes as far as the bytes go
        assert_eq!(short_name_text(b"AB"), "AB");
        assert_eq!(short_name_text(b"A\0B"), "A", "a NUL ends the field");
    }
}
