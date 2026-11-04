//! File-tree copy foundation (S18, slices 1-4 of 7): move an ISO/UDF
//! filesystem onto a real directory, exactly as Rufus does — one
//! directory at a time, deterministic order, progress by bytes,
//! symlinks recreated or dereferenced.
//!
//! PLAN §S18 asks for the image's tree on the target the way Rufus
//! lays it down. This slice builds only the foundation, on purpose:
//!
//! * [`Source`] (see [`source`]) abstracts the two readers behind the
//!   minimum a copy needs — listings, names, kinds, sizes, chunked
//!   reads, link targets — with thin [`IsoSource`] and [`UdfSource`]
//!   adapters. The readers themselves are untouched.
//! * [`DestDir`] writes into one existing directory on
//!   a real filesystem (Rufus copies into a mounted filesystem, never
//!   into a raw image).
//! * [`walk`] copies depth-first in byte-sorted name order with a
//!   fixed-size buffer, refuses a bad destination and a short
//!   filesystem before any write, and reports [`Summary`] counts.
//!   Nesting past the depth cap refuses as a possible directory loop,
//!   in both passes; re-running into a partial destination resumes
//!   it — existing directories are reused and files rewritten whole —
//!   so an interrupted copy recovers by running again. Entering a
//!   reused directory widens `u+wx` for the descent when the stored
//!   mode lacks it (a `0555` directory from an earlier run still
//!   opens), restoring the prior mode afterwards unless the source
//!   carries its own — then applying it is the restore.
//! * Links (this slice): a relative target resolving lexically inside
//!   the copied tree is recreated with the sanitised target; a target
//!   that escapes, is absolute, or names no copied entry is
//!   dereferenced (the resolved file's bytes land under the link's
//!   own name, as Rufus does); a link with no file behind it warns
//!   once naming the link and leaves nothing behind. Links never
//!   descend, even in a directory slot, and no created link ever
//!   points outside the destination.
//!
//! Not here yet: ownership (never applied —
//! it needs privileges), boot/extended attributes, and any CLI
//! wiring.
//!
//! On progress reporting: [`Progress`] is one method on purpose. The
//! pipeline's [`Event`](crate::pipeline::Event)/[`Reporter`](crate::pipeline::Reporter) would
//! drag the step-machine vocabulary (step starts, step finishes, step
//! names) into a module that has no steps, and
//! [`Logger`](crate::log::Logger) is a text log with a file sink and
//! a record cap — a log, not a meter, and progress is a
//! high-frequency numeric signal. A later slice adapts [`Progress`]
//! to the CLI's JSONL stream; until then tests record with a three-line
//! struct.
//!
//! [`Source`]: source::Source

pub mod dest;
pub mod source;

pub use dest::DestDir;
pub use source::Entry;
pub use source::IsoSource;
pub use source::Source;
pub use source::UdfSource;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::path::PathBuf;

use crate::error::CoreError;
use crate::error::Result;
use crate::text::device_text;

/// Fixed copy buffer in bytes (128 KiB): every file streams through
/// this one allocation, so even a huge file costs no more RAM.
const COPY_BUF_LEN: usize = 128 * 1024;

/// Hard ceiling on directory nesting in either pass: a deeper tree is
/// a directory loop (or hostile nesting), refused rather than
/// recursed into a stack overflow. Same order of magnitude as the
/// readers' own caps (`MAX_DIR_DEPTH`/`MAX_WALK_DEPTH`, 32 each).
const MAX_COPY_DEPTH: usize = 64;

/// Copy options: capacity only, for now. Later slices add knobs here
/// (filters, symlink policy, metadata handling) without touching
/// [`walk`]'s signature shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyOptions {
    /// Free bytes on the destination filesystem, when the caller knows
    /// them (`None` skips the up-front capacity check). `std` has no
    /// `statvfs`, so supplying this is the CLI/adapter's job; the copy
    /// refuses before any write when the tree's declared total exceeds
    /// it.
    pub free_bytes: Option<u64>,
}

/// What one [`walk`] moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Directories ensured under the destination (created or reused;
    /// the destination root itself pre-exists and is not counted).
    pub directories: u64,
    /// Regular files written.
    pub files: u64,
    /// File payload bytes copied.
    pub bytes: u64,
    /// Entries whose destination name differs from the source name:
    /// any sanitising rule or collision suffix applied (see
    /// [`walk`]).
    pub renamed: u64,
}

/// Progress sink for [`walk`]: `done_bytes` of `total_bytes` copied
/// so far. Called once up front with `(0, total)`, after every file
/// chunk, and once at completion — a consumer can always tell "done
/// instantly" from "never reported".
pub trait Progress {
    /// Report progress: `done_bytes` of `total_bytes` copied so far.
    fn report(&mut self, done_bytes: u64, total_bytes: u64);

    /// Report a warning line (an over-long name the walk shortens,
    /// a link it skips, a metadata write it cannot apply): the
    /// default body drops it, so the one-method trait
    /// stays source-compatible for implementors that only meter
    /// bytes. Warning texts are ASCII by construction (see the name
    /// rules).
    fn warn(&mut self, _text: &str) {}
}

/// Copy `source` under the existing directory `dest`: depth-first,
/// children sorted by name bytes at every level, files streamed
/// through one fixed buffer. Returns the [`Summary`] counts.
///
/// The copy merges, it does not mirror: entries already in the
/// destination from an earlier, different tree persist as orphans.
/// The replacement policy is remove-and-rewrite per kind — a regular
/// file in the way of a file (or of a dereferenced link, which lands
/// as a regular file) is removed and rewritten, a file or link in the
/// way of a recreated link is removed and relinked, an existing
/// directory is reused — while anything else in either slot refuses:
/// a symlink or directory in a file slot, a file or symlink in a
/// directory slot, a directory in a link slot (a symlink is never
/// traversed, in either direction).
///
/// Destination names are sanitised per component (version suffixes,
/// separators, trailing dots and spaces, length) and de-collided per
/// directory (case-insensitive `~N` suffixes); [`Summary::renamed`]
/// counts every entry stored under a different name, and truncations
/// warn through [`Progress::warn`].
///
/// Links resolve against the source tree, never the destination: a
/// relative target that stays inside and names a copied entry is
/// recreated as a link (counted as a file with no bytes, carrying no
/// metadata — stamping through a link would touch its target); any
/// other target whose file resolves is dereferenced instead (its
/// bytes land under the link's own name with the link's own
/// metadata); a link with no file behind it warns once naming the
/// link and leaves nothing behind. The sizing pass agrees exactly: a
/// recreated link costs nothing, a dereferenced one costs its file's
/// bytes, a skipped one costs nothing.
///
/// Order of checks: the destination must exist as a directory, then
/// the tree's declared total is summed (a second traversal — sources
/// are cheap listings, and the total must be known before any write),
/// then the capacity check, then the copy. An I/O error mid-copy
/// surfaces as [`CoreError::io`](crate::error::CoreError::io) naming
/// the path, and whatever landed before it stays (a copy is not a
/// transaction); cancellation arrives in a later slice.
pub fn walk(
    source: &dyn Source,
    dest: &Path,
    options: &CopyOptions,
    progress: &mut dyn Progress,
) -> Result<Summary> {
    let dest = DestDir::open(dest)?;
    let total = total_bytes(source)?;
    match options.free_bytes {
        Some(free) if total > free => {
            return Err(CoreError::invalid(format!(
                "copy needs {total} bytes but the destination reports {free} free: refusing before any write"
            )));
        }
        _ => {}
    }
    let mut copier = Copier {
        source,
        dest,
        buf: vec![0u8; COPY_BUF_LEN],
        summary: Summary {
            directories: 0,
            files: 0,
            bytes: 0,
            renamed: 0,
        },
        done: 0,
        total,
        progress,
        taken: HashSet::new(),
    };
    copier.progress.report(0, total);
    let mut rel = Vec::new();
    let mut abs = copier.dest.root().to_path_buf();
    copier.copy_dir(&mut rel, &mut abs, 0)?;
    let (done, total) = (copier.done, copier.total);
    copier.progress.report(done, total);
    Ok(copier.summary)
}

/// Children of `dir` (empty means the root) in byte-sorted name
/// order: the one place ordering happens, so every listing the walk
/// consumes is deterministic whatever order the store keeps.
fn sorted_children(source: &dyn Source, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
    let mut children = if dir.is_empty() {
        source.root_entries()?
    } else {
        source.child_entries(dir)?
    };
    children.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(children)
}

/// Refuse descent past [`MAX_COPY_DEPTH`]: a deeper tree is a
/// directory loop (or hostile nesting), refused rather than recursed
/// into a stack overflow. Names the source-side path, which is what
/// loops — the depth probe consults nothing else, so a cyclic
/// [`Source`] fails here in both passes before any byte moves.
fn check_depth(rel: &[Vec<u8>], depth: usize) -> Result<()> {
    if depth > MAX_COPY_DEPTH {
        let mut shown = String::from("/");
        for name in rel {
            shown.push_str(&String::from_utf8_lossy(name));
            shown.push('/');
        }
        return Err(CoreError::invalid(format!(
            "copy of '{shown}' nests past {MAX_COPY_DEPTH} directories: refusing as a possible directory loop"
        )));
    }
    Ok(())
}

/// Highest `~N` collision suffix probed in one directory before
/// refusing: three digits of overflow room past any plausible
/// duplicate run, while a hostile listing cannot make the walk probe
/// forever.
const MAX_COLLISION_SUFFIX: u32 = 999;

/// Longest destination component in bytes: the FAT/exFAT 255-byte
/// ceiling, the tightest common limit, wins over any one target's
/// larger allowance so one tree copies everywhere.
const MAX_COMPONENT_LEN: usize = 255;

/// Refuse the exact reserved names — empty, `.`, `..` — before
/// sanitising: mapping must never launder these into something
/// storable (a `..` rewritten as `_` would hide a traversal attempt
/// instead of reporting it). Names holding `/` are NOT refused here:
/// the sanitiser maps the separator away (see rule 2 below), which
/// defuses traversal — one flat `_` cannot climb — while refusing
/// would brick whole trees over one hostile entry. [`check_name`]
/// still guards the sanitised output (see below).
fn check_reserved(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::invalid(
            "copy refuses an entry with an empty name".to_string(),
        ));
    }
    if name == b"." || name == b".." {
        return Err(CoreError::invalid(format!(
            "copy refuses the reserved entry name '{}'",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(())
}

/// One sanitised destination component: the name plus whether the
/// length rule cut it (and from what), so the caller can warn with
/// both ends.
struct Sanitised {
    name: Vec<u8>,
    truncated_from: Option<Vec<u8>>,
}

/// Sanitize one source name for the destination component, leaving
/// the source path untouched. In order, each with its why:
///
/// 1. Version suffix: drop a trailing `;[0-9]+` — ISO9660 versions
///    are a container artefact, and the readers already strip exact
///    `;1` for display; the destination must not resurrect versions
///    as filename noise. Only a trailing digit run counts, so a
///    legal Rock Ridge name like `my;file.txt` survives
///    byte-identical.
/// 2. Control bytes and separators: every byte below `0x20` and `/`
///    becomes `_` — control bytes are unrepresentable on Windows
///    targets and in most GUI tooling, and `/` must stay the
///    component separator, or one entry becomes several (or an
///    escape) on disk.
/// 3. Trailing dots and spaces: trimmed from the end — Windows and
///    FAT strip them silently, so keeping them would make two names
///    for one file across platforms.
/// 4. Empty result: a name that sanitises to nothing becomes `_` —
///    every entry needs a name, and `_` collides honestly (through
///    the collision rule) instead of vanishing.
/// 5. Length: truncate to [`MAX_COMPONENT_LEN`] bytes without ever
///    splitting a multi-byte sequence (see [`clean_cut_len`]) — the
///    tightest common filesystem ceiling wins over any one target.
///    The trim and the empty fallback run again after the cut: a cut
///    can expose a trailing dot or space, and the result must satisfy
///    every rule above, not just the length.
fn sanitise(name: &[u8]) -> Sanitised {
    let mut out: Vec<u8> = strip_version_suffix(name).to_vec();
    for byte in out.iter_mut() {
        if *byte < 0x20 || *byte == b'/' {
            *byte = b'_';
        }
    }
    trim_trailing_dots_spaces(&mut out);
    let mut truncated_from = None;
    if out.len() > MAX_COMPONENT_LEN {
        let full = std::mem::take(&mut out);
        let cut = clean_cut_len(&full, MAX_COMPONENT_LEN);
        out.extend(full.iter().take(cut).copied());
        truncated_from = Some(full);
    }
    trim_trailing_dots_spaces(&mut out);
    if out.is_empty() {
        out.push(b'_');
    }
    Sanitised {
        name: out,
        truncated_from,
    }
}

/// Split off a trailing `;[0-9]+` version suffix, if present —
/// otherwise the name unchanged. Only a digit run at the very end
/// counts (checked without indexing, so no window can overrun).
fn strip_version_suffix(name: &[u8]) -> &[u8] {
    let Some(semi) = name.iter().rposition(|byte| *byte == b';') else {
        return name;
    };
    let digits = match name.get(semi + 1..) {
        // Unreachable (`semi` indexes the name, so `semi + 1` is in
        // bounds) — `get` still refuses to assume.
        Some(digits) => digits,
        None => return name,
    };
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return name;
    }
    match name.get(..semi) {
        // Unreachable for the same reason: `semi` indexes the name.
        Some(head) => head,
        None => name,
    }
}

/// Trim trailing dots and spaces (rule 3 of [`sanitise`], shared
/// with the collision room-cut below).
fn trim_trailing_dots_spaces(out: &mut Vec<u8>) {
    while matches!(out.last(), Some(b'.') | Some(b' ')) {
        out.pop();
    }
}

/// Byte length usable under `max` without splitting a multi-byte
/// UTF-8 sequence: the rule for over-long names whether valid or
/// not.
///
/// For valid UTF-8 this is exactly a character boundary (a cut inside
/// a sequence backs up to its lead). For invalid UTF-8 the cut backs
/// over at most one incomplete tail sequence to its lead and keeps
/// everything before it byte-identical — stray bytes elsewhere are
/// preserved (only the cut point must not create a NEW split), and a
/// tail of undecodable continuations with no lead in reach keeps the
/// cut: cutting anywhere inside pure garbage is equal, so the rule
/// prefers keeping bytes. `max` past the length is the length.
fn clean_cut_len(bytes: &[u8], max: usize) -> usize {
    let mut end = bytes.len().min(max);
    // Back over trailing continuation bytes to the sequence lead (at
    // most three steps: UTF-8 sequences are at most four bytes).
    let mut back = 0usize;
    while back < 4 && back < end {
        let byte = match bytes.get(end - 1 - back) {
            Some(byte) => *byte,
            None => break,
        };
        if !is_utf8_continuation(byte) {
            // Lead (or ASCII) `back + 1` bytes from the cut: drop the
            // sequence when it overruns the cut, keep it when it fits.
            if back + 1 < utf8_sequence_len(byte) {
                end -= back + 1;
            }
            break;
        }
        back += 1;
    }
    end
}

/// True for UTF-8 continuation bytes (`10xxxxxx`).
fn is_utf8_continuation(byte: u8) -> bool {
    matches!(byte, 0x80..0xC0)
}

/// Expected sequence length for a lead byte (1 for ASCII and for
/// bytes that can never lead — cutting before those is always
/// clean).
fn utf8_sequence_len(lead: u8) -> usize {
    match lead {
        0x00..0x80 => 1,
        0xC0..0xE0 => 2,
        0xE0..0xF0 => 3,
        0xF0..0xF8 => 4,
        _ => 1,
    }
}

/// ASCII-lowercased copy for collision keys: only `A`-`Z` fold (FAT
/// and NTFS compare case-insensitively over ASCII; anything else
/// compares byte-exact, so non-ASCII bytes pass through untouched).
fn ascii_lower(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|byte| byte.to_ascii_lowercase()).collect()
}

/// Split a sanitised name into stem and extension at the last `.`
/// (the extension keeps its dot): collision suffixes go between
/// them. A leading dot is not an extension marker (`.hidden` keeps
/// no extension), so dotfiles suffix at the end.
fn split_ext(name: &[u8]) -> (&[u8], &[u8]) {
    match name.iter().rposition(|byte| *byte == b'.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, b""),
    }
}

/// Render bytes for messages: lossy text through the ASCII device
/// sanitiser, so warning lines stay ASCII no matter what the image
/// names hold (a raw newline in a log line would break line-oriented
/// consumers just as badly as a control byte on disk).
fn display_name(name: &[u8]) -> String {
    device_text(&String::from_utf8_lossy(name))
}

/// Refuse entry names that could escape the destination or confuse
/// the walk: empty names, `.`/`..`, and anything holding `/` (one
/// component must stay one component). Applied to sanitised names as
/// an invariant — sanitising must never output one of these, so this
/// always passes today and guards future rule edits. A NUL byte needs
/// no rule here — the OS refuses it as an I/O error naming the path.
fn check_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::invalid(
            "copy refuses an entry with an empty name".to_string(),
        ));
    }
    if name == b"." || name == b".." {
        return Err(CoreError::invalid(format!(
            "copy refuses the reserved entry name '{}'",
            String::from_utf8_lossy(name)
        )));
    }
    if name.contains(&b'/') {
        return Err(CoreError::invalid(format!(
            "copy refuses the entry name '{}': one component must stay one component",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(())
}

/// Cap on symlink target components examined during resolution: a
/// longer target is hostile (real targets are a handful of
/// components), refused as dangling rather than allocated.
const MAX_LINK_COMPONENTS: usize = 128;

/// Cap on symlink chain steps followed during dereference: a longer
/// chain loops (POSIX allows 40), refused as dangling rather than
/// followed forever.
const MAX_SYMLINK_DEPTH: usize = 40;

/// Split a symlink target on `/`, dropping empty segments (so `//`
/// collapses and a trailing `/` reads as its directory). The caller
/// checks absoluteness separately — emptiness here only means the
/// target was empty or all slashes.
fn split_target(target: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for part in target.split(|byte| *byte == b'/') {
        if part.is_empty() {
            continue;
        }
        out.push(part.to_vec());
    }
    out
}

/// Lexically resolve `target` against `base` (the link's parent
/// directory, as source name bytes), strictly: relative targets that
/// never climb above the root resolve to the path inside, anything
/// absolute, empty or escaping reads as `None`. Dots skip, dot-dots
/// pop, names push; a dot-dot on an empty stack escapes.
fn strict_resolve(base: &[Vec<u8>], target: &[u8]) -> Option<Vec<Vec<u8>>> {
    if target.is_empty() {
        return None;
    }
    if target.first() == Some(&b'/') {
        return None;
    }
    let comps = split_target(target);
    if comps.len() > MAX_LINK_COMPONENTS {
        return None;
    }
    let mut stack = base.to_vec();
    for comp in &comps {
        if comp.as_slice() == b"." {
            continue;
        }
        if comp.as_slice() == b".." {
            stack.pop()?;
            continue;
        }
        stack.push(comp.clone());
    }
    Some(stack)
}

/// Lexically resolve `target` against `base` leniently, for
/// dereference: absolute targets resolve from the root, dot-dots
/// above the root clamp (POSIX `/../a` reads as `/a`), dots skip.
/// Returns `None` only for empty targets and hostile lengths — the
/// caller checks existence separately.
fn lenient_resolve(base: &[Vec<u8>], target: &[u8]) -> Option<Vec<Vec<u8>>> {
    if target.is_empty() {
        return None;
    }
    let comps = split_target(target);
    if comps.is_empty() || comps.len() > MAX_LINK_COMPONENTS {
        return None;
    }
    let mut stack = if target.first() == Some(&b'/') {
        Vec::new()
    } else {
        base.to_vec()
    };
    for comp in &comps {
        if comp.as_slice() == b"." {
            continue;
        }
        if comp.as_slice() == b".." {
            stack.pop();
            continue;
        }
        stack.push(comp.clone());
    }
    Some(stack)
}

/// Look up `path` (source name bytes from the root) through `source`:
/// `Ok(None)` when any component is missing, when descent would pass
/// through a file or a symlink (directory slots holding links are
/// never followed), or when a listing itself fails (target lookup is
/// best-effort — the tree walk still fails fast on its own listings).
/// The empty path (the root) reads as `None` too: the root always
/// exists, but it carries no `Entry` to return.
fn lookup_source(source: &dyn Source, path: &[Vec<u8>]) -> Result<Option<Entry>> {
    if path.is_empty() {
        return Ok(None);
    }
    let mut dir: Vec<Vec<u8>> = Vec::new();
    for (index, comp) in path.iter().enumerate() {
        let children = if dir.is_empty() {
            match source.root_entries() {
                Ok(children) => children,
                Err(_) => return Ok(None),
            }
        } else {
            match source.child_entries(&dir) {
                Ok(children) => children,
                Err(_) => return Ok(None),
            }
        };
        let found = children
            .iter()
            .find(|child| child.name.as_slice() == comp.as_slice());
        let entry = match found {
            Some(entry) => entry.clone(),
            None => return Ok(None),
        };
        let last = index + 1 == path.len();
        if last {
            return Ok(Some(entry));
        }
        if entry.is_symlink() || !entry.is_dir {
            return Ok(None);
        }
        dir.push(comp.clone());
    }
    Ok(None)
}

/// True when `target` (relative to `base`) strictly resolves inside
/// and names an existing entry (or the root): the shape recreated as
/// a symlink. Anything else — absolute, escaping, dangling, or
/// passing through a link — reads as `false` and falls to
/// dereference.
fn strict_link_inside(source: &dyn Source, base: &[Vec<u8>], target: &[u8]) -> bool {
    let resolved = match strict_resolve(base, target) {
        Some(path) => path,
        None => return false,
    };
    if resolved.is_empty() {
        return true;
    }
    match lookup_source(source, &resolved) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(_) => false,
    }
}

/// Resolve `target` (relative to `base`) to a regular file for
/// dereference: lenient resolution, then follow symlink chains (each
/// step lenient against its own parent) up to [`MAX_SYMLINK_DEPTH`].
/// Returns the file's source path and size, or `None` when the target
/// is missing, names a directory, loops, or runs too deep.
fn dereference_file(
    source: &dyn Source,
    base: &[Vec<u8>],
    target: &[u8],
) -> Option<(Vec<Vec<u8>>, u64)> {
    let mut path = lenient_resolve(base, target)?;
    let mut seen: Vec<Vec<Vec<u8>>> = Vec::new();
    for _ in 0..MAX_SYMLINK_DEPTH {
        if seen.contains(&path) {
            return None;
        }
        seen.push(path.clone());
        let entry = match lookup_source(source, &path) {
            Ok(Some(entry)) => entry,
            Ok(None) => return None,
            Err(_) => return None,
        };
        if let Some(next_target) = entry.link {
            let end = path.len().saturating_sub(1);
            let parent: &[Vec<u8>] = match path.get(..end) {
                Some(parent) => parent,
                None => &[],
            };
            let parent_vec = parent.to_vec();
            path = lenient_resolve(&parent_vec, &next_target)?;
            continue;
        }
        if entry.is_dir {
            return None;
        }
        return Some((path, entry.size));
    }
    None
}

/// Sanitise a symlink target for recreation: split on `/`, keep `.`
/// and `..` as navigation, sanitise every other component with
/// [`sanitise`] (no warnings — target shortening stays silent, and a
/// colliding rename may leave the link dangling, see the walk docs),
/// rejoin with `/`. Absolute targets never reach here (they
/// dereference), so no leading slash is preserved.
fn sanitised_target(target: &[u8]) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for part in target.split(|byte| *byte == b'/') {
        if part.is_empty() {
            continue;
        }
        if part == b"." || part == b".." {
            parts.push(part.to_vec());
            continue;
        }
        parts.push(sanitise(part).name);
    }
    let mut out = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    out
}

/// The walk state: everything [`copy_dir`](Copier::copy_dir) threads
/// through the recursion in one struct instead of nine arguments.
struct Copier<'a> {
    source: &'a dyn Source,
    dest: DestDir,
    buf: Vec<u8>,
    summary: Summary,
    done: u64,
    total: u64,
    progress: &'a mut dyn Progress,
    /// Destination names taken in the current directory (ASCII
    /// lowercase keys): cleared on entry to every directory and
    /// saved/restored around each descent, so collisions never leak
    /// across directories in either direction.
    taken: HashSet<Vec<u8>>,
}

/// What placing one name decided: the destination name plus the
/// over-long candidate when the collision room rule shortened the
/// stem, so the caller warns at most once per entry whatever the
/// causes (a truncated-then-collided entry warns once, not once per
/// reason).
struct PlacedName {
    dest: Vec<u8>,
    shortened_from: Option<Vec<u8>>,
}

impl Copier<'_> {
    /// Assign the destination name for one sanitised component in the    /// current directory: first-come keeps its name (entries arrive
    /// byte-sorted, so this is deterministic); a taken name (ASCII
    /// case-insensitive — see [`ascii_lower`]) earns `~N` before the
    /// extension, `N` from 1 to [`MAX_COLLISION_SUFFIX`], then refuses
    /// naming the source entry. The room rule trims a stem the suffix
    /// would overflow (same trailing-dot trim as sanitising, so no
    /// candidate ends dirty); the caller warns at most once per entry
    /// from the returned [`PlacedName`].
    fn assign_unique(&mut self, source: &[u8], sanitised: &[u8]) -> Result<PlacedName> {
        let mut key = ascii_lower(sanitised);
        if !self.taken.contains(&key) {
            self.taken.insert(key);
            return Ok(PlacedName {
                dest: sanitised.to_vec(),
                shortened_from: None,
            });
        }
        let (stem, ext) = split_ext(sanitised);
        for n in 1..=MAX_COLLISION_SUFFIX {
            let suffix = format!("~{n}");
            let room = MAX_COMPONENT_LEN
                .saturating_sub(suffix.len())
                .saturating_sub(ext.len());
            let mut stem_part = stem.to_vec();
            let shortened = stem_part.len() > room;
            if shortened {
                let cut = clean_cut_len(&stem_part, room);
                stem_part.truncate(cut);
                trim_trailing_dots_spaces(&mut stem_part);
            }
            let mut candidate = stem_part;
            candidate.extend_from_slice(suffix.as_bytes());
            candidate.extend_from_slice(ext);
            key = ascii_lower(&candidate);
            if !self.taken.contains(&key) {
                self.taken.insert(key);
                let shortened_from = if shortened {
                    let mut overlong = stem.to_vec();
                    overlong.extend_from_slice(suffix.as_bytes());
                    overlong.extend_from_slice(ext);
                    Some(overlong)
                } else {
                    None
                };
                return Ok(PlacedName {
                    dest: candidate,
                    shortened_from,
                });
            }
        }
        Err(CoreError::invalid(format!(
            "copy refuses '{}': more than {MAX_COLLISION_SUFFIX} case-insensitive collisions in one directory",
            display_name(source),
        )))
    }

    /// Stream `size` bytes of the source file at `src` (name bytes
    /// from the root) into the already-open `file` at destination
    /// `abs`: the shared body behind regular files and dereferenced
    /// links, so both count progress identically. A short read
    /// refuses naming the destination and both counts, exactly like
    /// the capacity check measured them.
    fn stream_from(
        &mut self,
        abs: &Path,
        src: &[Vec<u8>],
        size: u64,
        file: &mut std::fs::File,
    ) -> Result<()> {
        let mut offset = 0u64;
        while offset < size {
            let placed = self.source.read_bytes(src, offset, &mut self.buf)?;
            if placed == 0 {
                return Err(CoreError::invalid(format!(
                    "copy of '{}' ends at {offset} of {size} bytes: refusing a short read",
                    abs.display(),
                )));
            }
            let window = self.buf.get(..placed).ok_or_else(|| {
                CoreError::invalid(format!(
                    "copy window of {placed} bytes runs past the {} byte buffer",
                    self.buf.len()
                ))
            })?;
            file.write_all(window)
                .map_err(|error| CoreError::io(abs, error))?;
            offset = offset.checked_add(placed as u64).ok_or_else(|| {
                CoreError::invalid(format!(
                    "copy offset of '{}' overflows past {size} bytes",
                    abs.display(),
                ))
            })?;
            self.done = self.done.checked_add(placed as u64).ok_or_else(|| {
                CoreError::invalid("copy byte count overflows the counter".to_string())
            })?;
            self.progress.report(self.done, self.total);
        }
        Ok(())
    }

    /// Copy the directory at `rel` (name bytes from the source root)
    /// into `abs`: create each child directory and recurse, stream
    /// each file through the fixed buffer. `depth` counts descents
    /// from the root for [`check_depth`].
    fn copy_dir(&mut self, rel: &mut Vec<Vec<u8>>, abs: &mut PathBuf, depth: usize) -> Result<()> {
        check_depth(rel, depth)?;
        self.taken.clear();
        for child in sorted_children(self.source, rel)? {
            check_reserved(&child.name)?;
            let sanitised = sanitise(&child.name);
            let placed = self.assign_unique(&child.name, &sanitised.name)?;
            // One warning per renamed entry at most: the room
            // shortening wins when both rules fired, else the length
            // truncation; pure collisions stay silent.
            if let Some(overlong) = placed.shortened_from {
                self.progress.warn(&format!(
                    "copy shortens '{}' to '{}' to fit the collision suffix",
                    display_name(&overlong),
                    display_name(&placed.dest),
                ));
            } else if let Some(original) = sanitised.truncated_from {
                self.progress.warn(&format!(
                    "copy shortens over-long '{}' to '{}'",
                    display_name(&original),
                    display_name(&placed.dest),
                ));
            }
            let dest_name = placed.dest;
            check_name(&dest_name)?;
            rel.push(child.name.clone());
            abs.push(OsStr::from_bytes(&dest_name));
            if dest_name.as_slice() != child.name.as_slice() {
                self.summary.renamed = self.summary.renamed.checked_add(1).ok_or_else(|| {
                    CoreError::invalid("copy rename count overflows the counter".to_string())
                })?;
            }
            if let Some(target) = child.link.as_ref() {
                // Links never descend, even in a directory slot: the
                // target resolves against the parent directory (the
                // link's own name is not part of the base).
                let base: &[Vec<u8>] = match rel.split_last() {
                    Some((_, parent)) => parent,
                    None => &[],
                };
                if strict_link_inside(self.source, base, target) {
                    // Inside: recreate as a link with the sanitised
                    // target. Counts as a file with no bytes; no
                    // metadata is applied (setting times or modes
                    // through the link would touch the target).
                    let sanitised = sanitised_target(target);
                    let link_to = Path::new(OsStr::from_bytes(&sanitised));
                    self.dest.replace_symlink(abs, link_to)?;
                    self.summary.files = self.summary.files.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("copy file count overflows the counter".to_string())
                    })?;
                } else if let Some((resolved, size)) = dereference_file(self.source, base, target) {
                    // Outside or dangling-but-resolvable: copy the
                    // target's bytes as a regular file under the
                    // link's own name, with the link's own metadata.
                    let mut file = self.dest.replace_file(abs)?;
                    self.stream_from(abs, &resolved, size, &mut file)?;
                    self.summary.files = self.summary.files.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("copy file count overflows the counter".to_string())
                    })?;
                    self.summary.bytes = self.summary.bytes.checked_add(size).ok_or_else(|| {
                        CoreError::invalid("copy byte count overflows the counter".to_string())
                    })?;
                    if let Err(error) = self.dest.apply_metadata(abs, &child) {
                        self.progress.warn(&format!(
                            "copy cannot apply metadata to '{}': {error}; continuing",
                            abs.display(),
                        ));
                    }
                } else {
                    // No file to copy: warn once naming the link and
                    // leave nothing behind.
                    self.progress.warn(&format!(
                        "copy skips link '{}': its target does not resolve to a file inside \
                         the image; continuing",
                        display_name(&child.name),
                    ));
                }
            } else if child.is_dir {
                self.dest.create_dir(abs)?;
                self.summary.directories =
                    self.summary.directories.checked_add(1).ok_or_else(|| {
                        CoreError::invalid("copy directory count overflows the counter".to_string())
                    })?;
                // Widen a reused read-only directory for the descent:
                // removing and recreating children needs `u+w` on the
                // parent, which an earlier run's mode may lack. Best
                // effort with one warning — the children report for
                // themselves if the directory truly stays shut.
                let saved = match self.dest.enter_writable_dir(abs) {
                    Ok(saved) => saved,
                    Err(error) => {
                        self.progress.warn(&format!(
                            "copy cannot widen '{}': {error}; continuing",
                            abs.display(),
                        ));
                        None
                    }
                };
                // The child's pool must not replace this directory's:
                // save it aside, scan the child with a fresh pool, and
                // restore afterwards — otherwise the parent loses its
                // names to the child (or inherits them back).
                let taken = std::mem::take(&mut self.taken);
                let result = self.copy_dir(rel, abs, depth.saturating_add(1));
                self.taken = taken;
                result?;
                // Metadata lands after the children, as POSIX does: a
                // read-only directory must not block its own children.
                // Best effort (see below): a refused timestamp or mode
                // warns and the copy continues.
                if let Err(error) = self.dest.apply_metadata(abs, &child) {
                    self.progress.warn(&format!(
                        "copy cannot apply metadata to '{}': {error}; continuing",
                        abs.display(),
                    ));
                }
                // No source mode means the entry widened nothing
                // permanent: put back whatever mode it had before, so
                // the destination keeps no trace of the descent.
                // No source mode means the widen left nothing
                // permanent: put back whatever mode the directory had
                // before.
                if child.mode.is_none()
                    && let Some(prior) = saved
                    && let Err(error) = self.dest.restore_mode(abs, prior)
                {
                    self.progress.warn(&format!(
                        "copy cannot restore mode on '{}': {error}; continuing",
                        abs.display(),
                    ));
                }
            } else {
                let mut file = self.dest.replace_file(abs)?;
                self.stream_from(abs, rel, child.size, &mut file)?;
                self.summary.files = self.summary.files.checked_add(1).ok_or_else(|| {
                    CoreError::invalid("copy file count overflows the counter".to_string())
                })?;
                self.summary.bytes =
                    self.summary.bytes.checked_add(child.size).ok_or_else(|| {
                        CoreError::invalid("copy byte count overflows the counter".to_string())
                    })?;
                // Metadata lands after the bytes are complete — and
                // the mode last inside (see `apply_metadata`) so a
                // read-only mode cannot block the timestamp write.
                // Best effort: an unsettable timestamp on vfat must
                // not abort a valid image, so a refusal warns naming
                // the path and the copy continues.
                if let Err(error) = self.dest.apply_metadata(abs, &child) {
                    self.progress.warn(&format!(
                        "copy cannot apply metadata to '{}': {error}; continuing",
                        abs.display(),
                    ));
                }
            }
            rel.pop().ok_or_else(|| {
                CoreError::invalid("copy path stack underflows its push".to_string())
            })?;
            abs.pop();
        }
        Ok(())
    }
}

/// Sum every file size in the tree: the up-front total the capacity
/// check and the progress meter need before any write. A second
/// traversal is deliberate (see [`walk`]); it enforces the same
/// depth bound and name rules as the copy pass, so both passes agree
/// on which trees are copyable.
fn total_bytes(source: &dyn Source) -> Result<u64> {
    fn sum(source: &dyn Source, dir: &mut Vec<Vec<u8>>, depth: usize) -> Result<u64> {
        check_depth(dir, depth)?;
        let mut total = 0u64;
        for child in sorted_children(source, dir)? {
            // Reserved names refuse here exactly like the copy pass
            // (see `copy_dir`): sizing never touches the destination,
            // so only the traversal-blocking rules apply, not the
            // sanitiser.
            check_reserved(&child.name)?;
            if let Some(target) = child.link.as_ref() {
                // Links never descend (even in a directory slot): a
                // strictly-inside target costs nothing (recreated as a
                // link), a dereferenced one costs its file's size, and
                // a dangling one costs nothing (warned and skipped).
                if strict_link_inside(source, dir, target) {
                    continue;
                }
                if let Some((_, size)) = dereference_file(source, dir, target) {
                    total = total.checked_add(size).ok_or_else(|| {
                        CoreError::invalid("copy total overflows the byte arithmetic".to_string())
                    })?;
                }
                continue;
            }
            if child.is_dir {
                dir.push(child.name.clone());
                let sub = sum(source, dir, depth.saturating_add(1))?;
                dir.pop().ok_or_else(|| {
                    CoreError::invalid("copy path stack underflows its push".to_string())
                })?;
                total = total.checked_add(sub).ok_or_else(|| {
                    CoreError::invalid("copy total overflows the byte arithmetic".to_string())
                })?;
            } else {
                total = total.checked_add(child.size).ok_or_else(|| {
                    CoreError::invalid("copy total overflows the byte arithmetic".to_string())
                })?;
            }
        }
        Ok(total)
    }

    sum(source, &mut Vec::new(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    /// One in-memory file: payload bytes under a name.
    #[derive(Debug, Clone)]
    struct MemFile {
        name: Vec<u8>,
        bytes: Vec<u8>,
    }

    /// One in-memory symlink: its own name with the raw target.
    /// `is_dir` carries the directory flag for the directory-slot
    /// test only — proving the walk never descends through a link
    /// even when the listing marks one as a directory.
    #[derive(Debug, Clone)]
    struct MemLink {
        name: Vec<u8>,
        target: Vec<u8>,
        is_dir: bool,
    }

    /// One in-memory directory: child files, child directory names and
    /// child links. Children keep insertion order on purpose (unsorted,
    /// to prove the walk sorts).
    #[derive(Debug, Clone, Default)]
    struct MemDir {
        files: Vec<MemFile>,
        dirs: Vec<Vec<u8>>,
        links: Vec<MemLink>,
    }

    /// An in-memory [`Source`] over a `BTreeMap` of directories keyed
    /// by name-byte path (empty is the root), recording every file
    /// read in order. Listings come back in the deliberately unsorted
    /// insertion order; the walk must still visit sorted.
    #[derive(Debug, Default)]
    struct MemSource {
        dirs: BTreeMap<Vec<Vec<u8>>, MemDir>,
        reads: Rc<RefCell<Vec<Vec<Vec<u8>>>>>,
        /// Per-path mode overrides, keyed by full path from the root;
        /// entries without one keep the fixed defaults below.
        modes: BTreeMap<Vec<Vec<u8>>, u32>,
    }

    impl MemSource {
        fn dir(&mut self, path: &[Vec<u8>]) -> &mut MemDir {
            self.dirs.entry(path.to_vec()).or_default()
        }

        /// Full path of `name` under `dir`, for the mode overrides.
        fn full_path(dir: &[Vec<u8>], name: &[u8]) -> Vec<Vec<u8>> {
            let mut full = dir.to_vec();
            full.push(name.to_vec());
            full
        }

        /// Override mode for the entry at `full_path`, if the fixture
        /// pins one.
        fn mode_for(modes: &BTreeMap<Vec<Vec<u8>>, u32>, full_path: &[Vec<u8>]) -> Option<u32> {
            modes.get(full_path).copied()
        }
    }

    impl Source for MemSource {
        fn root_entries(&self) -> Result<Vec<Entry>> {
            self.child_entries(&[])
        }

        fn child_entries(&self, dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            let found = self.dirs.get(dir).ok_or_else(|| {
                CoreError::invalid(format!(
                    "test source has no directory '{}'",
                    dir.iter()
                        .map(|name| String::from_utf8_lossy(name).into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                ))
            })?;
            let mut out = Vec::new();
            for file in &found.files {
                let full = Self::full_path(dir, &file.name);
                out.push(Entry {
                    name: file.name.clone(),
                    is_dir: false,
                    size: file.bytes.len() as u64,
                    // Synthetic sources carry a fixed mode (like a
                    // real listing would), so the walk exercises the
                    // metadata path on every entry; stamps stay
                    // absent. Per-path overrides win when present.
                    mode: Some(Self::mode_for(&self.modes, &full).unwrap_or(0o644)),
                    modified: None,
                    accessed: None,
                    link: None,
                });
            }
            for name in &found.dirs {
                let full = Self::full_path(dir, name);
                out.push(Entry {
                    name: name.clone(),
                    is_dir: true,
                    size: 0,
                    mode: Some(Self::mode_for(&self.modes, &full).unwrap_or(0o755)),
                    modified: None,
                    accessed: None,
                    link: None,
                });
            }
            for link in &found.links {
                // Links list with their target and no size: a recreated
                // link costs no bytes, and a dereferenced link's size
                // resolves during the walk, not here.
                out.push(Entry {
                    name: link.name.clone(),
                    is_dir: link.is_dir,
                    size: 0,
                    mode: None,
                    modified: None,
                    accessed: None,
                    link: Some(link.target.clone()),
                });
            }
            Ok(out)
        }

        fn read_bytes(&self, file: &[Vec<u8>], offset: u64, buf: &mut [u8]) -> Result<usize> {
            let (name, parent) = file.split_last().ok_or_else(|| {
                CoreError::invalid("test source cannot read the root as a file".to_string())
            })?;
            let found = self.dirs.get(parent).ok_or_else(|| {
                CoreError::invalid("test source has no parent for the read".to_string())
            })?;
            let payload = found
                .files
                .iter()
                .find(|file| file.name.as_slice() == name.as_slice())
                .ok_or_else(|| CoreError::invalid("test source has no such file".to_string()))?;
            self.reads.borrow_mut().push(file.to_vec());
            let start = offset as usize;
            if start > payload.bytes.len() {
                return Err(CoreError::invalid(format!(
                    "test read at offset {offset} runs past the {} byte file",
                    payload.bytes.len()
                )));
            }
            let end = (start + buf.len()).min(payload.bytes.len());
            let window = payload
                .bytes
                .get(start..end)
                .ok_or_else(|| CoreError::invalid("test read window runs past its file"))?;
            let dest = buf
                .get_mut(..window.len())
                .ok_or_else(|| CoreError::invalid("test read window runs past its buffer"))?;
            dest.copy_from_slice(window);
            Ok(window.len())
        }
    }

    /// A recording [`Progress`]: every `(done, total)` report and
    /// every warning line, in order.
    #[derive(Debug, Default)]
    struct Recorder {
        reports: Vec<(u64, u64)>,
        warns: Vec<String>,
    }

    impl Progress for Recorder {
        fn report(&mut self, done_bytes: u64, total_bytes: u64) {
            self.reports.push((done_bytes, total_bytes));
        }

        fn warn(&mut self, text: &str) {
            self.warns.push(text.to_string());
        }
    }

    /// [`CopyOptions`] with no capacity limit.
    fn no_limit() -> CopyOptions {
        CopyOptions { free_bytes: None }
    }

    /// Two directories under the root (`B/` before `A/` on purpose),
    /// a nested file in `A/`, nothing anywhere else. Every named
    /// directory gets its own map entry (pushing a name alone does
    /// not create the directory it names).
    fn two_dir_source() -> MemSource {
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"B".to_vec());
        source.dir(&[]).dirs.push(b"A".to_vec());
        source.dir(&[b"B".to_vec()]);
        source.dir(&[]).files.push(MemFile {
            name: b"TOP.TXT".to_vec(),
            bytes: b"top-txt".to_vec(),
        });
        source.dir(&[b"A".to_vec()]).files.push(MemFile {
            name: b"NESTED.TXT".to_vec(),
            bytes: b"nested".to_vec(),
        });
        source
    }

    #[test]
    fn copies_directories_depth_first_in_sorted_order() {
        // Children arrive files-first and reverse-alphabetical, but
        // the file reads land in sorted depth-first order: A/ and its
        // file, then B/, then TOP.TXT — every file exactly once.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("a small tree copies");
        assert_eq!(
            source.reads.borrow().clone(),
            [
                vec![b"A".to_vec(), b"NESTED.TXT".to_vec()],
                vec![b"TOP.TXT".to_vec()],
            ]
        );
        assert_eq!(
            summary,
            Summary {
                directories: 2,
                files: 2,
                bytes: 13,
                renamed: 0,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
        assert!(
            std::fs::read_dir(scratch.path().join("B"))
                .expect("B lists")
                .count()
                == 0
        );
        // Progress opens at zero, never exceeds the total, and ends
        // exactly on it.
        assert_eq!(progress.reports.first().copied(), Some((0, 13)));
        assert_eq!(progress.reports.last().copied(), Some((13, 13)));
        assert!(
            progress.reports.iter().all(|&(done, _)| done <= 13),
            "no report past the total: {:?}",
            progress.reports
        );
    }

    #[test]
    fn refuses_a_destination_that_is_a_file() {
        // The destination is a regular file: the invalid refusal names
        // it, and its bytes are untouched.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let file = scratch.path().join("file");
        std::fs::write(&file, b"untouched").expect("the decoy writes");
        let mut progress = Recorder::default();
        let error = walk(&source, &file, &no_limit(), &mut progress)
            .expect_err("a file destination refuses");
        assert!(error.to_string().contains("not a directory"), "{error:?}");
        assert!(error.to_string().contains("file"), "{error:?}");
        assert_eq!(
            std::fs::read(&file).expect("the decoy reads back"),
            b"untouched"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn refuses_short_free_space_before_any_write() {
        // The tree holds 13 bytes and the destination reports 12: the
        // refusal names both counts, and the destination stays empty.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(
            &source,
            scratch.path(),
            &CopyOptions {
                free_bytes: Some(12),
            },
            &mut progress,
        )
        .expect_err("short space refuses");
        let text = error.to_string();
        assert!(text.contains("13"), "{text}");
        assert!(text.contains("12"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created before the check"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn refuses_reserved_entry_names() {
        // A `..` entry would escape the destination: the walk refuses
        // naming it, and nothing lands.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"..".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("a dot-dot entry refuses");
        assert!(error.to_string().contains(".."), "{error:?}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created"
        );
    }

    /// One file under the root with `name`: the small-name tests share
    /// this shape (one entry, one assertion family).
    fn one_file_source(name: Vec<u8>, bytes: Vec<u8>) -> MemSource {
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile { name, bytes });
        source
    }

    #[test]
    fn strips_version_suffixes_and_trailing_dots() {
        // `README.TXT;1` stores as `README.TXT`, `DIR.;1/` as `DIR`:
        // the version dies at the first `;`, then the trailing dot
        // trims. Both differ from their source names, so both count
        // as renamed.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"README.TXT;1".to_vec(),
            bytes: b"readme".to_vec(),
        });
        source.dir(&[]).dirs.push(b"DIR.;1".to_vec());
        source.dir(&[b"DIR.;1".to_vec()]);
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("strips copy");
        assert_eq!(
            summary,
            Summary {
                directories: 1,
                files: 1,
                bytes: 6,
                renamed: 2,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("README.TXT")).expect("stripped reads back"),
            b"readme"
        );
        assert!(
            scratch.path().join("DIR").is_dir(),
            "the dotted directory stores dotless"
        );
    }

    #[test]
    fn replaces_separators_and_control_bytes() {
        // `/`, SOH and a tab all become `_`: one flat component that
        // cannot climb out of the destination.
        let source = one_file_source(b"a/b\x01c\td".to_vec(), b"data".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("mapped copy");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 4,
                renamed: 1,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("a_b_c_d")).expect("mapped reads back"),
            b"data"
        );
    }

    #[test]
    fn keeps_legal_semicolons_that_are_not_versions() {
        // Only a trailing `;[0-9]+` strips: `my;file.txt` is a legal
        // Rock Ridge name and survives byte-identical (and uncounted),
        // while `v;2` strips to `v`.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"my;file.txt".to_vec(),
            bytes: b"kept".to_vec(),
        });
        source.dir(&[]).files.push(MemFile {
            name: b"v;2".to_vec(),
            bytes: b"stripped".to_vec(),
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("versions copy");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 2,
                bytes: 12,
                renamed: 1,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("my;file.txt")).expect("kept reads back"),
            b"kept"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("v")).expect("stripped reads back"),
            b"stripped"
        );
    }

    #[test]
    fn empty_after_sanitising_becomes_underscore() {
        // `...` trims to nothing: the entry stores as `_`. (A lone
        // `;` is kept as-is — only a trailing `;[0-9]+` version strips.)
        let source = one_file_source(b"...".to_vec(), b"data".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("empty maps");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 4,
                renamed: 1,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("_")).expect("underscore reads back"),
            b"data"
        );
    }

    #[test]
    fn truncates_long_components_and_warns() {
        // A 300-byte name stores 255 bytes, warns naming both ends,
        // and counts as renamed.
        let long = vec![b'A'; 300];
        let source = one_file_source(long.clone(), b"data".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("truncated copy");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 4,
                renamed: 1,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("A".repeat(255))).expect("truncated reads back"),
            b"data"
        );
        assert_eq!(progress.warns.len(), 1, "one truncation warns");
        assert!(
            progress.warns[0].contains(&"A".repeat(300)),
            "the warning names the original: {}",
            progress.warns[0]
        );
        assert!(
            progress.warns[0].contains(&"A".repeat(255)),
            "the warning names the result: {}",
            progress.warns[0]
        );
    }

    #[test]
    fn sanitise_truncates_on_character_boundaries() {
        // Direct unit pins for the rule-5 cutter the walk relies on:
        // ASCII cuts at 255, multi-byte cuts back to the lead, and
        // invalid tails keep every byte the cut does not split.
        assert_eq!(sanitise(&vec![b'A'; 300]).name.len(), 255);
        let mut wide = vec![b'A'; 200];
        for _ in 0..60 {
            wide.extend_from_slice(&[0xC3, 0xA9]);
        }
        let cut = sanitise(&wide);
        assert_eq!(cut.name.len(), 254);
        assert!(
            std::str::from_utf8(&cut.name).is_ok(),
            "a valid sequence never splits"
        );
        let mut ragged = vec![b'A'; 253];
        ragged.extend_from_slice(&[0xE3, 0x81, b'*']);
        let cut = sanitise(&ragged);
        assert_eq!(cut.name.len(), 253);
        let mut stray = vec![b'A'; 253];
        stray.extend_from_slice(&[0x80, 0x80, b'*']);
        let cut = sanitise(&stray);
        assert_eq!(cut.name.len(), 255);
    }

    #[test]
    fn case_collisions_get_numbered_suffixes() {
        // `FILE.TXT`, `file.txt`, `File.Txt` share one lowercase key.
        // Byte sort orders them `FILE.TXT`, `File.Txt`, `file.txt`,
        // so the first keeps its name and the rest earn `~1`/`~2`
        // before the extension with their own case intact — and their
        // own bytes.
        let mut source = MemSource::default();
        for (name, bytes) in [
            (b"FILE.TXT".to_vec(), b"upper".to_vec()),
            (b"file.txt".to_vec(), b"lower".to_vec()),
            (b"File.Txt".to_vec(), b"mixed".to_vec()),
        ] {
            source.dir(&[]).files.push(MemFile { name, bytes });
        }
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("collisions copy");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 3,
                bytes: 15,
                renamed: 2,
            }
        );
        assert_eq!(
            std::fs::read(scratch.path().join("FILE.TXT")).expect("first reads back"),
            b"upper"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("File~1.Txt")).expect("second reads back"),
            b"mixed"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("file~2.txt")).expect("third reads back"),
            b"lower"
        );
    }

    #[test]
    fn collision_cap_refuses() {
        // 1001 names sanitising to `DUP.TXT` (`DUP.TXT` plus
        // zero-padded `DUP.TXT;0001`..`;1000`, so sort order is
        // numeric): suffixes `~1`..`~999` fill, and the last entry
        // refuses naming itself and the cap.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"DUP.TXT".to_vec(),
            bytes: Vec::new(),
        });
        for n in 1..=1000u32 {
            source.dir(&[]).files.push(MemFile {
                name: format!("DUP.TXT;{n:04}").into_bytes(),
                bytes: Vec::new(),
            });
        }
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("the 1001st collision refuses");
        let text = error.to_string();
        assert!(text.contains("999"), "{text}");
        assert!(text.contains("DUP.TXT;1000"), "{text}");
    }

    #[test]
    fn collision_sets_do_not_leak_across_directories() {
        // Root holds file `X`, dir `a/` (child file `inside`), dir
        // `b/` (child file `zz`) and file `x`, plus root file `zz`:
        // the two root `x` collide case-insensitively (`x~1`,
        // counted) while `a/inside` and `b/zz` never collide with
        // root `zz` — without save/restore the parent inherits the
        // child's pool and one of the two shapes misnames.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"X".to_vec(),
            bytes: b"big-x".to_vec(),
        });
        source.dir(&[]).files.push(MemFile {
            name: b"x".to_vec(),
            bytes: b"small-x".to_vec(),
        });
        source.dir(&[]).files.push(MemFile {
            name: b"zz".to_vec(),
            bytes: b"root-zz".to_vec(),
        });
        source.dir(&[]).dirs.push(b"a".to_vec());
        source.dir(&[]).dirs.push(b"b".to_vec());
        source.dir(&[b"a".to_vec()]).files.push(MemFile {
            name: b"inside".to_vec(),
            bytes: b"in-a".to_vec(),
        });
        source.dir(&[b"b".to_vec()]).files.push(MemFile {
            name: b"zz".to_vec(),
            bytes: b"b-zz".to_vec(),
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("scoped copy");
        assert_eq!(
            summary,
            Summary {
                directories: 2,
                files: 5,
                bytes: 27,
                renamed: 1,
            }
        );
        for (name, bytes) in [
            ("X", b"big-x".as_slice()),
            ("x~1", b"small-x".as_slice()),
            ("zz", b"root-zz".as_slice()),
        ] {
            assert_eq!(
                std::fs::read(scratch.path().join(name)).expect("root file reads back"),
                bytes,
                "{name} holds its own bytes"
            );
        }
        assert_eq!(
            std::fs::read(scratch.path().join("a").join("inside")).expect("a/inside reads back"),
            b"in-a"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("b").join("zz")).expect("b/zz reads back"),
            b"b-zz"
        );
    }

    #[test]
    fn truncation_retrims_trailing_dots() {
        // 254 `a`s, one `.`, ten `b`s (265 bytes): the cut lands on
        // the dot, and the re-trim takes it back off — the stored
        // name is 254 `a`s, never dot-terminated.
        let mut name = vec![b'a'; 254];
        name.push(b'.');
        name.extend([b'b'; 10]);
        let source = one_file_source(name, b"data".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("retrimmed copy");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 4,
                renamed: 1,
            }
        );
        let names: Vec<String> = std::fs::read_dir(scratch.path())
            .expect("the destination lists")
            .map(|entry| {
                entry
                    .expect("entries read")
                    .file_name()
                    .into_string()
                    .expect("the name is UTF-8")
            })
            .collect();
        assert_eq!(names, ["a".repeat(254)]);
        assert_eq!(progress.warns.len(), 1, "one truncation warns");
    }

    #[test]
    fn collision_candidate_trims_dot_terminated_stems() {
        // Two entries colliding where the room cut lands on a dot:
        // `G`*248 + `.H.TXT` keeps its name, while lowercase twin
        // `g`*248 + `.h.txt` earns a suffix whose stem is trimmed back
        // past the dot (`g`*248 + `~1.txt`, not `g`*248 + `.~1.txt`).
        let mut upper = b"G".repeat(248);
        upper.extend_from_slice(b".H.TXT");
        let mut lower = b"g".repeat(248);
        lower.extend_from_slice(b".h.txt");
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: upper.clone(),
            bytes: b"kept".to_vec(),
        });
        source.dir(&[]).files.push(MemFile {
            name: lower.clone(),
            bytes: b"moved".to_vec(),
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("dotted collision");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 2,
                bytes: 9,
                renamed: 1,
            }
        );
        let upper_name = String::from_utf8(upper).expect("upper is UTF-8");
        assert_eq!(
            std::fs::read(scratch.path().join(&upper_name)).expect("first reads back"),
            b"kept"
        );
        let suffixed = "g".repeat(248) + "~1.txt";
        assert_eq!(
            std::fs::read(scratch.path().join(&suffixed)).expect("second reads back"),
            b"moved"
        );
    }

    #[test]
    fn sanitising_never_bypasses_reserved_names() {
        // A source entry named `..` refuses even though sanitising
        // would map other names: reserved names fail before mapping,
        // never through it.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"..".to_vec());
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("a dot-dot entry refuses");
        assert!(error.to_string().contains("reserved"), "{error:?}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created"
        );
    }

    /// A [`Source`] listing one directory under every directory it is
    /// asked about: a cyclic tree that would recurse forever without
    /// the depth bound.
    #[derive(Debug, Default)]
    struct LoopSource;

    impl Source for LoopSource {
        fn root_entries(&self) -> Result<Vec<Entry>> {
            Ok(vec![Entry {
                name: b"X".to_vec(),
                is_dir: true,
                size: 0,
                mode: None,
                modified: None,
                accessed: None,
                link: None,
            }])
        }

        fn child_entries(&self, _dir: &[Vec<u8>]) -> Result<Vec<Entry>> {
            Ok(vec![Entry {
                name: b"X".to_vec(),
                is_dir: true,
                size: 0,
                mode: None,
                modified: None,
                accessed: None,
                link: None,
            }])
        }

        fn read_bytes(&self, _file: &[Vec<u8>], _offset: u64, _buf: &mut [u8]) -> Result<usize> {
            Err(CoreError::invalid("loop source holds no files".to_string()))
        }
    }

    #[test]
    fn cyclic_tree_refuses_instead_of_overflowing() {
        // Every directory lists itself: without the depth bound the
        // walk recurses until the stack overflows. It must return Err
        // naming the loop instead, from the sizing pass — before any
        // write, with nothing reported.
        let source = LoopSource;
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect_err("a cyclic tree refuses");
        let text = error.to_string();
        assert!(text.contains('X'), "{text}");
        assert!(text.contains("possible directory loop"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "no entry is created"
        );
        assert!(progress.reports.is_empty(), "nothing reported");
    }

    #[test]
    fn second_run_into_the_same_destination_resumes() {
        // Copy twice into the same destination: existing directories
        // are reused and files rewritten whole, so the second run
        // succeeds with identical counts and bytes.
        let source = two_dir_source();
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let first =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("first copy runs");
        let mut progress = Recorder::default();
        let second =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("second copy resumes");
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read(scratch.path().join("TOP.TXT")).expect("top reads back"),
            b"top-txt"
        );
        assert_eq!(
            std::fs::read(scratch.path().join("A").join("NESTED.TXT")).expect("nested reads back"),
            b"nested"
        );
    }

    /// [`Progress`] deleting one path the moment the grand total is
    /// reported: the file's last chunk already landed, so only its
    /// metadata application can still fail. Deterministic — no timing,
    /// no threads — the report order guarantees the deletion lands
    /// between the last write and the apply.
    #[derive(Debug)]
    struct DeleteHook {
        target: PathBuf,
        warns: Vec<String>,
    }

    impl Progress for DeleteHook {
        fn report(&mut self, done_bytes: u64, total_bytes: u64) {
            if done_bytes == total_bytes && total_bytes > 0 {
                let _ = std::fs::remove_file(&self.target);
            }
        }

        fn warn(&mut self, text: &str) {
            self.warns.push(text.to_string());
        }
    }

    #[test]
    fn metadata_failure_warns_and_continues() {
        // One 300 KiB file (three chunks): its last chunk's report
        // deletes it before metadata applies, so the copy still
        // returns `Ok` with exactly one warning naming it — never an
        // error — and the counts stand.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"BIG".to_vec(),
            bytes: vec![0x5Au8; 300 * 1024],
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let target = scratch.path().join("BIG");
        let mut progress = DeleteHook {
            target,
            warns: Vec::new(),
        };
        let summary = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect("a metadata failure still copies");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 300 * 1024,
                renamed: 0,
            }
        );
        assert_eq!(progress.warns.len(), 1, "one warning, not an error");
        assert!(
            progress.warns[0].contains("BIG"),
            "the warning names the path: {}",
            progress.warns[0]
        );
    }

    /// Permission bits of `path`, masked to the mode proper.
    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path)
            .expect("entry stats")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn resumed_copy_reenters_a_read_only_directory() {
        // `B/` carries `0o500` with a child inside: the first run
        // creates it, writes the child, then chmods it; the second
        // run must widen it back for the descent, rewrite the child,
        // and leave `0o500` again — both runs `Ok`, bytes matching
        // both times.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"B".to_vec());
        source.dir(&[b"B".to_vec()]).files.push(MemFile {
            name: b"M.TXT".to_vec(),
            bytes: b"m!".to_vec(),
        });
        source.modes.insert(vec![b"B".to_vec()], 0o500);
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        for run in 1..=2 {
            let mut progress = Recorder::default();
            walk(&source, scratch.path(), &no_limit(), &mut progress)
                .expect("a read-only directory re-enters");
            assert_eq!(
                std::fs::read(scratch.path().join("B").join("M.TXT"))
                    .expect("the child reads back"),
                b"m!",
                "run {run} leaves matching bytes"
            );
            assert_eq!(
                mode_of(&scratch.path().join("B")),
                0o500,
                "run {run} leaves B at 0o500"
            );
        }
    }

    #[test]
    fn interrupted_file_in_a_read_only_directory_is_rewritten() {
        // A stale partial file under a `0o500` directory (the shape an
        // interrupted run leaves behind): the second run widens the
        // directory, replaces the partial file whole, and finishes
        // with correct bytes and the stored mode.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"B".to_vec());
        source.dir(&[b"B".to_vec()]).files.push(MemFile {
            name: b"BIG".to_vec(),
            bytes: vec![0x5Au8; 300 * 1024],
        });
        source.modes.insert(vec![b"B".to_vec()], 0o500);
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let dir = scratch.path().join("B");
        std::fs::create_dir(&dir).expect("the stale directory creates");
        std::fs::write(dir.join("BIG"), vec![0xAAu8; 100 * 1024]).expect("partial writes");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
            .expect("the stale directory chmods");
        let mut progress = Recorder::default();
        let summary = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect("a partial file under a read-only directory resumes");
        assert_eq!(
            summary,
            Summary {
                directories: 1,
                files: 1,
                bytes: 300 * 1024,
                renamed: 0,
            }
        );
        assert_eq!(
            std::fs::read(dir.join("BIG")).expect("the rewritten file reads back"),
            vec![0x5Au8; 300 * 1024]
        );
        assert_eq!(mode_of(&dir), 0o500, "B ends at its stored mode");
    }

    #[test]
    fn inside_link_recreated_as_link() {
        // LINK points at the sibling FILE.TXT: the walk recreates it
        // as a link (symlink metadata, the same target text) while
        // the file lands with its bytes. The link costs no bytes:
        // two files, 10 bytes, no warnings.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"FILE.TXT".to_vec(),
            bytes: b"file-bytes".to_vec(),
        });
        source.dir(&[]).links.push(MemLink {
            name: b"LINK".to_vec(),
            target: b"FILE.TXT".to_vec(),
            is_dir: false,
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary =
            walk(&source, scratch.path(), &no_limit(), &mut progress).expect("a link tree copies");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 2,
                bytes: 10,
                renamed: 0,
            }
        );
        assert!(
            progress.warns.is_empty(),
            "an inside link warns nothing: {:?}",
            progress.warns
        );
        let link = scratch.path().join("LINK");
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link stats")
                .file_type()
                .is_symlink(),
            "LINK lands as a link"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("the target reads"),
            Path::new("FILE.TXT")
        );
        assert_eq!(
            std::fs::read(scratch.path().join("FILE.TXT")).expect("the file reads back"),
            b"file-bytes"
        );
    }

    #[test]
    fn escaping_link_dereferenced_to_file() {
        // SUB/LINK climbs past the root (`../../FILE.TXT`): lexically
        // outside, so the walk copies the resolved file's bytes as a
        // regular file under the link's own name, as Rufus does. Both
        // passes agree on the total: the meter opens and ends on 18.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"FILE.TXT".to_vec(),
            bytes: b"top-bytes".to_vec(),
        });
        source.dir(&[]).dirs.push(b"SUB".to_vec());
        source.dir(&[b"SUB".to_vec()]);
        source.dir(&[b"SUB".to_vec()]).links.push(MemLink {
            name: b"LINK".to_vec(),
            target: b"../../FILE.TXT".to_vec(),
            is_dir: false,
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect("an escaping link copies");
        assert_eq!(
            summary,
            Summary {
                directories: 1,
                files: 2,
                bytes: 18,
                renamed: 0,
            }
        );
        assert!(
            progress.warns.is_empty(),
            "a resolved link warns nothing: {:?}",
            progress.warns
        );
        assert_eq!(progress.reports.first().copied(), Some((0, 18)));
        assert_eq!(progress.reports.last().copied(), Some((18, 18)));
        let link = scratch.path().join("SUB").join("LINK");
        let meta = std::fs::symlink_metadata(&link).expect("the dereferenced link stats");
        assert!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "an escaping link lands as a regular file"
        );
        assert_eq!(
            std::fs::read(&link).expect("the dereferenced bytes read back"),
            b"top-bytes"
        );
    }

    #[test]
    fn absolute_and_dangling_links_warn_and_skip() {
        // An absolute target and a dangling one resolve to no file:
        // each warns once naming the link and leaves nothing behind.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"FILE.TXT".to_vec(),
            bytes: b"top-bytes".to_vec(),
        });
        source.dir(&[]).links.push(MemLink {
            name: b"ABS".to_vec(),
            target: b"/NOPE.TXT".to_vec(),
            is_dir: false,
        });
        source.dir(&[]).links.push(MemLink {
            name: b"DANGLING".to_vec(),
            target: b"NOPE.TXT".to_vec(),
            is_dir: false,
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect("unresolvable links skip");
        assert_eq!(
            summary,
            Summary {
                directories: 0,
                files: 1,
                bytes: 9,
                renamed: 0,
            }
        );
        assert_eq!(
            progress.warns.len(),
            2,
            "one warning per link: {:?}",
            progress.warns
        );
        assert!(
            progress.warns.iter().any(|warn| warn.contains("ABS")),
            "the absolute link is named: {:?}",
            progress.warns
        );
        assert!(
            progress.warns.iter().any(|warn| warn.contains("DANGLING")),
            "the dangling link is named: {:?}",
            progress.warns
        );
        for name in ["ABS", "DANGLING"] {
            let missing = std::fs::symlink_metadata(scratch.path().join(name));
            assert!(
                missing.is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                "{name} leaves nothing behind"
            );
        }
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            1,
            "only the file lands"
        );
    }

    #[test]
    fn dereferenced_size_counted_by_free_space_check() {
        // FILE.TXT (9 bytes) plus SUB/LINK dereferencing it past the
        // root (9 more): the sizing pass counts both, so 17 free
        // bytes refuse naming both counts before any write.
        let mut source = MemSource::default();
        source.dir(&[]).files.push(MemFile {
            name: b"FILE.TXT".to_vec(),
            bytes: b"top-bytes".to_vec(),
        });
        source.dir(&[]).dirs.push(b"SUB".to_vec());
        source.dir(&[b"SUB".to_vec()]);
        source.dir(&[b"SUB".to_vec()]).links.push(MemLink {
            name: b"LINK".to_vec(),
            target: b"../../FILE.TXT".to_vec(),
            is_dir: false,
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let error = walk(
            &source,
            scratch.path(),
            &CopyOptions {
                free_bytes: Some(17),
            },
            &mut progress,
        )
        .expect_err("17 bytes refuse an 18 byte tree");
        let text = error.to_string();
        assert!(text.contains("18"), "{text}");
        assert!(text.contains("17"), "{text}");
        assert_eq!(
            std::fs::read_dir(scratch.path())
                .expect("the destination lists")
                .count(),
            0,
            "nothing is written"
        );
    }

    #[test]
    fn symlink_in_directory_slot_never_descended() {
        // LINK carries the directory flag but a link target: the walk
        // recreates it as a link and never descends — the reads prove
        // it, with only DIR/FILE.TXT read, once.
        let mut source = MemSource::default();
        source.dir(&[]).dirs.push(b"DIR".to_vec());
        source.dir(&[b"DIR".to_vec()]).files.push(MemFile {
            name: b"FILE.TXT".to_vec(),
            bytes: b"dir-bytes".to_vec(),
        });
        source.dir(&[]).links.push(MemLink {
            name: b"LINK".to_vec(),
            target: b"DIR".to_vec(),
            is_dir: true,
        });
        let scratch = tempfile::tempdir().expect("scratch dir fits");
        let mut progress = Recorder::default();
        let summary = walk(&source, scratch.path(), &no_limit(), &mut progress)
            .expect("a directory-slot link copies");
        assert_eq!(
            summary,
            Summary {
                directories: 1,
                files: 2,
                bytes: 9,
                renamed: 0,
            }
        );
        assert_eq!(
            source.reads.borrow().clone(),
            [vec![b"DIR".to_vec(), b"FILE.TXT".to_vec()]],
            "nothing reads through the link"
        );
        let link = scratch.path().join("LINK");
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link stats")
                .file_type()
                .is_symlink(),
            "a directory-slot link still lands as a link"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("the target reads"),
            Path::new("DIR")
        );
    }
}
