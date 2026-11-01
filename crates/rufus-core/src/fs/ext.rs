//! ext2/3/4 integration: drive the external `mke2fs`/`mkfs.ext*` tool, then
//! verify the superblock fields the mandate pins and, for persistence
//! volumes, activate Rufus's persistence mode through `debugfs`
//! (S12, slice 2 of 3).
//!
//! PLAN lines 681-701 mandate ext volumes matching Rufus's options, built by
//! shelling out to `mke2fs -q -F -t ext2|ext3|ext4 -L <label> -b 4096 -I 256`
//! plus `-E lazy_itable_init=0,lazy_journal_init=0` for predictable results —
//! journal on for ext3/4, and `-O ^has_journal` for ext2 — under PLAN decision
//! A4 (line 37), which keeps a curated set of filesystems on external-tool
//! formatters (the NTFS formatter of [`fs::ntfs`] rides on the same decision)
//! because a pure-Rust ext writer is a multi-year project. There is no native
//! writer here and no dependency on `rufus-linux` / `rufus-helper`: the tool
//! path arrives as a spawn argument, the tool runs as a bounded capture, and
//! the only bytes this module parses are the first 4096 bytes of the target —
//! the byte region whose tail the on-disk ext format lays the superblock
//! into, starting at byte 1024 of the first block.
//!
//! The superblock facts pinned below are two things and nothing else: the
//! ext on-disk format (the field offsets of `s_magic`, `s_log_block_size`,
//! `s_feature_compat` and `s_volume_name`, with `HAS_JOURNAL` as bit 0x0004
//! of the compatible-feature word) and our own contract (the 4096-byte block
//! size is the mandate's `-b 4096`, the label shape is the 16-byte
//! `s_volume_name` field, and [`superblock_for`] enforces the mandate's
//! journal split: none for ext2, one for ext3/4). No *conformance* claim is
//! made here about real `mke2fs`, `e2fsck` or `debugfs` output; their
//! agreement with the mandate rests on measurements taken on this host
//! against e2fsprogs 1.47.4 (each cited where the tool is driven), while
//! mount and write, the 2 TB sparse image and the QEMU-absent caveat stay
//! acceptance tests beyond this slice (PLAN lines 702-703).
//!
//! Deferred with notes, per the `fs::ntfs` S21 precedent: the optional
//! `libext2fs` e2fsprogs feature of PLAN lines 696-698 (the A5 fallback for
//! distros that forbid external tools) stays documented-not-implemented.
//! The persistence activation of PLAN lines 695-697 (the label plus
//! `/persistence.conf`, written through `debugfs`) and the `e2fsck -f -n`
//! verification of PLAN line 700 ship in this slice.
//!
//! Test discipline: every test drives `#!/bin/sh` stubs or synthetic
//! superblocks and claims nothing about real `mke2fs` output; the layout the
//! synthetic fixtures pin is the ext on-disk format, not tool behaviour.

use std::fmt;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::error::CoreError;
use crate::error::Result;
use crate::fs::exfat::get_u16;
use crate::fs::exfat::get_u32;
use crate::fs::tool;
use crate::log::Level;
use crate::log::Logger;
use crate::text::device_text;

/// Tool names in probe order: the canonical `mke2fs` first, then the
/// `mkfs.ext*` aliases. [`find_tool`] probes the whole list — the
/// "is there an ext formatter at all" question behind the wildcard hint —
/// while [`format`] narrows the alias to the flavour it runs (see
/// [`find_tool_in`]).
const TOOL_NAMES: [&str; 4] = ["mke2fs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4"];

/// The canonical tool name every probe tries first: the mandate's formatter
/// (PLAN line 692), whose `mkfs.ext*` aliases are fallbacks only.
const CANONICAL_TOOL: &str = "mke2fs";

/// The superblock's start inside the first block, per the on-disk ext
/// format: byte 1024. All the `SB_*` offsets below are absolute positions
/// in the first-block region [`format`] reads back.
const SB_AT: usize = 1024;

/// Block size in bytes the mandate fixes as `-b 4096` (PLAN line 692); the
/// parser accepts no other encoded size and no option ever sets one.
const FIXED_BLOCK_BYTES: u32 = 4096;

/// Inode size in bytes the mandate fixes as `-I 256` (PLAN line 692).
const INODE_BYTES: u32 = 256;

/// The size of the byte region [`format`] reads back from the target: the
/// whole first block of a 4096-byte-block volume, superblock inside.
const READ_REGION_BYTES: usize = 4096;

/// The superblock magic, `u16` LE — the on-disk ext format's signature.
const SUPER_MAGIC: u16 = 0xEF53;

/// `COMPAT_HAS_JOURNAL`: the `s_feature_compat` bit that says the volume
/// carries a journal. Ext3/4 must set it, ext2 must clear it (the mandate's
/// journal split).
const HAS_JOURNAL_BIT: u32 = 0x0004;

/// `s_log_block_size` (`u32` LE): block size is 1024 << value per the
/// on-disk format. Superblock-relative 24.
const SB_LOG_BLOCK_SIZE_AT: usize = SB_AT + 24;

/// `s_magic` (`u16` LE): [`SUPER_MAGIC`]. Superblock-relative 56.
const SB_MAGIC_AT: usize = SB_AT + 56;

/// `s_feature_compat` (`u32` LE) — superblock-relative 0x5C, i.e. byte 92
/// of the superblock structure, absolute [`SB_AT`] + 92. The on-disk
/// placement per the ext4 superblock table (kernel.org) and e2fsprogs's
/// `ext2_fs.h` layout (`/*05c*/ s_feature_compat`); do not confuse it with
/// the superblock-relative 76 of `s_rev_level`, the field just before.
const SB_FEATURE_COMPAT_AT: usize = SB_AT + 92;

/// `s_volume_name[16]`: the label run — the bytes up to the first NUL,
/// or the whole 16 bytes when the run carries no NUL (`EXT2_LABEL_LEN`
/// is the ceiling, never a terminator requirement). Superblock-relative
/// 0x78.
const SB_VOLUME_NAME_AT: usize = SB_AT + 120;

/// One past the label run: the last byte the parser reads, so a buffer
/// shorter than this cannot carry a complete superblock.
const SB_VOLUME_NAME_END: usize = SB_VOLUME_NAME_AT + 16;

/// Byte ceiling of the on-disk `s_volume_name` run: an ext label is at
/// most 16 bytes of ASCII — both facts show up in the refusals.
const LABEL_BYTES_MAX: usize = 16;

/// Refusal when no usable ext formatter is on `PATH`, one word per fact:
/// the hint names the tool family and the package the ext row of PLAN's
/// package-mapping table ships it in — `e2fsprogs` (PLAN.md line 136; the
/// neighbouring NTFS row at line 137 set this hint's shape in `fs::ntfs`).
const MISSING_TOOL_HINT: &str =
    "no ext formatter found (mke2fs or mkfs.ext*): install the e2fsprogs package";

/// The checker tool name [`verify`] probes: the read-only `e2fsck` run
/// (`-n` answers no to every repair prompt — measured read-only on this
/// host against e2fsprogs 1.47.4 during this slice: a corrupt ext4 image's
/// sha256 was identical before and after `e2fsck -f -n`, exit 4).
const VERIFY_TOOL: &str = "e2fsck";

/// Refusal when no usable ext checker is on `PATH`: names the tool and the
/// package that ships it — `e2fsprogs` — in the shape of [`MISSING_TOOL_HINT`].
const VERIFY_MISSING_TOOL_HINT: &str =
    "no ext checker found (e2fsck): install the e2fsprogs package";

/// The persistence label: with `persistence` set, the volume label must be
/// exactly this (Rufus names the live-boot persistence volume `persistence`,
/// PLAN lines 695-697), enforced by [`effective_label`] before any tool runs.
const PERSISTENCE_LABEL: &str = "persistence";

/// The persistence flag file inside the volume: Rufus's live boot reads
/// `/persistence.conf` carrying [`PERSISTENCE_CONF_BYTES`].
const PERSISTENCE_CONF_PATH: &str = "/persistence.conf";

/// The exact bytes `/persistence.conf` must carry: `/ union` plus a newline
/// (8 bytes; Rufus's persistence mode reads this file for the union
/// directive).
const PERSISTENCE_CONF_BYTES: [u8; 8] = *b"/ union\n";

/// The read-only request that proves the persistence write: run without
/// `-w`, its captured stdout must equal [`PERSISTENCE_CONF_BYTES`] exactly —
/// exit status alone is no proof (see [`activate_persistence`]).
const PERSISTENCE_CONF_CAT: &str = "cat /persistence.conf";

/// The persistence-writer tool [`activate_persistence`] probes: `debugfs`
/// carries the `write` and `cat` requests (measured with e2fsprogs 1.47.4).
const WRITER_TOOL: &str = "debugfs";

/// Refusal when no usable persistence writer is on `PATH`: names the tool
/// and the package that ships it — `e2fsprogs` — in the shape of
/// [`MISSING_TOOL_HINT`].
const WRITER_MISSING_TOOL_HINT: &str =
    "no ext persistence writer found (debugfs): install the e2fsprogs package";

/// Staging filename prefix inside [`std::env::temp_dir`]: the suffix carries
/// the process id, a nanosecond timestamp and a per-process counter (see
/// [`stage_persistence_source`]).
const STAGE_NAME_PREFIX: &str = "rufus-persistence-";

/// Locate the ext formatter over `PATH` without a flavour in hand: `mke2fs`,
/// falling back through `mkfs.ext2`, `mkfs.ext3`, `mkfs.ext4` in that order.
///
/// Each `PATH` directory is scanned by hand (existence plus the owner
/// execute bit — never a shell, never a `PATH` mutation), and the first
/// candidate whose version probe exits successfully wins; a candidate whose
/// probe fails is treated as absent. This answers "is there any ext
/// formatter at all"; [`format`] runs its own scan narrowed to the flavour
/// it formats (the scan is the shared [`tool::scan_candidates`] — no
/// TOCTOU).
pub fn find_tool() -> Result<&'static str> {
    probe_candidates(&tool::path_dirs(), &TOOL_NAMES).map(|(name, _)| name)
}

/// [`format`]'s tool resolution over an explicit directory list, so tests
/// can point the probe at scratch directories without touching the process
/// environment (`std::env::set_var` is `unsafe` under this crate's edition
/// and the crate keeps `#![forbid(unsafe_code)]`, which leaves no room for
/// it). The flavour narrows the alias: `mke2fs` first, then exactly the
/// `mkfs.<token>` alias of `flavour` — an `mkfs.ext2` on `PATH` is not an
/// ext4 formatter, and this reader refuses to guess that the aliases share
/// a binary.
fn find_tool_in(dirs: &[PathBuf], flavour: Flavour) -> Result<(&'static str, PathBuf)> {
    probe_candidates(dirs, &[CANONICAL_TOOL, flavour.alias()])
}

/// [`verify`]'s tool resolution over an explicit directory list, so tests
/// can point the probe at scratch directories without touching the process
/// environment (same injection seam as [`find_tool_in`]).
fn find_verify_tool_in(dirs: &[PathBuf]) -> Result<(&'static str, PathBuf)> {
    tool::scan_candidates(dirs, &[VERIFY_TOOL], "-V", verify_missing_tool_error)
}

/// [`activate_persistence`]'s tool resolution over an explicit directory
/// list, so tests can point the probe at scratch directories without
/// touching the process environment (same injection seam as
/// [`find_tool_in`]).
fn find_writer_in(dirs: &[PathBuf]) -> Result<(&'static str, PathBuf)> {
    tool::scan_candidates(dirs, &[WRITER_TOOL], "-V", writer_missing_tool_error)
}

/// Probe `names` in order over `dirs`, returning the first entry that is an
/// executable file whose version check exits successfully; nothing found,
/// nothing executable, or a probe that ran and failed reports the shared
/// [`MISSING_TOOL_HINT`] refusal. A probe that could not be spawned at all
/// (other than a vanishing `NotFound`) refuses as an I/O error naming the
/// candidate path, never the package hint.
///
/// This family passes `-V` (why the flag is a parameter lives with
/// [`tool::probe_with`]); the scan itself is [`tool::scan_candidates`].
/// The stub tests pin the flag as sent.
fn probe_candidates(dirs: &[PathBuf], names: &[&'static str]) -> Result<(&'static str, PathBuf)> {
    tool::scan_candidates(dirs, names, "-V", missing_tool_error)
}

/// The shared refusal for an absent formatter: nothing found, nothing
/// executable, or a probe that ran and failed. Spawn failures refuse as I/O
/// errors instead, so every "the toolchain is missing" path names the same
/// package without hiding an honest spawn error.
fn missing_tool_error() -> CoreError {
    CoreError::invalid(MISSING_TOOL_HINT)
}

/// The shared checker refusal for an absent checker: nothing found, nothing
/// executable, or a probe that ran and failed. Spawn failures refuse as I/O
/// errors instead, so the missing-checker path names the same package
/// without hiding an honest spawn error.
fn verify_missing_tool_error() -> CoreError {
    CoreError::invalid(VERIFY_MISSING_TOOL_HINT)
}

/// The shared writer refusal for an absent writer: nothing found, nothing
/// executable, or a probe that ran and failed. Spawn failures refuse as I/O
/// errors instead, so the missing-writer path names the same package without
/// hiding an honest spawn error.
fn writer_missing_tool_error() -> CoreError {
    CoreError::invalid(WRITER_MISSING_TOOL_HINT)
}

/// The ext flavour a format run builds: the `-t` spawn token and, as
/// [`Flavour::alias`], the `mkfs.` alias the probe accepts — the same word
/// by design. The journal split goes with the flavour: ext2 carries no
/// journal (`-O ^has_journal`), ext3 and ext4 carry one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// ext2: no journal.
    Ext2,
    /// ext3: journal, no ext4-only features demanded here.
    Ext3,
    /// ext4: journal.
    Ext4,
}

impl Flavour {
    /// The `-t` spawn token: `"ext2"`, `"ext3"` or `"ext4"`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
        }
    }

    /// The `mkfs.` alias the probe accepts for this flavour: the spawn
    /// token prefixed with `mkfs.`.
    fn alias(&self) -> &'static str {
        match self {
            Self::Ext2 => "mkfs.ext2",
            Self::Ext3 => "mkfs.ext3",
            Self::Ext4 => "mkfs.ext4",
        }
    }
}

impl fmt::Display for Flavour {
    /// The spawn token (`ext2`, `ext3`, `ext4`) — the same word refusals
    /// and summaries name the flavour by.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// The write-side options of [`format`]: the flavour, an optional label and
/// the slice-2 persistence switch. The 4096-byte block size is fixed by the
/// mandate (`-b 4096`) and is not an option at all — there is deliberately
/// no knob for it.
#[derive(Debug, Clone)]
pub struct Options {
    /// Which ext generation to build.
    pub flavour: Flavour,
    /// Volume label passed as `mke2fs -L`; `None` omits the flag entirely.
    /// Validated by [`Options::with_label`]: at most 16 bytes of ASCII.
    pub label: Option<String>,
    /// The persistence switch (label plus `/persistence.conf`,
    /// PLAN lines 695-697); [`format`] enforces the `persistence` label and
    /// writes the flag file through `debugfs` when this is set.
    pub persistence: bool,
}

impl Options {
    /// Options with no label and `persistence: false`; see
    /// [`Options::with_label`] to attach a validated one.
    #[must_use]
    pub fn new(flavour: Flavour) -> Self {
        Self {
            flavour,
            label: None,
            persistence: false,
        }
    }

    /// Attach a volume label, refused unless it is at most 16 bytes of
    /// ASCII — both facts are the on-disk format's (`s_volume_name` is a
    /// 16-byte field, ASCII by the tool family's own store shape) and both
    /// appear in the refusal text.
    pub fn with_label(mut self, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        let ascii = label.is_ascii();
        let length = label.len();
        if !ascii {
            return Err(CoreError::invalid(format!(
                "ext label is {length} bytes of non-ASCII text: the label must be \
                 at most 16 bytes of ASCII (the on-disk s_volume_name field is 16 bytes)"
            )));
        }
        if length > LABEL_BYTES_MAX {
            return Err(CoreError::invalid(format!(
                "ext label is {length} bytes long: the label must be at most \
                 16 bytes of ASCII (the on-disk s_volume_name field is 16 bytes)"
            )));
        }
        self.label = Some(label);
        Ok(self)
    }
}

/// The verified ext superblock fields [`format`] reads back from the
/// target: the parsed on-disk facts, screened by the flavour's invariant
/// when the read comes from a format run ([`superblock_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Super {
    /// Block size in bytes from `s_log_block_size`: the mandate pins
    /// `-b 4096`, anything else is refused.
    pub block_bytes: u32,
    /// The label `super_label` decoded from `s_volume_name`: the bytes
    /// up to the first NUL, or the whole 16 bytes when the run carries
    /// no NUL, trimmed through the one device-text sanitiser;
    /// `None` when the run is empty.
    pub label: Option<String>,
    /// Whether `s_feature_compat` carries [`HAS_JOURNAL_BIT`] — the
    /// journal presence the flavours' invariant screens against.
    pub has_journal: bool,
}

/// Verify the ext superblock inside a first-block byte region.
///
/// `sb` is the byte region from the target's byte 0 (as [`format`] reads
/// it): the on-disk format holds the superblock from byte 1024 into that
/// region, so the field reads run at the absolute `SB_*` offsets above. `Ok` requires, in order:
///
/// * the region reaches through byte [`SB_VOLUME_NAME_END`] — a shorter
///   buffer has no label field to read, and the refusal names the needed
///   byte count;
/// * the `u16` LE `s_magic` reads [`SUPER_MAGIC`] (0xEF53), named when
///   wrong;
/// * `s_log_block_size` (`u32` LE, `1024 << value`) encodes exactly
///   [`FIXED_BLOCK_BYTES`] — the mandate pins `-b 4096`, both the encoded
///   value and the encoded size are named on refusal;
/// * the 16-byte `s_volume_name` run holds the label: the bytes up to
///   the first NUL are the label (empty run → no label), and a run with
///   no NUL at all is a full-width 16-byte label.
///
/// The journal bit is parsed but not screened here — the flavour
/// invariant is the caller's contract ([`superblock_for`]); the plain
/// parser stays for readers that only want the block size and the label.
///
/// The field reads reuse the exFAT side's checked getters — one helper set
/// for the whole `fs` tree, no second implementation to drift. The offsets
/// and shapes pinned here are the ext on-disk format (kernel.org's ext4
/// superblock table, matching e2fsprogs's `ext2_fs.h` layout) plus this
/// house's contract; real `mke2fs` behaviour is not claimed (see the
/// module header's test discipline).
pub fn superblock(sb: &[u8]) -> Result<Super> {
    let length = sb.len();
    if length < SB_VOLUME_NAME_END {
        return Err(CoreError::invalid(format!(
            "the ext superblock buffer is {length} bytes but the on-disk format \
             needs {SB_VOLUME_NAME_END}: the last field this reader reads is the \
             16-byte s_volume_name run ending at byte {SB_VOLUME_NAME_END}"
        )));
    }
    let magic = get_u16(sb, SB_MAGIC_AT).ok_or_else(|| {
        CoreError::invalid(format!(
            "the first-block buffer ends before the s_magic field at byte {SB_MAGIC_AT}"
        ))
    })?;
    if magic != SUPER_MAGIC {
        return Err(CoreError::invalid(format!(
            "the ext superblock magic is 0x{magic:04X} not 0x{SUPER_MAGIC:04X}"
        )));
    }
    let log_block_size = get_u32(sb, SB_LOG_BLOCK_SIZE_AT).ok_or_else(|| {
        CoreError::invalid(format!(
            "the first-block buffer ends before the s_log_block_size field at \
             byte {SB_LOG_BLOCK_SIZE_AT}"
        ))
    })?;
    // Per the on-disk format the encoded size is 1024 << value; the shift
    // amount itself is checked so the arithmetic stays total. Values that
    // wrap inside a u32 (nothing here can: the 4096 screen below only
    // ever accepts 2) still end on that screen's refusal.
    let block_bytes = 1024u32.checked_shl(log_block_size).ok_or_else(|| {
        CoreError::invalid(format!(
            "ext s_log_block_size {log_block_size} does not fit a block size \
             into a u32: the mandate pins -b 4096"
        ))
    })?;
    if block_bytes != FIXED_BLOCK_BYTES {
        return Err(CoreError::invalid(format!(
            "ext block size {block_bytes} is not supported: the mandate pins \
             -b 4096 (s_log_block_size {log_block_size} encodes {block_bytes} byte blocks)"
        )));
    }
    let feature_compat = get_u32(sb, SB_FEATURE_COMPAT_AT).ok_or_else(|| {
        CoreError::invalid(format!(
            "the first-block buffer ends before the s_feature_compat field at \
             byte {SB_FEATURE_COMPAT_AT}"
        ))
    })?;
    let has_journal = feature_compat & HAS_JOURNAL_BIT != 0;
    let label = super_label(sb)?;
    Ok(Super {
        block_bytes,
        label,
        has_journal,
    })
}

/// [`superblock`] with the flavours' journal invariant enforced: ext2 must
/// have no journal and ext3/ext4 must have one, so the verification names
/// the flavour, the bit and the found value on refusal. The journal screen
/// is this module's reading of the mandate (PLAN line 694: journal on for
/// ext3/4, `-O ^has_journal` for ext2) — a contract, not a tool claim.
pub fn superblock_for(sb: &[u8], flavour: Flavour) -> Result<Super> {
    let wants_journal = flavour != Flavour::Ext2;
    let parsed = superblock(sb)?;
    if parsed.has_journal && !wants_journal {
        return Err(CoreError::invalid(format!(
            "the ext superblock carries a journal (s_feature_compat bit \
             0x{HAS_JOURNAL_BIT:04X} set) but the {flavour} mandate requires none"
        )));
    }
    if !parsed.has_journal && wants_journal {
        return Err(CoreError::invalid(format!(
            "the ext superblock carries no journal (s_feature_compat bit \
             0x{HAS_JOURNAL_BIT:04X} clear) but the {flavour} mandate requires one"
        )));
    }
    Ok(parsed)
}

/// The 16-byte `s_volume_name` run into a label: bytes up to the first NUL
/// are the value (all-NUL is no label at all), and a run with no NUL is a
/// full-width 16-byte label. The bytes decode through
/// `String::from_utf8_lossy` and the one device-text sanitiser
/// ([`device_text`]): non-ASCII becomes `?` instead of mojibake in the log.
///
/// A trailing space survives intact on disk and reads back intact through
/// `e2label`/`dumpe2fs`, while `blkid` shortens it — measured with
/// e2fsprogs 1.47.4 on this host, on-disk `RUFUS ` reports as
/// `LABEL="RUFUS"` — so comparisons must use the on-disk field or
/// `e2label`/`dumpe2fs`, never `blkid`.
///
/// The read-back above passes through [`device_text`], which trims: a
/// trailing-space label reads back shortened by our own reader too. The
/// persistence label check therefore compares against the no-space label
/// `persistence`, and callers must never compare [`Super::label`] to a
/// trailing-space [`Options::label`] for equality.
fn super_label(sb: &[u8]) -> Result<Option<String>> {
    let run = sb
        .get(SB_VOLUME_NAME_AT..SB_VOLUME_NAME_END)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "the first-block buffer ends before the s_volume_name run at \
             byte {SB_VOLUME_NAME_AT}"
            ))
        })?;
    let bytes = match run.iter().position(|&byte| byte == 0) {
        Some(nul) => run
            .get(..nul)
            .ok_or_else(|| CoreError::invalid("the ext label window vanished mid-copy"))?,
        None => run,
    };
    let decoded = device_text(&String::from_utf8_lossy(bytes));
    if decoded.is_empty() {
        Ok(None)
    } else {
        Ok(Some(decoded))
    }
}

/// Resolve the label [`format`] passes as `mke2fs -L`, enforcing the
/// persistence label rule before any tool runs.
///
/// With `persistence` unset the options' label passes through untouched
/// (`None` omits `-L`). With `persistence` set the label must be
/// [`PERSISTENCE_LABEL`]: `None` resolves to it (the formatter passes
/// `-L persistence` itself), while a conflicting `Some` refuses — naming the
/// conflict and the required label — before any `mke2fs`/`debugfs`
/// invocation, so a refusal never touches the caller's volume. The conflict
/// text runs through the one device-text sanitiser, so the refusal stays
/// ASCII even for a hand-built non-ASCII label.
fn effective_label(options: &Options) -> Result<Option<String>> {
    if !options.persistence {
        return Ok(options.label.clone());
    }
    match options.label.as_deref() {
        None => Ok(Some(PERSISTENCE_LABEL.to_string())),
        Some(PERSISTENCE_LABEL) => Ok(Some(PERSISTENCE_LABEL.to_string())),
        Some(conflict) => {
            let conflict = device_text(conflict);
            Err(CoreError::invalid(format!(
                "ext persistence needs the label `persistence` but the options carry \
                 `{conflict}`: pass no label or the `persistence` label (refusing before any tool runs)"
            )))
        }
    }
}

/// Format `target` as ext with the external formatter.
///
/// Runs `mke2fs -q -F -t <flavour> [-L <label>] -b 4096 -I 256
/// [-O ^has_journal for ext2 only] -E lazy_itable_init=0[,lazy_journal_init=0]
/// <target>` (the target path is always the last argument) as a bounded
/// capture — both streams piped and drained via `output()`, `LC_ALL=C` in
/// the child environment — then reads back bytes 0..4096 and verifies them
/// with [`superblock_for`] under the options' flavour invariant. Every
/// non-empty captured line (stdout then stderr, each through the one
/// device-text sanitiser) is logged verbatim at `Info` under the `ext`
/// target; a failing exit becomes a refusal naming the tool, the status and
/// the last [`tool::MAX_TAIL_LINES`] stderr lines. On success the summary is the
/// snapshot's final line and the verified fields come back as a [`Super`].
///
/// With `persistence` set, the label rule is enforced before any tool runs
/// (see [`effective_label`]: a conflicting label refuses without touching
/// the volume, an absent label becomes `-L persistence`), and after the
/// `mke2fs` read-back [`activate_persistence`] writes `/persistence.conf`
/// through `debugfs`, proves the write by reading the bytes back, and
/// re-checks the on-disk label — any of those steps can still refuse after
/// the volume was formatted.
pub fn format(target: &Path, options: &Options, logger: &Logger) -> Result<Super> {
    // The label rule runs before the probe: a refusal must not even run
    // `mke2fs -V`, let alone format the caller's volume.
    effective_label(options)?;
    let (tool, tool_path) = find_tool_in(&tool::path_dirs(), options.flavour)?;
    format_with(target, options, logger, tool, &tool_path)
}

/// [`format`] with the tool already resolved, so tests can point the run at
/// a stub by absolute path without touching the process environment.
fn format_with(
    target: &Path,
    options: &Options,
    logger: &Logger,
    tool: &'static str,
    tool_path: &Path,
) -> Result<Super> {
    format_with_in(target, options, logger, tool, tool_path, &tool::path_dirs())
}

/// [`format_with`] with the persistence-writer probe directories injected,
/// so tests can point the writer probe at scratch directories without
/// touching the process environment (same seam as [`find_writer_in`]).
/// Production passes the real `PATH` directories.
fn format_with_in(
    target: &Path,
    options: &Options,
    logger: &Logger,
    tool: &'static str,
    tool_path: &Path,
    writer_dirs: &[PathBuf],
) -> Result<Super> {
    // The label rule runs before the formatter spawns: a conflicting label
    // refuses here, before any `mke2fs`/`debugfs` invocation, so the
    // caller's volume is never touched by a refusal.
    let label = effective_label(options)?;
    let mut command = Command::new(tool_path);
    command
        .arg("-q")
        .arg("-F")
        .arg("-t")
        .arg(options.flavour.as_str());
    if let Some(label) = label.as_deref() {
        command.arg("-L").arg(label);
    }
    command
        .arg("-b")
        .arg(FIXED_BLOCK_BYTES.to_string())
        .arg("-I")
        .arg(INODE_BYTES.to_string());
    // The mandate: `-O ^has_journal` only for ext2 (journal on by default
    // for ext3/4).
    if options.flavour == Flavour::Ext2 {
        command.arg("-O").arg("^has_journal");
    }
    // `-E lazy_journal_init=0` is sent only when a journal is created;
    // ext2 gets only `lazy_itable_init=0`.
    let lazy = match options.flavour {
        Flavour::Ext2 => "lazy_itable_init=0",
        Flavour::Ext3 | Flavour::Ext4 => "lazy_itable_init=0,lazy_journal_init=0",
    };
    command.arg("-E").arg(lazy).arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture: the tool is this slice's external mandate (PLAN
    // lines 681-701), and `output` drains both pipes so a chatty tool
    // cannot block on a full buffer.
    let output =
        tool::output_retrying(&mut command).map_err(|error| CoreError::io(tool_path, error))?;

    let stderr_lines = tool::captured_lines(&output.stderr);
    tool::log_captured_lines(logger, "ext", &output);

    if !output.status.success() {
        return Err(tool::output_failure(
            tool,
            &output.status.to_string(),
            &stderr_lines,
        ));
    }

    let verified = superblock_for(&read_superblock(target)?, options.flavour)?;
    if !options.persistence {
        log_format_summary(
            logger,
            tool,
            &output.status.to_string(),
            options.flavour,
            &verified,
        );
        return Ok(verified);
    }
    // Persistence tail: the writer probe runs only now, after `mke2fs`
    // succeeded (a missing `debugfs` refuses with the volume otherwise
    // formatted; the stub tests pin this order).
    let (writer, writer_path) = find_writer_in(writer_dirs)?;
    activate_persistence(target, logger, writer, &writer_path)?;
    // Label read-back defence: the on-disk label must still be
    // `persistence` after the `debugfs` write.
    let final_verified = superblock_for(&read_superblock(target)?, options.flavour)?;
    if final_verified.label.as_deref() != Some(PERSISTENCE_LABEL) {
        let found = match final_verified.label.as_deref() {
            Some(name) => format!("`{name}`"),
            None => "missing".to_string(),
        };
        return Err(CoreError::invalid(format!(
            "persistence label read-back is {found} not `persistence`: the on-disk label \
             must stay `persistence` after the debugfs write"
        )));
    }
    log_format_summary(
        logger,
        tool,
        &output.status.to_string(),
        options.flavour,
        &final_verified,
    );
    Ok(final_verified)
}

/// Log the format success summary at `Info` under the `ext` target: the
/// tool, its exit, the flavour, the block size, the label and the journal
/// presence — the snapshot's final line on every successful [`format`].
fn log_format_summary(
    logger: &Logger,
    tool: &str,
    status: &str,
    flavour: Flavour,
    verified: &Super,
) {
    let label_text = match &verified.label {
        Some(name) => format!("label `{name}`"),
        None => "no label".to_string(),
    };
    let journal_text = if verified.has_journal {
        "a journal"
    } else {
        "no journal"
    };
    logger.log(
        Level::Info,
        "ext",
        &format!(
            "{tool} finished ({status}): verified {flavour} superblock with {} byte blocks, \
             {label_text} and {journal_text}",
            verified.block_bytes,
        ),
    );
}

/// Per-process counter disambiguating staged files that share a timestamp
/// (parallel format runs in one process, coarse host clocks).
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Stage [`PERSISTENCE_CONF_BYTES`] in a unique file under the process
/// temporary directory and return its path; the caller deletes it on both
/// the success and failure paths (see [`activate_persistence`]).
///
/// Uniqueness is process id plus a nanosecond timestamp plus a per-process
/// counter, created with `create_new` so a collision refuses instead of
/// clobbering: the id separates formatter processes, the timestamp
/// separates successive calls, and the counter separates calls that land in
/// the same timestamp (parallel threads, coarse clocks). Even a pathological
/// reuse (a recycled process id inside one shared timestamp) can only fail
/// the staging, never overwrite another run's bytes. `tempfile` stays a
/// dev-dependency: nothing is added to `[dependencies]` for this.
fn stage_persistence_source() -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|span| span.as_nanos())
        .map_err(|error| {
            CoreError::invalid(format!(
                "the system clock reads before the Unix epoch so no unique staged \
                 persistence name can be built: {error}"
            ))
        })?;
    let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "{STAGE_NAME_PREFIX}{}-{nanos}-{counter}.conf",
        std::process::id()
    );
    let path = std::env::temp_dir().join(name);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| {
            use std::io::Write as _;
            file.write_all(&PERSISTENCE_CONF_BYTES)
        })
        .map_err(|error| CoreError::io(&path, error))?;
    Ok(path)
}

/// Build the `debugfs -R` write request for a staged path, quoting the
/// native path (a bare path with spaces fails as
/// `write: Usage: write <native file> <new file>` — measured with e2fsprogs
/// 1.47.4, exit still 0).
///
/// A staged path holding `"` or a newline is refused instead of escaped:
/// `debugfs` honours no quoting of `"` — backslash-escaped, single-quoted
/// and raw forms all die as `debugfs: Unbalanced quotes in command line`
/// (measured with e2fsprogs 1.47.4, exit still 0) — and a newline would turn
/// the single `-R` request into several lines on a parser outside any
/// contract (a quoted newline happened to write on this host, but the shape
/// is version-fragile and would split the logged transcript). Refusing keeps
/// the request one ASCII line the tool either runs whole or never sees.
fn staged_write_request(staged: &Path) -> Result<String> {
    let text = staged.to_str().ok_or_else(|| {
        CoreError::invalid(
            "the staged persistence path is not UTF-8 so no debugfs write request can \
             name it: refusing before any tool runs",
        )
    })?;
    if text.contains('"') || text.contains('\n') {
        return Err(CoreError::invalid(format!(
            "the staged persistence path `{}` holds a double quote or newline the \
             debugfs write request cannot quote: refusing before any tool runs",
            device_text(text)
        )));
    }
    Ok(format!("write \"{text}\" {PERSISTENCE_CONF_PATH}"))
}

/// Write and prove `/persistence.conf` through an already-resolved `debugfs`.
///
/// Stages [`PERSISTENCE_CONF_BYTES`] in a unique file under the process
/// temporary directory (see [`stage_persistence_source`]), runs
/// `debugfs -w -R "write \"<staged>\" /persistence.conf" <target>`, and
/// deletes the staged file on both the success and failure paths. The write
/// exit status is not a success contract — `debugfs` exits 0 even when the
/// write fails (measured with e2fsprogs 1.47.4: `write: Ext2 file already
/// exists` and `write: File not found by ext2_lookup` both exit 0) — so
/// success is only the read-back: `debugfs -R "cat /persistence.conf"`
/// `<target>` (no `-w`, read-only) must exit 0 with its captured stdout
/// exactly equal to the staged bytes (measured with e2fsprogs 1.47.4: the
/// `cat` run returns exactly those 8 bytes on stdout, the version banner on
/// stderr). Anything else is a refusal naming `debugfs`, the status (or the
/// byte mismatch) and the last at most [`tool::MAX_TAIL_LINES`] lines of the
/// diagnostic streams. Every non-empty captured line of both runs is logged
/// verbatim at `Info` under the `ext` target; the byte comparison runs on
/// the raw captured stdout, never on the line-split sanitised view.
fn activate_persistence(
    target: &Path,
    logger: &Logger,
    writer: &str,
    writer_path: &Path,
) -> Result<()> {
    let staged = stage_persistence_source()?;
    let request = match staged_write_request(&staged) {
        Ok(request) => request,
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
    };
    let mut write = Command::new(writer_path);
    write.arg("-w").arg("-R").arg(&request).arg(target);
    write
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture, as in [`format`]: `output` drains both pipes so a
    // chatty tool cannot block on a full buffer.
    let write_output = match tool::output_retrying(&mut write) {
        Ok(output) => output,
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(CoreError::io(writer_path, error));
        }
    };
    let _ = std::fs::remove_file(&staged);
    tool::log_captured_lines(logger, "ext", &write_output);
    if !write_output.status.success() {
        return Err(tool::output_failure(
            writer,
            &write_output.status.to_string(),
            &combined_tail(&write_output),
        ));
    }
    let mut cat = Command::new(writer_path);
    cat.arg("-R").arg(PERSISTENCE_CONF_CAT).arg(target);
    cat.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    let cat_output =
        tool::output_retrying(&mut cat).map_err(|error| CoreError::io(writer_path, error))?;
    tool::log_captured_lines(logger, "ext", &cat_output);
    if !cat_output.status.success() {
        return Err(tool::output_failure(
            writer,
            &cat_output.status.to_string(),
            &combined_tail(&cat_output),
        ));
    }
    if cat_output.stdout != PERSISTENCE_CONF_BYTES {
        return Err(persistence_mismatch(writer, &cat_output));
    }
    Ok(())
}

/// Chain a writer run's stderr lines then its stdout lines for a refusal
/// tail: `debugfs` splits its transcript the way `e2fsck` does (the version
/// banner and the errors on stderr, request notes like `Allocated inode: N`
/// on stdout — measured with e2fsprogs 1.47.4), so a stderr-only tail would
/// drop half the transcript. [`tool::output_failure`] caps the chained sequence
/// at [`tool::MAX_TAIL_LINES`].
fn combined_tail(output: &std::process::Output) -> Vec<String> {
    tool::captured_lines(&output.stderr)
        .into_iter()
        .chain(tool::captured_lines(&output.stdout))
        .collect()
}

/// Refusal for a persistence read-back that is not exactly
/// [`PERSISTENCE_CONF_BYTES`]: names `debugfs`, the flag file, the expected
/// and found byte counts with a sanitised preview of what came back, and the
/// last at most [`tool::MAX_TAIL_LINES`] lines of the diagnostic streams (the
/// preview runs through the one device-text sanitiser, so the refusal stays
/// ASCII whatever bytes the tool returned).
fn persistence_mismatch(writer: &str, output: &std::process::Output) -> CoreError {
    let preview = device_text(&String::from_utf8_lossy(&output.stdout));
    let combined = combined_tail(output);
    let tail = tool::capped_tail(&combined);
    let report = format!(
        "{writer} read-back mismatch on {PERSISTENCE_CONF_PATH}: expected {} bytes \
         `/ union` plus newline but got {} bytes `{preview}`",
        PERSISTENCE_CONF_BYTES.len(),
        output.stdout.len(),
    );
    if tail.is_empty() {
        CoreError::invalid(format!("{report} with no diagnostic output"))
    } else {
        CoreError::invalid(format!("{report}: {}", tail.join("; ")))
    }
}

/// Verify `target` with the external checker.
///
/// Runs `e2fsck -f -n <target>` (the target path is always the last
/// argument) as a bounded capture — both streams piped and drained via
/// `output()`, `LC_ALL=C` in the child environment, stdin null. Every
/// non-empty captured line (stdout then stderr, each through the one
/// device-text sanitiser) is logged verbatim at `Info` under the `ext`
/// target; a failing exit becomes a refusal naming the tool, the status and
/// the last [`tool::MAX_TAIL_LINES`] lines of stderr followed by stdout (stderr
/// first, then stdout, capped as one sequence — `e2fsck` reports its
/// findings on stdout, measured on this host against e2fsprogs 1.47.4
/// during this slice: a corrupt filesystem's `Pass 1: ...` lines went to
/// stdout with only the version banner on stderr). Exit 0 means the
/// filesystem is clean (measured against e2fsprogs 1.47.4 during this
/// slice: clean image exit 0, corrupt image exit 4). The `-n` flag answers
/// no to every repair prompt, so this never writes to the target
/// (measured read-only on this host against e2fsprogs 1.47.4 during this
/// slice: a corrupt ext4 image's sha256 was identical before and after
/// `e2fsck -f -n`).
pub fn verify(target: &Path, logger: &Logger) -> Result<()> {
    let (tool, tool_path) = find_verify_tool_in(&tool::path_dirs())?;
    verify_with(target, logger, tool, &tool_path)
}

/// [`verify`] with the tool already resolved, so tests can point the run at
/// a stub by absolute path without touching the process environment.
fn verify_with(target: &Path, logger: &Logger, tool: &'static str, tool_path: &Path) -> Result<()> {
    let mut command = Command::new(tool_path);
    command.arg("-f").arg("-n").arg(target);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C");
    // Bounded capture: `output` drains both pipes so a chatty tool cannot
    // block on a full buffer.
    let output =
        tool::output_retrying(&mut command).map_err(|error| CoreError::io(tool_path, error))?;

    tool::log_captured_lines(logger, "ext", &output);

    if !output.status.success() {
        // The refusal tail chains stderr then stdout: `e2fsck` reports
        // its findings on stdout (measured against e2fsprogs 1.47.4), so
        // a stderr-only tail would read as a bare banner on a real
        // refusal. `tool::output_failure` caps the chained sequence at
        // [`tool::MAX_TAIL_LINES`].
        return Err(tool::output_failure(
            tool,
            &output.status.to_string(),
            &combined_tail(&output),
        ));
    }

    logger.log(
        Level::Info,
        "ext",
        &format!(
            "{tool} finished ({}): verified ext filesystem clean",
            output.status,
        ),
    );
    Ok(())
}

/// Read bytes 0..4096 of `target` — the first-block region where the
/// on-disk format lays the superblock at 1024 — for [`superblock_for`]
/// verification.
fn read_superblock(target: &Path) -> Result<[u8; READ_REGION_BYTES]> {
    let file = std::fs::File::open(target).map_err(|err| CoreError::io(target, err))?;
    let mut region = [0u8; READ_REGION_BYTES];
    file.read_exact_at(&mut region, 0)
        .map_err(|err| CoreError::io(target, err))?;
    Ok(region)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A 15-byte ASCII label the ext2 fixture carries — one byte of room
    /// left under the 16-byte field, so the NUL terminator is real.
    const LABELED_FIXTURE_LABEL: &[u8; 15] = b"RUFUS-EXT2-LAB0";

    /// Build a synthetic first-block byte region: the on-disk superblock at
    /// 1024 with `journal` driving [`HAS_JOURNAL_BIT`] (the fixtures also
    /// carry ordinary companion compat bits — `0x3C` = has_journal +
    /// ext_attr + resize_inode + dir_index with the journal, bare
    /// dir_index without it — but only the journal bit is parsed), a
    /// `s_log_block_size` of `log_block_size`, and `label` copied into
    /// `s_volume_name`, zero padding filling the rest of the run.
    /// Stub/synthetic only: pins the layout this module parses, claims
    /// nothing about real `mke2fs` output.
    fn synthetic_sb(journal: bool, log_block_size: u32, label: &[u8]) -> [u8; READ_REGION_BYTES] {
        let mut buffer = [0u8; READ_REGION_BYTES];
        buffer[SB_MAGIC_AT..SB_MAGIC_AT + 2].copy_from_slice(&SUPER_MAGIC.to_le_bytes());
        buffer[SB_LOG_BLOCK_SIZE_AT..SB_LOG_BLOCK_SIZE_AT + 4]
            .copy_from_slice(&log_block_size.to_le_bytes());
        let compat: u32 = if journal { 0x3C } else { 0x20 };
        buffer[SB_FEATURE_COMPAT_AT..SB_FEATURE_COMPAT_AT + 4]
            .copy_from_slice(&compat.to_le_bytes());
        let filled = label.len().min(LABEL_BYTES_MAX);
        buffer[SB_VOLUME_NAME_AT..SB_VOLUME_NAME_AT + filled].copy_from_slice(&label[..filled]);
        buffer
    }

    /// The bytes of a synthetic label naming `flavour`: `RUFUS-EXT4-TEST`
    /// for the ext4 row, and so on (15 bytes each).
    fn flavour_label(flavour: Flavour) -> Vec<u8> {
        format!("RUFUS-{}-TEST", flavour.as_str().to_ascii_uppercase()).into_bytes()
    }

    /// Write an executable `#!/bin/sh` stub into `dir`. Stub behaviour
    /// only: exercises the probe/spawn plumbing, never the real tool.
    fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("the stub writes");
        let mut permissions = std::fs::metadata(&path)
            .expect("the stub exists")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("the stub is executable");
        path
    }

    /// The discovery tests inject scratch directories (see
    /// [`find_tool_in`]): no test here mutates the process environment,
    /// so every test in this module runs in parallel safely.
    fn probe_dirs(dir: &Path) -> Vec<PathBuf> {
        vec![dir.to_path_buf()]
    }

    #[test]
    fn superblock_accepts_the_three_flavours_and_label_variants() {
        for flavour in [Flavour::Ext2, Flavour::Ext3, Flavour::Ext4] {
            let want_journal = flavour != Flavour::Ext2;
            let label_text = format!("RUFUS-{}-TEST", flavour.as_str().to_ascii_uppercase());
            for (kind, label_bytes) in [
                ("labeled", label_text.clone().into_bytes()),
                ("empty", Vec::new()),
            ] {
                let buffer = synthetic_sb(want_journal, 2, &label_bytes);
                let parsed = superblock(&buffer).expect("the synthetic superblock parses");
                assert_eq!(parsed.block_bytes, FIXED_BLOCK_BYTES, "{kind} {flavour}");
                assert_eq!(parsed.has_journal, want_journal, "{kind} {flavour}");
                if label_bytes.is_empty() {
                    assert_eq!(parsed.label, None, "{kind} {flavour}");
                } else {
                    assert_eq!(
                        parsed.label.as_deref(),
                        Some(label_text.as_str()),
                        "{kind} {flavour}"
                    );
                }
                // The flavour invariant screens the same fixture for its
                // own flavour without complaint.
                superblock_for(&buffer, flavour).expect("the invariant matches");
            }
        }
    }

    #[test]
    fn superblock_label_trims_at_the_nul_terminator() {
        let buffer = synthetic_sb(false, 2, b"RUFUS");
        let parsed = superblock(&buffer).expect("the synthetic superblock parses");
        assert_eq!(parsed.label.as_deref(), Some("RUFUS"));
        // Trailing run bytes past the NUL stay ignored (zero padding here).
        assert!(
            buffer[SB_VOLUME_NAME_AT + 5..SB_VOLUME_NAME_END]
                .iter()
                .all(|&byte| byte == 0)
        );
    }

    #[test]
    fn superblock_refuses_a_wrong_magic() {
        let mut buffer = synthetic_sb(false, 2, b"RUFUS");
        buffer[SB_MAGIC_AT..SB_MAGIC_AT + 2].copy_from_slice(&0xEF52u16.to_le_bytes());
        let error = superblock(&buffer).expect_err("0xEF52 is not the ext magic");
        let text = error.to_string();
        assert!(text.contains("0xEF53"), "{text}");
        assert!(text.contains("0xEF52"), "{text}");
        let found_at = text.find("0xEF52").expect("the found magic is named");
        let expected_at = text.find("0xEF53").expect("the expected magic is named");
        assert!(
            found_at < expected_at,
            "the found magic comes first: {text}"
        );
    }

    #[test]
    fn superblock_refuses_unpinned_block_sizes() {
        // s_log_block_size 1 -> 2048 bytes, 3 -> 8192 bytes: both refuse
        // naming the encoded size and the pinned 4096.
        for (log_block_size, encoded) in [(1u32, 2048u32), (3, 8192)] {
            let buffer = synthetic_sb(false, log_block_size, b"RUFUS");
            let error = superblock(&buffer).expect_err("only the pinned 4096 is accepted");
            let text = error.to_string();
            assert!(text.contains(&encoded.to_string()), "{text}");
            assert!(text.contains("4096"), "{text}");
        }
    }

    #[test]
    fn superblock_accepts_a_full_width_label_without_a_nul() {
        let buffer = synthetic_sb(false, 2, b"ABCDEFGHIJKLMNOP");
        let parsed = superblock(&buffer).expect("16 non-NUL bytes are a full-width label");
        assert_eq!(parsed.label.as_deref(), Some("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn superblock_refuses_a_cut_off_buffer() {
        let buffer = synthetic_sb(false, 2, b"RUFUS-EXT2-LAB00");
        let cut: Vec<u8> = buffer[..SB_VOLUME_NAME_END - 1].to_vec();
        let error = superblock(&cut).expect_err("a 1159-byte region has no complete label");
        let text = error.to_string();
        assert!(text.contains("1159"), "{text}");
        assert!(text.contains("1160"), "{text}");
    }

    #[test]
    fn options_new_defaults_flavour_label_and_persistence() {
        let options = Options::new(Flavour::Ext3);
        assert_eq!(options.flavour, Flavour::Ext3);
        assert_eq!(options.label, None);
        assert!(!options.persistence);
        // The 4096-byte block size is no option: no field carries one.
    }

    #[test]
    fn options_label_rules_pin_16_ascii_bytes() {
        let full = Options::new(Flavour::Ext4)
            .with_label("ABCDEFGHIJKLMNOP")
            .expect("16 ASCII bytes fit the field");
        assert_eq!(full.label.as_deref(), Some("ABCDEFGHIJKLMNOP"));

        let too_long = Options::new(Flavour::Ext4)
            .with_label("ABCDEFGHIJKLMNOPQ")
            .expect_err("17 bytes refuse");
        let text = too_long.to_string();
        assert!(text.contains("17"), "{text}");
        assert!(text.contains("16"), "{text}");
        assert!(text.contains("ASCII"), "{text}");

        let non_ascii = Options::new(Flavour::Ext4)
            .with_label("RUFUS\u{4e2d}")
            .expect_err("non-ASCII refuses");
        let text = non_ascii.to_string();
        assert!(text.contains("ASCII"), "{text}");
        assert!(text.contains("16"), "{text}");
    }

    #[test]
    fn probe_finds_mke2fs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let stub = write_stub(scratch.path(), "mke2fs", "#!/bin/sh\nexit 0\n");
        let (name, path) =
            find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext4).expect("the stub probes");
        assert_eq!(name, "mke2fs");
        assert_eq!(path, stub);
    }

    #[test]
    fn probe_falls_back_to_mkfs_ext4() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkfs.ext4", "#!/bin/sh\nexit 0\n");
        let (name, _) =
            find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext4).expect("the alias probes");
        assert_eq!(name, "mkfs.ext4");
        // The flavour-free probe of [`find_tool`] walks the same directory
        // through the full name list and lands on the same alias.
        let (generic, _) =
            probe_candidates(&probe_dirs(scratch.path()), &TOOL_NAMES).expect("it probes");
        assert_eq!(generic, "mkfs.ext4");
    }

    #[test]
    fn probe_prefers_mke2fs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mke2fs", "#!/bin/sh\nexit 0\n");
        write_stub(scratch.path(), "mkfs.ext4", "#!/bin/sh\nexit 0\n");
        let (name, _) =
            find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext4).expect("a stub probes");
        assert_eq!(name, "mke2fs");
    }

    #[test]
    fn probe_with_no_directories_names_the_package() {
        let error = find_tool_in(&[], Flavour::Ext3).expect_err("nothing can be found");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
            "the empty-PATH text is pinned exactly"
        );
    }

    #[test]
    fn probe_treats_a_failing_version_check_as_absent() {
        // A +x stub that exits 1 on any version probe: the probe fails, so
        // the scan reports the same package error as the empty directory
        // list. Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mke2fs", "#!/bin/sh\nexit 1\n");
        let error = find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext3)
            .expect_err("the failing probe is absent");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
    }

    #[test]
    fn probe_skips_files_that_are_not_executable() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        std::fs::write(scratch.path().join("mke2fs"), "#!/bin/sh\nexit 0\n")
            .expect("the non-executable file writes");
        let error = find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext2)
            .expect_err("a non-executable is skipped");
        assert!(error.to_string().contains("e2fsprogs"), "{error}");
    }

    #[test]
    fn probe_pins_the_dash_v_version_flag() {
        // The version check sends `-V` (this module's fixed contract; the
        // e2fsprogs family rejects `--version`, measured against the
        // installed e2fsprogs 1.47.4 during this slice) and the stub
        // records its first argument as proof.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" > '{}'\nexit 0\n",
            record.display()
        );
        write_stub(scratch.path(), "mke2fs", &body);
        let (name, _) =
            find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext2).expect("the stub probes");
        assert_eq!(name, "mke2fs");
        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        assert_eq!(recorded.trim(), "-V");
    }

    #[test]
    fn probe_narrows_the_alias_to_the_chosen_flavour() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        write_stub(scratch.path(), "mkfs.ext2", "#!/bin/sh\nexit 0\n");
        // The flavour-narrowed scan of [`format`] refuses to treat an
        // mkfs.ext2 as a stand-in for any other generation.
        let wrong_flavour = find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext4)
            .expect_err("mkfs.ext2 is not an ext4 alias");
        assert_eq!(
            wrong_flavour.to_string(),
            format!("invalid input: {MISSING_TOOL_HINT}"),
        );
        // The matching flavour finds exactly that alias.
        let (name, _) = find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext2)
            .expect("mkfs.ext2 is the ext2 alias");
        assert_eq!(name, "mkfs.ext2");
        // The canonical tool is never narrowed away.
        write_stub(scratch.path(), "mke2fs", "#!/bin/sh\nexit 0\n");
        let (canonical, _) = find_tool_in(&probe_dirs(scratch.path()), Flavour::Ext3)
            .expect("the canonical tool serves every flavour");
        assert_eq!(canonical, "mke2fs");
    }

    #[test]
    fn format_drives_the_stub_and_verifies_the_superblock() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mke2fs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\necho stub-stdout-line\necho stub-stderr-line >&2\nexit 0\n",
        );
        // The target already carries the synthetic ext4 superblock (the
        // stub never touches the target bytes; the read-back below
        // verifies them).
        let label = flavour_label(Flavour::Ext4);
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, &label))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Flavour::Ext4)
            .with_label(String::from_utf8(label.clone()).expect("synthetic labels are ASCII"))
            .expect("the synthetic label is valid");

        let verified = format_with(&target, &options, &logger, "mke2fs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(verified.block_bytes, FIXED_BLOCK_BYTES);
        assert!(verified.has_journal);
        assert_eq!(verified.label.as_deref(), Some("RUFUS-EXT4-TEST"));

        let snapshot = logger.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|record| record.target == "ext" && record.level == Level::Info),
            "every line is logged at Info under the ext target"
        );
        let messages: Vec<&str> = snapshot
            .iter()
            .map(|record| record.message.as_str())
            .collect();
        assert!(messages.contains(&"stub-stdout-line"), "{messages:?}");
        assert!(messages.contains(&"stub-stderr-line"), "{messages:?}");
        // The stub echoes its own argv: pins `-q -F -t`, the label flag,
        // the pinned `-b/-I` sizes, the ext4 `-E` set and the target path
        // as the last argument, in this exact order.
        let expected = format!(
            "got: -q -F -t ext4 -L RUFUS-EXT4-TEST -b 4096 -I 256 \
             -E lazy_itable_init=0,lazy_journal_init=0 {}",
            target.display()
        );
        assert!(messages.contains(&expected.as_str()), "{messages:?}");
        // The final line names the tool, the exit, the block size and the
        // label plus journal presence.
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("mke2fs"), "{summary}");
        assert!(summary.contains("exit status: 0"), "{summary}");
        assert!(summary.contains("4096"), "{summary}");
        assert!(summary.contains("label `RUFUS-EXT4-TEST`"), "{summary}");
        assert!(summary.contains("a journal"), "{summary}");
    }

    #[test]
    fn format_ext2_pins_the_has_journal_opt_out_argv() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mke2fs",
            "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\nexit 0\n",
        );
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(false, 2, LABELED_FIXTURE_LABEL))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Flavour::Ext2);

        let verified = format_with(&target, &options, &logger, "mke2fs", &tool_path)
            .expect("the stub exits 0");
        assert_eq!(verified.block_bytes, FIXED_BLOCK_BYTES);
        assert!(!verified.has_journal);
        assert_eq!(verified.label.as_deref(), Some("RUFUS-EXT2-LAB0"));

        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        // ext2 only: `-O ^has_journal`, and the `-E` value without the
        // journal term, pinning both halves of the mandate's split.
        let expected = format!(
            "got: -q -F -t ext2 -b 4096 -I 256 -O ^has_journal \
             -E lazy_itable_init=0 {}",
            target.display()
        );
        assert!(messages.contains(&expected), "{messages:?}");
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("no journal"), "{summary}");
    }

    #[test]
    fn format_flavours_pin_their_spawn_tokens() {
        for flavour in [Flavour::Ext3, Flavour::Ext4] {
            let scratch = tempfile::tempdir().expect("a scratch dir");
            let tool_path = write_stub(
                scratch.path(),
                "mke2fs",
                "#!/bin/sh\nprintf 'got: %s\\n' \"$*\"\nexit 0\n",
            );
            let label = flavour_label(flavour);
            let target = scratch.path().join("volume.bin");
            std::fs::write(&target, synthetic_sb(true, 2, &label))
                .expect("the synthetic target writes");
            let logger = Logger::new(Level::Trace);
            let options = Options::new(flavour);

            let verified = format_with(&target, &options, &logger, "mke2fs", &tool_path)
                .expect("the stub exits 0");
            assert!(verified.has_journal, "{flavour}");
            let messages: Vec<String> = logger
                .snapshot()
                .iter()
                .map(|record| record.message.clone())
                .collect();
            // Both journal flavours omit the `-O` opt-out but keep the
            // two-term `-E` value, and differ only in the `-t` token.
            let expected = format!(
                "got: -q -F -t {} -b 4096 -I 256 -E lazy_itable_init=0,lazy_journal_init=0 {}",
                flavour.as_str(),
                target.display()
            );
            assert!(messages.contains(&expected), "{messages:?}");
            assert!(
                !messages
                    .iter()
                    .any(|message| message.starts_with("got:") && message.contains("-O")),
                "no `-O` for journal flavours: {messages:?}"
            );
        }
    }

    #[test]
    fn format_failure_carries_the_status_and_the_tail() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "mke2fs",
            "#!/bin/sh\necho wiping\necho\n\
             echo l01 >&2\necho l02 >&2\necho l03 >&2\necho l04 >&2\necho l05 >&2\n\
             echo l06 >&2\necho l07 >&2\necho l08 >&2\necho l09 >&2\necho l10 >&2\n\
             exit 3\n",
        );
        // No target file is created: the run fails before any read-back.
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Flavour::Ext3);

        let error = format_with(&target, &options, &logger, "mke2fs", &tool_path)
            .expect_err("the stub exits 3");
        let text = error.to_string();
        assert!(text.contains("exit status: 3"), "{text}");
        assert!(text.contains("l10"), "{text}");
        assert!(text.contains("l03"), "{text}");
        assert!(!text.contains("l01"), "{text}");
        assert!(!text.contains("l02"), "{text}");
        assert!(
            !text.contains("wiping"),
            "stdout lines are logged, never part of the refusal: {text}"
        );

        // The stdout lines were still logged before the failure, and the
        // blank echo never became a record.
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        assert!(messages.contains(&"wiping".to_string()), "{messages:?}");
        assert!(
            messages.iter().all(|message| !message.is_empty()),
            "{messages:?}"
        );
    }

    #[test]
    fn format_surfaces_the_short_target_io_refusal() {
        // A target shorter than one block dies in `read_exact_at` AFTER a
        // successful tool run, surfaced as the house `CoreError::io`
        // naming the path and the io source.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "mke2fs", "#!/bin/sh\nexit 0\n");
        let target = scratch.path().join("tiny.bin");
        std::fs::write(&target, [b'e'; 100]).expect("the short target writes");
        let logger = Logger::new(Level::Trace);
        let options = Options::new(Flavour::Ext4);

        let error = format_with(&target, &options, &logger, "mke2fs", &tool_path)
            .expect_err("the 100-byte target cannot yield a superblock");
        let text = error.to_string();
        assert!(matches!(error, CoreError::Io { .. }), "{text}");
        assert!(text.contains(&target.display().to_string()), "{text}");
        // `read_exact_at`'s UnexpectedEof surfaces with the source's own
        // text; the test pins the whole house shape: path + source.
        assert!(text.contains("failed to fill whole buffer"), "{text}");
        let CoreError::Io { source, .. } = &error else {
            panic!("the error is the house io variant: {text}")
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn verify_drives_the_stub_checker_with_force_and_read_only_flags() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let record = scratch.path().join("args");
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" > '{}'\necho stub-stdout-line\necho stub-stderr-line >&2\nexit 0\n",
            record.display()
        );
        let tool_path = write_stub(scratch.path(), "e2fsck", &body);
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, [0u8; 64]).expect("the target writes");
        let logger = Logger::new(Level::Trace);

        verify_with(&target, &logger, "e2fsck", &tool_path).expect("the stub exits 0");

        let recorded = std::fs::read_to_string(&record).expect("the stub recorded");
        // One `<%s>` group per argv element, in order: a single
        // space-joined argument could never produce this shape, so the
        // flags are pinned as separate elements.
        let expected = format!("<-f><-n><{}>", target.display());
        assert_eq!(recorded, expected);
        let snapshot = logger.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|record| record.target == "ext" && record.level == Level::Info),
            "every line is logged at Info under the ext target"
        );
        let messages: Vec<&str> = snapshot
            .iter()
            .map(|record| record.message.as_str())
            .collect();
        assert!(messages.contains(&"stub-stdout-line"), "{messages:?}");
        assert!(messages.contains(&"stub-stderr-line"), "{messages:?}");
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("e2fsck"), "{summary}");
        assert!(summary.contains("exit status: 0"), "{summary}");
    }

    #[test]
    fn verify_failure_carries_the_status_and_the_tail() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "e2fsck",
            "#!/bin/sh\necho wiping\necho\n\
             echo l01 >&2\necho l02 >&2\necho l03 >&2\necho l04 >&2\necho l05 >&2\n\
             echo l06 >&2\necho l07 >&2\necho l08 >&2\necho l09 >&2\necho l10 >&2\n\
             exit 4\n",
        );
        // No target file is created: the run fails before any read-back.
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);

        let error =
            verify_with(&target, &logger, "e2fsck", &tool_path).expect_err("the stub exits 4");
        let text = error.to_string();
        assert!(text.contains("e2fsck"), "{text}");
        assert!(text.contains("exit status: 4"), "{text}");
        assert!(text.contains("l10"), "{text}");
        assert!(text.contains("l04"), "{text}");
        assert!(!text.contains("l01"), "{text}");
        assert!(!text.contains("l02"), "{text}");
        assert!(!text.contains("l03"), "{text}");
        // The stdout line is the newest entry of the chained
        // stderr-then-stdout sequence, so it survives the 8-line cap
        // alongside the last seven stderr lines.
        assert!(text.contains("wiping"), "{text}");

        // The stdout lines were still logged before the failure, and the
        // blank echo never became a record.
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        assert!(messages.contains(&"wiping".to_string()), "{messages:?}");
        assert!(
            messages.iter().all(|message| !message.is_empty()),
            "{messages:?}"
        );
    }

    #[test]
    fn verify_failure_carries_stdout_findings() {
        // `e2fsck` reports its findings on stdout (measured against
        // e2fsprogs 1.47.4 during this slice): a stub that writes only to
        // stdout must still have those lines carried in the refusal.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(
            scratch.path(),
            "e2fsck",
            "#!/bin/sh\necho 'Pass 1: Checking inodes, blocks, and sizes'\n\
             echo 'Inode 7 has illegal block(s). Clear? no'\nexit 4\n",
        );
        let target = scratch.path().join("missing.bin");
        let logger = Logger::new(Level::Trace);

        let error =
            verify_with(&target, &logger, "e2fsck", &tool_path).expect_err("the stub exits 4");
        let text = error.to_string();
        assert!(text.contains("e2fsck"), "{text}");
        assert!(text.contains("exit status: 4"), "{text}");
        assert!(
            text.contains("Pass 1: Checking inodes, blocks, and sizes"),
            "{text}"
        );
        assert!(
            text.contains("Inode 7 has illegal block(s). Clear? no"),
            "{text}"
        );
    }

    #[test]
    fn verify_refuses_a_killed_checker() {
        // A child killed by a signal has no exit code, so
        // `status.success()` is false and the run refuses: never `Ok`.
        // Stub behaviour only.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let tool_path = write_stub(scratch.path(), "e2fsck", "#!/bin/sh\nkill -9 $$\n");
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, [0u8; 64]).expect("the target writes");
        let logger = Logger::new(Level::Trace);

        verify_with(&target, &logger, "e2fsck", &tool_path)
            .expect_err("a killed child is never clean");
    }

    #[test]
    fn verify_without_a_checker_names_the_package() {
        let error = find_verify_tool_in(&[]).expect_err("nothing can be found");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {VERIFY_MISSING_TOOL_HINT}"),
            "the empty-PATH text is pinned exactly"
        );
        let text = error.to_string();
        assert!(text.contains("e2fsck"), "{text}");
        assert!(text.contains("e2fsprogs"), "{text}");
    }

    #[test]
    fn superblock_for_enforces_the_mandates_journal_invariant() {
        // ext2 with the journal bit set refuses, naming the flavour, the
        // bit and the found state.
        let ext2_with_journal = synthetic_sb(true, 2, b"RUFUS");
        let error = superblock_for(&ext2_with_journal, Flavour::Ext2)
            .expect_err("ext2 must carry no journal");
        let text = error.to_string();
        assert!(text.contains("ext2"), "{text}");
        assert!(text.contains("0x0004"), "{text}");
        assert!(text.contains("set"), "{text}");
        assert!(text.contains("requires none"), "{text}");

        // ext3 and ext4 without the journal bit refuse symmetrically.
        for flavour in [Flavour::Ext3, Flavour::Ext4] {
            let buffer = synthetic_sb(false, 2, &flavour_label(flavour));
            let error = superblock_for(&buffer, flavour)
                .expect_err("journal flavours must carry the journal");
            let text = error.to_string();
            assert!(text.contains(flavour.as_str()), "{text}");
            assert!(text.contains("0x0004"), "{text}");
            assert!(text.contains("clear"), "{text}");
            assert!(text.contains("requires one"), "{text}");
        }
    }

    /// Persistence options with the given label (or none): the struct
    /// fields are set directly so a conflicting label needs no
    /// [`Options::with_label`] round-trip.
    fn persistence_options(label: Option<&str>) -> Options {
        Options {
            flavour: Flavour::Ext4,
            label: label.map(str::to_string),
            persistence: true,
        }
    }

    /// Write an executable `#!/bin/sh` stub `mke2fs` that appends one
    /// `printf '<%s>' "$@"` line per invocation to `log`, so a test can
    /// assert the exact argv it received.
    fn write_recording_mke2fs(dir: &Path, log: &Path) -> PathBuf {
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" >> '{}'\nprintf '\\n' >> '{}'\nexit 0\n",
            log.display(),
            log.display()
        );
        write_stub(dir, "mke2fs", &body)
    }

    /// Write an executable `#!/bin/sh` stub `debugfs` that appends one
    /// `printf '<%s>' "$@"` line per invocation to `log` (including the
    /// `-V` probe), answers every `cat /persistence.conf` request by
    /// printing `cat_body` on stdout, and exits 0 for everything — the
    /// honest shape of the real tool's lying exit status. `cat_body` is a
    /// shell `printf` payload without `%` or quotes: `"/ union\\n"` for the
    /// real bytes, `"WRONG\\n"` for wrong bytes, `""` for an empty reply.
    fn write_debugfs_stub(dir: &Path, log: &Path, cat_body: &str) -> PathBuf {
        let body = format!(
            "#!/bin/sh\nprintf '<%s>' \"$@\" >> '{}'\nprintf '\\n' >> '{}'\n\
             if [ \"$2\" = 'cat /persistence.conf' ]; then\nprintf '{cat_body}'\nfi\nexit 0\n",
            log.display(),
            log.display()
        );
        write_stub(dir, "debugfs", &body)
    }

    /// Read a stub argv log back as one entry per invocation line.
    fn stub_log_lines(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .expect("the stub recorded")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Pull the staged path out of a recorded writer line of the shape
    /// `<-w><-R><write "<staged>" /persistence.conf><target>>`, and assert
    /// the staged file is already gone (the run deletes it on every path).
    fn staged_path_from_write_line(line: &str, target: &Path) -> PathBuf {
        let prefix = "<-w><-R><write \"";
        let suffix = format!("\" /persistence.conf><{}>", target.display());
        let rest = line
            .strip_prefix(prefix)
            .expect("the write request opens quoted");
        let staged = rest
            .strip_suffix(&suffix)
            .expect("the write request names the flag file and the target");
        let path = PathBuf::from(staged);
        assert!(
            !path.exists(),
            "the staged file is gone after the run: {}",
            path.display()
        );
        path
    }

    #[test]
    fn effective_label_resolves_the_persistence_rule() {
        // Plain options pass through untouched.
        let plain = effective_label(&Options::new(Flavour::Ext4)).expect("no label, no rule");
        assert_eq!(plain, None);
        let labeled = effective_label(
            &Options::new(Flavour::Ext2)
                .with_label("RUFUS")
                .expect("the label is valid"),
        )
        .expect("plain labels pass through");
        assert_eq!(labeled.as_deref(), Some("RUFUS"));

        // Persistence with no label resolves to the mandated one.
        let resolved =
            effective_label(&persistence_options(None)).expect("None becomes persistence");
        assert_eq!(resolved.as_deref(), Some("persistence"));

        // Persistence with the mandated label passes through.
        let kept = effective_label(&persistence_options(Some("persistence")))
            .expect("the mandated label passes");
        assert_eq!(kept.as_deref(), Some("persistence"));

        // Persistence with a conflicting label refuses, naming both.
        let error = effective_label(&persistence_options(Some("RUFUS-X")))
            .expect_err("a conflicting label refuses");
        let text = error.to_string();
        assert!(text.contains("persistence"), "{text}");
        assert!(text.contains("RUFUS-X"), "{text}");

        // The refusal stays ASCII even for a hand-built non-ASCII label.
        let mut nasty = persistence_options(None);
        nasty.label = Some("RUFU\u{4e2d}S".to_string());
        let error = effective_label(&nasty).expect_err("non-ASCII conflicts refuse");
        assert!(error.to_string().is_ascii(), "{error}");
    }

    #[test]
    fn staged_write_request_quotes_but_never_invents_escaping() {
        let plain = staged_write_request(Path::new("/tmp/rufus-persistence-1-2-3.conf"))
            .expect("a plain path quotes");
        assert_eq!(
            plain,
            "write \"/tmp/rufus-persistence-1-2-3.conf\" /persistence.conf"
        );
        // Spaces ride inside the quotes.
        let spaced = staged_write_request(Path::new("/tmp/with space/staged.conf"))
            .expect("a spaced path quotes");
        assert_eq!(
            spaced,
            "write \"/tmp/with space/staged.conf\" /persistence.conf"
        );
        // A double quote or a newline refuses: debugfs honours no escaping
        // for the first (measured `Unbalanced quotes`), and the second
        // would split the single `-R` request.
        for bad in ["/tmp/quo\"te.conf", "/tmp/new\nline.conf"] {
            let error =
                staged_write_request(Path::new(bad)).expect_err("unsafe staged paths refuse");
            let text = error.to_string();
            assert!(text.contains("refusing before any tool runs"), "{text}");
            assert!(text.is_ascii(), "{text}");
        }
    }

    #[test]
    fn staging_writes_the_exact_flag_bytes_under_unique_names() {
        let first = stage_persistence_source().expect("staging writes");
        let second = stage_persistence_source().expect("staging writes again");
        assert_ne!(first, second, "successive stages never share a name");
        let bytes = std::fs::read(&first).expect("the staged file reads");
        assert_eq!(bytes, b"/ union\n", "exactly the 8 flag bytes");
        assert!(
            first
                .file_name()
                .expect("the staged path has a name")
                .to_str()
                .expect("the staged name is UTF-8")
                .starts_with(STAGE_NAME_PREFIX),
            "staged names carry the house prefix: {}",
            first.display()
        );
        std::fs::remove_file(&first).expect("cleanup");
        std::fs::remove_file(&second).expect("cleanup");
        assert!(!first.exists() && !second.exists());
    }

    #[test]
    fn writer_probe_finds_debugfs_and_names_the_package_when_absent() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let writer_log = scratch.path().join("writer.log");
        let stub = write_debugfs_stub(scratch.path(), &writer_log, "/ union\\n");
        let (name, path) = find_writer_in(&probe_dirs(scratch.path())).expect("the stub probes");
        assert_eq!(name, "debugfs");
        assert_eq!(path, stub);
        // The probe itself is the one `-V` line in the stub log.
        assert_eq!(stub_log_lines(&writer_log), ["<-V>".to_string()]);

        let error = find_writer_in(&[]).expect_err("nothing can be found");
        assert_eq!(
            error.to_string(),
            format!("invalid input: {WRITER_MISSING_TOOL_HINT}"),
            "the empty-PATH text is pinned exactly"
        );

        // A stub whose version check fails is absent, same package text.
        let failing = tempfile::tempdir().expect("a scratch dir");
        write_stub(failing.path(), "debugfs", "#!/bin/sh\nexit 1\n");
        let error =
            find_writer_in(&probe_dirs(failing.path())).expect_err("the failing probe is absent");
        assert!(error.to_string().contains("e2fsprogs"), "{error}");
    }

    #[test]
    fn persistence_writes_the_flag_file_through_debugfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let writer_log = scratch.path().join("writer.log");
        write_debugfs_stub(scratch.path(), &writer_log, "/ union\\n");
        // The stub `mke2fs` never touches the target bytes: the target
        // carries the synthetic ext4 superblock the read-backs verify.
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"persistence"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);
        let options = persistence_options(None);

        let verified = format_with_in(
            &target,
            &options,
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect("persistence with no label activates");
        assert_eq!(verified.label.as_deref(), Some("persistence"));
        assert_eq!(verified.block_bytes, FIXED_BLOCK_BYTES);
        assert!(verified.has_journal);

        // No label in the options, yet `-L persistence` reaches the stub:
        // the formatter fills the mandated label in itself.
        let mke_lines = stub_log_lines(&mke_log);
        assert_eq!(mke_lines.len(), 1, "{mke_lines:?}");
        assert_eq!(
            mke_lines[0],
            format!(
                "<-q><-F><-t><ext4><-L><persistence><-b><4096><-I><256>\
                 <-E><lazy_itable_init=0,lazy_journal_init=0><{}>",
                target.display()
            ),
            "the label flag and the -E set are pinned exactly"
        );

        // The writer ran twice through the real probe seam: the `-V`
        // probe, the quoted write, and the read-back cat, each argv
        // pinned exactly.
        let writer_lines = stub_log_lines(&writer_log);
        assert_eq!(writer_lines.len(), 3, "{writer_lines:?}");
        assert_eq!(writer_lines[0], "<-V>");
        let staged = staged_path_from_write_line(&writer_lines[1], &target);
        assert_eq!(
            writer_lines[1],
            format!(
                "<-w><-R><write \"{}\" /persistence.conf><{}>",
                staged.display(),
                target.display()
            ),
        );
        assert_eq!(
            writer_lines[2],
            format!("<-R><cat /persistence.conf><{}>", target.display()),
        );

        // The summary names the persistence label.
        let messages: Vec<String> = logger
            .snapshot()
            .iter()
            .map(|record| record.message.clone())
            .collect();
        let summary = messages.last().expect("the summary is logged");
        assert!(summary.contains("label `persistence`"), "{summary}");
    }

    #[test]
    fn persistence_refuses_a_conflicting_label_before_any_tool_runs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let target = scratch.path().join("volume.bin");
        let logger = Logger::new(Level::Trace);
        let options = persistence_options(Some("RUFUS-X"));

        let error = format_with_in(
            &target,
            &options,
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect_err("a conflicting label refuses");
        let text = error.to_string();
        assert!(text.contains("persistence"), "{text}");
        assert!(text.contains("RUFUS-X"), "{text}");
        assert!(
            !mke_log.exists(),
            "the stub formatter never ran, not even its probe: the refusal precedes every tool invocation"
        );

        // The public entry refuses the same way even with the real
        // toolchain on PATH: the label rule precedes the probe.
        let error = format(&target, &options, &logger).expect_err("format refuses before probing");
        let text = error.to_string();
        assert!(text.contains("persistence"), "{text}");
        assert!(text.contains("RUFUS-X"), "{text}");
    }

    #[test]
    fn persistence_refuses_when_the_write_leaves_nothing_behind() {
        // The stub exits 0 for everything (the real tool's lying shape)
        // but the `cat` reply is empty: the read-back proof must refuse.
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let writer_log = scratch.path().join("writer.log");
        write_debugfs_stub(scratch.path(), &writer_log, "");
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"persistence"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);

        let error = format_with_in(
            &target,
            &persistence_options(None),
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect_err("an empty read-back refuses");
        let text = error.to_string();
        assert!(text.contains("debugfs"), "{text}");
        assert!(text.contains("persistence.conf"), "{text}");
        assert!(text.contains("mismatch"), "{text}");
        assert!(text.contains("got 0 bytes"), "{text}");

        // The staged file is gone even on the refused path.
        let writer_lines = stub_log_lines(&writer_log);
        assert_eq!(writer_lines.len(), 3, "{writer_lines:?}");
        staged_path_from_write_line(&writer_lines[1], &target);
    }

    #[test]
    fn persistence_refuses_when_the_read_back_returns_wrong_bytes() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let writer_log = scratch.path().join("writer.log");
        write_debugfs_stub(scratch.path(), &writer_log, "WRONG\\n");
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"persistence"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);

        let error = format_with_in(
            &target,
            &persistence_options(None),
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect_err("a wrong read-back refuses");
        let text = error.to_string();
        assert!(text.contains("debugfs"), "{text}");
        assert!(text.contains("persistence.conf"), "{text}");
        assert!(text.contains("mismatch"), "{text}");
        assert!(text.contains("got 6 bytes"), "{text}");
        assert!(text.contains("WRONG"), "{text}");

        // The staged file is gone even on the refused path.
        let writer_lines = stub_log_lines(&writer_log);
        assert_eq!(writer_lines.len(), 3, "{writer_lines:?}");
        staged_path_from_write_line(&writer_lines[1], &target);
    }

    #[test]
    fn persistence_without_a_writer_names_e2fsprogs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"persistence"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);

        let error = format_with_in(
            &target,
            &persistence_options(None),
            &logger,
            "mke2fs",
            &tool_path,
            &[],
        )
        .expect_err("no writer on PATH refuses");
        let text = error.to_string();
        assert!(text.contains("debugfs"), "{text}");
        assert!(text.contains("e2fsprogs"), "{text}");

        // The formatter ran first: the volume is otherwise formatted but
        // the call still refuses.
        let mke_lines = stub_log_lines(&mke_log);
        assert_eq!(mke_lines.len(), 1, "{mke_lines:?}");
        assert!(mke_lines[0].contains("<-L><persistence>"), "{mke_lines:?}");
    }

    #[test]
    fn plain_formatting_never_touches_debugfs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        // A stub `debugfs` that records any invocation at all (even the
        // `-V` probe): the plain path must leave its log unwritten.
        let writer_log = scratch.path().join("writer.log");
        write_debugfs_stub(scratch.path(), &writer_log, "/ union\\n");
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"RUFUS-EXT4-TEST"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);

        format_with_in(
            &target,
            &Options::new(Flavour::Ext4),
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect("plain formatting succeeds");
        assert!(
            !writer_log.exists(),
            "no debugfs invocation at all, not even a probe, on the plain path"
        );
    }

    #[test]
    fn persistence_refuses_when_the_label_read_back_differs() {
        let scratch = tempfile::tempdir().expect("a scratch dir");
        let mke_log = scratch.path().join("mke.log");
        let tool_path = write_recording_mke2fs(scratch.path(), &mke_log);
        let writer_log = scratch.path().join("writer.log");
        write_debugfs_stub(scratch.path(), &writer_log, "/ union\\n");
        // The stub `debugfs` cannot rewrite the target, so the on-disk
        // label stays foreign through a byte-perfect `cat` proof: the
        // read-back defence is what refuses.
        let target = scratch.path().join("volume.bin");
        std::fs::write(&target, synthetic_sb(true, 2, b"RUFUS-EXT4-TEST"))
            .expect("the synthetic target writes");
        let logger = Logger::new(Level::Trace);

        let error = format_with_in(
            &target,
            &persistence_options(None),
            &logger,
            "mke2fs",
            &tool_path,
            &probe_dirs(scratch.path()),
        )
        .expect_err("a foreign on-disk label refuses");
        let text = error.to_string();
        assert!(text.contains("persistence"), "{text}");
        assert!(text.contains("RUFUS-EXT4-TEST"), "{text}");
    }
}
