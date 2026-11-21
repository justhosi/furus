//! SUSP and Rock Ridge system-use parsing (S14, slice 3 of 4).
//!
//! *Measured* — what `xorriso -as mkisofs -R` (version 1.5.8, inside
//! `archlinux:latest`) writes, byte-checked sector by sector with `od`
//! and pinned again by the synthetic fixtures below:
//! the `SP` record (`SP`, 7, 1, `0xBE 0xEF`, skip) leads the root `.`
//! record's system-use area with skip 0, so entries follow it directly
//! and every other area starts with entries at once; `PX` is 36 bytes
//! (mode, links, uid, gid, no serial number) or 44 (with the serial);
//! `TF` carries three 7-byte stamps under flags `0x0e`, or three
//! 17-byte stamps under `0x8e` with `-long-rr-time` (16 ASCII digits
//! plus one signed GMT-offset byte); `NM` names are plain byte strings
//! (`caf\xc3\xa9.txt` arrives backslash-escaped, exactly as `isoinfo -R`
//! shows it); `SL` components use flag `0` (plain), `2` (current),
//! `4` (parent) and `8` (root), empty for the special kinds; a long
//! target (130 characters here) moves wholly into one `CE` area as a
//! single complete `SL` entry; the root `.` record's `CE` holds one
//! `ER` (`RRIP_1991A`, 237 bytes, skipped like any unknown entry, with
//! no `ST` terminator anywhere); records end with one trailing zero pad
//! byte past the last entry; `-hide-rr-moved` on a 13-level tree
//! relocates depth 9+ under `.rr_moved`: the parent's placeholder
//! record (flags 0, zero length, dead extent) carries `CL` (12 bytes,
//! both-endian LBA) plus the `NM`, the relocated directory's `..`
//! record carries `PL` (12 bytes, the logical parent's LBA — the `..`
//! record's own extent still points at the physical parent), and `RE`
//! (4 bytes) marks the relocation root's record, its `.`/`..` records
//! and the moved record inside it. Every one of these shapes has a
//! synthetic test below; the deep-tree behaviour is cross-checked
//! against `xorriso -find /` and `isoinfo -R -f` in the slice report.
//!
//! *Inferred* — the flag tables no real image exercises, taken from the
//! RRIP 1.12 spec text (IEEE P1281): `SL` entry flag 0 continues the
//! link in the next `SL` entry of the same area, component flags 1/2/3
//! are current/parent/root, 4/5 are implementation-specific
//! (volume-root/host, refused here) and 6/7 are reserved; `NM` flag 0
//! continues the name in the next `NM` entry, 1/2 name the `.`/`..`
//! records (with no name bytes), 5 is host-specific (refused) and the
//! rest reserved; `TF` bits 0-6 mark creation/modification/access/
//! attribute-change/backup/expiration/effective stamps in that order,
//! bit 7 selects the 17-byte form. Two rules extend the spec the way
//! the existing multi-extent joining does: an `NM` with the continue
//! flag continues in the next same-identifier record of the run (the
//! spec only chains within one area), and the `SP` skip counts for
//! every area of the volume (root: past the `SP` itself; elsewhere:
//! from the area start) — both pinned synthetically, since shipped
//! images all use skip 0 and single-area names.
//!
//! Timezone handling, stated honestly: every Rock Ridge stamp is local
//! time per the spec, with a GMT-offset adjunct in 15-minute steps.
//! The reader decodes the fields and exposes the offset raw
//! ([`RockTime::offset_quarters`]) and never converts: there is no
//! timezone database in this crate, and silently rendering into the
//! machine's zone would mislabel evidence. Callers interpret.
//!
//! Refusals, not panics: a present `SP` with the wrong magic refuses
//! naming the found bytes; a skip past the area end refuses; a `CE`
//! pointing at itself, looping, running past the store, nesting past
//! [`MAX_SUSP_CE_DEPTH`] areas or growing the stream past
//! [`MAX_SUSP_STREAM_BYTES`] bytes refuses with the numbers named; a
//! truncated entry (at the fixpoint, once every reachable `CE` is in)
//! refuses; unknown entries (`ER`, `RR`, `PN`, ...) skip by their
//! length so newer extensions never break old readers, while `ST` ends
//! the area; `PX` accepts only lengths 36 and 44; `TF` accepts only the
//! creation/modification/access/attribute-change stamps (backup/
//! expiration/effective refuse) with range-checked fields; duplicate
//! `PX`/`TF` stamps/`CL`/`PL`/complete `NM`s/`SL`s refuse; and
//! contradictory component or name flags refuse explicitly.

use crate::error::CoreError;
use crate::error::Result;
use crate::iso::SECTOR_BYTES;
use crate::iso::SECTOR_BYTES_U64;

/// Hard ceiling on continuation areas followed for one record: real
/// chains are one area deep (the `ER` area, one `SL` area), so more
/// than this without reaching a fixpoint means hostile nesting, and
/// the fetch loop must not walk the volume forever.
pub const MAX_SUSP_CE_DEPTH: usize = 8;

/// Hard ceiling on the concatenated SUSP bytes of one record
/// (in-record tail plus every continuation area): real streams are a
/// few hundred bytes (the measured `ER` area is 237), so more than
/// this means a hostile length, and one record must not demand an
/// unbounded buffer.
pub const MAX_SUSP_STREAM_BYTES: usize = 32_768;

/// `SP` magic, first byte: `0xBE`.
const SP_MAGIC_0: u8 = 0xBE;
/// `SP` magic, second byte: `0xEF`.
const SP_MAGIC_1: u8 = 0xEF;
/// `SP` entry length in bytes.
const SP_LEN: usize = 7;
/// `CE` entry length in bytes.
const CE_LEN: usize = 28;
/// `CL`/`PL` entry length in bytes.
const CL_PL_LEN: usize = 12;
/// `RE`/`ST` entry length in bytes.
const RE_ST_LEN: usize = 4;
/// Minimum `NM`/`SL` entry length (signature, length, version, flags).
const NAME_LINK_MIN: usize = 5;
/// Minimum `PX` entry length (without the serial number).
const PX_MIN: usize = 36;
/// `PX` entry length with the serial number.
const PX_FULL: usize = 44;
/// Entry version every parsed kind must carry.
const ENTRY_VERSION: u8 = 1;

/// `SL` entry flag 0: the link continues in the next `SL` entry of the
/// same system-use area.
const SL_CONTINUE: u8 = 0x01;
/// `SL` component flag 0: the component continues in the next
/// component record.
const COMP_CONTINUE: u8 = 0x01;
/// `SL` component flag 1: the component is the current directory.
const COMP_CURRENT: u8 = 0x02;
/// `SL` component flag 2: the component is the parent directory.
const COMP_PARENT: u8 = 0x04;
/// `SL` component flag 3: the component is the hierarchy root.
const COMP_ROOT: u8 = 0x08;
/// `SL` component flags 4-5: implementation-specific (volume root,
/// host); refused here.
const COMP_IMPL_SPECIFIC: u8 = 0x30;
/// `SL` component flags 6-7: reserved; refused here.
const COMP_RESERVED: u8 = 0xC0;

/// `NM` flag 0: the name continues in the next `NM` entry.
const NM_CONTINUE: u8 = 0x01;
/// `NM` flag 1: the name refers to the current directory.
const NM_CURRENT: u8 = 0x02;
/// `NM` flag 2: the name refers to the parent directory.
const NM_PARENT: u8 = 0x04;
/// `NM` flag 5: implementation-specific (host name); refused here.
const NM_HOST: u8 = 0x20;
/// `NM` reserved flags; refused here.
const NM_RESERVED: u8 = 0xD8;

/// `TF` flag 0: creation time is recorded.
const TF_CREATION: u8 = 0x01;
/// `TF` flag 1: modification time is recorded.
const TF_MODIFY: u8 = 0x02;
/// `TF` flag 2: last access time is recorded.
const TF_ACCESS: u8 = 0x04;
/// `TF` flag 3: last attribute-change time is recorded.
const TF_ATTRIBUTES: u8 = 0x08;
/// `TF` flags 4-6: backup/expiration/effective times; refused here
/// (timestamps the reader would silently drop).
const TF_UNSUPPORTED: u8 = 0x70;
/// `TF` flag 7: the 17-byte stamp form (7-byte otherwise).
const TF_LONG_FORM: u8 = 0x80;

/// POSIX file attributes from a `PX` record: mode, link count, owner,
/// group, and the inode serial when the record carries it (length 44;
/// length 36 leaves [`RockPosix::serial`] empty, as `xorriso` writes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RockPosix {
    /// File mode (type and permission bits), informational: the reader
    /// never interprets it (symlink detection is `SL` presence).
    pub mode: u32,
    /// Link count.
    pub nlinks: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Inode serial number (`None` for 36-byte `PX` records).
    pub serial: Option<u32>,
}

/// One Rock Ridge time stamp: decoded fields plus the raw GMT offset.
/// Local time per the spec — see the module docs for why the offset is
/// exposed, not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RockTime {
    /// Full year (1900-based for the 7-byte form, literal for 17-byte).
    pub year: u16,
    /// Month 1..12.
    pub month: u8,
    /// Day 1..31.
    pub day: u8,
    /// Hour 0..23.
    pub hour: u8,
    /// Minute 0..59.
    pub minute: u8,
    /// Second 0..60 (60 admits a leap second).
    pub second: u8,
    /// Centiseconds 0..99 (always 0 for the 7-byte form).
    pub centiseconds: u8,
    /// GMT offset in 15-minute steps, -48..52, raw and unapplied.
    pub offset_quarters: i8,
}

/// The `TF` stamps a record carries: each present stamp decoded, each
/// absent one empty. Backup/expiration/effective stamps are never
/// stored — a `TF` requesting them is refused outright.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RockTimes {
    /// Creation time (`TF` bit 0; rarely recorded).
    pub creation: Option<RockTime>,
    /// Modification time (`TF` bit 1).
    pub modification: Option<RockTime>,
    /// Last access time (`TF` bit 2).
    pub access: Option<RockTime>,
    /// Last attribute-change time (`TF` bit 3; what `xorriso` writes
    /// beside modification and access).
    pub attributes: Option<RockTime>,
}

/// One `NM` entry's name bytes: Rock Ridge names are byte strings, not
/// UCS-2 — non-ASCII bytes survive untouched, unlike Joliet decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltName {
    /// The name bytes (or name fragment, when [`AltName::continues`]).
    pub bytes: Vec<u8>,
    /// The continue flag: the name continues in the next `NM` entry.
    pub continues: bool,
}

/// Everything one record's system-use stream says: the alternate-name
/// parts, the symlink target, the POSIX attributes and stamps, the
/// relocation links, and whether the record is relocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RockAttrs {
    /// The `NM` entries in order (usually one; chained by continue
    /// flags when a name spans entries).
    pub names: Vec<AltName>,
    /// The assembled `SL` target (`None` for non-links; symlink
    /// detection is `SL` presence, never the `PX` mode).
    pub symlink_target: Option<String>,
    /// The `PX` attributes, when present.
    pub posix: Option<RockPosix>,
    /// The `TF` stamps (absent kinds stay empty).
    pub times: RockTimes,
    /// The `CL` child-link LBA: this record is a relocated-directory
    /// placeholder whose contents live there.
    pub child_link: Option<u32>,
    /// The `PL` parent-link LBA: the logical parent of this relocated
    /// directory (carried by its `..` record).
    pub parent_link: Option<u32>,
    /// True when `RE` or `CL` marks this record as relocated.
    pub relocated: bool,
}

/// One byte at `at` in `bytes`, refused with the context when the
/// buffer ends first.
fn byte_at(bytes: &[u8], at: usize, what: &str) -> Result<u8> {
    bytes.get(at).copied().ok_or_else(|| {
        CoreError::invalid(format!(
            "{what} ends before byte {at} of {} bytes",
            bytes.len()
        ))
    })
}

/// Both-endian 32-bit word: little-endian half at `le_at`, big-endian
/// half at `be_at`. The halves must agree; a mismatch is refused naming
/// the field and both numbers.
fn both32(bytes: &[u8], le_at: usize, be_at: usize, field: &str) -> Result<u32> {
    let little = u32::from_le_bytes([
        byte_at(bytes, le_at, field)?,
        byte_at(bytes, le_at + 1, field)?,
        byte_at(bytes, le_at + 2, field)?,
        byte_at(bytes, le_at + 3, field)?,
    ]);
    let big = u32::from_be_bytes([
        byte_at(bytes, be_at, field)?,
        byte_at(bytes, be_at + 1, field)?,
        byte_at(bytes, be_at + 2, field)?,
        byte_at(bytes, be_at + 3, field)?,
    ]);
    if little != big {
        return Err(CoreError::invalid(format!(
            "{field} endian halves disagree: little-endian {little} against big-endian {big}"
        )));
    }
    Ok(little)
}

/// Check an `SP` entry at the start of `area`: 7 bytes, version 1, the
/// `0xBE 0xEF` magic. A present `SP` with the wrong magic refuses with
/// the found bytes named; a truncated `SP` refuses with its length.
fn check_sp(area: &[u8]) -> Result<u8> {
    if area.len() < SP_LEN {
        return Err(CoreError::invalid(format!(
            "susp SP record of {} bytes is shorter than its {SP_LEN} byte length",
            area.len()
        )));
    }
    let len = byte_at(area, 2, "susp SP record")?;
    if usize::from(len) != SP_LEN {
        return Err(CoreError::invalid(format!(
            "susp SP record declares length {len}, not {SP_LEN}"
        )));
    }
    let version = byte_at(area, 3, "susp SP record")?;
    if version != ENTRY_VERSION {
        return Err(CoreError::invalid(format!(
            "susp SP record has version {version}, not {ENTRY_VERSION}"
        )));
    }
    let magic_0 = byte_at(area, 4, "susp SP record")?;
    let magic_1 = byte_at(area, 5, "susp SP record")?;
    if magic_0 != SP_MAGIC_0 || magic_1 != SP_MAGIC_1 {
        return Err(CoreError::invalid(format!(
            "susp SP record has magic bytes 0x{magic_0:02x} 0x{magic_1:02x}, not 0xBE 0xEF"
        )));
    }
    byte_at(area, 6, "susp SP record")
}

/// Detect SUSP on the volume from the root `.` record's system-use
/// area: `Some(skip)` when it opens with a valid `SP` (skip counts
/// bytes past the `SP` itself before the first entry), `None` when no
/// `SP` leads it (no Rock Ridge — the reader behaves as before), and a
/// refusal when a present `SP` is malformed.
pub fn detect_susp(root_dot_system_use: &[u8]) -> Result<Option<u8>> {
    let leads_with_sp =
        root_dot_system_use.len() >= 2 && root_dot_system_use.get(0..2) == Some(b"SP".as_slice());
    if !leads_with_sp {
        return Ok(None);
    }
    check_sp(root_dot_system_use).map(Some)
}

/// One `CE` entry at `entry` (already known to hold at least 4 bytes):
/// 28 bytes, version 1, and the block/offset/length both-endian words.
fn parse_ce(entry: &[u8]) -> Result<(u32, u64, u64)> {
    let len = byte_at(entry, 2, "susp CE record")?;
    if usize::from(len) != CE_LEN {
        return Err(CoreError::invalid(format!(
            "susp CE record declares length {len}, not {CE_LEN}"
        )));
    }
    let version = byte_at(entry, 3, "susp CE record")?;
    if version != ENTRY_VERSION {
        return Err(CoreError::invalid(format!(
            "susp CE record has version {version}, not {ENTRY_VERSION}"
        )));
    }
    let block = both32(entry, 4, 8, "susp CE record block")?;
    let offset = u64::from(both32(entry, 12, 16, "susp CE record offset")?);
    let length = u64::from(both32(entry, 20, 24, "susp CE record length")?);
    Ok((block, offset, length))
}

/// What [`scan_stream`] finds: the `CE` targets in stream order (with
/// their stream offset, so already-seen ones stay silent) and whether
/// the walk stopped inside a truncated entry.
struct ScanOutcome {
    /// `(stream offset, block, byte offset, length)` per `CE` entry.
    ces: Vec<(usize, u32, u64, u64)>,
    /// The offset where the walk stopped inside an entry, with its
    /// claimed length when the header survived (`None` when fewer than
    /// 4 bytes remain).
    fragment_at: Option<(usize, Option<usize>)>,
}

/// Walk `stream` for entry boundaries: collect the `CE` targets, stop
/// at `ST` or at trailing zero padding (records end with pad bytes
/// past the last entry — measured as one zero byte), and report a
/// trailing truncated entry instead of refusing, so the caller can
/// fetch continuations first and only refuse at the fixpoint.
fn scan_stream(stream: &[u8]) -> Result<ScanOutcome> {
    let mut data_end = stream.len();
    while data_end > 0 && stream.get(data_end - 1) == Some(&0) {
        data_end -= 1;
    }
    let mut ces = Vec::new();
    let mut at: usize = 0;
    let mut fragment_at: Option<(usize, Option<usize>)> = None;
    while at < data_end {
        let remaining = data_end.saturating_sub(at);
        if remaining < 4 {
            fragment_at = Some((at, None));
            break;
        }
        let sig_0 = byte_at(stream, at, "susp entry stream")?;
        let sig_1 = byte_at(stream, at + 1, "susp entry stream")?;
        let len_byte = byte_at(stream, at + 2, "susp entry stream")?;
        let entry_len = usize::from(len_byte);
        if entry_len < 4 {
            return Err(CoreError::invalid(format!(
                "susp entry {sig_0:02x}{sig_1:02x} declares length {len_byte}, \
                 below the 4 byte header"
            )));
        }
        if sig_0 == b'S' && sig_1 == b'T' {
            break;
        }
        if sig_0 == b'C' && sig_1 == b'E' {
            let entry = stream.get(at..at + CE_LEN).ok_or_else(|| {
                CoreError::invalid(format!(
                    "susp entry stream of {} bytes ends inside the {CE_LEN} byte CE record \
                     at offset {at}",
                    stream.len()
                ))
            })?;
            let (block, offset, length) = parse_ce(entry)?;
            ces.push((at, block, offset, length));
        }
        let end = at.checked_add(entry_len).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp entry of {entry_len} bytes at offset {at} overflows the offset arithmetic"
            ))
        })?;
        if end > stream.len() {
            fragment_at = Some((at, Some(entry_len)));
            break;
        }
        at = end;
    }
    Ok(ScanOutcome { ces, fragment_at })
}

/// Read `length` bytes at block-relative `offset` in `block` through
/// whole-sector reads: the window must sit inside `total_bytes`, and
/// unreadable sectors refuse with the area named. Block-relative
/// offsets past the first sector (a legal, if unusual, encoding) walk
/// into the following sectors — positions stay absolute throughout.
fn read_area(
    read_sector: &mut dyn FnMut(u32) -> Result<[u8; SECTOR_BYTES]>,
    total_bytes: u64,
    block: u32,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    let start = u64::from(block)
        .checked_mul(SECTOR_BYTES_U64)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "susp continuation at block {block} overflows the byte offset arithmetic"
            ))
        })?
        .checked_add(offset)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "susp continuation at block {block} offset {offset} \
                 overflows the byte offset arithmetic"
            ))
        })?;
    let end = start.checked_add(length).ok_or_else(|| {
        CoreError::invalid(format!(
            "susp continuation at block {block} offset {offset} length {length} \
             overflows the byte offset arithmetic"
        ))
    })?;
    if end > total_bytes {
        return Err(CoreError::invalid(format!(
            "susp continuation at block {block} offset {offset} length {length} spans bytes \
             {start}..{end} past the {total_bytes} byte volume end"
        )));
    }
    let first_sector = u32::try_from(start / SECTOR_BYTES_U64).map_err(|_| {
        CoreError::invalid(format!(
            "susp continuation at block {block} offset {offset} starts past the sector number range"
        ))
    })?;
    let last_sector = u32::try_from((end - 1) / SECTOR_BYTES_U64).map_err(|_| {
        CoreError::invalid(format!(
            "susp continuation at block {block} offset {offset} length {length} ends past the \
             sector number range"
        ))
    })?;
    let len_usize = usize::try_from(length).map_err(|_| {
        CoreError::invalid(format!(
            "susp continuation length {length} does not fit this machine's usize"
        ))
    })?;
    let mut out = Vec::new();
    out.try_reserve(len_usize).map_err(|_| {
        CoreError::invalid(format!(
            "susp continuation of {length} bytes cannot be buffered: the allocation failed"
        ))
    })?;
    let mut pos = start;
    let mut remaining = len_usize;
    let mut sector_no = first_sector;
    while remaining > 0 {
        if sector_no > last_sector {
            return Err(CoreError::invalid(format!(
                "susp continuation at block {block} offset {offset} length {length} read short \
                 by {remaining} bytes"
            )));
        }
        let bytes = read_sector(sector_no).map_err(|error| {
            CoreError::invalid(format!(
                "susp continuation at block {block} offset {offset} length {length} is \
                 unreadable at sector {sector_no} ({error})"
            ))
        })?;
        let sector_base = u64::from(sector_no)
            .checked_mul(SECTOR_BYTES_U64)
            .ok_or_else(|| {
                CoreError::invalid(format!(
                    "susp continuation sector {sector_no} overflows the byte offset arithmetic"
                ))
            })?;
        let intra = pos.saturating_sub(sector_base);
        let intra_usize = usize::try_from(intra).map_err(|_| {
            CoreError::invalid(format!(
                "susp continuation position {pos} does not fit this machine's usize"
            ))
        })?;
        let chunk = bytes.get(intra_usize..).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp continuation position {pos} runs past its {sector_no} sector"
            ))
        })?;
        let take = remaining.min(chunk.len());
        let piece = chunk.get(..take).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp continuation read of {take} bytes runs past sector {sector_no}"
            ))
        })?;
        out.extend_from_slice(piece);
        remaining -= take;
        pos = pos.saturating_add(take as u64);
        sector_no = sector_no.checked_add(1).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp continuation at block {block} overflows the sector number"
            ))
        })?;
    }
    Ok(out)
}

/// Collect one record's full SUSP byte stream: the system-use tail
/// past one leading `SP` copy (validated wherever it leads an area)
/// and the `SP` skip, concatenated with every reachable continuation
/// area in encounter order. `read_sector` serves whole sectors;
/// `total_bytes` bounds every window.
///
/// The walk re-scans from the start after each fetch (a fetched area
/// can complete an earlier fragment or hold nested `CE`s); entries at
/// already-scanned offsets stay silent, while a fresh entry repeating
/// a followed area refuses as a cycle — covering self-pointers and
/// ping-pong loops alike.
pub fn susp_stream(
    read_sector: &mut dyn FnMut(u32) -> Result<[u8; SECTOR_BYTES]>,
    total_bytes: u64,
    system_use: &[u8],
    skip: u8,
) -> Result<Vec<u8>> {
    let mut area = system_use;
    if area.len() >= 2 && area.get(0..2) == Some(b"SP".as_slice()) {
        check_sp(area)?;
        area = area.get(SP_LEN..).ok_or_else(|| {
            CoreError::invalid("susp SP record vanished between the check and the skip")
        })?;
    }
    let skip_usize = usize::from(skip);
    if skip_usize > area.len() {
        return Err(CoreError::invalid(format!(
            "susp skip of {skip} bytes runs past the {} byte system use area",
            area.len()
        )));
    }
    let head = area
        .get(skip_usize..)
        .ok_or_else(|| CoreError::invalid("susp skip vanished between the check and the cut"))?;
    let mut stream = head.to_vec();
    let mut visited: Vec<(u32, u64, u64)> = Vec::new();
    let mut scanned_upto: usize = 0;
    loop {
        let scan = scan_stream(&stream)?;
        let mut fresh: Vec<(u32, u64, u64)> = Vec::new();
        for (at, block, offset, length) in scan.ces {
            if at >= scanned_upto && !fresh.contains(&(block, offset, length)) {
                fresh.push((block, offset, length));
            }
        }
        scanned_upto = stream.len();
        if fresh.is_empty() {
            match scan.fragment_at {
                Some((at, Some(claimed))) => {
                    return Err(CoreError::invalid(format!(
                        "susp entry stream of {} bytes ends inside a {claimed} byte entry at \
                         offset {at}: refusing a truncated entry",
                        stream.len()
                    )));
                }
                Some((at, None)) => {
                    return Err(CoreError::invalid(format!(
                        "susp entry stream of {} bytes ends with {} trailing bytes at offset \
                         {at}: refusing a truncated entry",
                        stream.len(),
                        stream.len().saturating_sub(at)
                    )));
                }
                None => return Ok(stream),
            }
        }
        for (block, offset, length) in fresh {
            if visited.contains(&(block, offset, length)) {
                return Err(CoreError::invalid(format!(
                    "susp continuation at block {block} offset {offset} length {length} repeats \
                     a followed area: refusing a cyclic continuation"
                )));
            }
            if visited.len() >= MAX_SUSP_CE_DEPTH {
                return Err(CoreError::invalid(format!(
                    "susp continuation at block {block} offset {offset} length {length} nests \
                     past {MAX_SUSP_CE_DEPTH} areas: refusing a deep continuation chain"
                )));
            }
            if length == 0 {
                return Err(CoreError::invalid(format!(
                    "susp continuation at block {block} offset {offset} carries 0 bytes: \
                     refusing an empty continuation"
                )));
            }
            let len_usize = usize::try_from(length).map_err(|_| {
                CoreError::invalid(format!(
                    "susp continuation length {length} does not fit this machine's usize"
                ))
            })?;
            let grown = stream.len().checked_add(len_usize).ok_or_else(|| {
                CoreError::invalid(format!(
                    "susp continuation at block {block} offset {offset} length {length} \
                     overflows the stream arithmetic"
                ))
            })?;
            if grown > MAX_SUSP_STREAM_BYTES {
                return Err(CoreError::invalid(format!(
                    "susp continuation at block {block} offset {offset} length {length} grows \
                     the entry stream past {MAX_SUSP_STREAM_BYTES} bytes"
                )));
            }
            stream.try_reserve(len_usize).map_err(|_| {
                CoreError::invalid(format!(
                    "susp entry stream of {grown} bytes cannot be buffered: the allocation failed"
                ))
            })?;
            let bytes = read_area(read_sector, total_bytes, block, offset, length)?;
            stream.extend_from_slice(&bytes);
            visited.push((block, offset, length));
        }
    }
}

/// Decode one 7-byte stamp (years since 1900, month, day, hour,
/// minute, second, GMT offset in 15-minute steps) with range-checked
/// fields.
fn decode_short(stamp: &[u8]) -> Result<RockTime> {
    let year = u16::from(byte_at(stamp, 0, "susp TF time stamp")?)
        .checked_add(1900)
        .ok_or_else(|| {
            CoreError::invalid("susp TF time stamp year overflows the year arithmetic")
        })?;
    let month = byte_at(stamp, 1, "susp TF time stamp")?;
    let day = byte_at(stamp, 2, "susp TF time stamp")?;
    let hour = byte_at(stamp, 3, "susp TF time stamp")?;
    let minute = byte_at(stamp, 4, "susp TF time stamp")?;
    let second = byte_at(stamp, 5, "susp TF time stamp")?;
    let offset = byte_at(stamp, 6, "susp TF time stamp")? as i8;
    check_time_fields(month, day, hour, minute, second, 0)?;
    if !(-48..=52).contains(&offset) {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has GMT offset {offset}, not in -48..52"
        )));
    }
    Ok(RockTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        centiseconds: 0,
        offset_quarters: offset,
    })
}

/// One ASCII digit at `at` in a 17-byte stamp, refused naming the
/// position when it is not a digit.
fn stamp_digit(stamp: &[u8], at: usize) -> Result<u8> {
    let byte = byte_at(stamp, at, "susp TF long-form time stamp")?;
    if !byte.is_ascii_digit() {
        return Err(CoreError::invalid(format!(
            "susp TF long-form time stamp has non-digit byte 0x{byte:02x} at position {at}"
        )));
    }
    Ok(byte - b'0')
}

/// Decode one 17-byte stamp (16 ASCII digits `YYYYMMDDHHMMSScc` plus
/// the signed GMT-offset byte) with range-checked fields.
fn decode_long(stamp: &[u8]) -> Result<RockTime> {
    let year = u16::from(stamp_digit(stamp, 0)?)
        .checked_mul(1000)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?
        .checked_add(
            u16::from(stamp_digit(stamp, 1)?)
                .checked_mul(100)
                .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?,
        )
        .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?
        .checked_add(
            u16::from(stamp_digit(stamp, 2)?)
                .checked_mul(10)
                .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?,
        )
        .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?
        .checked_add(u16::from(stamp_digit(stamp, 3)?))
        .ok_or_else(|| CoreError::invalid("susp TF time stamp year overflows"))?;
    let month = stamp_digit(stamp, 4)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp month overflows"))?
        .checked_add(stamp_digit(stamp, 5)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp month overflows"))?;
    let day = stamp_digit(stamp, 6)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp day overflows"))?
        .checked_add(stamp_digit(stamp, 7)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp day overflows"))?;
    let hour = stamp_digit(stamp, 8)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp hour overflows"))?
        .checked_add(stamp_digit(stamp, 9)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp hour overflows"))?;
    let minute = stamp_digit(stamp, 10)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp minute overflows"))?
        .checked_add(stamp_digit(stamp, 11)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp minute overflows"))?;
    let second = stamp_digit(stamp, 12)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp second overflows"))?
        .checked_add(stamp_digit(stamp, 13)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp second overflows"))?;
    let centiseconds = stamp_digit(stamp, 14)?
        .checked_mul(10)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp centiseconds overflow"))?
        .checked_add(stamp_digit(stamp, 15)?)
        .ok_or_else(|| CoreError::invalid("susp TF time stamp centiseconds overflow"))?;
    let offset = byte_at(stamp, 16, "susp TF long-form time stamp")? as i8;
    check_time_fields(month, day, hour, minute, second, centiseconds)?;
    if !(-48..=52).contains(&offset) {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has GMT offset {offset}, not in -48..52"
        )));
    }
    Ok(RockTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        centiseconds,
        offset_quarters: offset,
    })
}

/// Range-check decoded stamp fields: month 1..12, day 1..31, hour
/// 0..23, minute 0..59, second 0..60, centiseconds 0..99.
fn check_time_fields(
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    centiseconds: u8,
) -> Result<()> {
    if !(1..=12).contains(&month) {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has month {month}, not in 1..12"
        )));
    }
    if !(1..=31).contains(&day) {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has day {day}, not in 1..31"
        )));
    }
    if hour > 23 {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has hour {hour}, not in 0..23"
        )));
    }
    if minute > 59 {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has minute {minute}, not in 0..59"
        )));
    }
    if second > 60 {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has second {second}, not in 0..60"
        )));
    }
    if centiseconds > 99 {
        return Err(CoreError::invalid(format!(
            "susp TF time stamp has centiseconds {centiseconds}, not in 0..99"
        )));
    }
    Ok(())
}

/// Parse one `TF` entry at `at` (its length already fits `stream`),
/// merging its stamps into `times`: creation, modification, access
/// and attribute-change in flag-bit order, both stamp forms.
fn parse_tf_entry(stream: &[u8], at: usize, entry_len: usize, times: &mut RockTimes) -> Result<()> {
    let version = byte_at(stream, at + 3, "susp TF record")?;
    if version != ENTRY_VERSION {
        return Err(CoreError::invalid(format!(
            "susp TF record has version {version}, not {ENTRY_VERSION}"
        )));
    }
    let flags = byte_at(stream, at + 4, "susp TF record")?;
    if flags & TF_UNSUPPORTED != 0 {
        return Err(CoreError::invalid(format!(
            "susp TF record requests backup, expiration or effective times \
             (flags 0x{flags:02x}): only creation, modification, access and attribute-change \
             times are supported"
        )));
    }
    let wide = flags & TF_LONG_FORM != 0;
    let step: usize = if wide { 17 } else { 7 };
    let mut count: usize = 0;
    for bit in 0..7 {
        if flags & (1 << bit) != 0 {
            count += 1;
        }
    }
    let want = 5usize
        .checked_add(count.checked_mul(step).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp TF record with flags 0x{flags:02x} overflows the length arithmetic"
            ))
        })?)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "susp TF record with flags 0x{flags:02x} overflows the length arithmetic"
            ))
        })?;
    if entry_len != want {
        return Err(CoreError::invalid(format!(
            "susp TF record with flags 0x{flags:02x} declares length {entry_len}, not the \
             {want} bytes its {count} time stamps need"
        )));
    }
    let kinds: [(u8, &str); 4] = [
        (TF_CREATION, "creation"),
        (TF_MODIFY, "modification"),
        (TF_ACCESS, "access"),
        (TF_ATTRIBUTES, "attribute-change"),
    ];
    let mut cursor = at.checked_add(5).ok_or_else(|| {
        CoreError::invalid("susp TF record time stamps overflow the offset arithmetic")
    })?;
    for (bit, kind) in kinds {
        if flags & bit == 0 {
            continue;
        }
        let end = cursor.checked_add(step).ok_or_else(|| {
            CoreError::invalid("susp TF record time stamps overflow the offset arithmetic")
        })?;
        let stamp = stream.get(cursor..end).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp TF record of {entry_len} bytes ends inside its {kind} time stamp"
            ))
        })?;
        let time = if wide {
            decode_long(stamp)?
        } else {
            decode_short(stamp)?
        };
        let slot = match bit {
            TF_CREATION => &mut times.creation,
            TF_MODIFY => &mut times.modification,
            TF_ACCESS => &mut times.access,
            _ => &mut times.attributes,
        };
        if slot.is_some() {
            return Err(CoreError::invalid(format!(
                "susp record carries a second {kind} time stamp"
            )));
        }
        *slot = Some(time);
        cursor = end;
    }
    Ok(())
}

/// Parse one `PX` entry at `at` into [`RockPosix`]: 36 bytes without
/// the serial number, 44 with it, every field both-endian.
fn parse_px_entry(stream: &[u8], at: usize, entry_len: usize) -> Result<RockPosix> {
    if entry_len != PX_MIN && entry_len != PX_FULL {
        return Err(CoreError::invalid(format!(
            "susp PX record declares length {entry_len}, not {PX_MIN} or {PX_FULL}"
        )));
    }
    let version = byte_at(stream, at + 3, "susp PX record")?;
    if version != ENTRY_VERSION {
        return Err(CoreError::invalid(format!(
            "susp PX record has version {version}, not {ENTRY_VERSION}"
        )));
    }
    let mode = both32(stream, at + 4, at + 8, "susp PX record mode")?;
    let nlinks = both32(stream, at + 12, at + 16, "susp PX record link count")?;
    let uid = both32(stream, at + 20, at + 24, "susp PX record user id")?;
    let gid = both32(stream, at + 28, at + 32, "susp PX record group id")?;
    let serial = if entry_len == PX_FULL {
        Some(both32(
            stream,
            at + 36,
            at + 40,
            "susp PX record serial number",
        )?)
    } else {
        None
    };
    Ok(RockPosix {
        mode,
        nlinks,
        uid,
        gid,
        serial,
    })
}

/// Parse one `NM` entry at `at` into [`RockAttrs::names`]: plain names
/// append, continue-flagged names chain, current/parent flags belong
/// on `.`/`..` records (accepted there, refused elsewhere), and a
/// second complete name refuses.
fn parse_nm_entry(
    stream: &[u8],
    at: usize,
    entry_len: usize,
    is_dot: bool,
    is_parent: bool,
    names: &mut Vec<AltName>,
    nm_complete: &mut bool,
) -> Result<()> {
    if entry_len < NAME_LINK_MIN {
        return Err(CoreError::invalid(format!(
            "susp NM record declares length {entry_len}, below the {NAME_LINK_MIN} byte minimum"
        )));
    }
    let version = byte_at(stream, at + 3, "susp NM record")?;
    if version != ENTRY_VERSION {
        return Err(CoreError::invalid(format!(
            "susp NM record has version {version}, not {ENTRY_VERSION}"
        )));
    }
    let flags = byte_at(stream, at + 4, "susp NM record")?;
    if flags & NM_RESERVED != 0 {
        return Err(CoreError::invalid(format!(
            "susp NM record has unsupported flags 0x{flags:02x}: refusing reserved bits"
        )));
    }
    if flags & NM_HOST != 0 {
        return Err(CoreError::invalid(format!(
            "susp NM record requests host-name insertion (flags 0x{flags:02x}): \
             host names are not supported"
        )));
    }
    let mut special = 0;
    for bit in [NM_CONTINUE, NM_CURRENT, NM_PARENT] {
        if flags & bit != 0 {
            special += 1;
        }
    }
    if special > 1 {
        return Err(CoreError::invalid(format!(
            "susp NM record sets more than one of the continue, current and parent flags \
             (0x{flags:02x})"
        )));
    }
    if *nm_complete {
        return Err(CoreError::invalid(
            "susp record carries a second alternate name after a complete one: \
             only continuations may follow",
        ));
    }
    if flags & NM_CURRENT != 0 {
        if !is_dot {
            return Err(CoreError::invalid(format!(
                "susp NM record claims the current directory (flags 0x{flags:02x}) outside a \
                 `.` record"
            )));
        }
        if entry_len != NAME_LINK_MIN {
            return Err(CoreError::invalid(format!(
                "susp NM record carries name bytes with the current flag set: the length must \
                 be {NAME_LINK_MIN}, not {entry_len}"
            )));
        }
        *nm_complete = true;
        return Ok(());
    }
    if flags & NM_PARENT != 0 {
        if !is_parent {
            return Err(CoreError::invalid(format!(
                "susp NM record claims the parent directory (flags 0x{flags:02x}) outside a \
                 `..` record"
            )));
        }
        if entry_len != NAME_LINK_MIN {
            return Err(CoreError::invalid(format!(
                "susp NM record carries name bytes with the parent flag set: the length must \
                 be {NAME_LINK_MIN}, not {entry_len}"
            )));
        }
        *nm_complete = true;
        return Ok(());
    }
    let start = at
        .checked_add(NAME_LINK_MIN)
        .ok_or_else(|| CoreError::invalid("susp NM record name overflows the offset arithmetic"))?;
    let end = at
        .checked_add(entry_len)
        .ok_or_else(|| CoreError::invalid("susp NM record name overflows the offset arithmetic"))?;
    let bytes = stream
        .get(start..end)
        .ok_or_else(|| {
            CoreError::invalid(format!(
                "susp NM record of {entry_len} bytes ends inside its name at bytes {start}..{end}"
            ))
        })?
        .to_vec();
    let continues = flags & NM_CONTINUE != 0;
    names.push(AltName { bytes, continues });
    if !continues {
        *nm_complete = true;
    }
    Ok(())
}

/// Assemble an `SL` component area (already chained across the
/// record's `SL` entries) into the target path: continued components
/// concatenate, current/parent/root map to `.`/`..`/empty (a leading
/// root yields the leading `/`), and plain components join with `/`
/// exactly as recorded — never normalised.
fn assemble_target(area: &[u8]) -> Result<String> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut pending_open = false;
    let mut at: usize = 0;
    while at < area.len() {
        let flags = byte_at(area, at, "susp SL component area")?;
        let len_byte = byte_at(area, at + 1, "susp SL component area")?;
        let comp_len = usize::from(len_byte);
        let start = at.checked_add(2).ok_or_else(|| {
            CoreError::invalid("susp SL component overflows the offset arithmetic")
        })?;
        let end = start.checked_add(comp_len).ok_or_else(|| {
            CoreError::invalid("susp SL component overflows the offset arithmetic")
        })?;
        if end > area.len() {
            return Err(CoreError::invalid(format!(
                "susp SL component of {comp_len} bytes at offset {at} runs past the {} byte \
                 component area",
                area.len()
            )));
        }
        if flags & COMP_RESERVED != 0 {
            return Err(CoreError::invalid(format!(
                "susp SL component has unsupported flags 0x{flags:02x}: refusing reserved bits"
            )));
        }
        if flags & COMP_IMPL_SPECIFIC != 0 {
            return Err(CoreError::invalid(format!(
                "susp SL component requests host or volume-root insertion \
                 (flags 0x{flags:02x}): these are not supported"
            )));
        }
        let mut special = 0;
        for bit in [COMP_CONTINUE, COMP_CURRENT, COMP_PARENT, COMP_ROOT] {
            if flags & bit != 0 {
                special += 1;
            }
        }
        if special > 1 {
            return Err(CoreError::invalid(format!(
                "susp SL component sets more than one of the continue, current, parent and \
                 root flags (0x{flags:02x})"
            )));
        }
        let text = area.get(start..end).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp SL component of {comp_len} bytes ends inside the {} byte component area",
                area.len()
            ))
        })?;
        if flags & COMP_CONTINUE != 0 {
            pending.extend_from_slice(text);
            pending_open = true;
        } else if flags & COMP_CURRENT != 0 {
            if pending_open {
                return Err(CoreError::invalid(
                    "susp SL component continues into a current-directory component: \
                     refusing a contradictory symbolic link",
                ));
            }
            parts.push(b".".to_vec());
        } else if flags & COMP_PARENT != 0 {
            if pending_open {
                return Err(CoreError::invalid(
                    "susp SL component continues into a parent-directory component: \
                     refusing a contradictory symbolic link",
                ));
            }
            parts.push(b"..".to_vec());
        } else if flags & COMP_ROOT != 0 {
            if pending_open {
                return Err(CoreError::invalid(
                    "susp SL component continues into a root component: \
                     refusing a contradictory symbolic link",
                ));
            }
            parts.push(Vec::new());
        } else {
            if text.is_empty() && !pending_open {
                return Err(CoreError::invalid(
                    "susp SL component is empty: refusing an empty path component",
                ));
            }
            pending.extend_from_slice(text);
            parts.push(pending);
            pending = Vec::new();
            pending_open = false;
        }
        at = end;
    }
    if pending_open {
        return Err(CoreError::invalid(
            "susp SL component continues in the next component record but none follows: \
             refusing a truncated symbolic link",
        ));
    }
    if parts.is_empty() {
        return Err(CoreError::invalid(
            "susp SL record carries no components: refusing an empty symbolic link",
        ));
    }
    let mut target: Vec<u8> = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            target.push(b'/');
        }
        target.extend_from_slice(part);
    }
    String::from_utf8(target).map_err(|_| {
        CoreError::invalid(format!(
            "symbolic link target of {} bytes is not valid UTF-8",
            parts.iter().map(Vec::len).sum::<usize>() + parts.len().saturating_sub(1)
        ))
    })
}

/// Parse one record's collected SUSP stream into [`RockAttrs`]:
/// `is_dot`/`is_parent` gate the `NM` current/parent flags, duplicate
/// singletons refuse, unknown entries skip by length, and `ST` ends
/// the area. `CE` entries are skipped here — [`susp_stream`] already
/// followed them.
pub fn parse_attrs(stream: &[u8], is_dot: bool, is_parent: bool) -> Result<RockAttrs> {
    let mut attrs = RockAttrs {
        names: Vec::new(),
        symlink_target: None,
        posix: None,
        times: RockTimes::default(),
        child_link: None,
        parent_link: None,
        relocated: false,
    };
    let mut data_end = stream.len();
    while data_end > 0 && stream.get(data_end - 1) == Some(&0) {
        data_end -= 1;
    }
    let mut nm_complete = false;
    let mut sl_chain: Vec<u8> = Vec::new();
    let mut sl_open = false;
    let mut sl_done = false;
    let mut sl_seen = false;
    let mut at: usize = 0;
    while at < data_end {
        let remaining = data_end.saturating_sub(at);
        if remaining < 4 {
            return Err(CoreError::invalid(format!(
                "susp entry stream of {} bytes ends with {remaining} trailing bytes at offset \
                 {at}: refusing a truncated entry",
                stream.len()
            )));
        }
        let sig_0 = byte_at(stream, at, "susp entry stream")?;
        let sig_1 = byte_at(stream, at + 1, "susp entry stream")?;
        let len_byte = byte_at(stream, at + 2, "susp entry stream")?;
        let entry_len = usize::from(len_byte);
        if entry_len < 4 {
            return Err(CoreError::invalid(format!(
                "susp entry {sig_0:02x}{sig_1:02x} declares length {len_byte}, \
                 below the 4 byte header"
            )));
        }
        if sig_0 == b'S' && sig_1 == b'T' {
            break;
        }
        let end = at.checked_add(entry_len).ok_or_else(|| {
            CoreError::invalid(format!(
                "susp entry of {entry_len} bytes at offset {at} overflows the offset arithmetic"
            ))
        })?;
        if end > stream.len() {
            return Err(CoreError::invalid(format!(
                "susp entry stream of {} bytes ends inside a {entry_len} byte entry at offset \
                 {at}: refusing a truncated entry",
                stream.len()
            )));
        }
        match (sig_0, sig_1) {
            (b'S', b'P') => {
                let entry = stream.get(at..end).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "susp SP record of {entry_len} bytes ends inside the {} byte stream",
                        stream.len()
                    ))
                })?;
                check_sp(entry)?;
                at = at.checked_add(SP_LEN).ok_or_else(|| {
                    CoreError::invalid("susp SP record overflows the offset arithmetic")
                })?;
                continue;
            }
            (b'C', b'E') => {
                let entry = stream.get(at..at + CE_LEN).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "susp entry stream of {} bytes ends inside the {CE_LEN} byte CE record \
                         at offset {at}",
                        stream.len()
                    ))
                })?;
                parse_ce(entry)?;
            }
            (b'N', b'M') => {
                parse_nm_entry(
                    stream,
                    at,
                    entry_len,
                    is_dot,
                    is_parent,
                    &mut attrs.names,
                    &mut nm_complete,
                )?;
            }
            (b'S', b'L') => {
                let version = byte_at(stream, at + 3, "susp SL record")?;
                if version != ENTRY_VERSION {
                    return Err(CoreError::invalid(format!(
                        "susp SL record has version {version}, not {ENTRY_VERSION}"
                    )));
                }
                let flags = byte_at(stream, at + 4, "susp SL record")?;
                if flags & !SL_CONTINUE != 0 {
                    return Err(CoreError::invalid(format!(
                        "susp SL record has unsupported entry flags 0x{flags:02x}: only the \
                         continue bit is defined"
                    )));
                }
                if sl_done {
                    return Err(CoreError::invalid(
                        "susp record carries a second symbolic link after a complete one: \
                         only continuations may follow",
                    ));
                }
                let start = at.checked_add(NAME_LINK_MIN).ok_or_else(|| {
                    CoreError::invalid("susp SL record components overflow the offset arithmetic")
                })?;
                let area = stream.get(start..end).ok_or_else(|| {
                    CoreError::invalid(format!(
                        "susp SL record of {entry_len} bytes ends inside its component area"
                    ))
                })?;
                sl_chain.extend_from_slice(area);
                sl_open = flags & SL_CONTINUE != 0;
                sl_seen = true;
                if !sl_open {
                    sl_done = true;
                }
            }
            (b'P', b'X') => {
                if attrs.posix.is_some() {
                    return Err(CoreError::invalid("susp record carries a second PX record"));
                }
                attrs.posix = Some(parse_px_entry(stream, at, entry_len)?);
            }
            (b'T', b'F') => {
                parse_tf_entry(stream, at, entry_len, &mut attrs.times)?;
            }
            (b'C', b'L') => {
                if attrs.child_link.is_some() {
                    return Err(CoreError::invalid(
                        "susp record carries a second child link",
                    ));
                }
                if entry_len != CL_PL_LEN {
                    return Err(CoreError::invalid(format!(
                        "susp CL record declares length {entry_len}, not {CL_PL_LEN}"
                    )));
                }
                let version = byte_at(stream, at + 3, "susp CL record")?;
                if version != ENTRY_VERSION {
                    return Err(CoreError::invalid(format!(
                        "susp CL record has version {version}, not {ENTRY_VERSION}"
                    )));
                }
                let lba = both32(stream, at + 4, at + 8, "susp CL record location")?;
                attrs.child_link = Some(lba);
                attrs.relocated = true;
            }
            (b'P', b'L') => {
                if attrs.parent_link.is_some() {
                    return Err(CoreError::invalid(
                        "susp record carries a second parent link",
                    ));
                }
                if entry_len != CL_PL_LEN {
                    return Err(CoreError::invalid(format!(
                        "susp PL record declares length {entry_len}, not {CL_PL_LEN}"
                    )));
                }
                let version = byte_at(stream, at + 3, "susp PL record")?;
                if version != ENTRY_VERSION {
                    return Err(CoreError::invalid(format!(
                        "susp PL record has version {version}, not {ENTRY_VERSION}"
                    )));
                }
                let lba = both32(stream, at + 4, at + 8, "susp PL record location")?;
                attrs.parent_link = Some(lba);
            }
            (b'R', b'E') => {
                if entry_len != RE_ST_LEN {
                    return Err(CoreError::invalid(format!(
                        "susp RE record declares length {entry_len}, not {RE_ST_LEN}"
                    )));
                }
                let version = byte_at(stream, at + 3, "susp RE record")?;
                if version != ENTRY_VERSION {
                    return Err(CoreError::invalid(format!(
                        "susp RE record has version {version}, not {ENTRY_VERSION}"
                    )));
                }
                attrs.relocated = true;
            }
            _ => {}
        }
        at = end;
    }
    if sl_open {
        return Err(CoreError::invalid(
            "susp SL record claims continuation but no further SL record follows: \
             refusing a truncated symbolic link",
        ));
    }
    if sl_seen && sl_chain.is_empty() {
        return Err(CoreError::invalid(
            "susp SL record carries no components: refusing an empty symbolic link",
        ));
    }
    if !sl_chain.is_empty() {
        attrs.symlink_target = Some(assemble_target(&sl_chain)?);
    }
    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both-endian encoding of one `u32` (little half then big half),
    /// mirroring the on-disk layout the parser reads. Test-only.
    fn bb(value: u32) -> Vec<u8> {
        let mut out = value.to_le_bytes().to_vec();
        out.extend_from_slice(&value.to_be_bytes());
        out
    }

    /// One SUSP entry with a computed length byte. Test-only.
    fn entry(sig: &[u8; 2], version: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![sig[0], sig[1], (4 + payload.len()) as u8, version];
        out.extend_from_slice(payload);
        out
    }

    /// One SUSP entry with an explicit length byte (for mismatch
    /// pins). Test-only.
    fn entry_with_len(sig: &[u8; 2], version: u8, len: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![sig[0], sig[1], len, version];
        out.extend_from_slice(payload);
        out
    }

    /// `SP` with the given skip.
    fn sp(skip: u8) -> Vec<u8> {
        vec![b'S', b'P', 7, 1, SP_MAGIC_0, SP_MAGIC_1, skip]
    }

    /// 36-byte `PX` (no serial) or 44-byte `PX` (serial `Some`).
    fn px(mode: u32, nlinks: u32, uid: u32, gid: u32, serial: Option<u32>) -> Vec<u8> {
        let mut payload = bb(mode);
        payload.extend_from_slice(&bb(nlinks));
        payload.extend_from_slice(&bb(uid));
        payload.extend_from_slice(&bb(gid));
        if let Some(number) = serial {
            payload.extend_from_slice(&bb(number));
        }
        entry(b"PX", 1, &payload)
    }

    /// `TF` with `flags` over the given raw stamps.
    fn tf(flags: u8, stamps: &[u8]) -> Vec<u8> {
        let mut payload = vec![flags];
        payload.extend_from_slice(stamps);
        entry(b"TF", 1, &payload)
    }

    /// `NM` with `flags` and the name bytes.
    fn nm(flags: u8, name: &[u8]) -> Vec<u8> {
        let mut payload = vec![flags];
        payload.extend_from_slice(name);
        entry(b"NM", 1, &payload)
    }

    /// `SL` with entry `flags` over `(component flags, text)` pairs.
    fn sl(flags: u8, comps: &[(u8, &[u8])]) -> Vec<u8> {
        let mut payload = vec![flags];
        for (cflags, text) in comps {
            payload.push(*cflags);
            payload.push(text.len() as u8);
            payload.extend_from_slice(text);
        }
        entry(b"SL", 1, &payload)
    }

    /// `CE` at block, byte offset and length.
    fn ce(block: u32, offset: u32, length: u32) -> Vec<u8> {
        let mut payload = bb(block);
        payload.extend_from_slice(&bb(offset));
        payload.extend_from_slice(&bb(length));
        entry(b"CE", 1, &payload)
    }

    /// `CL`/`PL` with the LBA.
    fn link(sig: &[u8; 2], lba: u32) -> Vec<u8> {
        entry(sig, 1, &bb(lba))
    }

    /// Image of `sectors` zeroed sectors with `writes` applied as
    /// (sector, byte offset, bytes). Test-only.
    fn image_with_writes(sectors: u32, writes: &[(u32, usize, &[u8])]) -> Vec<u8> {
        let mut image = vec![0u8; sectors as usize * SECTOR_BYTES];
        for (sector, at, bytes) in writes {
            let base = *sector as usize * SECTOR_BYTES + *at;
            image[base..base + bytes.len()].copy_from_slice(bytes);
        }
        image
    }

    /// Whole-sector reads over `image`, refusing past the end like the
    /// real cache. Test-only.
    fn sector_reader(image: &[u8]) -> impl FnMut(u32) -> Result<[u8; SECTOR_BYTES]> + '_ {
        move |sector: u32| {
            let start = sector as usize * SECTOR_BYTES;
            let window = image.get(start..start + SECTOR_BYTES).ok_or_else(|| {
                CoreError::invalid(format!("test sector {sector} is past the image end"))
            })?;
            let mut out = [0u8; SECTOR_BYTES];
            out.copy_from_slice(window);
            Ok(out)
        }
    }

    #[test]
    fn sp_detects_the_skip() {
        let mut area = sp(4);
        area.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(detect_susp(&area).expect("the SP parses"), Some(4));
    }

    #[test]
    fn no_sp_means_no_susp() {
        assert_eq!(detect_susp(&[]).expect("empty is fine"), None);
        assert_eq!(detect_susp(&[0, 0]).expect("padding is fine"), None);
        assert_eq!(
            detect_susp(&px(0x81A4, 1, 0, 0, None)).expect("entries alone are fine"),
            None
        );
    }

    #[test]
    fn sp_wrong_magic_names_both_bytes() {
        let mut area = sp(0);
        area[4] = 0x12;
        area[5] = 0x34;
        let error = detect_susp(&area).expect_err("the wrong magic refuses");
        let text = error.to_string();
        assert!(text.contains("0x12"), "{text}");
        assert!(text.contains("0x34"), "{text}");
        assert!(text.contains("0xBE"), "{text}");
    }

    #[test]
    fn sp_wrong_length_and_truncation_refused() {
        let mut area = sp(0);
        area[2] = 6;
        let error = detect_susp(&area).expect_err("length 6 refuses");
        assert!(error.to_string().contains('6'), "{error}");
        let error = detect_susp(b"SP").expect_err("two bytes hold no SP");
        assert!(error.to_string().contains('2'), "{error}");
    }

    #[test]
    fn ce_area_appends_to_the_stream() {
        let name = nm(0, b"longname");
        let image = image_with_writes(64, &[(50, 100, &name)]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let sys = ce(50, 100, name.len() as u32);
        let stream = susp_stream(&mut read, total, &sys, 0).expect("the CE resolves");
        // The CE entry stays in the stream; the area bytes follow it.
        let mut expected = sys;
        expected.extend_from_slice(&name);
        assert_eq!(stream, expected);
    }

    #[test]
    fn nm_spanning_the_ce_boundary_joins() {
        let mut first = nm(NM_CONTINUE, b"long");
        let rest = nm(0, b"name");
        let image = image_with_writes(64, &[(50, 0, &rest)]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        first.extend_from_slice(&ce(50, 0, rest.len() as u32));
        let stream = susp_stream(&mut read, total, &first, 0).expect("the CE resolves");
        let mut expected = first;
        expected.extend_from_slice(&rest);
        assert_eq!(stream, expected);
        let attrs = parse_attrs(&stream, false, false).expect("the chain parses");
        assert_eq!(attrs.names.len(), 2);
        assert_eq!(attrs.names[0].bytes, b"long");
        assert!(attrs.names[0].continues);
        assert_eq!(attrs.names[1].bytes, b"name");
        assert!(!attrs.names[1].continues);
    }

    #[test]
    fn ce_pointing_at_itself_refused() {
        let area = ce(50, 0, 28);
        let image = image_with_writes(64, &[(50, 0, &area)]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let error = susp_stream(&mut read, total, &area, 0).expect_err("the loop refuses");
        let text = error.to_string();
        assert!(text.contains("cyclic"), "{text}");
        assert!(text.contains("50"), "{text}");
    }

    #[test]
    fn ce_ping_pong_refused() {
        let to_b = ce(51, 0, 28);
        let to_a = ce(50, 0, 28);
        let image = image_with_writes(64, &[(50, 0, &to_b), (51, 0, &to_a)]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let error = susp_stream(&mut read, total, &to_a, 0).expect_err("the cycle refuses");
        assert!(error.to_string().contains("cyclic"), "{error}");
    }

    #[test]
    fn ce_past_the_store_refused() {
        let sys = ce(63, 0, 4096);
        let image = image_with_writes(64, &[]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let error = susp_stream(&mut read, total, &sys, 0).expect_err("the overrun refuses");
        let text = error.to_string();
        assert!(text.contains("past"), "{text}");
        assert!(text.contains("63"), "{text}");
    }

    #[test]
    fn ce_chain_past_the_depth_bound_refused() {
        // Nine nested continuations: sectors 50..58 each point at the
        // next, so the ninth follow breaches the bound of eight.
        let mut refs: Vec<(u32, usize, Vec<u8>)> = Vec::new();
        for sector in 50..59 {
            refs.push((sector, 0, ce(sector + 1, 0, 28)));
        }
        let borrowed: Vec<(u32, usize, &[u8])> = refs
            .iter()
            .map(|(sector, at, bytes)| (*sector, *at, bytes.as_slice()))
            .collect();
        let image = image_with_writes(64, &borrowed);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let sys = ce(50, 0, 28);
        let error = susp_stream(&mut read, total, &sys, 0).expect_err("the chain refuses");
        let text = error.to_string();
        assert!(text.contains('8'), "{text}");
        assert!(text.contains("deep"), "{text}");
    }

    #[test]
    fn ce_growing_past_the_stream_bound_refused() {
        let sys = ce(50, 0, 40_000);
        let image = image_with_writes(64, &[]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let error = susp_stream(&mut read, total, &sys, 0).expect_err("the flood refuses");
        let text = error.to_string();
        assert!(text.contains("32768"), "{text}");
        assert!(text.contains("40000"), "{text}");
    }

    #[test]
    fn ce_across_a_sector_edge_reads_both() {
        // A 105-byte NM entry split across the sector edge: its first
        // 48 bytes sit at the tail of sector 50, the remaining 57 at
        // the head of sector 51.
        let mut long_name = vec![b'x'; 100];
        long_name[0] = b'y';
        let name = nm(0, &long_name);
        assert_eq!(name.len(), 105);
        let image = image_with_writes(64, &[(50, 2000, &name[..48]), (51, 0, &name[48..])]);
        let total = image.len() as u64;
        let mut read = sector_reader(&image);
        let sys = ce(50, 2000, 105);
        let stream = susp_stream(&mut read, total, &sys, 0).expect("the span reads");
        let mut expected = sys;
        expected.extend_from_slice(&name);
        assert_eq!(stream, expected);
        let attrs = parse_attrs(&stream, false, false).expect("the split entry parses");
        assert_eq!(attrs.names.len(), 1);
        assert_eq!(attrs.names[0].bytes, long_name);
    }

    #[test]
    fn susp_skip_moves_the_stream_start() {
        let mut sys = vec![9, 9, 9, 9];
        let name = nm(0, b"skipped-to");
        sys.extend_from_slice(&name);
        let mut read = sector_reader(&[]);
        let stream = susp_stream(&mut read, 0, &sys, 4).expect("the skip applies");
        assert_eq!(stream, name);
    }

    #[test]
    fn susp_skip_past_the_area_refused() {
        let sys = vec![1, 2, 3, 4];
        let mut read = sector_reader(&[]);
        let error = susp_stream(&mut read, 0, &sys, 9).expect_err("the skip overruns");
        let text = error.to_string();
        assert!(text.contains('9'), "{text}");
        assert!(text.contains('4'), "{text}");
    }

    #[test]
    fn trailing_zero_pad_stops_but_nonzero_refuses() {
        let mut padded = nm(0, b"a");
        padded.push(0);
        let mut read = sector_reader(&[]);
        let stream = susp_stream(&mut read, 0, &padded, 0).expect("the pad stops");
        assert_eq!(stream, padded);
        let mut dirty = nm(0, b"a");
        dirty.push(7);
        let error = susp_stream(&mut read, 0, &dirty, 0).expect_err("the byte refuses");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn truncated_entry_at_the_fixpoint_refused() {
        let sys = vec![b'N', b'M', 60, 1, 0, 0, 0, 0, 0, 0];
        let mut read = sector_reader(&[]);
        let error = susp_stream(&mut read, 0, &sys, 0).expect_err("the fragment refuses");
        let text = error.to_string();
        assert!(text.contains("60"), "{text}");
        assert!(text.contains("truncated"), "{text}");
    }

    #[test]
    fn px_lengths_decode_with_and_without_serial() {
        let short = px(0x81A4, 1, 1000, 100, None);
        let attrs = parse_attrs(&short, false, false).expect("the 36 byte PX parses");
        let posix = attrs.posix.expect("PX is present");
        assert_eq!(posix.mode, 0x81A4);
        assert_eq!(posix.nlinks, 1);
        assert_eq!(posix.uid, 1000);
        assert_eq!(posix.gid, 100);
        assert_eq!(posix.serial, None);
        let full = px(0x41ED, 2, 0, 0, Some(7));
        let attrs = parse_attrs(&full, false, false).expect("the 44 byte PX parses");
        assert_eq!(attrs.posix.expect("PX is present").serial, Some(7));
    }

    #[test]
    fn px_wrong_length_and_endian_mismatch_refused() {
        let mut bad = px(0x81A4, 1, 0, 0, None);
        bad[2] = 40;
        let error = parse_attrs(&bad, false, false).expect_err("length 40 refuses");
        assert!(error.to_string().contains("40"), "{error}");
        let mut split = px(0x81A4, 1, 0, 0, None);
        split[12] = 2;
        let error = parse_attrs(&split, false, false).expect_err("halves disagree");
        let text = error.to_string();
        assert!(text.contains('2'), "{text}");
        assert!(text.contains('1'), "{text}");
        let mut doubled = px(0x81A4, 1, 0, 0, None);
        doubled.extend_from_slice(&px(0x81A4, 1, 0, 0, None));
        let error = parse_attrs(&doubled, false, false).expect_err("two PX refuse");
        assert!(error.to_string().contains("second PX"), "{error}");
    }

    /// The `xorriso` short-form stamps for a touched file: modification
    /// 2023-05-06 07:08:09, access and attribute-change beside it.
    fn short_stamps() -> Vec<u8> {
        vec![
            0x7b, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, // modification
            0x7e, 0x0b, 0x02, 0x06, 0x10, 0x36, 0x00, // access
            0x7e, 0x0b, 0x02, 0x06, 0x12, 0x31, 0x00, // attribute-change
        ]
    }

    #[test]
    fn tf_short_form_decodes_all_three() {
        let stream = tf(0x0e, &short_stamps());
        let attrs = parse_attrs(&stream, false, false).expect("the TF parses");
        assert_eq!(attrs.times.creation, None);
        assert_eq!(
            attrs.times.modification,
            Some(RockTime {
                year: 2023,
                month: 5,
                day: 6,
                hour: 7,
                minute: 8,
                second: 9,
                centiseconds: 0,
                offset_quarters: 0,
            })
        );
        let access = attrs.times.access.expect("access is present");
        assert_eq!((access.year, access.month, access.day), (2026, 11, 2));
        assert_eq!((access.hour, access.minute, access.second), (6, 16, 54));
        let attributes = attrs.times.attributes.expect("attributes are present");
        assert_eq!(
            (attributes.hour, attributes.minute, attributes.second),
            (6, 18, 49)
        );
    }

    #[test]
    fn tf_long_form_decodes_digits_and_offset() {
        let mut stamps = b"2023050607080900".to_vec();
        stamps.push(0x00);
        stamps.extend_from_slice(b"2020110221223307");
        stamps.push(0xD0);
        stamps.extend_from_slice(b"2020110221223307");
        stamps.push(0x00);
        let stream = tf(0x8e, &stamps);
        let attrs = parse_attrs(&stream, false, false).expect("the long TF parses");
        let modification = attrs.times.modification.expect("modification is present");
        assert_eq!(modification.year, 2023);
        assert_eq!(modification.centiseconds, 0);
        assert_eq!(modification.offset_quarters, 0);
        let access = attrs.times.access.expect("access is present");
        assert_eq!(access.year, 2020);
        assert_eq!(access.centiseconds, 7);
        assert_eq!(access.offset_quarters, -48);
        assert!(attrs.times.attributes.is_some());
    }

    #[test]
    fn tf_bad_month_and_non_digit_refused() {
        let mut stamps = short_stamps();
        stamps[1] = 13;
        let error = parse_attrs(&tf(0x0e, &stamps), false, false).expect_err("month 13 refuses");
        assert!(error.to_string().contains("13"), "{error}");
        let mut first = b"2023050607080900".to_vec();
        first[3] = b'X';
        let mut long = first;
        long.push(0x00);
        long.extend_from_slice(b"2020110221223300");
        long.push(0x00);
        long.extend_from_slice(b"2020110221223300");
        long.push(0x00);
        let error = parse_attrs(&tf(0x8e, &long), false, false).expect_err("X refuses");
        let text = error.to_string();
        assert!(text.contains('3'), "{text}");
        assert!(text.contains("digit"), "{text}");
    }

    #[test]
    fn tf_unsupported_kinds_and_bad_lengths_refused() {
        let mut stamps = short_stamps();
        stamps.extend_from_slice(&short_stamps()[..7]);
        let error = parse_attrs(&tf(0x1e, &stamps), false, false).expect_err("backup refuses");
        assert!(error.to_string().contains("backup"), "{error}");
        let mismatch = entry_with_len(b"TF", 1, 30, &tf_payload_26());
        let error = parse_attrs(&mismatch, false, false).expect_err("length 30 refuses");
        let text = error.to_string();
        assert!(text.contains("30"), "{text}");
        assert!(text.contains("26"), "{text}");
        let first = tf(0x02, &short_stamps()[..7]);
        let mut doubled = first.clone();
        doubled.extend_from_slice(&first);
        let error = parse_attrs(&doubled, false, false).expect_err("two modifications refuse");
        assert!(error.to_string().contains("second modification"), "{error}");
    }

    /// 22 payload bytes for flags `0x0e`: the flag byte plus three
    /// 7-byte stamps.
    fn tf_payload_26() -> Vec<u8> {
        let mut payload = vec![0x0e];
        payload.extend_from_slice(&short_stamps());
        payload
    }

    #[test]
    fn nm_plain_and_continued() {
        let stream = nm(0, b"hello.txt");
        let attrs = parse_attrs(&stream, false, false).expect("the NM parses");
        assert_eq!(attrs.names.len(), 1);
        assert_eq!(attrs.names[0].bytes, b"hello.txt");
        assert!(!attrs.names[0].continues);
        let mut chained = nm(NM_CONTINUE, b"long");
        chained.extend_from_slice(&nm(0, b"name"));
        let attrs = parse_attrs(&chained, false, false).expect("the chain parses");
        assert_eq!(attrs.names.len(), 2);
        assert!(attrs.names[0].continues);
    }

    #[test]
    fn nm_second_complete_and_bad_flags_refused() {
        let mut doubled = nm(0, b"a");
        doubled.extend_from_slice(&nm(0, b"b"));
        let error = parse_attrs(&doubled, false, false).expect_err("two names refuse");
        assert!(
            error.to_string().contains("second alternate name"),
            "{error}"
        );
        let error =
            parse_attrs(&nm(NM_CURRENT, b""), false, false).expect_err("current on a file refuses");
        assert!(error.to_string().contains("current"), "{error}");
        let error = parse_attrs(&nm(0x08, b""), false, false).expect_err("reserved refuses");
        assert!(error.to_string().contains("reserved"), "{error}");
        let error = parse_attrs(&nm(NM_HOST, b""), false, false).expect_err("host refuses");
        assert!(error.to_string().contains("host"), "{error}");
        let error = parse_attrs(&nm(0x03, b""), false, false).expect_err("the combo refuses");
        assert!(error.to_string().contains("more than one"), "{error}");
    }

    #[test]
    fn nm_current_and_parent_belong_on_dot_records() {
        let attrs = parse_attrs(&nm(NM_CURRENT, b""), true, false).expect("current on `.` is fine");
        assert!(attrs.names.is_empty());
        let attrs = parse_attrs(&nm(NM_PARENT, b""), false, true).expect("parent on `..` is fine");
        assert!(attrs.names.is_empty());
        let error =
            parse_attrs(&nm(NM_PARENT, b""), true, false).expect_err("parent on `.` refuses");
        assert!(error.to_string().contains("parent"), "{error}");
        let error = parse_attrs(
            &entry_with_len(b"NM", 1, 6, &[NM_CURRENT, b'x']),
            true,
            false,
        )
        .expect_err("current with bytes refuses");
        assert!(error.to_string().contains('5'), "{error}");
    }

    #[test]
    fn sl_targets_reconstruct() {
        let plain = sl(0, &[(0, b"hello.txt")]);
        let attrs = parse_attrs(&plain, false, false).expect("the SL parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("hello.txt"));
        let up = sl(0, &[(COMP_PARENT, b""), (0, b"hello.txt")]);
        let attrs = parse_attrs(&up, false, false).expect("parent parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("../hello.txt"));
        let root = sl(0, &[(COMP_ROOT, b""), (0, b"hello.txt")]);
        let attrs = parse_attrs(&root, false, false).expect("root parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("/hello.txt"));
        let here = sl(0, &[(COMP_CURRENT, b""), (0, b"hello.txt")]);
        let attrs = parse_attrs(&here, false, false).expect("current parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("./hello.txt"));
        let multi = sl(0, &[(0, b"d1"), (0, b"d1"), (0, b"target.txt")]);
        let attrs = parse_attrs(&multi, false, false).expect("multi parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("d1/d1/target.txt"));
    }

    #[test]
    fn sl_continuations_chain() {
        let mut split_comp = sl(0, &[(COMP_CONTINUE, b"hel"), (0, b"lo.txt")]);
        let attrs = parse_attrs(&split_comp, false, false).expect("the split parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some("hello.txt"));
        let mut chained = sl(SL_CONTINUE, &[(0, b"ab")]);
        chained.extend_from_slice(&sl(0, &[(0, b"cd")]));
        let attrs = parse_attrs(&chained, false, false).expect("the entries chain");
        assert_eq!(attrs.symlink_target.as_deref(), Some("ab/cd"));
        split_comp = sl(0, &[(COMP_CONTINUE, b"ab")]);
        let error = parse_attrs(&split_comp, false, false).expect_err("the dangling part refuses");
        assert!(error.to_string().contains("truncated"), "{error}");
        let dangling = sl(SL_CONTINUE, &[(0, b"ab")]);
        let error = parse_attrs(&dangling, false, false).expect_err("the dangling entry refuses");
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn sl_bad_components_refused() {
        let error =
            parse_attrs(&sl(0, &[(0x40, b"x")]), false, false).expect_err("reserved refuses");
        assert!(error.to_string().contains("reserved"), "{error}");
        let error = parse_attrs(&sl(0, &[(0x10, b"x")]), false, false).expect_err("host refuses");
        assert!(error.to_string().contains("host"), "{error}");
        let error =
            parse_attrs(&sl(0, &[(0x06, b"")]), false, false).expect_err("the combo refuses");
        assert!(error.to_string().contains("more than one"), "{error}");
        let error = parse_attrs(&sl(0, &[]), false, false).expect_err("empty refuses");
        assert!(error.to_string().contains("no components"), "{error}");
        let error =
            parse_attrs(&sl(0, &[(0, &[0xFF])]), false, false).expect_err("non-UTF-8 refuses");
        assert!(error.to_string().contains("UTF-8"), "{error}");
        let error = parse_attrs(&sl(0, &[(0, b"")]), false, false).expect_err("empty refuses");
        assert!(
            error.to_string().contains("empty path component"),
            "{error}"
        );
        let mut doubled = sl(0, &[(0, b"a")]);
        doubled.extend_from_slice(&sl(0, &[(0, b"b")]));
        let error = parse_attrs(&doubled, false, false).expect_err("two links refuse");
        assert!(
            error.to_string().contains("second symbolic link"),
            "{error}"
        );
        let error =
            parse_attrs(&sl(0x02, &[(0, b"a")]), false, false).expect_err("entry flags refuse");
        assert!(error.to_string().contains("entry flags"), "{error}");
        let error = parse_attrs(
            &sl(0, &[(COMP_CONTINUE, b"ab"), (COMP_PARENT, b"")]),
            false,
            false,
        )
        .expect_err("continue into parent refuses");
        assert!(error.to_string().contains("contradictory"), "{error}");
    }

    #[test]
    fn sl_special_with_content_tolerated() {
        // Real writers emit empty specials, but the flag (not the
        // length) carries the meaning, so stray bytes stay ignored.
        let attrs =
            parse_attrs(&sl(0, &[(COMP_PARENT, b"..")]), false, false).expect("the parent parses");
        assert_eq!(attrs.symlink_target.as_deref(), Some(".."));
    }

    #[test]
    fn cl_pl_and_re_parse() {
        let mut stream = link(b"CL", 28);
        stream.extend_from_slice(&link(b"PL", 26));
        stream.extend_from_slice(&entry(b"RE", 1, &[]));
        let attrs = parse_attrs(&stream, false, false).expect("the links parse");
        assert_eq!(attrs.child_link, Some(28));
        assert_eq!(attrs.parent_link, Some(26));
        assert!(attrs.relocated);
        let mut doubled = link(b"CL", 28);
        doubled.extend_from_slice(&link(b"CL", 29));
        let error = parse_attrs(&doubled, false, false).expect_err("two CL refuse");
        assert!(error.to_string().contains("second child link"), "{error}");
        let plain = nm(0, b"x");
        let attrs = parse_attrs(&plain, false, false).expect("plain parses");
        assert!(!attrs.relocated);
        assert_eq!(attrs.child_link, None);
    }

    #[test]
    fn unknown_entries_skip_and_st_stops() {
        let mut stream = entry(b"ER", 1, &[1, 2, 3]);
        stream.extend_from_slice(&entry(b"RR", 1, &[0xFF]));
        stream.extend_from_slice(&nm(0, b"a"));
        stream.extend_from_slice(&entry(b"ST", 1, &[]));
        stream.extend_from_slice(&nm(0, b"b"));
        let attrs = parse_attrs(&stream, false, false).expect("unknowns skip, ST stops");
        assert_eq!(attrs.names.len(), 1);
        assert_eq!(attrs.names[0].bytes, b"a");
    }

    #[test]
    fn leading_sp_copy_tolerated_and_empty_ok() {
        let mut stream = sp(0);
        stream.extend_from_slice(&nm(0, b"x"));
        let attrs = parse_attrs(&stream, false, false).expect("the copy skips");
        assert_eq!(attrs.names.len(), 1);
        let attrs = parse_attrs(&[0, 0, 0], false, false).expect("padding is fine");
        assert!(attrs.names.is_empty());
        assert!(!attrs.relocated);
    }
}
